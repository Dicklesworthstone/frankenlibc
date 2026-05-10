//! Contract tests for bd-5vr.3.1 statistical runtime-math completion evidence.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_MODULES: &[(&str, &str, usize)] = &[
    (
        "risk",
        "crates/frankenlibc-membrane/src/runtime_math/risk.rs",
        11,
    ),
    (
        "conformal",
        "crates/frankenlibc-membrane/src/runtime_math/conformal.rs",
        11,
    ),
    (
        "eprocess",
        "crates/frankenlibc-membrane/src/runtime_math/eprocess.rs",
        8,
    ),
    (
        "cvar",
        "crates/frankenlibc-membrane/src/runtime_math/cvar.rs",
        5,
    ),
    (
        "changepoint",
        "crates/frankenlibc-membrane/src/runtime_math/changepoint.rs",
        10,
    ),
    (
        "alpha_investing",
        "crates/frankenlibc-membrane/src/runtime_math/alpha_investing.rs",
        21,
    ),
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "module",
    "module_path",
    "inline_unit_tests",
    "artifact_refs",
    "test_refs",
    "failure_signature",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| test_error("frankenlibc-harness manifest should have a parent"))?;
    crates_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| test_error("frankenlibc-harness manifest should live below workspace root"))
}

fn safe_workspace_path(root: &Path, rel: &str) -> TestResult<PathBuf> {
    let trimmed = rel.trim_end_matches('/');
    let rel_path = Path::new(trimmed);
    ensure(!rel_path.is_absolute(), "artifact path must be relative")?;
    for component in rel_path.components() {
        ensure(
            matches!(component, Component::Normal(_)),
            "artifact path contains unsafe components",
        )?;
    }
    Ok(root.join(rel_path)) // ubs:ignore - rel_path is rejected unless relative with only normal components.
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/statistical_kernels_completion_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn as_array<'a>(value: &'a Value, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn as_object<'a>(
    value: &'a Value,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| test_error(format!("{context} must be an object")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (rel, line_text) = file_line_ref
        .rsplit_once(':')
        .ok_or_else(|| test_error("file-line ref should contain ':'"))?;
    let line_no = line_text.parse::<usize>()?;
    ensure(line_no > 0, "file-line ref line must be positive")?;
    let path = safe_workspace_path(root, rel)?;
    ensure(
        path.is_file(),
        format!("file-line ref path should exist: {file_line_ref}"),
    )?;
    let line_count = std::fs::read_to_string(path)?.lines().count();
    ensure(
        line_no <= line_count,
        format!("file-line ref outside file: {file_line_ref}"),
    )
}

fn function_exists(source_text: &str, name: &str) -> bool {
    source_text.contains(&format!("fn {name}"))
}

fn load_test_sources(root: &Path, evidence: &Value) -> TestResult<BTreeMap<String, String>> {
    let sources = as_object(&evidence["test_sources"], "test_sources")?;
    let mut texts = BTreeMap::new();
    for (source_name, path) in sources {
        let rel = path
            .as_str()
            .ok_or_else(|| test_error("test source path must be a string"))?;
        texts.insert(
            source_name.clone(),
            std::fs::read_to_string(safe_workspace_path(root, rel)?)?,
        );
    }
    Ok(texts)
}

fn validate_test_refs(evidence: &Value, source_texts: &BTreeMap<String, String>) -> TestResult {
    for section_name in ["unit_primary", "e2e_primary", "telemetry_primary"] {
        let section = &evidence[section_name];
        for reference in as_array(&section["required_test_refs"], "required_test_refs")? {
            let source = string_field(reference, "source", section_name)?;
            let name = string_field(reference, "name", section_name)?;
            let text = source_texts
                .get(source)
                .ok_or_else(|| test_error(format!("{section_name}: missing source {source}")))?;
            ensure(
                function_exists(text, name),
                format!("{section_name}: missing test ref {source}.{name}"),
            )?;
        }
    }
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "statistical-kernels-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_statistical_kernels_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_STATISTICAL_KERNELS_CONTRACT", contract)
        .env(
            "FRANKENLIBC_STATISTICAL_KERNELS_REPORT",
            out_dir.join("statistical_kernels_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_STATISTICAL_KERNELS_LOG",
            out_dir.join("statistical_kernels_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn expected_modules() -> BTreeSet<&'static str> {
    REQUIRED_MODULES
        .iter()
        .map(|(module, _, _)| *module)
        .collect()
}

#[test]
fn contract_binds_statistical_kernel_unit_and_e2e_evidence() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&contract_path(&root))?;
    ensure(
        string_field(&contract, "schema_version", "contract")?
            == "statistical_kernels_completion_contract.v1",
        "schema_version drifted",
    )?;
    ensure(
        string_field(&contract, "bead", "contract")? == "bd-5vr.3",
        "bead drifted",
    )?;
    ensure(
        string_field(&contract, "completion_debt_bead", "contract")? == "bd-5vr.3.1",
        "completion debt bead drifted",
    )?;

    let evidence = &contract["completion_debt_evidence"];
    ensure(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .unwrap_or_default()
            >= 800,
        "completion contract should target passing next audit score",
    )?;

    for reference in as_array(&evidence["implementation_refs"], "implementation_refs")? {
        file_line_ref_exists(
            &root,
            reference
                .as_str()
                .ok_or_else(|| test_error("implementation ref must be a string"))?,
        )?;
    }

    for value in as_object(&evidence["artifacts"], "artifacts")?.values() {
        let rel = value
            .as_str()
            .ok_or_else(|| test_error("artifact path must be a string"))?;
        ensure(
            safe_workspace_path(&root, rel)?.is_file(),
            format!("artifact should exist: {rel}"),
        )?;
    }

    for value in as_object(&evidence["gates"], "gates")?.values() {
        let rel = value
            .as_str()
            .ok_or_else(|| test_error("gate path must be a string"))?;
        ensure(
            safe_workspace_path(&root, rel)?.is_file(),
            format!("gate should exist: {rel}"),
        )?;
    }

    let kernel_contract = &evidence["statistical_kernel_contract"];
    let required_modules = as_array(&kernel_contract["required_modules"], "required_modules")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    ensure(
        expected_modules().is_subset(&required_modules),
        "statistical kernel contract should require every original kernel",
    )?;

    let module_specs = as_object(&kernel_contract["modules"], "modules")?;
    for (module, expected_path, expected_unit_tests) in REQUIRED_MODULES {
        let spec = module_specs
            .get(*module)
            .ok_or_else(|| test_error(format!("missing module spec for {module}")))?;
        ensure(
            string_field(spec, "module_path", module)? == *expected_path,
            format!("{module}: module_path drifted"),
        )?;
        ensure(
            spec["unit_test_min"].as_u64().unwrap_or_default() as usize >= *expected_unit_tests,
            format!("{module}: unit_test_min below expected"),
        )?;
        let source = std::fs::read_to_string(safe_workspace_path(&root, expected_path)?)?;
        ensure(
            source.matches("#[test]").count() >= *expected_unit_tests,
            format!("{module}: inline unit test count below expected"),
        )?;
        for token in as_array(&spec["entrypoint_tokens"], "entrypoint_tokens")? {
            let token = token
                .as_str()
                .ok_or_else(|| test_error("entrypoint token must be a string"))?;
            ensure(
                source.contains(token),
                format!("{module}: missing entrypoint token {token}"),
            )?;
        }
    }

    let source_texts = load_test_sources(&root, evidence)?;
    validate_test_refs(evidence, &source_texts)
}

#[test]
fn checker_passes_and_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    ensure(
        output.status.success(),
        format!(
            "checker should pass: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&out_dir.join("statistical_kernels_completion_contract.report.json"))?;
    ensure(
        string_field(&report, "status", "report")? == "pass",
        "report status should pass",
    )?;
    ensure(
        report["summary"]["bound_module_count"].as_u64() == Some(REQUIRED_MODULES.len() as u64),
        "report should bind every required module",
    )?;
    ensure(
        report["summary"]["inline_unit_test_total"]
            .as_u64()
            .unwrap_or_default()
            >= 66,
        "report should count the statistical inline unit tests",
    )?;

    let rows = read_jsonl(&out_dir.join("statistical_kernels_completion_contract.log.jsonl"))?;
    ensure(!rows.is_empty(), "checker should emit JSONL rows")?;
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    ensure(
        events.contains("statistical_kernels_completion_contract_validated"),
        "checker should emit pass event",
    )?;
    ensure(
        events.contains("statistical_kernel_module_bound"),
        "checker should emit module binding events",
    )?;
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            ensure(
                row.get(*field).is_some(),
                format!("JSONL row should include {field}"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_alpha_investing_binding() -> TestResult {
    let root = workspace_root()?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["statistical_kernel_contract"]["modules"]
        .as_object_mut()
        .ok_or_else(|| test_error("modules should be mutable"))?
        .remove("alpha_investing");

    let out_dir = unique_output_dir(&root, "missing-alpha")?;
    let mutated = out_dir.join("missing-alpha.contract.json");
    write_json(&mutated, &contract)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    ensure(
        !output.status.success(),
        "checker should fail when alpha_investing binding is missing",
    )?;
    let report = load_json(&out_dir.join("statistical_kernels_completion_contract.report.json"))?;
    ensure(
        string_field(&report, "status", "report")? == "fail",
        "report status should fail",
    )?;
    let errors = as_array(&report["errors"], "report.errors")?;
    ensure(
        errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|text| text.contains("statistical_kernel_missing_module"))
        }),
        "report should include missing module signature",
    )
}

#[test]
fn checker_rejects_inline_unit_threshold_drift() -> TestResult {
    let root = workspace_root()?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["statistical_kernel_contract"]["modules"]["cvar"]["unit_test_min"] =
        json!(999);

    let out_dir = unique_output_dir(&root, "threshold-drift")?;
    let mutated = out_dir.join("threshold-drift.contract.json");
    write_json(&mutated, &contract)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    ensure(
        !output.status.success(),
        "checker should fail when inline test threshold drifts beyond source evidence",
    )?;
    let report = load_json(&out_dir.join("statistical_kernels_completion_contract.report.json"))?;
    let errors = as_array(&report["errors"], "report.errors")?;
    ensure(
        errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|text| text.contains("statistical_kernel_unit_test_threshold_drift"))
        }),
        "report should include inline test threshold drift signature",
    )
}
