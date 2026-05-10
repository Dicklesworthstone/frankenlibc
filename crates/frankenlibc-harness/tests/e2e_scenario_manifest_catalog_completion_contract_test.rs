//! Contract tests for bd-b5a.1.1 deterministic E2E scenario-manifest evidence.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_CLASSES: &[(&str, usize)] =
    &[("smoke", 13), ("stress", 2), ("fault", 3), ("stability", 1)];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "scenario_class",
    "scenario_count",
    "manifest_id",
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
    root.join("tests/conformance/e2e_scenario_manifest_catalog_completion_contract.v1.json")
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
        "e2e-scenario-catalog-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_e2e_scenario_manifest_catalog_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_E2E_SCENARIO_CATALOG_CONTRACT", contract)
        .env(
            "FRANKENLIBC_E2E_SCENARIO_CATALOG_REPORT",
            out_dir.join("e2e_scenario_manifest_catalog_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_E2E_SCENARIO_CATALOG_LOG",
            out_dir.join("e2e_scenario_manifest_catalog_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn required_class_set() -> BTreeSet<&'static str> {
    REQUIRED_CLASSES
        .iter()
        .map(|(scenario_class, _)| *scenario_class)
        .collect()
}

#[test]
fn contract_binds_e2e_scenario_manifest_unit_and_e2e_evidence() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&contract_path(&root))?;
    ensure(
        string_field(&contract, "schema_version", "contract")?
            == "e2e_scenario_manifest_catalog_completion_contract.v1",
        "schema_version drifted",
    )?;
    ensure(
        string_field(&contract, "bead", "contract")? == "bd-b5a.1",
        "bead drifted",
    )?;
    ensure(
        string_field(&contract, "completion_debt_bead", "contract")? == "bd-b5a.1.1",
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

    let manifest_contract = &evidence["scenario_manifest_contract"];
    ensure(
        string_field(
            manifest_contract,
            "required_manifest_id",
            "scenario_manifest_contract",
        )? == "bd-b5a.1-e2e-scenario-catalog",
        "manifest id binding drifted",
    )?;
    ensure(
        manifest_contract["total_scenario_min"]
            .as_u64()
            .unwrap_or_default()
            >= 19,
        "scenario count minimum should bind the current catalog",
    )?;

    let required_classes = as_array(&manifest_contract["required_classes"], "required_classes")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    ensure(
        required_class_set().is_subset(&required_classes),
        "manifest contract should require all scenario classes",
    )?;

    let manifest_rel = string_field(manifest_contract, "manifest_path", "manifest_contract")?;
    let manifest = load_json(&safe_workspace_path(&root, manifest_rel)?)?;
    ensure(
        string_field(&manifest, "manifest_id", "manifest")? == "bd-b5a.1-e2e-scenario-catalog",
        "manifest_id drifted",
    )?;
    let scenarios = as_array(&manifest["scenarios"], "manifest.scenarios")?;
    ensure(
        scenarios.len() >= 19,
        "manifest should retain the original 19 scenario minimum",
    )?;

    let mut class_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut scenario_ids = BTreeSet::new();
    for scenario in scenarios {
        let scenario_class = string_field(scenario, "class", "scenario")?;
        *class_counts.entry(scenario_class.to_string()).or_default() += 1;
        scenario_ids.insert(string_field(scenario, "id", "scenario")?.to_string());
    }
    for (scenario_class, required_count) in REQUIRED_CLASSES {
        ensure(
            class_counts
                .get(*scenario_class)
                .copied()
                .unwrap_or_default()
                >= *required_count,
            format!("{scenario_class} scenario count below bound"),
        )?;
    }
    for id in as_array(
        &manifest_contract["representative_scenario_ids"],
        "representative_scenario_ids",
    )? {
        let id = id
            .as_str()
            .ok_or_else(|| test_error("representative scenario id must be a string"))?;
        ensure(
            scenario_ids.contains(id),
            format!("representative scenario id should exist: {id}"),
        )?;
    }

    let validator = std::fs::read_to_string(safe_workspace_path(
        &root,
        string_field(
            &evidence["artifacts"],
            "manifest_validator",
            "artifacts.manifest_validator",
        )?,
    )?)?;
    for token in as_array(
        &evidence["validator_contract"]["required_tokens"],
        "validator.required_tokens",
    )? {
        let token = token
            .as_str()
            .ok_or_else(|| test_error("validator token must be a string"))?;
        ensure(
            validator.contains(token),
            format!("validator should contain token {token}"),
        )?;
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

    let report =
        load_json(&out_dir.join("e2e_scenario_manifest_catalog_completion_contract.report.json"))?;
    ensure(
        string_field(&report, "status", "report")? == "pass",
        "report status should pass",
    )?;
    ensure(
        report["summary"]["manifest_id"].as_str() == Some("bd-b5a.1-e2e-scenario-catalog"),
        "report should bind the scenario manifest id",
    )?;
    ensure(
        report["summary"]["scenario_count"]
            .as_u64()
            .unwrap_or_default()
            >= 19,
        "report should count all scenario catalog entries",
    )?;
    ensure(
        report["summary"]["bound_class_count"].as_u64() == Some(REQUIRED_CLASSES.len() as u64),
        "report should bind every required scenario class",
    )?;

    let rows =
        read_jsonl(&out_dir.join("e2e_scenario_manifest_catalog_completion_contract.log.jsonl"))?;
    ensure(!rows.is_empty(), "checker should emit JSONL rows")?;
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    ensure(
        events.contains("e2e_scenario_manifest_catalog_completion_contract_validated"),
        "checker should emit pass event",
    )?;
    ensure(
        events.contains("e2e_scenario_manifest_class_bound"),
        "checker should emit class binding events",
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
fn checker_rejects_missing_fault_class_binding() -> TestResult {
    let root = workspace_root()?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["scenario_manifest_contract"]["class_minimums"]
        .as_object_mut()
        .ok_or_else(|| test_error("class_minimums should be mutable"))?
        .remove("fault");

    let out_dir = unique_output_dir(&root, "missing-fault")?;
    let mutated = out_dir.join("missing-fault.contract.json");
    write_json(&mutated, &contract)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    ensure(
        !output.status.success(),
        "checker should fail when fault class binding is missing",
    )?;
    let report =
        load_json(&out_dir.join("e2e_scenario_manifest_catalog_completion_contract.report.json"))?;
    ensure(
        string_field(&report, "status", "report")? == "fail",
        "report status should fail",
    )?;
    let errors = as_array(&report["errors"], "report.errors")?;
    ensure(
        errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|text| text.contains("class minimum for fault below required"))
        }),
        "report should include missing fault binding signature",
    )
}

#[test]
fn checker_rejects_stale_test_binding() -> TestResult {
    let root = workspace_root()?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["unit_primary"]["required_test_refs"] = json!([
        {
            "source": "manifest_validation",
            "name": "stale_missing_test_name"
        }
    ]);

    let out_dir = unique_output_dir(&root, "stale-test")?;
    let mutated = out_dir.join("stale-test.contract.json");
    write_json(&mutated, &contract)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    ensure(
        !output.status.success(),
        "checker should fail when test binding is stale",
    )?;
    let report =
        load_json(&out_dir.join("e2e_scenario_manifest_catalog_completion_contract.report.json"))?;
    let errors = as_array(&report["errors"], "report.errors")?;
    ensure(
        errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|text| text.contains("unit_primary: test ref missing"))
        }),
        "report should include stale test binding signature",
    )
}
