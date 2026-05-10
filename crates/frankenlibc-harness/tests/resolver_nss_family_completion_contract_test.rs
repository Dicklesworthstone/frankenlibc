//! Completion-contract tests for bd-ldj.3.1 resolver/NSS family evidence.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_SYMBOLS: &[&str] = &["getaddrinfo", "gethostbyname", "getpwnam", "getgrnam"];
const EXPECTED_MISSING_ITEMS: &[(&str, &str)] = &[
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("conformance_primary", "tests.conformance.primary"),
];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "api_family",
    "symbol",
    "fixture_case_count",
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
    ensure(!rel_path.is_absolute(), "workspace path must be relative")?;
    for component in rel_path.components() {
        ensure(
            matches!(component, Component::Normal(_)),
            "workspace path contains unsafe components",
        )?;
    }
    Ok(root.join(rel_path)) // ubs:ignore - rel_path is rejected unless relative with only normal components.
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/resolver_nss_family_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_resolver_nss_family_completion_contract.sh")
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

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
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
    let text = std::fs::read_to_string(path)?;
    let lines = text.lines().collect::<Vec<_>>();
    ensure(
        line_no <= lines.len(),
        format!("file-line ref outside file: {file_line_ref}"),
    )?;
    ensure(
        !lines[line_no - 1].trim().is_empty(),
        format!("file-line ref should not cite a blank line: {file_line_ref}"),
    )
}

fn function_exists(source_text: &str, name: &str) -> bool {
    source_text.contains(&format!("fn {name}"))
}

fn load_test_sources(root: &Path, evidence: &Value) -> TestResult<BTreeMap<String, String>> {
    let mut source_texts = BTreeMap::new();
    for (source_name, path) in as_object(&evidence["test_sources"], "test_sources")? {
        let rel = path
            .as_str()
            .ok_or_else(|| test_error("test source path must be a string"))?;
        source_texts.insert(
            source_name.clone(),
            std::fs::read_to_string(safe_workspace_path(root, rel)?)?,
        );
    }
    Ok(source_texts)
}

fn validate_test_refs(evidence: &Value, source_texts: &BTreeMap<String, String>) -> TestResult {
    for (section_name, missing_item_id) in EXPECTED_MISSING_ITEMS {
        let section = &evidence[*section_name];
        ensure(
            string_field(section, "missing_item_id", section_name)? == *missing_item_id,
            format!("{section_name} missing_item_id drifted"),
        )?;
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
        "resolver-nss-family-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RESOLVER_NSS_FAMILY_CONTRACT", contract)
        .env(
            "FRANKENLIBC_RESOLVER_NSS_FAMILY_REPORT",
            out_dir.join("resolver_nss_family_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RESOLVER_NSS_FAMILY_LOG",
            out_dir.join("resolver_nss_family_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn symbol_set(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .filter_map(|row| row.get("symbol").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

#[test]
fn contract_binds_resolver_nss_unit_e2e_and_conformance_evidence() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&contract_path(&root))?;
    ensure(
        string_field(&contract, "schema_version", "contract")?
            == "resolver_nss_family_completion_contract.v1",
        "schema_version drifted",
    )?;
    ensure(
        string_field(&contract, "bead", "contract")? == "bd-ldj.3",
        "original bead drifted",
    )?;
    ensure(
        string_field(&contract, "completion_debt_bead", "contract")? == "bd-ldj.3.1",
        "completion debt bead drifted",
    )?;

    let evidence = &contract["completion_debt_evidence"];
    ensure(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .unwrap_or_default()
            >= 800,
        "completion contract should target a passing audit score",
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

    let bindings = as_array(&evidence["missing_item_bindings"], "missing_item_bindings")?
        .iter()
        .map(|binding| {
            Ok((
                string_field(binding, "evidence_section", "binding")?.to_string(),
                string_field(binding, "missing_item_id", "binding")?.to_string(),
            ))
        })
        .collect::<TestResult<BTreeSet<_>>>()?;
    let expected_bindings = EXPECTED_MISSING_ITEMS
        .iter()
        .map(|(section, item)| ((*section).to_string(), (*item).to_string()))
        .collect::<BTreeSet<_>>();
    ensure(
        bindings == expected_bindings,
        "missing item bindings should cover unit, e2e, and conformance",
    )?;

    let symbols = as_array(&evidence["required_symbols"], "required_symbols")?;
    ensure(
        symbol_set(symbols)
            == EXPECTED_SYMBOLS
                .iter()
                .map(|symbol| (*symbol).to_string())
                .collect(),
        "required_symbols should bind exactly the resolver/NSS family surface",
    )?;

    let source_texts = load_test_sources(&root, evidence)?;
    validate_test_refs(evidence, &source_texts)?;

    for symbol in symbols {
        file_line_ref_exists(&root, string_field(symbol, "abi_ref", "symbol")?)?;
        for core_ref in as_array(&symbol["core_refs"], "core_refs")? {
            file_line_ref_exists(
                &root,
                core_ref
                    .as_str()
                    .ok_or_else(|| test_error("core ref must be a string"))?,
            )?;
        }
        ensure(
            symbol["fixture_case_min"].as_u64().unwrap_or_default() >= 2,
            "each symbol must require fixture coverage",
        )?;
        for mode in ["strict", "hardened"] {
            ensure(
                as_array(&symbol["required_modes"], "required_modes")?
                    .iter()
                    .any(|value| value.as_str() == Some(mode)),
                format!("symbol should require {mode} mode"),
            )?;
        }
    }
    Ok(())
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

    let report = load_json(&out_dir.join("resolver_nss_family_completion_contract.report.json"))?;
    ensure(
        string_field(&report, "status", "report")? == "pass",
        "report status should pass",
    )?;
    ensure(
        report["summary"]["bound_symbol_count"].as_u64() == Some(EXPECTED_SYMBOLS.len() as u64),
        "report should bind every required symbol",
    )?;
    ensure(
        report["summary"]["fixture_case_count"]
            .as_u64()
            .unwrap_or_default()
            >= 14,
        "report should count resolver, passwd, and group fixtures",
    )?;

    let rows = read_jsonl(&out_dir.join("resolver_nss_family_completion_contract.log.jsonl"))?;
    ensure(!rows.is_empty(), "checker should emit JSONL rows")?;
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    ensure(
        events.contains("resolver_nss_family_completion_contract_validated"),
        "checker should emit pass event",
    )?;
    ensure(
        events.contains("resolver_nss_family_symbol_bound"),
        "checker should emit per-symbol events",
    )?;
    ensure(
        events.contains("resolver_nss_family_completion_summary"),
        "checker should emit summary event",
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
fn checker_rejects_missing_getpwnam_symbol_binding() -> TestResult {
    let root = workspace_root()?;
    let mut contract = load_json(&contract_path(&root))?;
    let symbols = contract["completion_debt_evidence"]["required_symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_symbols should be mutable"))?;
    symbols.retain(|row| row["symbol"].as_str() != Some("getpwnam"));

    let out_dir = unique_output_dir(&root, "missing-getpwnam")?;
    let mutated = out_dir.join("missing-getpwnam.contract.json");
    write_json(&mutated, &contract)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    ensure(
        !output.status.success(),
        "checker should fail when getpwnam binding is missing",
    )?;
    let report = load_json(&out_dir.join("resolver_nss_family_completion_contract.report.json"))?;
    let errors = as_array(&report["errors"], "report.errors")?;
    ensure(
        errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|text| text.contains("required_symbols missing: getpwnam"))
        }),
        "report should include missing getpwnam binding",
    )
}

#[test]
fn checker_rejects_stale_conformance_test_ref() -> TestResult {
    let root = workspace_root()?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["conformance_primary"]["required_test_refs"] = json!([
        {
            "source": "resolver_conformance",
            "name": "stale_missing_resolver_test"
        }
    ]);

    let out_dir = unique_output_dir(&root, "stale-conformance-ref")?;
    let mutated = out_dir.join("stale-conformance-ref.contract.json");
    write_json(&mutated, &contract)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    ensure(
        !output.status.success(),
        "checker should fail when conformance refs go stale",
    )?;
    let report = load_json(&out_dir.join("resolver_nss_family_completion_contract.report.json"))?;
    let errors = as_array(&report["errors"], "report.errors")?;
    ensure(
        errors.iter().any(|error| {
            error.as_str().is_some_and(|text| {
                text.contains(
                    "conformance_primary.required_test_refs: test ref missing resolver_conformance.stale_missing_resolver_test",
                )
            })
        }),
        "report should include stale conformance test ref",
    )
}
