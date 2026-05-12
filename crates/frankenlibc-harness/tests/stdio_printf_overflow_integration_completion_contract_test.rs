//! Completion-contract tests for bd-5t6zo.1 stdio printf overflow integration evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "stdio_printf_overflow_completion.source_binding",
    "stdio_printf_overflow_completion.integration_binding",
    "stdio_printf_overflow_completion.summary",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/stdio_printf_overflow_integration_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_stdio_printf_overflow_integration_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "stdio-printf-overflow-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn mutated_manifest(root: &Path, label: &str, manifest: &Value) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, label)?;
    let path = out_dir.join("contract.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report["failures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["failure_signature"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn manifest_binds_printf_integration_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("stdio_printf_overflow_integration_completion_contract.v1")
    );
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-5t6zo.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-5t6zo"));
    let sources = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| test_error("source_artifacts should be object"))?;
    for required in [
        "implementation",
        "fixture_spec",
        "integration_fixture",
        "integration_gate",
        "fixture_suite_harness",
        "completion_gate",
        "completion_harness",
    ] {
        assert!(sources.contains_key(required), "missing source {required}");
    }
    assert_eq!(
        manifest["completion_debt_evidence"]["missing_items_closed"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn checker_accepts_printf_overflow_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS stdio printf overflow integration completion contract"),
        "{}",
        output_text(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("stdio_printf_overflow_integration_completion_contract.report.v1")
    );
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-5t6zo.1"));
    assert_eq!(report["summary"]["source_count"].as_u64(), Some(7));
    assert_eq!(report["summary"]["required_event_count"].as_u64(), Some(3));

    let rows = load_jsonl(&out_dir.join("events.jsonl"))?;
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(*event), "missing event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_helper_use() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]["implementation"]["minimum_helper_uses"] = Value::from(21);
    let (path, out_dir) = mutated_manifest(&root, "helper-use", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("printf_overflow_helper_use_count_drift"));
    Ok(())
}

#[test]
fn checker_rejects_fixture_symbol_drift() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]["fixture_spec"]["required_symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_symbols should be array"))?
        .push(Value::from("printf_missing_symbol"));
    let (path, out_dir) = mutated_manifest(&root, "fixture-symbol", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("fixture_stdio_printf_spec_drift"));
    Ok(())
}

#[test]
fn checker_rejects_missing_integration_function() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]["integration_fixture"]["required_functions"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_functions should be array"))?
        .push(Value::from("test_missing_printf_contract"));
    let (path, out_dir) = mutated_manifest(&root, "integration-function", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("stdio_printf_integration_fixture_drift"));
    Ok(())
}
