//! Integration test: full conformance fixture schema validation gate.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn gate_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("jsonl should be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl row should parse"))
        .collect()
}

fn unique_temp_dir(root: &Path, name: &str) -> PathBuf {
    let path = root.join("target/conformance").join(format!(
        "fixture_schema_validation_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn run_checker(root: &Path, fixtures_override: Option<&Path>) -> std::process::Output {
    let script = root.join("scripts/check_fixture_schema_validation.sh");
    let mut command = Command::new(&script);
    command.current_dir(root).arg("--validate-only");
    if let Some(path) = fixtures_override {
        command.env("FIXTURE_SCHEMA_VALIDATION_FIXTURES_DIR", path);
    }
    command
        .output()
        .expect("failed to run fixture schema validation checker")
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path = root.join("target/conformance/fixture_schema_validation.report.json");
    let log_path = root.join("target/conformance/fixture_schema_validation.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some(expected_signature)
    );
    assert!(
        report["trace_id"].is_string(),
        "failure report missing trace_id"
    );

    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("fixture_schema_validation_failed"))
        .expect("failure event should be logged");
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
}

#[test]
fn contract_declares_full_fixture_schema_gate() {
    let root = workspace_root();
    let contract = load_json(&root.join("tests/conformance/fixture_schema_validation.v1.json"));
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("fixture_schema_validation.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.6"));
    assert_eq!(
        contract["input_policy_artifact"]["policy_id"].as_str(),
        Some("adapter_normalized_tagged_values")
    );
    assert_eq!(
        contract["expected_inventory"]["fixture_file_count"].as_u64(),
        Some(127)
    );
    assert_eq!(
        contract["expected_inventory"]["standard_case_count"].as_u64(),
        Some(2787)
    );
    assert_eq!(
        contract["expected_inventory"]["expected_errno_optional_cases"].as_u64(),
        Some(42)
    );
}

#[test]
fn checker_passes_for_current_fixture_corpus() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&root.join("target/conformance/fixture_schema_validation.report.json"));
    assert_eq!(
        report["schema_version"].as_str(),
        Some("fixture_schema_validation.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.6"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["fixture_file_count"].as_u64(), Some(127));
    assert_eq!(
        report["summary"]["standard_case_count"].as_u64(),
        Some(2787)
    );
    assert_eq!(
        report["summary"]["primary_expectation_tags"]["expected_output"].as_u64(),
        Some(2670)
    );
    assert_eq!(
        report["summary"]["primary_expectation_tags"]["expected_return+expected_values"].as_u64(),
        Some(106)
    );
    assert!(
        report["source_commit"].is_string(),
        "source commit should be recorded"
    );

    let rows = load_jsonl(&root.join("target/conformance/fixture_schema_validation.log.jsonl"));
    let event = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("fixture_schema_validation_validated"))
        .expect("pass event should be logged");
    assert_eq!(event["outcome"].as_str(), Some("pass"));
}

#[test]
fn checker_rejects_missing_expected_errno_where_required() {
    let _guard = gate_lock();
    let root = workspace_root();
    let fixture_dir = unique_temp_dir(&root, "missing_errno");
    write_json(
        &fixture_dir.join("time_ops.json"),
        &serde_json::json!({
            "version": "v1",
            "family": "time_ops",
            "captured_at": "2026-05-06T00:00:00Z",
            "cases": [{
                "name": "time_missing_errno",
                "function": "time",
                "spec_section": "POSIX time",
                "inputs": {},
                "expected_output": "POSITIVE_INT",
                "mode": "strict"
            }]
        }),
    );

    let output = run_checker(&root, Some(&fixture_dir));
    assert!(
        !output.status.success(),
        "checker should reject missing expected_errno"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fixture_case_missing_expected_errno"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "fixture_case_missing_expected_errno");
}

#[test]
fn checker_rejects_invalid_expected_output_shape() {
    let _guard = gate_lock();
    let root = workspace_root();
    let fixture_dir = unique_temp_dir(&root, "invalid_output_shape");
    write_json(
        &fixture_dir.join("printf_conformance.json"),
        &serde_json::json!({
            "version": "v1",
            "family": "printf_conformance",
            "captured_at": "2026-05-06T00:00:00Z",
            "cases": [{
                "name": "sprintf_bad_bytes",
                "function": "sprintf",
                "spec_section": "C11 7.21.6.1",
                "inputs": {"format": "x"},
                "expected_output_bytes": "not-bytes",
                "expected_errno": 0,
                "mode": "strict"
            }]
        }),
    );

    let output = run_checker(&root, Some(&fixture_dir));
    assert!(
        !output.status.success(),
        "checker should reject invalid expected_output_bytes shape"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fixture_case_invalid_expectation_shape"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "fixture_case_invalid_expectation_shape");
}

#[test]
fn checker_rejects_unsupported_scenario_without_expected_outcome() {
    let _guard = gate_lock();
    let root = workspace_root();
    let fixture_dir = unique_temp_dir(&root, "unsupported_missing_outcome");
    write_json(
        &fixture_dir.join("setjmp_nested_edges.json"),
        &serde_json::json!({
            "version": "v1",
            "schema_version": "v1",
            "family": "setjmp_nested_edges",
            "captured_at": "2026-05-06T00:00:00Z",
            "unsupported_scenarios": [{
                "scenario_id": "cross_thread_longjmp",
                "expected_errno": "ENOSYS"
            }]
        }),
    );

    let output = run_checker(&root, Some(&fixture_dir));
    assert!(
        !output.status.success(),
        "checker should reject unsupported scenario without expected_outcome"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unsupported_scenario_missing_expected_outcome"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "unsupported_scenario_missing_expected_outcome");
}

#[test]
fn checker_rejects_unclassified_fixture_file() {
    let _guard = gate_lock();
    let root = workspace_root();
    let fixture_dir = unique_temp_dir(&root, "unclassified_file");
    write_json(
        &fixture_dir.join("skipped.json"),
        &serde_json::json!({
            "version": "v1",
            "family": "skipped",
            "captured_at": "2026-05-06T00:00:00Z"
        }),
    );

    let output = run_checker(&root, Some(&fixture_dir));
    assert!(
        !output.status.success(),
        "checker should reject unclassified fixture file"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fixture_file_unclassified"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "fixture_file_unclassified");
}
