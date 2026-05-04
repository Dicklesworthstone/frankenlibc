//! Integration test: runtime risk monitor calibration gate (bd-bp8fl.9.5)
//!
//! The gate freezes calibration records for e-process, changepoint, CVaR,
//! conformal, and risk monitors. Stale outcomes, threshold mismatches,
//! disabled monitors, and false-positive/false-negative budget overruns fail
//! closed.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "monitor_id",
    "fixture_set",
    "threshold",
    "expected_alarm",
    "actual_alarm",
    "risk_value",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REQUIRED_MONITORS: &[&str] = &["eprocess", "changepoint", "cvar", "conformal", "risk"];
const REQUIRED_SIGNATURES: &[&str] = &[
    "runtime_calibration_stale_fixture_outcomes",
    "runtime_calibration_threshold_edge_case_mismatch",
    "runtime_calibration_disabled_monitor",
    "runtime_calibration_false_positive_budget_exceeded",
    "runtime_calibration_false_negative_budget_exceeded",
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

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {:?}, got {:?}",
            context.into(),
            expected,
            actual
        )))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn gate_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_risk_monitor_calibration.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/runtime_risk_monitor_calibration.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/runtime_risk_monitor_calibration.log.jsonl")
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

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
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

fn set_object_field(value: &mut Value, key: &str, replacement: Value, context: &str) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    object.insert(key.to_owned(), replacement);
    Ok(())
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

fn run_gate(root: &Path) -> TestResult<std::process::Output> {
    Command::new(root.join("scripts/check_runtime_risk_monitor_calibration.sh"))
        .current_dir(root)
        .output()
        .map_err(|err| {
            test_error(format!(
                "failed to run runtime risk calibration gate: {err}"
            ))
        })
}

fn run_gate_with_fixture(root: &Path, case_name: &str, gate: &Value) -> TestResult<PathBuf> {
    let out_dir = root.join("target/conformance/runtime_risk_monitor_calibration_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", out_dir.display())))?;
    let gate_fixture = out_dir.join(format!("{case_name}.gate.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&gate_fixture, gate)?;

    let output = Command::new(root.join("scripts/check_runtime_risk_monitor_calibration.sh"))
        .current_dir(root)
        .env(
            "FRANKENLIBC_RUNTIME_RISK_MONITOR_CALIBRATION",
            &gate_fixture,
        )
        .env(
            "FRANKENLIBC_RUNTIME_RISK_MONITOR_CALIBRATION_REPORT",
            &report,
        )
        .env("FRANKENLIBC_RUNTIME_RISK_MONITOR_CALIBRATION_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run negative gate case: {err}")))?;
    ensure(
        !output.status.success(),
        format!("{case_name}: negative gate case should fail"),
    )?;
    Ok(report)
}

fn expect_error_signature(report: &Path, signature: &str) -> TestResult {
    let report_json = load_json(report)?;
    ensure_eq(
        string_field(&report_json, "status", "report")?,
        "fail",
        format!("{} status", report.display()),
    )?;
    let errors = as_array(field(&report_json, "errors", "report")?, "report.errors")?;
    ensure(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(signature)),
        format!("report errors should include {signature}"),
    )
}

fn mutable_records(gate: &mut Value) -> TestResult<&mut Vec<Value>> {
    gate.get_mut("calibration_records")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("calibration_records must be a mutable array"))
}

#[test]
fn gate_artifact_covers_runtime_risk_monitor_calibration_contract() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path(&root))?;
    ensure_eq(
        string_field(&gate, "schema_version", "gate")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(string_field(&gate, "bead", "gate")?, "bd-bp8fl.9.5", "bead")?;

    let inputs = as_object(field(&gate, "inputs", "gate")?, "inputs")?;
    for value in inputs.values() {
        let rel = value
            .as_str()
            .ok_or_else(|| test_error("input artifact path must be a string"))?;
        ensure(
            safe_workspace_path(&root, rel)?.exists(),
            "input artifact path points at missing file",
        )?;
    }

    let required_fields: Vec<&str> = as_array(
        field(&gate, "required_log_fields", "gate")?,
        "required_log_fields",
    )?
    .iter()
    .map(|value| value.as_str().unwrap_or_default())
    .collect();
    ensure_eq(
        required_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let records = as_array(
        field(&gate, "calibration_records", "gate")?,
        "calibration_records",
    )?;
    let monitors = records
        .iter()
        .filter_map(|record| record.get("monitor_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let expected_monitors = REQUIRED_MONITORS.iter().copied().collect::<BTreeSet<_>>();
    ensure_eq(monitors, expected_monitors, "monitor coverage")?;

    let modes = records
        .iter()
        .filter_map(|record| record.get("runtime_mode").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    ensure(
        modes.contains("strict"),
        "strict calibration mode is required",
    )?;
    ensure(
        modes.contains("hardened"),
        "hardened calibration mode is required",
    )?;

    for record in records {
        let refs = as_array(field(record, "artifact_refs", "record")?, "artifact_refs")?;
        ensure(!refs.is_empty(), "artifact_refs must not be empty")?;
        for rel in refs {
            let path = rel
                .as_str()
                .ok_or_else(|| test_error("artifact_refs entries must be strings"))?;
            ensure(
                safe_workspace_path(&root, path)?.exists(),
                "artifact_refs entry points at missing file",
            )?;
        }
    }

    let negative_cases = as_array(
        field(&gate, "negative_calibration_cases", "gate")?,
        "negative_calibration_cases",
    )?;
    let signatures = negative_cases
        .iter()
        .filter_map(|case| {
            case.get("expected_failure_signature")
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let expected_signatures = REQUIRED_SIGNATURES.iter().copied().collect::<BTreeSet<_>>();
    ensure_eq(
        signatures,
        expected_signatures,
        "negative signature coverage",
    )
}

#[test]
fn gate_script_passes_and_emits_report_and_jsonl_log() -> TestResult {
    let root = workspace_root();
    let output = run_gate(&root)?;
    ensure(
        output.status.success(),
        format!(
            "gate script failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&report_path(&root))?;
    ensure_eq(
        string_field(&report, "status", "report")?,
        "pass",
        "report status",
    )?;
    let summary = field(&report, "summary", "report")?;
    ensure_eq(
        field(summary, "calibration_record_count", "report.summary")?.as_u64(),
        Some(5),
        "report calibration_record_count",
    )?;

    let log = std::fs::read_to_string(log_path(&root))
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let mut line_count = 0usize;
    for line in log.lines() {
        line_count += 1;
        let entry: Value = serde_json::from_str(line)
            .map_err(|_| test_error("structured log entry should parse"))?;
        for field_name in REQUIRED_LOG_FIELDS {
            ensure(
                entry.get(*field_name).is_some(),
                "structured log entry is missing a required field",
            )?;
        }
    }
    ensure_eq(line_count, 10usize, "structured log row count")
}

#[test]
fn gate_fails_closed_for_stale_fixture_outcomes() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_records(&mut gate)?
        .get_mut(0)
        .ok_or_else(|| test_error("missing first calibration record"))?;
    set_object_field(
        record,
        "fixture_outcome_state",
        json!("stale"),
        "calibration_record",
    )?;
    let report = run_gate_with_fixture(&root, "stale_fixture_outcomes", &gate)?;
    expect_error_signature(&report, "runtime_calibration_stale_fixture_outcomes")
}

#[test]
fn gate_fails_closed_for_threshold_edge_case_mismatch() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_records(&mut gate)?
        .get_mut(1)
        .ok_or_else(|| test_error("missing changepoint calibration record"))?;
    set_object_field(record, "actual_alarm", json!(false), "calibration_record")?;
    let report = run_gate_with_fixture(&root, "threshold_edge_case_mismatch", &gate)?;
    expect_error_signature(&report, "runtime_calibration_threshold_edge_case_mismatch")
}

#[test]
fn gate_fails_closed_for_disabled_monitor() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_records(&mut gate)?
        .get_mut(2)
        .ok_or_else(|| test_error("missing cvar calibration record"))?;
    set_object_field(
        record,
        "monitor_state",
        json!("disabled"),
        "calibration_record",
    )?;
    let report = run_gate_with_fixture(&root, "disabled_monitor", &gate)?;
    expect_error_signature(&report, "runtime_calibration_disabled_monitor")
}

#[test]
fn gate_fails_closed_for_false_positive_budget_overrun() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_records(&mut gate)?
        .get_mut(3)
        .ok_or_else(|| test_error("missing conformal calibration record"))?;
    set_object_field(
        record,
        "false_positive_count",
        json!(1),
        "calibration_record",
    )?;
    let report = run_gate_with_fixture(&root, "false_positive_budget", &gate)?;
    expect_error_signature(
        &report,
        "runtime_calibration_false_positive_budget_exceeded",
    )
}

#[test]
fn gate_fails_closed_for_false_negative_budget_overrun() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_records(&mut gate)?
        .get_mut(4)
        .ok_or_else(|| test_error("missing risk calibration record"))?;
    set_object_field(
        record,
        "false_negative_count",
        json!(1),
        "calibration_record",
    )?;
    let report = run_gate_with_fixture(&root, "false_negative_budget", &gate)?;
    expect_error_signature(
        &report,
        "runtime_calibration_false_negative_budget_exceeded",
    )
}
