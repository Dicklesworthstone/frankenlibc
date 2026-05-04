//! Integration test: runtime evidence replay gate (bd-bp8fl.9.4)
//!
//! The gate freezes replayable runtime evidence decisions for Allow,
//! FullValidate, Repair, and Deny outcomes. Missing events, stale snapshots,
//! redaction, out-of-order ring entries, and mismatched decisions fail closed.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "replay_id",
    "symbol",
    "runtime_mode",
    "replacement_level",
    "expected_decision",
    "actual_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REQUIRED_DECISIONS: &[&str] = &["Allow", "FullValidate", "Repair", "Deny"];
const REQUIRED_NEGATIVE_SIGNATURES: &[&str] = &[
    "runtime_replay_missing_event",
    "runtime_replay_stale_snapshot",
    "runtime_replay_out_of_order",
    "runtime_replay_redacted_required_field",
    "runtime_replay_decision_mismatch",
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
    root.join("tests/conformance/runtime_evidence_replay_gate.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/runtime_evidence_replay_gate.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/runtime_evidence_replay_gate.log.jsonl")
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

fn set_object_field(
    value: &mut Value,
    key: &str,
    replacement: Value,
    context: &str,
) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    object.insert(key.to_owned(), replacement);
    Ok(())
}

fn set_snapshot_field(record: &mut Value, key: &str, replacement: Value) -> TestResult {
    let snapshot = record
        .get_mut("evidence_snapshot")
        .ok_or_else(|| test_error("record.evidence_snapshot is missing"))?;
    set_object_field(snapshot, key, replacement, "record.evidence_snapshot")
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
    Command::new(root.join("scripts/check_runtime_evidence_replay_gate.sh"))
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run runtime evidence replay gate: {err}")))
}

fn run_gate_with_fixture(root: &Path, case_name: &str, gate: &Value) -> TestResult<PathBuf> {
    let out_dir = root.join("target/conformance/runtime_evidence_replay_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", out_dir.display())))?;
    let gate_fixture = out_dir.join(format!("{case_name}.gate.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&gate_fixture, gate)?;

    let output = Command::new(root.join("scripts/check_runtime_evidence_replay_gate.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_GATE", &gate_fixture)
        .env("FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_REPORT", &report)
        .env("FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_LOG", &log)
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

fn mutable_replay_records(gate: &mut Value) -> TestResult<&mut Vec<Value>> {
    gate.get_mut("replay_records")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("replay_records must be a mutable array"))
}

#[test]
fn gate_artifact_covers_runtime_evidence_replay_contract() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path(&root))?;
    ensure_eq(
        string_field(&gate, "schema_version", "gate")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(string_field(&gate, "bead", "gate")?, "bd-bp8fl.9.4", "bead")?;

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

    let records = as_array(field(&gate, "replay_records", "gate")?, "replay_records")?;
    let decisions = records
        .iter()
        .filter_map(|record| record.get("expected_decision").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let expected_decisions = REQUIRED_DECISIONS.iter().copied().collect::<BTreeSet<_>>();
    ensure_eq(decisions, expected_decisions, "decision coverage")?;

    let mut modes = BTreeSet::new();
    for record in records {
        modes.insert(string_field(record, "runtime_mode", "record")?);
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
    ensure(modes.contains("strict"), "strict replay mode is required")?;
    ensure(
        modes.contains("hardened"),
        "hardened replay mode is required",
    )?;

    let negative_cases = as_array(
        field(&gate, "negative_replay_cases", "gate")?,
        "negative_replay_cases",
    )?;
    let signatures = negative_cases
        .iter()
        .filter_map(|case| {
            case.get("expected_failure_signature")
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let expected_signatures = REQUIRED_NEGATIVE_SIGNATURES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
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
        field(summary, "replay_record_count", "report.summary")?.as_u64(),
        Some(4),
        "report replay_record_count",
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
    ensure_eq(line_count, 9usize, "structured log row count")
}

#[test]
fn gate_fails_closed_when_replay_event_is_missing() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_replay_records(&mut gate)?
        .get_mut(0)
        .ok_or_else(|| test_error("missing first replay record"))?;
    set_snapshot_field(record, "event_ids", json!([]))?;
    let report = run_gate_with_fixture(&root, "missing_event", &gate)?;
    expect_error_signature(&report, "runtime_replay_missing_event")
}

#[test]
fn gate_fails_closed_for_out_of_order_ring_events() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_replay_records(&mut gate)?
        .get_mut(2)
        .ok_or_else(|| test_error("missing repair replay record"))?;
    set_snapshot_field(record, "event_ids", json!([
        "ev-1020-policy",
        "ev-1023-heal",
        "ev-1022-generation",
        "ev-1024-repair"
    ]))?;
    let report = run_gate_with_fixture(&root, "out_of_order_events", &gate)?;
    expect_error_signature(&report, "runtime_replay_out_of_order")
}

#[test]
fn gate_fails_closed_for_redacted_required_field() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_replay_records(&mut gate)?
        .get_mut(3)
        .ok_or_else(|| test_error("missing deny replay record"))?;
    set_snapshot_field(record, "redaction_state", json!("required_field_redacted"))?;
    let report = run_gate_with_fixture(&root, "redacted_required_field", &gate)?;
    expect_error_signature(&report, "runtime_replay_redacted_required_field")
}

#[test]
fn gate_fails_closed_for_stale_snapshot() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_replay_records(&mut gate)?
        .get_mut(1)
        .ok_or_else(|| test_error("missing full-validate replay record"))?;
    set_snapshot_field(record, "snapshot_age_state", json!("stale"))?;
    let report = run_gate_with_fixture(&root, "stale_snapshot", &gate)?;
    expect_error_signature(&report, "runtime_replay_stale_snapshot")
}

#[test]
fn gate_fails_closed_for_decision_mismatch() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let record = mutable_replay_records(&mut gate)?
        .get_mut(2)
        .ok_or_else(|| test_error("missing repair replay record"))?;
    set_object_field(record, "actual_decision", json!("Allow"), "record")?;
    let report = run_gate_with_fixture(&root, "decision_mismatch", &gate)?;
    expect_error_signature(&report, "runtime_replay_decision_mismatch")
}
