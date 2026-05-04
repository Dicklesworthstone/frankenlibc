//! Integration test: runtime-core fixture evidence gate (bd-bp8fl.3.6).
//!
//! The gate keeps all fpg-reverse-runtime-core gap IDs visible and binds each
//! row to strict and hardened fixture or semantic-overlay evidence.

use serde_json::{Value, json};
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_GAP_IDS: &[&str] = &[
    "fp-reverse-core-311e99aff4d6",
    "fp-reverse-core-a30cbdd5d2da",
    "fp-reverse-core-422dc81789ec",
    "fp-reverse-core-bbe405ff4f84",
    "fp-reverse-core-97ef5634c70b",
    "fp-reverse-core-bdb29f3d780e",
    "fp-reverse-core-d6c0faa879a5",
    "fp-reverse-core-36e1946e7f8d",
    "fp-reverse-core-afa6d92abe42",
    "fp-reverse-core-8f333dadeb11",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "gap_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "expected",
    "actual",
    "errno",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn missing_nested_key_error(context: &str, key: &str) -> Box<dyn Error> {
    test_error(format!("{context}.{key} is missing"))
}

fn missing_input_path_error(path: &str) -> Box<dyn Error> {
    test_error(format!("{path} should exist"))
}

fn log_parse_error(index: usize, err: serde_json::Error) -> Box<dyn Error> {
    test_error(format!("log line {index} should parse: {err}"))
}

fn missing_log_field_error(index: usize, field: &str) -> Box<dyn Error> {
    test_error(format!("log line {index} missing {field}"))
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
    root.join("tests/conformance/runtime_core_fixture_evidence_gate.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/runtime_core_fixture_evidence_gate.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/runtime_core_fixture_evidence_gate.log.jsonl")
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

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, key, context)?
        .as_object()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn safe_workspace_path(root: &Path, rel: &str) -> TestResult<PathBuf> {
    let base = rel.split('#').next().unwrap_or(rel).trim_end_matches('/');
    let rel_path = Path::new(base);
    ensure(!base.is_empty(), "artifact path must be non-empty")?;
    ensure(!rel_path.is_absolute(), "artifact path must be relative")?;
    for component in rel_path.components() {
        ensure(
            matches!(component, Component::Normal(_)),
            "artifact path contains unsafe components",
        )?;
    }
    Ok(root.join(rel_path)) // ubs:ignore - rel_path is rejected unless relative with normal components only.
}

fn run_gate(root: &Path) -> TestResult<std::process::Output> {
    Command::new(root.join("scripts/check_runtime_core_fixture_evidence_gate.sh"))
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run runtime-core gate: {err}")))
}

fn run_gate_with_fixture(root: &Path, case_name: &str, gate: &Value) -> TestResult<PathBuf> {
    let out_dir = root.join("target/conformance/runtime_core_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", out_dir.display())))?;
    let gate_fixture = out_dir.join(format!("{case_name}.gate.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&gate_fixture, gate)?;

    let output = Command::new(root.join("scripts/check_runtime_core_fixture_evidence_gate.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_CORE_GATE", &gate_fixture)
        .env("FRANKENLIBC_RUNTIME_CORE_REPORT", &report)
        .env("FRANKENLIBC_RUNTIME_CORE_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run negative gate case: {err}")))?;
    ensure(
        !output.status.success(),
        format!("{case_name}: negative gate case should fail"),
    )?;
    Ok(report)
}

fn expect_failed_check(report: &Path, check: &str) -> TestResult {
    let report_json = load_json(report)?;
    ensure_eq(
        string_field(&report_json, "status", "report")?,
        "fail",
        format!("{} status", report.display()),
    )?;
    let checks = object_field(&report_json, "checks", "report")?;
    let check_status = checks
        .get(check)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("checks.{check} must be a string")))?;
    ensure_eq(check_status, "fail", format!("checks.{check}"))
}

fn mutable_rows(gate: &mut Value) -> TestResult<&mut Vec<Value>> {
    gate.get_mut("rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("rows must be mutable array"))
}

fn mutable_row(gate: &mut Value, index: usize) -> TestResult<&mut Value> {
    mutable_rows(gate)?
        .get_mut(index)
        .ok_or_else(|| test_error(format!("row {index} must exist")))
}

fn object_mut<'a>(
    value: &'a mut Value,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))
}

fn set_nested_field(
    value: &mut Value,
    path: &[&str],
    replacement: Value,
    context: &str,
) -> TestResult {
    let (leaf, parents) = path
        .split_last()
        .ok_or_else(|| test_error("nested field path must be non-empty"))?;
    let mut current = value;
    for key in parents {
        current = object_mut(current, context)?
            .get_mut(*key)
            .ok_or_else(|| missing_nested_key_error(context, key))?;
    }
    object_mut(current, context)?.insert((*leaf).to_owned(), replacement);
    Ok(())
}

fn usize_to_u64(value: usize, context: &str) -> TestResult<u64> {
    u64::try_from(value).map_err(|err| test_error(format!("{context} conversion failed: {err}")))
}

#[test]
fn gate_artifact_preserves_runtime_core_gap_contract() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path(&root))?;

    ensure_eq(
        string_field(&gate, "schema_version", "gate")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(string_field(&gate, "bead", "gate")?, "bd-bp8fl.3.6", "bead")?;
    ensure_eq(
        string_field(&gate, "owner_family_group", "gate")?,
        "fpg-reverse-runtime-core",
        "owner_family_group",
    )?;

    let inputs = object_field(&gate, "inputs", "gate")?;
    for value in inputs.values() {
        let rel = value
            .as_str()
            .ok_or_else(|| test_error("input artifact path must be a string"))?;
        if !safe_workspace_path(&root, rel)?.exists() {
            return Err(missing_input_path_error(rel));
        }
    }

    let mut required_fields = Vec::new();
    for value in array_field(&gate, "required_log_fields", "gate")? {
        required_fields.push(
            value
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))?,
        );
    }
    ensure_eq(
        required_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let rows = array_field(&gate, "rows", "gate")?;
    let row_ids = rows
        .iter()
        .map(|row| string_field(row, "gap_id", "row"))
        .collect::<TestResult<Vec<_>>>()?;
    ensure_eq(row_ids, EXPECTED_GAP_IDS.to_vec(), "runtime-core gap IDs")?;

    for row in rows {
        let cases = array_field(row, "named_unsupported_or_fallback_cases", "row")?;
        ensure(
            !cases.is_empty(),
            "every row must name fallback or unsupported cases",
        )?;
        let evidence = object_field(row, "runtime_evidence", "row")?;
        ensure(
            evidence.contains_key("strict"),
            "strict evidence is required",
        )?;
        ensure(
            evidence.contains_key("hardened"),
            "hardened evidence is required",
        )?;
    }

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_and_logs() -> TestResult {
    let root = workspace_root();
    let output = run_gate(&root)?;
    ensure(
        output.status.success(),
        format!(
            "checker should pass\nstdout:\n{}\nstderr:\n{}",
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
    let summary = object_field(&report, "summary", "report")?;
    ensure_eq(
        summary
            .get("row_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| test_error("summary.row_count must be u64"))?,
        usize_to_u64(EXPECTED_GAP_IDS.len(), "expected gap count")?,
        "summary.row_count",
    )?;
    let expected_log_count = EXPECTED_GAP_IDS
        .len()
        .checked_mul(2)
        .ok_or_else(|| test_error("expected log count overflow"))?;
    ensure_eq(
        summary
            .get("structured_log_rows")
            .and_then(Value::as_u64)
            .ok_or_else(|| test_error("summary.structured_log_rows must be u64"))?,
        usize_to_u64(expected_log_count, "expected log count")?,
        "summary.structured_log_rows",
    )?;

    let log_content = std::fs::read_to_string(log_path(&root))
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let lines: Vec<&str> = log_content.lines().collect();
    ensure_eq(
        lines.len(),
        EXPECTED_GAP_IDS.len() * 2,
        "structured log line count",
    )?;
    for (idx, line) in lines.iter().enumerate() {
        let entry: Value = serde_json::from_str(line).map_err(|err| log_parse_error(idx, err))?;
        for field in REQUIRED_LOG_FIELDS {
            if entry.get(*field).is_none() {
                return Err(missing_log_field_error(idx, field));
            }
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_gap_row() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    mutable_rows(&mut gate)?.pop();
    let report = run_gate_with_fixture(&root, "missing_gap", &gate)?;
    expect_failed_check(&report, "row_contract")
}

#[test]
fn checker_rejects_stale_source_commit() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_row(&mut gate, 0)?;
    set_nested_field(
        row,
        &["runtime_evidence", "strict", "source_commit"],
        json!("stale-source-commit"),
        "row",
    )?;
    let report = run_gate_with_fixture(&root, "stale_source_commit", &gate)?;
    expect_failed_check(&report, "runtime_mode_evidence")
}

#[test]
fn checker_rejects_unsupported_row_without_named_case() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_row(&mut gate, 2)?;
    object_mut(row, "row")?.insert("named_unsupported_or_fallback_cases".to_owned(), json!([]));
    let report = run_gate_with_fixture(&root, "unsupported_without_named_case", &gate)?;
    expect_failed_check(&report, "explicit_case_binding")
}

#[test]
fn checker_rejects_expected_actual_mismatch() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_row(&mut gate, 1)?;
    set_nested_field(
        row,
        &["runtime_evidence", "hardened", "actual"],
        json!("mismatched evidence summary"),
        "row",
    )?;
    let report = run_gate_with_fixture(&root, "expected_actual_mismatch", &gate)?;
    expect_failed_check(&report, "runtime_mode_evidence")
}
