//! Integration tests for signal/setjmp async-cancellation fixtures (bd-bp8fl.5.8).

use serde_json::{Value, json};
use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "fixture_id",
    "signal",
    "mask_state",
    "jump_state",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "status",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_SCENARIO_KINDS: &[&str] = &[
    "signal_mask_change",
    "handler_longjmp",
    "nested_blocked_signal",
    "async_signal_safe_call",
    "cancellation_blocking_syscall",
    "pthread_cleanup_interaction",
    "sigsetjmp_mask_restore",
    "negative_timeout",
    "unsupported_async_boundary",
];

const REQUIRED_TIMEOUT_CLASSIFICATIONS: &[&str] = &[
    "not_applicable",
    "bounded_wait_pass",
    "expected_eintr",
    "expected_timeout",
    "unsupported_deferred",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/signal_setjmp_async_cancellation_fixture_pack.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_signal_setjmp_async_cancellation_fixture_pack.sh")
}

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

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
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

fn object_field_mut<'a>(
    value: &'a mut Value,
    key: &str,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .get_mut(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn mutable_rows(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("fixture_rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.fixture_rows must be mutable array"))
}

fn mutable_row(manifest: &mut Value, index: usize) -> TestResult<&mut Value> {
    mutable_rows(manifest)?
        .get_mut(index)
        .ok_or_else(|| test_error(format!("manifest.fixture_rows[{index}] must exist")))
}

fn set_string_field(value: &mut Value, key: &str, new_value: &str, context: &str) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    if object.insert(key.to_owned(), json!(new_value)).is_some() {
        Ok(())
    } else {
        Err(test_error(format!("{context}.{key} is missing")))
    }
}

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_OUT_DIR", out_dir)
        .env(
            "FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_REPORT",
            out_dir.join("signal-setjmp-async-cancellation.report.json"),
        )
        .env(
            "FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_LOG",
            out_dir.join("signal-setjmp-async-cancellation.log.jsonl"),
        )
        .env("FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run signal/setjmp gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("signal-setjmp-async-cancellation.report.json");
    write_json(&manifest_fixture, manifest)?;
    let output = run_gate(root, Some(&manifest_fixture), &out_dir)?;
    ensure(
        !output.status.success(),
        format!(
            "{case_name}: gate should fail\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    load_json(&report_path)
}

fn expect_failure_signature(report: &Value, signature: &str) -> TestResult {
    let errors = array_field(report, "errors", "report")?;
    if errors.iter().any(|row| {
        row.get("failure_signature").and_then(Value::as_str) == Some(signature)
            || row
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains(signature))
    }) {
        Ok(())
    } else {
        Err(test_error(format!(
            "report should contain failure signature {signature}: {report:#?}"
        )))
    }
}

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<HashSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} entries must be strings")))
        })
        .collect()
}

#[test]
fn manifest_defines_signal_setjmp_schema_and_required_coverage() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    ensure(
        string_field(&manifest, "schema_version", "manifest")? == "v1",
        "schema_version should be v1",
    )?;
    ensure(
        string_field(&manifest, "bead_id", "manifest")? == "bd-bp8fl.5.8",
        "bead_id should be bd-bp8fl.5.8",
    )?;
    ensure(
        string_field(&manifest, "gate_id", "manifest")?
            == "signal-setjmp-async-cancellation-fixture-pack-v1",
        "gate_id should match signal/setjmp async-cancellation gate",
    )?;

    for key in [
        "signal_ops_fixture",
        "setjmp_ops_fixture",
        "pthread_thread_fixture",
        "pthread_cond_fixture",
        "process_ops_fixture",
        "oracle_precedence_divergence",
        "hard_parts_failure_replay_gate",
        "hard_parts_e2e_catalog",
        "setjmp_semantics_contract",
        "signal_abi_test",
        "setjmp_abi_test",
        "signal_native_gate",
        "setjmp_native_gate",
        "setjmp_edges_fixture",
        "setjmp_nested_fixture",
    ] {
        let rel = string_field(field(&manifest, "sources", "manifest")?, key, "sources")?;
        ensure(!rel.is_empty(), "source path should not be empty")?;
    }

    let required_log_fields = array_field(&manifest, "required_log_fields", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    ensure(
        required_log_fields == REQUIRED_LOG_FIELDS,
        "required_log_fields should match signal/setjmp log contract",
    )?;

    ensure(
        string_set(&manifest, "required_scenario_kinds", "manifest")?
            == REQUIRED_SCENARIO_KINDS
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<HashSet<_>>(),
        "required_scenario_kinds should match hard-parts scope",
    )?;
    ensure(
        string_set(&manifest, "required_timeout_classifications", "manifest")?
            == REQUIRED_TIMEOUT_CLASSIFICATIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<HashSet<_>>(),
        "required_timeout_classifications should match hard-parts scope",
    )?;

    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    ensure(
        rows.len() == REQUIRED_SCENARIO_KINDS.len(),
        "fixture_rows should cover every required scenario exactly once",
    )?;
    for row in rows {
        for key in [
            "fixture_id",
            "scenario_kind",
            "signal",
            "handler_behavior",
            "mask_state",
            "jump_state",
            "cancellation_interaction",
            "async_safety_class",
            "runtime_mode",
            "replacement_level",
            "oracle_kind",
            "allowed_divergence",
            "deterministic_schedule",
            "expected",
            "actual",
            "timeout_ms",
            "timeout_classification",
            "flaky_risk_control",
            "source_fixture_refs",
            "direct_runner",
            "isolated_runner",
        ] {
            ensure(row.get(key).is_some(), "fixture row missing required key")?;
        }
        let expected = field(row, "expected", "fixture_row")?;
        for key in [
            "status",
            "errno",
            "order",
            "signal_result",
            "mask_result",
            "jump_result",
            "failure_signature",
            "user_diagnostic",
        ] {
            ensure(
                expected.get(key).is_some(),
                "expected block missing required key",
            )?;
        }
    }
    Ok(())
}

#[test]
fn checker_passes_and_emits_report_and_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("signal-setjmp-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    ensure(
        output.status.success(),
        format!(
            "signal/setjmp gate failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&out_dir.join("signal-setjmp-async-cancellation.report.json"))?;
    ensure(
        string_field(&report, "status", "report")? == "pass",
        "report status should be pass",
    )?;
    for (key, expected) in [
        ("fixture_count", json!(9)),
        ("scenario_kind_count", json!(9)),
        ("runtime_mode_count", json!(2)),
        ("timeout_classification_count", json!(5)),
        ("blocked_count", json!(2)),
        ("log_row_count", json!(9)),
    ] {
        ensure(
            field(&report, key, "report")? == &expected,
            "report summary count did not match expected value",
        )?;
    }

    let log_content =
        std::fs::read_to_string(out_dir.join("signal-setjmp-async-cancellation.log.jsonl"))?;
    let log_rows = log_content
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|err| test_error(format!("log line should parse: {err}: {line}")))
        })
        .collect::<TestResult<Vec<_>>>()?;
    ensure(log_rows.len() == 9, "checker should emit nine log rows")?;
    for row in log_rows {
        for field in REQUIRED_LOG_FIELDS {
            ensure(row.get(field).is_some(), "log row missing required field")?;
        }
    }
    Ok(())
}

#[test]
fn checker_rejects_stale_source_commit() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let freshness = object_field_mut(&mut manifest, "freshness", "manifest")?;
    freshness.insert(
        "required_source_commit".to_owned(),
        Value::String("stale-deadbeef".to_owned()),
    );
    let report = run_negative_case(&root, "signal-setjmp-stale-source", &manifest)?;
    expect_failure_signature(&report, "stale_artifact")
}

#[test]
fn checker_rejects_missing_required_scenario() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    mutable_rows(&mut manifest)?
        .retain(|row| row.get("scenario_kind").and_then(Value::as_str) != Some("handler_longjmp"));
    let report = run_negative_case(&root, "signal-setjmp-missing-scenario", &manifest)?;
    expect_failure_signature(&report, "missing_fixture_case")
}

#[test]
fn checker_rejects_signal_result_mismatch() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let actual = object_field_mut(mutable_row(&mut manifest, 0)?, "actual", "fixture_rows[0]")?;
    actual.insert(
        "signal_result".to_owned(),
        Value::String("handler_delivered".to_owned()),
    );
    let report = run_negative_case(&root, "signal-setjmp-signal-result", &manifest)?;
    expect_failure_signature(&report, "signal_result_mismatch")
}

#[test]
fn checker_rejects_missing_mask_evidence() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let actual = object_field_mut(mutable_row(&mut manifest, 6)?, "actual", "fixture_rows[6]")?;
    actual.insert(
        "mask_result".to_owned(),
        Value::String("not_applicable".to_owned()),
    );
    let report = run_negative_case(&root, "signal-setjmp-mask-evidence", &manifest)?;
    expect_failure_signature(&report, "mask_state_mismatch")
}

#[test]
fn checker_rejects_invalid_timeout_classification() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    set_string_field(
        mutable_row(&mut manifest, 7)?,
        "timeout_classification",
        "bounded_wait_pass",
        "fixture_rows[7]",
    )?;
    let report = run_negative_case(&root, "signal-setjmp-timeout-class", &manifest)?;
    expect_failure_signature(&report, "timeout_classification")
}

#[test]
fn checker_rejects_unsupported_async_overclaim() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let actual = object_field_mut(mutable_row(&mut manifest, 8)?, "actual", "fixture_rows[8]")?;
    actual.insert("status".to_owned(), Value::String("pass".to_owned()));
    let report = run_negative_case(&root, "signal-setjmp-unsupported-overclaim", &manifest)?;
    expect_failure_signature(&report, "unsupported_async_boundary")
}

#[test]
fn checker_rejects_oracle_mismatch() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    set_string_field(
        mutable_row(&mut manifest, 0)?,
        "oracle_kind",
        "imaginary_oracle",
        "fixture_rows[0]",
    )?;
    let report = run_negative_case(&root, "signal-setjmp-oracle", &manifest)?;
    expect_failure_signature(&report, "oracle_mismatch")
}

#[test]
fn checker_rejects_missing_source_fixture_anchor() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let refs = mutable_row(&mut manifest, 0)?
        .get_mut("source_fixture_refs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("source_fixture_refs should be mutable array"))?;
    let first_ref = refs
        .get_mut(0)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("first source fixture ref should be mutable object"))?;
    first_ref.insert("case".to_owned(), json!("missing_signal_case"));
    let report = run_negative_case(&root, "signal-setjmp-missing-source", &manifest)?;
    expect_failure_signature(&report, "missing_source_artifact")
}
