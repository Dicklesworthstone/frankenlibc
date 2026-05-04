//! Integration tests for pthread hard-parts fixtures (bd-bp8fl.5.6).

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
    "thread_count",
    "operation",
    "cancellation_state",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_SCENARIO_KINDS: &[&str] = &[
    "cancellation_blocking_call",
    "cleanup_handler",
    "robust_mutex_owner_dead",
    "fork_with_locks",
    "tls_destructor_iteration",
    "timeout_deadlock_negative",
];

const REQUIRED_OPERATIONS: &[&str] = &[
    "pthread_cancel",
    "pthread_cleanup",
    "pthread_mutex_consistent",
    "fork",
    "pthread_key_destructor",
    "pthread_cond_timedwait",
];

const REQUIRED_TIMEOUT_CLASSIFICATIONS: &[&str] = &[
    "not_applicable",
    "bounded_wait_pass",
    "expected_timeout",
    "deadlock_guard_timeout",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/pthread_cancellation_robust_tls_fixture_pack.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_pthread_cancellation_robust_tls_fixture_pack.sh")
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

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, key, context)?
        .as_object()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
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
        .env("FLC_PTHREAD_HARD_PARTS_OUT_DIR", out_dir)
        .env(
            "FLC_PTHREAD_HARD_PARTS_REPORT",
            out_dir.join("pthread-hard-parts.report.json"),
        )
        .env(
            "FLC_PTHREAD_HARD_PARTS_LOG",
            out_dir.join("pthread-hard-parts.log.jsonl"),
        )
        .env("FLC_PTHREAD_HARD_PARTS_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_PTHREAD_HARD_PARTS_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run pthread hard-parts gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("pthread-hard-parts.report.json");
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

#[test]
fn manifest_defines_pthread_hard_parts_schema_and_required_coverage() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    ensure(
        string_field(&manifest, "schema_version", "manifest")? == "v1",
        "schema_version should be v1",
    )?;
    ensure(
        string_field(&manifest, "bead_id", "manifest")? == "bd-bp8fl.5.6",
        "bead_id should be bd-bp8fl.5.6",
    )?;
    ensure(
        string_field(&manifest, "gate_id", "manifest")?
            == "pthread-cancellation-robust-tls-fixture-pack-v1",
        "gate_id should match pthread hard-parts gate",
    )?;

    for key in [
        "pthread_thread_fixture",
        "pthread_mutex_fixture",
        "pthread_cond_fixture",
        "pthread_tls_keys_fixture",
        "process_ops_fixture",
        "oracle_precedence_divergence",
        "hard_parts_failure_replay_gate",
        "hard_parts_e2e_catalog",
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
        "required_log_fields should match pthread hard-parts log contract",
    )?;

    let scenario_kinds: HashSet<_> = array_field(&manifest, "required_scenario_kinds", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_scenario_kinds entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .collect();
    ensure(
        scenario_kinds
            == REQUIRED_SCENARIO_KINDS
                .iter()
                .copied()
                .collect::<HashSet<_>>(),
        "required_scenario_kinds should match pthread hard-parts scope",
    )?;

    let operations: HashSet<_> = array_field(&manifest, "required_operations", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_operations entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .collect();
    ensure(
        operations == REQUIRED_OPERATIONS.iter().copied().collect::<HashSet<_>>(),
        "required_operations should match pthread hard-parts scope",
    )?;

    let timeout_classifications: HashSet<_> =
        array_field(&manifest, "required_timeout_classifications", "manifest")?
            .iter()
            .map(|field| {
                field.as_str().ok_or_else(|| {
                    test_error("required_timeout_classifications entries must be strings")
                })
            })
            .collect::<TestResult<Vec<_>>>()?
            .into_iter()
            .collect();
    ensure(
        timeout_classifications
            == REQUIRED_TIMEOUT_CLASSIFICATIONS
                .iter()
                .copied()
                .collect::<HashSet<_>>(),
        "required_timeout_classifications should match pthread hard-parts scope",
    )?;

    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    ensure(
        rows.len() >= REQUIRED_SCENARIO_KINDS.len(),
        "fixture_rows should cover every required scenario",
    )?;
    for row in rows {
        for key in [
            "fixture_id",
            "scenario_kind",
            "thread_topology",
            "thread_count",
            "operation",
            "synchronization_primitive",
            "cancellation_point",
            "cancellation_state",
            "fork_behavior",
            "tls_destructor_sequence",
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
        let expected = object_field(row, "expected", "fixture_row")?;
        for key in [
            "status",
            "errno",
            "order",
            "failure_signature",
            "user_diagnostic",
        ] {
            ensure(
                expected.contains_key(key),
                "expected block missing required key",
            )?;
        }
    }
    Ok(())
}

#[test]
fn checker_passes_and_emits_report_and_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("pthread-hard-parts-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    ensure(
        output.status.success(),
        format!(
            "pthread hard-parts gate failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&out_dir.join("pthread-hard-parts.report.json"))?;
    ensure(
        string_field(&report, "status", "report")? == "pass",
        "report status should be pass",
    )?;
    for (key, expected) in [
        ("fixture_count", json!(6)),
        ("scenario_kind_count", json!(6)),
        ("operation_count", json!(6)),
        ("runtime_mode_count", json!(2)),
        ("timeout_classification_count", json!(4)),
        ("blocked_count", json!(3)),
    ] {
        ensure(
            field(&report, key, "report")? == &expected,
            "report summary count did not match expected value",
        )?;
    }

    let log_content = std::fs::read_to_string(out_dir.join("pthread-hard-parts.log.jsonl"))?;
    let log_rows = log_content
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|err| test_error(format!("log line should parse: {err}: {line}")))
        })
        .collect::<TestResult<Vec<_>>>()?;
    ensure(log_rows.len() == 6, "checker should emit six log rows")?;
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
    let report = run_negative_case(&root, "pthread-hard-parts-stale-source", &manifest)?;
    expect_failure_signature(&report, "stale_artifact")
}

#[test]
fn checker_rejects_missing_required_scenario() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    mutable_rows(&mut manifest)?.retain(|row| {
        row.get("scenario_kind").and_then(Value::as_str) != Some("robust_mutex_owner_dead")
    });
    let report = run_negative_case(&root, "pthread-hard-parts-missing-scenario", &manifest)?;
    expect_failure_signature(&report, "missing_fixture_case")
}

#[test]
fn checker_rejects_invalid_timeout_classification() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    set_string_field(
        mutable_row(&mut manifest, 5)?,
        "timeout_classification",
        "flaky_timeout",
        "fixture_rows[5]",
    )?;
    let report = run_negative_case(&root, "pthread-hard-parts-timeout-class", &manifest)?;
    expect_failure_signature(&report, "timeout_classification")
}

#[test]
fn checker_rejects_missing_deterministic_scheduler_control() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    if let Some(schedule) = mutable_row(&mut manifest, 0)?
        .get_mut("deterministic_schedule")
        .and_then(Value::as_object_mut)
    {
        schedule.remove("control_token");
    }
    let report = run_negative_case(&root, "pthread-hard-parts-missing-scheduler", &manifest)?;
    expect_failure_signature(&report, "missing_field")
}

#[test]
fn checker_rejects_unstable_failure_signature() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let row = mutable_row(&mut manifest, 2)?;
    let actual = object_field_mut(row, "actual", "fixture_rows[2]")?;
    actual.insert(
        "failure_signature".to_owned(),
        Value::String("different_signature".to_owned()),
    );
    let report = run_negative_case(&root, "pthread-hard-parts-unstable-signature", &manifest)?;
    expect_failure_signature(&report, "failure_signature_unstable")
}
