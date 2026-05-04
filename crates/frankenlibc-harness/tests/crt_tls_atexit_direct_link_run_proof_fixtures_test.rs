//! Integration tests for CRT/TLS/atexit direct-link proof fixtures (bd-b92jd.1.2).

use serde_json::{Value, json};
use std::collections::HashSet;
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "fixture_id",
    "scenario_kind",
    "runtime_mode",
    "replacement_level",
    "execution_model",
    "expected_decision",
    "actual_decision",
    "expected_order",
    "actual_order",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "failure_signature",
];

const REQUIRED_SCENARIO_KINDS: &[&str] = &[
    "crt_startup",
    "tls_initialization",
    "tls_destructor",
    "init_fini_ordering",
    "atexit_on_exit",
    "errno_tls_isolation",
    "env_ownership",
    "secure_mode_diagnostics",
];

const REQUIRED_RUNTIME_MODES: &[&str] = &["strict", "hardened"];
const REQUIRED_EXECUTION_MODELS: &[&str] = &["direct_link_run", "replace_mode_simulated"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/crt_tls_atexit_direct_link_run_proof_fixtures.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_crt_tls_atexit_direct_link_run_proof_fixtures.sh")
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

fn remove_object_field(value: &mut Value, key: &str, context: &str) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    if object.remove(key).is_some() {
        Ok(())
    } else {
        Err(test_error(format!("{context}.{key} is missing")))
    }
}

fn set_object_field(value: &mut Value, key: &str, new_value: Value, context: &str) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    if object.insert(key.to_owned(), new_value).is_some() {
        Ok(())
    } else {
        Err(test_error(format!("{context}.{key} is missing")))
    }
}

fn set_nested_object_field(
    value: &mut Value,
    object_key: &str,
    field_key: &str,
    new_value: Value,
    context: &str,
) -> TestResult {
    object_field_mut(value, object_key, context)?.insert(field_key.to_owned(), new_value);
    Ok(())
}

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<HashSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain strings")))
        })
        .collect()
}

fn assert_repo_relative_existing_path(root: &Path, rel: &str, context: &str) -> TestResult {
    let path = Path::new(rel);
    ensure(
        !rel.is_empty(),
        format!("{context}: path must not be empty"),
    )?;
    ensure(
        !path.is_absolute(),
        format!("{context}: path must be repo-relative: {rel}"),
    )?;
    ensure(
        !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_))),
        format!("{context}: path must not escape repo root: {rel}"),
    )?;
    let full_path = root.join(path); // ubs:ignore - path is rejected above if absolute or parent-dir escaping.
    ensure(full_path.exists(), format!("{context}: missing {rel}"))
}

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FLC_CRT_TLS_PROOF_OUT_DIR", out_dir)
        .env(
            "FLC_CRT_TLS_PROOF_REPORT",
            out_dir.join("crt-tls-proof.report.json"),
        )
        .env(
            "FLC_CRT_TLS_PROOF_LOG",
            out_dir.join("crt-tls-proof.log.jsonl"),
        )
        .env("FLC_CRT_TLS_PROOF_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_CRT_TLS_PROOF_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run CRT/TLS proof gate: {err}")))
}

fn run_default_gate(root: &Path) -> TestResult<(Value, PathBuf)> {
    let out_dir = unique_temp_dir("crt-tls-proof-pass")?;
    let report_path = out_dir.join("crt-tls-proof.report.json");
    let log_path = out_dir.join("crt-tls-proof.log.jsonl");
    let output = run_gate(root, None, &out_dir)?;
    ensure(
        output.status.success(),
        format!(
            "gate should pass\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    Ok((load_json(&report_path)?, log_path))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("crt-tls-proof.report.json");
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

fn parse_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| test_error(format!("{err}"))))
        .collect()
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
fn manifest_defines_required_crt_tls_atexit_fixture_scope() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;

    ensure(
        string_field(&manifest, "schema_version", "manifest")? == "v1",
        "schema_version should be v1",
    )?;
    ensure(
        string_field(&manifest, "bead_id", "manifest")? == "bd-b92jd.1.2",
        "bead_id should be bd-b92jd.1.2",
    )?;
    ensure(
        string_field(&manifest, "gate_id", "manifest")?
            == "crt-tls-atexit-direct-link-run-proof-fixtures-v1",
        "gate_id should match CRT/TLS proof gate",
    )?;

    let required_log_fields: Vec<_> = array_field(&manifest, "required_log_fields", "manifest")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<_>>()?;
    ensure(
        required_log_fields == REQUIRED_LOG_FIELDS,
        "required_log_fields should match structured log contract",
    )?;
    ensure(
        string_set(&manifest, "required_scenario_kinds", "manifest")?
            == REQUIRED_SCENARIO_KINDS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        "required scenario kinds should match bead scope",
    )?;
    ensure(
        string_set(&manifest, "required_runtime_modes", "manifest")?
            == REQUIRED_RUNTIME_MODES
                .iter()
                .map(|value| value.to_string())
                .collect(),
        "required runtime modes should be strict+hardened",
    )?;
    ensure(
        string_set(&manifest, "required_execution_models", "manifest")?
            == REQUIRED_EXECUTION_MODELS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        "required execution models should include direct and simulated replacement",
    )?;

    for (key, value) in object_field(&manifest, "sources", "manifest")? {
        assert_repo_relative_existing_path(
            &root,
            value.as_str().ok_or_else(|| {
                test_error(format!("sources.{key} must be a string")) // ubs:ignore — test diagnostics include the manifest key, not a hot path
            })?,
            key,
        )?;
    }
    Ok(())
}

#[test]
fn fixture_rows_are_fail_closed_and_materialized() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    ensure(
        rows.len() == 8,
        "fixture row count should match required scope",
    )?;

    let mut seen_scenarios = HashSet::new();
    let mut seen_ids = HashSet::new();
    let mut seen_execution_models = HashSet::new();
    let required_runtime_modes = REQUIRED_RUNTIME_MODES
        .iter()
        .map(|value| value.to_string())
        .collect::<HashSet<_>>();
    for row in rows {
        let fixture_id = string_field(row, "fixture_id", "fixture_row")?;
        ensure(seen_ids.insert(fixture_id), "fixture_id should be unique")?;
        let scenario = string_field(row, "scenario_kind", fixture_id)?;
        seen_scenarios.insert(scenario);
        seen_execution_models.insert(string_field(row, "execution_model", fixture_id)?);
        ensure(
            string_set(row, "runtime_modes", fixture_id)? == required_runtime_modes,
            "every fixture row should cover strict and hardened",
        )?;
        ensure(
            field(row, "strict_expectation", fixture_id)?.is_object(),
            "strict expectation should be present",
        )?;
        ensure(
            field(row, "hardened_expectation", fixture_id)?.is_object(),
            "hardened expectation should be present",
        )?;
        ensure(
            string_field(row, "source_commit", fixture_id)? == "current",
            "fixture row should carry source_commit",
        )?;
        ensure(
            string_field(row, "expected_decision", fixture_id)? == "claim_blocked",
            "fixture row expected decision should fail closed",
        )?;
        ensure(
            string_field(row, "actual_decision", fixture_id)? == "claim_blocked",
            "fixture row actual decision should fail closed",
        )?;
        ensure(
            !array_field(row, "artifact_refs", fixture_id)?.is_empty(),
            "artifact_refs should be non-empty",
        )?;
        for artifact in array_field(row, "source_artifacts", fixture_id)? {
            assert_repo_relative_existing_path(
                &root,
                artifact
                    .as_str()
                    .ok_or_else(|| test_error("source_artifacts entries must be strings"))?,
                fixture_id,
            )?;
        }
        for artifact in array_field(row, "artifact_refs", fixture_id)? {
            assert_repo_relative_existing_path(
                &root,
                artifact
                    .as_str()
                    .ok_or_else(|| test_error("artifact_refs entries must be strings"))?,
                fixture_id,
            )?;
        }
    }

    ensure(
        seen_scenarios
            == REQUIRED_SCENARIO_KINDS
                .iter()
                .copied()
                .collect::<HashSet<_>>(),
        "fixture rows should cover every required scenario",
    )?;
    ensure(
        seen_execution_models
            == REQUIRED_EXECUTION_MODELS
                .iter()
                .copied()
                .collect::<HashSet<_>>(),
        "fixture rows should include both execution models",
    )
}

#[test]
fn checker_emits_report_and_mode_specific_jsonl_rows() -> TestResult {
    let root = workspace_root();
    let (report, log_path) = run_default_gate(&root)?;
    ensure(
        string_field(&report, "status", "report")? == "pass",
        "checker report should pass",
    )?;
    let summary = field(&report, "summary", "report")?;
    ensure(
        field(summary, "fixture_count", "summary")?.as_u64() == Some(8),
        "fixture_count should be 8",
    )?;
    ensure(
        field(summary, "claim_blocked_count", "summary")?.as_u64() == Some(8),
        "claim_blocked_count should be 8",
    )?;
    ensure(
        field(summary, "log_row_count", "summary")?.as_u64() == Some(16),
        "log_row_count should include strict and hardened rows",
    )?;
    ensure(
        string_field(&report, "source_commit", "report")?.len() == 40,
        "report should include current git source_commit",
    )?;

    let logs = parse_jsonl(&log_path)?;
    ensure(
        logs.len() == 16,
        "expected one log row per fixture/runtime mode",
    )?;
    let mut modes = HashSet::new();
    for row in &logs {
        for field_name in REQUIRED_LOG_FIELDS {
            ensure(
                row.get(*field_name).is_some(),
                "log row should include required field",
            )?;
        }
        modes.insert(string_field(row, "runtime_mode", "log_row")?);
    }
    ensure(
        modes == REQUIRED_RUNTIME_MODES.iter().copied().collect(),
        "JSONL rows should cover strict and hardened",
    )
}

#[test]
fn checker_rejects_row_missing_source_commit() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_object_field(
        mutable_row(&mut manifest, 0)?,
        "source_commit",
        "fixture_rows[0]",
    )?;
    let report = run_negative_case(&root, "crt-tls-proof-missing-source-commit", &manifest)?;
    expect_failure_signature(&report, "missing_source_commit")
}

#[test]
fn checker_rejects_row_missing_artifact_refs() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_object_field(
        mutable_row(&mut manifest, 1)?,
        "artifact_refs",
        "fixture_rows[1]",
    )?;
    let report = run_negative_case(&root, "crt-tls-proof-missing-artifact-refs", &manifest)?;
    expect_failure_signature(&report, "missing_artifact_refs")
}

#[test]
fn checker_rejects_conflicting_replace_claim_when_artifact_missing() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    set_nested_object_field(
        &mut manifest,
        "replacement_artifact_policy",
        "replace_artifact",
        json!("target/release/definitely_missing_libfrankenlibc_replace.so"),
        "manifest",
    )?;
    let row = mutable_row(&mut manifest, 2)?;
    set_object_field(
        row,
        "expected_decision",
        json!("evidence_allowed"),
        "fixture_rows[2]",
    )?;
    set_object_field(
        row,
        "actual_decision",
        json!("evidence_allowed"),
        "fixture_rows[2]",
    )?;
    let report = run_negative_case(&root, "crt-tls-proof-missing-replace-artifact", &manifest)?;
    expect_failure_signature(&report, "replace_artifact_missing")
}

#[test]
fn checker_rejects_missing_required_fixture_row() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let rows = mutable_rows(&mut manifest)?;
    let before = rows.len();
    rows.retain(|row| {
        string_field(row, "scenario_kind", "fixture_row").ok() != Some("atexit_on_exit")
    });
    ensure(rows.len() + 1 == before, "expected one atexit row removal")?;
    let report = run_negative_case(&root, "crt-tls-proof-missing-row", &manifest)?;
    expect_failure_signature(&report, "missing_fixture_row")
}

#[test]
fn checker_rejects_missing_hardened_expectation() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_object_field(
        mutable_row(&mut manifest, 3)?,
        "hardened_expectation",
        "fixture_rows[3]",
    )?;
    let report = run_negative_case(&root, "crt-tls-proof-missing-hardened", &manifest)?;
    expect_failure_signature(&report, "strict_hardened_expectation_missing")
}
