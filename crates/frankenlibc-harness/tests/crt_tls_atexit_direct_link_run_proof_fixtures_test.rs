//! Integration tests for CRT/TLS/atexit direct-link proof fixtures (bd-b92jd.1.2).

use serde_json::{Value, json};
use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsString;
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

const REQUIRED_EXECUTION_LOG_FIELDS: &[&str] = &[
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
    "event",
    "command",
    "exit_code",
    "stdout_sha256",
    "stderr_sha256",
    "stdout_path",
    "stderr_path",
    "loader_diagnostics",
    "artifact_status",
    "claim_status",
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

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn git_head(root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .map_err(|err| test_error(format!("git rev-parse HEAD should run: {err}")))?;
    ensure(
        output.status.success(),
        format!("git rev-parse HEAD failed with status {}", output.status),
    )?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("git rev-parse HEAD emitted non-UTF8: {err}")))?;
    let head = stdout.trim().to_owned();
    ensure(
        is_hex_commit(&head),
        format!("git HEAD must be a 40-hex commit, got {head:?}"),
    )?;
    Ok(head)
}

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

fn source_commit_freshness_policy(manifest: &Value) -> TestResult<&Value> {
    field(manifest, "source_commit_freshness_policy", "manifest")
}

fn assert_source_commit_freshness_policy(manifest: &Value) -> TestResult {
    let policy = source_commit_freshness_policy(manifest)?;
    ensure(
        string_field(
            policy,
            "recorded_source_commit_field",
            "source_commit_freshness_policy",
        )? == "source_commit",
        "source_commit_freshness_policy.recorded_source_commit_field should be source_commit",
    )?;
    ensure(
        string_field(
            policy,
            "comparison_target",
            "source_commit_freshness_policy",
        )? == "current git HEAD",
        "source_commit_freshness_policy.comparison_target should be current git HEAD",
    )?;
    ensure(
        string_field(policy, "stale_result", "source_commit_freshness_policy")?
            == "block_crt_tls_atexit_direct_link_proof_evidence",
        "source_commit_freshness_policy.stale_result should block CRT/TLS direct-link proof evidence",
    )?;
    ensure(
        field(
            policy,
            "direct_link_proof_evidence_allowed_when_stale",
            "source_commit_freshness_policy",
        )?
        .as_bool()
            == Some(false),
        "source_commit_freshness_policy.direct_link_proof_evidence_allowed_when_stale should be false",
    )?;
    ensure(
        string_field(
            policy,
            "rejected_evidence_kind",
            "source_commit_freshness_policy",
        )? == "stale_source_commit",
        "source_commit_freshness_policy.rejected_evidence_kind should be stale_source_commit",
    )
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

fn build_sample_shared_object(path: &Path) -> TestResult {
    let source = path.with_extension("c");
    std::fs::write(
        &source,
        "int frankenlibc_crt_tls_atexit_probe_symbol(void) { return 7; }\n",
    )?;
    let output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source)
        .arg("-o")
        .arg(path)
        .output()
        .map_err(|err| test_error(format!("failed to run cc: {err}")))?;
    ensure(
        output.status.success(),
        format!(
            "cc failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn build_host_dependent_shared_object(path: &Path) -> TestResult {
    let source = path.with_extension("c");
    std::fs::write(
        &source,
        "#include <stdio.h>\nint frankenlibc_crt_tls_host_dep_probe(void) { puts(\"host-libc\"); return 7; }\n",
    )?;
    let output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source)
        .arg("-o")
        .arg(path)
        .output()
        .map_err(|err| test_error(format!("failed to run cc: {err}")))?;
    ensure(
        output.status.success(),
        format!(
            "cc failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn fake_ldd_failure_path(out_dir: &Path) -> TestResult<OsString> {
    let fake_bin = out_dir.join("fake-bin");
    std::fs::create_dir_all(&fake_bin)?;
    let fake_ldd = fake_bin.join("ldd");
    std::fs::write(&fake_ldd, "#!/bin/sh\necho ldd probe failed >&2\nexit 42\n")?;
    let chmod = Command::new("chmod")
        .arg("+x")
        .arg(&fake_ldd)
        .output()
        .map_err(|err| test_error(format!("failed to run chmod: {err}")))?;
    ensure(
        chmod.status.success(),
        format!(
            "chmod failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&chmod.stdout),
            String::from_utf8_lossy(&chmod.stderr)
        ),
    )?;
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    Ok(path)
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
        row.get("failure_signature")
            .and_then(Value::as_str)
            .is_some_and(|actual| actual.eq(signature))
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
    let source_commit = string_field(&manifest, "source_commit", "manifest")?;

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
    ensure(
        is_hex_commit(source_commit),
        format!("source_commit should be a 40-hex git commit, got {source_commit:?}"),
    )?;
    assert_source_commit_freshness_policy(&manifest)?;

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
    let required_execution_log_fields: Vec<_> =
        array_field(&manifest, "required_execution_log_fields", "manifest")?
            .iter()
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    test_error("required_execution_log_fields entries must be strings")
                })
            })
            .collect::<TestResult<_>>()?;
    ensure(
        required_execution_log_fields == REQUIRED_EXECUTION_LOG_FIELDS,
        "required_execution_log_fields should match direct-link execution log contract",
    )?;
    ensure(
        field(
            field(&manifest, "execution_runner", "manifest")?,
            "proof_case_count",
            "execution_runner",
        )?
        .as_u64()
            == Some(5),
        "execution runner should declare five direct-link proof cases",
    )?;
    let policy = object_field(&manifest, "replacement_artifact_policy", "manifest")?;
    ensure(
        policy
            .get("host_glibc_dependency_result")
            .and_then(Value::as_str)
            == Some("claim_blocked"),
        "host-glibc-dependent artifacts must block claims",
    )?;
    let probe_tools = policy
        .get("host_dependency_probe_tools")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("host_dependency_probe_tools must be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    ensure(
        probe_tools.contains("readelf -d") && probe_tools.contains("ldd"),
        "host dependency probes should use readelf and ldd",
    )?;
    let diagnostic_signatures = array_field(&manifest, "diagnostic_signatures", "manifest")?
        .iter()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    ensure(
        diagnostic_signatures.contains("host_glibc_dependency")
            && diagnostic_signatures.contains("artifact_dependency_inspection_failed"),
        "diagnostics should include host dependency inspection failures",
    )?;
    let negative_signatures = array_field(&manifest, "negative_claim_tests", "manifest")?
        .iter()
        .filter_map(|entry| entry.get("failure_signature").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    ensure(
        negative_signatures.contains("host_glibc_dependency")
            && negative_signatures.contains("artifact_dependency_inspection_failed"),
        "negative claim tests should include host dependency failure cases",
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
fn stale_source_commit_policy_blocks_crt_tls_direct_link_proof_evidence() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    let source_commit = string_field(&manifest, "source_commit", "manifest")?;
    ensure(
        is_hex_commit(source_commit),
        format!("source_commit should be a 40-hex git commit, got {source_commit:?}"),
    )?;
    let current_head = git_head(&root)?;
    assert_source_commit_freshness_policy(&manifest)?;
    if source_commit != current_head {
        let policy = source_commit_freshness_policy(&manifest)?;
        ensure(
            string_field(policy, "stale_result", "source_commit_freshness_policy")?
                == "block_crt_tls_atexit_direct_link_proof_evidence",
            "stale source commits must block CRT/TLS direct-link proof evidence",
        )?;
        ensure(
            field(
                policy,
                "direct_link_proof_evidence_allowed_when_stale",
                "source_commit_freshness_policy",
            )?
            .as_bool()
                == Some(false),
            "stale source commits must not allow CRT/TLS direct-link proof evidence",
        )?;
        ensure(
            string_field(
                policy,
                "rejected_evidence_kind",
                "source_commit_freshness_policy",
            )? == "stale_source_commit",
            "stale source commits must use the stale_source_commit rejection kind",
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
        field(summary, "fixture_log_row_count", "summary")?.as_u64() == Some(16),
        "fixture_log_row_count should include strict and hardened fixture rows",
    )?;
    ensure(
        field(summary, "direct_link_execution_rows", "summary")?.as_u64() == Some(10),
        "direct_link_execution_rows should cover five probes in strict+hardened",
    )?;
    ensure(
        field(summary, "log_row_count", "summary")?.as_u64() == Some(26),
        "log_row_count should include fixture rows plus execution rows",
    )?;
    ensure(
        string_field(&report, "source_commit", "report")?.len() == 40,
        "report should include current git source_commit",
    )?;

    let logs = parse_jsonl(&log_path)?;
    ensure(
        logs.len() == 26,
        "expected fixture/runtime rows plus direct-link execution rows",
    )?;
    let mut modes = HashSet::new();
    let mut execution_rows = 0;
    for row in &logs {
        let required_fields: &[&str] = if row.get("event").is_some() {
            execution_rows += 1;
            REQUIRED_EXECUTION_LOG_FIELDS
        } else {
            REQUIRED_LOG_FIELDS
        };
        for field_name in required_fields {
            ensure(
                row.get(*field_name).is_some(),
                "log row should include required field",
            )?;
        }
        modes.insert(string_field(row, "runtime_mode", "log_row")?);
    }
    ensure(
        execution_rows == 10,
        "JSONL should include strict+hardened execution rows for five probes",
    )?;
    ensure(
        modes == REQUIRED_RUNTIME_MODES.iter().copied().collect(),
        "JSONL rows should cover strict and hardened",
    )
}

#[test]
fn checker_consumes_current_forged_artifact_and_runs_direct_link_probes() -> TestResult {
    let root = workspace_root();
    if Command::new("cc").arg("--version").output().is_err() {
        return Ok(());
    }
    let out_dir = unique_temp_dir("crt-tls-proof-current-artifact")?;
    let artifact = out_dir.join("libfrankenlibc_replace.so");
    build_sample_shared_object(&artifact)?;
    let report_path = out_dir.join("crt-tls-proof.report.json");
    let log_path = out_dir.join("crt-tls-proof.log.jsonl");
    let output = Command::new("bash")
        .arg(script_path(&root))
        .current_dir(&root)
        .env("FLC_CRT_TLS_PROOF_OUT_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPORT", &report_path)
        .env("FLC_CRT_TLS_PROOF_LOG", &log_path)
        .env("FLC_CRT_TLS_PROOF_TARGET_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPLACE_ARTIFACT", &artifact)
        .output()
        .map_err(|err| test_error(format!("failed to run CRT/TLS proof gate: {err}")))?;
    ensure(
        output.status.success(),
        format!(
            "gate should pass with current artifact\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    let report = load_json(&report_path)?;
    ensure(
        string_field(
            field(&report, "standalone_artifact", "report")?,
            "status",
            "standalone_artifact",
        )? == "current",
        "standalone artifact should be current",
    )?;
    let summary = field(&report, "summary", "report")?;
    ensure(
        field(summary, "direct_link_execution_rows", "summary")?.as_u64() == Some(10),
        "all strict+hardened direct-link probe rows should be emitted",
    )?;
    ensure(
        field(summary, "direct_link_execution_status_counts", "summary")?
            .get("pass")
            .and_then(Value::as_u64)
            == Some(10),
        "sample current artifact should run all direct-link probes",
    )
}

#[test]
fn checker_blocks_interpose_only_artifact_profile() -> TestResult {
    let root = workspace_root();
    if Command::new("cc").arg("--version").output().is_err() {
        return Ok(());
    }
    let out_dir = unique_temp_dir("crt-tls-proof-wrong-artifact")?;
    let artifact = out_dir.join("libfrankenlibc_abi.so");
    build_sample_shared_object(&artifact)?;
    let report_path = out_dir.join("crt-tls-proof.report.json");
    let output = Command::new("bash")
        .arg(script_path(&root))
        .current_dir(&root)
        .env("FLC_CRT_TLS_PROOF_OUT_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPORT", &report_path)
        .env(
            "FLC_CRT_TLS_PROOF_LOG",
            out_dir.join("crt-tls-proof.log.jsonl"),
        )
        .env("FLC_CRT_TLS_PROOF_TARGET_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPLACE_ARTIFACT", &artifact)
        .output()
        .map_err(|err| test_error(format!("failed to run CRT/TLS proof gate: {err}")))?;
    ensure(
        output.status.success(),
        "wrong-profile artifact should block claims without failing the gate",
    )?;
    let report = load_json(&report_path)?;
    ensure(
        string_field(
            field(&report, "standalone_artifact", "report")?,
            "failure_signature",
            "standalone_artifact",
        )? == "interpose_only_artifact",
        "interpose-only artifact should be classified explicitly",
    )
}

#[test]
fn checker_blocks_host_libc_dependent_standalone_artifact() -> TestResult {
    let root = workspace_root();
    if Command::new("cc").arg("--version").output().is_err() {
        return Ok(());
    }
    let out_dir = unique_temp_dir("crt-tls-proof-host-dependent-artifact")?;
    let artifact = out_dir.join("libfrankenlibc_replace.so");
    build_host_dependent_shared_object(&artifact)?;
    let report_path = out_dir.join("crt-tls-proof.report.json");
    let output = Command::new("bash")
        .arg(script_path(&root))
        .current_dir(&root)
        .env("FLC_CRT_TLS_PROOF_OUT_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPORT", &report_path)
        .env(
            "FLC_CRT_TLS_PROOF_LOG",
            out_dir.join("crt-tls-proof.log.jsonl"),
        )
        .env("FLC_CRT_TLS_PROOF_TARGET_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPLACE_ARTIFACT", &artifact)
        .output()
        .map_err(|err| test_error(format!("failed to run CRT/TLS proof gate: {err}")))?;
    ensure(
        output.status.success(),
        "host-dependent artifact should block claims without failing the gate",
    )?;
    let report = load_json(&report_path)?;
    let artifact_state = field(&report, "standalone_artifact", "report")?;
    ensure(
        string_field(artifact_state, "status", "standalone_artifact")? == "host_dependent",
        "host-dependent artifact should not be current proof evidence",
    )?;
    ensure(
        matches!(
            string_field(artifact_state, "failure_signature", "standalone_artifact")?,
            "host_glibc_dependency"
        ),
        "host-dependent artifact should be classified explicitly",
    )?;
    let counts = field(
        field(&report, "summary", "report")?,
        "direct_link_execution_status_counts",
        "summary",
    )?;
    ensure(
        counts.get("claim_blocked").and_then(Value::as_u64) == Some(10),
        "strict+hardened direct-link probes should remain claim_blocked",
    )
}

#[test]
fn checker_blocks_standalone_artifact_when_ldd_probe_fails() -> TestResult {
    let root = workspace_root();
    if Command::new("cc").arg("--version").output().is_err() {
        return Ok(());
    }
    let out_dir = unique_temp_dir("crt-tls-proof-ldd-probe-failed")?;
    let artifact = out_dir.join("libfrankenlibc_replace.so");
    build_sample_shared_object(&artifact)?;
    let fake_path = fake_ldd_failure_path(&out_dir)?;
    let report_path = out_dir.join("crt-tls-proof.report.json");
    let output = Command::new("bash")
        .arg(script_path(&root))
        .current_dir(&root)
        .env("PATH", fake_path)
        .env("FLC_CRT_TLS_PROOF_OUT_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPORT", &report_path)
        .env(
            "FLC_CRT_TLS_PROOF_LOG",
            out_dir.join("crt-tls-proof.log.jsonl"),
        )
        .env("FLC_CRT_TLS_PROOF_TARGET_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPLACE_ARTIFACT", &artifact)
        .output()
        .map_err(|err| test_error(format!("failed to run CRT/TLS proof gate: {err}")))?;
    ensure(
        output.status.success(),
        "dependency probe failure should block claims without failing the gate",
    )?;
    let report = load_json(&report_path)?;
    let artifact_state = field(&report, "standalone_artifact", "report")?;
    ensure(
        string_field(artifact_state, "status", "standalone_artifact")? == "inspection_failed",
        "failed dependency inspection should not be current proof evidence",
    )?;
    ensure(
        matches!(
            string_field(artifact_state, "failure_signature", "standalone_artifact")?,
            "artifact_dependency_inspection_failed"
        ),
        "failed dependency inspection should be classified explicitly",
    )?;
    let counts = field(
        field(&report, "summary", "report")?,
        "direct_link_execution_status_counts",
        "summary",
    )?;
    ensure(
        counts.get("claim_blocked").and_then(Value::as_u64) == Some(10),
        "dependency inspection failures should keep direct-link probes claim_blocked",
    )
}

#[test]
fn checker_blocks_stale_standalone_artifact() -> TestResult {
    let root = workspace_root();
    if Command::new("cc").arg("--version").output().is_err() {
        return Ok(());
    }
    let out_dir = unique_temp_dir("crt-tls-proof-stale-artifact")?;
    let artifact = out_dir.join("libfrankenlibc_replace.so");
    build_sample_shared_object(&artifact)?;
    let report_path = out_dir.join("crt-tls-proof.report.json");
    let output = Command::new("bash")
        .arg(script_path(&root))
        .current_dir(&root)
        .env("FLC_CRT_TLS_PROOF_OUT_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPORT", &report_path)
        .env(
            "FLC_CRT_TLS_PROOF_LOG",
            out_dir.join("crt-tls-proof.log.jsonl"),
        )
        .env("FLC_CRT_TLS_PROOF_TARGET_DIR", &out_dir)
        .env("FLC_CRT_TLS_PROOF_REPLACE_ARTIFACT", &artifact)
        .env("FLC_CRT_TLS_PROOF_HEAD_EPOCH", "4102444800")
        .output()
        .map_err(|err| test_error(format!("failed to run CRT/TLS proof gate: {err}")))?;
    ensure(
        output.status.success(),
        "stale artifact should block claims without failing the gate",
    )?;
    let report = load_json(&report_path)?;
    let actual_signature = string_field(
        field(&report, "standalone_artifact", "report")?,
        "failure_signature",
        "standalone_artifact",
    )?;
    ensure(
        actual_signature.eq("standalone_artifact_stale"),
        format!(
            "stale artifact should be classified explicitly, got {actual_signature}: {report:#?}"
        ),
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
fn checker_rejects_missing_source_commit_freshness_policy() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_object_field(&mut manifest, "source_commit_freshness_policy", "manifest")?;
    let report = run_negative_case(&root, "crt-tls-proof-missing-freshness-policy", &manifest)?;
    expect_failure_signature(&report, "stale_source_commit")
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
