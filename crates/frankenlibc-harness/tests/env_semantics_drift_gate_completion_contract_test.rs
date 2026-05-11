//! Completion-contract tests for bd-29b.3.1 env semantics and drift gates.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_contract_shape_validated",
    "env_drift_report_validated",
    "mode_semantics_matrix_validated",
    "mode_contract_lock_validated",
    "base_env_semantics_gates_replayed",
    "missing_item_bindings_validated",
    "test_surfaces_validated",
    "env_semantics_drift_gate_completion_contract_validated",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/env_semantics_drift_gate_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_env_semantics_drift_gate_completion_contract.sh")
}

fn mode_contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/mode_contract_lock.v1.json")
}

fn mode_semantics_matrix_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/mode_semantics_matrix.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
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

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<BTreeSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain only strings")))
        })
        .collect::<Result<_, _>>()
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_ENV_SEMANTICS_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_ENV_SEMANTICS_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_ENV_SEMANTICS_COMPLETION_REPORT",
            out_dir.join("env_semantics_drift_gate_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ENV_SEMANTICS_COMPLETION_LOG",
            out_dir.join("env_semantics_drift_gate_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("env_semantics_drift_gate_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("env_semantics_drift_gate_completion_contract.log.jsonl")
}

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn set_artifact_path(manifest: &mut Value, artifact_id: &str, path: &Path) -> TestResult {
    let artifacts = manifest
        .get_mut("source_artifacts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("source_artifacts should be an array"))?;
    let artifact = artifacts
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some(artifact_id))
        .ok_or_else(|| test_error(format!("missing source artifact {artifact_id}")))?;
    let artifact_object = artifact
        .as_object_mut()
        .ok_or_else(|| test_error(format!("source artifact {artifact_id} should be an object")))?;
    artifact_object.insert("path".to_owned(), json!(path.display().to_string()));
    Ok(())
}

fn failure_signatures(report: &Value) -> BTreeSet<&str> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .collect()
}

#[test]
fn contract_binds_env_semantics_unit_and_e2e_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "env_semantics_drift_gate_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-29b.3.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-29b.3"
    );

    let artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let artifact_ids: BTreeSet<_> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "docs_mismatch_report",
        "docs_env_gate",
        "mode_semantics_matrix",
        "mode_semantics_gate",
        "mode_contract_lock",
        "mode_contract_gate",
        "runtime_config",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(
            artifact_ids.contains(required),
            "missing artifact {required}"
        );
    }

    let completion = field(&manifest, "completion_contract", "manifest")?;
    assert_eq!(
        string_set(completion, "missing_item_ids", "completion_contract")?,
        BTreeSet::from([
            "tests.e2e.primary".to_owned(),
            "tests.unit.primary".to_owned(),
        ])
    );
    let mode_contract = field(completion, "required_mode_contract", "completion_contract")?;
    assert_eq!(
        string_field(mode_contract, "env_key", "required_mode_contract")?,
        "FRANKENLIBC_MODE"
    );
    assert_eq!(
        string_set(mode_contract, "allowed_values", "required_mode_contract")?,
        BTreeSet::from(["hardened".to_owned(), "strict".to_owned()])
    );
    Ok(())
}

#[test]
fn checker_accepts_env_semantics_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "env-semantics-completion")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["total_families"].as_u64(), Some(20));
    assert_eq!(report["summary"]["anchor_count"].as_u64(), Some(3));
    assert!(
        report["summary"]["total_heals_call_sites"]
            .as_u64()
            .is_some_and(|count| count >= 100),
        "completion report must carry mode semantics healing call-site count"
    );

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names: BTreeSet<_> = events
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(event_names.contains(required), "missing event {required}");
    }
    Ok(())
}

#[test]
fn completion_contract_runs_base_env_semantics_gates() -> TestResult {
    let root = workspace_root()?;
    for script in [
        "scripts/check_docs_env_mismatch.sh",
        "scripts/check_mode_semantics.sh",
        "scripts/check_mode_contract_lock.sh",
    ] {
        let output = Command::new("bash")
            .arg(root.join(script))
            .current_dir(&root)
            .output()?;
        assert!(
            output.status.success(),
            "{script} failed stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "env-semantics-missing-e2e")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("missing_item_bindings should be an array"))?;
    bindings.retain(|row| {
        row.get("missing_item_id").and_then(Value::as_str) != Some("tests.e2e.primary")
    });
    let bad_manifest = out_dir.join("manifest.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(
        signatures.contains("missing_e2e_binding"),
        "expected missing_e2e_binding, got {signatures:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_mode_contract_allowed_value_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "env-semantics-mode-contract-drift")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let mut artifact = load_json(&mode_contract_path(&root))?;
    let env_contract = artifact
        .get_mut("env_contract")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("env_contract should be an object"))?;
    env_contract.insert(
        "allowed_values".to_owned(),
        json!(["strict", "hardened", "off"]),
    );
    let bad_artifact = out_dir.join("mode_contract_lock.v1.json");
    write_json(&bad_artifact, &artifact)?;
    set_artifact_path(&mut manifest, "mode_contract_lock", &bad_artifact)?;
    let bad_manifest = out_dir.join("manifest.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(
        signatures.contains("mode_contract_drift"),
        "expected mode_contract_drift, got {signatures:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_mode_semantics_family_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "env-semantics-family-drift")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let mut matrix = load_json(&mode_semantics_matrix_path(&root))?;
    let families = matrix
        .get_mut("families")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("families should be an array"))?;
    families.pop();
    let bad_matrix = out_dir.join("mode_semantics_matrix.json");
    write_json(&bad_matrix, &matrix)?;
    set_artifact_path(&mut manifest, "mode_semantics_matrix", &bad_matrix)?;
    let bad_manifest = out_dir.join("manifest.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(
        signatures.contains("mode_semantics_drift"),
        "expected mode_semantics_drift, got {signatures:?}"
    );
    Ok(())
}
