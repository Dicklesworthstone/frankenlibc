//! Completion-contract tests for bd-747.1 environment invariants.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_contract_shape_validated",
    "missing_item_bindings_validated",
    "core_env_validation_validated",
    "abi_env_functions_validated",
    "env_test_sources_validated",
    "env_fuzz_shadow_model_validated",
    "env_telemetry_validated",
    "test_surfaces_validated",
    "env_invariants_completion_contract_validated",
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
    root.join("tests/conformance/env_invariants_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_env_invariants_completion_contract.sh")
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
        .env("FRANKENLIBC_ENV_INVARIANTS_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_ENV_INVARIANTS_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_ENV_INVARIANTS_COMPLETION_REPORT",
            out_dir.join("env_invariants_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ENV_INVARIANTS_COMPLETION_LOG",
            out_dir.join("env_invariants_completion_contract.events.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("env_invariants_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("env_invariants_completion_contract.events.jsonl")
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

fn source_artifact_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    Ok(array_field(manifest, "source_artifacts", "manifest")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect())
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

fn remove_binding(manifest: &mut Value, missing_item_id: &str) -> TestResult {
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("missing_item_bindings should be an array"))?;
    bindings
        .retain(|row| row.get("missing_item_id").and_then(Value::as_str) != Some(missing_item_id));
    Ok(())
}

fn remove_required_value(manifest: &mut Value, key: &str, needle: &str) -> TestResult {
    let values = manifest
        .get_mut("completion_contract")
        .and_then(Value::as_object_mut)
        .and_then(|obj| obj.get_mut(key))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error(format!("completion_contract.{key} should be an array")))?;
    values.retain(|row| row.as_str() != Some(needle));
    Ok(())
}

#[test]
fn contract_binds_env_invariant_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "env_invariants_completion_contract.v1"
    );
    assert_eq!(string_field(&manifest, "bead_id", "manifest")?, "bd-747.1");
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-747"
    );

    let artifact_ids = source_artifact_ids(&manifest)?;
    for required in [
        "core_env_validation",
        "abi_env_functions",
        "metamorphic_env_tests",
        "secure_getenv_diff_tests",
        "stdlib_env_regressions",
        "env_fuzz_shadow_model",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(
            artifact_ids.contains(required),
            "missing source artifact {required}"
        );
    }

    let completion = field(&manifest, "completion_contract", "manifest")?;
    let missing_items = string_set(completion, "missing_item_ids", "completion_contract")?;
    assert!(missing_items.contains("tests.unit.primary"));
    assert!(missing_items.contains("tests.e2e.primary"));
    assert!(missing_items.contains("telemetry.primary"));

    let required_symbols = string_set(completion, "required_symbols", "completion_contract")?;
    assert_eq!(
        required_symbols,
        BTreeSet::from([
            "getenv".to_owned(),
            "secure_getenv".to_owned(),
            "setenv".to_owned(),
            "unsetenv".to_owned(),
        ])
    );

    let validation_commands = array_field(&manifest, "required_validation_commands", "manifest")?;
    assert!(
        validation_commands
            .iter()
            .filter_map(Value::as_str)
            .any(|cmd| cmd.contains("--test metamorphic_getenv"))
    );
    assert!(
        validation_commands
            .iter()
            .filter_map(Value::as_str)
            .any(|cmd| cmd.contains("--test conformance_diff_secure_getenv"))
    );
    Ok(())
}

#[test]
fn checker_accepts_env_invariants_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "env-invariants-check")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS env invariants completion contract")
    );

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "env_invariants_completion_contract.report.v1"
    );
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    let artifact_refs = array_field(&report, "artifact_refs", "report")?;
    assert!(
        artifact_refs
            .iter()
            .filter_map(Value::as_str)
            .any(|path| path.ends_with("crates/frankenlibc-fuzz/fuzz_targets/fuzz_env.rs"))
    );
    Ok(())
}

#[test]
fn checker_emits_structured_env_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "env-invariants-telemetry")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names: BTreeSet<_> = events
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(
            event_names.contains(required),
            "missing checker event {required}"
        );
    }
    for row in &events {
        assert_eq!(string_field(row, "bead_id", "event")?, "bd-747.1");
        assert!(
            string_field(row, "trace_id", "event")?
                .starts_with("bd-747.1::env-invariants::completion::v1::")
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_binding(&mut manifest, "tests.e2e.primary")?;

    let out_dir = unique_output_dir(&root, "env-invariants-missing-e2e")?;
    let bad_manifest = out_dir.join("bad_missing_e2e.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_e2e_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_anchor() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_required_value(&mut manifest, "required_fuzz_anchors", "Final sweep")?;

    let out_dir = unique_output_dir(&root, "env-invariants-missing-fuzz")?;
    let bad_manifest = out_dir.join("bad_missing_fuzz_anchor.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(
        failure_signatures(&report).contains("env_fuzz_shadow_model_drift")
            || failure_signatures(&report).contains("malformed_contract")
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_binding(&mut manifest, "telemetry.primary")?;

    let out_dir = unique_output_dir(&root, "env-invariants-missing-telemetry")?;
    let bad_manifest = out_dir.join("bad_missing_telemetry.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_telemetry_binding"));
    Ok(())
}
