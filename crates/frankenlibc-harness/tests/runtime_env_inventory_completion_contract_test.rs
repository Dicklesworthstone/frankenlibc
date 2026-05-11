//! Completion-contract tests for bd-29b.1.1 runtime env inventory evidence.

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
    "inventory_metadata_validated",
    "missing_item_bindings_validated",
    "test_surfaces_validated",
    "runtime_env_inventory_completion_contract_validated",
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
    root.join("tests/conformance/runtime_env_inventory_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_env_inventory_completion_contract.sh")
}

fn base_gate_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_env_inventory.sh")
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
        .env("FRANKENLIBC_RUNTIME_ENV_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_RUNTIME_ENV_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RUNTIME_ENV_COMPLETION_REPORT",
            out_dir.join("runtime_env_inventory_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_ENV_COMPLETION_LOG",
            out_dir.join("runtime_env_inventory_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("runtime_env_inventory_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("runtime_env_inventory_completion_contract.log.jsonl")
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

fn write_mutated_manifest(
    root: &Path,
    prefix: &str,
    manifest: &Value,
) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, prefix)?;
    let path = out_dir.join("manifest.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

fn tracked_snapshot(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let out_dir = unique_output_dir(root, prefix)?;
    let archive = out_dir.join("repo.tar");
    let archive_output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["archive", "--format=tar", "-o"])
        .arg(&archive)
        .arg("HEAD")
        .output()?;
    assert!(
        archive_output.status.success(),
        "git archive failed stdout={} stderr={}",
        String::from_utf8_lossy(&archive_output.stdout),
        String::from_utf8_lossy(&archive_output.stderr)
    );

    let snapshot = out_dir.join("repo");
    std::fs::create_dir_all(&snapshot)?;
    let extract_output = Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(&snapshot)
        .output()?;
    assert!(
        extract_output.status.success(),
        "tar extract failed stdout={} stderr={}",
        String::from_utf8_lossy(&extract_output.stdout),
        String::from_utf8_lossy(&extract_output.stderr)
    );
    Ok(snapshot)
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
fn contract_binds_runtime_env_inventory_unit_and_e2e_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "runtime_env_inventory_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-29b.1.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-29b.1"
    );

    let artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let artifact_ids: BTreeSet<_> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "runtime_env_inventory",
        "runtime_env_generator",
        "runtime_env_gate",
        "runtime_env_harness_test",
        "completion_contract",
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
            "tests.unit.primary".to_owned()
        ])
    );
    let metadata = string_set(
        completion,
        "required_metadata_fields",
        "completion_contract",
    )?;
    assert!(metadata.contains("parse_rule"));
    assert!(metadata.contains("safety_impact"));

    let bindings = array_field(&manifest, "missing_item_bindings", "manifest")?;
    let bound_items: BTreeSet<_> = bindings
        .iter()
        .filter_map(|row| row.get("missing_item_id").and_then(Value::as_str))
        .collect();
    assert!(bound_items.contains("tests.unit.primary"));
    assert!(bound_items.contains("tests.e2e.primary"));
    Ok(())
}

#[test]
fn checker_accepts_runtime_env_inventory_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "runtime-env-completion")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["unknown_or_ambiguous_count"].as_u64(),
        Some(0)
    );
    assert!(
        report["summary"]["total_keys"]
            .as_u64()
            .is_some_and(|n| n >= 25),
        "completion report must carry inventory summary"
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
fn completion_contract_runs_base_inventory_gate() -> TestResult {
    let root = workspace_root()?;
    let root = tracked_snapshot(&root, "runtime-env-base-gate-snapshot")?;
    let output = Command::new("bash")
        .arg(base_gate_path(&root))
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "base gate failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS: runtime env inventory gate"));
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("missing_item_bindings should be an array"))?;
    bindings.retain(|row| {
        row.get("missing_item_id").and_then(Value::as_str) != Some("tests.e2e.primary")
    });
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "runtime-env-missing-e2e", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
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
fn checker_rejects_incomplete_missing_item_set() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest
        .get_mut("completion_contract")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("completion_contract should be an object"))?
        .insert("missing_item_ids".to_owned(), json!(["tests.unit.primary"]));
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "runtime-env-incomplete-items", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(
        signatures.contains("missing_completion_contract"),
        "expected missing_completion_contract, got {signatures:?}"
    );
    Ok(())
}
