//! Completion-contract tests for bd-29b.2.1 docs env mismatch evidence.

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
    "docs_inventory_validated",
    "docs_mismatch_report_validated",
    "docs_governance_validated",
    "base_docs_env_gate_replayed",
    "missing_item_bindings_validated",
    "test_surfaces_validated",
    "docs_env_mismatch_completion_contract_validated",
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
    root.join("tests/conformance/docs_env_mismatch_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_docs_env_mismatch_completion_contract.sh")
}

fn base_gate_path(root: &Path) -> PathBuf {
    root.join("scripts/check_docs_env_mismatch.sh")
}

fn mismatch_report_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/env_docs_code_mismatch_report.v1.json")
}

fn source_map_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/docs_source_of_truth_map.v1.json")
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
        .env("FRANKENLIBC_DOCS_ENV_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_DOCS_ENV_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_DOCS_ENV_COMPLETION_REPORT",
            out_dir.join("docs_env_mismatch_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_DOCS_ENV_COMPLETION_LOG",
            out_dir.join("docs_env_mismatch_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("docs_env_mismatch_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("docs_env_mismatch_completion_contract.log.jsonl")
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

fn set_artifact_path(manifest: &mut Value, artifact_id: &str, path: &Path) -> TestResult {
    let artifacts = manifest
        .get_mut("source_artifacts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("source_artifacts should be an array"))?;
    let artifact = artifacts
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some(artifact_id))
        .ok_or_else(|| test_error(format!("missing source artifact {artifact_id}")))?;
    artifact["path"] = json!(path.display().to_string());
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
fn contract_binds_docs_env_unit_and_e2e_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "docs_env_mismatch_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-29b.2.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-29b.2"
    );

    let artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let artifact_ids: BTreeSet<_> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "docs_env_inventory",
        "docs_mismatch_report",
        "docs_source_map",
        "docs_trace",
        "docs_env_generator",
        "docs_env_gate",
        "docs_env_harness_test",
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
            "tests.unit.primary".to_owned(),
        ])
    );
    let generator_surfaces = array_field(
        completion,
        "required_generator_surfaces",
        "completion_contract",
    )?;
    assert!(
        generator_surfaces
            .iter()
            .any(|row| row.as_str() == Some("classify_mismatches")),
        "completion contract must bind mismatch classifier implementation"
    );
    let required_docs = field(completion, "required_docs_summary", "completion_contract")?;
    let required_keys = string_set(required_docs, "required_env_keys", "required_docs_summary")?;
    assert!(required_keys.contains("FRANKENLIBC_MODE"));
    assert!(required_keys.contains("FRANKENLIBC_LOG"));

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
fn checker_accepts_docs_env_mismatch_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "docs-env-completion")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert!(
        report["summary"]["docs_keys"]
            .as_u64()
            .is_some_and(|n| n >= 25),
        "completion report must carry docs key count"
    );
    assert!(
        report["summary"]["surface_count"]
            .as_u64()
            .is_some_and(|n| n >= 6),
        "completion report must carry governed surface count"
    );
    assert_eq!(
        report["summary"]["classification_count"].as_u64(),
        Some(0),
        "completion report must preserve zero classifications"
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
fn completion_contract_runs_base_docs_env_gate() -> TestResult {
    let root = workspace_root()?;
    let output = Command::new("bash")
        .arg(base_gate_path(&root))
        .current_dir(root)
        .output()?;
    assert!(
        output.status.success(),
        "base gate failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS: docs/code mismatch report reconciled"));
    assert!(stdout.contains("PASS: docs source-of-truth map validated"));
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
        write_mutated_manifest(&root, "docs-env-missing-e2e", &manifest)?;
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
fn checker_rejects_unresolved_mismatch_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "docs-env-unresolved-report")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let mut report = load_json(&mismatch_report_path(&root))?;
    report["summary"]["missing_in_docs_count"] = json!(1);
    report["summary"]["total_classifications"] = json!(1);
    report["classifications"] = json!([
        {
            "env_key": "FRANKENLIBC_FAKE_TEST_ONLY",
            "mismatch_class": "missing_in_docs",
            "evidence": [
                {
                    "path": "tests/conformance/runtime_env_inventory.v1.json",
                    "source": "code_inventory"
                }
            ],
            "details": "test-only unresolved docs/code mismatch",
            "remediation_action": "document_knob_or_mark_internal_only"
        }
    ]);
    let bad_report = out_dir.join("env_docs_code_mismatch_report.v1.json");
    write_json(&bad_report, &report)?;
    set_artifact_path(&mut manifest, "docs_mismatch_report", &bad_report)?;
    let bad_manifest = out_dir.join("manifest.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;

    let checker_report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&checker_report);
    assert!(
        signatures.contains("unresolved_docs_mismatch"),
        "expected unresolved_docs_mismatch, got {signatures:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_governance_surface() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "docs-env-missing-surface")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let mut source_map = load_json(&source_map_path(&root))?;
    let surfaces = source_map
        .get_mut("surfaces")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("source map surfaces should be an array"))?;
    surfaces.retain(|row| row.get("surface_id").and_then(Value::as_str) != Some("TROUBLESHOOTING"));
    let bad_source_map = out_dir.join("docs_source_of_truth_map.v1.json");
    write_json(&bad_source_map, &source_map)?;
    set_artifact_path(&mut manifest, "docs_source_map", &bad_source_map)?;
    let bad_manifest = out_dir.join("manifest.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;

    let checker_report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&checker_report);
    assert!(
        signatures.contains("missing_governance_surface"),
        "expected missing_governance_surface, got {signatures:?}"
    );
    Ok(())
}
