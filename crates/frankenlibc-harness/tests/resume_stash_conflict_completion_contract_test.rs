//! Completion-contract tests for bd-jirj3.1 resume stash conflict repair evidence.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "git_index_validated",
    "conflict_markers_absent",
    "json_artifacts_validated",
    "missing_item_bindings_validated",
    "test_surfaces_validated",
    "resume_stash_conflict_completion_contract_validated",
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
    root.join("tests/conformance/resume_stash_conflict_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_resume_stash_conflict_completion_contract.sh")
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
        .env("FRANKENLIBC_RESUME_STASH_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_RESUME_STASH_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RESUME_STASH_COMPLETION_REPORT",
            out_dir.join("resume_stash_conflict_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RESUME_STASH_COMPLETION_LOG",
            out_dir.join("resume_stash_conflict_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("resume_stash_conflict_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("resume_stash_conflict_completion_contract.log.jsonl")
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

fn failure_signatures(report: &Value) -> BTreeSet<&str> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .collect()
}

fn object_field_mut<'a>(
    value: &'a mut Value,
    key: &str,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

#[test]
fn contract_binds_resume_stash_conflict_conformance_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "resume_stash_conflict_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-jirj3.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-jirj3"
    );

    let artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let artifact_ids: BTreeSet<_> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "original_tracker_row",
        "perf_regression_prevention_artifact",
        "uncovered_hotpath_manifest",
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
        BTreeSet::from(["tests.conformance.primary".to_owned()])
    );
    let prefixes = string_set(
        completion,
        "conflict_marker_prefixes",
        "completion_contract",
    )?;
    assert!(prefixes.contains("<<<<<<<"));
    assert!(prefixes.contains(">>>>>>>"));
    assert!(prefixes.contains("|||||||"));

    let bindings = array_field(&manifest, "missing_item_bindings", "manifest")?;
    let bound_items: BTreeSet<_> = bindings
        .iter()
        .filter_map(|row| row.get("missing_item_id").and_then(Value::as_str))
        .collect();
    assert!(bound_items.contains("tests.conformance.primary"));
    Ok(())
}

#[test]
fn checker_accepts_clean_resume_stash_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "resume-stash-completion")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["unmerged_entry_count"].as_u64(), Some(0));
    assert_eq!(report["summary"]["conflict_marker_count"].as_u64(), Some(0));
    assert!(
        report["summary"]["json_artifact_count"]
            .as_u64()
            .is_some_and(|count| count >= 100),
        "checker should parse the tracked JSON artifact family"
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
fn checker_rejects_missing_conformance_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    object_field_mut(&mut manifest, "completion_contract", "manifest")?
        .insert("missing_item_ids".to_owned(), json!([]));
    manifest
        .as_object_mut()
        .ok_or_else(|| test_error("manifest must be an object"))?
        .insert("missing_item_bindings".to_owned(), json!([]));

    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "resume-stash-missing-binding", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_conformance_binding"));
    Ok(())
}

#[test]
fn checker_rejects_conflict_marker_probe() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let probe_dir = unique_output_dir(&root, "resume-stash-conflict-probe")?;
    let probe = probe_dir.join("conflict.rs");
    std::fs::write(
        &probe,
        "<<<<<<< Updated upstream\nlet value = 1;\n>>>>>>> Stashed changes\n",
    )?;
    object_field_mut(&mut manifest, "completion_contract", "manifest")?.insert(
        "conflict_marker_probe_paths".to_owned(),
        json!([probe.display().to_string()]),
    );

    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "resume-stash-conflict-marker", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("conflict_marker_found"));
    Ok(())
}
