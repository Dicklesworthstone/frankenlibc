//! Completion-contract tests for bd-26xb.3.1 compatibility SLO/certification evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_and_bindings_validated",
    "release_dossier_report_validated",
    "compatibility_slo_certification_completion_contract_validated",
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
    root.join("tests/release/compatibility_slo_certification_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_compatibility_slo_certification_completion_contract.sh")
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

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_COMPAT_SLO_CONTRACT", manifest)
        .env("FRANKENLIBC_COMPAT_SLO_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_COMPAT_SLO_REPORT",
            out_dir.join("compatibility_slo_certification_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_COMPAT_SLO_LOG",
            out_dir.join("compatibility_slo_certification_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("compatibility_slo_certification_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("compatibility_slo_certification_completion_contract.log.jsonl")
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

#[test]
fn manifest_binds_unit_and_e2e_evidence_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "compatibility_slo_certification_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-26xb.3.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-26xb.3"
    );

    let artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let artifact_ids: BTreeSet<_> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "release_dossier_validator",
        "release_dossier_gate",
        "release_dossier_report",
        "release_dossier_harness_test",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(
            artifact_ids.contains(required),
            "missing artifact {required}"
        );
    }
    for artifact in artifacts {
        let path = string_field(artifact, "path", "source_artifacts[]")?;
        assert!(root.join(path).is_file(), "source artifact missing: {path}");
    }

    let dossier = field(&manifest, "dossier_contract", "manifest")?;
    assert_eq!(
        field(dossier, "required_artifact_count", "dossier_contract")?.as_u64(),
        Some(15)
    );
    assert_eq!(
        field(dossier, "required_integrity_entries", "dossier_contract")?.as_u64(),
        Some(14)
    );

    let bindings = array_field(&manifest, "missing_item_bindings", "manifest")?;
    let spec_items: BTreeSet<_> = bindings
        .iter()
        .filter_map(|binding| binding.get("spec_item").and_then(Value::as_str))
        .collect();
    assert!(spec_items.contains("tests.unit.primary"));
    assert!(spec_items.contains("tests.e2e.primary"));
    Ok(())
}

#[test]
fn checker_accepts_compatibility_slo_certification_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "compat-slo-certification-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    let summary = field(&report, "summary", "report")?;
    assert_eq!(
        field(summary, "artifact_count", "summary")?.as_u64(),
        Some(15)
    );
    assert_eq!(
        field(summary, "integrity_entries", "summary")?.as_u64(),
        Some(14)
    );
    assert_eq!(
        field(summary, "release_note_candidates", "summary")?.as_u64(),
        Some(8)
    );

    let refs: BTreeSet<_> = array_field(&report, "artifact_refs", "report")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for required in [
        "scripts/release_dossier_validator.py",
        "scripts/check_release_dossier.sh",
        "tests/release/dossier_validation_report.v1.json",
    ] {
        assert!(refs.contains(required), "missing artifact ref {required}");
    }

    let rows = load_jsonl(&checker_log(&out_dir))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(events.contains(required), "missing event {required}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_item_bindings should be array"))?;
    bindings.retain(|binding| {
        binding.get("spec_item").and_then(Value::as_str) != Some("tests.unit.primary")
    });
    let (manifest_path, out_dir) = write_mutated_manifest(&root, "compat-slo-no-unit", &manifest)?;

    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("missing_unit_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_item_bindings should be array"))?;
    bindings.retain(|binding| {
        binding.get("spec_item").and_then(Value::as_str) != Some("tests.e2e.primary")
    });
    let (manifest_path, out_dir) = write_mutated_manifest(&root, "compat-slo-no-e2e", &manifest)?;

    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("missing_e2e_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_artifact_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array_mut()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    artifacts.retain(|artifact| {
        artifact.get("id").and_then(Value::as_str) != Some("release_dossier_report")
    });
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "compat-slo-no-report", &manifest)?;

    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("missing_source_artifact"));
    Ok(())
}
