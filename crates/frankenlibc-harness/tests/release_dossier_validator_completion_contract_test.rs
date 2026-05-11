//! Completion-contract tests for bd-5fw.3.1 release dossier validator evidence.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_SOURCE_IDS: &[&str] = &[
    "release_dossier_validator",
    "release_dossier_gate",
    "release_dossier_report",
    "release_dossier_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
];

const REQUIRED_MISSING_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
];

const REQUIRED_DOSSIER_IDS: &[&str] = &[
    "support_matrix",
    "reality_report",
    "conformance_coverage",
    "claim_reconciliation",
    "closure_sweep",
    "replacement_levels",
    "opportunity_matrix",
    "math_governance",
    "controller_ablation",
    "admission_gate",
    "production_kernel_manifest",
    "release_gate_dag",
    "symbol_fixture_coverage",
    "e2e_scenario_manifest",
    "closure_contract",
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

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/release/release_dossier_validator_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_release_dossier_validator_completion_contract.sh")
}

fn source_report_path(root: &Path) -> PathBuf {
    root.join("tests/release/dossier_validation_report.v1.json")
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("release_dossier_validator_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("release_dossier_validator_completion_contract.log.jsonl")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
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
                .map(ToOwned::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain only strings")))
        })
        .collect::<TestResult<_>>()
}

fn run_checker(
    root: &Path,
    manifest: &Path,
    out_dir: &Path,
    dossier_report: Option<&Path>,
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_LOG",
            checker_log(out_dir),
        );
    if let Some(path) = dossier_report {
        command.env("FRANKENLIBC_RELEASE_DOSSIER_REPORT", path);
    }
    Ok(command.output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed: {}",
        output_text(output)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed: {}",
        output_text(output)
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

fn write_mutated_dossier_report(
    root: &Path,
    prefix: &str,
    report: &Value,
) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, prefix)?;
    let path = out_dir.join("dossier_validation_report.v1.json");
    write_json(&path, report)?;
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

fn expected(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn manifest_binds_unit_e2e_conformance_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "release_dossier_validator_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "completion_debt_bead", "manifest")?,
        "bd-5fw.3.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-5fw.3"
    );

    let artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let artifact_ids: BTreeSet<_> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_SOURCE_IDS {
        assert!(
            artifact_ids.contains(required),
            "source_artifacts missing {required}"
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
    assert_eq!(
        string_set(dossier, "required_artifact_ids", "dossier_contract")?,
        expected(REQUIRED_DOSSIER_IDS)
    );

    let bindings = array_field(&manifest, "missing_item_bindings", "manifest")?;
    let spec_items: BTreeSet<_> = bindings
        .iter()
        .filter_map(|binding| binding.get("spec_item").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_MISSING_ITEMS {
        assert!(spec_items.contains(required), "missing binding {required}");
    }
    Ok(())
}

#[test]
fn checker_accepts_release_dossier_validator_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "release-dossier-validator-ok")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir, None)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "completion_debt_bead", "report")?,
        "bd-5fw.3.1"
    );
    assert_eq!(
        string_field(&report, "original_bead", "report")?,
        "bd-5fw.3"
    );
    let summary = field(&report, "summary", "report")?;
    assert_eq!(
        field(summary, "dossier_artifact_count", "summary")?.as_u64(),
        Some(15)
    );
    assert_eq!(
        field(summary, "integrity_entries", "summary")?.as_u64(),
        Some(14)
    );
    assert_eq!(
        field(summary, "allowed_missing_count", "summary")?.as_u64(),
        Some(1)
    );
    Ok(())
}

#[test]
fn checker_emits_structured_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "release-dossier-validator-log")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir, None)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "release_dossier_validator_completion_contract.v1.report"
    );
    assert_eq!(string_field(&report, "status", "report")?, "pass");

    let log_text = std::fs::read_to_string(checker_log(&out_dir))?;
    let row: Value = serde_json::from_str(log_text.trim())?;
    assert_eq!(
        row["event"].as_str(),
        Some("release_dossier_validator_completion_contract_validated")
    );
    assert_eq!(row["stream"].as_str(), Some("release"));
    assert_eq!(
        row["gate"].as_str(),
        Some("release_dossier_validator_completion")
    );
    assert_eq!(row["outcome"].as_str(), Some("pass"));
    validate_log_line(log_text.trim(), 1)
        .map_err(|errors| test_error(format!("structured log validation failed: {errors:?}")))?;
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_item_bindings should be array"))?;
    bindings.retain(|binding| {
        binding.get("spec_item").and_then(Value::as_str) != Some("tests.unit.primary")
    });
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "release-dossier-no-unit", &manifest)?;

    let output = run_checker(&root, &manifest_path, &out_dir, None)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("missing_unit_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_item_bindings should be array"))?;
    bindings.retain(|binding| {
        binding.get("spec_item").and_then(Value::as_str) != Some("tests.e2e.primary")
    });
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "release-dossier-no-e2e", &manifest)?;

    let output = run_checker(&root, &manifest_path, &out_dir, None)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("missing_e2e_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_conformance_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_item_bindings should be array"))?;
    bindings.retain(|binding| {
        binding.get("spec_item").and_then(Value::as_str) != Some("tests.conformance.primary")
    });
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "release-dossier-no-conformance", &manifest)?;

    let output = run_checker(&root, &manifest_path, &out_dir, None)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("missing_conformance_binding"));
    Ok(())
}

#[test]
fn checker_rejects_removed_required_artifact_id() -> TestResult {
    let root = workspace_root()?;
    let mut dossier = load_json(&source_report_path(&root))?;
    let results = dossier["artifact_results"]
        .as_array_mut()
        .ok_or_else(|| test_error("artifact_results should be array"))?;
    results.retain(|row| row.get("id").and_then(Value::as_str) != Some("support_matrix"));
    let (dossier_path, out_dir) =
        write_mutated_dossier_report(&root, "release-dossier-no-support-matrix", &dossier)?;

    let output = run_checker(&root, &contract_path(&root), &out_dir, Some(&dossier_path))?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("dossier_report_failed"));
    Ok(())
}

#[test]
fn checker_rejects_missing_integrity_binding() -> TestResult {
    let root = workspace_root()?;
    let mut dossier = load_json(&source_report_path(&root))?;
    let integrity = dossier["integrity_index"]
        .as_object_mut()
        .ok_or_else(|| test_error("integrity_index should be object"))?;
    integrity.remove("support_matrix");
    let (dossier_path, out_dir) =
        write_mutated_dossier_report(&root, "release-dossier-no-integrity", &dossier)?;

    let output = run_checker(&root, &contract_path(&root), &out_dir, Some(&dossier_path))?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("dossier_integrity_failed"));
    Ok(())
}

#[test]
fn checker_rejects_non_pass_dossier_report() -> TestResult {
    let root = workspace_root()?;
    let mut dossier = load_json(&source_report_path(&root))?;
    dossier["status"] = Value::String("fail".to_owned());
    dossier["verdict"] = Value::String("FAIL".to_owned());
    let (dossier_path, out_dir) =
        write_mutated_dossier_report(&root, "release-dossier-fail-verdict", &dossier)?;

    let output = run_checker(&root, &contract_path(&root), &out_dir, Some(&dossier_path))?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report).contains("dossier_report_failed"));
    Ok(())
}
