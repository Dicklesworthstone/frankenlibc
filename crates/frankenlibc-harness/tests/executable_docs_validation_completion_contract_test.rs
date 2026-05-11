//! Completion-contract tests for bd-3rw.5.2 executable docs validation evidence.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
    root.join("tests/conformance/executable_docs_validation_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_executable_docs_validation_completion_contract.sh")
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
        if !line.trim().is_empty() {
            rows.push(serde_json::from_str(line)?);
        }
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

fn run_checker(
    root: &Path,
    manifest: &Path,
    out_dir: &Path,
    skip_base: bool,
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_EXEC_DOCS_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_EXEC_DOCS_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_EXEC_DOCS_COMPLETION_REPORT",
            out_dir.join("executable_docs_validation_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_EXEC_DOCS_COMPLETION_LOG",
            out_dir.join("executable_docs_validation_completion_contract.log.jsonl"),
        );
    if skip_base {
        command.env("FRANKENLIBC_EXEC_DOCS_SKIP_BASE_GATES", "1");
    }
    Ok(command.output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("executable_docs_validation_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("executable_docs_validation_completion_contract.log.jsonl")
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
fn manifest_binds_all_missing_items_and_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "executable_docs_validation_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-3rw.5.2"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-3rw.5"
    );

    let source_ids: BTreeSet<_> = array_field(&manifest, "source_artifacts", "manifest")?
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "docs_env_generator",
        "docs_env_gate",
        "claim_reconciliation",
        "claim_reconciliation_gate",
        "release_dossier_validator",
        "release_dossier_completion_gate",
        "fuzz_phase1_completion_contract",
        "fuzz_phase1_completion_gate",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(
            source_ids.contains(required),
            "missing source artifact {required}"
        );
    }

    let binding_ids: BTreeSet<_> = array_field(&manifest, "missing_item_bindings", "manifest")?
        .iter()
        .filter_map(|binding| binding.get("missing_item_id").and_then(Value::as_str))
        .collect();
    assert_eq!(
        binding_ids,
        BTreeSet::from([
            "telemetry.primary",
            "tests.conformance.primary",
            "tests.e2e.primary",
            "tests.fuzz.primary",
            "tests.unit.primary",
        ])
    );

    let required_tests = field(&manifest, "required_test_functions", "manifest")?;
    for test_file in [
        "crates/frankenlibc-harness/tests/docs_env_mismatch_test.rs",
        "crates/frankenlibc-harness/tests/claim_reconciliation_test.rs",
        "crates/frankenlibc-harness/tests/release_dossier_validator_test.rs",
        "crates/frankenlibc-harness/tests/fuzz_phase1_targets_completion_contract_test.rs",
        "crates/frankenlibc-harness/tests/executable_docs_validation_completion_contract_test.rs",
    ] {
        assert!(
            required_tests.get(test_file).is_some(),
            "missing required_test_functions entry for {test_file}"
        );
    }

    let telemetry = field(&manifest, "telemetry_contract", "manifest")?;
    assert!(
        string_set(telemetry, "required_events", "telemetry_contract")?
            .contains("executable_docs_completion_contract_validated")
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "executable-docs-pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir, false)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-3rw.5.2"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-3rw.5"));
    assert!(
        report["summary"]["binding_count"].as_u64().unwrap_or(0) >= 5,
        "all missing item bindings should be counted"
    );
    let base_gate_count = report["base_gate_results"].as_array().map_or(0, Vec::len);
    assert!(base_gate_count >= 4, "checker should run the base gates");

    let rows = load_jsonl(&checker_log(&out_dir))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for expected in [
        "executable_docs_sources_validated",
        "executable_docs_base_gates_validated",
        "executable_docs_bindings_validated",
        "executable_docs_completion_contract_validated",
    ] {
        assert!(events.contains(expected), "missing event {expected}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_item_bindings should be an array"))?;
    bindings.retain(|binding| {
        binding.get("missing_item_id").and_then(Value::as_str) != Some("tests.fuzz.primary")
    });
    let (path, out_dir) = write_mutated_manifest(&root, "missing-fuzz", &manifest)?;
    let output = run_checker(&root, &path, &out_dir, true)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_fuzz_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_source_artifact() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array_mut()
        .ok_or_else(|| test_error("source_artifacts should be an array"))?;
    let artifact = artifacts
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some("release_dossier_validator"))
        .ok_or_else(|| test_error("release_dossier_validator source artifact should exist"))?;
    artifact["path"] = json!("tests/conformance/does-not-exist-release-dossier-validator.py");
    let (path, out_dir) = write_mutated_manifest(&root, "missing-source", &manifest)?;
    let output = run_checker(&root, &path, &out_dir, true)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_source_artifact"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let events = manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("telemetry required_events should be an array"))?;
    events.retain(|event| event.as_str() != Some("executable_docs_completion_contract_validated"));
    let (path, out_dir) = write_mutated_manifest(&root, "missing-telemetry-event", &manifest)?;
    let output = run_checker(&root, &path, &out_dir, true)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("telemetry_contract_failed"));
    Ok(())
}
