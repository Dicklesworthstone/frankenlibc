//! Completion-contract tests for bd-2625.1 runtime_math divergence-bounds integration evidence.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "divergence_matrix_contract_validated",
    "integration_contract_validated",
    "integration_binding_validated",
    "harness_gate_surface_validated",
    "runtime_math_divergence_integration_contract_validated",
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
    root.join("tests/runtime_math/runtime_math_divergence_bounds_integration_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_divergence_bounds_integration_contract.sh")
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
        .env(
            "FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_REPORT",
            out_dir.join("runtime_math_divergence_bounds_integration_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_LOG",
            out_dir.join("runtime_math_divergence_bounds_integration_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("runtime_math_divergence_bounds_integration_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("runtime_math_divergence_bounds_integration_contract.log.jsonl")
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
fn contract_binds_runtime_math_divergence_integration_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "runtime_math_divergence_bounds_integration_contract.v1"
    );
    assert_eq!(string_field(&manifest, "bead_id", "manifest")?, "bd-2625.1");
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-2625"
    );
    assert_eq!(
        string_field(&manifest, "trace_id", "manifest")?,
        "bd-2625.1::runtime-math-divergence-bounds::integration::v1"
    );

    let artifacts = array_field(&manifest, "source_artifacts", "manifest")?;
    let artifact_ids: BTreeSet<_> = artifacts
        .iter()
        .filter_map(|artifact| artifact.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "divergence_matrix",
        "divergence_gate_script",
        "divergence_harness",
        "existing_integration_test",
        "completion_contract",
        "completion_gate",
        "completion_integration_test",
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

    let integration = field(&manifest, "integration_contract", "manifest")?;
    assert_eq!(
        string_field(integration, "missing_item_id", "integration_contract")?,
        "tests.integration.primary"
    );
    assert_eq!(
        string_set(integration, "required_modes", "integration_contract")?,
        BTreeSet::from(["hardened".to_owned(), "strict".to_owned()])
    );
    let outputs = string_set(
        integration,
        "required_output_artifacts",
        "integration_contract",
    )?;
    assert!(
        outputs.contains("runtime_math_divergence_bounds.integration.log.jsonl"),
        "contract must require integration log output"
    );
    assert!(
        outputs.contains("runtime_math_divergence_bounds.integration.report.json"),
        "contract must require integration report output"
    );

    let bindings = array_field(&manifest, "missing_item_bindings", "manifest")?;
    let binding = bindings
        .iter()
        .find(|row| {
            row.get("missing_item_id").and_then(Value::as_str) == Some("tests.integration.primary")
        })
        .ok_or_else(|| test_error("missing integration binding"))?;
    let implementation_refs =
        string_set(binding, "implementation_refs", "missing_item_bindings[]")?;
    assert!(
        implementation_refs
            .contains("crates/frankenlibc-harness/src/runtime_math_divergence_bounds.rs"),
        "binding must cite harness implementation"
    );
    let test_refs = string_set(binding, "test_refs", "missing_item_bindings[]")?;
    assert!(
        test_refs.contains(
            "crates/frankenlibc-harness/tests/runtime_math_divergence_bounds_integration_contract_test.rs"
        ),
        "binding must cite completion integration test"
    );
    Ok(())
}

#[test]
fn checker_accepts_runtime_math_divergence_integration_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "runtime-math-divergence-contract")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["total_cases"].as_u64(), Some(7));
    assert_eq!(
        report["summary"]["required_modes"].as_array().map(Vec::len),
        Some(2)
    );
    assert!(
        report["errors"].as_array().is_some_and(Vec::is_empty),
        "checker should emit no errors"
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
fn integration_gate_generates_structured_runtime_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "runtime-math-divergence-integration")?;
    let log_path = out_dir.join("runtime_math_divergence_bounds.integration.log.jsonl");
    let report_path = out_dir.join("runtime_math_divergence_bounds.integration.report.json");

    let report = frankenlibc_harness::runtime_math_divergence_bounds::run_and_write(
        &root,
        &log_path,
        &report_path,
    )?;
    assert_eq!(report.schema_version, "v1");
    assert_eq!(report.bead, "bd-2625");
    assert_eq!(report.summary.total_cases, 7);
    assert_eq!(report.summary.required_cases, 3);
    assert_eq!(report.summary.failed, 0);
    assert_eq!(report.summary.violations, 0);
    assert!(
        report
            .results
            .iter()
            .any(|row| row.strict.action != row.hardened.action
                || row.strict.profile != row.hardened.profile),
        "integration report should preserve at least one intentional strict/hardened divergence"
    );

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)?;
    assert!(errors.is_empty(), "structured log errors: {errors:#?}");
    assert!(
        line_count >= 8,
        "start plus seven case rows should produce at least eight log lines"
    );

    let persisted_report = load_json(&report_path)?;
    assert_eq!(persisted_report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(persisted_report["summary"]["violations"].as_u64(), Some(0));
    assert_eq!(
        persisted_report["sources"]["matrix"].as_str(),
        Some("tests/runtime_math/runtime_math_divergence_bounds.v1.json")
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_integration_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    *manifest
        .get_mut("missing_item_bindings")
        .ok_or_else(|| test_error("missing_item_bindings should exist"))? = json!([]);
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "runtime-math-divergence-missing-binding", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(
        signatures.contains("missing_integration_binding"),
        "expected missing_integration_binding, got {signatures:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_strict_hardened_mode_pair() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest
        .get_mut("integration_contract")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("integration_contract should be an object"))?
        .insert("required_modes".to_owned(), json!(["strict"]));
    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "runtime-math-divergence-missing-mode", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(
        signatures.contains("missing_integration_contract"),
        "expected missing_integration_contract, got {signatures:?}"
    );
    Ok(())
}
