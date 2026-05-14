//! Completion-contract tests for bd-2hh.5.1 fixture verification evidence.

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_and_bindings_validated",
    "fixture_generator_replayed",
    "fixture_verification_regression_completion_contract_validated",
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
    root.join("tests/conformance/fixture_verification_regression_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fixture_verification_regression_completion_contract.sh")
}

fn source_report_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/fixture_unit_tests.v1.json")
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "fixture-verification-regression-{label}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    out_dir: &Path,
    contract: &Path,
    source_report: Option<&Path>,
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_FIXTURE_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_FIXTURE_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FIXTURE_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_COMPLETION_LOG",
            out_dir.join("log.jsonl"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_COMPLETION_GENERATED",
            out_dir.join("generated.v1.json"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_COMPLETION_GENERATED_LOG",
            out_dir.join("generated.log.jsonl"),
        );
    if let Some(path) = source_report {
        command.env("FRANKENLIBC_FIXTURE_COMPLETION_SOURCE_REPORT", path);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn stdout_stderr(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_failure_contains(output: &Output, needle: &str) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed\n{}",
        stdout_stderr(output)
    );
    let combined = stdout_stderr(output);
    assert!(
        combined.contains(needle),
        "expected failure output to contain {needle:?}\n{combined}"
    );
}

#[test]
fn manifest_binds_fixture_unit_e2e_and_conformance_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("fixture_verification_regression_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2hh.5.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2hh.5"));

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| test_error("source_artifacts should be an object"))?;
    for key in [
        "generator",
        "source_gate",
        "source_report",
        "source_unit_tests",
        "fixture_root",
    ] {
        let path = artifacts[key]["path"]
            .as_str()
            .ok_or_else(|| test_error(format!("source_artifacts.{key}.path missing")))?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }

    let obligations = manifest["completion_obligations"]
        .as_array()
        .ok_or_else(|| test_error("completion_obligations should be an array"))?;
    for required in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.conformance.primary",
    ] {
        assert!(
            obligations
                .iter()
                .any(|row| row["id"].as_str() == Some(required)),
            "missing obligation {required}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_fixture_verification_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accept")?;
    let output = run_checker(&root, &out_dir, &contract_path(&root), None)?;
    assert!(
        output.status.success(),
        "checker failed\n{}",
        stdout_stderr(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert!(report["failure_signature"].is_null());
    assert!(
        report["summary"]["fixture_files"].as_u64().unwrap_or(0) >= 50,
        "expected at least 50 fixture files"
    );
    assert!(
        report["summary"]["total_cases"].as_u64().unwrap_or(0) >= 100,
        "expected at least 100 fixture cases"
    );
    assert!(
        report["summary"]["baseline_symbols"].as_u64().unwrap_or(0) >= 50,
        "expected at least 50 baseline symbols"
    );

    let rows = load_jsonl(&out_dir.join("log.jsonl"))?;
    for event in REQUIRED_EVENTS {
        assert!(
            rows.iter().any(|row| row["event"].as_str() == Some(event)),
            "missing completion log event {event}"
        );
    }

    let generated = load_json(&out_dir.join("generated.v1.json"))?;
    assert_eq!(
        generated["generated_at"].as_str(),
        Some("2026-05-10T00:00:00Z")
    );
    let generated_rows = load_jsonl(&out_dir.join("generated.log.jsonl"))?;
    assert!(
        generated_rows.len() >= 51,
        "generated log should include per-fixture rows plus summary"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_source_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]["source_unit_tests"]["required_functions"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_functions should be an array"))?
        .push(Value::from("fixture_unit_nonexistent_completion_binding"));
    let mutated_contract = out_dir.join("missing_unit_contract.v1.json");
    write_json(&mutated_contract, &manifest)?;

    let output = run_checker(&root, &out_dir, &mutated_contract, None)?;
    expect_failure_contains(&output, "missing source unit binding");
    Ok(())
}

#[test]
fn checker_rejects_understated_regression_baseline() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "baseline")?;
    let mut report = load_json(&source_report_path(&root))?;
    report["summary"]["unique_symbols"] = Value::from(1);
    report["regression_baseline"]["symbol_count"] = Value::from(1);
    let mutated_report = out_dir.join("understated_fixture_unit_tests.v1.json");
    write_json(&mutated_report, &report)?;

    let output = run_checker(
        &root,
        &out_dir,
        &contract_path(&root),
        Some(&mutated_report),
    )?;
    expect_failure_contains(
        &output,
        "fixture regression baseline below completion minimum",
    );
    Ok(())
}

#[test]
fn checker_rejects_generated_log_contract_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "log-contract")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["generated_log_contract"]["required_fields"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_fields should be an array"))?
        .push(Value::from("not_a_real_fixture_log_field"));
    let mutated_contract = out_dir.join("log_contract_drift.v1.json");
    write_json(&mutated_contract, &manifest)?;

    let output = run_checker(&root, &out_dir, &mutated_contract, None)?;
    expect_failure_contains(&output, "generated log missing required field");
    expect_failure_contains(&output, "not_a_real_fixture_log_field");
    Ok(())
}
