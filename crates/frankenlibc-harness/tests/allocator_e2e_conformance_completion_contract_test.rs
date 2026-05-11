//! Completion contract tests for bd-2x5.5.1 allocator E2E/conformance evidence.

use serde_json::{Value, json};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "allocator_completion_source_binding",
    "allocator_completion_conformance_binding",
    "allocator_completion_e2e_status",
    "allocator_completion_summary",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/allocator_e2e_conformance_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_allocator_e2e_conformance_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} read failed: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} parse failed: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} read failed: {err}", path.display())))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|err| test_error(format!("{} JSONL parse failed: {err}", path.display())))
        })
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| test_error(format!("{} mkdir failed: {err}", parent.display())))?;
    }
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "allocator-e2e-conformance-completion-{label}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, out_dir: &Path, contract: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_ALLOCATOR_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_ALLOCATOR_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_ALLOCATOR_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_ALLOCATOR_COMPLETION_LOG",
            out_dir.join("log.jsonl"),
        )
        .env("FRANKENLIBC_ALLOCATOR_COMPLETION_RUN_SOURCE_E2E", "0")
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
fn manifest_binds_allocator_e2e_and_conformance_sources() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("allocator_e2e_conformance_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2x5.5.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2x5.5"));

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| test_error("source_artifacts should be an object"))?;
    for key in [
        "allocator_e2e_gate",
        "fixture_spec",
        "allocator_fixture",
        "integration_fixtures",
        "source_tests",
    ] {
        assert!(
            artifacts.contains_key(key),
            "missing source_artifacts.{key}"
        );
    }

    let obligations = manifest["completion_obligations"]
        .as_array()
        .ok_or_else(|| test_error("completion_obligations should be an array"))?;
    for required in ["tests.e2e.primary", "tests.conformance.primary"] {
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
fn checker_accepts_allocator_completion_contract() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_output_dir(&root, "accept")?;
    let output = run_checker(&root, &out_dir, &contract_path(&root))?;
    assert!(
        output.status.success(),
        "checker failed\n{}",
        stdout_stderr(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-2x5.5.1"));
    assert!(
        report["summary"]["allocator_fixture_cases"]
            .as_u64()
            .unwrap_or(0)
            >= 5,
        "expected at least five allocator fixture cases"
    );
    assert_eq!(
        report["summary"]["source_e2e"]["status"].as_str(),
        Some("skipped")
    );

    let rows = load_jsonl(&out_dir.join("log.jsonl"))?;
    for event in REQUIRED_EVENTS {
        assert!(
            rows.iter().any(|row| row["event"].as_str() == Some(event)),
            "missing completion log event {event}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_allocator_gate_marker() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_output_dir(&root, "gate-marker")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]["allocator_e2e_gate"]["required_markers"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_markers should be an array"))?
        .push(Value::from("allocator_missing_completion_marker"));
    let mutated = out_dir.join("missing_gate_marker_contract.v1.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &out_dir, &mutated)?;
    expect_failure_contains(&output, "missing allocator e2e gate marker");
    Ok(())
}

#[test]
fn checker_rejects_missing_allocator_fixture_function() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_output_dir(&root, "fixture-function")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]["allocator_fixture"]["required_functions"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_functions should be an array"))?
        .push(Value::from("aligned_alloc_nonexistent"));
    let mutated = out_dir.join("missing_allocator_function_contract.v1.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &out_dir, &mutated)?;
    expect_failure_contains(&output, "allocator fixture missing required POSIX function");
    Ok(())
}

#[test]
fn checker_rejects_missing_completion_obligation() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_output_dir(&root, "obligation")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_obligations"] = json!([
        {
            "id": "tests.e2e.primary",
            "kind": "e2e",
            "description": "mutated obligation set"
        }
    ]);
    let mutated = out_dir.join("missing_obligation_contract.v1.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &out_dir, &mutated)?;
    expect_failure_contains(&output, "missing completion obligation");
    Ok(())
}
