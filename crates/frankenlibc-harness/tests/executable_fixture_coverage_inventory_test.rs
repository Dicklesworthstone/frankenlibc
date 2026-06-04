//! Executable fixture coverage inventory guard for bd-j1u6u.1.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn generated_report_path(label: &str) -> PathBuf {
    workspace_root().join(format!(
        "target/conformance/executable_fixture_coverage_inventory.{label}.generated.json"
    ))
}

fn run_checker(label: &str) -> Value {
    let root = workspace_root();
    let output = generated_report_path(label);
    let status = Command::new("python3")
        .arg(root.join("scripts/check_executable_fixture_coverage.py"))
        .arg("--repo-root")
        .arg(&root)
        .arg("--output")
        .arg(&output)
        .status()
        .expect("executable fixture coverage checker should run");
    assert!(status.success(), "checker should exit successfully");

    let content = std::fs::read_to_string(&output)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", output.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", output.display()))
}

#[test]
fn executable_fixture_inventory_has_required_shape() {
    let report = run_checker("shape");
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-j1u6u.1"));

    let summary = report["summary"]
        .as_object()
        .expect("summary must be an object");
    assert!(
        summary["fixture_file_count"].as_u64().unwrap_or(0) > 0,
        "fixture inventory should include fixture files"
    );
    assert!(
        summary["fixture_case_count"].as_u64().unwrap_or(0) > 0,
        "fixture inventory should include fixture cases"
    );
    assert_eq!(
        summary["gap_count"].as_u64().unwrap_or(0) as usize,
        report["gaps"].as_array().unwrap().len(),
        "summary gap_count must match gaps[] length"
    );
    assert!(
        report["fixture_inventory"].as_array().unwrap().len()
            >= summary["fixture_file_count"].as_u64().unwrap_or(0) as usize,
        "fixture_inventory must enumerate every fixture file"
    );
}

#[test]
fn executable_fixture_gaps_are_actionable() {
    let report = run_checker("gaps");
    let required_fields: Vec<_> = report["required_gap_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert!(
        required_fields.contains(&"fixture_path".to_string())
            && required_fields.contains(&"missing_executor_symbols".to_string())
            && required_fields.contains(&"suggested_test_target".to_string()),
        "gap schema must include fixture path, missing symbols, and suggested test target"
    );

    for gap in report["gaps"].as_array().unwrap() {
        let object = gap.as_object().expect("gap rows must be objects");
        for field in &required_fields {
            assert!(
                object.contains_key(field),
                "gap row missing required field {field}: {gap}"
            );
        }
        assert!(
            gap["fixture_path"]
                .as_str()
                .unwrap_or_default()
                .ends_with(".json"),
            "gap fixture_path should name a fixture JSON file: {gap}"
        );
        assert!(
            gap["missing_executor_symbols"].is_array(),
            "missing_executor_symbols must be an array: {gap}"
        );
        assert!(
            gap["suggested_test_target"]
                .as_str()
                .unwrap_or_default()
                .starts_with("crates/frankenlibc-harness/tests/"),
            "gap should suggest a harness test target: {gap}"
        );
    }
}

#[test]
fn rpc_wave03_is_counted_as_executable_coverage() {
    let report = run_checker("rpc-wave03");
    let inventory = report["fixture_inventory"].as_array().unwrap();
    let row = inventory
        .iter()
        .find(|row| {
            row["fixture_path"].as_str()
                == Some("tests/conformance/fixtures/rpc_legacy_network_wave03.json")
        })
        .expect("rpc wave03 fixture should be inventoried");

    assert_eq!(
        row["family"].as_str(),
        Some("rpc/legacy-network"),
        "rpc wave03 family drifted"
    );
    assert_eq!(
        row["executable_via_harness"].as_bool(),
        Some(true),
        "rpc wave03 must execute through the isolated harness"
    );
    assert!(
        row["executable_harness_tests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value
                .as_str()
                .unwrap_or_default()
                .ends_with("rpc_legacy_network_wave03_conformance_test.rs")),
        "rpc wave03 should point at its isolated harness test"
    );
    assert!(
        row["missing_executor_symbols"]
            .as_array()
            .unwrap()
            .is_empty(),
        "rpc wave03 should have execute_fixture_case dispatch for every symbol"
    );
}
