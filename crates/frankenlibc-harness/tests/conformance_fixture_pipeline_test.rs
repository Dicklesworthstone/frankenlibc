// conformance_fixture_pipeline_test.rs — bd-2hh.1
// Integration tests for the conformance fixture capture pipeline.

use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> Result<serde_json::Value, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

#[test]
fn pipeline_report_generates_successfully() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let script_arg = root
        .join("scripts/generate_conformance_fixture_pipeline.py")
        .to_string_lossy()
        .into_owned();
    let report_arg = report_path.to_string_lossy().into_owned();
    let output = Command::new("python3")
        .args([script_arg.as_str(), "-o", report_arg.as_str()])
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to execute fixture pipeline generator: {err}"))?;
    assert!(
        output.status.success(),
        "Fixture pipeline generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
    Ok(())
}

#[test]
fn pipeline_report_schema_complete() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2hh.1"));

    let summary = &data["summary"];
    for field in &[
        "total_fixture_files",
        "total_fixture_cases",
        "implemented_symbols",
        "symbols_with_fixtures",
        "coverage_pct",
        "min_coverage_pct",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["module_summary"].is_array());
    assert!(data["symbol_coverage"].is_array());
    assert!(data["fixture_files"].is_array());
    Ok(())
}

#[test]
fn pipeline_fixtures_have_valid_format() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let format_issues = data["summary"]["fixture_format_issues"].as_u64().unwrap();
    assert_eq!(format_issues, 0, "Fixture format issues found");

    let files = data["fixture_files"].as_array().unwrap();
    for f in files {
        assert!(
            f["valid"].as_bool().unwrap(),
            "Invalid fixture file: {}",
            f["file"].as_str().unwrap()
        );
    }
    Ok(())
}

#[test]
fn pipeline_sufficient_coverage() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let coverage = data["summary"]["coverage_pct"].as_f64().unwrap();
    let min_coverage = data["summary"]["min_coverage_pct"].as_f64().unwrap();
    assert!(
        coverage >= min_coverage,
        "Symbol coverage {coverage}% is below {min_coverage}% minimum"
    );
    Ok(())
}

#[test]
fn pipeline_sufficient_cases() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let total = data["summary"]["total_fixture_cases"].as_u64().unwrap();
    assert!(total >= 100, "Only {total} fixture cases (need >= 100)");
    Ok(())
}

#[test]
fn pipeline_multiple_modules_covered() -> Result<(), String> {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let modules = data["module_summary"].as_array().unwrap();
    let covered = modules
        .iter()
        .filter(|m| m["covered_symbols"].as_u64().unwrap() > 0)
        .count();
    assert!(
        covered >= 5,
        "Only {covered} modules have fixtures (need >= 5)"
    );
    Ok(())
}
