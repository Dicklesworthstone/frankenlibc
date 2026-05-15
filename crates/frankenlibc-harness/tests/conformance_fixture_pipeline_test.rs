// conformance_fixture_pipeline_test.rs — bd-2hh.1
// Integration tests for the conformance fixture capture pipeline.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir
        .parent()
        .ok_or_else(|| "frankenlibc-harness manifest should have a parent".to_string())?;
    Ok(crates_dir
        .parent()
        .ok_or_else(|| "crates directory should have workspace parent".to_string())?
        .to_path_buf())
}

fn load_json(path: &Path) -> Result<Value, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
}

fn json_u64(value: &Value, name: &str) -> Result<u64, String> {
    value.as_u64().ok_or_else(|| format!("{name} must be u64"))
}

fn json_f64(value: &Value, name: &str) -> Result<f64, String> {
    value.as_f64().ok_or_else(|| format!("{name} must be f64"))
}

fn json_bool(value: &Value, name: &str) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("{name} must be bool"))
}

fn json_str<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{name} must be string"))
}

fn json_array<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{name} must be array"))
}

#[test]
fn pipeline_report_generates_successfully() -> Result<(), String> {
    let root = repo_root()?;
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
    let root = repo_root()?;
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
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let format_issues = json_u64(
        &data["summary"]["fixture_format_issues"],
        "summary.fixture_format_issues",
    )?;
    assert_eq!(format_issues, 0, "Fixture format issues found");

    let files = json_array(&data["fixture_files"], "fixture_files")?;
    for f in files {
        let valid = json_bool(&f["valid"], "fixture_files[].valid")?;
        let file = json_str(&f["file"], "fixture_files[].file")?;
        assert!(valid, "Invalid fixture file: {file}");
    }
    Ok(())
}

#[test]
fn pipeline_sufficient_coverage() -> Result<(), String> {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let coverage = json_f64(&data["summary"]["coverage_pct"], "summary.coverage_pct")?;
    let min_coverage = json_f64(
        &data["summary"]["min_coverage_pct"],
        "summary.min_coverage_pct",
    )?;
    assert!(
        coverage >= min_coverage,
        "Symbol coverage {coverage}% is below {min_coverage}% minimum"
    );
    Ok(())
}

#[test]
fn pipeline_sufficient_cases() -> Result<(), String> {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let total = json_u64(
        &data["summary"]["total_fixture_cases"],
        "summary.total_fixture_cases",
    )?;
    assert!(total >= 100, "Only {total} fixture cases (need >= 100)");
    Ok(())
}

#[test]
fn pipeline_multiple_modules_covered() -> Result<(), String> {
    let root = repo_root()?;
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path)?;

    let modules = json_array(&data["module_summary"], "module_summary")?;
    let mut covered = 0;
    for module in modules {
        if json_u64(
            &module["covered_symbols"],
            "module_summary[].covered_symbols",
        )? > 0
        {
            covered += 1;
        }
    }
    assert!(
        covered >= 5,
        "Only {covered} modules have fixtures (need >= 5)"
    );
    Ok(())
}
