// per_symbol_fixture_tests_test.rs — bd-ldj.5
// Integration tests for per-symbol conformance fixture unit tests.

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

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn per_symbol_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/per_symbol_fixture_tests.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_per_symbol_fixture_tests.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute per-symbol fixture generator");
    assert!(
        output.status.success(),
        "Per-symbol fixture generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn per_symbol_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/per_symbol_fixture_tests.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-ldj.5"));
    assert!(data["report_hash"].is_string());

    let summary = &data["summary"];
    for field in &[
        "total_symbols",
        "symbols_with_fixtures",
        "fixture_coverage_pct",
        "total_cases",
        "symbols_with_edge_cases",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["per_symbol_report"].is_array());
    assert!(data["fixture_file_analyses"].is_array());
    assert!(data["uncovered_action_list"].is_array());
}

#[test]
fn per_symbol_coverage_adequate() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/per_symbol_fixture_tests.v1.json");
    let data = load_json(&report_path);

    let coverage = data["summary"]["fixture_coverage_pct"].as_f64().unwrap();
    assert!(
        coverage >= 50.0,
        "Fixture coverage {}% < 50% minimum",
        coverage
    );

    let total_cases = data["summary"]["total_cases"].as_u64().unwrap();
    assert!(
        total_cases >= 200,
        "Only {} total cases (need >= 200)",
        total_cases
    );
}

#[test]
fn per_symbol_all_have_valid_status() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/per_symbol_fixture_tests.v1.json");
    let data = load_json(&report_path);

    let symbols = data["per_symbol_report"].as_array().unwrap();
    let valid_statuses = ["Implemented", "RawSyscall", "GlibcCallThrough", "Stub"];

    for s in symbols {
        let name = s["symbol"].as_str().unwrap_or("?");
        let status = s["status"].as_str().unwrap_or("?");
        assert!(
            valid_statuses.contains(&status),
            "Symbol {} has invalid status: {}",
            name,
            status
        );
    }
}

#[test]
fn per_symbol_edge_cases_detected() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/per_symbol_fixture_tests.v1.json");
    let data = load_json(&report_path);

    let edge_count = data["summary"]["symbols_with_edge_cases"].as_u64().unwrap();
    assert!(
        edge_count >= 20,
        "Only {} symbols with edge cases (need >= 20)",
        edge_count
    );
}

#[test]
fn per_symbol_uncovered_actions_present() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/per_symbol_fixture_tests.v1.json");
    let data = load_json(&report_path);

    let without = data["summary"]["symbols_without_fixtures"]
        .as_u64()
        .unwrap();
    let actions = data["uncovered_action_list"].as_array().unwrap();

    // If there are uncovered symbols, there should be action items
    if without > 0 {
        assert!(
            !actions.is_empty(),
            "{} uncovered symbols but no action items",
            without
        );

        for a in actions {
            assert!(a["symbol"].is_string());
            assert!(a["action"].is_string());
        }
    }
}

#[test]
fn per_symbol_report_reproducible() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/per_symbol_fixture_tests.v1.json");
    let data1 = load_json(&report_path);

    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_per_symbol_fixture_tests.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute generator");
    assert!(output.status.success());

    let data2 = load_json(&report_path);
    assert_eq!(
        data1["report_hash"].as_str(),
        data2["report_hash"].as_str(),
        "Report hash changed on regeneration"
    );
}
