//! Backtrace operations conformance test suite.
//!
//! Validates GNU backtrace/unwinding functions: backtrace, backtrace_symbols, backtrace_symbols_fd.
//! Run: cargo test -p frankenlibc-harness --test backtrace_ops_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureFile {
    version: String,
    family: String,
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    description: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    #[serde(default)]
    expected_output: Option<String>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn backtrace_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/backtrace_ops.json");
    assert!(path.exists(), "backtrace_ops.json fixture must exist");
}

#[test]
fn backtrace_ops_fixture_valid_schema() {
    let fixture = load_fixture("backtrace_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "backtrace_ops");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
}

#[test]
fn backtrace_ops_covers_backtrace() {
    let fixture = load_fixture("backtrace_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("backtrace_captures"))
            .count()
            >= 2,
        "backtrace needs at least 2 test cases (strict and hardened)"
    );
}

#[test]
fn backtrace_ops_covers_backtrace_symbols() {
    let fixture = load_fixture("backtrace_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|name| name.contains("symbols")),
        "Missing test coverage for backtrace_symbols"
    );
}

#[test]
fn backtrace_ops_covers_backtrace_symbols_fd() {
    let fixture = load_fixture("backtrace_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|name| name.contains("symbols_fd")),
        "Missing test coverage for backtrace_symbols_fd"
    );
}

#[test]
fn backtrace_ops_modes_valid() {
    let fixture = load_fixture("backtrace_ops");
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
}

#[test]
fn backtrace_ops_covers_both_modes() {
    let fixture = load_fixture("backtrace_ops");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "backtrace_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "backtrace_ops must have hardened mode test cases"
    );
}

#[test]
fn backtrace_ops_case_count_stable() {
    let fixture = load_fixture("backtrace_ops");
    assert!(
        fixture.cases.len() >= 4,
        "backtrace_ops fixture has {} cases, expected at least 4",
        fixture.cases.len()
    );
    eprintln!(
        "backtrace_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn backtrace_ops_has_spec_references() {
    let fixture = load_fixture("backtrace_ops");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("GNU")
                || case.spec_section.contains("backtrace")
                || case.spec_section.contains("FrankenLibC"),
            "Case {} spec_section should reference GNU or FrankenLibC: {}",
            case.name,
            case.spec_section
        );
    }
}
