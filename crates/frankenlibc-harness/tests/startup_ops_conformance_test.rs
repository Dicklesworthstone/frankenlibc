//! Startup operations conformance test suite.
//!
//! Validates FrankenLibC startup functions: __frankenlibc_startup_phase0,
//! __frankenlibc_startup_snapshot, __libc_start_main.
//! Run: cargo test -p frankenlibc-harness --test startup_ops_conformance_test

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
fn startup_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/startup_ops.json");
    assert!(path.exists(), "startup_ops.json fixture must exist");
}

#[test]
fn startup_ops_fixture_valid_schema() {
    let fixture = load_fixture("startup_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "startup_ops");
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
fn startup_ops_covers_phase0() {
    let fixture = load_fixture("startup_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("phase0")).count() >= 2,
        "__frankenlibc_startup_phase0 needs at least 2 test cases"
    );
}

#[test]
fn startup_ops_covers_snapshot() {
    let fixture = load_fixture("startup_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("snapshot")).count() >= 2,
        "__frankenlibc_startup_snapshot needs at least 2 test cases"
    );
}

#[test]
fn startup_ops_covers_libc_start_main() {
    let fixture = load_fixture("startup_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("libc_start"))
            .count()
            >= 2,
        "__libc_start_main needs at least 2 test cases"
    );
}

#[test]
fn startup_ops_covers_error_paths() {
    let fixture = load_fixture("startup_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("rejects") || n.contains("deny")),
        "startup_ops must test rejection/deny paths"
    );
}

#[test]
fn startup_ops_modes_valid() {
    let fixture = load_fixture("startup_ops");
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
fn startup_ops_covers_both_modes() {
    let fixture = load_fixture("startup_ops");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "startup_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "startup_ops must have hardened mode test cases"
    );
}

#[test]
fn startup_ops_case_count_stable() {
    let fixture = load_fixture("startup_ops");
    assert!(
        fixture.cases.len() >= 10,
        "startup_ops fixture has {} cases, expected at least 10",
        fixture.cases.len()
    );
    eprintln!("startup_ops fixture has {} test cases", fixture.cases.len());
}

#[test]
fn startup_ops_has_spec_references() {
    let fixture = load_fixture("startup_ops");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("FrankenLibC")
                || case.spec_section.contains("glibc")
                || case.spec_section.contains("startup"),
            "Case {} spec_section should reference FrankenLibC or glibc: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn startup_ops_error_codes_valid() {
    let fixture = load_fixture("startup_ops");

    // Valid error codes for startup operations
    let valid_errno_values = [
        0,  // Success
        7,  // E2BIG (startup context validation)
        22, // EINVAL (invalid main pointer)
    ];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (expected one of {:?})",
            case.name,
            case.expected_errno,
            valid_errno_values
        );
    }
}
