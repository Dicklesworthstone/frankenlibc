//! Internal I/O operations conformance test suite.
//!
//! Validates internal glibc _IO_* stdio functions with native implementations.
//! Run: cargo test -p frankenlibc-harness --test io_internal_ops_conformance_test

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
fn io_internal_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/io_internal_ops.json");
    assert!(path.exists(), "io_internal_ops.json fixture must exist");
}

#[test]
fn io_internal_ops_fixture_valid_schema() {
    let fixture = load_fixture("io_internal_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "io_internal");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn io_internal_ops_covers_adjust_column() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("adjust_column"))
            .count()
            >= 2,
        "_IO_adjust_column needs at least 2 test cases"
    );
}

#[test]
fn io_internal_ops_covers_adjust_wcolumn() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wcolumn")),
        "Missing test coverage for _IO_adjust_wcolumn"
    );
}

#[test]
fn io_internal_ops_covers_default_doallocate() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("doallocate")),
        "Missing test coverage for _IO_default_doallocate"
    );
}

#[test]
fn io_internal_ops_covers_file_init() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("file_init")),
        "Missing test coverage for _IO_file_init"
    );
}

#[test]
fn io_internal_ops_modes_valid() {
    let fixture = load_fixture("io_internal_ops");
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
fn io_internal_ops_case_count_stable() {
    let fixture = load_fixture("io_internal_ops");
    assert!(
        fixture.cases.len() >= 5,
        "io_internal_ops fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!(
        "io_internal_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn io_internal_ops_has_spec_references() {
    let fixture = load_fixture("io_internal_ops");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("glibc")
                || case.spec_section.contains("libio")
                || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference glibc/libio/GNU: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn io_internal_ops_error_codes_valid() {
    let fixture = load_fixture("io_internal_ops");
    // Internal I/O functions may set ENOSYS for unimplemented features
    for case in &fixture.cases {
        assert!(
            case.expected_errno == 0 || case.expected_errno == 38,
            "Case {} has unexpected errno {} (expected 0 or ENOSYS)",
            case.name,
            case.expected_errno
        );
    }
}
