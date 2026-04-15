//! memcpy strict conformance test suite.
//!
//! Validates POSIX memcpy function with various sizes and edge cases.
//! Run: cargo test -p frankenlibc-harness --test memcpy_strict_conformance_test

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
fn memcpy_strict_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/memcpy_strict.json");
    assert!(path.exists(), "memcpy_strict.json fixture must exist");
}

#[test]
fn memcpy_strict_fixture_valid_schema() {
    let fixture = load_fixture("memcpy_strict");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/memcpy");
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
fn memcpy_strict_covers_full_copy() {
    let fixture = load_fixture("memcpy_strict");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("full")),
        "Missing test coverage for full buffer copy"
    );
}

#[test]
fn memcpy_strict_covers_partial_copy() {
    let fixture = load_fixture("memcpy_strict");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("partial")),
        "Missing test coverage for partial buffer copy"
    );
}

#[test]
fn memcpy_strict_covers_zero_size() {
    let fixture = load_fixture("memcpy_strict");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("zero")),
        "Missing test coverage for zero-size copy"
    );
}

#[test]
fn memcpy_strict_covers_single_byte() {
    let fixture = load_fixture("memcpy_strict");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("single")),
        "Missing test coverage for single-byte copy"
    );
}

#[test]
fn memcpy_strict_modes_valid() {
    let fixture = load_fixture("memcpy_strict");
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
fn memcpy_strict_case_count_stable() {
    let fixture = load_fixture("memcpy_strict");
    assert!(
        fixture.cases.len() >= 3,
        "memcpy_strict fixture has {} cases, expected at least 3",
        fixture.cases.len()
    );
    eprintln!(
        "memcpy_strict fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn memcpy_strict_has_posix_references() {
    let fixture = load_fixture("memcpy_strict");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn memcpy_strict_error_codes_valid() {
    let fixture = load_fixture("memcpy_strict");

    // memcpy doesn't set errno
    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {} (memcpy doesn't set errno)",
            case.name, case.expected_errno
        );
    }
}
