//! stdlib numeric operations conformance test suite.
//!
//! Validates POSIX/C11 stdlib.h numeric functions: atoi, atol, strtol, strtoul.
//! Run: cargo test -p frankenlibc-harness --test stdlib_numeric_conformance_test

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
    #[serde(default)]
    spec_reference: String,
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

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/stdlib_numeric.json");
    assert!(path.exists(), "stdlib_numeric.json fixture must exist");
}

#[test]
fn stdlib_numeric_fixture_valid_schema() {
    let fixture = load_fixture("stdlib_numeric");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdlib/numeric");
    assert!(!fixture.cases.is_empty(), "Must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            !case.spec_section.is_empty(),
            "Spec section must not be empty"
        );
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: atoi family
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_covers_atoi() {
    let fixture = load_fixture("stdlib_numeric");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("atoi")).count() >= 2,
        "atoi needs at least 2 test cases"
    );
}

#[test]
fn stdlib_numeric_covers_atol() {
    let fixture = load_fixture("stdlib_numeric");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("atol")).count() >= 2,
        "atol needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: strtol family
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_covers_strtol() {
    let fixture = load_fixture("stdlib_numeric");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("strtol")).count() >= 2,
        "strtol needs at least 2 test cases"
    );
}

#[test]
fn stdlib_numeric_covers_strtoul() {
    let fixture = load_fixture("stdlib_numeric");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("strtoul")),
        "Missing test coverage for strtoul"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_error_codes_valid() {
    let fixture = load_fixture("stdlib_numeric");

    // Valid POSIX/Linux error codes for numeric conversion functions
    let valid_errno_values = [
        0,  // Success
        22, // EINVAL
        34, // ERANGE
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

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_modes_valid() {
    let fixture = load_fixture("stdlib_numeric");

    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {} (expected 'both', 'strict', or 'hardened')",
            case.name,
            case.mode
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_case_count_stable() {
    let fixture = load_fixture("stdlib_numeric");

    const EXPECTED_MIN_CASES: usize = 8;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "stdlib_numeric fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "stdlib_numeric fixture has {} test cases",
        fixture.cases.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_covers_edge_cases() {
    let fixture = load_fixture("stdlib_numeric");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("negative")),
        "Must test negative number conversion"
    );
    assert!(
        case_names.iter().any(|n| n.contains("whitespace")),
        "Must test whitespace handling"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_numeric_has_spec_references() {
    let fixture = load_fixture("stdlib_numeric");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("C"),
            "Case {} spec_section should reference POSIX or C standard: {}",
            case.name,
            case.spec_section
        );
    }
}
