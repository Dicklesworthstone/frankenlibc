//! ctype operations conformance test suite.
//!
//! Validates POSIX/C11 character classification and conversion functions.
//! Run: cargo test -p frankenlibc-harness --test ctype_ops_conformance_test

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
fn ctype_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/ctype_ops.json");
    assert!(path.exists(), "ctype_ops.json fixture must exist");
}

#[test]
fn ctype_ops_fixture_valid_schema() {
    let fixture = load_fixture("ctype_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "ctype");
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
// Coverage validation: classification functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_covers_isalpha() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isalpha")).count() >= 3,
        "isalpha needs at least 3 test cases"
    );
}

#[test]
fn ctype_ops_covers_isdigit() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isdigit")).count() >= 2,
        "isdigit needs at least 2 test cases"
    );
}

#[test]
fn ctype_ops_covers_isalnum() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isalnum")).count() >= 2,
        "isalnum needs at least 2 test cases"
    );
}

#[test]
fn ctype_ops_covers_case_functions() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["isupper", "islower"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for case function: {}",
            pattern
        );
    }
}

#[test]
fn ctype_ops_covers_isspace() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Should test multiple whitespace chars: space, tab, newline
    assert!(
        case_names.iter().filter(|n| n.contains("isspace")).count() >= 3,
        "isspace needs at least 3 test cases (space, tab, newline)"
    );
}

#[test]
fn ctype_ops_covers_isprint() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isprint")).count() >= 3,
        "isprint needs at least 3 test cases"
    );
}

#[test]
fn ctype_ops_covers_ispunct() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("ispunct")).count() >= 2,
        "ispunct needs at least 2 test cases"
    );
}

#[test]
fn ctype_ops_covers_isxdigit() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isxdigit")).count() >= 3,
        "isxdigit needs at least 3 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: conversion functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_covers_tolower() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("tolower")).count() >= 3,
        "tolower needs at least 3 test cases"
    );
}

#[test]
fn ctype_ops_covers_toupper() {
    let fixture = load_fixture("ctype_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("toupper")).count() >= 3,
        "toupper needs at least 3 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_error_codes_valid() {
    let fixture = load_fixture("ctype_ops");

    // ctype functions don't set errno
    let valid_errno_values = [0];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (ctype functions don't set errno)",
            case.name,
            case.expected_errno,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Function grouping validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_function_distribution() {
    let fixture = load_fixture("ctype_ops");

    let mut classification_count = 0;
    let mut conversion_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "isalpha" | "isdigit" | "isalnum" | "isupper" | "islower" | "isspace" | "isprint"
            | "ispunct" | "isxdigit" | "iscntrl" | "isgraph" | "isblank" => {
                classification_count += 1
            }
            "tolower" | "toupper" => conversion_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    assert!(
        classification_count >= 25,
        "Classification functions need more test cases (have {})",
        classification_count
    );
    assert!(
        conversion_count >= 6,
        "Conversion functions need more test cases (have {})",
        conversion_count
    );

    eprintln!(
        "ctype_ops coverage: classification={}, conversion={}",
        classification_count, conversion_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_modes_valid() {
    let fixture = load_fixture("ctype_ops");

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
fn ctype_ops_case_count_stable() {
    let fixture = load_fixture("ctype_ops");

    const EXPECTED_MIN_CASES: usize = 30;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "ctype_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("ctype_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_has_posix_references() {
    let fixture = load_fixture("ctype_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case coverage: boundary values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_covers_boundary_values() {
    let fixture = load_fixture("ctype_ops");

    // Check that we test boundary characters
    let inputs: Vec<i64> = fixture
        .cases
        .iter()
        .filter_map(|c| c.inputs.get("c").and_then(|v| v.as_i64()))
        .collect();

    // Should test: space (32), digits (48-57), uppercase (65-90), lowercase (97-122)
    assert!(inputs.contains(&32), "Must test space character (ASCII 32)");
    assert!(
        inputs.contains(&48) && inputs.contains(&57),
        "Must test digit boundaries (0=48, 9=57)"
    );
    assert!(
        inputs.contains(&65) && inputs.contains(&90),
        "Must test uppercase boundaries (A=65, Z=90)"
    );
    assert!(
        inputs.contains(&97) && inputs.contains(&122),
        "Must test lowercase boundaries (a=97, z=122)"
    );
}
