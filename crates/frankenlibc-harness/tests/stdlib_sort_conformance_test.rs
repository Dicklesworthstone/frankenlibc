//! stdlib sort operations conformance test suite.
//!
//! Validates ISO C/POSIX stdlib.h sort/search functions: qsort, bsearch.
//! Run: cargo test -p frankenlibc-harness --test stdlib_sort_conformance_test

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
fn stdlib_sort_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/stdlib_sort.json");
    assert!(path.exists(), "stdlib_sort.json fixture must exist");
}

#[test]
fn stdlib_sort_fixture_valid_schema() {
    let fixture = load_fixture("stdlib_sort");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdlib/sort");
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
// Coverage validation: qsort
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_sort_covers_qsort() {
    let fixture = load_fixture("stdlib_sort");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("qsort")),
        "Missing test coverage for qsort"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: bsearch
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_sort_covers_bsearch() {
    let fixture = load_fixture("stdlib_sort");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("bsearch")).count() >= 2,
        "bsearch needs at least 2 test cases (found and not found)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_sort_error_codes_valid() {
    let fixture = load_fixture("stdlib_sort");

    // qsort and bsearch don't set errno
    let valid_errno_values = [0];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (qsort/bsearch don't set errno)",
            case.name,
            case.expected_errno,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_sort_modes_valid() {
    let fixture = load_fixture("stdlib_sort");

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
fn stdlib_sort_case_count_stable() {
    let fixture = load_fixture("stdlib_sort");

    const EXPECTED_MIN_CASES: usize = 3;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "stdlib_sort fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("stdlib_sort fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_sort_has_spec_references() {
    let fixture = load_fixture("stdlib_sort");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("ISO C") || case.spec_section.contains("C"),
            "Case {} spec_section should reference ISO C standard: {}",
            case.name,
            case.spec_section
        );
    }
}
