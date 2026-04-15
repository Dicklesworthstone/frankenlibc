//! Memory operations conformance test suite.
//!
//! Validates C11 memory APIs: memcpy, memmove, memset, memcmp, memchr.
//! Run: cargo test -p frankenlibc-harness --test memory_ops_conformance_test

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
fn memory_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/memory_ops.json");
    assert!(path.exists(), "memory_ops.json fixture must exist");
}

#[test]
fn memory_ops_fixture_valid_schema() {
    let fixture = load_fixture("memory_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "memory_ops");
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
// Coverage validation: memory operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_covers_memcpy() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["memcpy_basic", "memcpy_zero"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for memcpy pattern: {}",
            pattern
        );
    }
}

#[test]
fn memory_ops_covers_memmove() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("memmove")),
        "Missing test coverage for memmove"
    );
}

#[test]
fn memory_ops_covers_memset() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("memset")),
        "Missing test coverage for memset"
    );
}

#[test]
fn memory_ops_covers_memcmp() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["memcmp_equal", "memcmp_less", "memcmp_greater"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for memcmp pattern: {}",
            pattern
        );
    }
}

#[test]
fn memory_ops_covers_memchr() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["memchr_found", "memchr_not_found"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for memchr pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_error_codes_valid() {
    let fixture = load_fixture("memory_ops");

    // Memory ops generally don't set errno on success
    let valid_errno_values = [0];

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
// Function grouping validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_function_distribution() {
    let fixture = load_fixture("memory_ops");

    let mut memcpy_count = 0;
    let mut memmove_count = 0;
    let mut memset_count = 0;
    let mut memcmp_count = 0;
    let mut memchr_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "memcpy" => memcpy_count += 1,
            "memmove" => memmove_count += 1,
            "memset" => memset_count += 1,
            "memcmp" => memcmp_count += 1,
            "memchr" => memchr_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure at least basic coverage
    assert!(
        memcpy_count >= 2,
        "memcpy needs more test cases (have {})",
        memcpy_count
    );
    assert!(
        memmove_count >= 1,
        "memmove needs test cases (have {})",
        memmove_count
    );
    assert!(
        memset_count >= 2,
        "memset needs more test cases (have {})",
        memset_count
    );
    assert!(
        memcmp_count >= 2,
        "memcmp needs more test cases (have {})",
        memcmp_count
    );
    assert!(
        memchr_count >= 2,
        "memchr needs more test cases (have {})",
        memchr_count
    );

    eprintln!(
        "memory_ops coverage: memcpy={}, memmove={}, memset={}, memcmp={}, memchr={}",
        memcpy_count, memmove_count, memset_count, memcmp_count, memchr_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_modes_valid() {
    let fixture = load_fixture("memory_ops");

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
fn memory_ops_case_count_stable() {
    let fixture = load_fixture("memory_ops");

    const EXPECTED_MIN_CASES: usize = 10;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "memory_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("memory_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec reference validation: all cases reference C11 spec
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_has_c11_references() {
    let fixture = load_fixture("memory_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11") || case.spec_section.contains("7.24"),
            "Case {} spec_section should reference C11 standard: {}",
            case.name,
            case.spec_section
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_covers_both_modes() {
    let fixture = load_fixture("memory_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "memory_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "memory_ops must have hardened mode test cases"
    );
}
