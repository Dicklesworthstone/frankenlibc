//! setjmp/longjmp operations conformance test suite.
//!
//! Validates C11/POSIX non-local jump functions: setjmp, longjmp, sigsetjmp, siglongjmp.
//! Run: cargo test -p frankenlibc-harness --test setjmp_ops_conformance_test

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
    expected_output: Option<serde_json::Value>,
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
fn setjmp_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/setjmp_ops.json");
    assert!(path.exists(), "setjmp_ops.json fixture must exist");
}

#[test]
fn setjmp_ops_fixture_valid_schema() {
    let fixture = load_fixture("setjmp_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "setjmp_ops");
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
// Coverage validation: setjmp/longjmp
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_covers_setjmp() {
    let fixture = load_fixture("setjmp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("setjmp")).count() >= 2,
        "setjmp needs at least 2 test cases"
    );
}

#[test]
fn setjmp_ops_covers_longjmp() {
    let fixture = load_fixture("setjmp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("longjmp")).count() >= 2,
        "longjmp needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: zero value handling
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_covers_zero_becomes_one() {
    let fixture = load_fixture("setjmp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("zero")),
        "Must test longjmp with val=0 becoming 1"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_error_codes_valid() {
    let fixture = load_fixture("setjmp_ops");

    // setjmp/longjmp don't set errno
    let valid_errno_values = [0];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (setjmp/longjmp don't set errno)",
            case.name,
            case.expected_errno,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_modes_valid() {
    let fixture = load_fixture("setjmp_ops");

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
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_covers_both_modes() {
    let fixture = load_fixture("setjmp_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "setjmp_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "setjmp_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_case_count_stable() {
    let fixture = load_fixture("setjmp_ops");

    const EXPECTED_MIN_CASES: usize = 5;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "setjmp_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("setjmp_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened mode coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_covers_corruption_detection() {
    let fixture = load_fixture("setjmp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Hardened mode should detect corrupted jump buffers
    assert!(
        case_names.iter().any(|n| n.contains("corrupted")),
        "setjmp_ops must test jmp_buf corruption detection in hardened mode"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn setjmp_ops_has_spec_references() {
    let fixture = load_fixture("setjmp_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11")
                || case.spec_section.contains("POSIX")
                || case.spec_section.contains("FrankenLibC"),
            "Case {} spec_section should reference C11, POSIX, or FrankenLibC: {}",
            case.name,
            case.spec_section
        );
    }
}
