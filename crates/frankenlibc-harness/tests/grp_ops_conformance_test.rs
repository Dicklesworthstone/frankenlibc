//! Group database operations conformance test suite.
//!
//! Validates POSIX grp.h functions: getgrnam, getgrgid, getgrent, setgrent, endgrent.
//! Run: cargo test -p frankenlibc-harness --test grp_ops_conformance_test

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
fn grp_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/grp_ops.json");
    assert!(path.exists(), "grp_ops.json fixture must exist");
}

#[test]
fn grp_ops_fixture_valid_schema() {
    let fixture = load_fixture("grp_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "grp_ops");
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
// Coverage validation: getgrnam
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_covers_getgrnam() {
    let fixture = load_fixture("grp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("getgrnam")).count() >= 2,
        "getgrnam needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: getgrgid
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_covers_getgrgid() {
    let fixture = load_fixture("grp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("getgrgid")).count() >= 2,
        "getgrgid needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: setgrent/endgrent
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_covers_enumeration() {
    let fixture = load_fixture("grp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|name| name.contains("setgrent") || name.contains("endgrent")),
        "Missing test coverage for setgrent/endgrent"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_error_codes_valid() {
    let fixture = load_fixture("grp_ops");

    // grp functions typically return NULL without setting errno for "not found"
    let valid_errno_values = [0];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (grp functions typically don't set errno)",
            case.name,
            case.expected_errno,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_modes_valid() {
    let fixture = load_fixture("grp_ops");

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
fn grp_ops_covers_both_modes() {
    let fixture = load_fixture("grp_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "grp_ops must have strict mode test cases");
    assert!(has_hardened, "grp_ops must have hardened mode test cases");
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_case_count_stable() {
    let fixture = load_fixture("grp_ops");

    const EXPECTED_MIN_CASES: usize = 8;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "grp_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("grp_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_covers_error_paths() {
    let fixture = load_fixture("grp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("nonexistent")),
        "grp_ops must test nonexistent group handling"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Root group coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_covers_root_group() {
    let fixture = load_fixture("grp_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|n| n.contains("root") || n.contains("zero")),
        "grp_ops must test root group (GID 0) lookup"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grp_ops_has_posix_references() {
    let fixture = load_fixture("grp_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}
