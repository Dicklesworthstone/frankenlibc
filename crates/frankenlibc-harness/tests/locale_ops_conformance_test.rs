//! Locale operations conformance test suite.
//!
//! Validates C11/POSIX locale functions: setlocale, localeconv, nl_langinfo, newlocale, uselocale, etc.
//! Run: cargo test -p frankenlibc-harness --test locale_ops_conformance_test

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
fn locale_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/locale_ops.json");
    assert!(path.exists(), "locale_ops.json fixture must exist");
}

#[test]
fn locale_ops_fixture_valid_schema() {
    let fixture = load_fixture("locale_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "locale_ops");
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
// Coverage validation: setlocale
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_setlocale() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("setlocale")).count() >= 3,
        "setlocale needs at least 3 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: localeconv
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_localeconv() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("localeconv")),
        "Missing test coverage for localeconv"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: nl_langinfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_nl_langinfo() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("nl_langinfo")).count() >= 2,
        "nl_langinfo needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: POSIX.1-2008 locale functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_posix_2008_functions() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["newlocale", "uselocale", "duplocale", "freelocale"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for POSIX.1-2008 function: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_error_codes_valid() {
    let fixture = load_fixture("locale_ops");

    // locale functions typically don't set errno, or use EINVAL
    let valid_errno_values = [
        0,  // Success
        22, // EINVAL
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
fn locale_ops_modes_valid() {
    let fixture = load_fixture("locale_ops");

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
fn locale_ops_covers_both_modes() {
    let fixture = load_fixture("locale_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "locale_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "locale_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_case_count_stable() {
    let fixture = load_fixture("locale_ops");

    const EXPECTED_MIN_CASES: usize = 15;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "locale_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("locale_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened fallback coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_hardened_fallbacks() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Hardened mode should test unsupported/unknown locale fallbacks
    assert!(
        case_names.iter().any(|n| n.contains("unsupported") || n.contains("unknown")),
        "locale_ops must test unsupported locale fallbacks in hardened mode"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_has_spec_references() {
    let fixture = load_fixture("locale_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11")
                || case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference C11 or POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}
