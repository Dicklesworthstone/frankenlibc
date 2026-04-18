//! stdlib conversion operations conformance test suite.
//!
//! Validates POSIX/C11 stdlib.h conversion functions: atoi, atol, strtol, strtoul, etc.
//! Run: cargo test -p frankenlibc-harness --test stdlib_conversion_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
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
fn stdlib_conversion_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/stdlib_conversion.json");
    assert!(path.exists(), "stdlib_conversion.json fixture must exist");
}

#[test]
fn stdlib_conversion_fixture_valid_schema() {
    let fixture = load_fixture("stdlib_conversion");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdlib/conversion");
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
fn stdlib_conversion_covers_atoi() {
    let fixture = load_fixture("stdlib_conversion");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("atoi")).count() >= 2,
        "atoi needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: strtol family
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_conversion_covers_strtol() {
    let fixture = load_fixture("stdlib_conversion");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("strtol")).count() >= 3,
        "strtol needs at least 3 test cases (decimal, hex, auto)"
    );
}

#[test]
fn stdlib_conversion_covers_bases() {
    let fixture = load_fixture("stdlib_conversion");

    // Check that different bases are tested
    let has_decimal = fixture.cases.iter().any(|c| c.name.contains("decimal"));
    let has_hex = fixture.cases.iter().any(|c| c.name.contains("hex"));
    let has_auto = fixture.cases.iter().any(|c| c.name.contains("auto"));

    assert!(has_decimal, "Must test decimal base conversion");
    assert!(has_hex, "Must test hexadecimal base conversion");
    assert!(has_auto, "Must test automatic base detection (base 0)");
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_conversion_error_codes_valid() {
    let fixture = load_fixture("stdlib_conversion");

    // Valid POSIX/Linux error codes for conversion functions
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
// Overflow handling
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_conversion_tests_overflow() {
    let fixture = load_fixture("stdlib_conversion");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("overflow")),
        "Must test overflow handling for conversion functions"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_conversion_modes_valid() {
    let fixture = load_fixture("stdlib_conversion");

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
fn stdlib_conversion_case_count_stable() {
    let fixture = load_fixture("stdlib_conversion");

    const EXPECTED_MIN_CASES: usize = 5;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "stdlib_conversion fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "stdlib_conversion fixture has {} test cases",
        fixture.cases.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdlib_conversion_covers_edge_cases() {
    let fixture = load_fixture("stdlib_conversion");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Should test: negative numbers, whitespace handling
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
fn stdlib_conversion_has_spec_references() {
    let fixture = load_fixture("stdlib_conversion");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("C11"),
            "Case {} spec_section should reference POSIX or C11: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn stdlib_conversion_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("stdlib_conversion");

    for case in &fixture.cases {
        let expected_output = case
            .expected_output
            .as_deref()
            .unwrap_or_else(|| panic!("case {} missing expected_output", case.name));
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_fixture_case(&case.function, &case.inputs, mode).unwrap_or_else(|err| {
                    panic!(
                        "fixture case {} ({mode}) failed to execute: {err}",
                        case.name
                    )
                });
            assert_eq!(
                result.impl_output, expected_output,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity || result.host_output == "UB",
                "defined host behavior diverged for {} ({mode}): host={}, impl={}",
                case.name,
                result.host_output,
                result.impl_output
            );
        }
    }
}
