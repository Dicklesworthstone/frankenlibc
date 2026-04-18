//! errno operations conformance test suite.
//!
//! Validates errno operations: __errno_location, strerror, strerror_r, perror.
//! Run: cargo test -p frankenlibc-harness --test errno_ops_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};

use frankenlibc_fixture_exec::execute_fixture_case;

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
    expected_return: Option<i32>,
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    notes: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn expected_contract_text(case: &FixtureCase) -> String {
    case.expected_output.clone().unwrap_or_else(|| {
        case.expected_return
            .expect("errno_ops cases must have expected_output or expected_return")
            .to_string()
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn errno_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/errno_ops.json");
    assert!(path.exists(), "errno_ops.json fixture must exist");
}

#[test]
fn errno_ops_fixture_valid_schema() {
    let fixture = load_fixture("errno_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "errno_ops");
    assert!(!fixture.cases.is_empty(), "Must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            !case.spec_section.is_empty(),
            "Spec section must not be empty"
        );
        assert!(
            case.expected_output.is_some() || case.expected_return.is_some(),
            "Case {} must have expected_output or expected_return",
            case.name
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: all errno operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn errno_ops_covers_errno_location() {
    let fixture = load_fixture("errno_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "errno_location_nonnull",
        "errno_initially_zero",
        "errno_set_read",
        "errno_thread_local",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for __errno_location pattern: {}",
            pattern
        );
    }
}

#[test]
fn errno_ops_covers_strerror() {
    let fixture = load_fixture("errno_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "strerror_einval",
        "strerror_enoent",
        "strerror_eacces",
        "strerror_zero",
        "strerror_unknown",
        "strerror_negative",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for strerror pattern: {}",
            pattern
        );
    }
}

#[test]
fn errno_ops_covers_strerror_r() {
    let fixture = load_fixture("errno_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "strerror_r_success",
        "strerror_r_buffer_too_small",
        "strerror_r_null",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for strerror_r pattern: {}",
            pattern
        );
    }
}

#[test]
fn errno_ops_covers_perror() {
    let fixture = load_fixture("errno_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["perror_prefix", "perror_null", "perror_empty"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for perror pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn errno_ops_error_codes_valid() {
    let fixture = load_fixture("errno_ops");

    // Valid POSIX/Linux error codes that should appear
    let valid_errno_values = [
        0,  // Success
        2,  // ENOENT
        13, // EACCES
        17, // EEXIST
        22, // EINVAL
        34, // ERANGE
        42, // Custom test value
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
// Function grouping validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn errno_ops_function_distribution() {
    let fixture = load_fixture("errno_ops");

    let mut errno_location_count = 0;
    let mut strerror_count = 0;
    let mut strerror_r_count = 0;
    let mut strerror_l_count = 0;
    let mut perror_count = 0;
    let mut constants_count = 0;
    let mut preservation_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "__errno_location" => errno_location_count += 1,
            "strerror" => strerror_count += 1,
            "strerror_r" => strerror_r_count += 1,
            "strerror_l" => strerror_l_count += 1,
            "perror" => perror_count += 1,
            "errno_constants" => constants_count += 1,
            "errno_preservation" => preservation_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure reasonable coverage for each function
    assert!(
        errno_location_count >= 4,
        "__errno_location needs more test cases (have {})",
        errno_location_count
    );
    assert!(
        strerror_count >= 8,
        "strerror needs more test cases (have {})",
        strerror_count
    );
    assert!(
        strerror_r_count >= 2,
        "strerror_r needs more test cases (have {})",
        strerror_r_count
    );
    assert!(
        perror_count >= 2,
        "perror needs more test cases (have {})",
        perror_count
    );

    eprintln!(
        "errno_ops coverage: errno_location={}, strerror={}, strerror_r={}, strerror_l={}, perror={}, constants={}, preservation={}",
        errno_location_count,
        strerror_count,
        strerror_r_count,
        strerror_l_count,
        perror_count,
        constants_count,
        preservation_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn errno_ops_modes_valid() {
    let fixture = load_fixture("errno_ops");

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
fn errno_ops_case_count_stable() {
    let fixture = load_fixture("errno_ops");

    // This test ensures we don't accidentally remove test cases
    // Update this count when intentionally adding/removing cases
    const EXPECTED_MIN_CASES: usize = 20;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "errno_ops fixture has {} cases, expected at least {}. \
         If cases were intentionally removed, update EXPECTED_MIN_CASES.",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("errno_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec reference validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn errno_ops_has_spec_references() {
    let fixture = load_fixture("errno_ops");

    assert!(
        !fixture.spec_reference.is_empty(),
        "errno_ops fixture must have a spec_reference"
    );

    for case in &fixture.cases {
        assert!(
            !case.spec_section.is_empty(),
            "Case {} must have a spec_section",
            case.name
        );
    }
}

#[test]
fn errno_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("errno_ops");

    for case in &fixture.cases {
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
                result.impl_output,
                expected_contract_text(case),
                "fixture contract mismatch for {} ({mode})",
                case.name
            );
            assert_eq!(
                result.host_output, "SKIP",
                "errno_ops executor should stay deterministic instead of mutating host errno/stderr"
            );
            assert!(
                result.host_parity,
                "errno_ops symbolic execution should mark fixture contract parity"
            );
        }
    }
}
