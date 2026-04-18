//! String operations conformance test suite.
//!
//! Validates POSIX string APIs: strcpy, strncpy, strcat, strcmp, strchr, strrchr, strstr, etc.
//! Run: cargo test -p frankenlibc-harness --test string_ops_conformance_test

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
fn string_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/string_ops.json");
    assert!(path.exists(), "string_ops.json fixture must exist");
}

#[test]
fn string_ops_fixture_valid_schema() {
    let fixture = load_fixture("string_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/narrow");
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
// Coverage validation: string operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_covers_copy_functions() {
    let fixture = load_fixture("string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["strcpy", "strncpy"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for copy function: {}",
            pattern
        );
    }
}

#[test]
fn string_ops_covers_concat_functions() {
    let fixture = load_fixture("string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("strcat")),
        "Missing test coverage for strcat"
    );
}

#[test]
fn string_ops_covers_strl_functions() {
    let fixture = load_fixture("string_ops");

    for function in ["strlcpy", "strlcat"] {
        assert!(
            fixture
                .cases
                .iter()
                .any(|case| case.function == function && case.mode == "strict"),
            "Missing strict fixture coverage for {function}"
        );
        assert!(
            fixture.cases.iter().any(|case| {
                case.function == function
                    && case.mode == "hardened"
                    && case.name.contains("dst_bound")
                    && case
                        .expected_output
                        .as_deref()
                        .is_some_and(|output| output.contains("repair=TruncateWithNull"))
            }),
            "Missing hardened destination-bound repair fixture coverage for {function}"
        );
    }
}

#[test]
fn string_ops_covers_compare_functions() {
    let fixture = load_fixture("string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["strcmp", "memcmp"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for compare function: {}",
            pattern
        );
    }
}

#[test]
fn string_ops_covers_search_functions() {
    let fixture = load_fixture("string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["strchr", "strrchr", "strstr", "memchr"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for search function: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_error_codes_valid() {
    let fixture = load_fixture("string_ops");

    // String ops generally don't set errno on success
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
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_modes_valid() {
    let fixture = load_fixture("string_ops");

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
fn string_ops_case_count_stable() {
    let fixture = load_fixture("string_ops");

    const EXPECTED_MIN_CASES: usize = 10;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "string_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("string_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_covers_both_modes() {
    let fixture = load_fixture("string_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "string_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "string_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened mode: buffer overflow protection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_covers_overflow_protection() {
    let fixture = load_fixture("string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Hardened mode should have overflow protection tests
    assert!(
        case_names.iter().any(|name| name.contains("overflow")),
        "Missing test coverage for hardened overflow protection"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Function distribution
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_function_distribution() {
    let fixture = load_fixture("string_ops");

    let functions: Vec<&str> = fixture.cases.iter().map(|c| c.function.as_str()).collect();

    let unique_functions: std::collections::HashSet<_> = functions.iter().collect();

    // Ensure we have diversity of functions
    assert!(
        unique_functions.len() >= 8,
        "string_ops should cover at least 8 different functions, has {}",
        unique_functions.len()
    );

    eprintln!(
        "string_ops covers {} unique functions: {:?}",
        unique_functions.len(),
        unique_functions
    );
}

#[test]
fn string_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("string_ops");

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
