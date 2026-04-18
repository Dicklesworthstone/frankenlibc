//! Directory operations conformance test suite.
//!
//! Validates POSIX directory APIs: opendir, readdir, closedir, etc.
//! Run: cargo test -p frankenlibc-harness --test dirent_ops_conformance_test

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
fn dirent_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/dirent_ops.json");
    assert!(path.exists(), "dirent_ops.json fixture must exist");
}

#[test]
fn dirent_ops_fixture_valid_schema() {
    let fixture = load_fixture("dirent_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "dirent_ops");
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
// Coverage validation: directory operations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_covers_opendir() {
    let fixture = load_fixture("dirent_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["opendir_root", "opendir_nonexistent"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for opendir pattern: {}",
            pattern
        );
    }
}

#[test]
fn dirent_ops_covers_readdir() {
    let fixture = load_fixture("dirent_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("readdir")),
        "Missing test coverage for readdir"
    );
}

#[test]
fn dirent_ops_covers_closedir() {
    let fixture = load_fixture("dirent_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("closedir")),
        "Missing test coverage for closedir"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_error_codes_valid() {
    let fixture = load_fixture("dirent_ops");

    // Valid POSIX/Linux error codes for dirent functions
    let valid_errno_values = [
        0, // Success
        2, // ENOENT
        9, // EBADF
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
fn dirent_ops_function_distribution() {
    let fixture = load_fixture("dirent_ops");

    let mut opendir_count = 0;
    let mut readdir_count = 0;
    let mut closedir_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "opendir" => opendir_count += 1,
            "readdir" | "readdir_r" => readdir_count += 1,
            "closedir" => closedir_count += 1,
            "rewinddir" | "seekdir" | "telldir" | "scandir" | "fdopendir" | "dirfd" => {}
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    assert!(
        opendir_count >= 2,
        "opendir needs more test cases (have {})",
        opendir_count
    );
    assert!(
        readdir_count >= 1,
        "readdir needs test cases (have {})",
        readdir_count
    );
    assert!(
        closedir_count >= 1,
        "closedir needs test cases (have {})",
        closedir_count
    );

    eprintln!(
        "dirent_ops coverage: opendir={}, readdir={}, closedir={}",
        opendir_count, readdir_count, closedir_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_modes_valid() {
    let fixture = load_fixture("dirent_ops");

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
fn dirent_ops_case_count_stable() {
    let fixture = load_fixture("dirent_ops");

    const EXPECTED_MIN_CASES: usize = 5;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "dirent_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("dirent_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_covers_both_modes() {
    let fixture = load_fixture("dirent_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "dirent_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "dirent_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_covers_error_paths() {
    let fixture = load_fixture("dirent_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("nonexistent")),
        "dirent_ops must test ENOENT error path"
    );
}

#[test]
fn dirent_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("dirent_ops");

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
                result.host_parity,
                "executor reported parity failure for {} ({mode})",
                case.name
            );
        }
    }
}
