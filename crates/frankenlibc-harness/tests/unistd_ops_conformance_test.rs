//! unistd operations conformance test suite.
//!
//! Validates POSIX unistd.h syscall wrappers: getpid, getuid, read, write, close, etc.
//! Run: cargo test -p frankenlibc-harness --test unistd_ops_conformance_test

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
fn unistd_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/unistd_ops.json");
    assert!(path.exists(), "unistd_ops.json fixture must exist");
}

#[test]
fn unistd_ops_fixture_valid_schema() {
    let fixture = load_fixture("unistd_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "unistd");
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
// Coverage validation: unistd operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_covers_process_identity() {
    let fixture = load_fixture("unistd_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["getpid", "getppid"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for process identity: {}",
            pattern
        );
    }
}

#[test]
fn unistd_ops_covers_user_identity() {
    let fixture = load_fixture("unistd_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["getuid", "getgid", "geteuid", "getegid"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for user identity: {}",
            pattern
        );
    }
}

#[test]
fn unistd_ops_covers_file_ops() {
    let fixture = load_fixture("unistd_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["read", "write", "close", "lseek"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for file operation: {}",
            pattern
        );
    }
}

#[test]
fn unistd_ops_covers_filesystem() {
    let fixture = load_fixture("unistd_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["getcwd", "access"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for filesystem: {}",
            pattern
        );
    }
}

#[test]
fn unistd_ops_covers_terminal() {
    let fixture = load_fixture("unistd_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("isatty")),
        "Missing test coverage for isatty"
    );
}

#[test]
fn unistd_ops_covers_pipe() {
    let fixture = load_fixture("unistd_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("pipe")),
        "Missing test coverage for pipe"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_error_codes_valid() {
    let fixture = load_fixture("unistd_ops");

    // Valid POSIX/Linux error codes for unistd functions
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
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_modes_valid() {
    let fixture = load_fixture("unistd_ops");

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
fn unistd_ops_case_count_stable() {
    let fixture = load_fixture("unistd_ops");

    const EXPECTED_MIN_CASES: usize = 15;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "unistd_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("unistd_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_has_posix_references() {
    let fixture = load_fixture("unistd_ops");

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
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_covers_error_paths() {
    let fixture = load_fixture("unistd_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Must have error path tests
    let error_patterns = ["invalid", "enoent", "ebadf"];

    let has_error_tests = error_patterns
        .iter()
        .any(|p| case_names.iter().any(|n| n.to_lowercase().contains(p)));

    assert!(
        has_error_tests,
        "unistd_ops must have error path test cases"
    );
}
