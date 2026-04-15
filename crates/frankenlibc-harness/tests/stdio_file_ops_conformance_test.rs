//! stdio file operations conformance test suite.
//!
//! Validates C11/POSIX stdio.h file functions: fopen, fclose, fread, fwrite, fseek, ftell, etc.
//! Run: cargo test -p frankenlibc-harness --test stdio_file_ops_conformance_test

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
fn stdio_file_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/stdio_file_ops.json");
    assert!(path.exists(), "stdio_file_ops.json fixture must exist");
}

#[test]
fn stdio_file_ops_fixture_valid_schema() {
    let fixture = load_fixture("stdio_file_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdio_file_ops");
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
// Coverage validation: file opening/closing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_fopen() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("fopen")).count() >= 2,
        "fopen needs at least 2 test cases"
    );
}

#[test]
fn stdio_file_ops_covers_fclose() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fclose")),
        "Missing test coverage for fclose"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: read/write operations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_fread() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fread")),
        "Missing test coverage for fread"
    );
}

#[test]
fn stdio_file_ops_covers_fwrite() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fwrite")),
        "Missing test coverage for fwrite"
    );
}

#[test]
fn stdio_file_ops_covers_formatted_io() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|name| name.contains("printf") || name.contains("snprintf")),
        "Missing test coverage for formatted output (printf/snprintf)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: seeking and position
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_fseek() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fseek")),
        "Missing test coverage for fseek"
    );
}

#[test]
fn stdio_file_ops_covers_ftell() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("ftell")),
        "Missing test coverage for ftell"
    );
}

#[test]
fn stdio_file_ops_covers_fflush() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fflush")),
        "Missing test coverage for fflush"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_error_codes_valid() {
    let fixture = load_fixture("stdio_file_ops");

    // Valid POSIX/Linux error codes for stdio functions
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
fn stdio_file_ops_modes_valid() {
    let fixture = load_fixture("stdio_file_ops");

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
fn stdio_file_ops_covers_both_modes() {
    let fixture = load_fixture("stdio_file_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(
        has_strict,
        "stdio_file_ops must have strict mode test cases"
    );
    assert!(
        has_hardened,
        "stdio_file_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_case_count_stable() {
    let fixture = load_fixture("stdio_file_ops");

    const EXPECTED_MIN_CASES: usize = 12;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "stdio_file_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "stdio_file_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_error_paths() {
    let fixture = load_fixture("stdio_file_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|n| n.contains("invalid") || n.contains("nonexistent")),
        "stdio_file_ops must test error paths (invalid path/mode)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_has_spec_references() {
    let fixture = load_fixture("stdio_file_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11") || case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference C11 or POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}
