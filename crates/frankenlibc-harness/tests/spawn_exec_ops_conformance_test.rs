//! Spawn/exec operations conformance test suite.
//!
//! Validates POSIX/C11 process creation functions: posix_spawn, execve, system.
//! Run: cargo test -p frankenlibc-harness --test spawn_exec_ops_conformance_test

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
fn spawn_exec_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/spawn_exec_ops.json");
    assert!(path.exists(), "spawn_exec_ops.json fixture must exist");
}

#[test]
fn spawn_exec_ops_fixture_valid_schema() {
    let fixture = load_fixture("spawn_exec_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "spawn_exec_ops");
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
// Coverage validation: posix_spawn
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spawn_exec_ops_covers_posix_spawn() {
    let fixture = load_fixture("spawn_exec_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("posix_spawn"))
            .count()
            >= 2,
        "posix_spawn needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: execve
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spawn_exec_ops_covers_execve() {
    let fixture = load_fixture("spawn_exec_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("execve")),
        "Missing test coverage for execve"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: system
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spawn_exec_ops_covers_system() {
    let fixture = load_fixture("spawn_exec_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("system")),
        "Missing test coverage for system()"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spawn_exec_ops_error_codes_valid() {
    let fixture = load_fixture("spawn_exec_ops");

    // Valid POSIX/Linux error codes for spawn/exec functions
    let valid_errno_values = [
        0,  // Success
        2,  // ENOENT
        13, // EACCES
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
fn spawn_exec_ops_modes_valid() {
    let fixture = load_fixture("spawn_exec_ops");

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
fn spawn_exec_ops_covers_both_modes() {
    let fixture = load_fixture("spawn_exec_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(
        has_strict,
        "spawn_exec_ops must have strict mode test cases"
    );
    assert!(
        has_hardened,
        "spawn_exec_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spawn_exec_ops_case_count_stable() {
    let fixture = load_fixture("spawn_exec_ops");

    const EXPECTED_MIN_CASES: usize = 5;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "spawn_exec_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "spawn_exec_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spawn_exec_ops_covers_error_paths() {
    let fixture = load_fixture("spawn_exec_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Should test ENOENT (nonexistent) and EACCES errors
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("nonexistent") || n.contains("eacces")),
        "spawn_exec_ops must test error paths (ENOENT, EACCES)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spawn_exec_ops_has_spec_references() {
    let fixture = load_fixture("spawn_exec_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("C11"),
            "Case {} spec_section should reference POSIX or C11: {}",
            case.name,
            case.spec_section
        );
    }
}
