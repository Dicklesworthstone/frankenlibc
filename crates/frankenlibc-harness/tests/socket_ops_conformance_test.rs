//! Socket operations conformance test suite.
//!
//! Validates POSIX socket APIs: socket, bind, listen, accept, connect, etc.
//! Run: cargo test -p frankenlibc-harness --test socket_ops_conformance_test

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
fn socket_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/socket_ops.json");
    assert!(path.exists(), "socket_ops.json fixture must exist");
}

#[test]
fn socket_ops_fixture_valid_schema() {
    let fixture = load_fixture("socket_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "socket_ops");
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
// Coverage validation: socket operations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_socket() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["socket_tcp", "socket_udp", "socket_invalid"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for socket pattern: {}",
            pattern
        );
    }
}

#[test]
fn socket_ops_covers_bind() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("bind")),
        "Missing test coverage for bind"
    );
}

#[test]
fn socket_ops_covers_listen() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("listen")),
        "Missing test coverage for listen"
    );
}

#[test]
fn socket_ops_covers_shutdown() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("shutdown")),
        "Missing test coverage for shutdown"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_error_codes_valid() {
    let fixture = load_fixture("socket_ops");

    // Valid POSIX/Linux error codes for socket functions
    let valid_errno_values = [
        0,  // Success
        9,  // EBADF
        22, // EINVAL
        97, // EAFNOSUPPORT
        98, // EADDRINUSE
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
fn socket_ops_modes_valid() {
    let fixture = load_fixture("socket_ops");

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
fn socket_ops_case_count_stable() {
    let fixture = load_fixture("socket_ops");

    const EXPECTED_MIN_CASES: usize = 8;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "socket_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("socket_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_both_modes() {
    let fixture = load_fixture("socket_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "socket_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "socket_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_error_paths() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Must test invalid fd and invalid domain errors
    assert!(
        case_names.iter().any(|n| n.contains("invalid")),
        "socket_ops must test error paths (invalid fd/domain)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol coverage: TCP and UDP
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_tcp_and_udp() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("tcp")),
        "socket_ops must test TCP sockets"
    );
    assert!(
        case_names.iter().any(|n| n.contains("udp")),
        "socket_ops must test UDP sockets"
    );
}
