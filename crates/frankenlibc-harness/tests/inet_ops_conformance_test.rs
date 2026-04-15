//! Internet address operations conformance test suite.
//!
//! Validates POSIX arpa/inet.h functions: htons, htonl, ntohs, ntohl, inet_addr, inet_pton, inet_ntop.
//! Run: cargo test -p frankenlibc-harness --test inet_ops_conformance_test

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
fn inet_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/inet_ops.json");
    assert!(path.exists(), "inet_ops.json fixture must exist");
}

#[test]
fn inet_ops_fixture_valid_schema() {
    let fixture = load_fixture("inet_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "inet");
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
// Coverage validation: byte order macros
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inet_ops_covers_htons() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("htons")).count() >= 2,
        "htons needs at least 2 test cases"
    );
}

#[test]
fn inet_ops_covers_htonl() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("htonl")),
        "Missing test coverage for htonl"
    );
}

#[test]
fn inet_ops_covers_ntohs() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("ntohs")),
        "Missing test coverage for ntohs"
    );
}

#[test]
fn inet_ops_covers_ntohl() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("ntohl")),
        "Missing test coverage for ntohl"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: address conversion functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inet_ops_covers_inet_addr() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("inet_addr"))
            .count()
            >= 2,
        "inet_addr needs at least 2 test cases"
    );
}

#[test]
fn inet_ops_covers_inet_pton() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("inet_pton"))
            .count()
            >= 2,
        "inet_pton needs at least 2 test cases (v4 and v6)"
    );
}

#[test]
fn inet_ops_covers_inet_ntop() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("inet_ntop")),
        "Missing test coverage for inet_ntop"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv4/IPv6 coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inet_ops_covers_ipv4_and_ipv6() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("v4")),
        "inet_ops must test IPv4 addresses"
    );
    assert!(
        case_names.iter().any(|n| n.contains("v6")),
        "inet_ops must test IPv6 addresses"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inet_ops_error_codes_valid() {
    let fixture = load_fixture("inet_ops");

    // inet functions generally don't set errno
    let valid_errno_values = [0];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (inet functions don't set errno)",
            case.name,
            case.expected_errno,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inet_ops_modes_valid() {
    let fixture = load_fixture("inet_ops");

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
fn inet_ops_case_count_stable() {
    let fixture = load_fixture("inet_ops");

    const EXPECTED_MIN_CASES: usize = 12;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "inet_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("inet_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inet_ops_covers_error_paths() {
    let fixture = load_fixture("inet_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("invalid")),
        "inet_ops must test invalid address parsing"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inet_ops_has_posix_references() {
    let fixture = load_fixture("inet_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}
