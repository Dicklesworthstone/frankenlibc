//! pthread TLS keys conformance test suite.
//!
//! Validates POSIX pthread TLS key functions: pthread_key_create, pthread_key_delete,
//! pthread_getspecific, pthread_setspecific.
//! Run: cargo test -p frankenlibc-harness --test pthread_tls_keys_conformance_test

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
    notes: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn pthread_tls_keys_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pthread_tls_keys.json");
    assert!(path.exists(), "pthread_tls_keys.json fixture must exist");
}

#[test]
fn pthread_tls_keys_fixture_valid_schema() {
    let fixture = load_fixture("pthread_tls_keys");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pthread/tls_keys");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
}

#[test]
fn pthread_tls_keys_covers_key_create() {
    let fixture = load_fixture("pthread_tls_keys");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("key_create"))
            .count()
            >= 2,
        "pthread_key_create needs at least 2 test cases"
    );
}

#[test]
fn pthread_tls_keys_covers_key_delete() {
    let fixture = load_fixture("pthread_tls_keys");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("key_delete"))
            .count()
            >= 2,
        "pthread_key_delete needs at least 2 test cases"
    );
}

#[test]
fn pthread_tls_keys_covers_getspecific() {
    let fixture = load_fixture("pthread_tls_keys");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("getspecific"))
            .count()
            >= 2,
        "pthread_getspecific needs at least 2 test cases"
    );
}

#[test]
fn pthread_tls_keys_covers_setspecific() {
    let fixture = load_fixture("pthread_tls_keys");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("setspecific"))
            .count()
            >= 2,
        "pthread_setspecific needs at least 2 test cases"
    );
}

#[test]
fn pthread_tls_keys_covers_destructors() {
    let fixture = load_fixture("pthread_tls_keys");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("destructor"))
            .count()
            >= 3,
        "pthread TLS key destructors need at least 3 test cases"
    );
}

#[test]
fn pthread_tls_keys_modes_valid() {
    let fixture = load_fixture("pthread_tls_keys");
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
}

#[test]
fn pthread_tls_keys_error_codes_valid() {
    let fixture = load_fixture("pthread_tls_keys");

    // Valid error codes for pthread TLS key operations
    let valid_errno_values = [
        0,  // Success
        11, // EAGAIN (key exhaustion)
        22, // EINVAL (invalid key)
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

#[test]
fn pthread_tls_keys_case_count_stable() {
    let fixture = load_fixture("pthread_tls_keys");
    assert!(
        fixture.cases.len() >= 12,
        "pthread_tls_keys fixture has {} cases, expected at least 12",
        fixture.cases.len()
    );
    eprintln!(
        "pthread_tls_keys fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn pthread_tls_keys_has_posix_references() {
    let fixture = load_fixture("pthread_tls_keys");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn pthread_tls_keys_covers_edge_cases() {
    let fixture = load_fixture("pthread_tls_keys");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Should test: exhaustion, invalid key, deleted key, out of bounds
    assert!(
        case_names.iter().any(|n| n.contains("exhaustion")),
        "Must test key exhaustion"
    );
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("invalid") || n.contains("out_of_bounds")),
        "Must test invalid key handling"
    );
    assert!(
        case_names.iter().any(|n| n.contains("deleted")),
        "Must test deleted key handling"
    );
}
