//! Virtual memory operations conformance test suite.
//!
//! Validates POSIX virtual memory functions: mmap, munmap, mprotect, madvise.
//! Run: cargo test -p frankenlibc-harness --test virtual_memory_ops_conformance_test

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
    note: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn virtual_memory_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/virtual_memory_ops.json");
    assert!(path.exists(), "virtual_memory_ops.json fixture must exist");
}

#[test]
fn virtual_memory_ops_fixture_valid_schema() {
    let fixture = load_fixture("virtual_memory_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "virtual_memory_ops");
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
fn virtual_memory_ops_covers_mmap() {
    let fixture = load_fixture("virtual_memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("mmap")).count() >= 2,
        "mmap needs at least 2 test cases"
    );
}

#[test]
fn virtual_memory_ops_covers_munmap() {
    let fixture = load_fixture("virtual_memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("munmap")),
        "Missing test coverage for munmap"
    );
}

#[test]
fn virtual_memory_ops_covers_mprotect() {
    let fixture = load_fixture("virtual_memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("mprotect")),
        "Missing test coverage for mprotect"
    );
}

#[test]
fn virtual_memory_ops_covers_madvise() {
    let fixture = load_fixture("virtual_memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("madvise")),
        "Missing test coverage for madvise"
    );
}

#[test]
fn virtual_memory_ops_modes_valid() {
    let fixture = load_fixture("virtual_memory_ops");
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
fn virtual_memory_ops_covers_both_modes() {
    let fixture = load_fixture("virtual_memory_ops");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(
        has_strict,
        "virtual_memory_ops must have strict mode test cases"
    );
    assert!(
        has_hardened,
        "virtual_memory_ops must have hardened mode test cases"
    );
}

#[test]
fn virtual_memory_ops_case_count_stable() {
    let fixture = load_fixture("virtual_memory_ops");
    assert!(
        fixture.cases.len() >= 6,
        "virtual_memory_ops fixture has {} cases, expected at least 6",
        fixture.cases.len()
    );
    eprintln!(
        "virtual_memory_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn virtual_memory_ops_has_posix_references() {
    let fixture = load_fixture("virtual_memory_ops");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("Linux"),
            "Case {} spec_section should reference POSIX or Linux: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn virtual_memory_ops_error_codes_valid() {
    let fixture = load_fixture("virtual_memory_ops");

    // Valid error codes for virtual memory operations
    let valid_errno_values = [
        0,  // Success
        22, // EINVAL (invalid arguments)
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
fn virtual_memory_ops_covers_error_paths() {
    let fixture = load_fixture("virtual_memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("zero_length") || n.contains("invalid")),
        "virtual_memory_ops must test error paths"
    );
}
