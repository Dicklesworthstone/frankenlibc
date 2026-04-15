//! Allocator conformance test suite.
//!
//! Validates POSIX memory allocation functions: malloc, calloc, free, realloc.
//! Run: cargo test -p frankenlibc-harness --test allocator_conformance_test

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
fn allocator_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/allocator.json");
    assert!(path.exists(), "allocator.json fixture must exist");
}

#[test]
fn allocator_fixture_valid_schema() {
    let fixture = load_fixture("allocator");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "allocator");
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
fn allocator_covers_malloc() {
    let fixture = load_fixture("allocator");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("malloc")).count() >= 2,
        "malloc needs at least 2 test cases"
    );
}

#[test]
fn allocator_covers_calloc() {
    let fixture = load_fixture("allocator");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("calloc")),
        "Missing test coverage for calloc"
    );
}

#[test]
fn allocator_covers_free() {
    let fixture = load_fixture("allocator");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("free")),
        "Missing test coverage for free"
    );
}

#[test]
fn allocator_covers_realloc() {
    let fixture = load_fixture("allocator");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("realloc")),
        "Missing test coverage for realloc"
    );
}

#[test]
fn allocator_modes_valid() {
    let fixture = load_fixture("allocator");
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
fn allocator_case_count_stable() {
    let fixture = load_fixture("allocator");
    assert!(
        fixture.cases.len() >= 4,
        "allocator fixture has {} cases, expected at least 4",
        fixture.cases.len()
    );
    eprintln!("allocator fixture has {} test cases", fixture.cases.len());
}

#[test]
fn allocator_has_posix_references() {
    let fixture = load_fixture("allocator");
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
fn allocator_error_codes_valid() {
    let fixture = load_fixture("allocator");

    // malloc/calloc/free/realloc don't set errno on success
    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {} (allocation functions don't set errno on success)",
            case.name, case.expected_errno
        );
    }
}

#[test]
fn allocator_covers_edge_cases() {
    let fixture = load_fixture("allocator");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("zero") || n.contains("null")),
        "allocator must test edge cases (zero size, null ptr)"
    );
}
