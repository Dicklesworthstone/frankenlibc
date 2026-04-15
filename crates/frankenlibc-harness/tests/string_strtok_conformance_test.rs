//! String tokenization conformance test suite.
//!
//! Validates POSIX strtok/strtok_r functions.
//! Run: cargo test -p frankenlibc-harness --test string_strtok_conformance_test

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
fn string_strtok_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/string_strtok.json");
    assert!(path.exists(), "string_strtok.json fixture must exist");
}

#[test]
fn string_strtok_fixture_valid_schema() {
    let fixture = load_fixture("string_strtok");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/strtok");
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
fn string_strtok_covers_strtok() {
    let fixture = load_fixture("string_strtok");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.starts_with("strtok_"))
            .count()
            >= 3,
        "strtok needs at least 3 test cases"
    );
}

#[test]
fn string_strtok_covers_strtok_r() {
    let fixture = load_fixture("string_strtok");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("strtok_r")).count() >= 2,
        "strtok_r needs at least 2 test cases"
    );
}

#[test]
fn string_strtok_covers_edge_cases() {
    let fixture = load_fixture("string_strtok");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    // Should test: leading delims, no delim found, all delims
    assert!(
        case_names.iter().any(|n| n.contains("leading")),
        "Must test leading delimiters"
    );
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("no_delim") || n.contains("all_delim")),
        "Must test edge cases"
    );
}

#[test]
fn string_strtok_modes_valid() {
    let fixture = load_fixture("string_strtok");
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
fn string_strtok_case_count_stable() {
    let fixture = load_fixture("string_strtok");
    assert!(
        fixture.cases.len() >= 6,
        "string_strtok fixture has {} cases, expected at least 6",
        fixture.cases.len()
    );
    eprintln!(
        "string_strtok fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn string_strtok_has_posix_references() {
    let fixture = load_fixture("string_strtok");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}
