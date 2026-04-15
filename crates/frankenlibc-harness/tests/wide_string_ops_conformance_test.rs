//! Wide string operations conformance test suite.
//!
//! Validates ISO C wide string functions: wcslen, wcscpy, wcscmp, wcsncpy, wcscat,
//! wcschr, wcsstr, wcsncmp, wcsrchr.
//! Run: cargo test -p frankenlibc-harness --test wide_string_ops_conformance_test

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
fn wide_string_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/wide_string_ops.json");
    assert!(path.exists(), "wide_string_ops.json fixture must exist");
}

#[test]
fn wide_string_ops_fixture_valid_schema() {
    let fixture = load_fixture("wide_string_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/wide");
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
fn wide_string_ops_covers_wcslen() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wcslen")).count() >= 2,
        "wcslen needs at least 2 test cases"
    );
}

#[test]
fn wide_string_ops_covers_wcscpy() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wcscpy")),
        "Missing test coverage for wcscpy"
    );
}

#[test]
fn wide_string_ops_covers_wcscmp() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wcscmp")).count() >= 2,
        "wcscmp needs at least 2 test cases"
    );
}

#[test]
fn wide_string_ops_covers_wcschr() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wcschr")).count() >= 2,
        "wcschr needs at least 2 test cases (found and not found)"
    );
}

#[test]
fn wide_string_ops_covers_wcsstr() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wcsstr")),
        "Missing test coverage for wcsstr"
    );
}

#[test]
fn wide_string_ops_modes_valid() {
    let fixture = load_fixture("wide_string_ops");
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
fn wide_string_ops_covers_hardened_mode() {
    let fixture = load_fixture("wide_string_ops");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(
        has_hardened,
        "wide_string_ops must have hardened mode test cases"
    );
}

#[test]
fn wide_string_ops_case_count_stable() {
    let fixture = load_fixture("wide_string_ops");
    assert!(
        fixture.cases.len() >= 10,
        "wide_string_ops fixture has {} cases, expected at least 10",
        fixture.cases.len()
    );
    eprintln!(
        "wide_string_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn wide_string_ops_has_spec_references() {
    let fixture = load_fixture("wide_string_ops");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("ISO C") || case.spec_section.contains("TSM"),
            "Case {} spec_section should reference ISO C or TSM: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn wide_string_ops_error_codes_valid() {
    let fixture = load_fixture("wide_string_ops");

    // Wide string functions don't set errno
    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {} (wide string functions don't set errno)",
            case.name, case.expected_errno
        );
    }
}
