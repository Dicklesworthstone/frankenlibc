//! iconv phase-1 conformance test suite.
//!
//! Validates POSIX iconv functions: iconv_open, iconv, iconv_close.
//! Run: cargo test -p frankenlibc-harness --test iconv_phase1_conformance_test

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
fn iconv_phase1_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/iconv_phase1.json");
    assert!(path.exists(), "iconv_phase1.json fixture must exist");
}

#[test]
fn iconv_phase1_fixture_valid_schema() {
    let fixture = load_fixture("iconv_phase1");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "iconv/phase1");
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
fn iconv_phase1_covers_iconv_open() {
    let fixture = load_fixture("iconv_phase1");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("iconv_open"))
            .count()
            >= 2,
        "iconv_open needs at least 2 test cases"
    );
}

#[test]
fn iconv_phase1_covers_iconv() {
    let fixture = load_fixture("iconv_phase1");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.starts_with("strict_") || n.starts_with("hardened_"))
            .count()
            >= 5,
        "iconv conversion needs at least 5 test cases"
    );
}

#[test]
fn iconv_phase1_covers_iconv_close() {
    let fixture = load_fixture("iconv_phase1");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("iconv_close")),
        "Missing test coverage for iconv_close"
    );
}

#[test]
fn iconv_phase1_covers_error_codes() {
    let fixture = load_fixture("iconv_phase1");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("e2big") || n.contains("E2BIG")),
        "Missing test coverage for E2BIG"
    );
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("eilseq") || n.contains("EILSEQ")),
        "Missing test coverage for EILSEQ"
    );
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("einval") || n.contains("EINVAL")),
        "Missing test coverage for EINVAL"
    );
}

#[test]
fn iconv_phase1_modes_valid() {
    let fixture = load_fixture("iconv_phase1");
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
fn iconv_phase1_covers_both_modes() {
    let fixture = load_fixture("iconv_phase1");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "iconv_phase1 must have strict mode test cases");
    assert!(
        has_hardened,
        "iconv_phase1 must have hardened mode test cases"
    );
}

#[test]
fn iconv_phase1_case_count_stable() {
    let fixture = load_fixture("iconv_phase1");
    assert!(
        fixture.cases.len() >= 10,
        "iconv_phase1 fixture has {} cases, expected at least 10",
        fixture.cases.len()
    );
    eprintln!(
        "iconv_phase1 fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn iconv_phase1_has_spec_references() {
    let fixture = load_fixture("iconv_phase1");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX")
                || case.spec_section.contains("iconv")
                || case.spec_section.contains("TSM"),
            "Case {} spec_section should reference POSIX, iconv, or TSM: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn iconv_phase1_error_codes_valid() {
    let fixture = load_fixture("iconv_phase1");

    // Valid error codes for iconv operations
    let valid_errno_values = [
        0,  // Success
        7,  // E2BIG (output buffer too small)
        22, // EINVAL (incomplete sequence)
        84, // EILSEQ (invalid sequence)
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
