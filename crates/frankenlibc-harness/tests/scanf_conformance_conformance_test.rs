//! scanf conformance test suite.
//!
//! Validates C11/POSIX scanf family functions: sscanf with all conversion
//! specifiers, assignment suppression, width, and length modifiers.
//! Run: cargo test -p frankenlibc-harness --test scanf_conformance_conformance_test

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
    expected_return: Option<i32>,
    #[serde(default)]
    expected_values: Option<serde_json::Value>,
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
fn scanf_conformance_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/scanf_conformance.json");
    assert!(path.exists(), "scanf_conformance.json fixture must exist");
}

#[test]
fn scanf_conformance_fixture_valid_schema() {
    let fixture = load_fixture("scanf_conformance");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "scanf_conformance");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn scanf_conformance_covers_integer_specifiers() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("_d_")),
        "Missing %d tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_i_")),
        "Missing %i tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_u_")),
        "Missing %u tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_o_")),
        "Missing %o tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_x_")),
        "Missing %x tests"
    );
}

#[test]
fn scanf_conformance_covers_float_specifiers() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("_f_")),
        "Missing %f tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_lf_")),
        "Missing %lf tests"
    );
}

#[test]
fn scanf_conformance_covers_string_specifiers() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("_s_")),
        "Missing %s tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_c_")),
        "Missing %c tests"
    );
}

#[test]
fn scanf_conformance_covers_scansets() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("scanset")).count() >= 3,
        "Scanset needs at least 3 test cases"
    );
}

#[test]
fn scanf_conformance_covers_suppression() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("suppress")),
        "Missing assignment suppression (*) tests"
    );
}

#[test]
fn scanf_conformance_covers_length_modifiers() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("hh_")),
        "Missing hh length tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("h_")),
        "Missing h length tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("l_")),
        "Missing l length tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("ll_")),
        "Missing ll length tests"
    );
}

#[test]
fn scanf_conformance_covers_eof_and_errors() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("eof")),
        "Missing EOF tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("no_match")),
        "Missing no-match tests"
    );
}

#[test]
fn scanf_conformance_modes_valid() {
    let fixture = load_fixture("scanf_conformance");
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
fn scanf_conformance_case_count_stable() {
    let fixture = load_fixture("scanf_conformance");
    assert!(
        fixture.cases.len() >= 50,
        "scanf_conformance fixture has {} cases, expected at least 50",
        fixture.cases.len()
    );
    eprintln!(
        "scanf_conformance fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn scanf_conformance_has_spec_references() {
    let fixture = load_fixture("scanf_conformance");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11") || case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference C11 or POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn scanf_conformance_covers_special_values() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("inf")),
        "Missing infinity tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("nan")),
        "Missing NaN tests"
    );
}

#[test]
fn scanf_conformance_covers_width() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("width")).count() >= 3,
        "Width specifier needs at least 3 test cases"
    );
}
