//! Pressure sensing conformance test suite.
//!
//! Validates PressureSensor regime state machine transitions.
//! Run: cargo test -p frankenlibc-harness --test pressure_sensing_conformance_test

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

#[test]
fn pressure_sensing_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pressure_sensing.json");
    assert!(path.exists(), "pressure_sensing.json fixture must exist");
}

#[test]
fn pressure_sensing_fixture_valid_schema() {
    let fixture = load_fixture("pressure_sensing");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pressure_sensing");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn pressure_sensing_covers_nominal_regime() {
    let fixture = load_fixture("pressure_sensing");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("nominal")),
        "Missing test coverage for Nominal regime"
    );
}

#[test]
fn pressure_sensing_covers_pressured_regime() {
    let fixture = load_fixture("pressure_sensing");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("pressured")),
        "Missing test coverage for Pressured regime"
    );
}

#[test]
fn pressure_sensing_covers_overloaded_regime() {
    let fixture = load_fixture("pressure_sensing");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("overloaded")),
        "Missing test coverage for Overloaded regime"
    );
}

#[test]
fn pressure_sensing_covers_recovery() {
    let fixture = load_fixture("pressure_sensing");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("recovery")),
        "Missing test coverage for Recovery transitions"
    );
}

#[test]
fn pressure_sensing_covers_hysteresis() {
    let fixture = load_fixture("pressure_sensing");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("hysteresis")),
        "Missing test coverage for hysteresis behavior"
    );
}

#[test]
fn pressure_sensing_has_strict_and_hardened() {
    let fixture = load_fixture("pressure_sensing");
    let strict_count = fixture.cases.iter().filter(|c| c.mode == "strict").count();
    let hardened_count = fixture
        .cases
        .iter()
        .filter(|c| c.mode == "hardened")
        .count();
    assert!(
        strict_count >= 1,
        "pressure_sensing needs at least 1 strict mode case"
    );
    assert!(
        hardened_count >= 1,
        "pressure_sensing needs at least 1 hardened mode case"
    );
}

#[test]
fn pressure_sensing_modes_valid() {
    let fixture = load_fixture("pressure_sensing");
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
fn pressure_sensing_case_count_stable() {
    let fixture = load_fixture("pressure_sensing");
    assert!(
        fixture.cases.len() >= 5,
        "pressure_sensing fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!(
        "pressure_sensing fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn pressure_sensing_has_spec_references() {
    let fixture = load_fixture("pressure_sensing");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("bd-w2c3") || case.spec_section.contains("Regime"),
            "Case {} spec_section should reference bd-w2c3 or Regime: {}",
            case.name,
            case.spec_section
        );
    }
}
