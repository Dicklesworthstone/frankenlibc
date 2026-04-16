//! Setjmp nested edges conformance test suite.
//!
//! Validates nested and edge non-local jump scenarios.
//! Run: cargo test -p frankenlibc-harness --test setjmp_nested_edges_conformance_test

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
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    bead: String,
    family: String,
    #[serde(default)]
    captured_at: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    seed: String,
    program_scenarios: Vec<ProgramScenario>,
    #[serde(default)]
    unsupported_scenarios: Vec<UnsupportedScenario>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ProgramScenario {
    scenario_id: String,
    source: String,
    jump_depth: i32,
    mask_state: String,
    expected: ExpectedOutcome,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ExpectedOutcome {
    strict: ModeExpectation,
    hardened: ModeExpectation,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ModeExpectation {
    exit_code: i32,
    stdout_contains: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct UnsupportedScenario {
    scenario_id: String,
    modes: Vec<String>,
    jump_depth: i32,
    mask_state: String,
    expected_outcome: String,
    expected_errno: String,
    documented_semantics: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn setjmp_nested_edges_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/setjmp_nested_edges.json");
    assert!(path.exists(), "setjmp_nested_edges.json fixture must exist");
}

#[test]
fn setjmp_nested_edges_fixture_valid_schema() {
    let fixture = load_fixture("setjmp_nested_edges");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "setjmp_nested_edges");
    assert!(
        !fixture.program_scenarios.is_empty(),
        "Must have program scenarios"
    );
    for scenario in &fixture.program_scenarios {
        assert!(
            !scenario.scenario_id.is_empty(),
            "Scenario ID must not be empty"
        );
        assert!(!scenario.source.is_empty(), "Source must not be empty");
    }
}

#[test]
fn setjmp_nested_edges_covers_nested_longjmp() {
    let fixture = load_fixture("setjmp_nested_edges");
    let scenario_ids: Vec<&str> = fixture
        .program_scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert!(
        scenario_ids.iter().any(|id| id.contains("nested")),
        "Missing test coverage for nested longjmp"
    );
}

#[test]
fn setjmp_nested_edges_covers_sigmask() {
    let fixture = load_fixture("setjmp_nested_edges");
    let scenario_ids: Vec<&str> = fixture
        .program_scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert!(
        scenario_ids
            .iter()
            .any(|id| id.contains("sigmask") || id.contains("mask")),
        "Missing test coverage for sigmask handling"
    );
}

#[test]
fn setjmp_nested_edges_has_depth_variants() {
    let fixture = load_fixture("setjmp_nested_edges");
    let depths: Vec<i32> = fixture
        .program_scenarios
        .iter()
        .map(|s| s.jump_depth)
        .collect();
    let has_depth_one = depths.contains(&1);
    let has_depth_two = depths.contains(&2);
    assert!(
        has_depth_one && has_depth_two,
        "Need scenarios with jump depth 1 and 2"
    );
}

#[test]
fn setjmp_nested_edges_documents_unsupported() {
    let fixture = load_fixture("setjmp_nested_edges");
    assert!(
        !fixture.unsupported_scenarios.is_empty(),
        "Should document unsupported scenarios"
    );
    for scenario in &fixture.unsupported_scenarios {
        assert!(
            !scenario.documented_semantics.is_empty(),
            "Unsupported scenario {} must have documented semantics",
            scenario.scenario_id
        );
    }
}

#[test]
fn setjmp_nested_edges_unsupported_covers_cross_thread() {
    let fixture = load_fixture("setjmp_nested_edges");
    let scenario_ids: Vec<&str> = fixture
        .unsupported_scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert!(
        scenario_ids.iter().any(|id| id.contains("cross_thread")),
        "Should document cross-thread longjmp as unsupported"
    );
}

#[test]
fn setjmp_nested_edges_both_modes_expected() {
    let fixture = load_fixture("setjmp_nested_edges");
    for scenario in &fixture.program_scenarios {
        assert!(
            scenario.expected.strict.exit_code == 0,
            "Scenario {} strict mode should expect success",
            scenario.scenario_id
        );
        assert!(
            scenario.expected.hardened.exit_code == 0,
            "Scenario {} hardened mode should expect success",
            scenario.scenario_id
        );
    }
}

#[test]
fn setjmp_nested_edges_scenario_count_stable() {
    let fixture = load_fixture("setjmp_nested_edges");
    let total_scenarios = fixture.program_scenarios.len() + fixture.unsupported_scenarios.len();
    assert!(
        total_scenarios >= 3,
        "setjmp_nested_edges fixture has {} scenarios, expected at least 3",
        total_scenarios
    );
    eprintln!(
        "setjmp_nested_edges fixture has {} program + {} unsupported scenarios",
        fixture.program_scenarios.len(),
        fixture.unsupported_scenarios.len()
    );
}

#[test]
fn setjmp_nested_edges_has_bead_reference() {
    let fixture = load_fixture("setjmp_nested_edges");
    assert!(
        !fixture.bead.is_empty(),
        "setjmp_nested_edges should reference a bead"
    );
}
