//! Setjmp nested edges conformance test suite.
//!
//! Validates nested and edge non-local jump scenarios.
//! Run: cargo test -p frankenlibc-harness --test setjmp_nested_edges_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn unique_program_bin_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    repo_root().join("target").join(format!(
        "setjmp_nested_edges_bins_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn program_expectation<'a>(scenario: &'a ProgramScenario, mode: &str) -> &'a ModeExpectation {
    match mode {
        "strict" => &scenario.expected.strict,
        "hardened" => &scenario.expected.hardened,
        other => panic!("unexpected mode {other}"),
    }
}

fn compile_program_scenario(bin_dir: &Path, scenario: &ProgramScenario) -> PathBuf {
    let source_path = repo_root().join(&scenario.source);
    assert!(
        source_path.exists(),
        "scenario {} source must exist at {}",
        scenario.scenario_id,
        source_path.display()
    );
    std::fs::create_dir_all(bin_dir).expect("program bin dir should be creatable");
    let binary_path = bin_dir.join(&scenario.scenario_id);
    let output = Command::new("cc")
        .arg("-std=c11")
        .arg("-O2")
        .arg(&source_path)
        .arg("-o")
        .arg(&binary_path)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "failed to spawn cc for {} at {}: {err}",
                scenario.scenario_id,
                source_path.display()
            )
        });
    assert!(
        output.status.success(),
        "cc failed for scenario {}:\nstdout={}\nstderr={}",
        scenario.scenario_id,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary_path
}

fn run_program_scenario(binary_path: &Path, scenario: &ProgramScenario, mode: &str) {
    let expected = program_expectation(scenario, mode);
    let output = Command::new(binary_path)
        .env("FRANKENLIBC_MODE", mode)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "failed to execute scenario {} ({mode}) at {}: {err}",
                scenario.scenario_id,
                binary_path.display()
            )
        });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let exit_code = output.status.code().unwrap_or_else(|| {
        panic!(
            "scenario {} ({mode}) terminated by signal",
            scenario.scenario_id
        )
    });
    assert_eq!(
        exit_code, expected.exit_code,
        "scenario {} ({mode}) exit-code mismatch\nstdout={stdout}\nstderr={stderr}",
        scenario.scenario_id
    );
    assert!(
        stdout.contains(&expected.stdout_contains),
        "scenario {} ({mode}) stdout missing expected token {:?}\nstdout={stdout}\nstderr={stderr}",
        scenario.scenario_id,
        expected.stdout_contains
    );
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
fn setjmp_nested_edges_program_scenarios_execute_with_expected_profiles() {
    let fixture = load_fixture("setjmp_nested_edges");
    let bin_dir = unique_program_bin_dir();

    for scenario in &fixture.program_scenarios {
        let binary_path = compile_program_scenario(&bin_dir, scenario);
        for mode in ["strict", "hardened"] {
            run_program_scenario(&binary_path, scenario, mode);
        }
    }
}

#[test]
fn setjmp_nested_edges_unsupported_modes_are_explicitly_documented() {
    let fixture = load_fixture("setjmp_nested_edges");

    for scenario in &fixture.unsupported_scenarios {
        assert!(
            !scenario.modes.is_empty(),
            "unsupported scenario {} must list modes",
            scenario.scenario_id
        );
        for mode in &scenario.modes {
            assert!(
                mode == "strict" || mode == "hardened",
                "unsupported scenario {} has invalid mode {}",
                scenario.scenario_id,
                mode
            );
        }
        assert_eq!(
            scenario.expected_outcome, "unsupported_deferred",
            "unsupported scenario {} should stay explicitly deferred",
            scenario.scenario_id
        );
        assert!(
            !scenario.expected_errno.is_empty(),
            "unsupported scenario {} must document expected_errno",
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
