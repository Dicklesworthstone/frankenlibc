//! Regex/glob operations conformance test suite.
//!
//! Validates POSIX pattern matching and shell expansion functions:
//! regcomp, regexec, fnmatch, glob, wordexp.
//! Run: cargo test -p frankenlibc-harness --test regex_glob_ops_conformance_test

use frankenlibc_harness::{FixtureSet, TestRunner};
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

fn load_fixture_set(name: &str) -> FixtureSet {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    FixtureSet::from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load {} as FixtureSet: {}", path.display(), e))
}

fn mode_matches(active_mode: &str, case_mode: &str) -> bool {
    case_mode == active_mode || case_mode == "both"
}

#[test]
fn regex_glob_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/regex_glob_ops.json");
    assert!(path.exists(), "regex_glob_ops.json fixture must exist");
}

#[test]
fn regex_glob_ops_fixture_valid_schema() {
    let fixture = load_fixture("regex_glob_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "regex_glob_ops");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn regex_glob_ops_covers_regcomp() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("regcomp")),
        "Missing test coverage for regcomp"
    );
}

#[test]
fn regex_glob_ops_covers_regexec() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("regexec")).count() >= 2,
        "regexec needs at least 2 test cases (match and nomatch)"
    );
}

#[test]
fn regex_glob_ops_covers_fnmatch() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("fnmatch")).count() >= 2,
        "fnmatch needs at least 2 test cases"
    );
}

#[test]
fn regex_glob_ops_covers_glob() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("glob")),
        "Missing test coverage for glob"
    );
}

#[test]
fn regex_glob_ops_covers_wordexp() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wordexp")).count() >= 3,
        "wordexp needs at least 3 host-parity cases"
    );
}

#[test]
fn regex_glob_ops_modes_valid() {
    let fixture = load_fixture("regex_glob_ops");
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
fn regex_glob_ops_covers_both_modes() {
    let fixture = load_fixture("regex_glob_ops");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(
        has_strict,
        "regex_glob_ops must have strict mode test cases"
    );
    assert!(
        has_hardened,
        "regex_glob_ops must have hardened mode test cases"
    );
}

#[test]
fn regex_glob_ops_case_count_stable() {
    let fixture = load_fixture("regex_glob_ops");
    assert!(
        fixture.cases.len() >= 9,
        "regex_glob_ops fixture has {} cases, expected at least 9",
        fixture.cases.len()
    );
    eprintln!(
        "regex_glob_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn regex_glob_ops_fixture_executes_with_host_parity_in_both_modes() {
    let fixture = load_fixture_set("regex_glob_ops");

    for mode in ["strict", "hardened"] {
        let results = TestRunner::new("regex_glob_ops", mode).run(&fixture);
        let expected_cases = fixture
            .cases
            .iter()
            .filter(|case| mode_matches(mode, &case.mode))
            .count();
        assert_eq!(
            results.len(),
            expected_cases,
            "{mode} run should execute every regex_glob_ops fixture case"
        );

        for result in results {
            assert!(
                result.passed,
                "{mode} case {} failed: expected={}, actual={}, diff={:?}",
                result.case_name, result.expected, result.actual, result.diff
            );
            assert!(
                result.diff.is_none(),
                "{mode} case {} lost host parity or emitted notes: {:?}",
                result.case_name,
                result.diff
            );
        }
    }
}
