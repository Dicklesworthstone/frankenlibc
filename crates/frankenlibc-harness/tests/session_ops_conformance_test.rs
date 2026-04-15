//! Session operations conformance test suite.
//!
//! Validates POSIX session/login functions: getlogin, getlogin_r, setsid, getsid.
//! Run: cargo test -p frankenlibc-harness --test session_ops_conformance_test

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
fn session_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/session_ops.json");
    assert!(path.exists(), "session_ops.json fixture must exist");
}

#[test]
fn session_ops_fixture_valid_schema() {
    let fixture = load_fixture("session_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "session_ops");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn session_ops_covers_getlogin() {
    let fixture = load_fixture("session_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("getlogin")).count() >= 2,
        "getlogin needs at least 2 test cases"
    );
}

#[test]
fn session_ops_covers_setsid() {
    let fixture = load_fixture("session_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|name| name.contains("setsid")),
        "Missing test coverage for setsid"
    );
}

#[test]
fn session_ops_covers_getsid() {
    let fixture = load_fixture("session_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|name| name.contains("getsid")),
        "Missing test coverage for getsid"
    );
}

#[test]
fn session_ops_modes_valid() {
    let fixture = load_fixture("session_ops");
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
fn session_ops_covers_both_modes() {
    let fixture = load_fixture("session_ops");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "session_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "session_ops must have hardened mode test cases"
    );
}

#[test]
fn session_ops_case_count_stable() {
    let fixture = load_fixture("session_ops");
    assert!(
        fixture.cases.len() >= 5,
        "session_ops fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!("session_ops fixture has {} test cases", fixture.cases.len());
}
