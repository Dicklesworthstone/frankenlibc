//! Loader edges conformance test suite.
//!
//! Validates ELF loader edge cases: dlopen, dlsym, dlclose, dladdr, dlinfo.
//! Run: cargo test -p frankenlibc-harness --test loader_edges_conformance_test

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
fn loader_edges_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/loader_edges.json");
    assert!(path.exists(), "loader_edges.json fixture must exist");
}

#[test]
fn loader_edges_fixture_valid_schema() {
    let fixture = load_fixture("loader_edges");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "loader_edges");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn loader_edges_covers_dlopen() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlopen")),
        "Missing test coverage for dlopen"
    );
}

#[test]
fn loader_edges_covers_dlsym() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlsym")),
        "Missing test coverage for dlsym"
    );
}

#[test]
fn loader_edges_covers_dlclose() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlclose")),
        "Missing test coverage for dlclose"
    );
}

#[test]
fn loader_edges_covers_dladdr() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dladdr")),
        "Missing test coverage for dladdr"
    );
}

#[test]
fn loader_edges_covers_dlinfo() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlinfo")),
        "Missing test coverage for dlinfo"
    );
}

#[test]
fn loader_edges_has_strict_and_hardened() {
    let fixture = load_fixture("loader_edges");
    let strict_count = fixture.cases.iter().filter(|c| c.mode == "strict").count();
    let hardened_count = fixture
        .cases
        .iter()
        .filter(|c| c.mode == "hardened")
        .count();
    assert!(
        strict_count >= 1,
        "loader_edges needs at least 1 strict mode case"
    );
    assert!(
        hardened_count >= 1,
        "loader_edges needs at least 1 hardened mode case"
    );
}

#[test]
fn loader_edges_modes_valid() {
    let fixture = load_fixture("loader_edges");
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
fn loader_edges_case_count_stable() {
    let fixture = load_fixture("loader_edges");
    assert!(
        fixture.cases.len() >= 5,
        "loader_edges fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!(
        "loader_edges fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn loader_edges_has_spec_references() {
    let fixture = load_fixture("loader_edges");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference POSIX or GNU: {}",
            case.name,
            case.spec_section
        );
    }
}
