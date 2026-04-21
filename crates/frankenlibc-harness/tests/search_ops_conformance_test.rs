//! search.h operations conformance test suite.
//!
//! Validates POSIX/XSI `<search.h>` entrypoints through the shared fixture
//! runner against host glibc parity.

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

fn load_fixture_set(name: &str) -> FixtureSet {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    FixtureSet::from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load {} as FixtureSet: {}", path.display(), e))
}

#[test]
fn search_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/search_ops.json");
    assert!(path.exists(), "search_ops.json fixture must exist");
}

#[test]
fn search_ops_fixture_valid_schema() {
    let fixture = load_fixture("search_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "search/ops");
    assert!(
        !fixture.description.is_empty(),
        "fixture should describe its scope"
    );
    assert!(
        !fixture.spec_reference.is_empty(),
        "fixture should include top-level spec reference"
    );
    assert!(!fixture.cases.is_empty(), "Must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            !case.spec_section.is_empty(),
            "Spec section must not be empty"
        );
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
}

#[test]
fn search_ops_covers_hash_tables() {
    let fixture = load_fixture("search_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for pattern in ["hcreate", "hsearch", "hdestroy", "hsearch_r"] {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing hash-table coverage for {pattern}"
        );
    }
}

#[test]
fn search_ops_covers_binary_trees() {
    let fixture = load_fixture("search_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for pattern in ["tsearch", "tfind", "tdelete", "twalk"] {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing binary-tree coverage for {pattern}"
        );
    }
}

#[test]
fn search_ops_covers_linear_search() {
    let fixture = load_fixture("search_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for pattern in ["lfind", "lsearch"] {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing linear-search coverage for {pattern}"
        );
    }
}

#[test]
fn search_ops_covers_queue_operations() {
    let fixture = load_fixture("search_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for pattern in ["insque", "remque"] {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing queue-operation coverage for {pattern}"
        );
    }
}

#[test]
fn search_ops_error_codes_valid() {
    let fixture = load_fixture("search_ops");

    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {}",
            case.name, case.expected_errno
        );
    }
}

#[test]
fn search_ops_modes_valid() {
    let fixture = load_fixture("search_ops");

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
fn search_ops_case_count_stable() {
    let fixture = load_fixture("search_ops");

    const EXPECTED_MIN_CASES: usize = 11;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "search_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );
}

#[test]
fn search_ops_has_search_spec_references() {
    let fixture = load_fixture("search_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("XSI"),
            "Case {} spec_section should reference POSIX or XSI: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn search_ops_fixture_executes_with_host_parity_in_both_modes() {
    let fixture = load_fixture_set("search_ops");

    for mode in ["strict", "hardened"] {
        let results = TestRunner::new("search_ops", mode).run(&fixture);
        assert_eq!(
            results.len(),
            fixture.cases.len(),
            "{mode} run should execute every search_ops fixture case"
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
