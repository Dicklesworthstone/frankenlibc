//! Wide memory conformance test suite.
//!
//! Validates ISO C wide memory functions: wmemcpy, wmemmove, wmemset, wmemcmp, wmemchr.
//! Run: cargo test -p frankenlibc-harness --test wide_memory_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
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
fn wide_memory_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/wide_memory.json");
    assert!(path.exists(), "wide_memory.json fixture must exist");
}

#[test]
fn wide_memory_fixture_valid_schema() {
    let fixture = load_fixture("wide_memory");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/wide_memory");
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
fn wide_memory_covers_wmemcpy() {
    let fixture = load_fixture("wide_memory");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wmemcpy")),
        "Missing test coverage for wmemcpy"
    );
}

#[test]
fn wide_memory_covers_wmemmove() {
    let fixture = load_fixture("wide_memory");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wmemmove")),
        "Missing test coverage for wmemmove"
    );
}

#[test]
fn wide_memory_covers_wmemset() {
    let fixture = load_fixture("wide_memory");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wmemset")),
        "Missing test coverage for wmemset"
    );
}

#[test]
fn wide_memory_covers_wmemcmp() {
    let fixture = load_fixture("wide_memory");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wmemcmp")).count() >= 2,
        "wmemcmp needs at least 2 test cases"
    );
}

#[test]
fn wide_memory_covers_wmemchr() {
    let fixture = load_fixture("wide_memory");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wmemchr")),
        "Missing test coverage for wmemchr"
    );
}

#[test]
fn wide_memory_modes_valid() {
    let fixture = load_fixture("wide_memory");
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
fn wide_memory_case_count_stable() {
    let fixture = load_fixture("wide_memory");
    assert!(
        fixture.cases.len() >= 5,
        "wide_memory fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!("wide_memory fixture has {} test cases", fixture.cases.len());
}

#[test]
fn wide_memory_has_spec_references() {
    let fixture = load_fixture("wide_memory");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("ISO C"),
            "Case {} spec_section should reference ISO C: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn wide_memory_error_codes_valid() {
    let fixture = load_fixture("wide_memory");

    // Wide memory functions don't set errno
    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {} (wide memory functions don't set errno)",
            case.name, case.expected_errno
        );
    }
}

#[test]
fn wide_memory_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("wide_memory");

    for case in &fixture.cases {
        let expected_output = case
            .expected_output
            .as_deref()
            .unwrap_or_else(|| panic!("case {} missing expected_output", case.name));
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_fixture_case(&case.function, &case.inputs, mode).unwrap_or_else(|err| {
                    panic!(
                        "fixture case {} ({mode}) failed to execute: {err}",
                        case.name
                    )
                });
            assert_eq!(
                result.impl_output, expected_output,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity || result.host_output == "UB",
                "defined host behavior diverged for {} ({mode}): host={}, impl={}",
                case.name,
                result.host_output,
                result.impl_output
            );
        }
    }
}
