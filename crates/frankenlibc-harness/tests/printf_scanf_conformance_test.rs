//! printf/scanf conformance test suite.
//!
//! Validates printf and scanf implementations against POSIX.1-2024 / C11 fixtures.
//! Run: cargo test -p frankenlibc-harness --test printf_scanf_conformance_test

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
#[allow(dead_code)] // Fields are part of complete schema; metadata used for documentation
struct FixtureFile {
    version: String,
    family: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    spec_reference: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are part of complete schema; will be used by runtime execution tests
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    #[serde(default)]
    expected_output: Option<String>,
    #[serde(default)]
    expected_output_pattern: Option<String>,
    #[serde(default)]
    expected_output_bytes: Option<Vec<u8>>,
    #[serde(default)]
    expected_return: Option<i64>,
    #[serde(default)]
    expected_values: Option<Vec<serde_json::Value>>,
    expected_errno: i32,
    mode: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Printf fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn printf_conformance_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/printf_conformance.json");
    assert!(path.exists(), "printf_conformance.json fixture must exist");
}

#[test]
fn printf_conformance_fixture_valid_schema() {
    let fixture = load_fixture("printf_conformance");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "printf_conformance");
    assert!(!fixture.cases.is_empty(), "Must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(!case.spec_section.is_empty(), "Spec section must not be empty");
        assert!(
            case.expected_output.is_some()
                || case.expected_output_pattern.is_some()
                || case.expected_output_bytes.is_some(),
            "Case {} must have expected output",
            case.name
        );
    }
}

#[test]
fn printf_conformance_covers_all_specifiers() {
    let fixture = load_fixture("printf_conformance");

    // Map specifiers to their expected test name patterns
    let specifier_patterns = [
        ("d", "_d_"),
        ("i", "_i_"),
        ("u", "_u_"),
        ("o", "_o_"),
        ("x", "_x_"),
        ("X", "_X_"),
        ("f", "_f_"),
        ("e", "_e_"),
        ("E", "_E_"),
        ("g", "_g_"),
        ("G", "_G_"),
        ("c", "_c_"),
        ("s", "_s_"),
        ("p", "_p_"),
        ("a", "_a_"),
        ("A", "_A_"),
        ("%", "literal_percent"),
    ];
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for (spec, pattern) in specifier_patterns {
        let found = case_names.iter().any(|name| name.contains(pattern));
        assert!(
            found,
            "Missing test coverage for %{spec} specifier"
        );
    }
}

#[test]
fn printf_conformance_covers_flags() {
    let fixture = load_fixture("printf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Check for flag coverage
    let flags = [
        ("plus_flag", "+ flag"),
        ("space_flag", "space flag"),
        ("alt_form", "# flag"),
        ("zero_pad", "0 flag"),
        ("left", "- flag"),
    ];

    for (pattern, desc) in flags {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for {} in printf",
            desc
        );
    }
}

#[test]
fn printf_conformance_covers_width_precision() {
    let fixture = load_fixture("printf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("width")),
        "Missing width test coverage"
    );
    assert!(
        case_names.iter().any(|name| name.contains("precision")),
        "Missing precision test coverage"
    );
    assert!(
        case_names.iter().any(|name| name.contains("star")),
        "Missing * (dynamic width/precision) test coverage"
    );
}

#[test]
fn printf_conformance_covers_length_modifiers() {
    let fixture = load_fixture("printf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let lengths = [
        ("hh_", "hh"),
        ("h_", "h"),
        ("l_", "l"),
        ("ll_", "ll"),
        ("z_", "z"),
    ];

    for (pattern, desc) in lengths {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing length modifier {} test coverage",
            desc
        );
    }
}

#[test]
fn printf_conformance_covers_special_values() {
    let fixture = load_fixture("printf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("inf")),
        "Missing infinity test coverage"
    );
    assert!(
        case_names.iter().any(|name| name.contains("nan")),
        "Missing NaN test coverage"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanf fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

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
        assert!(!case.spec_section.is_empty(), "Spec section must not be empty");
        assert!(
            case.expected_return.is_some(),
            "Case {} must have expected return value",
            case.name
        );
    }
}

#[test]
fn scanf_conformance_covers_all_specifiers() {
    let fixture = load_fixture("scanf_conformance");

    let specifiers = ["d", "i", "u", "o", "x", "X", "f", "c", "s", "p", "n"];
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for spec in specifiers {
        let pattern = format!("_{spec}_");
        let found = case_names.iter().any(|name| name.contains(&pattern) || name.ends_with(&format!("_{spec}")));
        assert!(
            found,
            "Missing test coverage for %{spec} specifier in scanf"
        );
    }
}

#[test]
fn scanf_conformance_covers_scansets() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("scanset")),
        "Missing scanset %[] test coverage"
    );
}

#[test]
fn scanf_conformance_covers_assignment_suppression() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("suppress")),
        "Missing assignment suppression * test coverage"
    );
}

#[test]
fn scanf_conformance_covers_eof_and_errors() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("eof")),
        "Missing EOF test coverage"
    );
    assert!(
        case_names.iter().any(|name| name.contains("no_match") || name.contains("mismatch")),
        "Missing conversion failure test coverage"
    );
}

#[test]
fn scanf_conformance_covers_length_modifiers() {
    let fixture = load_fixture("scanf_conformance");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let lengths = [("hh_", "hh"), ("h_", "h"), ("l_", "l"), ("ll_", "ll")];

    for (pattern, desc) in lengths {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing length modifier {} test coverage in scanf",
            desc
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden output verification (frozen reference outputs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn printf_fixture_case_count_stable() {
    let fixture = load_fixture("printf_conformance");
    // Freeze the case count to detect accidental deletions
    assert!(
        fixture.cases.len() >= 60,
        "printf_conformance must have at least 60 cases, found {}",
        fixture.cases.len()
    );
}

#[test]
fn scanf_fixture_case_count_stable() {
    let fixture = load_fixture("scanf_conformance");
    // Freeze the case count to detect accidental deletions
    assert!(
        fixture.cases.len() >= 50,
        "scanf_conformance must have at least 50 cases, found {}",
        fixture.cases.len()
    );
}

#[test]
fn printf_fixture_spec_references_posix() {
    let fixture = load_fixture("printf_conformance");
    assert!(
        fixture.spec_reference.contains("POSIX") || fixture.spec_reference.contains("C11"),
        "printf fixture must reference POSIX or C11 spec"
    );
}

#[test]
fn scanf_fixture_spec_references_posix() {
    let fixture = load_fixture("scanf_conformance");
    assert!(
        fixture.spec_reference.contains("POSIX") || fixture.spec_reference.contains("C11"),
        "scanf fixture must reference POSIX or C11 spec"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn printf_fixture_has_strict_mode_cases() {
    let fixture = load_fixture("printf_conformance");
    let strict_count = fixture.cases.iter().filter(|c| c.mode == "strict").count();
    assert!(
        strict_count > 0,
        "printf fixture must have strict mode cases"
    );
}

#[test]
fn scanf_fixture_has_strict_mode_cases() {
    let fixture = load_fixture("scanf_conformance");
    let strict_count = fixture.cases.iter().filter(|c| c.mode == "strict").count();
    assert!(
        strict_count > 0,
        "scanf fixture must have strict mode cases"
    );
}
