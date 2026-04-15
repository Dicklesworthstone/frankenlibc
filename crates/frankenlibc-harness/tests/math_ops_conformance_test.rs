//! Math operations conformance test suite.
//!
//! Validates C11/POSIX math.h functions: sin, cos, tan, exp, log, pow, floor, ceil, etc.
//! Run: cargo test -p frankenlibc-harness --test math_ops_conformance_test

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

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/math_ops.json");
    assert!(path.exists(), "math_ops.json fixture must exist");
}

#[test]
fn math_ops_fixture_valid_schema() {
    let fixture = load_fixture("math_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "math");
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

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: trigonometric functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_trig_basic() {
    let fixture = load_fixture("math_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["sin", "cos", "tan"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for trig function: {}",
            pattern
        );
    }
}

#[test]
fn math_ops_covers_inverse_trig() {
    let fixture = load_fixture("math_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["asin", "acos", "atan"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for inverse trig function: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: exponential and logarithmic functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_exp_log() {
    let fixture = load_fixture("math_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["exp", "log"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for exp/log function: {}",
            pattern
        );
    }
}

#[test]
fn math_ops_covers_pow() {
    let fixture = load_fixture("math_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("pow")).count() >= 2,
        "pow needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: rounding functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_rounding() {
    let fixture = load_fixture("math_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["floor", "ceil", "round"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for rounding function: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: special functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_fabs() {
    let fixture = load_fixture("math_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("fabs")).count() >= 2,
        "fabs needs at least 2 test cases"
    );
}

#[test]
fn math_ops_covers_gamma() {
    let fixture = load_fixture("math_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("gamma")),
        "Missing test coverage for gamma functions"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_error_codes_valid() {
    let fixture = load_fixture("math_ops");

    // Valid POSIX/Linux error codes for math functions
    let valid_errno_values = [
        0,  // Success
        33, // EDOM
        34, // ERANGE
    ];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (expected one of {:?})",
            case.name,
            case.expected_errno,
            valid_errno_values
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_modes_valid() {
    let fixture = load_fixture("math_ops");

    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {} (expected 'both', 'strict', or 'hardened')",
            case.name,
            case.mode
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_case_count_stable() {
    let fixture = load_fixture("math_ops");

    const EXPECTED_MIN_CASES: usize = 30;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "math_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("math_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Function distribution
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_function_distribution() {
    let fixture = load_fixture("math_ops");

    let mut trig_count = 0;
    let mut exp_log_count = 0;
    let mut rounding_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "sin" | "cos" | "tan" | "asin" | "acos" | "atan" | "atan2" => trig_count += 1,
            "exp" | "log" | "log10" | "pow" => exp_log_count += 1,
            "floor" | "ceil" | "round" | "trunc" | "fmod" => rounding_count += 1,
            "fabs" | "erf" | "tgamma" | "lgamma" => {}
            f => eprintln!("Note: unclassified math function: {}", f),
        }
    }

    assert!(
        trig_count >= 10,
        "Trig functions need more test cases (have {})",
        trig_count
    );
    assert!(
        exp_log_count >= 6,
        "Exp/log functions need more test cases (have {})",
        exp_log_count
    );
    assert!(
        rounding_count >= 4,
        "Rounding functions need more test cases (have {})",
        rounding_count
    );

    eprintln!(
        "math_ops coverage: trig={}, exp_log={}, rounding={}",
        trig_count, exp_log_count, rounding_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference C11 or POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_has_spec_references() {
    let fixture = load_fixture("math_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11") || case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference C11 or POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}
