//! Time operations conformance test suite.
//!
//! Validates POSIX time APIs: time, clock, clock_gettime, localtime_r.
//! Run: cargo test -p frankenlibc-harness --test time_ops_conformance_test

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
fn time_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/time_ops.json");
    assert!(path.exists(), "time_ops.json fixture must exist");
}

#[test]
fn time_ops_fixture_valid_schema() {
    let fixture = load_fixture("time_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "time_ops");
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
// Coverage validation: time operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn time_ops_covers_time() {
    let fixture = load_fixture("time_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("time_returns")),
        "Missing test coverage for time()"
    );
}

#[test]
fn time_ops_covers_clock_gettime() {
    let fixture = load_fixture("time_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "clock_gettime_realtime",
        "clock_gettime_monotonic",
        "clock_gettime_invalid",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for clock_gettime pattern: {}",
            pattern
        );
    }
}

#[test]
fn time_ops_covers_clock() {
    let fixture = load_fixture("time_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("clock_returns")),
        "Missing test coverage for clock()"
    );
}

#[test]
fn time_ops_covers_localtime() {
    let fixture = load_fixture("time_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("localtime")),
        "Missing test coverage for localtime_r"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn time_ops_error_codes_valid() {
    let fixture = load_fixture("time_ops");

    // Valid POSIX/Linux error codes for time functions
    let valid_errno_values = [
        0,  // Success
        14, // EFAULT
        22, // EINVAL
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
// Function grouping validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn time_ops_function_distribution() {
    let fixture = load_fixture("time_ops");

    let mut time_count = 0;
    let mut clock_count = 0;
    let mut clock_gettime_count = 0;
    let mut localtime_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "time" => time_count += 1,
            "clock" => clock_count += 1,
            "clock_gettime" => clock_gettime_count += 1,
            "localtime_r" => localtime_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure at least basic coverage
    assert!(
        time_count >= 1,
        "time needs test cases (have {})",
        time_count
    );
    assert!(
        clock_count >= 1,
        "clock needs test cases (have {})",
        clock_count
    );
    assert!(
        clock_gettime_count >= 3,
        "clock_gettime needs more test cases (have {})",
        clock_gettime_count
    );
    assert!(
        localtime_count >= 1,
        "localtime_r needs test cases (have {})",
        localtime_count
    );

    eprintln!(
        "time_ops coverage: time={}, clock={}, clock_gettime={}, localtime_r={}",
        time_count, clock_count, clock_gettime_count, localtime_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn time_ops_modes_valid() {
    let fixture = load_fixture("time_ops");

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
fn time_ops_case_count_stable() {
    let fixture = load_fixture("time_ops");

    const EXPECTED_MIN_CASES: usize = 6;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "time_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("time_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Clock ID coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn time_ops_covers_clock_ids() {
    let fixture = load_fixture("time_ops");

    // Check that we test both CLOCK_REALTIME and CLOCK_MONOTONIC
    let has_realtime = fixture.cases.iter().any(|c| {
        c.name.contains("realtime") || c.inputs.get("clk_id") == Some(&serde_json::json!(0))
    });
    let has_monotonic = fixture.cases.iter().any(|c| {
        c.name.contains("monotonic") || c.inputs.get("clk_id") == Some(&serde_json::json!(1))
    });

    assert!(has_realtime, "Must test CLOCK_REALTIME (clk_id 0)");
    assert!(has_monotonic, "Must test CLOCK_MONOTONIC (clk_id 1)");
}
