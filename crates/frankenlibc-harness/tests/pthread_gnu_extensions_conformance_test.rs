//! pthread GNU extensions conformance test suite.
//!
//! Validates GNU pthread extensions: pthread_cond_clockwait, pthread_timedjoin_np,
//! pthread_tryjoin_np, pthread_clockjoin_np, pthread_getattr_np.
//! Run: cargo test -p frankenlibc-harness --test pthread_gnu_extensions_conformance_test

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
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    notes: String,
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
fn pthread_gnu_extensions_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pthread_gnu_extensions.json");
    assert!(
        path.exists(),
        "pthread_gnu_extensions.json fixture must exist"
    );
}

#[test]
fn pthread_gnu_extensions_fixture_valid_schema() {
    let fixture = load_fixture("pthread_gnu_extensions");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pthread/gnu_extensions");
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
// Coverage validation: all GNU pthread extensions have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_gnu_extensions_covers_clockwait() {
    let fixture = load_fixture("pthread_gnu_extensions");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // pthread_cond_clockwait cases
    let clockwait_patterns = [
        "clockwait_realtime",
        "clockwait_monotonic",
        "clockwait_timeout",
        "clockwait_null",
        "clockwait_invalid",
    ];

    for pattern in clockwait_patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_cond_clockwait pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_gnu_extensions_covers_timedjoin() {
    let fixture = load_fixture("pthread_gnu_extensions");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // pthread_timedjoin_np cases
    let patterns = [
        "timedjoin_before_exit",
        "timedjoin_timeout",
        "timedjoin_null_abstime",
        "timedjoin_detached",
        "timedjoin_invalid",
        "timedjoin_self",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_timedjoin_np pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_gnu_extensions_covers_tryjoin() {
    let fixture = load_fixture("pthread_gnu_extensions");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // pthread_tryjoin_np cases
    let patterns = [
        "tryjoin_finished",
        "tryjoin_running",
        "tryjoin_detached",
        "tryjoin_invalid",
        "tryjoin_self",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_tryjoin_np pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_gnu_extensions_covers_clockjoin() {
    let fixture = load_fixture("pthread_gnu_extensions");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // pthread_clockjoin_np cases
    let patterns = [
        "clockjoin_realtime",
        "clockjoin_monotonic",
        "clockjoin_timeout",
        "clockjoin_null_abstime",
        "clockjoin_detached",
        "clockjoin_self",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_clockjoin_np pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_gnu_extensions_covers_getattr_np() {
    let fixture = load_fixture("pthread_gnu_extensions");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // pthread_getattr_np cases
    let patterns = [
        "getattr_np_self",
        "getattr_np_other",
        "getattr_np_null",
        "getattr_np_detach",
        "getattr_np_stack",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_getattr_np pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_gnu_extensions_error_codes_valid() {
    let fixture = load_fixture("pthread_gnu_extensions");

    // Valid POSIX/Linux error codes that should appear
    let valid_errno_values = [
        0,   // Success
        3,   // ESRCH
        16,  // EBUSY
        22,  // EINVAL
        35,  // EDEADLK
        110, // ETIMEDOUT
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
fn pthread_gnu_extensions_function_distribution() {
    let fixture = load_fixture("pthread_gnu_extensions");

    let mut clockwait_count = 0;
    let mut timedjoin_count = 0;
    let mut tryjoin_count = 0;
    let mut clockjoin_count = 0;
    let mut getattr_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "pthread_cond_clockwait" => clockwait_count += 1,
            "pthread_timedjoin_np" => timedjoin_count += 1,
            "pthread_tryjoin_np" => tryjoin_count += 1,
            "pthread_clockjoin_np" => clockjoin_count += 1,
            "pthread_getattr_np" => getattr_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure reasonable coverage for each function
    assert!(
        clockwait_count >= 5,
        "pthread_cond_clockwait needs more test cases (have {})",
        clockwait_count
    );
    assert!(
        timedjoin_count >= 5,
        "pthread_timedjoin_np needs more test cases (have {})",
        timedjoin_count
    );
    assert!(
        tryjoin_count >= 4,
        "pthread_tryjoin_np needs more test cases (have {})",
        tryjoin_count
    );
    assert!(
        clockjoin_count >= 5,
        "pthread_clockjoin_np needs more test cases (have {})",
        clockjoin_count
    );
    assert!(
        getattr_count >= 4,
        "pthread_getattr_np needs more test cases (have {})",
        getattr_count
    );

    eprintln!(
        "pthread GNU extensions coverage: clockwait={}, timedjoin={}, tryjoin={}, clockjoin={}, getattr={}",
        clockwait_count, timedjoin_count, tryjoin_count, clockjoin_count, getattr_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_gnu_extensions_modes_valid() {
    let fixture = load_fixture("pthread_gnu_extensions");

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
fn pthread_gnu_extensions_case_count_stable() {
    let fixture = load_fixture("pthread_gnu_extensions");

    // This test ensures we don't accidentally remove test cases
    // Update this count when intentionally adding/removing cases
    const EXPECTED_MIN_CASES: usize = 30;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "pthread_gnu_extensions fixture has {} cases, expected at least {}. \
         If cases were intentionally removed, update EXPECTED_MIN_CASES.",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "pthread_gnu_extensions fixture has {} test cases",
        fixture.cases.len()
    );
}
