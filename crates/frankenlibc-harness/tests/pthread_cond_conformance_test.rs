//! pthread condition variable conformance test suite.
//!
//! Validates POSIX pthread_cond_* APIs: init, destroy, wait, timedwait, signal, broadcast.
//! Run: cargo test -p frankenlibc-harness --test pthread_cond_conformance_test

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
fn pthread_cond_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pthread_cond.json");
    assert!(path.exists(), "pthread_cond.json fixture must exist");
}

#[test]
fn pthread_cond_fixture_valid_schema() {
    let fixture = load_fixture("pthread_cond");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pthread/cond");
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
// Coverage validation: all pthread_cond operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_cond_covers_init() {
    let fixture = load_fixture("pthread_cond");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["init_default", "init_monotonic", "init_null", "reinit"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_cond_init pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_cond_covers_destroy() {
    let fixture = load_fixture("pthread_cond");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["destroy_idle", "destroy_with_waiters", "destroy_null"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_cond_destroy pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_cond_covers_wait() {
    let fixture = load_fixture("pthread_cond");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "wait_basic",
        "wait_null_condvar",
        "wait_null_mutex",
        "wait_mutex_mismatch",
        "wait_reacquires_mutex",
        "spurious_wakeup",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_cond_wait pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_cond_covers_timedwait() {
    let fixture = load_fixture("pthread_cond");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "timedwait_before_deadline",
        "timedwait_expired",
        "timedwait_invalid_nsec",
        "timedwait_monotonic",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_cond_timedwait pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_cond_covers_signal() {
    let fixture = load_fixture("pthread_cond");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["signal_one_waiter", "signal_no_waiters", "signal_null"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_cond_signal pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_cond_covers_broadcast() {
    let fixture = load_fixture("pthread_cond");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "broadcast_multiple_waiters",
        "broadcast_no_waiters",
        "broadcast_null",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_cond_broadcast pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_cond_error_codes_valid() {
    let fixture = load_fixture("pthread_cond");

    // Valid POSIX/Linux error codes for pthread_cond functions
    let valid_errno_values = [
        0,   // Success
        16,  // EBUSY
        22,  // EINVAL
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
fn pthread_cond_function_distribution() {
    let fixture = load_fixture("pthread_cond");

    let mut init_count = 0;
    let mut destroy_count = 0;
    let mut wait_count = 0;
    let mut timedwait_count = 0;
    let mut signal_count = 0;
    let mut broadcast_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "pthread_cond_init" => init_count += 1,
            "pthread_cond_destroy" => destroy_count += 1,
            "pthread_cond_wait" => wait_count += 1,
            "pthread_cond_timedwait" => timedwait_count += 1,
            "pthread_cond_signal" => signal_count += 1,
            "pthread_cond_broadcast" => broadcast_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure reasonable coverage for each function
    assert!(
        init_count >= 3,
        "pthread_cond_init needs more test cases (have {})",
        init_count
    );
    assert!(
        destroy_count >= 3,
        "pthread_cond_destroy needs more test cases (have {})",
        destroy_count
    );
    assert!(
        wait_count >= 4,
        "pthread_cond_wait needs more test cases (have {})",
        wait_count
    );
    assert!(
        timedwait_count >= 3,
        "pthread_cond_timedwait needs more test cases (have {})",
        timedwait_count
    );
    assert!(
        signal_count >= 3,
        "pthread_cond_signal needs more test cases (have {})",
        signal_count
    );
    assert!(
        broadcast_count >= 3,
        "pthread_cond_broadcast needs more test cases (have {})",
        broadcast_count
    );

    eprintln!(
        "pthread_cond coverage: init={}, destroy={}, wait={}, timedwait={}, signal={}, broadcast={}",
        init_count, destroy_count, wait_count, timedwait_count, signal_count, broadcast_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_cond_modes_valid() {
    let fixture = load_fixture("pthread_cond");

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
fn pthread_cond_case_count_stable() {
    let fixture = load_fixture("pthread_cond");

    // This test ensures we don't accidentally remove test cases
    // Update this count when intentionally adding/removing cases
    const EXPECTED_MIN_CASES: usize = 20;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "pthread_cond fixture has {} cases, expected at least {}. \
         If cases were intentionally removed, update EXPECTED_MIN_CASES.",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "pthread_cond fixture has {} test cases",
        fixture.cases.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_cond_has_posix_references() {
    let fixture = load_fixture("pthread_cond");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case validation: spurious wakeup and mutex reacquisition
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_cond_covers_edge_cases() {
    let fixture = load_fixture("pthread_cond");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Critical edge cases that MUST be tested
    let edge_patterns = [
        "spurious_wakeup",  // Must handle spurious wakeups
        "reacquires_mutex", // Must reacquire mutex on return
        "mutex_mismatch",   // Must detect mutex mismatch
    ];

    for pattern in edge_patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing critical edge case coverage: {}",
            pattern
        );
    }
}
