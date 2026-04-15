//! pthread thread lifecycle conformance test suite.
//!
//! Validates POSIX pthread thread APIs: create, join, detach, self, equal.
//! Run: cargo test -p frankenlibc-harness --test pthread_thread_conformance_test

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
fn pthread_thread_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pthread_thread.json");
    assert!(path.exists(), "pthread_thread.json fixture must exist");
}

#[test]
fn pthread_thread_fixture_valid_schema() {
    let fixture = load_fixture("pthread_thread");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pthread/thread");
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
// Coverage validation: all pthread thread operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_thread_covers_create() {
    let fixture = load_fixture("pthread_thread");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["pthread_create_basic", "pthread_create_multiple"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_create pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_thread_covers_join() {
    let fixture = load_fixture("pthread_thread");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "pthread_join_returns",
        "pthread_join_null",
        "pthread_join_self",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_join pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_thread_covers_detach() {
    let fixture = load_fixture("pthread_thread");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = [
        "pthread_detach_running",
        "pthread_detach_null",
        "pthread_detach_finished",
    ];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_detach pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_thread_covers_self() {
    let fixture = load_fixture("pthread_thread");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["pthread_self"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_self pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_thread_covers_equal() {
    let fixture = load_fixture("pthread_thread");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["pthread_equal_same", "pthread_equal_different"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_equal pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_thread_error_codes_valid() {
    let fixture = load_fixture("pthread_thread");

    // Valid POSIX/Linux error codes for pthread thread functions
    let valid_errno_values = [
        0,  // Success
        3,  // ESRCH
        22, // EINVAL
        35, // EDEADLK
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
fn pthread_thread_function_distribution() {
    let fixture = load_fixture("pthread_thread");

    let mut create_count = 0;
    let mut join_count = 0;
    let mut detach_count = 0;
    let mut self_count = 0;
    let mut equal_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "pthread_create" => create_count += 1,
            "pthread_join" => join_count += 1,
            "pthread_detach" => detach_count += 1,
            "pthread_self" => self_count += 1,
            "pthread_equal" => equal_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure reasonable coverage for each function
    assert!(
        create_count >= 2,
        "pthread_create needs more test cases (have {})",
        create_count
    );
    assert!(
        join_count >= 3,
        "pthread_join needs more test cases (have {})",
        join_count
    );
    assert!(
        detach_count >= 2,
        "pthread_detach needs more test cases (have {})",
        detach_count
    );
    assert!(
        self_count >= 1,
        "pthread_self needs test cases (have {})",
        self_count
    );
    assert!(
        equal_count >= 2,
        "pthread_equal needs more test cases (have {})",
        equal_count
    );

    eprintln!(
        "pthread_thread coverage: create={}, join={}, detach={}, self={}, equal={}",
        create_count, join_count, detach_count, self_count, equal_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_thread_modes_valid() {
    let fixture = load_fixture("pthread_thread");

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
fn pthread_thread_case_count_stable() {
    let fixture = load_fixture("pthread_thread");

    // This test ensures we don't accidentally remove test cases
    // Update this count when intentionally adding/removing cases
    const EXPECTED_MIN_CASES: usize = 10;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "pthread_thread fixture has {} cases, expected at least {}. \
         If cases were intentionally removed, update EXPECTED_MIN_CASES.",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "pthread_thread fixture has {} test cases",
        fixture.cases.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_thread_has_posix_references() {
    let fixture = load_fixture("pthread_thread");

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
// Edge case validation: deadlock detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_thread_covers_deadlock_detection() {
    let fixture = load_fixture("pthread_thread");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Thread must detect joining itself (deadlock)
    assert!(
        case_names.iter().any(|name| name.contains("join_self")),
        "Missing critical edge case: pthread_join self-join deadlock detection"
    );
}
