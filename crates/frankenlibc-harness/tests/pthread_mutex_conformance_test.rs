//! pthread mutex conformance test suite.
//!
//! Validates POSIX pthread_mutex_* APIs: init, destroy, lock, trylock, unlock.
//! Run: cargo test -p frankenlibc-harness --test pthread_mutex_conformance_test

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
fn pthread_mutex_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pthread_mutex.json");
    assert!(path.exists(), "pthread_mutex.json fixture must exist");
}

#[test]
fn pthread_mutex_fixture_valid_schema() {
    let fixture = load_fixture("pthread_mutex");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pthread/mutex");
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
// Coverage validation: all pthread_mutex operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_mutex_covers_init() {
    let fixture = load_fixture("pthread_mutex");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["mutex_init"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_mutex_init pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_mutex_covers_lock() {
    let fixture = load_fixture("pthread_mutex");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["mutex_lock"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_mutex_lock pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_mutex_covers_trylock() {
    let fixture = load_fixture("pthread_mutex");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["mutex_trylock_unlocked", "mutex_trylock_locked"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_mutex_trylock pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_mutex_covers_unlock() {
    let fixture = load_fixture("pthread_mutex");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["mutex_unlock"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_mutex_unlock pattern: {}",
            pattern
        );
    }
}

#[test]
fn pthread_mutex_covers_destroy() {
    let fixture = load_fixture("pthread_mutex");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["mutex_destroy"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for pthread_mutex_destroy pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_mutex_error_codes_valid() {
    let fixture = load_fixture("pthread_mutex");

    // Valid POSIX/Linux error codes for pthread_mutex functions
    let valid_errno_values = [
        0,  // Success
        16, // EBUSY
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
fn pthread_mutex_function_distribution() {
    let fixture = load_fixture("pthread_mutex");

    let mut init_count = 0;
    let mut lock_count = 0;
    let mut trylock_count = 0;
    let mut unlock_count = 0;
    let mut destroy_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "pthread_mutex_init" => init_count += 1,
            "pthread_mutex_lock" => lock_count += 1,
            "pthread_mutex_trylock" => trylock_count += 1,
            "pthread_mutex_unlock" => unlock_count += 1,
            "pthread_mutex_destroy" => destroy_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure at least basic coverage for each function
    assert!(
        init_count >= 1,
        "pthread_mutex_init needs test cases (have {})",
        init_count
    );
    assert!(
        lock_count >= 1,
        "pthread_mutex_lock needs test cases (have {})",
        lock_count
    );
    assert!(
        trylock_count >= 2,
        "pthread_mutex_trylock needs more test cases (have {})",
        trylock_count
    );
    assert!(
        unlock_count >= 1,
        "pthread_mutex_unlock needs test cases (have {})",
        unlock_count
    );
    assert!(
        destroy_count >= 1,
        "pthread_mutex_destroy needs test cases (have {})",
        destroy_count
    );

    eprintln!(
        "pthread_mutex coverage: init={}, lock={}, trylock={}, unlock={}, destroy={}",
        init_count, lock_count, trylock_count, unlock_count, destroy_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_mutex_modes_valid() {
    let fixture = load_fixture("pthread_mutex");

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
fn pthread_mutex_case_count_stable() {
    let fixture = load_fixture("pthread_mutex");

    // This test ensures we don't accidentally remove test cases
    // Update this count when intentionally adding/removing cases
    const EXPECTED_MIN_CASES: usize = 6;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "pthread_mutex fixture has {} cases, expected at least {}. \
         If cases were intentionally removed, update EXPECTED_MIN_CASES.",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "pthread_mutex fixture has {} test cases",
        fixture.cases.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pthread_mutex_has_posix_references() {
    let fixture = load_fixture("pthread_mutex");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}
