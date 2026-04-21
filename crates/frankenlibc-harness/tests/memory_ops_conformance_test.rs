//! Memory operations conformance test suite.
//!
//! Validates C11 memory APIs: memcpy, memmove, memset, memcmp, memchr.
//! Run: cargo test -p frankenlibc-harness --test memory_ops_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
fn memory_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/memory_ops.json");
    assert!(path.exists(), "memory_ops.json fixture must exist");
}

#[test]
fn memory_ops_fixture_valid_schema() {
    let fixture = load_fixture("memory_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "memory_ops");
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
// Coverage validation: memory operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_covers_memcpy() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["memcpy_basic", "memcpy_zero"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for memcpy pattern: {}",
            pattern
        );
    }
}

#[test]
fn memory_ops_covers_memmove() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("memmove")),
        "Missing test coverage for memmove"
    );
}

#[test]
fn memory_ops_covers_memset() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("memset")),
        "Missing test coverage for memset"
    );
}

#[test]
fn memory_ops_covers_memcmp() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["memcmp_equal", "memcmp_less", "memcmp_greater"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for memcmp pattern: {}",
            pattern
        );
    }
}

#[test]
fn memory_ops_covers_memchr() {
    let fixture = load_fixture("memory_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["memchr_found", "memchr_not_found"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for memchr pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_error_codes_valid() {
    let fixture = load_fixture("memory_ops");

    // Memory ops generally don't set errno on success
    let valid_errno_values = [0];

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
fn memory_ops_function_distribution() {
    let fixture = load_fixture("memory_ops");

    let mut memcpy_count = 0;
    let mut memmove_count = 0;
    let mut memset_count = 0;
    let mut memcmp_count = 0;
    let mut memchr_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "memcpy" => memcpy_count += 1,
            "memmove" => memmove_count += 1,
            "memset" => memset_count += 1,
            "memcmp" => memcmp_count += 1,
            "memchr" => memchr_count += 1,
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure at least basic coverage
    assert!(
        memcpy_count >= 2,
        "memcpy needs more test cases (have {})",
        memcpy_count
    );
    assert!(
        memmove_count >= 1,
        "memmove needs test cases (have {})",
        memmove_count
    );
    assert!(
        memset_count >= 2,
        "memset needs more test cases (have {})",
        memset_count
    );
    assert!(
        memcmp_count >= 2,
        "memcmp needs more test cases (have {})",
        memcmp_count
    );
    assert!(
        memchr_count >= 2,
        "memchr needs more test cases (have {})",
        memchr_count
    );

    eprintln!(
        "memory_ops coverage: memcpy={}, memmove={}, memset={}, memcmp={}, memchr={}",
        memcpy_count, memmove_count, memset_count, memcmp_count, memchr_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_modes_valid() {
    let fixture = load_fixture("memory_ops");

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
fn memory_ops_case_count_stable() {
    let fixture = load_fixture("memory_ops");

    const EXPECTED_MIN_CASES: usize = 10;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "memory_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("memory_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec reference validation: all cases reference C11 spec
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_has_c11_references() {
    let fixture = load_fixture("memory_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11") || case.spec_section.contains("7.24"),
            "Case {} spec_section should reference C11 standard: {}",
            case.name,
            case.spec_section
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn memory_ops_covers_both_modes() {
    let fixture = load_fixture("memory_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "memory_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "memory_ops must have hardened mode test cases"
    );
}

// ---------------------------------------------------------------------------
// Execution coverage (bd-rw7a)
// ---------------------------------------------------------------------------
//
// Dispatch every fixture case through both the in-process
// `frankenlibc_fixture_exec::execute_fixture_case` helper and the
// isolated `harness conformance-matrix-case` subprocess used by the
// CI conformance matrix.

#[test]
fn memory_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("memory_ops");

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

#[derive(Debug, Deserialize)]
struct MatrixCaseEnvelope {
    kind: String,
    #[serde(default)]
    run: Option<DifferentialExecution>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DifferentialExecution {
    host_output: String,
    impl_output: String,
    host_parity: bool,
}

fn execute_case_via_harness(
    function: &str,
    inputs: &serde_json::Value,
    mode: &str,
) -> Result<DifferentialExecution, String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_harness"))
        .arg("conformance-matrix-case")
        .arg("--function")
        .arg(function)
        .arg("--mode")
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn harness subprocess: {err}"))?;

    let payload =
        serde_json::to_vec(inputs).map_err(|err| format!("failed to serialize inputs: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(&payload)
            .map_err(|err| format!("failed to write subprocess stdin: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait on harness subprocess: {err}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        return Err(format!(
            "harness subprocess exited with status {:?}: {}",
            output.status.code(),
            stderr
        ));
    }

    let envelope: MatrixCaseEnvelope = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid harness subprocess payload: {err}"))?;
    match envelope.kind.as_str() {
        "ok" => envelope
            .run
            .ok_or_else(|| String::from("missing run payload from harness subprocess")),
        "error" => Err(envelope
            .error
            .unwrap_or_else(|| String::from("missing error payload from harness subprocess"))),
        other => Err(format!("unknown harness subprocess payload kind: {other}")),
    }
}

#[test]
fn memory_ops_fixture_executes_with_host_parity_via_harness_matrix() {
    let fixture = load_fixture("memory_ops");

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
            let result = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "memory_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            assert!(
                result.host_parity || result.host_output == "UB",
                "memory_ops case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name,
                result.host_output,
                result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "memory_ops case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
}
