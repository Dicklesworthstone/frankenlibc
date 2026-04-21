//! Time operations conformance test suite.
//!
//! Validates POSIX time APIs: time, clock, clock_gettime, localtime_r.
//! Run: cargo test -p frankenlibc-harness --test time_ops_conformance_test

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

// ---------------------------------------------------------------------------
// Execution coverage (bd-qhgx)
// ---------------------------------------------------------------------------
//
// Dispatch every fixture case through both:
//   1. The in-process `frankenlibc_fixture_exec::execute_fixture_case`
//      helper (fast-path oracle).
//   2. The isolated `harness conformance-matrix-case` subprocess
//      (mirrors the CI conformance matrix's dispatch path).
//
// time_ops fixtures use placeholder expected_output strings
// ("POSITIVE_INT", "0", "-1", "NON_NEGATIVE", "TM_STRUCT") rather than
// literal wall-clock values, because time() and friends return
// non-deterministic values. The in-process executor emits matching
// placeholders when the real call succeeds.

#[test]
fn time_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("time_ops");

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
fn time_ops_fixture_executes_with_host_parity_via_harness_matrix() {
    let fixture = load_fixture("time_ops");

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
                        "time_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            assert!(
                result.host_parity || result.host_output == "UB",
                "time_ops case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name,
                result.host_output,
                result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "time_ops case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
}
