//! Signal operations conformance test suite.
//!
//! Validates POSIX/System V signal APIs: kill, raise, sigaction, ssignal, gsignal.
//! Run: cargo test -p frankenlibc-harness --test signal_ops_conformance_test

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
    impl_output: String,
    #[allow(dead_code)]
    host_output: String,
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

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signal_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/signal_ops.json");
    assert!(path.exists(), "signal_ops.json fixture must exist");
}

#[test]
fn signal_ops_fixture_valid_schema() {
    let fixture = load_fixture("signal_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "signal_ops");
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
// Coverage validation: signal operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signal_ops_covers_raise() {
    let fixture = load_fixture("signal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("raise")),
        "Missing test coverage for raise"
    );
}

#[test]
fn signal_ops_covers_kill() {
    let fixture = load_fixture("signal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["kill_self", "kill_invalid"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for kill pattern: {}",
            pattern
        );
    }
}

#[test]
fn signal_ops_covers_sigaction() {
    let fixture = load_fixture("signal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("sigaction")),
        "Missing test coverage for sigaction"
    );
}

#[test]
fn signal_ops_covers_signal() {
    let fixture = load_fixture("signal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for pattern in ["signal_install", "signal_invalid"] {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for signal pattern: {}",
            pattern
        );
    }
}

#[test]
fn signal_ops_covers_legacy_sysv_signals() {
    let fixture = load_fixture("signal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    for pattern in ["ssignal", "gsignal"] {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for legacy signal pattern: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signal_ops_error_codes_valid() {
    let fixture = load_fixture("signal_ops");

    // Valid POSIX/Linux error codes for signal functions
    let valid_errno_values = [
        0,  // Success
        1,  // EPERM
        3,  // ESRCH
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
fn signal_ops_function_distribution() {
    let fixture = load_fixture("signal_ops");

    let mut raise_count = 0;
    let mut ssignal_count = 0;
    let mut gsignal_count = 0;
    let mut kill_count = 0;
    let mut sigaction_count = 0;
    let mut signal_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "raise" => raise_count += 1,
            "ssignal" => ssignal_count += 1,
            "gsignal" => gsignal_count += 1,
            "kill" => kill_count += 1,
            "sigaction" => sigaction_count += 1,
            "signal" => signal_count += 1,
            "sigemptyset" | "sigfillset" | "sigaddset" | "sigdelset" | "sigismember" => {}
            f => panic!("Unexpected function in fixture: {}", f),
        }
    }

    // Ensure at least basic coverage
    assert!(
        raise_count >= 1,
        "raise needs test cases (have {})",
        raise_count
    );
    assert!(
        ssignal_count >= 2,
        "ssignal needs test cases (have {})",
        ssignal_count
    );
    assert!(
        gsignal_count >= 2,
        "gsignal needs test cases (have {})",
        gsignal_count
    );
    assert!(
        kill_count >= 2,
        "kill needs test cases (have {})",
        kill_count
    );
    assert!(
        sigaction_count >= 1,
        "sigaction needs test cases (have {})",
        sigaction_count
    );
    assert!(
        signal_count >= 2,
        "signal needs test cases (have {})",
        signal_count
    );

    eprintln!(
        "signal_ops coverage: raise={}, ssignal={}, gsignal={}, kill={}, sigaction={}, signal={}",
        raise_count, ssignal_count, gsignal_count, kill_count, sigaction_count, signal_count
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signal_ops_modes_valid() {
    let fixture = load_fixture("signal_ops");

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
fn signal_ops_case_count_stable() {
    let fixture = load_fixture("signal_ops");

    const EXPECTED_MIN_CASES: usize = 5;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "signal_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("signal_ops fixture has {} test cases", fixture.cases.len());
}

#[test]
fn signal_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("signal_ops");

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
                        "signal_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            assert_eq!(
                result.impl_output, expected_output,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity,
                "executor reported parity failure for {} ({mode})",
                case.name
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signal_ops_covers_both_modes() {
    let fixture = load_fixture("signal_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "signal_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "signal_ops must have hardened mode test cases"
    );
}
