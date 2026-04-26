//! Socket operations conformance test suite.
//!
//! Validates POSIX socket APIs: socket, bind, listen, accept, connect, etc.
//! Run: cargo test -p frankenlibc-harness --test socket_ops_conformance_test

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
fn socket_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/socket_ops.json");
    assert!(path.exists(), "socket_ops.json fixture must exist");
}

#[test]
fn socket_ops_fixture_valid_schema() {
    let fixture = load_fixture("socket_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "socket_ops");
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
// Coverage validation: socket operations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_socket() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["socket_tcp", "socket_udp", "socket_invalid"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for socket pattern: {}",
            pattern
        );
    }
}

#[test]
fn socket_ops_covers_bind() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("bind")),
        "Missing test coverage for bind"
    );
}

#[test]
fn socket_ops_covers_listen() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("listen")),
        "Missing test coverage for listen"
    );
}

#[test]
fn socket_ops_covers_shutdown() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("shutdown")),
        "Missing test coverage for shutdown"
    );
}

#[test]
fn socket_ops_covers_send_recv_getsockopt() {
    let fixture = load_fixture("socket_ops");
    let functions: Vec<&str> = fixture
        .cases
        .iter()
        .map(|case| case.function.as_str())
        .collect();

    for function in ["send", "recv", "getsockopt"] {
        assert!(
            functions.contains(&function),
            "Missing fixture execution coverage for {function}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_error_codes_valid() {
    let fixture = load_fixture("socket_ops");

    // Valid POSIX/Linux error codes for socket functions
    let valid_errno_values = [
        0,  // Success
        9,  // EBADF
        22, // EINVAL
        97, // EAFNOSUPPORT
        98, // EADDRINUSE
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
fn socket_ops_modes_valid() {
    let fixture = load_fixture("socket_ops");

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
fn socket_ops_case_count_stable() {
    let fixture = load_fixture("socket_ops");

    const EXPECTED_MIN_CASES: usize = 14;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "socket_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("socket_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_both_modes() {
    let fixture = load_fixture("socket_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "socket_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "socket_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_error_paths() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Must test invalid fd and invalid domain errors
    assert!(
        case_names.iter().any(|n| n.contains("invalid")),
        "socket_ops must test error paths (invalid fd/domain)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol coverage: TCP and UDP
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn socket_ops_covers_tcp_and_udp() {
    let fixture = load_fixture("socket_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("tcp")),
        "socket_ops must test TCP sockets"
    );
    assert!(
        case_names.iter().any(|n| n.contains("udp")),
        "socket_ops must test UDP sockets"
    );
}

// ---------------------------------------------------------------------------
// In-process executor coverage (bd-xejg)
// ---------------------------------------------------------------------------
//
// Dispatches every socket_ops fixture case through the shared
// `frankenlibc_fixture_exec::execute_fixture_case` entrypoint and
// asserts the impl output matches the fixture's `expected_output`.
// The socket-family executors run impl-only (host_output="SKIP",
// host_parity=true) because the RawSyscall path exercises the kernel
// directly on both sides; differential parity is already enforced by
// the kernel.

#[test]
fn socket_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("socket_ops");

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
                        "socket_ops case {} ({mode}) failed to execute: {err}",
                        case.name
                    )
                });
            assert_eq!(
                result.impl_output, expected_output,
                "socket_ops case {} ({mode}) mismatched fixture output",
                case.name
            );
            assert!(
                result.host_parity,
                "socket_ops case {} ({mode}) lost host parity: host={}, impl={}",
                case.name, result.host_output, result.impl_output
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Isolated harness subprocess coverage (bd-xejg)
// ---------------------------------------------------------------------------
//
// Each fixture case is also dispatched through the
// `harness conformance-matrix-case` subprocess that the CI conformance
// matrix uses, so packaging/dispatch regressions surface here even when
// the in-process executor still passes.

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
fn socket_ops_fixture_executes_with_host_parity_via_harness_matrix() {
    let fixture = load_fixture("socket_ops");

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
                        "socket_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            assert!(
                result.host_parity,
                "socket_ops case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name, result.host_output, result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "socket_ops case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
}
