//! System V IPC operations conformance test suite.
//!
//! Validates POSIX System V IPC functions: semget, semop, semctl, shmget, shmat, shmdt, msgget.
//! Run: cargo test -p frankenlibc-harness --test sysv_ipc_ops_conformance_test

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
    expected_output: Option<serde_json::Value>,
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

fn expected_output_text(case: &FixtureCase) -> String {
    match case
        .expected_output
        .as_ref()
        .unwrap_or_else(|| panic!("case {} missing expected_output", case.name))
    {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        other => panic!(
            "case {} has unsupported expected_output value: {}",
            case.name, other
        ),
    }
}

#[test]
fn sysv_ipc_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/sysv_ipc_ops.json");
    assert!(path.exists(), "sysv_ipc_ops.json fixture must exist");
}

#[test]
fn sysv_ipc_ops_fixture_valid_schema() {
    let fixture = load_fixture("sysv_ipc_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "sysv_ipc_ops");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }
}

#[test]
fn sysv_ipc_ops_covers_semaphores() {
    let fixture = load_fixture("sysv_ipc_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("semget")),
        "Missing test coverage for semget"
    );
    assert!(
        case_names.iter().any(|n| n.contains("semop")),
        "Missing test coverage for semop"
    );
    assert!(
        case_names.iter().any(|n| n.contains("semctl")),
        "Missing test coverage for semctl"
    );
}

#[test]
fn sysv_ipc_ops_covers_shared_memory() {
    let fixture = load_fixture("sysv_ipc_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("shmget")),
        "Missing test coverage for shmget"
    );
    assert!(
        case_names.iter().any(|n| n.contains("shmat")),
        "Missing test coverage for shmat"
    );
    assert!(
        case_names.iter().any(|n| n.contains("shmdt")),
        "Missing test coverage for shmdt"
    );
}

#[test]
fn sysv_ipc_ops_covers_message_queues() {
    let fixture = load_fixture("sysv_ipc_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("msgget")),
        "Missing test coverage for msgget"
    );
}

#[test]
fn sysv_ipc_ops_modes_valid() {
    let fixture = load_fixture("sysv_ipc_ops");
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
}

#[test]
fn sysv_ipc_ops_covers_both_modes() {
    let fixture = load_fixture("sysv_ipc_ops");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "sysv_ipc_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "sysv_ipc_ops must have hardened mode test cases"
    );
}

#[test]
fn sysv_ipc_ops_case_count_stable() {
    let fixture = load_fixture("sysv_ipc_ops");
    assert!(
        fixture.cases.len() >= 7,
        "sysv_ipc_ops fixture has {} cases, expected at least 7",
        fixture.cases.len()
    );
    eprintln!(
        "sysv_ipc_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn sysv_ipc_ops_has_posix_references() {
    let fixture = load_fixture("sysv_ipc_ops");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn sysv_ipc_ops_error_codes_valid() {
    let fixture = load_fixture("sysv_ipc_ops");

    // Valid error codes for System V IPC operations
    let valid_errno_values = [
        0,  // Success
        11, // EAGAIN (semop with IPC_NOWAIT)
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

#[test]
fn sysv_ipc_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("sysv_ipc_ops");

    for case in &fixture.cases {
        let expected_output = expected_output_text(case);
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "sysv_ipc_ops case {} ({mode}) failed to execute via harness: {err}",
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
