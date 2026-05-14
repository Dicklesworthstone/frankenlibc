//! unistd operations conformance test suite.
//!
//! Validates POSIX unistd.h syscall wrappers: getpid, getuid, read, write, close, etc.
//! Run: cargo test -p frankenlibc-harness --test unistd_ops_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().ok_or_else(|| {
        format!(
            "harness manifest directory has no parent: {}",
            manifest_dir.display()
        )
    })?;
    workspace_root
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "workspace root has no repository parent: {}",
                workspace_root.display()
            )
        })
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

fn load_fixture(name: &str) -> Result<FixtureFile, String> {
    let path = repo_root()?.join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
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
fn unistd_ops_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/unistd_ops.json");
    assert!(path.exists(), "unistd_ops.json fixture must exist");
    Ok(())
}

#[test]
fn unistd_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "unistd");
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
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: unistd operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_covers_process_identity() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["getpid", "getppid"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for process identity: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn unistd_ops_covers_user_identity() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["getuid", "getgid", "geteuid", "getegid"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for user identity: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn unistd_ops_covers_file_ops() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["read", "write", "close", "lseek"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for file operation: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn unistd_ops_covers_filesystem() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["getcwd", "access"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for filesystem: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn unistd_ops_covers_terminal() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("isatty")),
        "Missing test coverage for isatty"
    );
    Ok(())
}

#[test]
fn unistd_ops_covers_pipe() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("pipe")),
        "Missing test coverage for pipe"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;

    // Valid POSIX/Linux error codes for unistd functions
    let valid_errno_values = [
        0, // Success
        2, // ENOENT
        9, // EBADF
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
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;

    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {} (expected 'both', 'strict', or 'hardened')",
            case.name,
            case.mode
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;

    const EXPECTED_MIN_CASES: usize = 15;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "unistd_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("unistd_ops fixture has {} test cases", fixture.cases.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_has_posix_references() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unistd_ops_covers_error_paths() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Must have error path tests
    let error_patterns = ["invalid", "enoent", "ebadf"];

    let has_error_tests = error_patterns
        .iter()
        .any(|p| case_names.iter().any(|n| n.to_lowercase().contains(p)));

    assert!(
        has_error_tests,
        "unistd_ops must have error path test cases"
    );
    Ok(())
}

#[test]
fn unistd_ops_fixture_cases_match_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture("unistd_ops")?;

    for case in &fixture.cases {
        if case.inputs.get("fd").map(|v| v.as_str()) == Some(Some("pipe_write_end"))
            || case.inputs.get("fd").map(|v| v.as_str()) == Some(Some("pipe_read_end"))
            || case.inputs.get("fd").map(|v| v.as_str()) == Some(Some("opened_fd"))
        {
            continue;
        }
        let expected_output = case
            .expected_output
            .as_deref()
            .ok_or_else(|| format!("case {} missing expected_output", case.name))?;
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_case_via_harness(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "unistd_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;
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
    Ok(())
}
