//! stdio file operations conformance test suite.
//!
//! Validates C11/POSIX stdio.h file functions: fopen, fclose, fread, fwrite, fseek, ftell, etc.
//! Run: cargo test -p frankenlibc-harness --test stdio_file_ops_conformance_test

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

fn load_fixture(name: &str) -> Result<FixtureFile, String> {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
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
fn stdio_file_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/stdio_file_ops.json");
    assert!(path.exists(), "stdio_file_ops.json fixture must exist");
}

#[test]
fn stdio_file_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdio_file_ops");
    assert!(
        !fixture.description.is_empty(),
        "fixture should describe its scope"
    );
    assert!(
        !fixture.spec_reference.is_empty(),
        "fixture should include top-level spec reference"
    );
    assert!(!fixture.cases.is_empty(), "Must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
        assert!(
            !case.spec_section.is_empty(),
            "Case {} must include spec_section",
            case.name
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
// Coverage validation: file opening/closing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_fopen() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("fopen")).count() >= 2,
        "fopen needs at least 2 test cases"
    );
    Ok(())
}

#[test]
fn stdio_file_ops_covers_fclose() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fclose")),
        "Missing test coverage for fclose"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: read/write operations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_fread() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fread")),
        "Missing test coverage for fread"
    );
    Ok(())
}

#[test]
fn stdio_file_ops_covers_fwrite() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fwrite")),
        "Missing test coverage for fwrite"
    );
    Ok(())
}

#[test]
fn stdio_file_ops_covers_formatted_io() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|name| name.contains("printf") || name.contains("snprintf")),
        "Missing test coverage for formatted output (printf/snprintf)"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: seeking and position
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_fseek() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fseek")),
        "Missing test coverage for fseek"
    );
    Ok(())
}

#[test]
fn stdio_file_ops_covers_ftell() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("ftell")),
        "Missing test coverage for ftell"
    );
    Ok(())
}

#[test]
fn stdio_file_ops_covers_fflush() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("fflush")),
        "Missing test coverage for fflush"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;

    // Valid POSIX/Linux error codes for stdio functions
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
fn stdio_file_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;

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
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_both_modes() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(
        has_strict,
        "stdio_file_ops must have strict mode test cases"
    );
    assert!(
        has_hardened,
        "stdio_file_ops must have hardened mode test cases"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;

    const EXPECTED_MIN_CASES: usize = 12;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "stdio_file_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!(
        "stdio_file_ops fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_covers_error_paths() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|n| n.contains("invalid") || n.contains("nonexistent")),
        "stdio_file_ops must test error paths (invalid path/mode)"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stdio_file_ops_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11")
                || case.spec_section.contains("POSIX")
                || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference C11, POSIX, or GNU: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn stdio_file_ops_fixture_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture("stdio_file_ops")?;

    for case in fixture.cases {
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
                        "fixture case {} ({mode}) failed to execute through harness: {err}",
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
