//! Directory operations conformance test suite.
//!
//! Validates POSIX directory APIs: opendir, readdir, closedir, etc.
//! Run: cargo test -p frankenlibc-harness --test dirent_ops_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", manifest_dir.display()))?;
    let workspace_dir = crate_dir
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", crate_dir.display()))?;
    Ok(workspace_dir.to_path_buf())
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

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/dirent_ops.json");
    assert!(path.exists(), "dirent_ops.json fixture must exist");
    Ok(())
}

#[test]
fn dirent_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "dirent_ops");
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
// Coverage validation: directory operations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_covers_opendir() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["opendir_root", "opendir_nonexistent"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for opendir pattern: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn dirent_ops_covers_readdir() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("readdir")),
        "Missing test coverage for readdir"
    );
    Ok(())
}

#[test]
fn dirent_ops_covers_closedir() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("closedir")),
        "Missing test coverage for closedir"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

    // Valid POSIX/Linux error codes for dirent functions
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
// Function grouping validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_function_distribution() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

    let mut opendir_count = 0;
    let mut readdir_count = 0;
    let mut closedir_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "opendir" => opendir_count += 1,
            "readdir" | "readdir_r" => readdir_count += 1,
            "closedir" => closedir_count += 1,
            "rewinddir" | "seekdir" | "telldir" | "scandir" | "fdopendir" | "dirfd" => {}
            function => return Err(format!("unexpected function in fixture: {function}")),
        }
    }

    assert!(
        opendir_count >= 2,
        "opendir needs more test cases (have {})",
        opendir_count
    );
    assert!(
        readdir_count >= 1,
        "readdir needs test cases (have {})",
        readdir_count
    );
    assert!(
        closedir_count >= 1,
        "closedir needs test cases (have {})",
        closedir_count
    );

    eprintln!(
        "dirent_ops coverage: opendir={}, readdir={}, closedir={}",
        opendir_count, readdir_count, closedir_count
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

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
fn dirent_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

    const EXPECTED_MIN_CASES: usize = 5;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "dirent_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("dirent_ops fixture has {} test cases", fixture.cases.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_covers_both_modes() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "dirent_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "dirent_ops must have hardened mode test cases"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dirent_ops_covers_error_paths() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("nonexistent")),
        "dirent_ops must test ENOENT error path"
    );
    Ok(())
}

#[test]
fn dirent_ops_fixture_cases_match_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

    for case in &fixture.cases {
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
                execute_fixture_case(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "fixture case {} ({mode}) failed to execute: {err}",
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

// ---------------------------------------------------------------------------
// Isolated harness subprocess coverage (bd-jitv)
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
fn dirent_ops_fixture_executes_with_host_parity_via_harness_matrix() -> Result<(), String> {
    let fixture = load_fixture("dirent_ops")?;

    for case in &fixture.cases {
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
                        "dirent_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;
            assert!(
                result.host_parity,
                "dirent_ops case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name, result.host_output, result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "dirent_ops case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
    Ok(())
}
