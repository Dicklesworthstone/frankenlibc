//! Password database operations conformance test suite.
//!
//! Validates POSIX pwd.h functions: getpwnam, getpwuid, getpwent, setpwent, endpwent.
//! Run: cargo test -p frankenlibc-harness --test pwd_ops_conformance_test

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
fn pwd_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pwd_ops.json");
    assert!(path.exists(), "pwd_ops.json fixture must exist");
}

#[test]
fn pwd_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pwd_ops");
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
// Coverage validation: getpwnam
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_covers_getpwnam() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("getpwnam")).count() >= 2,
        "getpwnam needs at least 2 test cases"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: getpwuid
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_covers_getpwuid() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("getpwuid")).count() >= 2,
        "getpwuid needs at least 2 test cases"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: setpwent/endpwent
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_covers_enumeration() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|name| name.contains("setpwent") || name.contains("endpwent")),
        "Missing test coverage for setpwent/endpwent"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;

    // pwd functions typically return NULL without setting errno for "not found"
    let valid_errno_values = [0];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (pwd functions typically don't set errno)",
            case.name,
            case.expected_errno,
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;

    for case in &fixture.cases {
        assert!(
            matches!(case.mode.as_str(), "both" | "strict" | "hardened"),
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
fn pwd_ops_covers_both_modes() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "pwd_ops must have strict mode test cases");
    assert!(has_hardened, "pwd_ops must have hardened mode test cases");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;

    const EXPECTED_MIN_CASES: usize = 8;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "pwd_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("pwd_ops fixture has {} test cases", fixture.cases.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error path coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_covers_error_paths() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|n| n.contains("nonexistent")),
        "pwd_ops must test nonexistent user handling"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Root user coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_covers_root_user() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .any(|n| n.contains("root") || n.contains("zero")),
        "pwd_ops must test root user (UID 0) lookup"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pwd_ops_has_posix_references() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;

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

#[test]
fn pwd_ops_fixture_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture("pwd_ops")?;

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
