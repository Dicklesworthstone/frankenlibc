//! Backtrace operations conformance test suite.
//!
//! Validates GNU backtrace/unwinding functions: backtrace, backtrace_symbols, backtrace_symbols_fd.
//! Run: cargo test -p frankenlibc-harness --test backtrace_ops_conformance_test

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", manifest_dir.display()))?;
    let repo_root = crates_dir
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", crates_dir.display()))?;
    Ok(repo_root.to_path_buf())
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
fn backtrace_ops_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/backtrace_ops.json");
    assert!(path.exists(), "backtrace_ops.json fixture must exist");
    Ok(())
}

#[test]
fn backtrace_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "backtrace_ops");
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
    Ok(())
}

#[test]
fn backtrace_ops_covers_backtrace() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("backtrace_captures"))
            .count()
            >= 2,
        "backtrace needs at least 2 test cases (strict and hardened)"
    );
    Ok(())
}

#[test]
fn backtrace_ops_covers_backtrace_symbols() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|name| name.contains("symbols")),
        "Missing test coverage for backtrace_symbols"
    );
    Ok(())
}

#[test]
fn backtrace_ops_covers_backtrace_symbols_fd() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|name| name.contains("symbols_fd")),
        "Missing test coverage for backtrace_symbols_fd"
    );
    Ok(())
}

#[test]
fn backtrace_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
    Ok(())
}

#[test]
fn backtrace_ops_covers_both_modes() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "backtrace_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "backtrace_ops must have hardened mode test cases"
    );
    Ok(())
}

#[test]
fn backtrace_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    assert!(
        fixture.cases.len() >= 4,
        "backtrace_ops fixture has {} cases, expected at least 4",
        fixture.cases.len()
    );
    eprintln!(
        "backtrace_ops fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn backtrace_ops_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("GNU")
                || case.spec_section.contains("backtrace")
                || case.spec_section.contains("FrankenLibC"),
            "Case {} spec_section should reference GNU or FrankenLibC: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn backtrace_ops_fixture_executes_via_harness() -> Result<(), String> {
    let fixture = load_fixture("backtrace_ops")?;

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
                        "backtrace_ops case {} ({mode}) failed to execute via harness: {err}",
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
                "executor reported parity failure for {} ({mode}); host_output={}",
                case.name, result.host_output
            );
        }
    }
    Ok(())
}
