//! C23 stdbit.h operation conformance test suite.
//!
//! Validates executable fixture coverage for representative unsigned integer bit operations.
//! Run: cargo test -p frankenlibc-harness --test stdbit_ops_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

fn load_fixture() -> Result<FixtureFile, String> {
    let path = repo_root().join("tests/conformance/fixtures/stdbit_ops.json");
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

#[test]
fn stdbit_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/stdbit_ops.json");
    assert!(path.exists(), "stdbit_ops.json fixture must exist");
}

#[test]
fn stdbit_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture()?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "stdbit/ops");
    assert!(
        !fixture.description.is_empty(),
        "fixture should describe its scope"
    );
    assert!(
        fixture.spec_reference.contains("C23"),
        "fixture should cite the C23 stdbit contract"
    );
    assert!(!fixture.cases.is_empty(), "fixture must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.function.is_empty(), "function must not be empty");
        assert!(
            case.function.starts_with("stdc_"),
            "case {} should target a stdbit function",
            case.name
        );
        assert!(
            case.spec_section.contains("C23"),
            "case {} spec_section should reference C23: {}",
            case.name,
            case.spec_section
        );
        assert!(
            case.expected_output.is_some(),
            "case {} must have expected_output",
            case.name
        );
        assert_eq!(case.expected_errno, 0, "stdbit cases do not set errno");
        assert_eq!(case.mode, "both", "stdbit cases should run in both modes");
    }

    Ok(())
}

#[test]
fn stdbit_ops_covers_unsigned_integer_operations() -> Result<(), String> {
    let fixture = load_fixture()?;
    let functions: BTreeSet<&str> = fixture
        .cases
        .iter()
        .map(|case| case.function.as_str())
        .collect();
    let operations = [
        "leading_zeros",
        "leading_ones",
        "trailing_zeros",
        "trailing_ones",
        "first_leading_zero",
        "first_leading_one",
        "first_trailing_zero",
        "first_trailing_one",
        "count_ones",
        "count_zeros",
        "has_single_bit",
        "bit_width",
        "bit_floor",
        "bit_ceil",
    ];
    let suffixes = ["uc", "us", "ui", "ul", "ull"];

    for suffix in suffixes {
        for operation in operations {
            let function = format!("stdc_{operation}_{suffix}");
            assert!(
                functions.contains(function.as_str()),
                "missing stdbit fixture coverage for {function}"
            );
        }
    }

    Ok(())
}

#[test]
fn stdbit_ops_fixture_cases_match_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture()?;

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
                "stdbit fixture should be internally parity-classified for {} ({mode})",
                case.name
            );
        }
    }

    Ok(())
}

#[test]
fn stdbit_ops_fixture_cases_match_harness_matrix_execution() -> Result<(), String> {
    let fixture = load_fixture()?;

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
                        "fixture case {} ({mode}) failed harness matrix execution: {err}",
                        case.name
                    )
                })?;
            assert_eq!(
                result.impl_output, expected_output,
                "fixture expected_output mismatch through harness matrix for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity,
                "stdbit fixture should be parity-classified through harness matrix for {} ({mode})",
                case.name
            );
        }
    }

    Ok(())
}
