//! Pressure sensing conformance test suite.
//!
//! Validates PressureSensor regime state machine transitions.
//! Run: cargo test -p frankenlibc-harness --test pressure_sensing_conformance_test

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

fn load_fixture(name: &str) -> Result<FixtureFile, String> {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
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

fn expected_output_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

#[test]
fn pressure_sensing_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/pressure_sensing.json");
    assert!(path.exists(), "pressure_sensing.json fixture must exist");
}

#[test]
fn pressure_sensing_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pressure_sensing");
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
fn pressure_sensing_covers_nominal_regime() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("nominal")),
        "Missing test coverage for Nominal regime"
    );
    Ok(())
}

#[test]
fn pressure_sensing_covers_pressured_regime() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("pressured")),
        "Missing test coverage for Pressured regime"
    );
    Ok(())
}

#[test]
fn pressure_sensing_covers_overloaded_regime() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("overloaded")),
        "Missing test coverage for Overloaded regime"
    );
    Ok(())
}

#[test]
fn pressure_sensing_covers_recovery() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("recovery")),
        "Missing test coverage for Recovery transitions"
    );
    Ok(())
}

#[test]
fn pressure_sensing_covers_hysteresis() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("hysteresis")),
        "Missing test coverage for hysteresis behavior"
    );
    Ok(())
}

#[test]
fn pressure_sensing_has_strict_and_hardened() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    let strict_count = fixture.cases.iter().filter(|c| c.mode == "strict").count();
    let hardened_count = fixture
        .cases
        .iter()
        .filter(|c| c.mode == "hardened")
        .count();
    assert!(
        strict_count >= 1,
        "pressure_sensing needs at least 1 strict mode case"
    );
    assert!(
        hardened_count >= 1,
        "pressure_sensing needs at least 1 hardened mode case"
    );
    Ok(())
}

#[test]
fn pressure_sensing_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    for case in &fixture.cases {
        assert!(
            matches!(case.mode.as_str(), "both" | "strict" | "hardened"),
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
    Ok(())
}

#[test]
fn pressure_sensing_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    assert!(
        fixture.cases.len() >= 5,
        "pressure_sensing fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!(
        "pressure_sensing fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn pressure_sensing_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("bd-w2c3") || case.spec_section.contains("Regime"),
            "Case {} spec_section should reference bd-w2c3 or Regime: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn pressure_sensing_fixture_executes_via_harness() -> Result<(), String> {
    let fixture = load_fixture("pressure_sensing")?;

    for case in &fixture.cases {
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_case_via_harness(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "pressure_sensing case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;
            let expected_value = case.expected_output.as_ref().ok_or_else(|| {
                format!(
                    "pressure_sensing case {} is missing expected_output",
                    case.name
                )
            })?;
            let expected = expected_output_text(expected_value);
            assert_eq!(
                result.impl_output, expected,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert_eq!(
                result.host_output, "SKIP",
                "pressure_sensing executor must stay isolated from host-specific load signals"
            );
            assert!(
                result.host_parity,
                "pressure_sensing symbolic execution should mark fixture contract parity"
            );
        }
    }
    Ok(())
}
