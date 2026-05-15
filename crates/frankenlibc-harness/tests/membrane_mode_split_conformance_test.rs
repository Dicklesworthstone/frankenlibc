//! Membrane mode split conformance test suite.
//!
//! Validates strict/hardened mode behavior divergence for TSM memory safety.
//! Run: cargo test -p frankenlibc-harness --test membrane_mode_split_conformance_test

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
fn membrane_mode_split_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/membrane_mode_split.json");
    assert!(path.exists(), "membrane_mode_split.json fixture must exist");
    Ok(())
}

#[test]
fn membrane_mode_split_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "membrane/mode-split");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
    Ok(())
}

#[test]
fn membrane_mode_split_covers_memcpy() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("memcpy")).count() >= 2,
        "memcpy needs at least 2 test cases (strict and hardened)"
    );
    Ok(())
}

#[test]
fn membrane_mode_split_covers_strlen() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("strlen")).count() >= 2,
        "strlen needs at least 2 test cases (strict and hardened)"
    );
    Ok(())
}

#[test]
fn membrane_mode_split_has_strict_ub_cases() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
    let ub_cases = fixture
        .cases
        .iter()
        .filter(|c| c.mode == "strict" && c.expected_output.as_deref() == Some("UB"))
        .count();
    assert!(
        ub_cases >= 1,
        "strict mode needs at least 1 UB case for overflow scenarios"
    );
    Ok(())
}

#[test]
fn membrane_mode_split_has_hardened_safe_cases() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
    let hardened_safe = fixture
        .cases
        .iter()
        .filter(|c| c.mode == "hardened" && c.expected_output.as_deref() != Some("UB"))
        .count();
    assert!(
        hardened_safe >= 1,
        "hardened mode needs at least 1 safe clamped case"
    );
    Ok(())
}

#[test]
fn membrane_mode_split_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
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
fn membrane_mode_split_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
    assert!(
        fixture.cases.len() >= 4,
        "membrane_mode_split fixture has {} cases, expected at least 4",
        fixture.cases.len()
    );
    eprintln!(
        "membrane_mode_split fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn membrane_mode_split_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("membrane_mode_split")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("TSM"),
            "Case {} spec_section should reference TSM: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn membrane_mode_split_fixture_executes_with_host_parity_via_harness_matrix() -> Result<(), String>
{
    let fixture = load_fixture("membrane_mode_split")?;

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
                        "membrane_mode_split case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;
            assert!(
                result.host_parity || result.host_output == "UB",
                "membrane_mode_split case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name,
                result.host_output,
                result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "membrane_mode_split case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
    Ok(())
}
