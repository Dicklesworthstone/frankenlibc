//! iconv phase-1 conformance test suite.
//!
//! Validates POSIX iconv functions: iconv_open, iconv, iconv_close.
//! Run: cargo test -p frankenlibc-harness --test iconv_phase1_conformance_test

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
    let path = repo_root()?.join(format!("tests/conformance/fixtures/{name}.json"));
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
fn iconv_phase1_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/iconv_phase1.json");
    assert!(path.exists(), "iconv_phase1.json fixture must exist");
    Ok(())
}

#[test]
fn iconv_phase1_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "iconv/phase1");
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

#[test]
fn iconv_phase1_covers_iconv_open() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("iconv_open"))
            .count()
            >= 2,
        "iconv_open needs at least 2 test cases"
    );
    Ok(())
}

#[test]
fn iconv_phase1_covers_iconv() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.starts_with("strict_") || n.starts_with("hardened_"))
            .count()
            >= 5,
        "iconv conversion needs at least 5 test cases"
    );
    Ok(())
}

#[test]
fn iconv_phase1_covers_iconv_close() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("iconv_close")),
        "Missing test coverage for iconv_close"
    );
    Ok(())
}

#[test]
fn iconv_phase1_covers_error_codes() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("e2big") || n.contains("E2BIG")),
        "Missing test coverage for E2BIG"
    );
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("eilseq") || n.contains("EILSEQ")),
        "Missing test coverage for EILSEQ"
    );
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("einval") || n.contains("EINVAL")),
        "Missing test coverage for EINVAL"
    );
    Ok(())
}

#[test]
fn iconv_phase1_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
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
fn iconv_phase1_covers_both_modes() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(has_strict, "iconv_phase1 must have strict mode test cases");
    assert!(
        has_hardened,
        "iconv_phase1 must have hardened mode test cases"
    );
    Ok(())
}

#[test]
fn iconv_phase1_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    assert!(
        fixture.cases.len() >= 10,
        "iconv_phase1 fixture has {} cases, expected at least 10",
        fixture.cases.len()
    );
    eprintln!(
        "iconv_phase1 fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn iconv_phase1_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX")
                || case.spec_section.contains("iconv")
                || case.spec_section.contains("TSM"),
            "Case {} spec_section should reference POSIX, iconv, or TSM: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn iconv_phase1_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;

    // Valid error codes for iconv operations
    let valid_errno_values = [
        0,  // Success
        7,  // E2BIG (output buffer too small)
        22, // EINVAL (incomplete sequence)
        84, // EILSEQ (invalid sequence)
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

#[test]
fn iconv_phase1_fixture_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture("iconv_phase1")?;

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
