//! Fixture-backed mntent operations conformance tests.

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

#[test]
fn mntent_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/mntent_ops.json");
    assert!(path.exists(), "mntent_ops.json fixture must exist");
}

#[test]
fn mntent_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "mntent");
    assert!(
        !fixture.description.is_empty(),
        "fixture should describe its scope"
    );
    assert!(
        !fixture.spec_reference.is_empty(),
        "fixture should include a top-level spec reference"
    );
    assert!(!fixture.cases.is_empty(), "must have test cases");

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.function.is_empty(), "function must not be empty");
        assert!(
            !case.spec_section.is_empty(),
            "spec section must not be empty"
        );
        assert!(
            case.expected_output.is_some(),
            "case {} must have expected_output",
            case.name
        );
    }

    Ok(())
}

#[test]
fn mntent_ops_covers_getmntent_r() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;
    assert!(
        fixture
            .cases
            .iter()
            .filter(|case| case.function == "getmntent_r")
            .count()
            >= 3,
        "getmntent_r needs basic, defaulted, and skipped-comment coverage"
    );

    Ok(())
}

#[test]
fn mntent_ops_covers_hasmntopt() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;
    assert!(
        fixture
            .cases
            .iter()
            .filter(|case| case.function == "hasmntopt")
            .count()
            >= 3,
        "hasmntopt needs whole-token, substring, and key=value coverage"
    );

    Ok(())
}

#[test]
fn mntent_ops_covers_parser_and_token_boundaries() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;
    let case_names: Vec<&str> = fixture
        .cases
        .iter()
        .map(|case| case.name.as_str())
        .collect();

    assert!(
        case_names
            .iter()
            .any(|name| name.contains("missing_freq_passno")),
        "mntent_ops must cover missing freq/passno defaults"
    );
    assert!(
        case_names.iter().any(|name| name.contains("comment")),
        "mntent_ops must cover comment-only lines"
    );
    assert!(
        case_names.iter().any(|name| name.contains("substring")),
        "mntent_ops must cover hasmntopt substring rejection"
    );

    Ok(())
}

#[test]
fn mntent_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;

    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "case {} has unexpected errno value: {}",
            case.name, case.expected_errno
        );
    }

    Ok(())
}

#[test]
fn mntent_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;

    for case in &fixture.cases {
        assert!(
            matches!(case.mode.as_str(), "both" | "strict" | "hardened"),
            "case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }

    Ok(())
}

#[test]
fn mntent_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;

    const EXPECTED_MIN_CASES: usize = 6;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "mntent_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    Ok(())
}

#[test]
fn mntent_ops_fixture_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture("mntent_ops")?;

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
