//! Internal I/O operations conformance test suite.
//!
//! Validates internal glibc _IO_* stdio functions with native implementations.
//! Run: cargo test -p frankenlibc-harness --test io_internal_ops_conformance_test

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
fn io_internal_ops_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/io_internal_ops.json");
    assert!(path.exists(), "io_internal_ops.json fixture must exist");
    Ok(())
}

#[test]
fn io_internal_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "io_internal");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }

    Ok(())
}

#[test]
fn io_internal_ops_covers_adjust_column() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("adjust_column"))
            .count()
            >= 2,
        "_IO_adjust_column needs at least 2 test cases"
    );

    Ok(())
}

#[test]
fn io_internal_ops_covers_adjust_wcolumn() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wcolumn")),
        "Missing test coverage for _IO_adjust_wcolumn"
    );

    Ok(())
}

#[test]
fn io_internal_ops_covers_default_doallocate() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("doallocate")),
        "Missing test coverage for _IO_default_doallocate"
    );

    Ok(())
}

#[test]
fn io_internal_ops_covers_file_init() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("file_init")),
        "Missing test coverage for _IO_file_init"
    );

    Ok(())
}

#[test]
fn io_internal_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
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
fn io_internal_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    assert!(
        fixture.cases.len() >= 5,
        "io_internal_ops fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!(
        "io_internal_ops fixture has {} test cases",
        fixture.cases.len()
    );

    Ok(())
}

#[test]
fn io_internal_ops_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("glibc")
                || case.spec_section.contains("libio")
                || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference glibc/libio/GNU: {}",
            case.name,
            case.spec_section
        );
    }

    Ok(())
}

#[test]
fn io_internal_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;
    // Internal I/O functions may set ENOSYS for unimplemented features
    for case in &fixture.cases {
        assert!(
            case.expected_errno == 0 || case.expected_errno == 38,
            "Case {} has unexpected errno {} (expected 0 or ENOSYS)",
            case.name,
            case.expected_errno
        );
    }

    Ok(())
}

#[test]
fn io_internal_ops_fixture_executes_via_harness() -> Result<(), String> {
    let fixture = load_fixture("io_internal_ops")?;

    for case in &fixture.cases {
        let modes = if case.mode == "both" {
            vec!["strict", "hardened"]
        } else {
            vec![case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_case_via_harness(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "io_internal case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;

            let expected_text = case
                .expected_output
                .as_deref()
                .ok_or_else(|| format!("io_internal case {} missing expected_output", case.name))?;

            assert_eq!(
                result.impl_output, expected_text,
                "io_internal case {} ({mode}) impl_output mismatch",
                case.name
            );
            assert!(
                result.host_parity,
                "io_internal case {} ({mode}) lost host parity: {:?}",
                case.name, result
            );
        }
    }

    Ok(())
}
