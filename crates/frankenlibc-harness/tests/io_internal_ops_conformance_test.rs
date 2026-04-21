//! Internal I/O operations conformance test suite.
//!
//! Validates internal glibc _IO_* stdio functions with native implementations.
//! Run: cargo test -p frankenlibc-harness --test io_internal_ops_conformance_test

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
    expected_output: Option<String>,
    #[serde(default)]
    expected_errno: i32,
    mode: String,
    #[serde(default)]
    note: String,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
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
fn io_internal_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/io_internal_ops.json");
    assert!(path.exists(), "io_internal_ops.json fixture must exist");
}

#[test]
fn io_internal_ops_fixture_valid_schema() {
    let fixture = load_fixture("io_internal_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "io_internal");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn io_internal_ops_covers_adjust_column() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("adjust_column"))
            .count()
            >= 2,
        "_IO_adjust_column needs at least 2 test cases"
    );
}

#[test]
fn io_internal_ops_covers_adjust_wcolumn() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wcolumn")),
        "Missing test coverage for _IO_adjust_wcolumn"
    );
}

#[test]
fn io_internal_ops_covers_default_doallocate() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("doallocate")),
        "Missing test coverage for _IO_default_doallocate"
    );
}

#[test]
fn io_internal_ops_covers_file_init() {
    let fixture = load_fixture("io_internal_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("file_init")),
        "Missing test coverage for _IO_file_init"
    );
}

#[test]
fn io_internal_ops_modes_valid() {
    let fixture = load_fixture("io_internal_ops");
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
}

#[test]
fn io_internal_ops_case_count_stable() {
    let fixture = load_fixture("io_internal_ops");
    assert!(
        fixture.cases.len() >= 5,
        "io_internal_ops fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!(
        "io_internal_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn io_internal_ops_has_spec_references() {
    let fixture = load_fixture("io_internal_ops");
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
}

#[test]
fn io_internal_ops_error_codes_valid() {
    let fixture = load_fixture("io_internal_ops");
    // Internal I/O functions may set ENOSYS for unimplemented features
    for case in &fixture.cases {
        assert!(
            case.expected_errno == 0 || case.expected_errno == 38,
            "Case {} has unexpected errno {} (expected 0 or ENOSYS)",
            case.name,
            case.expected_errno
        );
    }
}

#[test]
fn io_internal_ops_fixture_executes_via_harness() {
    let fixture = load_fixture("io_internal_ops");

    for case in &fixture.cases {
        let modes = if case.mode == "both" {
            vec!["strict", "hardened"]
        } else {
            vec![case.mode.as_str()]
        };

        for mode in modes {
            let result = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "io_internal case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });

            let expected_text = case.expected_output.as_deref().unwrap_or_else(|| {
                panic!("io_internal case {} missing expected_output", case.name)
            });

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
}
