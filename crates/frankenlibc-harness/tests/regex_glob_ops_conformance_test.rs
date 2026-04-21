//! Regex/glob operations conformance test suite.
//!
//! Validates POSIX pattern matching and shell expansion functions:
//! regcomp, regexec, fnmatch, glob, wordexp.
//! Run: cargo test -p frankenlibc-harness --test regex_glob_ops_conformance_test

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

fn mode_matches(active_mode: &str, case_mode: &str) -> bool {
    case_mode == active_mode || case_mode == "both"
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
fn regex_glob_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/regex_glob_ops.json");
    assert!(path.exists(), "regex_glob_ops.json fixture must exist");
}

#[test]
fn regex_glob_ops_fixture_valid_schema() {
    let fixture = load_fixture("regex_glob_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "regex_glob_ops");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn regex_glob_ops_covers_regcomp() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("regcomp")),
        "Missing test coverage for regcomp"
    );
}

#[test]
fn regex_glob_ops_covers_regexec() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("regexec")).count() >= 2,
        "regexec needs at least 2 test cases (match and nomatch)"
    );
}

#[test]
fn regex_glob_ops_covers_fnmatch() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("fnmatch")).count() >= 2,
        "fnmatch needs at least 2 test cases"
    );
}

#[test]
fn regex_glob_ops_covers_glob() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("glob")),
        "Missing test coverage for glob"
    );
}

#[test]
fn regex_glob_ops_covers_wordexp() {
    let fixture = load_fixture("regex_glob_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wordexp")).count() >= 3,
        "wordexp needs at least 3 host-parity cases"
    );
}

#[test]
fn regex_glob_ops_modes_valid() {
    let fixture = load_fixture("regex_glob_ops");
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
fn regex_glob_ops_covers_both_modes() {
    let fixture = load_fixture("regex_glob_ops");
    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(
        has_strict,
        "regex_glob_ops must have strict mode test cases"
    );
    assert!(
        has_hardened,
        "regex_glob_ops must have hardened mode test cases"
    );
}

#[test]
fn regex_glob_ops_case_count_stable() {
    let fixture = load_fixture("regex_glob_ops");
    assert!(
        fixture.cases.len() >= 9,
        "regex_glob_ops fixture has {} cases, expected at least 9",
        fixture.cases.len()
    );
    eprintln!(
        "regex_glob_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn regex_glob_ops_fixture_executes_with_host_parity_in_both_modes() {
    let fixture = load_fixture("regex_glob_ops");

    for mode in ["strict", "hardened"] {
        for case in fixture
            .cases
            .iter()
            .filter(|case| mode_matches(mode, &case.mode))
        {
            let result = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "regex_glob_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            let expected = expected_output_text(
                case.expected_output
                    .as_ref()
                    .expect("regex_glob_ops cases must have expected_output"),
            );
            assert_eq!(
                result.impl_output, expected,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity,
                "regex_glob_ops case {} ({mode}) lost host parity: host_output={}",
                case.name, result.host_output
            );
        }
    }
}
