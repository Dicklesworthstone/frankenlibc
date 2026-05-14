//! String and memory operations conformance test suite.
//!
//! Validates POSIX string/memory functions: memset, memcmp, memchr, strcmp, strcpy, strncpy.
//! Run: cargo test -p frankenlibc-harness --test string_memory_full_conformance_test

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
    impl_output: String,
    host_output: String,
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
fn string_memory_full_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/string_memory_full.json");
    assert!(path.exists(), "string_memory_full.json fixture must exist");
}

#[test]
fn string_memory_full_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/memory");
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
fn string_memory_full_covers_memset() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("memset")),
        "Missing test coverage for memset"
    );
    Ok(())
}

#[test]
fn string_memory_full_covers_memcmp() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("memcmp")).count() >= 2,
        "memcmp needs at least 2 test cases (equal and not equal)"
    );
    Ok(())
}

#[test]
fn string_memory_full_covers_memchr() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("memchr")),
        "Missing test coverage for memchr"
    );
    Ok(())
}

#[test]
fn string_memory_full_covers_memrchr() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("memrchr")),
        "Missing test coverage for memrchr"
    );
    Ok(())
}

#[test]
fn string_memory_full_covers_strcmp() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("strcmp")).count() >= 2,
        "strcmp needs at least 2 test cases (equal and not equal)"
    );
    Ok(())
}

#[test]
fn string_memory_full_covers_strcpy() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("strcpy")),
        "Missing test coverage for strcpy"
    );
    Ok(())
}

#[test]
fn string_memory_full_covers_strncpy() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("strncpy")),
        "Missing test coverage for strncpy"
    );
    Ok(())
}

#[test]
fn string_memory_full_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
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
fn string_memory_full_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    assert!(
        fixture.cases.len() >= 8,
        "string_memory_full fixture has {} cases, expected at least 8",
        fixture.cases.len()
    );
    eprintln!(
        "string_memory_full fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn string_memory_full_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference POSIX or GNU: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn string_memory_full_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;
    // Standard string/memory functions don't set errno
    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {} (string/memory functions don't set errno)",
            case.name, case.expected_errno
        );
    }
    Ok(())
}

#[test]
fn string_memory_full_fixture_cases_match_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture("string_memory_full")?;

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
                        "string_memory_full case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;
            assert_eq!(
                result.impl_output, expected_output,
                "fixture expected_output mismatch for {} ({mode})",
                case.name
            );
            assert!(
                result.host_parity || result.host_output == "UB",
                "defined host behavior diverged for {} ({mode}): host={}, impl={}",
                case.name,
                result.host_output,
                result.impl_output
            );
        }
    }

    Ok(())
}
