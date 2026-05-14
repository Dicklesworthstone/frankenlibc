//! ctype operations conformance test suite.
//!
//! Validates POSIX/C11 character classification and conversion functions.
//! Run: cargo test -p frankenlibc-harness --test ctype_ops_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
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

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/ctype_ops.json");
    assert!(path.exists(), "ctype_ops.json fixture must exist");
    Ok(())
}

#[test]
fn ctype_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "ctype");
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
            "Spec section must not be empty"
        );
        assert!(
            case.expected_output.is_some(),
            "Case {} must have expected_output",
            case.name
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: classification functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_covers_isalpha() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isalpha")).count() >= 3,
        "isalpha needs at least 3 test cases"
    );

    Ok(())
}

#[test]
fn ctype_ops_covers_isdigit() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isdigit")).count() >= 2,
        "isdigit needs at least 2 test cases"
    );

    Ok(())
}

#[test]
fn ctype_ops_covers_isalnum() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isalnum")).count() >= 2,
        "isalnum needs at least 2 test cases"
    );

    Ok(())
}

#[test]
fn ctype_ops_covers_case_functions() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["isupper", "islower"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for case function: {}",
            pattern
        );
    }

    Ok(())
}

#[test]
fn ctype_ops_covers_isspace() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Should test multiple whitespace chars: space, tab, newline
    assert!(
        case_names.iter().filter(|n| n.contains("isspace")).count() >= 3,
        "isspace needs at least 3 test cases (space, tab, newline)"
    );

    Ok(())
}

#[test]
fn ctype_ops_covers_isprint() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isprint")).count() >= 3,
        "isprint needs at least 3 test cases"
    );

    Ok(())
}

#[test]
fn ctype_ops_covers_ispunct() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("ispunct")).count() >= 2,
        "ispunct needs at least 2 test cases"
    );

    Ok(())
}

#[test]
fn ctype_ops_covers_isxdigit() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("isxdigit")).count() >= 3,
        "isxdigit needs at least 3 test cases"
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: conversion functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_covers_tolower() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("tolower")).count() >= 3,
        "tolower needs at least 3 test cases"
    );

    Ok(())
}

#[test]
fn ctype_ops_covers_toupper() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("toupper")).count() >= 3,
        "toupper needs at least 3 test cases"
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

    // ctype functions don't set errno
    let valid_errno_values = [0];

    for case in &fixture.cases {
        assert!(
            valid_errno_values.contains(&case.expected_errno),
            "Case {} has unexpected errno value: {} (ctype functions don't set errno)",
            case.name,
            case.expected_errno,
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function grouping validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_function_distribution() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

    let mut classification_count = 0;
    let mut conversion_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "isalpha" | "isdigit" | "isalnum" | "isupper" | "islower" | "isspace" | "isprint"
            | "ispunct" | "isxdigit" | "iscntrl" | "isgraph" | "isblank" => {
                classification_count += 1
            }
            "tolower" | "toupper" => conversion_count += 1,
            function => return Err(format!("unexpected function in fixture: {function}")),
        }
    }

    assert!(
        classification_count >= 25,
        "Classification functions need more test cases (have {})",
        classification_count
    );
    assert!(
        conversion_count >= 6,
        "Conversion functions need more test cases (have {})",
        conversion_count
    );

    eprintln!(
        "ctype_ops coverage: classification={}, conversion={}",
        classification_count, conversion_count
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {} (expected 'both', 'strict', or 'hardened')",
            case.name,
            case.mode
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

    const EXPECTED_MIN_CASES: usize = 30;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "ctype_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("ctype_ops fixture has {} test cases", fixture.cases.len());

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_has_posix_references() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference POSIX: {}",
            case.name,
            case.spec_section
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case coverage: boundary values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctype_ops_covers_boundary_values() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

    // Check that we test boundary characters
    let inputs: Vec<i64> = fixture
        .cases
        .iter()
        .filter_map(|c| c.inputs.get("c").and_then(|v| v.as_i64()))
        .collect();

    // Should test: space (32), digits (48-57), uppercase (65-90), lowercase (97-122)
    assert!(inputs.contains(&32), "Must test space character (ASCII 32)");
    assert!(
        inputs.contains(&48) && inputs.contains(&57),
        "Must test digit boundaries (0=48, 9=57)"
    );
    assert!(
        inputs.contains(&65) && inputs.contains(&90),
        "Must test uppercase boundaries (A=65, Z=90)"
    );
    assert!(
        inputs.contains(&97) && inputs.contains(&122),
        "Must test lowercase boundaries (a=97, z=122)"
    );

    Ok(())
}

#[test]
fn ctype_ops_fixture_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

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

#[test]
fn ctype_ops_fixture_cases_match_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture("ctype_ops")?;

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
                "executor reported parity failure for {} ({mode})",
                case.name
            );
        }
    }

    Ok(())
}
