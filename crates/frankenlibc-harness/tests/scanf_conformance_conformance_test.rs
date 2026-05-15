//! scanf conformance test suite.
//!
//! Validates C11/POSIX scanf family functions: sscanf with all conversion
//! specifiers, assignment suppression, width, and length modifiers.
//! Run: cargo test -p frankenlibc-harness --test scanf_conformance_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type TestResult = Result<(), String>;

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            format!(
                "failed to derive workspace root from {}",
                manifest_dir.display()
            )
        })?;
    Ok(root.to_path_buf())
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
    expected_return: Option<i32>,
    #[serde(default)]
    expected_values: Option<serde_json::Value>,
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

#[test]
fn scanf_conformance_fixture_exists() -> TestResult {
    let path = repo_root()?.join("tests/conformance/fixtures/scanf_conformance.json");
    assert!(path.exists(), "scanf_conformance.json fixture must exist");
    Ok(())
}

#[test]
fn scanf_conformance_fixture_valid_schema() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "scanf_conformance");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
    Ok(())
}

#[test]
fn scanf_conformance_covers_integer_specifiers() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("_d_")),
        "Missing %d tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_i_")),
        "Missing %i tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_u_")),
        "Missing %u tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_o_")),
        "Missing %o tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_x_")),
        "Missing %x tests"
    );
    Ok(())
}

#[test]
fn scanf_conformance_covers_float_specifiers() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("_f_")),
        "Missing %f tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_lf_")),
        "Missing %lf tests"
    );
    Ok(())
}

#[test]
fn scanf_conformance_covers_string_specifiers() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("_s_")),
        "Missing %s tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_c_")),
        "Missing %c tests"
    );
    Ok(())
}

#[test]
fn scanf_conformance_covers_scansets() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("scanset")).count() >= 3,
        "Scanset needs at least 3 test cases"
    );
    Ok(())
}

#[test]
fn scanf_conformance_covers_suppression() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("suppress")),
        "Missing assignment suppression (*) tests"
    );
    Ok(())
}

#[test]
fn scanf_conformance_covers_length_modifiers() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("hh_")),
        "Missing hh length tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("h_")),
        "Missing h length tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("l_")),
        "Missing l length tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("ll_")),
        "Missing ll length tests"
    );
    Ok(())
}

#[test]
fn scanf_conformance_covers_eof_and_errors() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("eof")),
        "Missing EOF tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("no_match")),
        "Missing no-match tests"
    );
    Ok(())
}

#[test]
fn scanf_conformance_modes_valid() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {}",
            case.name,
            case.mode
        );
    }
    Ok(())
}

#[test]
fn scanf_conformance_case_count_stable() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    assert!(
        fixture.cases.len() >= 50,
        "scanf_conformance fixture has {} cases, expected at least 50",
        fixture.cases.len()
    );
    eprintln!(
        "scanf_conformance fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn scanf_conformance_has_spec_references() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11") || case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference C11 or POSIX: {}",
            case.name,
            case.spec_section
        );
    }
    Ok(())
}

#[test]
fn scanf_conformance_covers_special_values() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("inf")),
        "Missing infinity tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("nan")),
        "Missing NaN tests"
    );
    Ok(())
}

#[test]
fn scanf_conformance_covers_width() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("width")).count() >= 3,
        "Width specifier needs at least 3 test cases"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Execution coverage (bd-66m4)
// ---------------------------------------------------------------------------

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

fn scanf_result_matches_fixture(
    got: &str,
    expected_return: i32,
    expected_values: Option<&serde_json::Value>,
) -> bool {
    let Some((ret_part, vals_part)) = got.split_once(':') else {
        return false;
    };
    if ret_part.parse::<i32>().ok() != Some(expected_return) {
        return false;
    }

    let got_inner = vals_part
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");
    let got_parts: Vec<&str> = if got_inner.is_empty() {
        Vec::new()
    } else {
        got_inner.split(',').collect()
    };

    let Some(expected_values) = expected_values else {
        return got_parts.is_empty();
    };
    let Some(expected_items) = expected_values.as_array() else {
        return false;
    };
    if got_parts.len() != expected_items.len() {
        return false;
    }

    for (got_part, expected) in got_parts.iter().zip(expected_items.iter()) {
        match expected {
            serde_json::Value::Number(number) => {
                if let Some(expected_int) = number.as_i64() {
                    if got_part.parse::<i64>().ok() != Some(expected_int) {
                        return false;
                    }
                } else if let Some(expected_float) = number.as_f64() {
                    let Some(got_float) = got_part.parse::<f64>().ok() else {
                        return false;
                    };
                    let tolerance = expected_float.abs() * 1e-5 + 1e-9;
                    if (got_float - expected_float).abs() > tolerance {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            serde_json::Value::String(string) => {
                if *got_part != format!("\"{string}\"") {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn format_expected_scanf_result(
    expected_return: i32,
    expected_values: Option<&serde_json::Value>,
) -> String {
    let values = expected_values
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rendered_values: Vec<String> = values
        .iter()
        .map(|value| match value {
            serde_json::Value::Number(number) => {
                if let Some(int_value) = number.as_i64() {
                    int_value.to_string()
                } else if let Some(float_value) = number.as_f64() {
                    format!("{float_value}")
                } else {
                    number.to_string()
                }
            }
            serde_json::Value::String(string) => format!("\"{string}\""),
            _ => value.to_string(),
        })
        .collect();
    format!("{expected_return}:[{}]", rendered_values.join(","))
}

#[test]
fn scanf_conformance_fixture_cases_match_execute_fixture_case() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let mut executed = 0usize;
    let skipped = 0usize;

    for case in &fixture.cases {
        let expected_return = case
            .expected_return
            .ok_or_else(|| format!("case {} missing expected_return", case.name))?;
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_fixture_case(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "scanf_conformance case {} ({mode}) failed to execute: {err}",
                        case.name
                    )
                })?;
            assert!(
                scanf_result_matches_fixture(
                    &result.impl_output,
                    expected_return,
                    case.expected_values.as_ref(),
                ),
                "scanf_conformance case {} ({mode}) mismatched fixture output: got={}, expected={}",
                case.name,
                result.impl_output,
                format_expected_scanf_result(expected_return, case.expected_values.as_ref())
            );
            assert!(
                result.host_parity,
                "scanf_conformance case {} ({mode}) lost host parity: host={}, impl={}",
                case.name, result.host_output, result.impl_output
            );
            executed += 1;
        }
    }

    eprintln!("scanf_conformance in-process: executed={executed} skipped={skipped}");
    assert!(
        executed >= 10,
        "scanf_conformance in-process expected at least 10 executed cases, got {executed}"
    );
    Ok(())
}

#[test]
fn scanf_conformance_fixture_executes_with_host_parity_via_harness_matrix() -> TestResult {
    let fixture = load_fixture("scanf_conformance")?;
    let mut executed = 0usize;
    let skipped = 0usize;

    for case in &fixture.cases {
        let expected_return = case
            .expected_return
            .ok_or_else(|| format!("case {} missing expected_return", case.name))?;
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_case_via_harness(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "scanf_conformance case {} ({mode}) failed via harness matrix: {err}",
                        case.name
                    )
                })?;
            assert!(
                scanf_result_matches_fixture(
                    &result.impl_output,
                    expected_return,
                    case.expected_values.as_ref(),
                ),
                "scanf_conformance case {} ({mode}) mismatched fixture output via harness: got={}, expected={}",
                case.name,
                result.impl_output,
                format_expected_scanf_result(expected_return, case.expected_values.as_ref())
            );
            assert!(
                result.host_parity,
                "scanf_conformance case {} ({mode}) lost host parity via harness: host={}, impl={}",
                case.name, result.host_output, result.impl_output
            );
            executed += 1;
        }
    }

    eprintln!("scanf_conformance harness-matrix: executed={executed} skipped={skipped}");
    assert!(
        executed >= 10,
        "scanf_conformance harness-matrix expected at least 10 executed cases, got {executed}"
    );
    Ok(())
}
