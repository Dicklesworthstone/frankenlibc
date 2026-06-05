//! printf conformance test suite.
//!
//! Validates C11/POSIX printf family functions: sprintf, snprintf with all
//! conversion specifiers, flags, width, precision, and length modifiers.
//! Run: cargo test -p frankenlibc-harness --test printf_conformance_conformance_test

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
    expected_output_bytes: Option<Vec<u8>>,
    #[serde(default)]
    expected_output_pattern: Option<String>,
    #[serde(default)]
    expected_return: Option<i32>,
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
fn printf_conformance_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/printf_conformance.json");
    assert!(path.exists(), "printf_conformance.json fixture must exist");
    Ok(())
}

#[test]
fn printf_conformance_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "printf_conformance");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
    Ok(())
}

#[test]
fn printf_conformance_covers_integer_specifiers() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
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
fn printf_conformance_covers_float_specifiers() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("_f_")),
        "Missing %f tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_e_")),
        "Missing %e tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("_g_")),
        "Missing %g tests"
    );
    Ok(())
}

#[test]
fn printf_conformance_covers_string_specifiers() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
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
fn printf_conformance_covers_flags() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("left")),
        "Missing left-justify (-) tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("zero_pad")),
        "Missing zero-pad (0) tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("plus")),
        "Missing plus (+) flag tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("space")),
        "Missing space flag tests"
    );
    assert!(
        case_names.iter().any(|n| n.contains("alt")),
        "Missing alternate (#) flag tests"
    );
    Ok(())
}

#[test]
fn printf_conformance_covers_length_modifiers() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
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
fn printf_conformance_covers_snprintf() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    let snprintf_cases = fixture
        .cases
        .iter()
        .filter(|c| c.function == "snprintf")
        .count();
    assert!(snprintf_cases >= 2, "snprintf needs at least 2 test cases");
    Ok(())
}

#[test]
fn printf_conformance_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
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
fn printf_conformance_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    assert!(
        fixture.cases.len() >= 50,
        "printf_conformance fixture has {} cases, expected at least 50",
        fixture.cases.len()
    );
    eprintln!(
        "printf_conformance fixture has {} test cases",
        fixture.cases.len()
    );
    Ok(())
}

#[test]
fn printf_conformance_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
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
fn printf_conformance_covers_special_values() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
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

// ---------------------------------------------------------------------------
// Execution coverage (bd-12hh)
// ---------------------------------------------------------------------------
//
// Dispatch fixture cases with a concrete `expected_output: Some(String)`
// through both the in-process executor and the isolated harness
// subprocess. Cases that rely on `expected_output_bytes` or
// `expected_output_pattern` (e.g. %p pointer addresses, %a hex floats
// whose exact output is non-deterministic) are skipped here — their
// validation belongs in a dedicated bytes/pattern path.

/// Cases where FrankenLibC's fixture output is correct, but the host
/// oracle path cannot yet push an x86_64 `long double` through Rust's
/// C-variadic boundary and reports an explicit oracle gap.
const HOST_LONG_DOUBLE_ORACLE_GAPS: &[&str] = &["sprintf_Lf_basic", "sprintf_Le_basic"];

fn case_has_host_long_double_oracle_gap(name: &str) -> bool {
    HOST_LONG_DOUBLE_ORACLE_GAPS.contains(&name)
}

fn host_output_is_explicit_long_double_oracle_gap(value: &str) -> bool {
    matches!(value, "UNSUPPORTED_HOST_ORACLE" | "nan" | "-nan")
}

#[test]
fn printf_conformance_fixture_cases_match_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    let mut executed = 0usize;
    let mut skipped = 0usize;

    for case in &fixture.cases {
        if case_has_host_long_double_oracle_gap(&case.name) {
            eprintln!("skip {} — host long-double oracle gap", case.name);
            skipped += 1;
            continue;
        }
        let Some(expected_output) = case.expected_output.as_deref() else {
            skipped += 1;
            continue;
        };
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
                result.host_parity || result.host_output == "UB",
                "defined host behavior diverged for {} ({mode}): host={}, impl={}",
                case.name,
                result.host_output,
                result.impl_output
            );
            executed += 1;
        }
    }
    eprintln!(
        "printf_conformance in-process: executed={executed} skipped={skipped} (skipped cases use expected_output_bytes/pattern)"
    );
    Ok(())
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
fn printf_long_double_host_oracle_gap_is_explicit_in_process() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    let mut seen = Vec::new();

    for case in &fixture.cases {
        if !matches!(case.name.as_str(), "sprintf_Lf_basic" | "sprintf_Le_basic") {
            continue;
        }
        let expected_output = case
            .expected_output
            .as_deref()
            .ok_or_else(|| String::from("long-double printf fixture missing expected_output"))?;
        let result = execute_fixture_case(&case.function, &case.inputs, "strict")
            .map_err(|err| format!("long-double printf fixture failed in process: {err}"))?;
        assert_eq!(
            result.impl_output, expected_output,
            "FrankenLibC long-double fixture output mismatch for {}",
            case.name
        );
        assert!(
            !result.host_parity,
            "host long-double oracle gap should remain explicit for {}",
            case.name
        );
        assert!(
            host_output_is_explicit_long_double_oracle_gap(&result.host_output),
            "host long-double oracle should expose an explicit varargs gap for {}: host={}, impl={}",
            case.name,
            result.host_output,
            result.impl_output
        );
        seen.push(case.name.as_str());
    }

    assert_eq!(
        seen,
        vec!["sprintf_Lf_basic", "sprintf_Le_basic"],
        "long-double printf fixtures must execute instead of being skipped"
    );
    Ok(())
}

#[test]
fn printf_long_double_host_oracle_gap_is_explicit_via_harness_matrix() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    let mut seen = Vec::new();

    for case in &fixture.cases {
        if !matches!(case.name.as_str(), "sprintf_Lf_basic" | "sprintf_Le_basic") {
            continue;
        }
        let expected_output = case
            .expected_output
            .as_deref()
            .ok_or_else(|| String::from("long-double printf fixture missing expected_output"))?;
        let result = execute_case_via_harness(&case.function, &case.inputs, "strict")
            .map_err(|err| format!("long-double printf fixture failed via harness: {err}"))?;
        assert!(
            !result.host_parity,
            "host long-double oracle gap should remain explicit via harness for {}",
            case.name
        );
        assert!(
            host_output_is_explicit_long_double_oracle_gap(&result.host_output),
            "host long-double oracle should expose an explicit varargs gap via harness for {}: host={}, impl={}",
            case.name,
            result.host_output,
            result.impl_output
        );
        assert_eq!(result.impl_output, expected_output);
        seen.push(case.name.as_str());
    }

    assert_eq!(
        seen,
        vec!["sprintf_Lf_basic", "sprintf_Le_basic"],
        "long-double printf fixtures must execute through the harness matrix"
    );
    Ok(())
}

#[test]
fn printf_conformance_fixture_executes_with_host_parity_via_harness_matrix() -> Result<(), String> {
    let fixture = load_fixture("printf_conformance")?;
    let mut executed = 0usize;
    let mut skipped = 0usize;

    for case in &fixture.cases {
        if case_has_host_long_double_oracle_gap(&case.name) {
            eprintln!("skip {} — host long-double oracle gap", case.name);
            skipped += 1;
            continue;
        }
        let Some(expected_output) = case.expected_output.as_deref() else {
            skipped += 1;
            continue;
        };
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_case_via_harness(&case.function, &case.inputs, mode).map_err(|err| {
                    format!(
                        "printf_conformance case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;
            assert!(
                result.host_parity || result.host_output == "UB",
                "printf_conformance case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name,
                result.host_output,
                result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "printf_conformance case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
            executed += 1;
        }
    }
    eprintln!("printf_conformance harness-matrix: executed={executed} skipped={skipped}");
    Ok(())
}
