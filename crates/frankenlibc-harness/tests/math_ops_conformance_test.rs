//! Math operations conformance test suite.
//!
//! Validates C11/POSIX math.h functions: sin, cos, tan, exp, log, pow, floor, ceil, etc.
//! Run: cargo test -p frankenlibc-harness --test math_ops_conformance_test

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

fn math_output_matches_expected(expected: &str, actual: &str) -> bool {
    let exp = match expected.parse::<f64>() {
        Ok(v) => v,
        Err(_) => return expected == actual,
    };
    let act = match actual.parse::<f64>() {
        Ok(v) => v,
        Err(_) => return false,
    };

    if exp.is_nan() && act.is_nan() {
        return true;
    }
    if exp.is_infinite() || act.is_infinite() {
        return exp == act;
    }

    let diff = (exp - act).abs();
    let scale = exp.abs().max(act.abs()).max(1.0);
    diff <= 1e-12 * scale
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/math_ops.json");
    assert!(path.exists(), "math_ops.json fixture must exist");
    Ok(())
}

#[test]
fn math_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "math");
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
// Coverage validation: trigonometric functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_trig_basic() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["sin", "cos", "tan"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for trig function: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn math_ops_covers_inverse_trig() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["asin", "acos", "atan"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for inverse trig function: {}",
            pattern
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: exponential and logarithmic functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_exp_log() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["exp", "log"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for exp/log function: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn math_ops_covers_pow() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("pow")).count() >= 2,
        "pow needs at least 2 test cases"
    );
    Ok(())
}

#[test]
fn math_ops_covers_finite_domain_error_bucket() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let required = [
        "asin_domain_gt_one",
        "acos_domain_gt_one",
        "log_domain_negative",
        "log10_domain_negative",
        "pow_domain_negative_fractional",
        "fmod_domain_zero_divisor",
    ];

    for name in required {
        assert!(
            case_names.contains(&name),
            "Missing finite math domain-error fixture case: {name}"
        );
    }

    for case in &fixture.cases {
        if case.name.contains("_domain_") {
            assert_eq!(
                case.expected_errno, 33,
                "domain-error case {} should use EDOM",
                case.name
            );
            assert_eq!(
                case.expected_output.as_deref(),
                Some("NaN"),
                "domain-error case {} should expect NaN output",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn math_ops_covers_classification_helper_pilot() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let required = [
        ("fpclassify_nan", "__fpclassify", "0"),
        ("fpclassifyf_infinite", "__fpclassifyf", "1"),
        ("signbit_negative_zero", "__signbit", "1"),
        ("signbitf_negative_normal", "__signbitf", "1"),
        ("isinf_negative_infinity", "__isinf", "-1"),
        ("isinff_positive_infinity", "__isinff", "1"),
        ("isnan_nan", "__isnan", "1"),
        ("isnanf_finite_normal", "__isnanf", "0"),
        ("finite_internal_finite_normal", "__finite", "1"),
        ("finitef_internal_infinite", "__finitef", "0"),
        ("finite_public_finite_normal", "finite", "1"),
        ("finitef_public_nan", "finitef", "0"),
    ];

    for (name, function, expected_output) in required {
        let case = fixture
            .cases
            .iter()
            .find(|case| case.name == name)
            .ok_or_else(|| format!("missing math classification fixture case: {name}"))?;
        assert_eq!(case.function, function);
        assert_eq!(case.expected_output.as_deref(), Some(expected_output));
        assert_eq!(case.expected_errno, 0);
        assert_eq!(case.mode, "both");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: rounding functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_rounding() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["floor", "ceil", "round"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for rounding function: {}",
            pattern
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: special functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_covers_fabs() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().filter(|n| n.contains("fabs")).count() >= 2,
        "fabs needs at least 2 test cases"
    );
    Ok(())
}

#[test]
fn math_ops_covers_gamma() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("gamma")),
        "Missing test coverage for gamma functions"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;

    // Valid POSIX/Linux error codes for math functions
    let valid_errno_values = [
        0,  // Success
        33, // EDOM
        34, // ERANGE
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

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;

    for case in &fixture.cases {
        assert!(
            matches!(case.mode.as_str(), "both" | "strict" | "hardened"),
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
fn math_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;

    const EXPECTED_MIN_CASES: usize = 30;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "math_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("math_ops fixture has {} test cases", fixture.cases.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function distribution
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_function_distribution() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;

    let mut trig_count = 0;
    let mut exp_log_count = 0;
    let mut rounding_count = 0;

    for case in &fixture.cases {
        match case.function.as_str() {
            "sin" | "cos" | "tan" | "asin" | "acos" | "atan" | "atan2" => trig_count += 1,
            "exp" | "log" | "log10" | "pow" => exp_log_count += 1,
            "floor" | "ceil" | "round" | "trunc" | "fmod" => rounding_count += 1,
            "fabs" | "erf" | "tgamma" | "lgamma" => {}
            f => eprintln!("Note: unclassified math function: {}", f),
        }
    }

    assert!(
        trig_count >= 10,
        "Trig functions need more test cases (have {})",
        trig_count
    );
    assert!(
        exp_log_count >= 6,
        "Exp/log functions need more test cases (have {})",
        exp_log_count
    );
    assert!(
        rounding_count >= 4,
        "Rounding functions need more test cases (have {})",
        rounding_count
    );

    eprintln!(
        "math_ops coverage: trig={}, exp_log={}, rounding={}",
        trig_count, exp_log_count, rounding_count
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance: all cases reference C11 or POSIX sections
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn math_ops_has_spec_references() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;

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
fn math_ops_fixture_executes_with_host_parity_via_harness_matrix() -> Result<(), String> {
    let fixture = load_fixture("math_ops")?;

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
                        "math_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                })?;
            assert!(
                math_output_matches_expected(expected_output, &result.impl_output),
                "fixture expected_output mismatch for {} ({mode}): expected {} got {}",
                case.name,
                expected_output,
                result.impl_output
            );
            assert!(
                result.host_parity,
                "math_ops case {} ({mode}) lost host parity: host={}, impl={}",
                case.name, result.host_output, result.impl_output
            );
        }
    }

    Ok(())
}
