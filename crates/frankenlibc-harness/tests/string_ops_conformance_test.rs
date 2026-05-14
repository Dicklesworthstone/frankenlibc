//! String operations conformance test suite.
//!
//! Validates POSIX string APIs: strcpy, strncpy, strcat, strcmp, strchr, strrchr, strstr, etc.
//! Run: cargo test -p frankenlibc-harness --test string_ops_conformance_test

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

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structure validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_fixture_exists() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/string_ops.json");
    assert!(path.exists(), "string_ops.json fixture must exist");
    Ok(())
}

#[test]
fn string_ops_fixture_valid_schema() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/narrow");
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
// Coverage validation: string operations have test cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_covers_copy_functions() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["strcpy", "strncpy"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for copy function: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn string_ops_covers_concat_functions() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("strcat")),
        "Missing test coverage for strcat"
    );
    Ok(())
}

#[test]
fn string_ops_covers_strl_functions() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

    for function in ["strlcpy", "strlcat"] {
        assert!(
            fixture
                .cases
                .iter()
                .any(|case| case.function == function && case.mode == "strict"),
            "Missing strict fixture coverage for {function}"
        );
        assert!(
            fixture.cases.iter().any(|case| {
                case.function == function
                    && case.mode == "hardened"
                    && case.name.contains("dst_bound")
                    && case
                        .expected_output
                        .as_deref()
                        .is_some_and(|output| output.contains("repair=TruncateWithNull"))
            }),
            "Missing hardened destination-bound repair fixture coverage for {function}"
        );
    }
    Ok(())
}

#[test]
fn string_ops_covers_compare_functions() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["strcmp", "memcmp"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for compare function: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn string_ops_covers_search_functions() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["strchr", "strrchr", "strstr", "memchr"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for search function: {}",
            pattern
        );
    }
    Ok(())
}

#[test]
fn string_ops_covers_hotpath_first_wave_symbols() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

    for function in [
        "__memcmpeq",
        "__mempcpy",
        "__rawmemchr",
        "__stpcpy",
        "__stpcpy_small",
        "__stpncpy",
        "__strcasecmp",
        "__strcasecmp_l",
        "__strcasestr",
        "__strcoll_l",
        "__strcpy_small",
        "__strcspn_c1",
    ] {
        assert!(
            fixture.cases.iter().any(|case| case.function == function),
            "Missing first-wave hot-path fixture coverage for {function}"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_error_codes_valid() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

    // String ops generally don't set errno on success
    let valid_errno_values = [0];

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
fn string_ops_modes_valid() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

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
fn string_ops_case_count_stable() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

    const EXPECTED_MIN_CASES: usize = 10;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "string_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("string_ops fixture has {} test cases", fixture.cases.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_covers_both_modes() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "string_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "string_ops must have hardened mode test cases"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened mode: buffer overflow protection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_covers_overflow_protection() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Hardened mode should have overflow protection tests
    assert!(
        case_names.iter().any(|name| name.contains("overflow")),
        "Missing test coverage for hardened overflow protection"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Function distribution
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn string_ops_function_distribution() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

    let functions: Vec<&str> = fixture.cases.iter().map(|c| c.function.as_str()).collect();

    let unique_functions: std::collections::HashSet<_> = functions.iter().collect();

    // Ensure we have diversity of functions
    assert!(
        unique_functions.len() >= 8,
        "string_ops should cover at least 8 different functions, has {}",
        unique_functions.len()
    );

    eprintln!(
        "string_ops covers {} unique functions: {:?}",
        unique_functions.len(),
        unique_functions
    );
    Ok(())
}

#[test]
fn string_ops_fixture_cases_match_direct_execute_fixture_case() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

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
                        "string_ops case {} ({mode}) failed to execute directly: {err}",
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

#[test]
fn string_ops_fixture_cases_match_isolated_harness_subprocess() -> Result<(), String> {
    let fixture = load_fixture("string_ops")?;

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
                        "string_ops case {} ({mode}) failed to execute via harness: {err}",
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
