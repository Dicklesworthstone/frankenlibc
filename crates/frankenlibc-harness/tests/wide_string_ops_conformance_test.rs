//! Wide string operations conformance test suite.
//!
//! Validates ISO C wide string functions: wcslen, wcscpy, wcscmp, wcsncpy, wcscat,
//! wcschr, wcsstr, wcsncmp, wcsrchr.
//!
//! Two execution paths are exercised against `wide_string_ops.json`:
//!   1. The in-process `frankenlibc_fixture_exec::execute_fixture_case` helper,
//!      which catches divergence from the fixture and the host libc directly
//!      from the test process.
//!   2. The isolated harness subprocess (`harness conformance-matrix-case`),
//!      which mirrors how the conformance matrix runs each case for crash /
//!      timeout containment in CI.
//!
//! Run: cargo test -p frankenlibc-harness --test wide_string_ops_conformance_test

use frankenlibc_fixture_exec::execute_fixture_case;
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

#[test]
fn wide_string_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/wide_string_ops.json");
    assert!(path.exists(), "wide_string_ops.json fixture must exist");
}

#[test]
fn wide_string_ops_fixture_valid_schema() {
    let fixture = load_fixture("wide_string_ops");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string/wide");
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
}

#[test]
fn wide_string_ops_covers_wcslen() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wcslen")).count() >= 2,
        "wcslen needs at least 2 test cases"
    );
}

#[test]
fn wide_string_ops_covers_wcscpy() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wcscpy")),
        "Missing test coverage for wcscpy"
    );
}

#[test]
fn wide_string_ops_covers_wcscmp() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wcscmp")).count() >= 2,
        "wcscmp needs at least 2 test cases"
    );
}

#[test]
fn wide_string_ops_covers_wcschr() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().filter(|n| n.contains("wcschr")).count() >= 2,
        "wcschr needs at least 2 test cases (found and not found)"
    );
}

#[test]
fn wide_string_ops_covers_wcsstr() {
    let fixture = load_fixture("wide_string_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("wcsstr")),
        "Missing test coverage for wcsstr"
    );
}

#[test]
fn wide_string_ops_modes_valid() {
    let fixture = load_fixture("wide_string_ops");
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
fn wide_string_ops_covers_hardened_mode() {
    let fixture = load_fixture("wide_string_ops");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");
    assert!(
        has_hardened,
        "wide_string_ops must have hardened mode test cases"
    );
}

#[test]
fn wide_string_ops_case_count_stable() {
    let fixture = load_fixture("wide_string_ops");
    assert!(
        fixture.cases.len() >= 10,
        "wide_string_ops fixture has {} cases, expected at least 10",
        fixture.cases.len()
    );
    eprintln!(
        "wide_string_ops fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn wide_string_ops_has_spec_references() {
    let fixture = load_fixture("wide_string_ops");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("ISO C") || case.spec_section.contains("TSM"),
            "Case {} spec_section should reference ISO C or TSM: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn wide_string_ops_error_codes_valid() {
    let fixture = load_fixture("wide_string_ops");

    // Wide string functions don't set errno
    for case in &fixture.cases {
        assert_eq!(
            case.expected_errno, 0,
            "Case {} has unexpected errno {} (wide string functions don't set errno)",
            case.name, case.expected_errno
        );
    }
}

#[test]
fn wide_string_ops_fixture_cases_match_execute_fixture_case() {
    let fixture = load_fixture("wide_string_ops");

    for case in &fixture.cases {
        let expected_output = case
            .expected_output
            .as_deref()
            .unwrap_or_else(|| panic!("case {} missing expected_output", case.name));
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result =
                execute_fixture_case(&case.function, &case.inputs, mode).unwrap_or_else(|err| {
                    panic!(
                        "fixture case {} ({mode}) failed to execute: {err}",
                        case.name
                    )
                });
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
}

// ---------------------------------------------------------------------------
// Isolated harness subprocess coverage (bd-jtix)
// ---------------------------------------------------------------------------
//
// Mirrors search_ops_conformance_test's harness-matrix path. Each fixture
// case is dispatched through `harness conformance-matrix-case`, which runs
// the differential executor in a subprocess so a panic / abort in one case
// can't destabilize the whole test process. This is the same code path the
// CI conformance matrix uses, so it catches packaging/dispatch regressions
// that the in-process executor can't see.

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
fn wide_string_ops_fixture_executes_with_host_parity_via_harness_matrix() {
    let fixture = load_fixture("wide_string_ops");

    for case in &fixture.cases {
        let expected_output = case
            .expected_output
            .as_deref()
            .unwrap_or_else(|| panic!("case {} missing expected_output", case.name));
        let modes: &[&str] = if case.mode.eq_ignore_ascii_case("both") {
            &["strict", "hardened"]
        } else {
            &[case.mode.as_str()]
        };

        for mode in modes {
            let result = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "wide_string_ops case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            assert!(
                result.host_parity || result.host_output == "UB",
                "wide_string_ops case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}",
                case.name,
                result.host_output,
                result.impl_output
            );
            assert_eq!(
                result.impl_output, expected_output,
                "wide_string_ops case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
}
