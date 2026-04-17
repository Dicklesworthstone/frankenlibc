//! Locale operations conformance test suite.
//!
//! Validates C11/POSIX locale functions: setlocale, localeconv, nl_langinfo, newlocale, uselocale, etc.
//! Run: cargo test -p frankenlibc-harness --test locale_ops_conformance_test

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
    host_output: String,
    impl_output: String,
    host_parity: bool,
    #[serde(default)]
    note: Option<String>,
}

fn load_fixture(name: &str) -> FixtureFile {
    let path = repo_root().join(format!("tests/conformance/fixtures/{name}.json"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
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
fn locale_ops_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/locale_ops.json");
    assert!(path.exists(), "locale_ops.json fixture must exist");
}

#[test]
fn locale_ops_fixture_valid_schema() {
    let fixture = load_fixture("locale_ops");

    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "locale_ops");
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: setlocale
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_setlocale() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("setlocale"))
            .count()
            >= 3,
        "setlocale needs at least 3 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: localeconv
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_localeconv() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names.iter().any(|name| name.contains("localeconv")),
        "Missing test coverage for localeconv"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: nl_langinfo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_nl_langinfo() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    assert!(
        case_names
            .iter()
            .filter(|n| n.contains("nl_langinfo"))
            .count()
            >= 2,
        "nl_langinfo needs at least 2 test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Coverage validation: POSIX.1-2008 locale functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_posix_2008_functions() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    let patterns = ["newlocale", "uselocale", "duplocale", "freelocale"];

    for pattern in patterns {
        assert!(
            case_names.iter().any(|name| name.contains(pattern)),
            "Missing test coverage for POSIX.1-2008 function: {}",
            pattern
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error code validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_error_codes_valid() {
    let fixture = load_fixture("locale_ops");

    // locale functions typically don't set errno, or use EINVAL
    let valid_errno_values = [
        0,  // Success
        22, // EINVAL
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_modes_valid() {
    let fixture = load_fixture("locale_ops");

    for case in &fixture.cases {
        assert!(
            case.mode == "both" || case.mode == "strict" || case.mode == "hardened",
            "Case {} has invalid mode: {} (expected 'both', 'strict', or 'hardened')",
            case.name,
            case.mode
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode coverage: both strict and hardened are tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_both_modes() {
    let fixture = load_fixture("locale_ops");

    let has_strict = fixture.cases.iter().any(|c| c.mode == "strict");
    let has_hardened = fixture.cases.iter().any(|c| c.mode == "hardened");

    assert!(has_strict, "locale_ops must have strict mode test cases");
    assert!(
        has_hardened,
        "locale_ops must have hardened mode test cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Case count stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_case_count_stable() {
    let fixture = load_fixture("locale_ops");

    const EXPECTED_MIN_CASES: usize = 15;

    assert!(
        fixture.cases.len() >= EXPECTED_MIN_CASES,
        "locale_ops fixture has {} cases, expected at least {}",
        fixture.cases.len(),
        EXPECTED_MIN_CASES
    );

    eprintln!("locale_ops fixture has {} test cases", fixture.cases.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened fallback coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_covers_hardened_fallbacks() {
    let fixture = load_fixture("locale_ops");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();

    // Hardened mode should test unsupported/unknown locale fallbacks
    assert!(
        case_names
            .iter()
            .any(|n| n.contains("unsupported") || n.contains("unknown")),
        "locale_ops must test unsupported locale fallbacks in hardened mode"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Spec compliance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_ops_has_spec_references() {
    let fixture = load_fixture("locale_ops");

    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("C11") || case.spec_section.contains("POSIX"),
            "Case {} spec_section should reference C11 or POSIX: {}",
            case.name,
            case.spec_section
        );
    }
}

#[test]
fn locale_ops_fixture_executes_mode_specific_contracts() {
    let fixture = load_fixture("locale_ops");

    for mode in ["strict", "hardened"] {
        let expected_cases = fixture
            .cases
            .iter()
            .filter(|case| case.mode == mode || case.mode == "both")
            .count();
        let cases: Vec<_> = fixture
            .cases
            .iter()
            .filter(|case| case.mode == mode || case.mode == "both")
            .collect();

        assert_eq!(
            cases.len(),
            expected_cases,
            "{mode} run should include every matching locale_ops fixture case"
        );
        assert!(
            !cases.is_empty(),
            "{mode} run should have at least one locale_ops fixture case"
        );

        for case in cases {
            let execution = execute_case_via_harness(&case.function, &case.inputs, mode)
                .unwrap_or_else(|err| {
                    panic!(
                        "{mode} case {} failed to execute through harness subprocess: {}",
                        case.name, err
                    )
                });
            let expected_output = case
                .expected_output
                .as_deref()
                .unwrap_or_else(|| panic!("case {} missing expected_output", case.name));
            assert_eq!(
                execution.impl_output, expected_output,
                "{mode} case {} returned unexpected impl output (host={}, note={:?})",
                case.name, execution.host_output, execution.note
            );

            let expects_hardened_note = mode == "hardened"
                && (case.name.contains("unsupported") || case.name.contains("unknown"));

            if mode == "strict" {
                assert!(
                    execution.host_parity,
                    "{mode} case {} lost host parity: host={}, impl={}, note={:?}",
                    case.name, execution.host_output, execution.impl_output, execution.note
                );
                assert!(
                    execution.note.is_none(),
                    "{mode} case {} emitted unexpected strict note: {:?}",
                    case.name,
                    execution.note
                );
                continue;
            }

            match execution.note.as_deref() {
                None => {
                    assert!(
                        !expects_hardened_note,
                        "{mode} case {} should explain its hardened fallback",
                        case.name
                    );
                }
                Some(note) => {
                    assert!(
                        expects_hardened_note,
                        "{mode} case {} emitted an unexpected note: {}",
                        case.name, note
                    );
                    assert!(
                        note.contains("hardened mode")
                            || note.contains("falls back")
                            || note.contains("safe empty default"),
                        "{mode} case {} note should describe hardened fallback behavior: {}",
                        case.name,
                        note
                    );
                }
            }
        }
    }
}
