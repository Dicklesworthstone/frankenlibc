//! Loader edges conformance test suite.
//!
//! Validates ELF loader edge cases: dlopen, dlsym, dlclose, dladdr, dlinfo.
//! Run: cargo test -p frankenlibc-harness --test loader_edges_conformance_test

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

#[test]
fn loader_edges_fixture_exists() {
    let path = repo_root().join("tests/conformance/fixtures/loader_edges.json");
    assert!(path.exists(), "loader_edges.json fixture must exist");
}

#[test]
fn loader_edges_fixture_valid_schema() {
    let fixture = load_fixture("loader_edges");
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "loader_edges");
    assert!(!fixture.cases.is_empty(), "Must have test cases");
    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "Case name must not be empty");
        assert!(!case.function.is_empty(), "Function must not be empty");
    }
}

#[test]
fn loader_edges_covers_dlopen() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlopen")),
        "Missing test coverage for dlopen"
    );
}

#[test]
fn loader_edges_covers_dlsym() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlsym")),
        "Missing test coverage for dlsym"
    );
}

#[test]
fn loader_edges_covers_dlclose() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlclose")),
        "Missing test coverage for dlclose"
    );
}

#[test]
fn loader_edges_covers_dladdr() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dladdr")),
        "Missing test coverage for dladdr"
    );
}

#[test]
fn loader_edges_covers_dlinfo() {
    let fixture = load_fixture("loader_edges");
    let case_names: Vec<&str> = fixture.cases.iter().map(|c| c.name.as_str()).collect();
    assert!(
        case_names.iter().any(|n| n.contains("dlinfo")),
        "Missing test coverage for dlinfo"
    );
}

#[test]
fn loader_edges_has_strict_and_hardened() {
    let fixture = load_fixture("loader_edges");
    let strict_count = fixture.cases.iter().filter(|c| c.mode == "strict").count();
    let hardened_count = fixture
        .cases
        .iter()
        .filter(|c| c.mode == "hardened")
        .count();
    assert!(
        strict_count >= 1,
        "loader_edges needs at least 1 strict mode case"
    );
    assert!(
        hardened_count >= 1,
        "loader_edges needs at least 1 hardened mode case"
    );
}

#[test]
fn loader_edges_modes_valid() {
    let fixture = load_fixture("loader_edges");
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
fn loader_edges_case_count_stable() {
    let fixture = load_fixture("loader_edges");
    assert!(
        fixture.cases.len() >= 5,
        "loader_edges fixture has {} cases, expected at least 5",
        fixture.cases.len()
    );
    eprintln!(
        "loader_edges fixture has {} test cases",
        fixture.cases.len()
    );
}

#[test]
fn loader_edges_has_spec_references() {
    let fixture = load_fixture("loader_edges");
    for case in &fixture.cases {
        assert!(
            case.spec_section.contains("POSIX") || case.spec_section.contains("GNU"),
            "Case {} spec_section should reference POSIX or GNU: {}",
            case.name,
            case.spec_section
        );
    }
}

/// Normalize a fixture's `expected_output` JSON value (which may be a
/// string, number, or boolean) to the string form the differential
/// executor emits, so the comparison matches across case types.
fn expected_output_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Returns true when the fixture case's note marks its outcome as
/// POSIX "implementation-defined" or undefined behavior. For those
/// cases we still assert `impl_output == expected_output` (FrankenLibC
/// picks a deterministic answer) but we do NOT require host libc to
/// agree — glibc may legally return a different value.
fn case_note_indicates_impl_defined(note: &str) -> bool {
    let lower = note.to_ascii_lowercase();
    lower.contains("implementation-defined")
        || lower.contains("undefined behavior")
        || lower.starts_with("hardened:")
}

/// Cases with an outstanding implementation gap in frankenlibc. The
/// harness-matrix path records the gap rather than failing so the
/// dispatch/packaging coverage stays green; the underlying gap is
/// tracked in its own bead.
const KNOWN_IMPL_GAPS: &[(&str, &str)] = &[];

fn case_is_known_impl_gap(name: &str) -> Option<&'static str> {
    KNOWN_IMPL_GAPS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, bead)| *bead)
}

#[test]
fn loader_edges_fixture_cases_match_execute_fixture_case() {
    // In-process oracle: dispatches each case through the shared
    // `frankenlibc_fixture_exec` helper. Cases with a tracked
    // implementation gap (see KNOWN_IMPL_GAPS) are skipped here and
    // logged so dispatch coverage still runs.
    let fixture = load_fixture("loader_edges");

    for case in &fixture.cases {
        if let Some(bead) = case_is_known_impl_gap(&case.name) {
            eprintln!("skip {} — tracked implementation gap ({bead})", case.name);
            continue;
        }
        let expected_output = case
            .expected_output
            .as_ref()
            .map(expected_output_to_string)
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
                result.host_parity
                    || result.host_output == "UB"
                    || case_note_indicates_impl_defined(&case.note),
                "defined host behavior diverged for {} ({mode}): host={}, impl={}, note={:?}",
                case.name,
                result.host_output,
                result.impl_output,
                case.note
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Isolated harness subprocess coverage (bd-k2d8)
// ---------------------------------------------------------------------------
//
// Each fixture case is also dispatched through the
// `harness conformance-matrix-case` subprocess that the CI conformance
// matrix uses, so packaging/dispatch regressions surface here even when
// the in-process executor still passes.

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
fn loader_edges_fixture_executes_with_host_parity_via_harness_matrix() {
    let fixture = load_fixture("loader_edges");

    for case in &fixture.cases {
        if let Some(bead) = case_is_known_impl_gap(&case.name) {
            eprintln!("skip {} — tracked implementation gap ({bead})", case.name);
            continue;
        }
        let expected_output = case
            .expected_output
            .as_ref()
            .map(expected_output_to_string)
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
                        "loader_edges case {} ({mode}) failed to execute via harness: {err}",
                        case.name
                    )
                });
            assert!(
                result.host_parity
                    || result.host_output == "UB"
                    || case_note_indicates_impl_defined(&case.note),
                "loader_edges case {} ({mode}) lost host parity via harness: host_output={}, impl_output={}, note={:?}",
                case.name,
                result.host_output,
                result.impl_output,
                case.note
            );
            assert_eq!(
                result.impl_output, expected_output,
                "loader_edges case {} ({mode}) mismatched fixture output via harness",
                case.name
            );
        }
    }
}
