//! Deterministic wave-10 string/memory hot-path fixture tests.
//!
//! Run: cargo test -p frankenlibc-harness --test string_memory_hotpaths_wave10_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FIRST_WAVE_SYMBOLS: &[&str] = &[
    "argz_create",
    "bcmp",
    "bcopy",
    "bzero",
    "consttime_bcmp",
    "consttime_memequal",
    "explicit_bzero",
    "explicit_memset",
    "globfree",
    "index",
    "memccpy",
    "memmem",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str = "forbid_pointer_locale_or_process_buffer_capture";

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
    captured_at: String,
    description: String,
    spec_reference: String,
    campaign: Campaign,
    structured_log_fields: Vec<String>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Campaign {
    bead: String,
    campaign_id: String,
    wave_id: String,
    source_artifact: String,
    ambient_state_policy: String,
    first_wave_symbols: Vec<String>,
    residual_symbols: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureCase {
    name: String,
    function: String,
    spec_section: String,
    inputs: serde_json::Value,
    expected_output: String,
    expected_errno: i32,
    mode: String,
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

fn load_fixture() -> FixtureFile {
    let path = repo_root().join("tests/conformance/fixtures/string_memory_hotpaths_wave10.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
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
fn string_memory_hotpaths_wave10_fixture_exists_and_names_campaign() {
    let path = repo_root().join("tests/conformance/fixtures/string_memory_hotpaths_wave10.json");
    assert!(
        path.exists(),
        "string_memory_hotpaths_wave10.json fixture must exist"
    );

    let fixture = load_fixture();
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "string_memory_hotpaths_wave10");
    assert_eq!(fixture.campaign.bead, "pending-string-memory-wave10");
    assert_eq!(fixture.campaign.campaign_id, "fcq-string-memory-hotpaths");
    assert_eq!(fixture.campaign.wave_id, "wave-10-string-memory-hotpaths");
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    assert!(
        fixture.description.contains("without recording pointers")
            && fixture.description.contains("allocation addresses")
            && fixture.description.contains("errno buffers")
            && fixture.description.contains("file descriptors")
            && fixture.description.contains("process-global state"),
        "fixture description must reject ambient pointer/allocation/errno/fd/process capture"
    );
}

#[test]
fn string_memory_hotpaths_wave10_covers_first_wave_in_both_modes() {
    let fixture = load_fixture();
    let expected: BTreeSet<_> = FIRST_WAVE_SYMBOLS.iter().copied().collect();
    let declared: BTreeSet<_> = fixture
        .campaign
        .first_wave_symbols
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, expected, "campaign first-wave symbol drift");
    assert!(
        fixture.campaign.residual_symbols.is_empty(),
        "wave-10 fixture should not leave residual symbols"
    );

    let mut modes_by_symbol: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for case in &fixture.cases {
        modes_by_symbol
            .entry(case.function.as_str())
            .or_default()
            .insert(case.mode.as_str());
    }

    for symbol in FIRST_WAVE_SYMBOLS {
        let modes = modes_by_symbol
            .get(symbol)
            .unwrap_or_else(|| panic!("missing fixture cases for {symbol}"));
        assert!(modes.contains("strict"), "missing strict case for {symbol}");
        assert!(
            modes.contains("hardened"),
            "missing hardened case for {symbol}"
        );
    }
}

#[test]
fn string_memory_hotpaths_wave10_logs_without_ambient_leaks() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.structured_log_fields, REQUIRED_LOG_FIELDS,
        "structured log field contract drifted"
    );

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.spec_section.is_empty(), "case spec_section missing");
        assert_eq!(
            case.inputs["ambient_state_policy"].as_str(),
            Some(AMBIENT_POLICY),
            "case {} must state ambient policy",
            case.name
        );

        for forbidden in [
            "0x",
            "/tmp",
            "pointer",
            "address",
            "fd=",
            "errno_ptr",
            "locale_t",
        ] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} leaks ambient token {forbidden}",
                case.name
            );
        }
    }
}

#[test]
fn string_memory_hotpaths_wave10_spec_reference_names_required_surfaces() {
    let fixture = load_fixture();
    for token in FIRST_WAVE_SYMBOLS {
        assert!(
            fixture.spec_reference.contains(token),
            "spec reference must mention {token}"
        );
    }
}

#[test]
fn string_memory_hotpaths_wave10_executes_via_isolated_harness() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        let run = execute_case_via_harness(&case.function, &case.inputs, &case.mode)
            .unwrap_or_else(|err| panic!("{} failed isolated harness execution: {err}", case.name));
        assert_eq!(run.impl_output, case.expected_output, "impl log mismatch");
        assert_eq!(
            run.host_output, "SKIP",
            "wave-10 fixture should not use ambient host outputs for {}",
            case.name
        );
        assert!(run.host_parity, "case {} must preserve parity", case.name);
        assert!(
            run.note.is_none(),
            "case {} should not emit notes",
            case.name
        );
    }
}
