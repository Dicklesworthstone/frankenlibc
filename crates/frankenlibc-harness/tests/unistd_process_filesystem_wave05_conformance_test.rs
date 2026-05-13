//! Deterministic wave-05 unistd/process/filesystem argp/codeset/process fixture tests.
//!
//! Run: cargo test -p frankenlibc-harness --test unistd_process_filesystem_wave05_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FIRST_WAVE_SYMBOLS: &[&str] = &[
    "argp_parse",
    "argp_state_help",
    "argp_usage",
    "bind_textdomain_codeset",
    "brk",
    "bsd_signal",
    "c8rtomb",
    "canonicalize_file_name",
    "capget",
    "capset",
    "chdir",
    "chmod",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str =
    "forbid_ambient_argv_textdomain_heap_signal_path_cwd_capability_or_mode_metadata";

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
    let path = repo_root().join("tests/conformance/fixtures/unistd_process_filesystem_wave05.json");
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
fn unistd_process_filesystem_wave05_fixture_exists_and_names_campaign() {
    let path = repo_root().join("tests/conformance/fixtures/unistd_process_filesystem_wave05.json");
    assert!(
        path.exists(),
        "unistd_process_filesystem_wave05.json fixture must exist"
    );

    let fixture = load_fixture();
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "unistd/process-filesystem");
    assert_eq!(
        fixture.campaign.bead,
        "tracker-blocked-empty-queue-discovery"
    );
    assert_eq!(
        fixture.campaign.campaign_id,
        "fcq-unistd-process-filesystem"
    );
    assert_eq!(
        fixture.campaign.wave_id,
        "wave-05-unistd-process-filesystem-argp-codeset-process-fd"
    );
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    assert!(
        fixture
            .description
            .contains("without recording argv addresses")
            && fixture.description.contains("heap break addresses")
            && fixture.description.contains("capability bits")
            && fixture.description.contains("cwd")
            && fixture.description.contains("file modes"),
        "fixture description must reject ambient argv/heap/signal/cwd/capability/mode capture"
    );
}

#[test]
fn unistd_process_filesystem_wave05_covers_first_wave_in_both_modes() {
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
        "wave-05 fixture should not leave residual symbols"
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
fn unistd_process_filesystem_wave05_logs_without_ambient_leaks() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.structured_log_fields, REQUIRED_LOG_FIELDS,
        "structured log field contract drifted"
    );

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.spec_section.is_empty(), "case spec_section missing");
        assert_eq!(case.expected_errno, 0, "fixture should not expose errno");
        assert!(
            case.mode == "strict" || case.mode == "hardened",
            "case {} has unsupported mode {}",
            case.name,
            case.mode
        );

        let inputs = case
            .inputs
            .as_object()
            .unwrap_or_else(|| panic!("case {} inputs must be an object", case.name));
        for field in [
            "symbol",
            "scenario",
            "expected",
            "oracle_source",
            "ambient_state_policy",
        ] {
            assert!(
                inputs
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some(),
                "case {} missing string inputs.{field}",
                case.name
            );
        }
        assert_eq!(
            inputs["symbol"].as_str(),
            Some(case.function.as_str()),
            "case {} inputs.symbol must match function",
            case.name
        );
        assert_eq!(
            inputs["ambient_state_policy"].as_str(),
            Some(AMBIENT_POLICY),
            "case {} ambient-state policy drifted",
            case.name
        );

        for field in REQUIRED_LOG_FIELDS {
            assert!(
                case.expected_output.contains(&format!("{field}=")),
                "case {} expected_output missing {field}",
                case.name
            );
        }
        for forbidden in [
            "0x",
            "ptr=",
            "address",
            "pid=",
            "fd=",
            "inode",
            "dev=",
            "/tmp",
            "thread=",
            "timestamp",
            "tv_sec",
            "time_offset",
            "scheduler",
            "cwd=",
            "capability=",
            "file_mode",
            "mode=0o",
            "path=",
        ] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} expected_output leaks ambient detail {forbidden}",
                case.name
            );
        }
    }
}

#[test]
fn unistd_process_filesystem_wave05_spec_reference_names_required_surfaces() {
    let fixture = load_fixture();
    assert!(
        fixture.spec_reference.contains("GNU argp")
            && fixture.spec_reference.contains("gettext")
            && fixture.spec_reference.contains("Linux brk")
            && fixture.spec_reference.contains("BSD bsd_signal")
            && fixture.spec_reference.contains("C23 c8rtomb")
            && fixture
                .spec_reference
                .contains("GNU canonicalize_file_name")
            && fixture.spec_reference.contains("POSIX chdir/chmod"),
        "fixture must bind GNU/gettext/Linux/BSD/C23/POSIX wave-05 semantics"
    );
}

#[test]
fn unistd_process_filesystem_wave05_executes_via_isolated_harness() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.cases.len(),
        FIRST_WAVE_SYMBOLS.len() * 2,
        "fixture should include strict+hardened rows for every first-wave symbol"
    );

    for case in &fixture.cases {
        let result = execute_case_via_harness(&case.function, &case.inputs, &case.mode)
            .unwrap_or_else(|err| {
                panic!(
                    "unistd process/filesystem wave-05 case {} ({}) failed via harness: {err}",
                    case.name, case.mode
                )
            });
        assert_eq!(
            result.impl_output, case.expected_output,
            "fixture expected_output mismatch for {} ({})",
            case.name, case.mode
        );
        assert_eq!(
            result.host_output, "SKIP",
            "wave-05 fixture should not use ambient host outputs for {}",
            case.name
        );
        assert!(result.host_parity, "fixture executor reported failure");
        assert!(result.note.is_none(), "unexpected fixture note drift");
    }
}
