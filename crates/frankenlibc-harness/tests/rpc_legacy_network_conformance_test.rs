//! RPC legacy-network deterministic fixture coverage for bd-mu4lw.1.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FIRST_WAVE_SYMBOLS: &[&str] = &[
    "__rpc_thread_createerr",
    "__rpc_thread_svc_fdset",
    "__rpc_thread_svc_max_pollfd",
    "__rpc_thread_svc_pollfd",
    "_authenticate",
    "_null_auth",
    "_rpc_dtablesize",
    "_seterr_reply",
    "authdes_create",
    "authdes_getucred",
    "authdes_pk_create",
    "authnone_create",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "symbol",
    "mode",
    "expected_class",
    "actual",
    "failure_signature",
];

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
    source_artifact: String,
    source_lines: String,
    first_wave_symbols: Vec<String>,
    network_access: String,
    oracle_source: String,
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
    let path = repo_root().join("tests/conformance/fixtures/rpc_legacy_network.json");
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
fn rpc_legacy_network_fixture_exists_and_names_campaign() {
    let path = repo_root().join("tests/conformance/fixtures/rpc_legacy_network.json");
    assert!(path.exists(), "rpc_legacy_network.json fixture must exist");

    let fixture = load_fixture();
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "rpc/legacy-network");
    assert_eq!(fixture.campaign.bead, "bd-mu4lw.1");
    assert_eq!(fixture.campaign.campaign_id, "fcq-rpc-legacy-network");
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.network_access, "forbidden");
    assert!(
        fixture.description.contains("without network access"),
        "fixture description must forbid ambient network dependence"
    );
}

#[test]
fn rpc_legacy_network_fixture_covers_first_wave_symbols_in_both_modes() {
    let fixture = load_fixture();
    let expected: BTreeSet<_> = FIRST_WAVE_SYMBOLS.iter().copied().collect();
    let declared: BTreeSet<_> = fixture
        .campaign
        .first_wave_symbols
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, expected, "campaign first-wave symbol drift");

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
fn rpc_legacy_network_cases_bind_expected_behavior_and_log_fields() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.structured_log_fields, REQUIRED_LOG_FIELDS,
        "structured log field contract drifted"
    );

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.spec_section.is_empty(), "case spec_section missing");
        assert_eq!(case.expected_errno, 0, "RPC fixtures do not set errno");
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
            "expected_class",
            "strict_behavior",
            "hardened_behavior",
            "safe_default_rationale",
            "oracle_source",
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

        for field in REQUIRED_LOG_FIELDS {
            let token = format!("{field}=");
            assert!(
                case.expected_output.contains(&token),
                "case {} expected_output missing structured token {token}",
                case.name
            );
        }
    }
}

#[test]
fn rpc_legacy_network_fixture_executes_via_isolated_harness() {
    let fixture = load_fixture();

    for case in &fixture.cases {
        let result = execute_case_via_harness(&case.function, &case.inputs, &case.mode)
            .unwrap_or_else(|err| {
                panic!(
                    "rpc_legacy_network case {} ({}) failed via harness: {err}",
                    case.name, case.mode
                )
            });
        assert!(
            result.host_parity,
            "case {} lost deterministic fixture parity: host_output={}",
            case.name, result.host_output
        );
        assert_eq!(
            result.impl_output, case.expected_output,
            "case {} ({}) fixture output mismatch",
            case.name, case.mode
        );
        assert!(
            result
                .note
                .as_deref()
                .unwrap_or_default()
                .contains("ambient host RPC state is intentionally not consulted"),
            "case {} should document host RPC isolation",
            case.name
        );
    }
}
