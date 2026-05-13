//! Deterministic wave-02 pthread rwlock, TLS, and cancellation fixture tests.
//!
//! Run: cargo test -p frankenlibc-harness --test pthread_sync_wave02_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SECOND_WAVE_SYMBOLS: &[&str] = &[
    "__pthread_register_cancel_defer",
    "__pthread_rwlock_destroy",
    "__pthread_rwlock_init",
    "__pthread_rwlock_rdlock",
    "__pthread_rwlock_tryrdlock",
    "__pthread_rwlock_trywrlock",
    "__pthread_rwlock_unlock",
    "__pthread_rwlock_wrlock",
    "__pthread_setspecific",
    "__pthread_unregister_cancel",
    "__pthread_unregister_cancel_restore",
    "__pthread_unwind_next",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str = "forbid_pthread_object_address_native_thread_id_scheduler_timing_stderr_or_global_counter_capture";

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir.parent().ok_or_else(|| {
        format!(
            "harness manifest directory has no parent: {}",
            manifest_dir.display()
        )
    })?;
    crate_dir.parent().map(Path::to_path_buf).ok_or_else(|| {
        format!(
            "harness crate directory has no parent: {}",
            crate_dir.display()
        )
    })
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

fn load_fixture() -> Result<FixtureFile, String> {
    let path = repo_root()?.join("tests/conformance/fixtures/pthread_sync_wave02.json");
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("invalid JSON in {}: {err}", path.display()))
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
fn pthread_sync_wave02_fixture_exists_and_names_campaign() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/pthread_sync_wave02.json");
    assert!(path.exists(), "pthread_sync_wave02.json fixture must exist");

    let fixture = load_fixture()?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "pthread/sync");
    assert_eq!(fixture.campaign.bead, "bd-uivdf");
    assert_eq!(fixture.campaign.campaign_id, "fcq-pthread-sync");
    assert_eq!(
        fixture.campaign.wave_id,
        "wave-02-pthread-rwlock-cancel-alias-state"
    );
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    assert!(
        fixture.description.contains("rwlock")
            && fixture.description.contains("cancellation")
            && fixture
                .description
                .contains("without recording pthread object addresses")
            && fixture.description.contains("native thread ids")
            && fixture.description.contains("scheduler timing")
            && fixture.description.contains("stderr bytes")
            && fixture.description.contains("process-global counters"),
        "fixture description must reject ambient pthread metadata capture"
    );
    Ok(())
}

#[test]
fn pthread_sync_wave02_covers_second_wave_in_both_modes() -> Result<(), String> {
    let fixture = load_fixture()?;
    let expected: BTreeSet<_> = SECOND_WAVE_SYMBOLS.iter().copied().collect();
    let declared: BTreeSet<_> = fixture
        .campaign
        .first_wave_symbols
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, expected, "campaign second-wave symbol drift");
    assert!(
        fixture.campaign.residual_symbols.is_empty(),
        "wave-02 fixture should not leave residual symbols"
    );

    let mut modes_by_symbol: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for case in &fixture.cases {
        modes_by_symbol
            .entry(case.function.as_str())
            .or_default()
            .insert(case.mode.as_str());
    }

    for symbol in SECOND_WAVE_SYMBOLS {
        let modes = modes_by_symbol
            .get(symbol)
            .ok_or_else(|| format!("missing fixture cases for {symbol}"))?;
        assert!(modes.contains("strict"), "missing strict case for {symbol}");
        assert!(
            modes.contains("hardened"),
            "missing hardened case for {symbol}"
        );
    }
    Ok(())
}

#[test]
fn pthread_sync_wave02_logs_without_ambient_leaks() -> Result<(), String> {
    let fixture = load_fixture()?;
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
            .ok_or_else(|| format!("case {} inputs must be an object", case.name))?;
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
            inputs.get("symbol").and_then(serde_json::Value::as_str),
            Some(case.function.as_str()),
            "case {} inputs.symbol must match function",
            case.name
        );
        assert_eq!(
            inputs
                .get("ambient_state_policy")
                .and_then(serde_json::Value::as_str),
            Some(AMBIENT_POLICY),
            "case {} ambient-state policy drifted",
            case.name
        );

        for field_prefix in [
            "symbol=",
            "mode=",
            "expected=",
            "actual=",
            "failure_signature=",
        ] {
            assert!(
                case.expected_output.contains(field_prefix),
                "case {} expected_output missing {}",
                case.name,
                field_prefix.trim_end_matches('=')
            );
        }
        for forbidden in [
            "0x",
            "addr",
            "address",
            "pthread_t=",
            "tid=",
            "thread=",
            "scheduler",
            "timing",
            "stderr=",
            "counter=",
            "global=",
            "path=",
            "timestamp",
        ] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} expected_output leaks ambient pthread detail {forbidden}",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn pthread_sync_wave02_spec_reference_names_required_surfaces() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert!(
        fixture.spec_reference.contains("POSIX pthread")
            && fixture.spec_reference.contains("__pthread_rwlock_init")
            && fixture.spec_reference.contains("__pthread_rwlock_wrlock")
            && fixture.spec_reference.contains("__pthread_setspecific")
            && fixture.spec_reference.contains("cancellation")
            && fixture.spec_reference.contains("__pthread_unwind_next"),
        "fixture must bind pthread rwlock aliases, TLS setspecific, and cancellation stubs"
    );
    Ok(())
}

#[test]
fn pthread_sync_wave02_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert_eq!(
        fixture.cases.len(),
        SECOND_WAVE_SYMBOLS.len() * 2,
        "fixture should include strict+hardened rows for every second-wave symbol"
    );

    for case in &fixture.cases {
        let result =
            execute_case_via_harness(&case.function, &case.inputs, &case.mode).map_err(|err| {
                format!(
                    "pthread sync wave-02 case {} ({}) failed via harness: {err}",
                    case.name, case.mode
                )
            })?;
        assert_eq!(
            result.impl_output, case.expected_output,
            "fixture expected_output mismatch for {} ({})",
            case.name, case.mode
        );
        assert_eq!(
            result.host_output, "SKIP",
            "wave-02 fixture should not use ambient host outputs for {}",
            case.name
        );
        assert!(result.host_parity, "fixture executor reported failure");
        assert!(result.note.is_none(), "unexpected fixture note drift");
    }
    Ok(())
}
