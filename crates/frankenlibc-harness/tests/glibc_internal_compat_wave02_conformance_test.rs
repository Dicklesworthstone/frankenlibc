//! Deterministic glibc-internal compatibility fixture wave-02 tests.
//!
//! Run: cargo test -p frankenlibc-harness --test glibc_internal_compat_wave02_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FIRST_WAVE_SYMBOLS: &[&str] = &[
    "_IO_enable_locks",
    "__abort_msg",
    "__adjtimex",
    "__after_morecore_hook",
    "__arch_prctl",
    "__asprintf",
    "__b64_ntop",
    "__b64_pton",
    "__backtrace",
    "__backtrace_symbols",
    "__backtrace_symbols_fd",
    "__bsd_getpgrp",
];

const SUPPORTED_SYMBOLS: &[&str] = &["_IO_enable_locks", "__b64_ntop", "__b64_pton"];
const DETERMINISTIC_FALLBACK_SYMBOLS: &[&str] = &[
    "__abort_msg",
    "__adjtimex",
    "__after_morecore_hook",
    "__arch_prctl",
    "__asprintf",
    "__backtrace",
    "__backtrace_symbols",
    "__backtrace_symbols_fd",
    "__bsd_getpgrp",
];
const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str =
    "forbid_pointer_address_frame_path_stderr_pid_timing_global_diagnostic_capture";

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
    symbol_groups: SymbolGroups,
    first_wave_symbols: Vec<String>,
    residual_symbols: Vec<String>,
    deferred_ambient_symbols: Vec<DeferredSymbol>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SymbolGroups {
    supported: Vec<String>,
    deterministic_fallback: Vec<String>,
    claim_blocked: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DeferredSymbol {
    symbol: String,
    reason: String,
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
    let path = repo_root()?.join("tests/conformance/fixtures/glibc_internal_compat_wave02.json");
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
fn glibc_internal_compat_wave02_fixture_exists_and_names_campaign() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/glibc_internal_compat_wave02.json");
    assert!(
        path.exists(),
        "glibc_internal_compat_wave02.json fixture must exist"
    );

    let fixture = load_fixture()?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "glibc/internal-compat");
    assert_eq!(fixture.campaign.bead, "bd-r5k32.13");
    assert_eq!(fixture.campaign.campaign_id, "fcq-glibc-internal-compat");
    assert_eq!(
        fixture.campaign.wave_id,
        "wave-02-glibc-internal-compat-deterministic-diagnostics"
    );
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    assert!(
        fixture.description.contains("no-op")
            && fixture.description.contains("static null-state")
            && fixture.description.contains("invalid-argument errno")
            && fixture.description.contains("zero-frame diagnostic")
            && fixture.description.contains("base64 helper")
            && fixture
                .description
                .contains("without recording pointer values")
            && fixture.description.contains("stack frames")
            && fixture.description.contains("host paths")
            && fixture.description.contains("stderr bytes")
            && fixture.description.contains("pid values")
            && fixture.description.contains("timing")
            && fixture
                .description
                .contains("process-global diagnostic text"),
        "fixture description must reject ambient glibc-internal diagnostic capture"
    );
    Ok(())
}

#[test]
fn glibc_internal_compat_wave02_covers_slice_in_both_modes() -> Result<(), String> {
    let fixture = load_fixture()?;
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
        "wave should not leave residual symbols inside its selected slice"
    );
    assert!(
        fixture.campaign.deferred_ambient_symbols.is_empty(),
        "wave should classify every selected symbol instead of deferring it"
    );

    let supported: BTreeSet<_> = fixture
        .campaign
        .symbol_groups
        .supported
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        supported,
        SUPPORTED_SYMBOLS.iter().copied().collect(),
        "supported symbol group drifted"
    );
    let deterministic_fallback: BTreeSet<_> = fixture
        .campaign
        .symbol_groups
        .deterministic_fallback
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        deterministic_fallback,
        DETERMINISTIC_FALLBACK_SYMBOLS.iter().copied().collect(),
        "deterministic fallback group drifted"
    );
    assert!(
        fixture.campaign.symbol_groups.claim_blocked.is_empty(),
        "wave should not claim-block any selected symbol"
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
fn glibc_internal_compat_wave02_logs_without_ambient_leaks() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert_eq!(
        fixture.structured_log_fields, REQUIRED_LOG_FIELDS,
        "structured log field contract drifted"
    );

    for case in &fixture.cases {
        assert!(!case.name.is_empty(), "case name must not be empty");
        assert!(!case.spec_section.is_empty(), "case spec_section missing");
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

        for field in REQUIRED_LOG_FIELDS {
            assert!(
                case.expected_output.contains(&format!("{field}=")),
                "case {} expected_output missing {field}",
                case.name
            );
        }
        for forbidden in [
            "0x",
            "address=",
            "pointer=",
            "pc=",
            "frame=",
            "pid=",
            "tid=",
            "thread=",
            "stderr=",
            "global=",
            "path=",
            "timestamp",
            "diagnostic=",
        ] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} expected_output leaks ambient glibc-internal detail {forbidden}",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn glibc_internal_compat_wave02_spec_reference_names_required_surfaces() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert!(
        fixture.spec_reference.contains("glibc internal")
            && fixture.spec_reference.contains("_IO_enable_locks")
            && fixture.spec_reference.contains("__abort_msg")
            && fixture.spec_reference.contains("__adjtimex")
            && fixture.spec_reference.contains("__after_morecore_hook")
            && fixture.spec_reference.contains("__arch_prctl")
            && fixture.spec_reference.contains("__asprintf")
            && fixture.spec_reference.contains("__b64_ntop")
            && fixture.spec_reference.contains("__b64_pton")
            && fixture.spec_reference.contains("__backtrace")
            && fixture.spec_reference.contains("__backtrace_symbols")
            && fixture.spec_reference.contains("__backtrace_symbols_fd")
            && fixture.spec_reference.contains("__bsd_getpgrp"),
        "fixture must bind glibc-internal wave-02 diagnostics and helper surfaces"
    );
    Ok(())
}

#[test]
fn glibc_internal_compat_wave02_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture()?;
    assert_eq!(
        fixture.cases.len(),
        FIRST_WAVE_SYMBOLS.len() * 2,
        "fixture should include strict+hardened rows for every selected symbol"
    );

    for case in &fixture.cases {
        let result =
            execute_case_via_harness(&case.function, &case.inputs, &case.mode).map_err(|err| {
                format!(
                    "glibc internal compat wave-02 case {} ({}) failed via harness: {err}",
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
            "compat fixture should not use ambient host outputs for {}",
            case.name
        );
        assert!(result.host_parity, "fixture executor reported failure");
        assert!(result.note.is_none(), "unexpected fixture note drift");
    }
    Ok(())
}
