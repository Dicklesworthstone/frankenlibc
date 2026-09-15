//! Deterministic wave-05 residual fortify checked-wrapper fixture tests.
//!
//! Run: cargo test -p frankenlibc-harness --test fortify_checked_wrapper_wave05_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const WAVE05_SYMBOLS: &[&str] = &[
    "__printf_chk",
    "__wprintf_chk",
    "__wcstombs_chk",
    "__wcsrtombs_chk",
    "__wcsnrtombs_chk",
    "__wctomb_chk",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str =
    "forbid_raw_pointer_file_path_fd_stdout_stderr_pid_or_wall_clock_capture";

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
    #[allow(dead_code)]
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
}

fn load_fixture() -> Result<FixtureFile, String> {
    let path = repo_root()?.join("tests/conformance/fixtures/fortify_checked_wrapper_wave05.json");
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
        .env("FRANKENLIBC_MODE", mode)
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
fn fortify_checked_wrapper_wave05_fixture_exists_and_names_campaign() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/fortify_checked_wrapper_wave05.json");
    assert!(
        path.exists(),
        "fortify_checked_wrapper_wave05.json fixture must exist"
    );

    let fixture = load_fixture()?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "fortify/checked-wrapper");
    assert_eq!(
        fixture.campaign.bead, "bd-reality-202609-lx578q.6.1",
        "wave05 belongs to the replacement-integration bead"
    );
    assert_eq!(fixture.campaign.campaign_id, "fcq-fortify-bounds");
    assert_eq!(
        fixture.campaign.wave_id,
        "wave-05-fortify-checked-wrapper-conversions"
    );
    // The fifteen deferred members (the __v* variadic family needs a C
    // va_list forwarder shim; __syslog_chk needs a deterministic fl-syslog
    // scenario) are recorded explicitly so wave06 cannot silently drop one.
    let residual: BTreeSet<_> = fixture
        .campaign
        .residual_symbols
        .iter()
        .map(String::as_str)
        .collect();
    let expected_residual: BTreeSet<_> = [
        "__syslog_chk",
        "__vasprintf_chk",
        "__vdprintf_chk",
        "__vfprintf_chk",
        "__vfwprintf_chk",
        "__vprintf_chk",
        "__vsnprintf_chk",
        "__vsprintf_chk",
        "__vsyslog_chk",
        "__vwprintf_chk",
    ]
    .into_iter()
    .collect();
    assert_eq!(residual, expected_residual, "wave05 residual drift");
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    Ok(())
}

#[test]
fn fortify_checked_wrapper_wave05_covers_residual_symbols_in_both_modes() -> Result<(), String> {
    let fixture = load_fixture()?;
    let expected: BTreeSet<_> = WAVE05_SYMBOLS.iter().copied().collect();
    let declared: BTreeSet<_> = fixture
        .campaign
        .first_wave_symbols
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, expected, "wave05 symbol drift");

    let mut modes_by_symbol: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for case in &fixture.cases {
        modes_by_symbol
            .entry(case.function.as_str())
            .or_default()
            .insert(case.mode.as_str());
    }

    for symbol in WAVE05_SYMBOLS {
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
fn fortify_checked_wrapper_wave05_logs_without_ambient_leaks() -> Result<(), String> {
    let fixture = load_fixture()?;
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
        assert_eq!(
            case.expected_errno, 0,
            "expected_errno must stay classified; wave05 markers embed errno instead"
        );
        assert!(
            case.expected_output.starts_with("symbol="),
            "case {} must use structured log output",
            case.name
        );
        for forbidden in [
            "0x", "/tmp/", "/dev/", "pid=", "fd=", "stdout=", "stderr=", "FILE*", "elapsed",
        ] {
            assert!(
                !case.expected_output.contains(forbidden),
                "case {} leaked ambient token {forbidden}",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn fortify_checked_wrapper_wave05_respects_ambient_policy_scenarios() -> Result<(), String> {
    let fixture = load_fixture()?;
    // Wave05 scenarios are either capture-free replays (bad fds, constant
    // missing paths, bounded in-memory buffers) or explicitly CONTAINED
    // writes to the harness subprocess's own piped stdout, which the parent
    // collects and discards. Anything else would reintroduce the
    // contamination class bd-ug42ol measured.
    for case in &fixture.cases {
        let scenario = case.inputs["scenario"].as_str().unwrap_or_default();
        assert!(
            scenario.ends_with("_without_capture") || scenario.starts_with("contained_"),
            "case {} scenario {scenario:?} must be capture-free or contained",
            case.name
        );
    }
    Ok(())
}

#[test]
fn fortify_checked_wrapper_wave05_executes_via_isolated_harness() -> Result<(), String> {
    let fixture = load_fixture()?;
    for case in &fixture.cases {
        let result =
            execute_case_via_harness(&case.function, &case.inputs, &case.mode).map_err(|err| {
                format!(
                    "fixture case {} ({}) failed to execute: {err}",
                    case.name, case.mode
                )
            })?;
        assert_eq!(
            result.impl_output, case.expected_output,
            "fixture expected_output mismatch for {} ({}): impl={}",
            case.name, case.mode, result.impl_output
        );
        assert!(
            result.host_parity,
            "fixture case {} ({}) lost host parity: host={} impl={}",
            case.name, case.mode, result.host_output, result.impl_output
        );
    }
    Ok(())
}
