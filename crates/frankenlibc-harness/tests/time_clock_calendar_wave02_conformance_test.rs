//! Deterministic wave-02 time/clock calendar fixture tests.
//!
//! Run: cargo test -p frankenlibc-harness --test time_clock_calendar_wave02_conformance_test

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SECOND_WAVE_SYMBOLS: &[&str] = &[
    "gmtime_r",
    "localtime",
    "mktime",
    "nanosleep",
    "strptime",
    "timegm",
    "timespec_get",
    "timespec_getres",
    "timezone",
    "tzset",
];

const REQUIRED_LOG_FIELDS: &[&str] = &["symbol", "mode", "expected", "actual", "failure_signature"];
const AMBIENT_POLICY: &str = "forbid_host_wall_clock_timestamp_timezone_database_raw_environ_text_raw_pointer_pid_tid_stdout_stderr_capture";

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
}

fn load_fixture() -> Result<FixtureFile, String> {
    let path = repo_root()?.join("tests/conformance/fixtures/time_clock_calendar_wave02.json");
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
fn time_clock_calendar_wave02_fixture_exists_and_names_campaign() -> Result<(), String> {
    let path = repo_root()?.join("tests/conformance/fixtures/time_clock_calendar_wave02.json");
    assert!(
        path.exists(),
        "time_clock_calendar_wave02.json fixture must exist"
    );

    let fixture = load_fixture()?;
    assert_eq!(fixture.version, "v1");
    assert_eq!(fixture.family, "time/clock-calendar");
    assert_eq!(fixture.campaign.bead, "bd-gmbqy.7");
    assert_eq!(fixture.campaign.campaign_id, "fcq-time-clock-calendar");
    assert_eq!(fixture.campaign.wave_id, "wave-02-time-clock-calendar");
    assert_eq!(
        fixture.campaign.source_artifact,
        "tests/conformance/fixture_coverage_prioritizer.v1.json"
    );
    assert_eq!(fixture.campaign.ambient_state_policy, AMBIENT_POLICY);
    assert!(
        fixture
            .description
            .contains("fixed UTC caller-buffer conversions")
            && fixture.description.contains("UTC-only local calendar")
            && fixture.description.contains("normalized epoch conversion")
            && fixture.description.contains("zero-duration sleep")
            && fixture.description.contains("ISO strptime")
            && fixture.description.contains("C TIME_UTC")
            && fixture.description.contains("timezone global shape")
            && fixture.description.contains("host wall-clock values")
            && fixture.description.contains("raw timezone database text")
            && fixture.description.contains("raw TZ environment text")
            && fixture.description.contains("raw pointers")
            && fixture.description.contains("pids")
            && fixture.description.contains("tids")
            && fixture.description.contains("stdout")
            && fixture.description.contains("stderr"),
        "fixture description must reject ambient time/timezone capture"
    );
    Ok(())
}

#[test]
fn time_clock_calendar_wave02_covers_second_wave_in_both_modes() -> Result<(), String> {
    let fixture = load_fixture()?;
    let expected: BTreeSet<_> = SECOND_WAVE_SYMBOLS.iter().copied().collect();
    let declared: BTreeSet<_> = fixture
        .campaign
        .first_wave_symbols
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(declared, expected, "campaign first-wave symbol drift");
    assert!(
        fixture.campaign.residual_symbols.is_empty(),
        "time/clock calendar wave should not leave residual symbols"
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
            .unwrap_or_else(|| panic!("missing fixture cases for {symbol}"));
        assert!(modes.contains("strict"), "missing strict case for {symbol}");
        assert!(
            modes.contains("hardened"),
            "missing hardened case for {symbol}"
        );
    }
    Ok(())
}

#[test]
fn time_clock_calendar_wave02_logs_without_ambient_leaks() -> Result<(), String> {
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
            "expected_errno must stay classified"
        );
        assert!(
            case.expected_output.starts_with("symbol="),
            "case {} must use structured log output",
            case.name
        );
        for forbidden in [
            "0x",
            "/tmp/",
            "/usr/",
            "pid=",
            "tid=",
            "stdout=",
            "stderr=",
            "pointer=",
            "environ_text=",
            "tz=",
            "timezone=",
            "tv_sec=",
            "tv_nsec=",
            "elapsed",
            "wall_clock",
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
fn time_clock_calendar_wave02_spec_reference_names_required_surfaces() -> Result<(), String> {
    let fixture = load_fixture()?;
    for symbol in SECOND_WAVE_SYMBOLS {
        assert!(
            fixture.spec_reference.contains(symbol),
            "spec reference missing {symbol}"
        );
    }
    assert!(
        fixture.spec_reference.contains("POSIX")
            && fixture.spec_reference.contains("GNU")
            && fixture.spec_reference.contains("C11")
            && fixture.spec_reference.contains("C23"),
        "spec reference must name POSIX, GNU, C11, and C23 surfaces"
    );
    Ok(())
}

#[test]
fn time_clock_calendar_wave02_executes_via_isolated_harness() -> Result<(), String> {
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
            "fixture expected_output mismatch for {} ({})",
            case.name, case.mode
        );
        assert!(
            result.host_parity,
            "fixture case {} ({}) lost host parity: host={} impl={}",
            case.name, case.mode, result.host_output, result.impl_output
        );
    }
    Ok(())
}
