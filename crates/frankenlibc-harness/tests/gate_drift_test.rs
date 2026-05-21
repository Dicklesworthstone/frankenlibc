//! WS-0 gate-drift monitor tests for bd-3yr14.4.

use frankenlibc_harness::gate_drift::{GateDriftConfig, GateObservation, evaluate_gate_drift};
use serde_json::{Value, json};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_gate_drift.sh")
}

fn canonical_series_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/gate_drift_series.v1.json")
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("gate-drift-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn observation(
    gate: &str,
    passed: bool,
    expected_passed: bool,
    code_delta: bool,
) -> GateObservation {
    GateObservation {
        gate: gate.to_string(),
        passed,
        expected_passed,
        code_delta,
    }
}

fn run_checker(root: &Path, series: &Path, report: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_GATE_DRIFT_SERIES", series)
        .env("FRANKENLIBC_GATE_DRIFT_REPORT", report)
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_series(path: &Path, observations: Vec<Value>) -> TestResult {
    let series = json!({
        "schema_version": "gate_drift_series.v1",
        "streams": [
            {
                "gate": "synthetic_gate",
                "observations": observations
            }
        ]
    });
    fs::write(path, serde_json::to_string_pretty(&series)? + "\n")?;
    Ok(())
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn rust_monitor_flags_uncorrelated_gate_pass_rate_jump() {
    let stable = (0..200).map(|_| observation("synthetic_gate", false, false, false));
    let suspicious = (0..100).map(|_| observation("synthetic_gate", true, false, false));
    let summary = evaluate_gate_drift(GateDriftConfig::default(), stable.chain(suspicious));
    assert_eq!(summary.flagged_gates, 1);
    assert_eq!(summary.gates[0].gate, "synthetic_gate");
    assert!(summary.gates[0].flagged);
    assert_eq!(summary.gates[0].uncorrelated_shifts, 100);
}

#[test]
fn rust_monitor_accepts_code_correlated_change() {
    let stable = (0..200).map(|_| observation("synthetic_gate", false, false, false));
    let real_change = (0..100).map(|_| observation("synthetic_gate", true, false, true));
    let summary = evaluate_gate_drift(GateDriftConfig::default(), stable.chain(real_change));
    assert_eq!(summary.flagged_gates, 0);
    assert_eq!(summary.gates[0].uncorrelated_shifts, 0);
}

#[test]
fn checker_accepts_canonical_clean_series() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "canonical")?;
    let report = out_dir.join("report.json");
    let output = run_checker(&root, &canonical_series_path(&root), &report)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS gate drift"),
        "{}",
        output_text(&output)
    );
    let report_json = load_json(&report)?;
    assert_eq!(report_json["schema_version"], "gate_drift_report.v1");
    assert_eq!(report_json["status"], "pass");
    assert_eq!(report_json["failure_signature"], "none");
    Ok(())
}

#[test]
fn checker_rejects_uncorrelated_pass_rate_jump() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "suspicious")?;
    let series = out_dir.join("series.json");
    let report = out_dir.join("report.json");
    let stable = (0..200).map(|_| {
        json!({
            "passed": false,
            "expected_passed": false,
            "code_delta": false
        })
    });
    let suspicious = (0..100).map(|_| {
        json!({
            "passed": true,
            "expected_passed": false,
            "code_delta": false
        })
    });
    write_series(&series, stable.chain(suspicious).collect())?;

    let output = run_checker(&root, &series, &report)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"], "fail");
    assert_eq!(
        report_json["failure_signature"],
        "gate_drift_uncorrelated_changepoint"
    );
    assert_eq!(report_json["gate_summaries"][0]["flagged"], true);
    assert_eq!(report_json["gate_summaries"][0]["uncorrelated_shifts"], 100);
    Ok(())
}

#[test]
fn checker_accepts_code_correlated_pass_rate_jump() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "code-correlated")?;
    let series = out_dir.join("series.json");
    let report = out_dir.join("report.json");
    let stable = (0..200).map(|_| {
        json!({
            "passed": false,
            "expected_passed": false,
            "code_delta": false
        })
    });
    let real_change = (0..100).map(|_| {
        json!({
            "passed": true,
            "expected_passed": false,
            "code_delta": true
        })
    });
    write_series(&series, stable.chain(real_change).collect())?;

    let output = run_checker(&root, &series, &report)?;
    assert!(output.status.success(), "{}", output_text(&output));
    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"], "pass");
    assert_eq!(report_json["gate_summaries"][0]["uncorrelated_shifts"], 0);
    Ok(())
}
