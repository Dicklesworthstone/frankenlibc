//! Evidence freshness e-process gate tests for bd-3yr14.3.

use frankenlibc_harness::evidence_freshness::{
    EvidenceFreshnessConfig, evaluate_evidence_freshness,
};
use frankenlibc_membrane::runtime_math::eprocess::SequentialState;
use serde_json::Value;
use std::collections::BTreeSet;
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

fn ledger_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/evidence_ledger.jsonl")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_evidence_freshness.sh")
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "evidence-freshness-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_ledger_rows(path: &Path) -> TestResult<Vec<Value>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|err| test_error(format!("ledger line must parse as JSON: {err}")))
        })
        .collect()
}

fn write_ledger(path: &Path, rows: &[Value]) -> TestResult {
    let mut out = String::new();
    for row in rows {
        out.push_str(&serde_json::to_string(row)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

fn run_checker(root: &Path, ledger: &Path, report: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_EVIDENCE_LEDGER", ledger)
        .env("FRANKENLIBC_EVIDENCE_FRESHNESS_REPORT", report)
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

#[test]
fn rust_eprocess_consumer_calibrates_false_alarm_bound() {
    let clean = evaluate_evidence_freshness(EvidenceFreshnessConfig::default(), [false]);
    assert_eq!(clean.state, SequentialState::Normal);
    assert_eq!(clean.false_alarm_alpha, 0.1);
    assert!(clean.e_value < 1.0);

    let divergent = evaluate_evidence_freshness(EvidenceFreshnessConfig::default(), [true]);
    assert_eq!(divergent.state, SequentialState::Alarm);
    assert_eq!(divergent.divergences, 1);
    assert!(divergent.e_value >= EvidenceFreshnessConfig::default().alarm_e_value);
}

#[test]
fn checker_accepts_current_ledger_without_divergence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let report_path = out_dir.join("report.json");
    let output = run_checker(&root, &ledger_path(&root), &report_path)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS evidence freshness"),
        "{}",
        output_text(&output)
    );

    let report = load_json(&report_path)?;
    assert_eq!(report["schema_version"], "evidence_freshness_report.v1");
    assert_eq!(report["status"], "pass");
    assert_eq!(report["state"], "normal");
    assert_eq!(report["false_alarm_alpha"].as_f64(), Some(0.1));
    assert_eq!(report["divergences"].as_u64(), Some(0));
    Ok(())
}

#[test]
fn checker_rejects_divergent_artifact_with_alarm() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "divergent")?;
    let bad_ledger = out_dir.join("bad_ledger.jsonl");
    let report_path = out_dir.join("report.json");
    let mut rows = load_ledger_rows(&ledger_path(&root))?;
    // Diverge every artifact_hash so the anytime-valid e-process alarm fires
    // regardless of how many entries the canonical ledger currently carries.
    // A single divergence among many fresh entries is (correctly) not enough
    // adverse evidence to cross the alarm threshold, so corrupting only row[0]
    // silently stopped tripping the alarm once the WS-0 ledger grew past one
    // entry. Per-artifact staleness is still caught exactly by the ledger
    // chain gate; this test exercises the divergence-rate alarm specifically.
    let divergent_count = rows.len();
    for row in &mut rows {
        row["artifact_hash"] = Value::String("0".repeat(64));
    }
    write_ledger(&bad_ledger, &rows)?;

    let output = run_checker(&root, &bad_ledger, &report_path)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert_eq!(report["state"], "alarm");
    assert_eq!(report["divergences"].as_u64(), Some(divergent_count as u64));
    assert!(failure_signatures(&report).contains("evidence_freshness_alarm"));
    assert!(
        report["e_value"].as_f64().unwrap_or_default()
            >= report["parameters"]["alarm_e_value"]
                .as_f64()
                .unwrap_or(f64::INFINITY)
    );
    Ok(())
}
