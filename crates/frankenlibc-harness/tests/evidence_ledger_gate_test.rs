//! Evidence ledger gate tests for bd-3yr14.2.

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
    root.join("scripts/check_evidence_ledger.sh")
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "evidence-ledger-{label}-{}-{nanos}",
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
        .env("FRANKENLIBC_EVIDENCE_LEDGER_REPORT", report)
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
fn evidence_ledger_rows_bind_existing_artifacts() -> TestResult {
    let root = workspace_root()?;
    let rows = load_ledger_rows(&ledger_path(&root))?;
    assert!(!rows.is_empty(), "ledger must contain at least one row");

    let first = rows
        .first()
        .ok_or_else(|| test_error("missing first row"))?;
    assert_eq!(
        first["schema_version"].as_str(),
        Some("evidence_ledger_entry.v1")
    );
    assert_eq!(first["entry_index"].as_u64(), Some(0));
    let artifact_path = first["artifact_path"]
        .as_str()
        .ok_or_else(|| test_error("artifact_path must be a string"))?;
    assert!(
        root.join(artifact_path).is_file(),
        "artifact path must exist: {artifact_path}"
    );
    for field in [
        "artifact_hash",
        "source_commit",
        "generator_command",
        "tool_version",
        "prev_chain_hash",
        "chain_hash",
    ] {
        assert!(
            first.get(field).and_then(Value::as_str).is_some(),
            "ledger row missing {field}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_canonical_evidence_ledger() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let report_path = out_dir.join("report.json");
    let output = run_checker(&root, &ledger_path(&root), &report_path)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS evidence ledger"),
        "{}",
        output_text(&output)
    );

    let report = load_json(&report_path)?;
    assert_eq!(report["schema_version"], "evidence_ledger_check_report.v1");
    assert_eq!(report["status"], "pass");
    assert_eq!(report["failure_signature"], "none");
    assert_eq!(report["checked_entry_count"].as_u64(), Some(1));
    Ok(())
}

#[test]
fn checker_rejects_artifact_hash_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "artifact-hash-drift")?;
    let bad_ledger = out_dir.join("bad_ledger.jsonl");
    let report_path = out_dir.join("report.json");
    let mut rows = load_ledger_rows(&ledger_path(&root))?;
    rows[0]["artifact_hash"] = Value::String("0".repeat(64));
    write_ledger(&bad_ledger, &rows)?;

    let output = run_checker(&root, &bad_ledger, &report_path)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert!(failure_signatures(&report).contains("artifact_hash_mismatch"));
    Ok(())
}

#[test]
fn checker_rejects_mutated_ledger_entry_chain() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "ledger-tamper")?;
    let bad_ledger = out_dir.join("bad_ledger.jsonl");
    let report_path = out_dir.join("report.json");
    let mut rows = load_ledger_rows(&ledger_path(&root))?;
    rows[0]["generator_command"] = Value::String("manually edited command".to_string());
    write_ledger(&bad_ledger, &rows)?;

    let output = run_checker(&root, &bad_ledger, &report_path)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert!(failure_signatures(&report).contains("ledger_chain_hash_mismatch"));
    Ok(())
}
