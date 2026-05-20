//! Integration tests for the DB-free completion evidence index checker.
//!
//! The checker lets agents resume completion proof handoff from JSONL and
//! checked-in evidence artifacts without trusting stale SQLite tracker state.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/completion_evidence_index.v1.json";
const CHECKER_REL: &str = "scripts/check_completion_evidence_index.sh";

fn repo_root() -> TestResult<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory should have workspace parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent should have repo parent"))?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join(CONTRACT_REL)
}

fn checker_path(root: &Path) -> PathBuf {
    root.join(CHECKER_REL)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_jsonl(path: &Path, rows: &[Value]) -> TestResult {
    let mut text = String::new();
    for row in rows {
        text.push_str(&serde_json::to_string(row)?);
        text.push('\n');
    }
    std::fs::write(path, text)?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "completion_evidence_index_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn fixture_issues_path(out_dir: &Path) -> TestResult<PathBuf> {
    let issues = out_dir.join("issues.jsonl");
    write_jsonl(
        &issues,
        &[
            json!({
                "id": "bd-eu2ku.4",
                "title": "Tracker JSONL degraded-readiness proof",
                "status": "closed"
            }),
            json!({
                "id": "bd-eu2ku.2",
                "title": "RCH remote admissibility blocker evidence",
                "status": "closed"
            }),
            json!({
                "id": "bd-waaa6.4",
                "title": "RCH proof manifest lint proof",
                "status": "closed"
            }),
        ],
    )?;
    Ok(issues)
}

fn run_checker(root: &Path, issues: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_CONTRACT",
            contract_path(root),
        )
        .env("FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_ISSUES", issues)
        .env("FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_REPORT",
            out_dir.join("completion_evidence_index.report.json"),
        )
        .env(
            "FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_LOG",
            out_dir.join("completion_evidence_index.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    let values = value
        .get(field)
        .ok_or_else(|| io::Error::other(format!("{field} must be present")))?
        .as_array()
        .ok_or_else(|| io::Error::other(format!("{field} must be an array")))?;
    values
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other(format!("{field} entries must be strings")).into())
        })
        .collect()
}

#[test]
fn contract_declares_db_free_evidence_index_policy() -> TestResult {
    let root = repo_root()?;
    let contract = load_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("completion_evidence_index.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-eu2ku.3"));
    assert_eq!(
        contract["issues_source"].as_str(),
        Some(".beads/issues.jsonl")
    );
    assert_eq!(
        contract["sqlite_access_policy"]["sqlite_accessed"].as_bool(),
        Some(false)
    );

    let proof_status_values = string_set(&contract, "proof_status_values")?;
    assert_eq!(
        proof_status_values,
        BTreeSet::from([
            "blocker_evidence".to_string(),
            "successful_proof".to_string()
        ])
    );

    let required_fields = string_set(&contract, "required_entry_fields")?;
    for field in [
        "bead_id",
        "artifact_path",
        "proof_command",
        "proof_status",
        "last_checked_utc",
    ] {
        assert!(required_fields.contains(field), "missing field {field}");
    }

    let controls = string_set(&contract, "required_negative_controls")?;
    for control in [
        "missing_artifact_path_fails",
        "missing_proof_command_fails",
        "invalid_proof_status_fails",
        "blocker_evidence_is_not_successful_proof",
    ] {
        assert!(controls.contains(control), "missing control {control}");
    }
    Ok(())
}

#[test]
fn checker_emits_index_report_and_jsonl_events_without_sqlite() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "positive")?;
    let issues = fixture_issues_path(&out)?;
    let output = run_checker(&root, &issues, &out)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let stdout_json: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(stdout_json["status"].as_str(), Some("pass"));
    assert_eq!(stdout_json["entry_count"].as_u64(), Some(3));
    assert_eq!(stdout_json["successful_proof_count"].as_u64(), Some(2));
    assert_eq!(stdout_json["blocker_evidence_count"].as_u64(), Some(1));
    assert_eq!(stdout_json["sqlite_accessed"].as_bool(), Some(false));

    let report = load_json(&out.join("completion_evidence_index.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("completion_evidence_index.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["sqlite_accessed"].as_bool(), Some(false));
    assert_eq!(report["summary"]["entry_count"].as_u64(), Some(3));
    assert_eq!(
        report["summary"]["successful_proof_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        report["summary"]["blocker_evidence_count"].as_u64(),
        Some(1)
    );
    assert_eq!(report["failures"].as_array().map(Vec::len), Some(0));

    let index = report["evidence_index"]
        .as_array()
        .ok_or_else(|| io::Error::other("evidence_index must be an array"))?;
    assert_eq!(index.len(), 3);
    assert!(index.iter().all(|row| row["artifact_exists"] == true));
    assert!(index.iter().any(|row| {
        row["bead_id"] == "bd-eu2ku.2"
            && row["counts_as_blocker_evidence"] == true
            && row["counts_as_validation_proof"] == false
    }));
    assert!(
        index
            .iter()
            .filter(|row| {
                row["proof_status"] == "successful_proof"
                    && row["counts_as_validation_proof"] == true
            })
            .count()
            >= 2
    );

    let log = std::fs::read_to_string(out.join("completion_evidence_index.log.jsonl"))?;
    let events: Vec<Value> = log
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(events.len(), 5);
    assert_eq!(
        events[0]["schema_version"].as_str(),
        Some("completion_evidence_index.event.v1")
    );
    assert_eq!(
        events[0]["event"].as_str(),
        Some("completion_evidence_index_checked")
    );
    assert!(
        events[1..]
            .iter()
            .all(|event| event["event"].as_str() == Some("negative_control"))
    );
    Ok(())
}

#[test]
fn checker_runs_all_required_negative_controls() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "negative_controls")?;
    let issues = fixture_issues_path(&out)?;
    let output = run_checker(&root, &issues, &out)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out.join("completion_evidence_index.report.json"))?;
    let controls = report["negative_controls"]
        .as_array()
        .ok_or_else(|| io::Error::other("negative_controls must be an array"))?;
    let mut observed = BTreeSet::new();
    for control in controls {
        assert_eq!(control["status"].as_str(), Some("pass"));
        observed.insert((
            control["name"]
                .as_str()
                .ok_or_else(|| io::Error::other("control name must be string"))?
                .to_owned(),
            control["expected_signature"]
                .as_str()
                .ok_or_else(|| io::Error::other("expected_signature must be string"))?
                .to_owned(),
        ));
    }

    assert!(observed.contains(&(
        "missing_artifact_path_fails".to_string(),
        "missing_artifact_path".to_string()
    )));
    assert!(observed.contains(&(
        "missing_proof_command_fails".to_string(),
        "missing_proof_command".to_string()
    )));
    assert!(observed.contains(&(
        "invalid_proof_status_fails".to_string(),
        "invalid_proof_status".to_string()
    )));
    assert!(observed.contains(&(
        "blocker_evidence_is_not_successful_proof".to_string(),
        "blocker_evidence_separated".to_string()
    )));
    Ok(())
}
