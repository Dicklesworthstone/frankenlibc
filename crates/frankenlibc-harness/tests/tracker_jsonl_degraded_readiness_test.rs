//! Integration tests for the JSONL-only tracker degraded-readiness gate.
//!
//! The gate is the source-aware fallback when br/bv or SQLite-backed tracker
//! paths are stale, locked, or polluted by cross-project rows.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/tracker_jsonl_degraded_readiness.v1.json";
const CHECKER_REL: &str = "scripts/check_tracker_jsonl_degraded_readiness.sh";

fn repo_root() -> TestResult<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory should have workspace parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent should have repo parent"))?;
    Ok(root.to_path_buf())
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

fn contract_path(root: &Path) -> PathBuf {
    root.join(CONTRACT_REL)
}

fn checker_path(root: &Path) -> PathBuf {
    root.join(CHECKER_REL)
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "tracker_jsonl_degraded_readiness_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, issues: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg("--validate-only")
        .current_dir(root)
        .env("FRANKENLIBC_TRACKER_JSONL_DEGRADED_CONTRACT", contract)
        .env("FRANKENLIBC_TRACKER_JSONL_DEGRADED_ISSUES", issues)
        .env("FRANKENLIBC_TRACKER_JSONL_DEGRADED_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_TRACKER_JSONL_DEGRADED_REPORT",
            out_dir.join("tracker_jsonl_degraded_readiness.report.json"),
        )
        .env(
            "FRANKENLIBC_TRACKER_JSONL_DEGRADED_LOG",
            out_dir.join("tracker_jsonl_degraded_readiness.log.jsonl"),
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
fn contract_declares_jsonl_only_cycle_fields() -> TestResult {
    let root = repo_root()?;
    let contract = load_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("tracker_jsonl_degraded_readiness.v1")
    );
    assert_eq!(
        contract["issues_source"].as_str(),
        Some(".beads/issues.jsonl")
    );

    let forbidden = string_set(&contract, "forbidden_sources")?;
    for source in [".beads/beads.db", ".beads/issues.db", "br", "bv"] {
        assert!(
            forbidden.contains(source),
            "missing forbidden source {source}"
        );
    }

    let report_fields = string_set(&contract, "required_report_fields")?;
    assert!(report_fields.contains("dependency_cycles"));

    let stdout_fields = string_set(&contract, "stdout_summary_fields")?;
    assert!(stdout_fields.contains("dependency_cycle_count"));
    assert!(stdout_fields.contains("dependency_cycles"));

    let controls = string_set(&contract, "required_negative_controls")?;
    assert!(controls.contains("dependency_cycle_detected_without_br"));
    assert!(controls.contains("action_prioritizes_dependency_cycles"));

    let validation_commands = string_set(&contract, "validation_commands")?;
    assert!(
        validation_commands
            .iter()
            .any(|command| command.contains("dependency_cycle_count"))
    );
    assert!(
        validation_commands
            .iter()
            .any(|command| command.contains("dependency_cycles"))
    );
    Ok(())
}

#[test]
fn checker_validates_live_jsonl_and_emits_cycle_fields() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "live")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &root.join(".beads/issues.jsonl"),
        &out,
    )?;
    assert!(output.status.success(), "{}", output_text(&output));

    let stdout_json: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(stdout_json["status"].as_str(), Some("pass"));
    assert!(stdout_json["dependency_cycle_count"].is_number());
    assert!(stdout_json["dependency_cycles"].is_array());

    let report = load_json(&out.join("tracker_jsonl_degraded_readiness.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["stdout_summary"]["dependency_cycle_count"],
        stdout_json["dependency_cycle_count"]
    );
    assert_eq!(
        report["stdout_summary"]["dependency_cycles"],
        stdout_json["dependency_cycles"]
    );
    assert!(
        report["negative_controls"]
            .as_array()
            .ok_or_else(|| io::Error::other("negative_controls must be array"))?
            .iter()
            .all(|control| control["status"].as_str() == Some("pass"))
    );
    Ok(())
}

#[test]
fn checker_detects_dependency_cycle_from_jsonl_fixture() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "cycle")?;
    let issues = out.join("cycle_issues.jsonl");
    write_jsonl(
        &issues,
        &[
            json!({
                "id": "bd-jsonl-cycle-a",
                "title": "fixture cycle a",
                "status": "open",
                "updated_at": "2026-05-20T00:00:00Z",
                "dependencies": [{
                    "issue_id": "bd-jsonl-cycle-a",
                    "depends_on_id": "bd-jsonl-cycle-b",
                    "type": "blocks"
                }]
            }),
            json!({
                "id": "bd-jsonl-cycle-b",
                "title": "fixture cycle b",
                "status": "open",
                "updated_at": "2026-05-20T00:00:00Z",
                "dependencies": [{
                    "issue_id": "bd-jsonl-cycle-b",
                    "depends_on_id": "bd-jsonl-cycle-a",
                    "type": "blocks"
                }]
            }),
        ],
    )?;

    let output = run_checker(&root, &contract_path(&root), &issues, &out)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let stdout_json: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(stdout_json["dependency_cycle_count"].as_u64(), Some(1));
    assert_eq!(
        stdout_json["recommended_next_action"]["decision"].as_str(),
        Some("fix_dependency_cycles")
    );
    assert_eq!(
        stdout_json["recommended_next_action"]["candidate_ids"],
        json!(["bd-jsonl-cycle-a", "bd-jsonl-cycle-b"])
    );
    assert_eq!(
        stdout_json["dependency_cycles"][0]["cycle_ids"],
        json!(["bd-jsonl-cycle-a", "bd-jsonl-cycle-b"])
    );
    assert_eq!(
        stdout_json["dependency_cycles"][0]["edge_type"].as_str(),
        Some("blocks")
    );

    let report = load_json(&out.join("tracker_jsonl_degraded_readiness.report.json"))?;
    assert_eq!(
        report["summary"]["dependency_cycle_total"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["stdout_summary"]["recommended_next_action"]["decision"].as_str(),
        Some("fix_dependency_cycles")
    );
    Ok(())
}
