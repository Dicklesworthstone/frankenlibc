//! Integration tests for the blocked-validation no-cargo guard.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const GUARD_CONTRACT_REL: &str = "tests/conformance/blocked_validation_work_guard.v1.json";
const GUARD_CHECKER_REL: &str = "scripts/check_blocked_validation_work_guard.sh";
const RCH_CONTRACT_REL: &str = "tests/conformance/rch_remote_admissibility_preflight.v1.json";

struct GuardRun {
    output: Output,
    report_path: PathBuf,
}

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

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn write_jsonl(path: &Path, rows: &[Value]) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = String::new();
    for row in rows {
        text.push_str(&serde_json::to_string(row)?);
        text.push('\n');
    }
    std::fs::write(path, text)?;
    Ok(())
}

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn unique_case_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "blocked_validation_work_guard_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn prepare_contracts(root: &Path, out: &Path) -> TestResult<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let guard_report = out.join("blocked_validation_work_guard.report.json");
    let rch_report = out.join("rch_remote_admissibility.report.json");
    let rch_log = out.join("rch_remote_admissibility.log.jsonl");

    let mut guard_contract = load_json(&root.join(GUARD_CONTRACT_REL))?;
    guard_contract["report_contract"]["output_path"] = json!(repo_relative(root, &guard_report)?);
    let guard_contract_path = out.join("blocked_validation_work_guard.contract.json");
    write_json(&guard_contract_path, &guard_contract)?;

    let mut rch_contract = load_json(&root.join(RCH_CONTRACT_REL))?;
    rch_contract["report_contract"]["output_path"] = json!(repo_relative(root, &rch_report)?);
    rch_contract["report_contract"]["log_path"] = json!(repo_relative(root, &rch_log)?);
    let rch_contract_path = out.join("rch_remote_admissibility.contract.json");
    write_json(&rch_contract_path, &rch_contract)?;

    Ok((
        guard_contract_path,
        guard_report,
        rch_contract_path,
        rch_report,
    ))
}

fn write_admissible_dry_run(path: &Path) -> TestResult {
    std::fs::write(
        path,
        "Would offload: YES\nWorker selection: ts1\nCommand classified for remote execution\n",
    )?;
    Ok(())
}

fn write_blocked_dry_run(path: &Path) -> TestResult {
    std::fs::write(
        path,
        concat!(
            "Would offload: YES\n",
            "Skip: worker selection skipped (no admissible workers: critical_pressure=7)\n"
        ),
    )?;
    Ok(())
}

fn run_guard(
    root: &Path,
    label: &str,
    issues: &[Value],
    blocked_rch: bool,
) -> TestResult<GuardRun> {
    let out = unique_case_dir(root, label)?;
    let issues_path = out.join("issues.jsonl");
    let dry_run = out.join("rch_diagnose_dry_run.sample.out");
    let readiness_report = out.join("tracker_jsonl_degraded_readiness.report.json");
    let readiness_log = out.join("tracker_jsonl_degraded_readiness.log.jsonl");
    let (guard_contract, guard_report, rch_contract, rch_report) = prepare_contracts(root, &out)?;

    write_jsonl(&issues_path, issues)?;
    if blocked_rch {
        write_blocked_dry_run(&dry_run)?;
    } else {
        write_admissible_dry_run(&dry_run)?;
    }

    let output = Command::new("bash")
        .arg(root.join(GUARD_CHECKER_REL))
        .current_dir(root)
        .env(
            "FRANKENLIBC_BLOCKED_VALIDATION_GUARD_CONTRACT",
            &guard_contract,
        )
        .env("FRANKENLIBC_BLOCKED_VALIDATION_GUARD_REPORT", &guard_report)
        .env("FRANKENLIBC_TRACKER_JSONL", &issues_path)
        .env("FRANKENLIBC_TRACKER_JSONL_DEGRADED_ISSUES", &issues_path)
        .env("FRANKENLIBC_TRACKER_JSONL_DEGRADED_OUT_DIR", &out)
        .env(
            "FRANKENLIBC_TRACKER_JSONL_DEGRADED_REPORT",
            &readiness_report,
        )
        .env("FRANKENLIBC_TRACKER_JSONL_DEGRADED_LOG", &readiness_log)
        .env("FRANKENLIBC_RCH_PREFLIGHT_CONTRACT", &rch_contract)
        .env("FRANKENLIBC_RCH_PREFLIGHT_OUT_DIR", &out)
        .env("FRANKENLIBC_RCH_PREFLIGHT_REPORT", &rch_report)
        .env(
            "FRANKENLIBC_RCH_PREFLIGHT_LOG",
            out.join("rch_remote_admissibility.log.jsonl"),
        )
        .env("FRANKENLIBC_RCH_PREFLIGHT_DRY_RUN_OUTPUT", &dry_run)
        .env(
            "FRANKENLIBC_RCH_PACKET_REPORT",
            out.join("approval_packet.report.json"),
        )
        .env(
            "FRANKENLIBC_RCH_PACKET_MARKDOWN",
            out.join("approval_packet.approval.md"),
        )
        .output()?;

    Ok(GuardRun {
        output,
        report_path: guard_report,
    })
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other(format!("{field} must be an array")).into())
}

fn string_array_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other(format!("{field} entries must be strings")).into())
        })
        .collect()
}

fn negative_control_status(report: &Value, control_id: &str) -> TestResult<String> {
    json_array(report, "negative_controls")?
        .iter()
        .find(|control| control["control_id"].as_str() == Some(control_id))
        .and_then(|control| control["status"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            io::Error::other(format!("missing negative control status for {control_id}")).into()
        })
}

fn assert_negative_controls_pass(report: &Value, controls: &[&str]) -> TestResult {
    for control in controls {
        assert_eq!(
            negative_control_status(report, control)?,
            "pass",
            "negative control {control} should pass"
        );
    }
    Ok(())
}

#[test]
fn contract_declares_guard_report_decisions_and_controls() -> TestResult {
    let root = repo_root()?;
    let contract = load_json(&root.join(GUARD_CONTRACT_REL))?;

    assert_eq!(
        contract["manifest_id"].as_str(),
        Some("blocked_validation_work_guard")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-rchk0.94"));

    let fields = string_array_set(&contract["report_contract"], "must_materialize")?;
    for field in [
        "decision",
        "current_decision_allowed",
        "safe_ready_count",
        "stale_in_progress_count",
        "blocked_validation_issue_ids",
        "dirty_validation_paths",
        "negative_controls",
    ] {
        assert!(fields.contains(field), "missing report field {field}");
    }

    let decisions = string_array_set(&contract["guard_contract"], "allowed_current_decisions")?;
    for decision in [
        "recover_stale_in_progress_before_new_discovery",
        "claim_safe_ready_before_new_discovery",
        "resume_cargo_validation_queue",
        "avoid_new_cargo_backed_work",
        "no_guard_needed",
    ] {
        assert!(decisions.contains(decision), "missing decision {decision}");
    }

    let controls: BTreeSet<_> = json_array(&contract, "negative_controls")?
        .iter()
        .filter_map(|control| control["control_id"].as_str().map(str::to_owned))
        .collect();
    for control in [
        "rch_admissible_with_dependents_changes_decision",
        "rch_admissible_without_dependents_removes_guard",
        "safe_ready_changes_decision",
        "stale_in_progress_changes_decision",
        "blocked_dependents_blocks_new_work",
        "dirty_validation_path_counted",
    ] {
        assert!(controls.contains(control), "missing control {control}");
    }
    Ok(())
}

#[test]
fn admissible_rch_without_dependents_reports_no_guard_needed() -> TestResult {
    let root = repo_root()?;
    let run = run_guard(
        &root,
        "admissible_no_dependents",
        &[json!({
            "id": "bd-synthetic-closed",
            "title": "synthetic closed issue",
            "status": "closed",
            "priority": 2
        })],
        false,
    )?;
    assert!(run.output.status.success(), "{}", output_text(&run.output));

    let report = load_json(&run.report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["decision"].as_str(), Some("no_guard_needed"));
    assert_eq!(report["current_decision_allowed"].as_bool(), Some(true));
    assert_eq!(report["rch_status"].as_str(), Some("admissible"));
    assert_eq!(report["safe_ready_count"].as_u64(), Some(0));
    assert_eq!(report["stale_in_progress_count"].as_u64(), Some(0));
    assert!(json_array(&report, "blocked_validation_issue_ids")?.is_empty());
    assert!(json_array(&report, "failure_signatures")?.is_empty());

    assert_negative_controls_pass(
        &report,
        &[
            "rch_admissible_with_dependents_changes_decision",
            "rch_admissible_without_dependents_removes_guard",
            "safe_ready_changes_decision",
            "stale_in_progress_changes_decision",
            "blocked_dependents_blocks_new_work",
            "dirty_validation_path_counted",
            "missing_report_field_fails",
            "output_path_mismatch_fails",
            "bad_current_status_fails",
        ],
    )?;
    Ok(())
}

#[test]
fn blocked_rch_with_active_validation_dependent_blocks_new_cargo_work() -> TestResult {
    let root = repo_root()?;
    let run = run_guard(
        &root,
        "blocked_with_dependent",
        &[json!({
            "id": "bd-synthetic-validation-dependent",
            "title": "synthetic validation work waiting on RCH",
            "status": "open",
            "priority": 1,
            "dependencies": [{
                "issue_id": "bd-synthetic-validation-dependent",
                "depends_on_id": "bd-716tv",
                "type": "blocks",
                "metadata": "{\"why\":\"synthetic RCH validation blocker\"}"
            }]
        })],
        true,
    )?;
    assert!(run.output.status.success(), "{}", output_text(&run.output));

    let report = load_json(&run.report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["decision"].as_str(),
        Some("avoid_new_cargo_backed_work")
    );
    assert_eq!(report["rch_status"].as_str(), Some("blocked"));
    assert_eq!(report["safe_ready_count"].as_u64(), Some(0));
    assert_eq!(report["stale_in_progress_count"].as_u64(), Some(0));
    assert_eq!(
        report["blocked_validation_issue_ids"],
        json!(["bd-synthetic-validation-dependent"])
    );

    let signatures = string_array_set(&report, "failure_signatures")?;
    for signature in [
        "critical_pressure",
        "no_admissible_workers",
        "worker_selection_skipped",
    ] {
        assert!(signatures.contains(signature), "missing {signature}");
    }
    assert_negative_controls_pass(
        &report,
        &[
            "no_waiting_dependents_removes_guard",
            "blocked_dependents_blocks_new_work",
            "dirty_validation_path_counted",
        ],
    )?;
    Ok(())
}
