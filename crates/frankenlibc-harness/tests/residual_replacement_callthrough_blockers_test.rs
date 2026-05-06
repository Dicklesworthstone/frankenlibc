//! Integration test: residual replacement call-through blocker truth gate.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn gate_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("jsonl should be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl row should parse"))
        .collect()
}

fn write_mutation(root: &Path, name: &str, value: &serde_json::Value) -> PathBuf {
    let path = root.join("target/conformance").join(format!(
        "residual_replacement_callthrough_blockers_{name}_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path
}

fn run_checker(
    root: &Path,
    replacement_report: Option<&Path>,
    interpose_report: Option<&Path>,
    run_guard: bool,
) -> std::process::Output {
    let script = root.join("scripts/check_residual_replacement_callthrough_blockers.sh");
    let mut command = Command::new(&script);
    command.current_dir(root).arg("--validate-only");
    if let Some(path) = replacement_report {
        command.env("RESIDUAL_REPLACEMENT_GUARD_REPLACEMENT_REPORT", path);
    }
    if let Some(path) = interpose_report {
        command.env("RESIDUAL_REPLACEMENT_GUARD_INTERPOSE_REPORT", path);
    }
    if !run_guard {
        command.env("RESIDUAL_REPLACEMENT_RUN_GUARD", "0");
    }
    command
        .output()
        .expect("failed to run residual replacement checker")
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path =
        root.join("target/conformance/residual_replacement_callthrough_blockers.report.json");
    let log_path =
        root.join("target/conformance/residual_replacement_callthrough_blockers.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some(expected_signature)
    );
    assert!(
        report["trace_id"].is_string(),
        "failure report missing trace_id"
    );

    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| {
            row["event"].as_str() == Some("residual_replacement_callthrough_blockers_failed")
        })
        .expect("failure event should be logged");
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
}

#[test]
fn contract_declares_zero_residual_truth() {
    let root = workspace_root();
    let contract = load_json(
        &root.join("tests/conformance/residual_replacement_callthrough_blockers.v1.json"),
    );
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("residual_replacement_callthrough_blockers.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.9"));
    assert_eq!(
        contract["current_truth"]["residual_forbidden_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        contract["current_truth"]["followup_child_beads_created"].as_bool(),
        Some(false)
    );
    assert_eq!(
        contract["stale_ledger_reconciliation"]["todo_ids"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
}

#[test]
fn checker_passes_with_live_replacement_guard_reports() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None, None, true);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(
        &root.join("target/conformance/residual_replacement_callthrough_blockers.report.json"),
    );
    assert_eq!(
        report["schema_version"].as_str(),
        Some("residual_replacement_callthrough_blockers.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.9"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["residual_forbidden_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["replacement_total_call_throughs"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["interpose_total_call_throughs"].as_u64(),
        Some(0)
    );
    assert!(
        report["source_commit"].is_string(),
        "source_commit should be recorded"
    );

    let rows = load_jsonl(
        &root.join("target/conformance/residual_replacement_callthrough_blockers.log.jsonl"),
    );
    let event = rows
        .iter()
        .find(|row| {
            row["event"].as_str() == Some("residual_replacement_callthrough_blockers_validated")
        })
        .expect("pass event should be logged");
    assert_eq!(event["outcome"].as_str(), Some("pass"));
}

#[test]
fn checker_rejects_nonzero_replacement_report() {
    let _guard = gate_lock();
    let root = workspace_root();
    let clean_replacement =
        root.join("target/conformance/replacement_guard.replacement.report.json");
    let clean_interpose = root.join("target/conformance/replacement_guard.interpose.report.json");

    let seed = run_checker(&root, None, None, true);
    assert!(
        seed.status.success(),
        "seed checker should generate clean guard reports"
    );

    let mut replacement = load_json(&clean_replacement);
    replacement["ok"] = serde_json::Value::Bool(false);
    replacement["total_call_throughs"] = serde_json::Value::from(1);
    replacement["modules_with_call_throughs"] = serde_json::Value::from(1);
    replacement["violations"] = serde_json::Value::from(1);
    replacement["module_counts"] = serde_json::json!({"stdio_abi": 1});
    replacement["symbol_rankings"] = serde_json::json!([{
        "rank": 1,
        "module": "stdio_abi",
        "symbol": "printf",
        "source_pattern": "libc",
        "classification": "non_threading",
        "callthrough_count": 1
    }]);
    let mutated = write_mutation(&root, "replacement_nonzero", &replacement);

    let output = run_checker(&root, Some(&mutated), Some(&clean_interpose), false);
    assert!(
        !output.status.success(),
        "checker should reject nonzero residual replacement report"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("residual_callthrough_reintroduced"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "residual_callthrough_reintroduced");
}

#[test]
fn checker_rejects_nonzero_interpose_report() {
    let _guard = gate_lock();
    let root = workspace_root();
    let clean_replacement =
        root.join("target/conformance/replacement_guard.replacement.report.json");
    let clean_interpose = root.join("target/conformance/replacement_guard.interpose.report.json");

    let seed = run_checker(&root, None, None, true);
    assert!(
        seed.status.success(),
        "seed checker should generate clean guard reports"
    );

    let mut interpose = load_json(&clean_interpose);
    interpose["ok"] = serde_json::Value::Bool(false);
    interpose["total_call_throughs"] = serde_json::Value::from(1);
    interpose["modules_with_call_throughs"] = serde_json::Value::from(1);
    interpose["violations"] = serde_json::Value::from(1);
    interpose["module_counts"] = serde_json::json!({"dlfcn_abi": 1});
    interpose["symbol_rankings"] = serde_json::json!([{
        "rank": 1,
        "module": "dlfcn_abi",
        "symbol": "dlopen",
        "source_pattern": "libc",
        "classification": "non_threading",
        "callthrough_count": 1
    }]);
    let mutated = write_mutation(&root, "interpose_nonzero", &interpose);

    let output = run_checker(&root, Some(&clean_replacement), Some(&mutated), false);
    assert!(
        !output.status.success(),
        "checker should reject nonzero residual interpose report"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("residual_callthrough_reintroduced"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "residual_callthrough_reintroduced");
}
