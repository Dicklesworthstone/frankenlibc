//! Integration test: hardened-mode coverage inventory dashboard.

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

fn unique_temp_dir(root: &Path, name: &str) -> PathBuf {
    let path = root.join("target/conformance").join(format!(
        "hardened_mode_coverage_inventory_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn run_checker(root: &Path, contract_override: Option<&Path>) -> std::process::Output {
    let script = root.join("scripts/check_hardened_mode_coverage_inventory.sh");
    let mut command = Command::new(&script);
    command.current_dir(root).arg("--validate-only");
    if let Some(path) = contract_override {
        command.env("HARDENED_MODE_COVERAGE_INVENTORY_CONTRACT", path);
    }
    command
        .output()
        .expect("failed to run hardened coverage inventory checker")
}

fn mutated_contract(root: &Path, name: &str) -> (PathBuf, serde_json::Value) {
    let contract =
        load_json(&root.join("tests/conformance/hardened_mode_coverage_inventory.v1.json"));
    let path = unique_temp_dir(root, name).join("hardened_mode_coverage_inventory.v1.json");
    (path, contract)
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path = root.join("target/conformance/hardened_mode_coverage_inventory.report.json");
    let log_path = root.join("target/conformance/hardened_mode_coverage_inventory.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some(expected_signature)
    );

    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("hardened_mode_coverage_inventory_failed"))
        .expect("failure event should be logged");
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
}

#[test]
fn contract_declares_hardened_mode_dashboard_guardrails() {
    let root = workspace_root();
    let contract =
        load_json(&root.join("tests/conformance/hardened_mode_coverage_inventory.v1.json"));
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("hardened_mode_coverage_inventory.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.10"));
    assert_eq!(
        contract["expected_inventory"]["standard_case_count"].as_u64(),
        Some(2774)
    );
    assert_eq!(
        contract["expected_inventory"]["mode_case_counts"]["hardened_only"].as_u64(),
        Some(849)
    );
    assert_eq!(
        contract["expected_inventory"]["mode_case_counts"]["strict_hardened_pair"].as_u64(),
        Some(571)
    );
    assert_eq!(
        contract["expected_inventory"]["hardened_repair_deny_matrix"]["repair_count"].as_u64(),
        Some(9)
    );
    assert_eq!(contract["risk_groups"].as_array().unwrap().len(), 6);
    assert!(
        contract["classification_contract"]["overclaim_guardrails"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row
                .as_str()
                .unwrap()
                .contains("not replacement-readiness proof"))
    );
}

#[test]
fn checker_passes_for_current_dashboard() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        load_json(&root.join("target/conformance/hardened_mode_coverage_inventory.report.json"));
    assert_eq!(
        report["schema_version"].as_str(),
        Some("hardened_mode_coverage_inventory.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.10"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["fixture_inventory"]["effective_mode_case_counts"]["hardened"].as_u64(),
        Some(1420)
    );
    assert_eq!(
        report["summary"]["hardened_repair_deny_matrix"]["deny_count"].as_u64(),
        Some(6)
    );
    assert_eq!(
        report["summary"]["stress_orchard"]["hardened_repair_scenarios"].as_u64(),
        Some(2)
    );
    assert!(
        report["summary"]["risk_groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |row| row["id"].as_str() == Some("allocator_anomaly_repairs")
                    && row["coverage_status"].as_str() == Some("gap_identified")
            )
    );

    let rows =
        load_jsonl(&root.join("target/conformance/hardened_mode_coverage_inventory.log.jsonl"));
    let event = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("hardened_mode_coverage_inventory_validated"))
        .expect("pass event should be logged");
    assert_eq!(event["outcome"].as_str(), Some("pass"));
}

#[test]
fn checker_rejects_hardened_mode_count_drift() {
    let _guard = gate_lock();
    let root = workspace_root();
    let (contract_path, mut contract) = mutated_contract(&root, "count_drift");
    contract["expected_inventory"]["mode_case_counts"]["hardened_only"] = serde_json::json!(999);
    write_json(&contract_path, &contract);

    let output = run_checker(&root, Some(&contract_path));
    assert!(
        !output.status.success(),
        "checker should reject mode count drift"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("hardened_coverage_fixture_inventory_mismatch"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "hardened_coverage_fixture_inventory_mismatch");
}

#[test]
fn checker_rejects_missing_support_matrix_module() {
    let _guard = gate_lock();
    let root = workspace_root();
    let (contract_path, mut contract) = mutated_contract(&root, "support_module");
    contract["risk_groups"][0]["support_modules"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("not_real_abi"));
    write_json(&contract_path, &contract);

    let output = run_checker(&root, Some(&contract_path));
    assert!(
        !output.status.success(),
        "checker should reject unknown support module"
    );
    assert_failure_outputs(&root, "hardened_coverage_support_matrix_mismatch");
}

#[test]
fn checker_rejects_inventory_overclaim() {
    let _guard = gate_lock();
    let root = workspace_root();
    let (contract_path, mut contract) = mutated_contract(&root, "overclaim");
    contract["risk_groups"][0]["coverage_status"] = serde_json::json!("covered");
    contract["risk_groups"][0]["claim_strength"] = serde_json::json!("replacement_ready");
    write_json(&contract_path, &contract);

    let output = run_checker(&root, Some(&contract_path));
    assert!(
        !output.status.success(),
        "checker should reject overclaimed inventory"
    );
    assert_failure_outputs(&root, "hardened_coverage_group_overclaim");
}
