//! Integration test: replacement-readiness acceptance thresholds.

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
        "replacement_readiness_acceptance_thresholds_{name}_{}_{}",
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
    let script = root.join("scripts/check_replacement_readiness_acceptance_thresholds.sh");
    let mut command = Command::new(&script);
    command.current_dir(root).arg("--validate-only");
    if let Some(path) = contract_override {
        command.env("REPLACEMENT_READINESS_THRESHOLDS_CONTRACT", path);
    }
    command
        .output()
        .expect("failed to run replacement readiness threshold checker")
}

fn mutated_contract(root: &Path, name: &str) -> (PathBuf, serde_json::Value) {
    let contract = load_json(
        &root.join("tests/conformance/replacement_readiness_acceptance_thresholds.v1.json"),
    );
    let path =
        unique_temp_dir(root, name).join("replacement_readiness_acceptance_thresholds.v1.json");
    (path, contract)
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path =
        root.join("target/conformance/replacement_readiness_acceptance_thresholds.report.json");
    let log_path =
        root.join("target/conformance/replacement_readiness_acceptance_thresholds.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some(expected_signature)
    );

    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| {
            row["event"].as_str() == Some("replacement_readiness_acceptance_thresholds_failed")
        })
        .expect("failure event should be logged");
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
}

#[test]
fn contract_declares_replacement_readiness_policy() {
    let root = workspace_root();
    let contract = load_json(
        &root.join("tests/conformance/replacement_readiness_acceptance_thresholds.v1.json"),
    );
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("replacement_readiness_acceptance_thresholds.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.17"));
    assert_eq!(
        contract["readiness_policy"]["minimum_supported_status_pct"].as_f64(),
        Some(100.0)
    );
    assert_eq!(
        contract["readiness_policy"]["maximum_missing_exports_per_family"].as_u64(),
        Some(0)
    );
    assert_eq!(
        contract["readiness_policy"]["maximum_residual_callthrough_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        contract["expected_current_summary"]["claim_gate_decision"].as_str(),
        Some("blocked")
    );
    assert_eq!(
        contract["expected_current_summary"]["family_fail_count"].as_u64(),
        Some(38)
    );
}

#[test]
fn checker_passes_and_blocks_current_readiness() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(
        &root.join("target/conformance/replacement_readiness_acceptance_thresholds.report.json"),
    );
    assert_eq!(
        report["schema_version"].as_str(),
        Some("replacement_readiness_acceptance_thresholds.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.17"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["family_count"].as_u64(), Some(40));
    assert_eq!(report["summary"]["family_pass_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["family_fail_count"].as_u64(), Some(38));
    assert_eq!(
        report["summary"]["family_coverage_fail_count"].as_u64(),
        Some(37)
    );
    assert_eq!(
        report["summary"]["aggregate_support_green"].as_bool(),
        Some(true)
    );
    assert_eq!(report["summary"]["missing_export_count"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["residual_forbidden_callthrough_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["claim_gate_decision"].as_str(),
        Some("blocked")
    );
    assert!(
        report["family_decisions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["family_id"].as_str() == Some("stdio_abi")
                && row["failure_reasons"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|reason| reason.as_str() == Some("missing_version_export")))
    );
}

#[test]
fn checker_rejects_callthrough_threshold_relaxation() {
    let _guard = gate_lock();
    let root = workspace_root();
    let (contract_path, mut contract) = mutated_contract(&root, "callthrough_relaxed");
    contract["readiness_policy"]["maximum_residual_callthrough_count"] = serde_json::json!(1);
    write_json(&contract_path, &contract);

    let output = run_checker(&root, Some(&contract_path));
    assert!(
        !output.status.success(),
        "checker should reject relaxed call-through threshold"
    );
    assert_failure_outputs(&root, "replacement_readiness_policy_invalid");
}

#[test]
fn checker_rejects_current_summary_overclaim() {
    let _guard = gate_lock();
    let root = workspace_root();
    let (contract_path, mut contract) = mutated_contract(&root, "summary_overclaim");
    contract["expected_current_summary"]["family_pass_count"] = serde_json::json!(40);
    contract["expected_current_summary"]["family_fail_count"] = serde_json::json!(0);
    contract["expected_current_summary"]["claim_gate_decision"] = serde_json::json!("ready");
    write_json(&contract_path, &contract);

    let output = run_checker(&root, Some(&contract_path));
    assert!(
        !output.status.success(),
        "checker should reject readiness overclaim"
    );
    assert_failure_outputs(&root, "replacement_readiness_summary_mismatch");
}

#[test]
fn checker_rejects_missing_input_artifact() {
    let _guard = gate_lock();
    let root = workspace_root();
    let (contract_path, mut contract) = mutated_contract(&root, "missing_input");
    contract["input_artifacts"]["support_matrix"] =
        serde_json::json!("tests/conformance/not-real.json");
    write_json(&contract_path, &contract);

    let output = run_checker(&root, Some(&contract_path));
    assert!(
        !output.status.success(),
        "checker should reject missing input artifact"
    );
    assert_failure_outputs(&root, "replacement_readiness_input_missing");
}
