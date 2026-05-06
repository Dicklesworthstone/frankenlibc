//! Integration test: fixture executor ownership and golden output invariant.

use frankenlibc_fixture_exec::execute_fixture_case;
use sha2::{Digest, Sha256};
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

fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn unique_temp_dir(root: &Path, name: &str) -> PathBuf {
    let path = root.join("target/conformance").join(format!(
        "fixture_executor_ownership_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/fixture_executor_ownership_and_golden.v1.json")
}

fn run_checker(root: &Path, contract_override: Option<&Path>) -> std::process::Output {
    let script = root.join("scripts/check_fixture_executor_ownership_and_golden.sh");
    let mut command = Command::new(&script);
    command.current_dir(root).arg("--validate-only");
    if let Some(path) = contract_override {
        command.env("FIXTURE_EXECUTOR_OWNERSHIP_CONTRACT", path);
    }
    command
        .output()
        .expect("failed to run fixture executor ownership checker")
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path =
        root.join("target/conformance/fixture_executor_ownership_and_golden.report.json");
    let log_path = root.join("target/conformance/fixture_executor_ownership_and_golden.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some(expected_signature)
    );

    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("fixture_executor_ownership_and_golden_failed"))
        .expect("failure event should be logged");
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string should serialize")
}

fn canonical_payload(
    fixture: &str,
    case_name: &str,
    function: &str,
    mode: &str,
    execution: &frankenlibc_fixture_exec::DifferentialExecution,
) -> String {
    format!(
        "fixture={fixture}\ncase={case_name}\nfunction={function}\nmode={mode}\nhost_output={}\nimpl_output={}\nhost_parity={}\nnote={}\n",
        json_string(&execution.host_output),
        json_string(&execution.impl_output),
        execution.host_parity,
        serde_json::to_string(&execution.note).expect("note should serialize"),
    )
}

fn sha256_hex(payload: &str) -> String {
    let digest = Sha256::digest(payload.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn find_fixture_case(root: &Path, fixture: &str, case_name: &str) -> serde_json::Value {
    let fixture_path = root.join(format!("tests/conformance/fixtures/{fixture}.json"));
    let fixture_json = load_json(&fixture_path);
    fixture_json["cases"]
        .as_array()
        .expect("fixture should contain cases")
        .iter()
        .find(|case| case["name"].as_str() == Some(case_name))
        .expect("fixture case should exist")
        .clone()
}

#[test]
fn contract_declares_fixture_executor_ownership_boundary() {
    let root = workspace_root();
    let contract = load_json(&contract_path(&root));
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("fixture_executor_ownership_and_golden.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.7"));
    assert_eq!(
        contract["ownership_contract"]["stable_public_boundary"]["crate"].as_str(),
        Some("frankenlibc-fixture-exec")
    );
    assert_eq!(
        contract["ownership_contract"]["stable_public_boundary"]["current_implementation_source"]
            .as_str(),
        Some("frankenlibc-fixture-exec")
    );
    assert_eq!(
        contract["ownership_contract"]["harness_consumer"]["forbidden_direct_dependency"].as_str(),
        Some("frankenlibc_conformance")
    );
    assert_eq!(
        contract["migration_note"]["completed_by_bead"].as_str(),
        Some("bd-0agsk.8")
    );
    assert_eq!(
        contract["golden_manifest"]["cases"]
            .as_array()
            .expect("golden cases should be an array")
            .len(),
        7
    );
}

#[test]
fn checker_passes_for_current_workspace() {
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
        &root.join("target/conformance/fixture_executor_ownership_and_golden.report.json"),
    );
    assert_eq!(
        report["schema_version"].as_str(),
        Some("fixture_executor_ownership_and_golden.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.7"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));

    let rows = load_jsonl(
        &root.join("target/conformance/fixture_executor_ownership_and_golden.log.jsonl"),
    );
    let event = rows
        .iter()
        .find(|row| {
            row["event"].as_str() == Some("fixture_executor_ownership_and_golden_validated")
        })
        .expect("pass event should be logged");
    assert_eq!(event["outcome"].as_str(), Some("pass"));
}

#[test]
fn golden_manifest_matches_current_execute_fixture_case_outputs() {
    let root = workspace_root();
    let contract = load_json(&contract_path(&root));
    let cases = contract["golden_manifest"]["cases"]
        .as_array()
        .expect("golden cases should be an array");

    for sample in cases {
        let fixture = sample["fixture"]
            .as_str()
            .expect("fixture should be a string");
        let case_name = sample["case"].as_str().expect("case should be a string");
        let function = sample["function"]
            .as_str()
            .expect("function should be a string");
        let mode = sample["mode"].as_str().expect("mode should be a string");
        let fixture_case = find_fixture_case(&root, fixture, case_name);
        assert_eq!(
            fixture_case["function"].as_str(),
            Some(function),
            "fixture case {fixture}/{case_name} function drifted"
        );

        let execution = execute_fixture_case(function, &fixture_case["inputs"], mode)
            .expect("golden fixture case should execute");
        assert_eq!(
            execution.host_output,
            sample["expected_host_output"]
                .as_str()
                .expect("expected_host_output should be a string"),
            "{fixture}/{case_name} ({mode}) host output drifted"
        );
        assert_eq!(
            execution.impl_output,
            sample["expected_impl_output"]
                .as_str()
                .expect("expected_impl_output should be a string"),
            "{fixture}/{case_name} ({mode}) impl output drifted"
        );
        assert_eq!(
            execution.host_parity,
            sample["expected_host_parity"]
                .as_bool()
                .expect("expected_host_parity should be a bool"),
            "{fixture}/{case_name} ({mode}) host parity drifted"
        );
        assert_eq!(
            serde_json::to_value(&execution.note).expect("note should serialize"),
            sample["expected_note"],
            "{fixture}/{case_name} ({mode}) note drifted"
        );

        let payload = canonical_payload(fixture, case_name, function, mode, &execution);
        let actual_hash = sha256_hex(&payload);
        let expected_hash = sample["canonical_sha256"]
            .as_str()
            .expect("canonical_sha256 should be a string");
        assert_eq!(
            actual_hash, expected_hash,
            "golden hash drift for {fixture}/{case_name} ({mode})\ncanonical payload:\n{payload}"
        );
    }
}

#[test]
fn checker_rejects_missing_golden_case() {
    let _guard = gate_lock();
    let root = workspace_root();
    let temp_dir = unique_temp_dir(&root, "missing_case");
    let mut contract = load_json(&contract_path(&root));
    contract["golden_manifest"]["cases"] = serde_json::json!([]);
    let temp_contract = temp_dir.join("fixture_executor_ownership_and_golden.v1.json");
    write_json(&temp_contract, &contract);

    let output = run_checker(&root, Some(&temp_contract));
    assert!(
        !output.status.success(),
        "checker should reject empty golden manifest"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("fixture_executor_golden_case_count_mismatch"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "fixture_executor_golden_case_count_mismatch");
}

#[test]
fn checker_rejects_missing_ownership_path() {
    let _guard = gate_lock();
    let root = workspace_root();
    let temp_dir = unique_temp_dir(&root, "missing_path");
    let mut contract = load_json(&contract_path(&root));
    contract["ownership_contract"]["stable_public_boundary"]["entrypoint"] =
        serde_json::json!("crates/frankenlibc-fixture-exec/src/does_not_exist.rs");
    let temp_contract = temp_dir.join("fixture_executor_ownership_and_golden.v1.json");
    write_json(&temp_contract, &contract);

    let output = run_checker(&root, Some(&temp_contract));
    assert!(
        !output.status.success(),
        "checker should reject missing ownership path"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fixture_executor_contract_path_missing"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_failure_outputs(&root, "fixture_executor_contract_path_missing");
}
