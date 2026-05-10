//! Integration test: fixture expected-output schema policy gate.
//!
//! This locks the current adapter-normalized fixture contract before the broader
//! fixture schema validation work can build on it.

use std::collections::HashSet;
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
        "fixture_expected_output_schema_policy_{name}_{}_{}.json",
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

fn run_checker(root: &Path, contract_override: Option<&Path>) -> std::process::Output {
    let script = root.join("scripts/check_fixture_expected_output_schema_policy.sh");
    let mut command = Command::new(&script);
    command.current_dir(root).arg("--validate-only");
    if let Some(path) = contract_override {
        command.env("FIXTURE_EXPECTED_OUTPUT_POLICY_CONTRACT", path);
    }
    command
        .output()
        .expect("failed to run fixture expected-output policy checker")
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path =
        root.join("target/conformance/fixture_expected_output_schema_policy.report.json");
    let log_path = root.join("target/conformance/fixture_expected_output_schema_policy.log.jsonl");
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
        .find(|row| row["event"].as_str() == Some("fixture_expected_output_schema_policy_failed"))
        .expect("failure event should be logged");
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
    assert!(
        event["trace_id"].is_string(),
        "failure log missing trace_id"
    );
}

#[test]
fn contract_declares_adapter_normalized_policy() {
    let root = workspace_root();
    let contract_path =
        root.join("tests/conformance/fixture_expected_output_schema_policy.v1.json");
    let contract = load_json(&contract_path);
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("fixture_expected_output_schema_policy.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.5"));
    assert_eq!(
        contract["canonical_policy"]["id"].as_str(),
        Some("adapter_normalized_tagged_values")
    );
    assert_eq!(
        contract["canonical_policy"]["internal_comparison_type"].as_str(),
        Some("string")
    );
    assert_eq!(
        contract["migration_notes"]["no_broad_fixture_rewrite"].as_bool(),
        Some(true)
    );
    assert_eq!(
        contract["migration_controls"]["id"].as_str(),
        Some("fixture_expected_output_adapter_migration.v1")
    );
    assert_eq!(
        contract["migration_controls"]["downstream_schema_gate"].as_str(),
        Some("tests/conformance/fixture_schema_validation.v1.json")
    );
    assert!(
        contract["migration_controls"]["required_migration_steps"]
            .as_array()
            .expect("migration steps should be an array")
            .iter()
            .any(|step| step.as_str()
                == Some("Consume this policy from the whole-tree fixture schema validation gate")),
        "migration controls must bind the downstream schema gate"
    );
    assert!(
        contract["migration_controls"]["prohibited_migrations"]
            .as_array()
            .expect("prohibited migrations should be an array")
            .iter()
            .any(|step| step.as_str() == Some("No broad fixture rewrite")),
        "migration controls must keep broad fixture rewrites prohibited"
    );
    assert_eq!(
        contract["conformance_gate"]["harness_test"].as_str(),
        Some("crates/frankenlibc-harness/tests/fixture_expected_output_schema_policy_test.rs")
    );
    assert_eq!(
        contract["conformance_gate"]["validated_focus_case_count"].as_u64(),
        Some(58)
    );

    let tags = contract["expectation_tag_precedence"]
        .as_array()
        .expect("tag precedence should be an array");
    assert_eq!(
        tags.first().unwrap()["tag"].as_str(),
        Some("expected_output")
    );
    assert!(
        tags.iter()
            .any(|tag| tag["tag"].as_str() == Some("expected_return+expected_values")),
        "scanf return/value adapter tag must be documented"
    );

    let focus = contract["focus_fixture_inventory"]
        .as_array()
        .expect("focus fixtures array");
    let ids: HashSet<_> = focus.iter().filter_map(|row| row["id"].as_str()).collect();
    assert_eq!(
        ids,
        HashSet::from(["elf_loader", "resolver", "time_ops", "termios_ops"])
    );
}

#[test]
fn checker_passes_and_reports_all_focus_cases() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path =
        root.join("target/conformance/fixture_expected_output_schema_policy.report.json");
    let log_path = root.join("target/conformance/fixture_expected_output_schema_policy.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(
        report["schema_version"].as_str(),
        Some("fixture_expected_output_schema_policy.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.5"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert!(report["source_commit"].is_string(), "source_commit missing");
    assert_eq!(report["summary"]["focus_fixture_count"].as_u64(), Some(4));
    assert_eq!(report["summary"]["total_focus_cases"].as_u64(), Some(58));
    assert_eq!(
        report["summary"]["classified_focus_cases"].as_u64(),
        Some(58)
    );
    assert_eq!(
        report["summary"]["expected_output_value_kinds"]["string"].as_u64(),
        Some(31)
    );
    assert_eq!(
        report["summary"]["expected_output_value_kinds"]["object"].as_u64(),
        Some(16)
    );
    assert_eq!(
        report["summary"]["expected_output_value_kinds"]["array"].as_u64(),
        Some(6)
    );
    assert_eq!(
        report["summary"]["expected_output_value_kinds"]["number"].as_u64(),
        Some(5)
    );
    assert_eq!(
        report["summary"]["migration_contract"].as_str(),
        Some("fixture_expected_output_adapter_migration.v1")
    );
    assert_eq!(report["summary"]["migration_step_count"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["prohibited_migration_count"].as_u64(),
        Some(4)
    );
    assert_eq!(
        report["summary"]["conformance_gate"].as_str(),
        Some("fixture_expected_output_schema_policy_conformance.v1")
    );
    assert_eq!(
        report["summary"]["conformance_harness_test"].as_str(),
        Some("crates/frankenlibc-harness/tests/fixture_expected_output_schema_policy_test.rs")
    );

    let focus = report["focus_fixtures"]
        .as_array()
        .expect("focus fixture report array");
    for row in focus {
        assert_eq!(
            row["case_count"], row["classified_cases"],
            "focus fixture should not skip cases silently"
        );
    }

    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| {
            row["event"].as_str() == Some("fixture_expected_output_schema_policy_validated")
        })
        .expect("pass event should be logged");
    assert_eq!(event["outcome"].as_str(), Some("pass"));
    assert!(
        event["source_commit"].is_string(),
        "log source_commit missing"
    );
}

#[test]
fn checker_rejects_string_only_policy_downgrade() {
    let _guard = gate_lock();
    let root = workspace_root();
    let contract_path =
        root.join("tests/conformance/fixture_expected_output_schema_policy.v1.json");
    let mut contract = load_json(&contract_path);
    contract["canonical_policy"]["id"] = serde_json::Value::from("string_only");
    let mutation = write_mutation(&root, "string_only_policy", &contract);

    let output = run_checker(&root, Some(&mutation));
    assert!(
        !output.status.success(),
        "checker should reject string-only policy downgrade"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("canonical_policy_mismatch"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "canonical_policy_mismatch");
}

#[test]
fn checker_rejects_missing_focus_fixture_inventory() {
    let _guard = gate_lock();
    let root = workspace_root();
    let contract_path =
        root.join("tests/conformance/fixture_expected_output_schema_policy.v1.json");
    let mut contract = load_json(&contract_path);
    let focus = contract["focus_fixture_inventory"]
        .as_array_mut()
        .expect("focus array should exist");
    focus.retain(|row| row["id"].as_str() != Some("termios_ops"));
    let mutation = write_mutation(&root, "missing_termios", &contract);

    let output = run_checker(&root, Some(&mutation));
    assert!(
        !output.status.success(),
        "checker should reject missing termios focus fixture"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("focus_fixture_missing"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "focus_fixture_missing");
}

#[test]
fn checker_rejects_migration_control_drift() {
    let _guard = gate_lock();
    let root = workspace_root();
    let contract_path =
        root.join("tests/conformance/fixture_expected_output_schema_policy.v1.json");
    let mut contract = load_json(&contract_path);
    let steps = contract["migration_controls"]["required_migration_steps"]
        .as_array_mut()
        .expect("migration steps should exist");
    steps.retain(|step| {
        step.as_str() != Some("Fail closed when undocumented expected_* supplemental fields appear")
    });
    let mutation = write_mutation(&root, "missing_migration_step", &contract);

    let output = run_checker(&root, Some(&mutation));
    assert!(
        !output.status.success(),
        "checker should reject missing migration-control steps"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("migration_controls_invalid"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "migration_controls_invalid");
}

#[test]
fn checker_rejects_conformance_gate_drift() {
    let _guard = gate_lock();
    let root = workspace_root();
    let contract_path =
        root.join("tests/conformance/fixture_expected_output_schema_policy.v1.json");
    let mut contract = load_json(&contract_path);
    contract["conformance_gate"]["validated_focus_case_count"] = serde_json::Value::from(57);
    let mutation = write_mutation(&root, "stale_conformance_gate", &contract);

    let output = run_checker(&root, Some(&mutation));
    assert!(
        !output.status.success(),
        "checker should reject stale conformance-gate counts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conformance_gate_invalid"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "conformance_gate_invalid");
}

#[test]
fn checker_rejects_resolver_kind_inventory_drift() {
    let _guard = gate_lock();
    let root = workspace_root();
    let contract_path =
        root.join("tests/conformance/fixture_expected_output_schema_policy.v1.json");
    let mut contract = load_json(&contract_path);
    let resolver = contract["focus_fixture_inventory"]
        .as_array_mut()
        .expect("focus array should exist")
        .iter_mut()
        .find(|row| row["id"].as_str() == Some("resolver"))
        .expect("resolver row should exist");
    resolver["expected_output_value_kinds"] = serde_json::json!({"string": 25});
    let mutation = write_mutation(&root, "resolver_string_only", &contract);

    let output = run_checker(&root, Some(&mutation));
    assert!(
        !output.status.success(),
        "checker should reject resolver kind drift"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expected_output_kind_mismatch"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "expected_output_kind_mismatch");
}
