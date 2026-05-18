//! Integration test: support/reality paired regeneration gate.
//!
//! Validates:
//! 1) the committed contract binds support_matrix.json and reality_report.v1.json.
//! 2) the checker emits source commit, generator command, and output hashes.
//! 3) single-artifact update paths fail closed before canonical artifacts can drift.

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
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
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
        "support_reality_regeneration_{name}_{}_{}.json",
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
    contract_override: Option<&Path>,
    extra_arg: Option<&str>,
) -> std::process::Output {
    let script = root.join("scripts/check_support_reality_regeneration.sh");
    let mut command = Command::new(&script);
    command.current_dir(root);
    if let Some(path) = contract_override {
        command.env("SUPPORT_REALITY_REGEN_CONTRACT", path);
    }
    if let Some(arg) = extra_arg {
        command.arg(arg);
    } else {
        command.arg("--validate-only");
    }
    command
        .output()
        .expect("failed to run support/reality regeneration checker")
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path = root.join("target/conformance/support_reality_regeneration.report.json");
    let log_path = root.join("target/conformance/support_reality_regeneration.log.jsonl");
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
        .find(|row| row["event"].as_str() == Some("support_reality_regeneration_failed"))
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
fn contract_has_required_pair_shape() {
    let root = workspace_root();
    let contract_path = root.join("tests/conformance/support_reality_regeneration.v1.json");
    let contract = load_json(&contract_path);
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("support_reality_regeneration.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.3"));
    assert_eq!(contract["mode"].as_str(), Some("validate_only"));
    assert_eq!(
        contract["canonical_command"].as_str(),
        Some("scripts/check_support_reality_regeneration.sh --validate-only")
    );
    assert_eq!(
        contract["regeneration_command"].as_str(),
        Some("scripts/check_support_reality_regeneration.sh --regenerate")
    );
    let modes: std::collections::HashSet<_> = contract["supported_modes"]
        .as_array()
        .expect("supported_modes array")
        .iter()
        .filter_map(|row| row.as_str())
        .collect();
    assert!(modes.contains("validate_only"));
    assert!(modes.contains("regenerate"));
    assert_eq!(
        contract["generator_versions"]["support_matrix_source"].as_str(),
        Some("bash scripts/abi_audit.sh --json-only --deterministic")
    );
    assert_eq!(
        contract["paired_update_policy"]["single_artifact_update"].as_str(),
        Some("forbidden")
    );

    let outputs = contract["output_artifacts"]
        .as_array()
        .expect("output_artifacts array");
    let ids: std::collections::HashSet<_> = outputs
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(ids.contains("support_matrix"));
    assert!(ids.contains("reality_report"));
    for row in outputs {
        assert!(row["path"].is_string(), "output path must be recorded");
        assert_eq!(
            row["sha256"].as_str().map(str::len),
            Some(64),
            "output sha256 must be recorded"
        );
    }
}

#[test]
fn checker_passes_and_emits_hash_report() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None, None);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/support_reality_regeneration.report.json");
    let log_path = root.join("target/conformance/support_reality_regeneration.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(
        report["schema_version"].as_str(),
        Some("support_reality_regeneration.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.3"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert!(report["source_commit"].is_string(), "source_commit missing");
    assert_eq!(
        report["checks"]["paired_artifacts_present"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["checks"]["artifact_sha256s_current"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["output_hashes"]["support_matrix"]
            .as_str()
            .map(str::len),
        Some(64)
    );
    assert_eq!(
        report["output_hashes"]["reality_report"]
            .as_str()
            .map(str::len),
        Some(64)
    );
    assert!(
        report["summary"]["generator_command"]
            .as_str()
            .is_some_and(|cmd| cmd.contains("reality-report")),
        "generator command should be recorded"
    );
    assert_eq!(
        report["regeneration_command"].as_str(),
        Some("scripts/check_support_reality_regeneration.sh --regenerate")
    );

    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("support_reality_regeneration_validated"))
        .expect("pass event should be logged");
    assert_eq!(event["outcome"].as_str(), Some("pass"));
    assert!(
        event["source_commit"].is_string(),
        "log source_commit missing"
    );
}

#[test]
fn checker_fails_when_contract_drops_reality_output() {
    let _guard = gate_lock();
    let root = workspace_root();
    let contract_path = root.join("tests/conformance/support_reality_regeneration.v1.json");
    let mut contract = load_json(&contract_path);
    let outputs = contract["output_artifacts"]
        .as_array_mut()
        .expect("output_artifacts array");
    outputs.retain(|row| row["id"].as_str() != Some("reality_report"));
    let mutation = write_mutation(&root, "drops_reality_output", &contract);

    let output = run_checker(&root, Some(&mutation), None);
    assert!(
        !output.status.success(),
        "checker should reject a one-artifact contract"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("paired_artifacts_missing"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "paired_artifacts_missing");
}

#[test]
fn checker_fails_when_reality_hash_is_stale() {
    let _guard = gate_lock();
    let root = workspace_root();
    let contract_path = root.join("tests/conformance/support_reality_regeneration.v1.json");
    let mut contract = load_json(&contract_path);
    let outputs = contract["output_artifacts"]
        .as_array_mut()
        .expect("output_artifacts array");
    let reality = outputs
        .iter_mut()
        .find(|row| row["id"].as_str() == Some("reality_report"))
        .expect("reality output should exist");
    reality["sha256"] = serde_json::Value::from("0".repeat(64));
    let mutation = write_mutation(&root, "stale_reality_hash", &contract);

    let output = run_checker(&root, Some(&mutation), None);
    assert!(
        !output.status.success(),
        "checker should reject a stale reality hash"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("artifact_sha256_mismatch"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "artifact_sha256_mismatch");
}

#[test]
fn checker_rejects_single_artifact_write_mode() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None, Some("--write-reality-only"));
    assert!(
        !output.status.success(),
        "checker should reject single-artifact write mode"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("single_artifact_update_forbidden"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "single_artifact_update_forbidden");
}
