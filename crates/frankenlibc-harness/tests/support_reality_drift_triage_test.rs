//! Integration test: support/reality drift triage gate.

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
        "support_reality_drift_triage_{name}_{}_{}.json",
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

fn run_checker(root: &Path, triage_override: Option<&Path>) -> std::process::Output {
    let script = root.join("scripts/check_support_reality_drift_triage.sh");
    let mut command = Command::new(&script);
    command.arg("--validate-only").current_dir(root);
    if let Some(path) = triage_override {
        command.env("SUPPORT_REALITY_DRIFT_TRIAGE_REPORT", path);
    }
    command
        .output()
        .expect("failed to run support/reality drift triage checker")
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path = root.join("target/conformance/support_reality_drift_triage.report.json");
    let log_path = root.join("target/conformance/support_reality_drift_triage.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some(expected_signature)
    );
    let rows = load_jsonl(&log_path);
    let event = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("support_reality_drift_triage_failed"))
        .expect("failure event should be logged");
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
}

#[test]
fn triage_report_has_required_shape() {
    let root = workspace_root();
    let triage_path = root.join("tests/conformance/support_reality_drift_triage.v1.json");
    let triage = load_json(&triage_path);
    assert_eq!(
        triage["schema_version"].as_str(),
        Some("support_reality_drift_triage.v1")
    );
    assert_eq!(triage["generated_by_bead"].as_str(), Some("bd-0agsk.4"));
    assert_eq!(triage["claim_status"].as_str(), Some("triage_report_only"));
    assert_eq!(triage["summary"]["delta_symbol_count"].as_u64(), Some(75));
    assert_eq!(triage["summary"]["missing_export_count"].as_u64(), Some(5));
    assert_eq!(
        triage["summary"]["expected_unsupported_surface_count"].as_u64(),
        Some(70)
    );
    assert!(
        triage["delta_buckets"]
            .as_array()
            .is_some_and(|rows| rows.len() >= 3),
        "expected classified delta buckets"
    );
}

#[test]
fn checker_passes_and_emits_summary() {
    let _guard = gate_lock();
    let root = workspace_root();
    let output = run_checker(&root, None);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/support_reality_drift_triage.report.json");
    let log_path = root.join("target/conformance/support_reality_drift_triage.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(
        report["schema_version"].as_str(),
        Some("support_reality_drift_triage.report.v1")
    );
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(
        report["checks"]["version_script_deltas_classified"].as_str(),
        Some("pass")
    );
    assert_eq!(report["summary"]["delta_symbol_count"].as_u64(), Some(75));
    assert_eq!(
        report["summary"]["classification_counts"]["expected_unsupported_surface"].as_u64(),
        Some(70)
    );

    let rows = load_jsonl(&log_path);
    assert!(
        rows.iter()
            .any(|row| row["event"].as_str() == Some("support_reality_drift_triage_validated")),
        "pass event should be logged"
    );
}

#[test]
fn checker_accepts_expected_unsupported_surface_row() {
    let root = workspace_root();
    let triage_path = root.join("tests/conformance/support_reality_drift_triage.v1.json");
    let triage = load_json(&triage_path);
    let accepted = triage["accepted_expected_unsupported_rows"]
        .as_array()
        .expect("accepted expected unsupported rows");
    assert!(
        accepted.iter().any(|row| {
            row["symbol"].as_str() == Some("__cxa_bad_cast")
                && row["classification"].as_str() == Some("expected_unsupported_surface")
        }),
        "expected unsupported compatibility export should be accepted"
    );
}

#[test]
fn checker_fails_on_unclassified_delta() {
    let _guard = gate_lock();
    let root = workspace_root();
    let triage_path = root.join("tests/conformance/support_reality_drift_triage.v1.json");
    let mut triage = load_json(&triage_path);
    triage["delta_buckets"][0]["classification"] = serde_json::Value::from("unclassified");
    let mutation = write_mutation(&root, "unclassified_delta", &triage);

    let output = run_checker(&root, Some(&mutation));
    assert!(
        !output.status.success(),
        "checker should reject unclassified deltas"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unclassified_delta"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "unclassified_delta");
}

#[test]
fn checker_fails_when_expected_delta_is_missing() {
    let _guard = gate_lock();
    let root = workspace_root();
    let triage_path = root.join("tests/conformance/support_reality_drift_triage.v1.json");
    let mut triage = load_json(&triage_path);
    let first_bucket = triage["delta_buckets"][0]
        .as_object_mut()
        .expect("first bucket must be object");
    let symbols = first_bucket
        .get_mut("symbols")
        .and_then(|value| value.as_array_mut())
        .expect("symbols must be array");
    symbols.retain(|value| value.as_str() != Some("_IO_2_1_stderr_"));
    let mutation = write_mutation(&root, "missing_expected_delta", &triage);

    let output = run_checker(&root, Some(&mutation));
    assert!(
        !output.status.success(),
        "checker should reject missing expected deltas"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("delta_symbol_missing"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "delta_symbol_missing");
}
