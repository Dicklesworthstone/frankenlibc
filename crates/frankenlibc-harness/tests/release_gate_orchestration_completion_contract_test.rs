//! Contract tests for bd-5fw.2.1 release-gate orchestration completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
];

const EXPECTED_SEQUENCE: &[&str] = &[
    "lint",
    "unit",
    "conformance",
    "conformance_coverage",
    "claim_reconciliation",
    "e2e",
    "perf",
    "docs_reports",
    "release_dossier",
];

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_bindings_validated",
    "release_gate_dag_validated",
    "release_dry_run_pass_replayed",
    "release_dry_run_fail_fast_resume_replayed",
    "release_dry_run_source_checker_replayed",
    "release_gate_orchestration_completion_contract_pass",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/release_gate_orchestration_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_release_gate_orchestration_completion_contract.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("release_gate_orchestration_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("release_gate_orchestration_completion_contract.log.jsonl")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "release-gate-orchestration-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg(contract)
        .arg(out_dir)
        .current_dir(root)
        .env("TMPDIR", "/data/tmp")
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    match report["errors"].as_array() {
        Some(errors) => errors
            .iter()
            .filter_map(|row| row["failure_signature"].as_str())
            .map(ToString::to_string)
            .collect(),
        None => BTreeSet::new(),
    }
}

fn mutated_contract(
    root: &Path,
    out_dir: &Path,
    label: &str,
    mutator: impl FnOnce(&mut Value),
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    mutator(&mut manifest);
    let path = out_dir.join(format!("{label}.contract.json"));
    write_json(&path, &manifest)?;
    Ok(path)
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_gate_orchestration_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("release_gate_orchestration_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-5fw.2.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-5fw.2"));

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing bindings"))?;
    let bound_items: BTreeSet<String> = bindings
        .iter()
        .filter_map(|row| row["spec_item"].as_str())
        .map(ToString::to_string)
        .collect();
    let required_items: BTreeSet<String> =
        REQUIRED_ITEMS.iter().map(|item| item.to_string()).collect();
    assert_eq!(bound_items, required_items);

    let expected_sequence = string_set(&manifest["gate_contract"]["expected_full_gate_sequence"])?;
    let required_sequence: BTreeSet<String> = EXPECTED_SEQUENCE
        .iter()
        .map(|item| item.to_string())
        .collect();
    assert_eq!(expected_sequence, required_sequence);

    for artifact in manifest["source_artifacts"].as_array().unwrap() {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path missing"))?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }

    let required_events = string_set(&manifest["completion_output_contract"]["required_events"])?;
    let expected_events: BTreeSet<String> = REQUIRED_EVENTS
        .iter()
        .map(|item| item.to_string())
        .collect();
    assert_eq!(required_events, expected_events);
    Ok(())
}

#[test]
fn checker_replays_gate_order_fail_fast_resume_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\n{}",
        output_text(&output)
    );

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["gate_count"].as_u64(),
        Some(EXPECTED_SEQUENCE.len() as u64)
    );
    assert_eq!(
        report["missing_item_bindings"].as_array().unwrap().len(),
        REQUIRED_ITEMS.len()
    );

    let rows = read_jsonl(&log_path(&out_dir))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .map(ToString::to_string)
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(*event), "missing event {event}");
    }

    for (_, value) in report["generated_artifacts"].as_object().unwrap() {
        let path = value
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact ref not string"))?;
        assert!(
            root.join(path).exists(),
            "generated artifact missing: {path}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_integration_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-integration")?;
    let bad_contract = mutated_contract(&root, &out_dir, "missing-integration", |manifest| {
        let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
            .as_array_mut()
            .expect("bindings should be an array");
        bindings.retain(|row| row["spec_item"].as_str() != Some("tests.integration.primary"));
    })?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_completion_binding"));
    Ok(())
}

#[test]
fn checker_rejects_gate_sequence_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gate-sequence-drift")?;
    let bad_contract = mutated_contract(&root, &out_dir, "gate-sequence-drift", |manifest| {
        let sequence = manifest["gate_contract"]["expected_full_gate_sequence"]
            .as_array_mut()
            .expect("expected sequence should be an array");
        sequence.retain(|gate| gate.as_str() != Some("claim_reconciliation"));
    })?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("gate_sequence_mismatch"));
    Ok(())
}
