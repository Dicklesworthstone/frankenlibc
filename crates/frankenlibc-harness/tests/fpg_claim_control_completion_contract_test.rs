//! Contract tests for bd-bp8fl.3.5.1 fpg-claim-control completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_GAP_IDS: &[&str] = &[
    "fp-macro-targets-fa7a23e18f01",
    "fp-macro-targets-7b75050a0f03",
    "fp-macro-targets-025864627e97",
    "fp-macro-targets-b1b8d5acbeff",
    "fp-macro-targets-b1983d62901c",
    "fp-macro-targets-556631616b22",
    "fp-macro-targets-1e330b896784",
];

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "conformance_binding_validated",
    "fpg_claim_control_gate_validated",
    "source_checker_validate_only_replayed",
    "fpg_claim_control_completion_contract_pass",
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
    root.join("tests/conformance/fpg_claim_control_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fpg_claim_control_completion_contract.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("fpg_claim_control_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("fpg_claim_control_completion_contract.log.jsonl")
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
        "fpg-claim-control-completion-{label}-{}-{nanos}",
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

fn mutated_contract(
    root: &Path,
    out_dir: &Path,
    label: &str,
    mutator: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    mutator(&mut manifest)?;
    let path = out_dir.join(format!("{label}.contract.json"));
    write_json(&path, &manifest)?;
    Ok(path)
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

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_fpg_claim_control_conformance_item() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("fpg_claim_control_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.3.5.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.3.5"));

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing bindings"))?;
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0]["spec_item"].as_str(),
        Some("tests.conformance.primary")
    );

    let expected_ids = string_set(&manifest["fpg_claim_control_contract"]["expected_gap_ids"])?;
    let required_ids: BTreeSet<String> = EXPECTED_GAP_IDS
        .iter()
        .map(|item| item.to_string())
        .collect();
    assert_eq!(expected_ids, required_ids);

    let source_artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts missing"))?;
    for artifact in source_artifacts {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path missing"))?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }

    let events = string_set(&manifest["completion_output_contract"]["required_events"])?;
    let required_events: BTreeSet<String> = REQUIRED_EVENTS
        .iter()
        .map(|item| item.to_string())
        .collect();
    assert_eq!(events, required_events);
    Ok(())
}

#[test]
fn checker_validates_fpg_claim_control_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["gap_count"].as_u64(), Some(7));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(1));
    assert_eq!(
        report["fpg_claim_control"]["source_checker"]["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        string_set(&report["fpg_claim_control"]["gap_ids"])?,
        EXPECTED_GAP_IDS
            .iter()
            .map(|item| item.to_string())
            .collect()
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
    Ok(())
}

#[test]
fn checker_rejects_missing_conformance_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-conformance")?;
    let bad_contract = mutated_contract(&root, &out_dir, "missing-conformance", |manifest| {
        manifest["completion_debt_evidence"]["missing_item_bindings"] = Value::Array(Vec::new());
        Ok(())
    })?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_conformance_binding"));
    Ok(())
}

#[test]
fn checker_rejects_gap_id_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gap-id-drift")?;
    let bad_contract = mutated_contract(&root, &out_dir, "gap-id-drift", |manifest| {
        let ids = manifest["fpg_claim_control_contract"]["expected_gap_ids"]
            .as_array_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected_gap_ids array"))?;
        ids.retain(|id| id.as_str() != Some("fp-macro-targets-fa7a23e18f01"));
        Ok(())
    })?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("gap_id_drift"));
    Ok(())
}
