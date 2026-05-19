//! Contract tests for bd-bp8fl.7.7.1 artifact precedence completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_SPEC_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
];

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "missing_item_bindings_validated",
    "source_manifest_validated",
    "ci_wiring_validated",
    "source_tests_validated",
    "source_checker_replayed",
    "artifact_precedence_completion_contract_pass",
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
    root.join("tests/conformance/artifact_precedence_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_artifact_precedence_completion_contract.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("artifact_precedence_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("artifact_precedence_completion_contract.log.jsonl")
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
        "artifact-precedence-completion-{label}-{}-{nanos}",
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
    mutator: impl FnOnce(&mut Value),
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    mutator(&mut manifest);
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
fn manifest_binds_artifact_precedence_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("artifact_precedence_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.7.7.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.7.7"));

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing bindings"))?;
    assert_eq!(bindings.len(), 3);
    let specs: BTreeSet<String> = bindings
        .iter()
        .filter_map(|binding| binding["spec_item"].as_str())
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        specs,
        REQUIRED_SPEC_ITEMS
            .iter()
            .map(|item| item.to_string())
            .collect()
    );

    let expected_summary = &manifest["artifact_precedence_contract"]["expected_summary"];
    assert_eq!(expected_summary["artifact_count"].as_u64(), Some(12));
    assert_eq!(expected_summary["claim_count"].as_u64(), Some(3));
    assert_eq!(expected_summary["missing_artifact_count"].as_u64(), Some(0));
    assert_eq!(expected_summary["stale_artifact_count"].as_u64(), Some(0));
    assert_eq!(
        expected_summary["conflicting_claim_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        expected_summary["missing_regeneration_command_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        expected_summary["readme_rpc_stub_claim_count"].as_u64(),
        Some(0)
    );
    assert_eq!(expected_summary["prose_only_claim_count"].as_u64(), Some(0));
    assert_eq!(
        expected_summary["out_of_order_artifact_count"].as_u64(),
        Some(0)
    );

    for artifact in manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts array"))?
    {
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
fn checker_validates_artifact_precedence_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["artifact_count"].as_u64(), Some(12));
    assert_eq!(report["summary"]["claim_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(3));
    assert_eq!(
        report["artifact_precedence"]["source_checker"]["status"].as_str(),
        Some("pass")
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
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-e2e")?;
    let bad_contract = mutated_contract(&root, &out_dir, "missing-e2e", |manifest| {
        if let Some(bindings) =
            manifest["completion_debt_evidence"]["missing_item_bindings"].as_array_mut()
        {
            bindings.retain(|binding| binding["spec_item"].as_str() != Some("tests.e2e.primary"));
        }
    })?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_completion_binding"));
    Ok(())
}

#[test]
fn checker_rejects_source_summary_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "summary-drift")?;
    let bad_contract = mutated_contract(&root, &out_dir, "summary-drift", |manifest| {
        manifest["artifact_precedence_contract"]["expected_summary"]["artifact_count"] =
            Value::from(13);
    })?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&report_path(&out_dir))?;
    assert!(
        failure_signatures(&report).contains("source_manifest_drift")
            || failure_signatures(&report).contains("source_checker_failed")
    );
    Ok(())
}
