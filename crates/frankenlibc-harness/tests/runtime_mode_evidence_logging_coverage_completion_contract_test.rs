//! Contract tests for bd-0agsk.11.1 runtime-mode evidence logging completion.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_SPEC_ITEMS: &[&str] = &["telemetry.primary", "tests.conformance.primary"];
const REQUIRED_CAMPAIGNS: &[&str] = &[
    "c_fixture_suite",
    "e2e_suite",
    "harness_conformance_matrix_isolated",
    "harness_kernel_regression_report",
    "ld_preload_smoke",
    "shadow_run_candidate_replay",
    "standalone_link_run_smoke",
];
const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_bindings_validated",
    "source_contract_validated",
    "source_checker_replayed",
    "telemetry_output_validated",
    "conformance_test_bindings_validated",
    "runtime_mode_evidence_logging_coverage_completion_contract_pass",
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
    root.join(
        "tests/conformance/runtime_mode_evidence_logging_coverage_completion_contract.v1.json",
    )
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_mode_evidence_logging_coverage_completion_contract.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("runtime_mode_evidence_logging_coverage_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("runtime_mode_evidence_logging_coverage_completion_contract.log.jsonl")
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
        "runtime-mode-evidence-completion-{label}-{}-{nanos}",
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
fn manifest_binds_runtime_mode_evidence_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_mode_evidence_logging_coverage_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-0agsk.11.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-0agsk.11"));

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing bindings"))?;
    assert_eq!(bindings.len(), 2);
    let specs: BTreeSet<String> = bindings
        .iter()
        .filter_map(|binding| binding["spec_item"].as_str())
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        specs,
        REQUIRED_SPEC_ITEMS
            .iter()
            .map(|spec| spec.to_string())
            .collect()
    );

    let runtime = &manifest["runtime_mode_evidence_contract"];
    assert_eq!(
        runtime["expected_summary"]["coverage_row_count"].as_u64(),
        Some(7)
    );
    assert_eq!(
        runtime["expected_summary"]["startup_evidence_row_count"].as_u64(),
        Some(7)
    );
    assert_eq!(
        runtime["expected_summary"]["ambient_tz_dependent_row_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        runtime["required_policy"]["env_key"].as_str(),
        Some("FRANKENLIBC_MODE")
    );

    let campaigns = string_set(&runtime["required_campaign_ids"])?;
    assert_eq!(
        campaigns,
        REQUIRED_CAMPAIGNS
            .iter()
            .map(|campaign| campaign.to_string())
            .collect()
    );

    for artifact in manifest["source_artifacts"].as_array().unwrap() {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path missing"))?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }

    let events = string_set(&manifest["completion_output_contract"]["required_events"])?;
    let required_events: BTreeSet<String> = REQUIRED_EVENTS
        .iter()
        .map(|event| event.to_string())
        .collect();
    assert_eq!(events, required_events);
    Ok(())
}

#[test]
fn checker_validates_runtime_mode_evidence_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["campaign_count"].as_u64(), Some(7));
    assert_eq!(
        report["summary"]["expected_coverage_rows"].as_u64(),
        Some(7)
    );
    assert_eq!(report["summary"]["expected_startup_rows"].as_u64(), Some(7));

    let source_report =
        read_json(&out_dir.join("runtime_mode_evidence_logging_coverage.source.report.json"))?;
    assert_eq!(source_report["outcome"].as_str(), Some("pass"));
    assert_eq!(source_report["summary"]["coverage_rows"].as_u64(), Some(7));

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
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let contract = mutated_contract(&root, &out_dir, "missing-telemetry", |manifest| {
        let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
            .as_array_mut()
            .expect("bindings array");
        bindings.retain(|binding| binding["spec_item"].as_str() != Some("telemetry.primary"));
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("missing_completion_binding"));
    Ok(())
}

#[test]
fn checker_rejects_source_summary_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "summary-drift")?;
    let contract = mutated_contract(&root, &out_dir, "summary-drift", |manifest| {
        manifest["runtime_mode_evidence_contract"]["expected_summary"]["coverage_row_count"] =
            Value::from(99);
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("source_contract_drift"));
    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-source-test")?;
    let contract = mutated_contract(&root, &out_dir, "missing-source-test", |manifest| {
        let tests = manifest["runtime_mode_evidence_contract"]["required_source_tests"]
            .as_array_mut()
            .expect("required source tests array");
        tests.retain(|test| {
            test.as_str()
                != Some("isolated_conformance_child_overrides_ambient_mode_and_logs_startup")
        });
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("conformance_binding_drift"));
    Ok(())
}
