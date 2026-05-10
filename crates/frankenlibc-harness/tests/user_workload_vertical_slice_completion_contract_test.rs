//! Completion-contract tests for bd-bp8fl.10.6.1 user workload vertical slice evidence.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_MISSING_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
];

const EXPECTED_EVENTS: &[&str] = &[
    "user_workload_vertical_slice_completion_contract_validated",
    "user_workload_vertical_slice_completion_contract_failed",
    "user_workload_vertical_slice_replayed",
    "user_workload_vertical_slice_claim_blocker_preserved",
    "user_workload_vertical_slice_completion_summary",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "workload_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
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
    root.join("tests/conformance/user_workload_vertical_slice_completion_contract.v1.json")
}

fn source_manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/user_workload_vertical_slice.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_user_workload_vertical_slice_completion_contract.sh")
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "user-workload-vertical-slice-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    source_manifest: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_VERTICAL_SLICE_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_MANIFEST",
            source_manifest,
        )
        .env(
            "FRANKENLIBC_VERTICAL_SLICE_COMPLETION_REPORT",
            out_dir.join("user_workload_vertical_slice_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_VERTICAL_SLICE_COMPLETION_LOG",
            out_dir.join("user_workload_vertical_slice_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_REPORT",
            out_dir.join("user_workload_vertical_slice_completion_contract.source.report.json"),
        )
        .env(
            "FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_LOG",
            out_dir.join("user_workload_vertical_slice_completion_contract.source.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_INDEX",
            out_dir.join(
                "user_workload_vertical_slice_completion_contract.source.artifact_index.json",
            ),
        )
        .output()?)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let text = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = text.lines().collect();
    assert!(
        line_no <= lines.len(),
        "file-line ref outside file: {file_line_ref}"
    );
    assert!(
        !lines[line_no - 1].trim().is_empty(),
        "file-line ref should not cite a blank line: {file_line_ref}"
    );
    Ok(())
}

fn source_text(root: &Path, path: &str) -> TestResult<String> {
    Ok(std::fs::read_to_string(root.join(path))?)
}

fn assert_checker_failed(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn manifest_binds_missing_items_and_vertical_slice_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("user_workload_vertical_slice_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.10.6.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.10.6"));

    for path in manifest["source_artifacts"].as_object().unwrap().values() {
        let rel = path.as_str().unwrap();
        assert!(
            root.join(rel).exists(),
            "source artifact should exist: {rel}"
        );
    }

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|binding| binding["missing_item_id"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        bindings,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    for item in manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .unwrap()
    {
        assert_file_line_ref_exists(&root, item.as_str().unwrap())?;
    }

    let contract = &manifest["completion_debt_evidence"]["required_vertical_slice_contract"];
    assert_eq!(contract["bead"].as_str(), Some("bd-bp8fl.10.6"));
    assert_eq!(
        contract["selected_workload_id"].as_str(),
        Some("uwm-shell-coreutils")
    );
    assert_eq!(contract["minimum_replay_binding_count"].as_u64(), Some(2));
    assert_eq!(
        string_set(&contract["required_log_fields"])?,
        REQUIRED_LOG_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect()
    );
    Ok(())
}

#[test]
fn source_gate_and_tests_are_anchored() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let evidence = &manifest["completion_debt_evidence"];
    let source_harness = source_text(
        &root,
        evidence["test_sources"]["source_harness"].as_str().unwrap(),
    )?;
    let completion_harness = source_text(
        &root,
        evidence["test_sources"]["completion_harness"]
            .as_str()
            .unwrap(),
    )?;
    let checker = source_text(
        &root,
        manifest["source_artifacts"]["completion_gate"]
            .as_str()
            .unwrap(),
    )?;

    for section in [
        "unit_primary",
        "e2e_primary",
        "conformance_primary",
        "telemetry_primary",
    ] {
        for test_ref in evidence[section]["required_test_refs"].as_array().unwrap() {
            let source_name = test_ref["source"].as_str().unwrap();
            let test_name = test_ref["name"].as_str().unwrap();
            let source = if source_name == "source_harness" {
                &source_harness
            } else {
                &completion_harness
            };
            assert!(
                source.contains(&format!("fn {test_name}")),
                "{section} references missing test {source_name}::{test_name}"
            );
        }
    }

    for needle in [
        "check_user_workload_vertical_slice.sh",
        "required_vertical_slice_contract",
        "claim_blocked",
        "user_workload_vertical_slice_replayed",
    ] {
        assert!(checker.contains(needle), "checker missing {needle}");
    }
    Ok(())
}

#[test]
fn checker_runs_source_gate_and_emits_completion_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &source_manifest_path(&root),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        read_json(&out_dir.join("user_workload_vertical_slice_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["missing_items_bound"].as_array().unwrap().len(),
        EXPECTED_MISSING_ITEMS.len()
    );
    assert_eq!(
        report["vertical_slice_summary"]["selected_workload_id"].as_str(),
        Some("uwm-shell-coreutils")
    );
    assert_eq!(
        report["vertical_slice_summary"]["replay_binding_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        report["vertical_slice_summary"]["expected_current_decision"]["status"].as_str(),
        Some("claim_blocked")
    );

    let completion_rows =
        read_jsonl(&out_dir.join("user_workload_vertical_slice_completion_contract.log.jsonl"))?;
    let completion_events = completion_rows
        .iter()
        .map(|row| row["event"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    for event in EXPECTED_EVENTS
        .iter()
        .filter(|event| **event != "user_workload_vertical_slice_completion_contract_failed")
    {
        assert!(completion_events.contains(*event), "missing event {event}");
    }
    for (index, row) in completion_rows.iter().enumerate() {
        let line = serde_json::to_string(row)?;
        let errors = validate_log_line(&line, index + 1)
            .err()
            .unwrap_or_default();
        assert!(
            errors.is_empty(),
            "completion log row {index} rejected: {errors:?}"
        );
    }

    let source_report = read_json(
        &out_dir.join("user_workload_vertical_slice_completion_contract.source.report.json"),
    )?;
    assert_eq!(source_report["status"].as_str(), Some("pass"));
    let source_rows = read_jsonl(
        &out_dir.join("user_workload_vertical_slice_completion_contract.source.log.jsonl"),
    )?;
    assert_eq!(source_rows.len(), 2);
    Ok(())
}

#[test]
fn checker_rejects_missing_required_log_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-log-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_vertical_slice_contract"]["required_log_fields"]
        .as_array_mut()
        .unwrap()
        .retain(|field| field.as_str() != Some("source_commit"));
    let bad_contract = out_dir.join("bad-contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &source_manifest_path(&root), &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("user_workload_vertical_slice_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("required_log_fields"))
    );
    Ok(())
}

#[test]
fn checker_rejects_unblocked_support_claim() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "unblocked-support")?;
    let mut source_manifest = read_json(&source_manifest_path(&root))?;
    source_manifest["expected_current_decision"]["support_claimed"] = serde_json::json!(true);
    let bad_source_manifest = out_dir.join("bad-source-manifest.json");
    write_json(&bad_source_manifest, &source_manifest)?;

    let output = run_checker(&root, &contract_path(&root), &bad_source_manifest, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("user_workload_vertical_slice_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(report["errors"].as_array().unwrap().iter().any(|error| {
        error.as_str().unwrap().contains("support")
            || error
                .as_str()
                .unwrap()
                .contains("expected_current_decision")
    }));
    Ok(())
}

#[test]
fn checker_rejects_missing_smoke_case_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-smoke")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_vertical_slice_contract"]
        ["required_negative_test_ids"]
        .as_array_mut()
        .unwrap()
        .retain(|id| id.as_str() != Some("missing_smoke_case"));
    let bad_contract = out_dir.join("bad-contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &source_manifest_path(&root), &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("user_workload_vertical_slice_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(report["errors"].as_array().unwrap().iter().any(|error| {
        error
            .as_str()
            .unwrap()
            .contains("required_negative_test_ids")
    }));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"]
        .as_array_mut()
        .unwrap()
        .retain(|event| event.as_str() != Some("user_workload_vertical_slice_replayed"));
    let bad_contract = out_dir.join("bad-contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &source_manifest_path(&root), &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("user_workload_vertical_slice_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("required_events"))
    );
    Ok(())
}
