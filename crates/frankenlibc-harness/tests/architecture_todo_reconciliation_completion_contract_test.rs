//! Completion-contract tests for bd-0agsk.1.1 architecture TODO reconciliation evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_MISSING_ITEMS: &[&str] = &[
    "tests.conformance.primary",
    "migrations.primary",
    "theater.todo_wording.primary",
];

const EXPECTED_EVENTS: &[&str] = &[
    "architecture_todo_reconciliation_completion_validated",
    "architecture_todo_reconciliation_source_gate_replayed",
    "architecture_todo_reconciliation_completion_failed",
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
    root.join("tests/conformance/architecture_todo_reconciliation_completion_contract.v1.json")
}

fn source_artifact_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/architecture_todo_reconciliation.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_architecture_todo_reconciliation_completion_contract.sh")
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
        "architecture-todo-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    source_artifact: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_ARCH_TODO_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_ARCH_TODO_COMPLETION_SOURCE_ARTIFACT",
            source_artifact,
        )
        .env(
            "FRANKENLIBC_ARCH_TODO_COMPLETION_REPORT",
            out_dir.join("architecture_todo_reconciliation_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ARCH_TODO_COMPLETION_LOG",
            out_dir.join("architecture_todo_reconciliation_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out_dir = unique_output_dir(root, label)?;
    let output = run_checker(
        root,
        &contract_path(root),
        &source_artifact_path(root),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );
    Ok(out_dir)
}

fn failure_message(output: &std::process::Output) -> String {
    checker_output_message(output)
}

#[test]
fn contract_binds_architecture_source_gate_and_missing_items() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("architecture_todo_reconciliation_completion_contract.v1")
    );
    assert_eq!(
        contract["completion_debt_bead"].as_str(),
        Some("bd-0agsk.1.1")
    );
    assert_eq!(contract["original_bead"].as_str(), Some("bd-0agsk.1"));
    assert!(contract["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800);

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| item.to_string())
            .collect()
    );

    let source_contract = &evidence["source_contract"];
    assert_eq!(
        source_contract["artifact"].as_str(),
        Some("tests/conformance/architecture_todo_reconciliation.v1.json")
    );
    assert_eq!(
        source_contract["generated_by_bead"].as_str(),
        Some("bd-0agsk.1")
    );
    assert_eq!(
        source_contract["claim_status"].as_str(),
        Some("report_only")
    );
    assert_eq!(
        source_contract["replacement_level_change"].as_str(),
        Some("forbidden")
    );
    assert_eq!(
        source_contract["expected_counts"]["row_count"].as_u64(),
        Some(73)
    );

    let test_sources = evidence["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    for path in test_sources.values() {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        assert!(root.join(path).is_file(), "missing test source {path}");
    }
    Ok(())
}

#[test]
fn checker_emits_completion_report_log_and_replays_source_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report = read_json(
        &out_dir.join("architecture_todo_reconciliation_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("architecture_todo_reconciliation_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["row_count"].as_u64(), Some(73));
    assert_eq!(report["mapped_row_count"].as_u64(), Some(73));
    assert_eq!(
        string_set(&report["missing_items_bound"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| item.to_string())
            .collect()
    );

    let rows = read_jsonl(
        &out_dir.join("architecture_todo_reconciliation_completion_contract.log.jsonl"),
    )?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    assert!(events.contains("architecture_todo_reconciliation_completion_validated"));
    assert!(events.contains("architecture_todo_reconciliation_source_gate_replayed"));

    let source_report_ref = report["source_report"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_report string"))?;
    let source_report_path = if Path::new(source_report_ref).is_absolute() {
        PathBuf::from(source_report_ref)
    } else {
        root.join(source_report_ref)
    };
    let source_report = read_json(&source_report_path)?;
    let checks = source_report["checks"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source checks object"))?;
    assert!(checks.values().all(|value| value.as_str() == Some("pass")));
    Ok(())
}

#[test]
fn checker_rejects_source_artifact_count_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "bad-source-count")?;
    let mut source = read_json(&source_artifact_path(&root))?;
    source["ledger_counts"]["row_count"] = serde_json::json!(72);
    let bad_source = out_dir.join("bad_source.json");
    write_json(&bad_source, &source)?;

    let output = run_checker(&root, &contract_path(&root), &bad_source, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail on count drift"
    );
    let message = failure_message(&output);
    assert!(
        message.contains("ledger_counts row_count mismatch")
            || message.contains("source architecture TODO checker failed"),
        "failure should name count drift: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "bare-cargo")?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["tests_conformance_primary"]["required_commands"][0] = serde_json::json!(
        "cargo test -p frankenlibc-harness --test architecture_todo_reconciliation_test"
    );
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &contract)?;

    let output = run_checker(&root, &bad_contract, &source_artifact_path(&root), &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail on bare cargo command"
    );
    let message = failure_message(&output);
    assert!(
        message.contains("required command must use rch"),
        "failure should name local cargo rejection: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_theater_resolution() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-theater-resolution")?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["theater_todo_wording_primary"]["resolution_policy"] =
        serde_json::json!("TODO rows are fine.");
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &contract)?;

    let output = run_checker(&root, &bad_contract, &source_artifact_path(&root), &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail when theater resolution weakens"
    );
    let message = failure_message(&output);
    assert!(
        message.contains("theater TODO wording resolution is missing or too weak"),
        "failure should name theater resolution drift: {message}"
    );
    Ok(())
}

#[test]
fn telemetry_contract_lists_required_events_and_fields() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;
    let telemetry = &contract["completion_debt_evidence"]["telemetry"];
    assert_eq!(
        string_set(&telemetry["required_events"])?,
        EXPECTED_EVENTS
            .iter()
            .map(|item| item.to_string())
            .collect()
    );
    for field in [
        "timestamp",
        "trace_id",
        "completion_debt_bead",
        "original_bead",
        "row_count",
        "mapped_row_count",
        "failure_signature",
    ] {
        assert!(
            string_set(&telemetry["required_fields"])?.contains(field),
            "telemetry should require {field}"
        );
    }
    Ok(())
}
