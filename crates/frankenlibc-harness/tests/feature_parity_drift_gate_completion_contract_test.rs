//! Completion-contract tests for bd-w2c3.1.2.1 drift-gate evidence.

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
    "feature_parity_drift_gate_completion_source_gates_replayed",
    "feature_parity_drift_gate_completion_validated",
    "feature_parity_drift_gate_completion_failed",
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
    root.join("tests/conformance/feature_parity_drift_gate_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_feature_parity_drift_gate_completion_contract.sh")
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
        "feature-parity-drift-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FLC_FP_DRIFT_COMPLETION_CONTRACT", contract)
        .env(
            "FLC_FP_DRIFT_COMPLETION_REPORT",
            out_dir.join("feature_parity_drift_gate_completion_contract.report.json"),
        )
        .env(
            "FLC_FP_DRIFT_COMPLETION_LOG",
            out_dir.join("feature_parity_drift_gate_completion_contract.log.jsonl"),
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
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );
    Ok(out_dir)
}

#[test]
fn contract_binds_all_source_gates_and_missing_items() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("feature_parity_drift_gate_completion_contract.v1")
    );
    assert_eq!(
        contract["completion_debt_bead"].as_str(),
        Some("bd-w2c3.1.2.1")
    );
    assert_eq!(contract["original_bead"].as_str(), Some("bd-w2c3.1.2"));
    assert!(contract["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800);

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(
        string_set(&evidence["missing_items"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| item.to_string())
            .collect()
    );

    let source_gates = evidence["source_gates"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_gates object"))?;
    for key in [
        "feature_parity_drift",
        "support_matrix_maintenance",
        "feature_parity_gap_bead_coverage",
        "feature_parity_gap_ledger",
    ] {
        let gate = source_gates
            .get(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source gate missing"))?;
        for path_key in ["script", "artifact", "harness_test"] {
            let path = gate[path_key]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "path string"))?;
            assert!(
                root.join(path).is_file(),
                "{key} {path_key} missing: {path}"
            );
        }
    }
    assert_eq!(
        source_gates["support_matrix_maintenance"]["expected_outcome"].as_str(),
        Some("pass_or_fail_closed")
    );
    Ok(())
}

#[test]
fn checker_replays_source_gates_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report =
        read_json(&out_dir.join("feature_parity_drift_gate_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("feature_parity_drift_gate_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        string_set(&report["missing_items_bound"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| item.to_string())
            .collect()
    );

    let results = report["source_gate_results"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source gate results"))?;
    for key in [
        "feature_parity_drift",
        "support_matrix_maintenance",
        "feature_parity_gap_bead_coverage",
        "feature_parity_gap_ledger",
    ] {
        let gate = results
            .get(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing gate result"))?;
        assert_eq!(gate["accepted"].as_bool(), Some(true), "{key} not accepted");
    }
    assert!(
        results["feature_parity_drift"]["diagnostic_count"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(
        results["feature_parity_gap_bead_coverage"]["uncovered_gaps"].as_i64(),
        Some(0)
    );
    assert!(
        matches!(
            results["support_matrix_maintenance"]["status"].as_str(),
            Some("pass") | Some("fail_closed")
        ),
        "support matrix maintenance must pass or fail closed"
    );

    let rows =
        read_jsonl(&out_dir.join("feature_parity_drift_gate_completion_contract.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    assert!(events.contains("feature_parity_drift_gate_completion_source_gates_replayed"));
    assert!(events.contains("feature_parity_drift_gate_completion_validated"));
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "bare-cargo")?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["tests_e2e_primary"]["required_commands"][2] = serde_json::json!(
        "cargo test -p frankenlibc-harness --test feature_parity_drift_gate_completion_contract_test"
    );
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &contract)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail on bare cargo command"
    );
    let message = checker_output_message(&output);
    assert!(
        message.contains("required command must use rch"),
        "failure should name local cargo rejection: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_ref() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-test-ref")?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["tests_unit_primary"]["required_test_refs"][0]["name"] =
        serde_json::json!("missing_source_test_ref_for_completion_gate");
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &contract)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail when a source test ref is missing"
    );
    let message = checker_output_message(&output);
    assert!(
        message.contains("missing referenced test"),
        "failure should name missing source test ref: {message}"
    );
    Ok(())
}

#[test]
fn telemetry_contract_lists_required_events_and_fields() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;
    let telemetry = &contract["completion_debt_evidence"]["telemetry_primary"];
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
        "source_gate_results",
        "artifact_refs",
        "failure_signature",
    ] {
        assert!(
            string_set(&telemetry["required_fields"])?.contains(field),
            "telemetry should require {field}"
        );
    }
    for field in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(
            string_set(&telemetry["source_event_fields"])?.contains(field),
            "source telemetry should require {field}"
        );
    }
    Ok(())
}
