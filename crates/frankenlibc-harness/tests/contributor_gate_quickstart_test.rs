//! Integration tests for the deterministic contributor gate quickstart.
//!
//! The quickstart binds the local evidence-gate sequence contributors should
//! run before making support or replacement-readiness claims.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/contributor_gate_quickstart.v1.json";
const CHECKER_REL: &str = "scripts/check_contributor_gate_quickstart.sh";
const WORKFLOW_IDS: &[&str] = &[
    "architecture_ledger_reconciliation",
    "support_reality_regeneration",
    "fixture_schema_validation",
    "replacement_guard",
    "runtime_mode_evidence",
    "hardened_coverage_inventory",
];

fn repo_root() -> TestResult<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory should have workspace parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent should have repo parent"))?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join(CONTRACT_REL)
}

fn checker_path(root: &Path) -> PathBuf {
    root.join(CHECKER_REL)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "contributor_gate_quickstart_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg("--validate-only")
        .current_dir(root)
        .env("CONTRIBUTOR_GATE_QUICKSTART_CONTRACT", contract)
        .env(
            "CONTRIBUTOR_GATE_QUICKSTART_REPORT",
            out_dir.join("contributor_gate_quickstart.report.json"),
        )
        .env(
            "CONTRIBUTOR_GATE_QUICKSTART_LOG",
            out_dir.join("contributor_gate_quickstart.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    let values = value
        .get(field)
        .ok_or_else(|| io::Error::other(format!("{field} must be present")))?
        .as_array()
        .ok_or_else(|| io::Error::other(format!("{field} must be an array")))?;
    values
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other(format!("{field} entries must be strings")).into())
        })
        .collect()
}

#[test]
fn contract_declares_local_quickstart_workflow_sequence() -> TestResult {
    let root = repo_root()?;
    let contract = load_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("contributor_gate_quickstart.v1")
    );
    assert_eq!(contract["generated_by_bead"].as_str(), Some("bd-0agsk.15"));
    assert_eq!(
        contract["canonical_command"].as_str(),
        Some("scripts/check_contributor_gate_quickstart.sh --validate-only")
    );

    let source_todos = string_set(&contract, "source_todo_ids")?;
    assert_eq!(source_todos, BTreeSet::from(["TODO-1004".to_string()]));
    assert_eq!(
        contract["runner_policy"]["default_execution_host"].as_str(),
        Some("local")
    );
    assert_eq!(
        contract["runner_policy"]["rch_required"].as_bool(),
        Some(false)
    );
    assert_eq!(
        contract["runner_policy"]["report_target_dir"].as_str(),
        Some("target/conformance")
    );

    let workflows = contract["required_workflows"]
        .as_array()
        .ok_or_else(|| io::Error::other("required_workflows must be an array"))?;
    assert_eq!(workflows.len(), WORKFLOW_IDS.len());
    for (index, (workflow, expected_id)) in workflows.iter().zip(WORKFLOW_IDS).enumerate() {
        assert_eq!(workflow["id"].as_str(), Some(*expected_id));
        assert_eq!(workflow["order"].as_u64(), Some((index + 1) as u64));
        assert_eq!(workflow["execution_host"].as_str(), Some("local"));
        assert_eq!(workflow["target_dir"].as_str(), Some("target/conformance"));

        let script = workflow["script"]
            .as_str()
            .ok_or_else(|| io::Error::other("workflow script must be a string"))?;
        assert!(
            root.join(script).is_file(),
            "workflow script should exist: {script}"
        );
        let command = workflow["command"]
            .as_str()
            .ok_or_else(|| io::Error::other("workflow command must be a string"))?;
        assert!(
            command.starts_with(script),
            "workflow command should start with its script path: {command}"
        );

        for artifact in workflow["primary_artifacts"]
            .as_array()
            .ok_or_else(|| io::Error::other("primary_artifacts must be an array"))?
        {
            let artifact = artifact
                .as_str()
                .ok_or_else(|| io::Error::other("primary artifact must be a string"))?;
            assert!(
                root.join(artifact).exists(),
                "primary artifact should exist: {artifact}"
            );
        }
        for report in workflow["expected_reports"]
            .as_array()
            .ok_or_else(|| io::Error::other("expected_reports must be an array"))?
        {
            let report = report
                .as_str()
                .ok_or_else(|| io::Error::other("expected report must be a string"))?;
            assert!(report.starts_with("target/conformance/"));
            assert!(report.ends_with(".json"));
        }
        for log in workflow["expected_logs"]
            .as_array()
            .ok_or_else(|| io::Error::other("expected_logs must be an array"))?
        {
            let log = log
                .as_str()
                .ok_or_else(|| io::Error::other("expected log must be a string"))?;
            assert!(log.starts_with("target/conformance/"));
            assert!(log.ends_with(".jsonl"));
        }
    }

    let negatives: BTreeSet<String> = contract["negative_tests"]
        .as_array()
        .ok_or_else(|| io::Error::other("negative_tests must be an array"))?
        .iter()
        .filter_map(|entry| entry["expected_failure_signature"].as_str())
        .map(str::to_owned)
        .collect();
    for signature in [
        "workflow_set_drift",
        "referenced_script_missing",
        "primary_artifact_missing",
        "failure_signature_unanchored",
    ] {
        assert!(
            negatives.contains(signature),
            "missing negative signature {signature}"
        );
    }

    assert_eq!(
        contract["summary"]["workflow_count"].as_u64(),
        Some(WORKFLOW_IDS.len() as u64)
    );
    assert_eq!(contract["summary"]["rch_command_count"].as_u64(), Some(0));
    Ok(())
}

#[test]
fn checker_emits_pass_report_and_log_for_current_contract() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS: contributor gate quickstart validated")
    );

    let report = load_json(&out.join("contributor_gate_quickstart.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("contributor_gate_quickstart.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.15"));
    assert_eq!(report["mode"].as_str(), Some("validate-only"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));

    let workflow_ids: Vec<&str> = report["summary"]["workflow_ids"]
        .as_array()
        .ok_or_else(|| io::Error::other("workflow_ids must be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(workflow_ids, WORKFLOW_IDS);
    assert_eq!(
        report["summary"]["reports"].as_array().map(Vec::len),
        Some(WORKFLOW_IDS.len())
    );
    assert_eq!(
        report["summary"]["logs"].as_array().map(Vec::len),
        Some(WORKFLOW_IDS.len())
    );

    let rows = read_jsonl(&out.join("contributor_gate_quickstart.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"].as_str(),
        Some("contributor_gate_quickstart_validated")
    );
    assert_eq!(rows[0]["outcome"].as_str(), Some("pass"));
    assert_eq!(rows[0]["failure_signature"].as_str(), Some("none"));
    Ok(())
}

#[test]
fn checker_rejects_workflow_command_drift() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "command_drift")?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["required_workflows"][0]["command"] =
        json!("scripts/check_missing_contributor_gate_quickstart.sh");
    let mutated = out.join("contributor_gate_quickstart_command_drift.v1.json");
    write_json(&mutated, &contract)?;

    let output = run_checker(&root, &mutated, &out)?;
    assert!(!output.status.success(), "{}", output_text(&output));

    let report = load_json(&out.join("contributor_gate_quickstart.report.json"))?;
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("workflow_command_drift")
    );
    assert_eq!(
        report["summary"]["actual"].as_str(),
        Some("scripts/check_missing_contributor_gate_quickstart.sh")
    );

    let rows = read_jsonl(&out.join("contributor_gate_quickstart.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"].as_str(),
        Some("contributor_gate_quickstart_failed")
    );
    assert_eq!(
        rows[0]["failure_signature"].as_str(),
        Some("workflow_command_drift")
    );
    Ok(())
}
