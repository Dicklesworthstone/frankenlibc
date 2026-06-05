use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory has workspace parent"))?
        .parent()
        .ok_or_else(|| io::Error::other("workspace has root parent"))?
        .to_path_buf();
    Ok(root)
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/fpg_evidence_foundation_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fpg_evidence_foundation_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let content = std::fs::read_to_string(path)?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let dir = root.join(format!(
        "target/conformance/fpg_evidence_foundation_completion_contract_test_{}_{}",
        std::process::id(),
        label
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg(contract)
        .arg(out_dir)
        .current_dir(root)
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "value should be an array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "array item should be a string")
                })?
                .to_string(),
        );
    }
    Ok(set)
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker should fail for mutated contract\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_fpg_evidence_foundation_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("fpg_evidence_foundation_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.3.12"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.3.12.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.integration.primary".to_string(),
            "tests.conformance.primary".to_string()
        ])
    );

    let source_artifacts = manifest["source_artifacts"].as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "source_artifacts should be an object",
        )
    })?;
    assert_eq!(source_artifacts.len(), 9);
    for (name, path) in source_artifacts {
        let rel = path.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "source artifact path should be a string",
            )
        })?;
        assert!(
            root.join(rel).is_file(),
            "source artifact {name} should exist at {rel}"
        );
    }

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        evidence["unit_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        evidence["integration_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );
    assert_eq!(
        evidence["conformance_primary"]["required_artifacts"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );

    let contract = &manifest["required_source_gate_contract"];
    assert_eq!(contract["expected_gap_count"].as_u64(), Some(7));
    assert_eq!(
        contract["expected_required_log_field_count"].as_u64(),
        Some(16)
    );
    assert_eq!(contract["expected_input_artifact_count"].as_u64(), Some(13));
    assert_eq!(
        contract["claim_policy"]["default_decision"].as_str(),
        Some("block_done_until_foundation_evidence_current")
    );
    assert_eq!(
        contract["source_commit_freshness_policy"]["stale_result"].as_str(),
        Some("block_foundation_gate_evidence")
    );

    Ok(())
}

#[test]
fn checker_validates_fpg_evidence_foundation_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report =
        read_json(&out_dir.join("fpg_evidence_foundation_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-bp8fl.3.12"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.3.12.1"));
    assert_eq!(report["source_gate_summary"]["gap_count"].as_u64(), Some(7));
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        report["integration_bindings"].as_array().map(Vec::len),
        Some(5)
    );
    assert_eq!(
        report["conformance_bindings"].as_array().map(Vec::len),
        Some(5)
    );

    let rows = read_jsonl(&out_dir.join("fpg_evidence_foundation_completion_contract.log.jsonl"))?;
    let mut events = BTreeSet::new();
    for row in &rows {
        events.insert(
            row["event"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "event string"))?
                .to_string(),
        );
    }
    assert!(events.contains("fpg_evidence_foundation_completion.source_artifacts"));
    assert!(events.contains("fpg_evidence_foundation_completion.evidence_refs"));
    assert!(events.contains("fpg_evidence_foundation_completion.source_gate_contract"));
    assert!(
        rows.iter()
            .all(|row| row["bead"].as_str() == Some("bd-bp8fl.3.12.1"))
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_integration_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-integration-ref")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["integration_primary"]["required_test_refs"] = json!([]);
    let mutated = out_dir.join("fpg_evidence_foundation_missing_integration_ref.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("fpg_evidence_foundation_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("integration_primary test refs mismatch"),
        "report should cite missing integration refs: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_gap_count_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "gap-count-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_source_gate_contract"]["expected_gap_count"] = json!(6);
    let mutated = out_dir.join("fpg_evidence_foundation_gap_count_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("fpg_evidence_foundation_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("source gate row count drift"),
        "report should cite row count drift: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non-rch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"] =
        json!(["cargo test -p frankenlibc-harness --test fpg_evidence_foundation_gate_test"]);
    let mutated = out_dir.join("fpg_evidence_foundation_non_rch.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("fpg_evidence_foundation_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("non-rch cargo"),
        "report should cite non-rch command: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_source_commit_policy_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "freshness-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_source_gate_contract"]["source_commit_freshness_policy"]["foundation_evidence_allowed_when_stale"] =
        json!(true);
    let mutated = out_dir.join("fpg_evidence_foundation_freshness_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("fpg_evidence_foundation_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("source commit freshness policy drift"),
        "report should cite freshness policy drift: {report}"
    );
    Ok(())
}
