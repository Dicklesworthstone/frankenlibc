use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace has root parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/real_program_smoke_suite_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_real_program_smoke_suite_completion_contract.sh")
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
        "target/conformance/real_program_smoke_suite_completion_contract_test_{}_{}",
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

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("value should be an array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("array item should be a string")
                .to_string()
        })
        .collect()
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker should fail for mutated contract\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_real_program_smoke_completion_items() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("real_program_smoke_suite_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.10.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.10.2.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"]),
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string()
        ])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .expect("source_artifacts should be an object");
    for (name, path) in source_artifacts {
        let rel = path
            .as_str()
            .expect("source artifact path should be a string");
        assert!(
            root.join(rel).is_file(),
            "source artifact {name} should exist at {rel}"
        );
    }

    let unit_refs = manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
        .as_array()
        .expect("unit refs should be an array");
    let e2e_refs = manifest["completion_debt_evidence"]["e2e_primary"]["required_test_refs"]
        .as_array()
        .expect("e2e refs should be an array");
    assert_eq!(unit_refs.len(), 4);
    assert_eq!(e2e_refs.len(), 5);

    let contract = &manifest["required_real_program_smoke_contract"];
    assert_eq!(contract["expected_case_count"].as_u64(), Some(20));
    assert_eq!(contract["expected_l0_case_count"].as_u64(), Some(8));
    assert_eq!(contract["expected_l1_case_count"].as_u64(), Some(12));
    assert!(string_set(&contract["required_domains"]).contains("standalone_future"));
    assert!(string_set(&contract["required_runtime_modes"]).contains("hardened"));
    assert!(string_set(&contract["required_replacement_levels"]).contains("L1"));
    assert_eq!(
        contract["source_commit_freshness_policy"]["stale_result"].as_str(),
        Some("block_real_program_smoke_evidence")
    );

    Ok(())
}

#[test]
fn checker_validates_real_program_smoke_contract_and_emits_report_log() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report =
        read_json(&out_dir.join("real_program_smoke_suite_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-bp8fl.10.2"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.10.2.1"));
    assert_eq!(report["case_count"].as_u64(), Some(20));
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(4));
    assert_eq!(report["e2e_bindings"].as_array().map(Vec::len), Some(5));
    assert!(string_set(&report["domains"]).contains("failure_unsupported"));

    let rows = read_jsonl(&out_dir.join("real_program_smoke_suite_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .map(|row| row["event"].as_str().unwrap().to_string())
        .collect();
    assert!(events.contains("real_program_smoke_completion.source_artifacts"));
    assert!(events.contains("real_program_smoke_completion.test_refs"));
    assert!(events.contains("real_program_smoke_completion.smoke_contract"));
    assert!(
        rows.iter()
            .all(|row| row["bead"].as_str() == Some("bd-bp8fl.10.2.1"))
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_ref() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-unit-ref")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"] = json!([]);
    let mutated = out_dir.join("real_program_smoke_missing_unit_ref.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("real_program_smoke_suite_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("unit_primary test refs mismatch"),
        "report should cite missing unit refs: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_case_count_drift() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "case-count-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_real_program_smoke_contract"]["expected_case_count"] = json!(19);
    let mutated = out_dir.join("real_program_smoke_case_count_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("real_program_smoke_suite_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("case_count drift")
            || report["errors"].to_string().contains("case count drift"),
        "report should cite case count drift: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "non-rch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"] =
        json!(["cargo test -p frankenlibc-harness --test real_program_smoke_suite_test"]);
    let mutated = out_dir.join("real_program_smoke_non_rch.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("real_program_smoke_suite_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("non-rch cargo"),
        "report should cite non-rch command: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_source_commit_policy_drift() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "freshness-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_real_program_smoke_contract"]["source_commit_freshness_policy"]["real_program_smoke_evidence_allowed_when_stale"] =
        json!(true);
    let mutated = out_dir.join("real_program_smoke_freshness_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("real_program_smoke_suite_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("source commit freshness policy drift"),
        "report should cite freshness policy drift: {report}"
    );
    Ok(())
}
