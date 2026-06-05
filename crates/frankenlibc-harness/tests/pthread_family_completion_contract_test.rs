use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory must have workspace parent")?
        .parent()
        .ok_or("workspace must have root parent")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/pthread_family_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_pthread_family_completion_contract.sh")
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
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join(format!(
        "target/conformance/pthread_family_completion_contract_test_{}_{}_{}",
        std::process::id(),
        label,
        stamp
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
    let values = value.as_array().ok_or("value must be an array")?;
    values
        .iter()
        .map(|item| {
            Ok(item
                .as_str()
                .ok_or("array item must be a string")?
                .to_string())
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
fn manifest_binds_pthread_family_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("pthread_family_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-ldj.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-ldj.2.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.integration.primary".to_string(),
            "tests.e2e.primary".to_string(),
        ])
    );
    assert_eq!(
        manifest["target_symbols"].as_array().map(Vec::len),
        Some(42)
    );
    let target_symbols = string_set(&manifest["target_symbols"])?;
    assert!(target_symbols.contains("pthread_create"));
    assert!(target_symbols.contains("pthread_clockjoin_np"));

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be an object")?;
    assert_eq!(source_artifacts.len(), 32);
    for (name, path) in source_artifacts {
        let rel = path
            .as_str()
            .ok_or("source artifact path must be a string")?;
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
        Some(12)
    );
    assert_eq!(
        evidence["integration_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(22)
    );
    assert_eq!(
        evidence["e2e_primary"]["required_artifacts"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );

    let contract = &manifest["required_source_contract"];
    assert_eq!(
        string_set(&contract["support_matrix"]["expected_statuses"])?,
        BTreeSet::from(["Implemented".to_string(), "WrapsHostLibc".to_string()])
    );
    assert_eq!(
        contract["support_matrix"]["expected_module"].as_str(),
        Some("pthread_abi")
    );
    assert_eq!(
        contract["support_matrix"]["expected_symbols"].as_u64(),
        Some(42)
    );

    Ok(())
}

#[test]
fn checker_validates_pthread_family_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report = read_json(&out_dir.join("pthread_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-ldj.2"));
    assert_eq!(report["bead"].as_str(), Some("bd-ldj.2.1"));
    assert_eq!(report["target_symbols"].as_array().map(Vec::len), Some(42));
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(12));
    assert_eq!(
        report["integration_bindings"].as_array().map(Vec::len),
        Some(22)
    );
    assert_eq!(report["e2e_bindings"].as_array().map(Vec::len), Some(4));
    assert_eq!(report["abi_exports"].as_array().map(Vec::len), Some(42));

    let events = read_jsonl(&out_dir.join("pthread_family_completion_contract.log.jsonl"))?;
    assert!(events.len() >= 3, "expected structured checker events");
    assert!(events.iter().all(|event| event["bead_id"] == "bd-ldj.2.1"));
    assert!(events.iter().all(|event| event["api_family"] == "pthread"));
    assert!(events.iter().all(|event| event["outcome"] == "pass"));

    Ok(())
}

#[test]
fn checker_rejects_missing_target_symbol() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_symbol")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let symbols = manifest["target_symbols"]
        .as_array_mut()
        .ok_or("target_symbols must be a mutable array")?;
    symbols.retain(|symbol| symbol.as_str() != Some("pthread_clockjoin_np"));
    let mutated = out_dir.join("missing_symbol.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("pthread_family_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .ok_or("errors must be present on failure")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("target_symbols mismatch")),
        "expected target_symbols mismatch in {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non_rch_command")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["integration_primary"]["required_commands"][0] =
        json!("cargo test -p frankenlibc-abi --test pthread_abi_test");
    let mutated = out_dir.join("non_rch_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("pthread_family_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .ok_or("errors must be present on failure")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("non-rch cargo validation command")),
        "expected non-rch command rejection in {errors:?}"
    );

    Ok(())
}
