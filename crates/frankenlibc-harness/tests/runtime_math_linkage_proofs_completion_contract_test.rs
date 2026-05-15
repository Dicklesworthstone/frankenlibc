use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| invalid_data("crate directory has workspace parent"))?
        .parent()
        .ok_or_else(|| invalid_data("workspace has root parent"))?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_math_linkage_proofs_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_linkage_proofs_completion_contract.sh")
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
        "target/conformance/runtime_math_linkage_proofs_completion_contract_test_{}_{}",
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

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn json_array<'a>(value: &'a Value, name: &str) -> TestResult<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_data(format!("{name} must be array")).into())
}

fn json_object<'a>(value: &'a Value, name: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_data(format!("{name} must be object")).into())
}

fn json_str<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| invalid_data(format!("{name} must be string")).into())
}

fn string_set(value: &Value, name: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, name)?
        .iter()
        .map(|item| Ok(json_str(item, &format!("{name} item"))?.to_string()))
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
fn manifest_binds_linkage_proof_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_math_linkage_proofs_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-7dw2"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-7dw2.1"));
    assert_eq!(
        string_set(
            &manifest["completion_debt"]["missing_items_closed"],
            "completion_debt.missing_items_closed"
        )?,
        BTreeSet::from(["tests.integration.primary".to_string()])
    );

    let source_artifacts = json_object(&manifest["source_artifacts"], "source_artifacts")?;
    for (name, path) in source_artifacts {
        let rel = json_str(path, "source artifact path")?;
        assert!(
            root.join(rel).is_file(),
            "source artifact {name} should exist at {rel}"
        );
    }

    let integration = &manifest["completion_debt_evidence"]["integration_primary"];
    let test_names: BTreeSet<_> = json_array(
        &integration["required_test_refs"],
        "integration_primary.required_test_refs",
    )?
    .iter()
    .map(|entry| Ok(json_str(&entry["name"], "integration test ref name")?.to_string()))
    .collect::<TestResult<_>>()?;
    assert_eq!(
        test_names,
        BTreeSet::from([
            "gate_script_exists_and_executable".to_string(),
            "gate_script_emits_logs_and_report".to_string()
        ])
    );
    for command in json_array(
        &integration["required_commands"],
        "integration_primary.required_commands",
    )? {
        let command = json_str(command, "required command")?;
        if command.contains("cargo ") {
            assert!(
                command.starts_with("rch exec --"),
                "cargo validation command must be rch wrapped: {command}"
            );
        }
    }

    let contract = &manifest["required_runtime_math_linkage_proof_contract"];
    assert_eq!(
        contract["gate_id"].as_str(),
        Some("runtime_math_linkage_proofs")
    );
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(
        contract["expected_production_module_count"].as_u64(),
        Some(25)
    );
    assert_eq!(
        contract["expected_research_module_count"].as_u64(),
        Some(44)
    );
    assert_eq!(contract["expected_linkage_module_count"].as_u64(), Some(69));
    assert!(
        string_set(&contract["required_log_events"], "required_log_events")?
            .contains("runtime_math.linkage_proof.boundary_assumption")
    );

    Ok(())
}

#[test]
fn checker_validates_linkage_proof_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report =
        read_json(&out_dir.join("runtime_math_linkage_proofs_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-7dw2"));
    assert_eq!(report["bead"].as_str(), Some("bd-7dw2.1"));
    assert_eq!(report["production_module_count"].as_u64(), Some(25));
    assert_eq!(report["research_module_count"].as_u64(), Some(44));
    assert_eq!(report["linkage_module_count"].as_u64(), Some(69));
    assert_eq!(
        report["integration_bindings"].as_array().map(Vec::len),
        Some(2)
    );

    let rows =
        read_jsonl(&out_dir.join("runtime_math_linkage_proofs_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .map(|row| Ok(json_str(&row["event"], "log event")?.to_string()))
        .collect::<TestResult<_>>()?;
    assert!(events.contains("runtime_math_linkage_completion.source_artifacts"));
    assert!(events.contains("runtime_math_linkage_completion.integration_evidence"));
    assert!(events.contains("runtime_math_linkage_completion.proof_contract"));
    assert!(
        rows.iter()
            .all(|row| row["bead"].as_str() == Some("bd-7dw2.1"))
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_integration_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-ref")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["integration_primary"]["required_test_refs"] = json!([{
        "artifact": "linkage_proofs_test",
        "name": "gate_script_exists_and_executable",
        "covers": ["gate script presence"]
    }]);
    let mutated = out_dir.join("runtime_math_linkage_missing_ref.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_math_linkage_proofs_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("integration test refs mismatch"),
        "report should cite missing integration ref: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_production_module_count_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "count-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_runtime_math_linkage_proof_contract"]["expected_production_module_count"] =
        json!(24);
    let mutated = out_dir.join("runtime_math_linkage_count_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_math_linkage_proofs_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("production module count drift"),
        "report should cite production count drift: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non-rch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["integration_primary"]["required_commands"] =
        json!(["cargo test -p frankenlibc-harness --test runtime_math_linkage_proofs_test"]);
    let mutated = out_dir.join("runtime_math_linkage_non_rch.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_math_linkage_proofs_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("non-rch cargo"),
        "report should cite non-rch command: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_source_marker() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "marker-drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_runtime_math_linkage_proof_contract"]["required_source_markers"]["linkage_proofs_impl"] =
        json!(["not_a_real_linkage_source_marker"]);
    let mutated = out_dir.join("runtime_math_linkage_marker_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("runtime_math_linkage_proofs_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("missing source marker"),
        "report should cite missing source marker: {report}"
    );
    Ok(())
}
