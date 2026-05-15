use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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
    root.join("tests/conformance/stdio_family_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_stdio_family_completion_contract.sh")
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
        "target/conformance/stdio_family_completion_contract_test_{}_{}_{}",
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
fn manifest_binds_stdio_family_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("stdio_family_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-ldj.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-ldj.1.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.conformance.primary".to_string(),
        ])
    );
    assert_eq!(
        string_set(&manifest["target_symbols"])?,
        BTreeSet::from([
            "fopen".to_string(),
            "fclose".to_string(),
            "fread".to_string(),
            "fwrite".to_string(),
            "fprintf".to_string(),
            "fscanf".to_string(),
            "fseek".to_string(),
            "fflush".to_string(),
        ])
    );

    let source_artifacts = manifest["source_artifacts"].as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "source_artifacts should be an object",
        )
    })?;
    assert_eq!(source_artifacts.len(), 20);
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
        Some(11)
    );
    assert_eq!(
        evidence["e2e_primary"]["required_artifacts"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        evidence["conformance_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(11)
    );
    assert_eq!(
        evidence["conformance_primary"]["required_artifacts"]
            .as_array()
            .map(Vec::len),
        Some(6)
    );

    let contract = &manifest["required_source_contract"];
    assert_eq!(
        contract["support_matrix"]["expected_status"].as_str(),
        Some("Implemented")
    );
    assert_eq!(
        contract["support_matrix"]["expected_module"].as_str(),
        Some("stdio_abi")
    );
    assert_eq!(
        contract["stdio_fixture"]["expected_min_cases"].as_u64(),
        Some(12)
    );
    assert_eq!(
        contract["scanf_fixture"]["expected_min_cases"].as_u64(),
        Some(50)
    );

    Ok(())
}

#[test]
fn checker_validates_stdio_family_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report = read_json(&out_dir.join("stdio_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-ldj.1"));
    assert_eq!(report["bead"].as_str(), Some("bd-ldj.1.1"));
    assert_eq!(report["target_symbols"].as_array().map(Vec::len), Some(8));
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(11));
    assert_eq!(report["e2e_bindings"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        report["conformance_test_bindings"].as_array().map(Vec::len),
        Some(11)
    );
    assert_eq!(
        report["conformance_bindings"].as_array().map(Vec::len),
        Some(6)
    );
    assert!(
        report["source_summary"]["stdio_fixture"]["case_count"]
            .as_u64()
            .unwrap_or(0)
            >= 12
    );
    assert!(
        report["source_summary"]["scanf_fixture"]["case_count"]
            .as_u64()
            .unwrap_or(0)
            >= 50
    );

    let rows = read_jsonl(&out_dir.join("stdio_family_completion_contract.log.jsonl"))?;
    let mut events = BTreeSet::new();
    for row in &rows {
        events.insert(
            row["event"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "event string"))?
                .to_string(),
        );
    }
    assert!(events.contains("stdio_family_completion.source_artifacts"));
    assert!(events.contains("stdio_family_completion.evidence_refs"));
    assert!(events.contains("stdio_family_completion.source_contract"));
    for row in rows {
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
            assert!(row.get(field).is_some(), "log row missing {field}: {row}");
        }
        assert_eq!(row["bead"].as_str(), Some("bd-ldj.1.1"));
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-unit-ref")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"] = json!([]);
    let mutated = out_dir.join("stdio_family_missing_unit_ref.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("stdio_family_completion_contract.report.json"))?;
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
fn checker_rejects_missing_e2e_artifact_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-e2e")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["e2e_primary"]["required_artifacts"] = json!([]);
    let mutated = out_dir.join("stdio_family_missing_e2e_artifact.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("stdio_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("e2e_primary artifact refs mismatch"),
        "report should cite missing e2e artifacts: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_symbol_status_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "symbol-status")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_source_contract"]["support_matrix"]["expected_status"] = json!("Stub");
    let mutated = out_dir.join("stdio_family_status_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("stdio_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("support_matrix fopen status drift"),
        "report should cite support-matrix status drift: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non-rch")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"] =
        json!(["cargo test -p frankenlibc-core stdio::"]);
    let mutated = out_dir.join("stdio_family_non_rch.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("stdio_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("non-rch cargo"),
        "report should cite non-rch cargo command: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_fixture_function_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "fixture-function")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_source_contract"]["stdio_fixture"]["required_functions"] =
        json!(["definitely_missing_stdio_function"]);
    let mutated = out_dir.join("stdio_family_fixture_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("stdio_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("stdio_fixture missing required function"),
        "report should cite fixture function drift: {report}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_log_field_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "log-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["required_source_contract"]["required_log_fields"] =
        json!(["definitely_missing_log_field"]);
    let mutated = out_dir.join("stdio_family_log_field_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("stdio_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("e2e checker missing required log field"),
        "report should cite missing log field: {report}"
    );
    Ok(())
}
