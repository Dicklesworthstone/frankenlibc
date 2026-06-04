use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "crate directory should have workspace parent",
            )
        })?;
    let root = workspace.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "workspace directory should have repo root parent",
        )
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/claim_reconciliation_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_claim_reconciliation_completion_contract.sh")
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
        "target/conformance/claim_reconciliation_completion_contract_test_{}_{}_{}",
        std::process::id(),
        label,
        stamp
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/"))
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
    Ok(value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "value should be an array"))?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "array item should be a string")
            })
        })
        .collect::<Result<_, _>>()?)
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker should fail for mutated contract\n{}",
        output_text(output)
    );
}

fn error_strings(report: &Value) -> TestResult<Vec<&str>> {
    let errors = report["errors"].as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "errors should be present on failure",
        )
    })?;
    errors
        .iter()
        .map(|error| {
            error.as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "error entry should be a string")
            })
        })
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

#[test]
fn manifest_binds_claim_reconciliation_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("claim_reconciliation_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-w2c3.10.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.10.1.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
        ])
    );

    let source_artifacts = manifest["source_artifacts"].as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "source_artifacts should be an object",
        )
    })?;
    assert_eq!(source_artifacts.len(), 15);
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

    let surface = &manifest["claim_reconciliation_surface"];
    assert_eq!(surface["input_artifacts"].as_array().map(Vec::len), Some(7));
    assert_eq!(surface["env_overrides"].as_array().map(Vec::len), Some(8));

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(
        evidence["unit_primary"]["required_engine_functions"]
            .as_array()
            .map(Vec::len),
        Some(19)
    );
    assert_eq!(
        evidence["unit_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );
    assert_eq!(
        evidence["e2e_primary"]["required_artifacts"]
            .as_array()
            .map(Vec::len),
        Some(7)
    );
    assert_eq!(
        evidence["e2e_primary"]["required_report_contract"]["status"].as_str(),
        Some("pass")
    );

    Ok(())
}

#[test]
fn checker_validates_claim_reconciliation_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report = read_json(&out_dir.join("claim_reconciliation_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-w2c3.10.1"));
    assert_eq!(report["bead"].as_str(), Some("bd-w2c3.10.1.1"));
    assert_eq!(
        report["engine_functions"].as_array().map(Vec::len),
        Some(19)
    );
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(5));
    assert_eq!(report["e2e_artifacts"].as_array().map(Vec::len), Some(7));
    assert_eq!(report["input_artifacts"].as_array().map(Vec::len), Some(7));
    assert_eq!(report["report_contract"]["status"].as_str(), Some("pass"));
    assert_eq!(
        report["report_contract"]["summary"]["total_findings"].as_u64(),
        Some(0)
    );

    let events = read_jsonl(&out_dir.join("claim_reconciliation_completion_contract.log.jsonl"))?;
    assert!(events.len() >= 3, "expected structured checker events");
    assert!(
        events
            .iter()
            .all(|event| event["bead_id"] == "bd-w2c3.10.1.1")
    );
    assert!(
        events
            .iter()
            .all(|event| event["api_family"] == "claim_reconciliation")
    );
    assert!(events.iter().all(|event| event["outcome"] == "pass"));

    Ok(())
}

#[test]
fn checker_rejects_stale_claim_reconciliation_report() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "stale_report")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let mut report =
        read_json(&root.join("tests/conformance/claim_reconciliation_report.v1.json"))?;
    report["status"] = json!("fail");
    report["summary"]["errors"] = json!(1);
    report["summary"]["total_findings"] = json!(1);

    let stale_report = out_dir.join("claim_reconciliation_report.stale.json");
    write_json(&stale_report, &report)?;
    manifest["source_artifacts"]["claim_reconciliation_report"] =
        json!(repo_relative(&root, &stale_report)?);
    let mutated = out_dir.join("stale_report_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("claim_reconciliation_completion_contract.report.json"))?;
    let errors = error_strings(&report)?;
    assert!(
        errors
            .iter()
            .any(|error| error.contains("report status mismatch")),
        "expected report status mismatch in {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non_rch_command")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        json!("cargo test -p frankenlibc-harness --test claim_reconciliation_test");
    let mutated = out_dir.join("non_rch_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("claim_reconciliation_completion_contract.report.json"))?;
    let errors = error_strings(&report)?;
    assert!(
        errors
            .iter()
            .any(|error| error.contains("non-rch cargo validation command")),
        "expected non-rch command rejection in {errors:?}"
    );

    Ok(())
}
