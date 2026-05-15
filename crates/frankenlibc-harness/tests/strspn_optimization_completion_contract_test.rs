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
    root.join("tests/conformance/strspn_optimization_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_strspn_optimization_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "strspn_optimization_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_STRSPN_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_STRSPN_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STRSPN_COMPLETION_REPORT",
            out_dir.join("strspn_optimization_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_STRSPN_COMPLETION_LOG",
            out_dir.join("strspn_optimization_completion_contract.log.jsonl"),
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

#[test]
fn manifest_binds_strspn_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("strspn_optimization_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-0e4vu"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-0e4vu.1")
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings should be an array")?
        .iter()
        .map(|entry| {
            Ok(entry["id"]
                .as_str()
                .ok_or("missing_item_bindings entry id should be a string")?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or("source_artifacts should be an array")?;
    assert_eq!(source_artifacts.len(), 7);
    for artifact in source_artifacts {
        let path = artifact["path"]
            .as_str()
            .ok_or("source artifact path should be a string")?;
        assert!(root.join(path).is_file(), "missing artifact {path}");
    }

    Ok(())
}

#[test]
fn checker_validates_strspn_completion_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("strspn_optimization_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-0e4vu"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-0e4vu.1"));
    let events: BTreeSet<_> = report["events"]
        .as_array()
        .ok_or("events should be an array")?
        .iter()
        .map(|event| {
            Ok(event
                .as_str()
                .ok_or("event should be a string")?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    for event in [
        "strspn_optimization.conformance_primary",
        "strspn_optimization.source_artifact",
        "strspn_optimization.telemetry_primary",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }

    let rows = read_jsonl(&out_dir.join("strspn_optimization_completion_contract.log.jsonl"))?;
    assert!(
        rows.iter()
            .any(|row| row["event"].as_str() == Some("strspn_optimization.completion_contract")),
        "checker should emit completion telemetry"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_core_source_needle() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_source")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array_mut()
        .ok_or("source_artifacts should be mutable")?;
    let core = artifacts
        .iter_mut()
        .find(|entry| entry["artifact_id"].as_str() == Some("core_string_strspn"))
        .ok_or("core_string_strspn artifact should exist")?;
    core["required_needles"] = json!(["needle_that_does_not_exist"]);

    let mutated = out_dir.join("missing_source.contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing source needle\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing needle"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_symbol() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_telemetry")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["telemetry_primary"]["required_json_symbols"][0]["symbol"] =
        json!("symbol_that_does_not_exist");

    let mutated = out_dir.join("missing_telemetry.contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing telemetry symbol\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("symbol_that_does_not_exist"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
