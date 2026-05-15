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
    root.join("tests/conformance/pthread_bootstrap_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_pthread_bootstrap_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join(format!(
        "target/conformance/pthread_bootstrap_completion_contract_test_{}_{}_{}",
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
fn manifest_binds_pthread_bootstrap_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("pthread_bootstrap_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-yos"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-yos.1"));
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "telemetry.primary".to_string()
        ])
    );

    let source_artifacts = manifest["source_artifacts"].as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "source_artifacts should be an object",
        )
    })?;
    assert_eq!(source_artifacts.len(), 10);
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

    assert_eq!(
        string_set(&manifest["pthread_bootstrap_surface"]["required_symbols"])?,
        BTreeSet::from([
            "pthread_create".to_string(),
            "pthread_join".to_string(),
            "pthread_detach".to_string()
        ])
    );
    assert_eq!(
        manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );
    assert_eq!(
        manifest["completion_debt_evidence"]["e2e_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(6)
    );
    assert_eq!(
        manifest["completion_debt_evidence"]["telemetry_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );

    Ok(())
}

#[test]
fn checker_validates_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report = read_json(&out_dir.join("pthread_bootstrap_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-yos"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-yos.1"));
    assert_eq!(
        report["source_artifacts"].as_object().map(|m| m.len()),
        Some(10)
    );
    assert_eq!(report["unit_refs"].as_array().map(Vec::len), Some(5));
    assert_eq!(report["e2e_refs"].as_array().map(Vec::len), Some(6));
    assert_eq!(report["telemetry_refs"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        string_set(&report["required_symbols"])?,
        BTreeSet::from([
            "pthread_create".to_string(),
            "pthread_join".to_string(),
            "pthread_detach".to_string()
        ])
    );
    assert_eq!(report["stress_scenarios"].as_array().map(Vec::len), Some(4));

    let events = read_jsonl(&out_dir.join("pthread_bootstrap_completion_contract.log.jsonl"))?;
    assert!(events.len() >= 5, "expected structured checker events");
    assert!(events.iter().all(|event| event["bead_id"] == "bd-yos"));
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "pthread_bootstrap.completion_contract_validated")
    );
    assert!(events.iter().all(|event| event["status"] == "pass"));

    Ok(())
}

#[test]
fn checker_rejects_missing_required_symbol() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_symbol")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["pthread_bootstrap_surface"]["required_symbols"] =
        json!(["pthread_create", "pthread_join"]);
    let mutated = out_dir.join("missing_symbol.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("pthread_bootstrap_completion_contract.report.json"))?;
    let errors = error_strings(&report)?;
    assert!(
        errors
            .iter()
            .any(|error| error.contains("required_symbols")),
        "expected required-symbols error in {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_unit")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
        .as_array_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "unit refs should be mutable array",
            )
        })?;
    refs.retain(|item| {
        item["name"].as_str() != Some("pthread_join_and_detach_unknown_thread_are_esrch")
    });
    let mutated = out_dir.join("missing_unit.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("pthread_bootstrap_completion_contract.report.json"))?;
    let errors = error_strings(&report)?;
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unit_primary missing")),
        "expected missing unit ref error in {errors:?}"
    );

    Ok(())
}
