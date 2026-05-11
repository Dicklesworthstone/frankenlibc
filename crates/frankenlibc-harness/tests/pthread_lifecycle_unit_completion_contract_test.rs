use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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
    root.join("tests/conformance/pthread_lifecycle_unit_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_pthread_lifecycle_unit_completion_contract.sh")
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
        "target/conformance/pthread_lifecycle_unit_completion_contract_test_{}_{}_{}",
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
fn manifest_binds_pthread_lifecycle_unit_completion_items() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("pthread_lifecycle_unit_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-xxd9"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-xxd9.2"));
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"]),
        BTreeSet::from(["tests.unit.primary".to_string()])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .expect("source_artifacts should be an object");
    assert_eq!(source_artifacts.len(), 16);
    for (name, path) in source_artifacts {
        let rel = path
            .as_str()
            .expect("source artifact path should be a string");
        assert!(
            root.join(rel).is_file(),
            "source artifact {name} should exist at {rel}"
        );
    }

    let surface = &manifest["pthread_lifecycle_surface"];
    assert_eq!(
        surface["required_families"].as_array().map(Vec::len),
        Some(9)
    );
    assert_eq!(
        surface["stress_support"]["required_scenarios"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    assert_eq!(
        surface["stress_support"]["required_modes"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    let evidence = &manifest["completion_debt_evidence"]["unit_primary"];
    assert_eq!(
        evidence["required_test_refs"].as_array().map(Vec::len),
        Some(36)
    );
    assert_eq!(
        evidence["required_commands"].as_array().map(Vec::len),
        Some(11)
    );

    Ok(())
}

#[test]
fn checker_validates_pthread_lifecycle_unit_contract_and_emits_report_log() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report =
        read_json(&out_dir.join("pthread_lifecycle_unit_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-xxd9"));
    assert_eq!(report["bead"].as_str(), Some("bd-xxd9.2"));
    assert_eq!(
        report["source_artifacts"].as_object().map(|m| m.len()),
        Some(16)
    );
    assert_eq!(report["families"].as_array().map(Vec::len), Some(9));
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(36));
    assert_eq!(
        report["stress_support"]["scenarios"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    assert_eq!(
        string_set(&report["stress_support"]["modes"]),
        BTreeSet::from(["hardened".to_string(), "strict".to_string()])
    );

    let events = read_jsonl(&out_dir.join("pthread_lifecycle_unit_completion_contract.log.jsonl"))?;
    assert!(events.len() >= 4, "expected structured checker events");
    assert!(events.iter().all(|event| event["bead_id"] == "bd-xxd9.2"));
    assert!(events.iter().all(|event| event["api_family"] == "pthread"));
    assert!(events.iter().all(|event| event["outcome"] == "pass"));

    Ok(())
}

#[test]
fn checker_rejects_missing_required_family() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_family")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["pthread_lifecycle_surface"]["required_families"] = json!([
        "mutex",
        "condvar",
        "rwlock",
        "rwlock_trylock",
        "once",
        "tsd",
        "thread_lifecycle",
        "mutex_contract_matrix"
    ]);
    let mutated = out_dir.join("missing_family.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("pthread_lifecycle_unit_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .expect("errors should be present on failure");
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("required families mismatch")),
        "expected required-family mismatch in {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_ref() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_ref")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
        .as_array_mut()
        .expect("required_test_refs should be an array");
    refs.retain(|reference| {
        reference["name"].as_str() != Some("pthread_self_join_is_rejected_with_edeadlk")
    });
    let mutated = out_dir.join("missing_ref.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("pthread_lifecycle_unit_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .expect("errors should be present on failure");
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("unit_primary test refs mismatch")),
        "expected unit ref mismatch in {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "non_rch_command")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] =
        json!("cargo test -p frankenlibc-abi --test pthread_mutex_core_test");
    let mutated = out_dir.join("non_rch_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("pthread_lifecycle_unit_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .expect("errors should be present on failure");
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("non-rch cargo validation command")),
        "expected non-rch command error in {errors:?}"
    );

    Ok(())
}
