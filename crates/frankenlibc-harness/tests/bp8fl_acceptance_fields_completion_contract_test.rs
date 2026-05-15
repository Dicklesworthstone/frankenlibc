use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory has workspace parent")?
        .parent()
        .ok_or("workspace has root parent")?
        .to_path_buf();
    Ok(root)
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/bp8fl_acceptance_fields_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_bp8fl_acceptance_fields_completion_contract.sh")
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
        "target/conformance/bp8fl_acceptance_fields_completion_contract_test_{}_{}_{}",
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
    value
        .as_array()
        .ok_or("value should be an array")?
        .iter()
        .map(|item| {
            Ok(item
                .as_str()
                .ok_or("array item should be a string")?
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

fn relative_path(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn mutate_source_artifact_path(manifest: &mut Value, key: &str, path: &str) {
    manifest["source_artifacts"][key] = json!(path);
}

fn valid_acceptance_text() -> &'static str {
    "Preserve existing scope and do not narrow the work. Required unit tests \
must cover parser, stale artifact, and regression cases. Required deterministic \
e2e harness scripts must replay tracker rows. Structured logs must include \
trace_id, source_commit, artifact_refs, and failure_signature. Closure must \
list exact commands, claim gates, br dep cycles, bv --robot-triage, and a \
no-feature-loss statement."
}

fn write_historical_issues_fixture(path: &Path, missing_first_acceptance: bool) -> TestResult {
    let mut rows = Vec::new();
    for index in 0..89 {
        let mut row = json!({
            "id": format!("bd-bp8fl.fixture.{index:02}"),
            "title": "Fixture historical acceptance row",
            "description": "Fixture row for bd-bp8fl.2.5 historical acceptance completion tests.",
            "status": "closed",
            "priority": 0,
            "issue_type": "task",
            "created_at": "2026-05-03T12:00:00Z",
            "acceptance_criteria": valid_acceptance_text()
        });
        if index == 0 && missing_first_acceptance {
            row.as_object_mut()
                .ok_or("issue row should be object")?
                .remove("acceptance_criteria");
        }
        rows.push(row);
    }
    rows.push(json!({
        "id": "bd-bp8fl.fixture.post-scope",
        "title": "Post scope missing acceptance row",
        "description": "This row is intentionally outside the bd-bp8fl.2.5 historical closeout scope.",
        "status": "open",
        "priority": 1,
        "issue_type": "task",
        "created_at": "2026-05-04T12:00:00Z"
    }));
    let content = rows
        .iter()
        .map(|row| Ok(serde_json::to_string(row)? + "\n"))
        .collect::<TestResult<String>>()?;
    std::fs::write(path, content)?;
    Ok(())
}

fn write_contract_with_issues_fixture(
    root: &Path,
    out_dir: &Path,
    label: &str,
    missing_first_acceptance: bool,
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    let issues = out_dir.join(format!("{label}.issues.jsonl"));
    write_historical_issues_fixture(&issues, missing_first_acceptance)?;
    let rel_issues = relative_path(root, &issues)?;
    mutate_source_artifact_path(&mut manifest, "issues_jsonl", &rel_issues);
    let mutated = out_dir.join(format!("{label}.contract.json"));
    write_json(&mutated, &manifest)?;
    Ok(mutated)
}

#[test]
fn manifest_binds_bp8fl_acceptance_fields_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("bp8fl_acceptance_fields_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.2.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.2.5.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string()
        ])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts should be an object")?;
    assert_eq!(source_artifacts.len(), 13);
    for (name, path) in source_artifacts {
        let rel = path
            .as_str()
            .ok_or("source artifact path should be a string")?;
        assert!(
            root.join(rel).is_file(),
            "source artifact {name} should exist at {rel}"
        );
    }

    let historical = &manifest["historical_scope"];
    assert_eq!(historical["id_prefix"].as_str(), Some("bd-bp8fl"));
    assert_eq!(
        historical["created_before"].as_str(),
        Some("2026-05-04T00:00:00")
    );
    assert_eq!(historical["expected_rows"].as_u64(), Some(89));
    assert_eq!(historical["expected_missing_acceptance"].as_u64(), Some(0));

    assert_eq!(
        manifest["acceptance_field_contract"]["required_aggregate_terms"]
            .as_array()
            .map(Vec::len),
        Some(10)
    );
    assert_eq!(
        manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(9)
    );
    assert_eq!(
        manifest["completion_debt_evidence"]["e2e_primary"]["required_commands"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );

    Ok(())
}

#[test]
fn checker_validates_historical_acceptance_fields_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let contract = write_contract_with_issues_fixture(&root, &out_dir, "positive", false)?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let report =
        read_json(&out_dir.join("bp8fl_acceptance_fields_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-bp8fl.2.5"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.2.5.1")
    );
    assert_eq!(report["historical_row_count"].as_u64(), Some(89));
    assert_eq!(
        report["historical_missing_acceptance_ids"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert!(
        report["current_row_count"].as_u64().unwrap_or_default()
            >= report["historical_row_count"].as_u64().unwrap_or_default()
    );
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(9));
    assert_eq!(report["e2e_commands"].as_array().map(Vec::len), Some(8));
    assert_eq!(
        report["source_artifacts"].as_object().map(|m| m.len()),
        Some(13)
    );

    let events =
        read_jsonl(&out_dir.join("bp8fl_acceptance_fields_completion_contract.log.jsonl"))?;
    assert!(events.len() >= 4, "expected structured checker events");
    assert!(
        events
            .iter()
            .all(|event| event["bead_id"] == "bd-bp8fl.2.5.1")
    );
    assert!(
        events
            .iter()
            .all(|event| event["source_bead"] == "bd-bp8fl.2.5")
    );
    assert!(events.iter().all(|event| event["outcome"] == "pass"));

    Ok(())
}

#[test]
fn checker_rejects_missing_historical_acceptance_field() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_acceptance")?;
    let mutated = write_contract_with_issues_fixture(&root, &out_dir, "missing_acceptance", true)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("bp8fl_acceptance_fields_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .ok_or("errors should be present on failure")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("historical missing acceptance mismatch")),
        "expected historical missing acceptance error in {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_wrong_historical_row_count() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "wrong_row_count")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["historical_scope"]["expected_rows"] = json!(90);
    let mutated = out_dir.join("wrong_row_count.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("bp8fl_acceptance_fields_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .ok_or("errors should be present on failure")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("historical_scope.expected_rows mismatch")),
        "expected historical row count error in {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non_rch_command")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["e2e_primary"]["required_commands"][6] = json!(
        "cargo check -p frankenlibc-harness --test bp8fl_acceptance_fields_completion_contract_test"
    );
    let mutated = out_dir.join("non_rch_command.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("bp8fl_acceptance_fields_completion_contract.report.json"))?;
    let errors = report["errors"]
        .as_array()
        .ok_or("errors should be present on failure")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or_default()
            .contains("non-rch cargo validation command")),
        "expected non-rch command error in {errors:?}"
    );

    Ok(())
}
