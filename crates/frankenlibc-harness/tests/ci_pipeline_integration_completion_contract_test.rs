use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir
        .parent()
        .ok_or("crate directory has workspace parent")?;
    let root = workspace
        .parent()
        .ok_or("workspace parent has repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/ci_pipeline_integration_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_ci_pipeline_integration_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "ci_pipeline_integration_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_CI_PIPELINE_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_CI_PIPELINE_COMPLETION_REPORT",
            out_dir.join("ci_pipeline_integration_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_CI_PIPELINE_COMPLETION_LOG",
            out_dir.join("ci_pipeline_integration_completion_contract.log.jsonl"),
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

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_all_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("ci_pipeline_integration_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3f6f"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-3f6f.1"));

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in artifacts {
        let path = path.as_str().ok_or("artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let item_ids: Vec<&str> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for required in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.fuzz.primary",
        "tests.golden.primary",
        "tests.conformance.primary",
    ] {
        assert!(
            item_ids.contains(&required),
            "missing completion binding {required}"
        );
    }

    let workflow_jobs = manifest["required_source_contract"]["workflow_jobs"]
        .as_array()
        .ok_or("workflow_jobs must be array")?;
    assert_eq!(workflow_jobs.len(), 6);

    let fuzz_targets = manifest["required_source_contract"]["fuzz_targets"]
        .as_array()
        .ok_or("fuzz_targets must be array")?;
    assert_eq!(fuzz_targets.len(), 8);

    Ok(())
}

#[test]
fn checker_validates_ci_pipeline_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("ci_pipeline_integration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-3f6f"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3f6f.1"));
    assert_eq!(
        report["workflow_summary"]["workflow_jobs"].as_u64(),
        Some(6)
    );
    assert_eq!(report["workflow_summary"]["fuzz_targets"].as_u64(), Some(8));
    assert_eq!(report["binding_summary"]["binding_count"].as_u64(), Some(5));
    assert_eq!(
        report["source_summary"]["conformance_total_cases"].as_u64(),
        Some(3369)
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("ci_pipeline_integration_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("ci_pipeline_integration_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(3));

    let records =
        log_records(&out_dir.join("ci_pipeline_integration_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert!(events.contains(&"ci_pipeline_completion_summary"));
    assert!(events.contains(&"ci_pipeline_lane_bindings"));
    assert!(events.contains(&"ci_pipeline_completion_contract_pass"));

    for record in records {
        for field in [
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "artifact_refs",
        ] {
            assert!(
                !record[field].is_null(),
                "log record missing {field}: {record}"
            );
        }
        assert_eq!(record["status"].as_str(), Some("pass"));
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_required_workflow_job() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_job")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["workflow_jobs"]
        .as_array_mut()
        .ok_or("workflow_jobs must be array")?
        .push(json!("definitely-missing-ci-job"));
    let mutated = out_dir.join("contract_missing_job.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing workflow job:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("ci_pipeline_integration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("definitely-missing-ci-job")),
        "expected missing workflow job failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_artifact_upload() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_upload")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["artifact_upload_names"]
        .as_array_mut()
        .ok_or("artifact_upload_names must be array")?
        .push(json!("definitely-missing-artifact-upload"));
    let mutated = out_dir.join("contract_missing_upload.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing artifact upload:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("ci_pipeline_integration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("definitely-missing-artifact-upload")),
        "expected missing artifact upload failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_source_marker() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_marker")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["ci_script_markers"]
        .as_array_mut()
        .ok_or("ci_script_markers must be array")?
        .push(json!("definitely_missing_ci_script_marker"));
    let mutated = out_dir.join("contract_missing_marker.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing CI source marker:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("ci_pipeline_integration_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("definitely_missing_ci_script_marker")),
        "expected missing marker failure, got {report}"
    );

    Ok(())
}
