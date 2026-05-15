use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = crate_dir
        .parent()
        .ok_or("workspace parent should have repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_math_admission_ci_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_admission_ci_completion_contract.sh")
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
        "runtime_math_admission_ci_completion_contract_{label}_{}_{}",
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
        .env(
            "FRANKENLIBC_RUNTIME_MATH_ADMISSION_CI_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_ADMISSION_CI_COMPLETION_REPORT",
            out_dir.join("runtime_math_admission_ci_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_ADMISSION_CI_COMPLETION_LOG",
            out_dir.join("runtime_math_admission_ci_completion_contract.log.jsonl"),
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
fn manifest_binds_unit_and_e2e_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_math_admission_ci_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3ot.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-3ot.3.1")
    );

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
    for required in ["tests.unit.primary", "tests.e2e.primary"] {
        assert!(
            item_ids.contains(&required),
            "missing item binding {required}"
        );
    }

    let policies = manifest["required_source_contract"]["admission_report"]["policies_enforced"]
        .as_array()
        .ok_or("policies_enforced must be array")?;
    assert_eq!(policies.len(), 19);
    assert_eq!(
        manifest["required_source_contract"]["admission_report"]["admitted"].as_u64(),
        Some(25)
    );
    assert_eq!(
        manifest["required_source_contract"]["admission_report"]["retired"].as_u64(),
        Some(44)
    );

    Ok(())
}

#[test]
fn checker_validates_runtime_math_admission_ci_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("runtime_math_admission_ci_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-3ot.3"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3ot.3.1"));
    assert_eq!(
        report["admission_summary"]["total_modules"].as_u64(),
        Some(69)
    );
    assert_eq!(report["admission_summary"]["admitted"].as_u64(), Some(25));
    assert_eq!(report["admission_summary"]["retired"].as_u64(), Some(44));
    assert_eq!(report["admission_summary"]["blocked"].as_u64(), Some(0));
    assert_eq!(
        report["admission_summary"]["policy_count"].as_u64(),
        Some(19)
    );
    assert_eq!(report["binding_summary"]["binding_count"].as_u64(), Some(2));

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("runtime_math_admission_ci_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_math_admission_ci_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(3));

    let records =
        log_records(&out_dir.join("runtime_math_admission_ci_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert!(events.contains(&"runtime_math_admission_ci_completion_summary"));
    assert!(events.contains(&"runtime_math_admission_ci_bindings"));
    assert!(events.contains(&"runtime_math_admission_ci_completion_contract_pass"));

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
fn checker_rejects_missing_policy() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_policy")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["admission_report"]["policies_enforced"]
        .as_array_mut()
        .ok_or("policies_enforced must be array")?
        .push(json!("admission: definitely_missing_policy"));
    let mutated = out_dir.join("contract_missing_policy.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing policy:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("runtime_math_admission_ci_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("definitely_missing_policy")),
        "expected missing policy failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_bad_admission_count() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bad_count")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["admission_report"]["admitted"] = json!(26);
    let mutated = out_dir.join("contract_bad_count.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject admission count drift:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("runtime_math_admission_ci_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("admission summary admitted drifted")),
        "expected admitted-count drift failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_ci_marker() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_ci_marker")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["ci_markers"]
        .as_array_mut()
        .ok_or("ci_markers must be array")?
        .push(json!(
            "scripts/check_definitely_missing_runtime_math_gate.sh"
        ));
    let mutated = out_dir.join("contract_missing_ci_marker.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing CI marker:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("runtime_math_admission_ci_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("check_definitely_missing_runtime_math_gate")),
        "expected missing CI marker failure, got {report}"
    );

    Ok(())
}
