use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory must have workspace parent")?
        .parent()
        .ok_or("workspace parent must have repo parent")?
        .to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/user_workload_acceptance_matrix_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_user_workload_acceptance_matrix_completion_contract.sh")
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "user_workload_acceptance_matrix_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_USER_WORKLOAD_ACCEPTANCE_MATRIX_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_USER_WORKLOAD_ACCEPTANCE_MATRIX_COMPLETION_REPORT",
            out_dir.join("user_workload_acceptance_matrix_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_USER_WORKLOAD_ACCEPTANCE_MATRIX_COMPLETION_LOG",
            out_dir.join("user_workload_acceptance_matrix_completion_contract.log.jsonl"),
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

fn source_texts(root: &Path, manifest: &Value) -> TestResult<Vec<String>> {
    let mut texts = Vec::new();
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or("test_sources must be object")?;
    for source in sources.values() {
        let path = source["path"].as_str().ok_or("test source needs path")?;
        texts.push(std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

#[test]
fn manifest_binds_unit_e2e_conformance_and_telemetry_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("user_workload_acceptance_matrix_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.10.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.10.1.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in source_artifacts {
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
        "tests.conformance.primary",
        "telemetry.primary",
    ] {
        assert!(
            item_ids.contains(&required),
            "missing item binding {required}"
        );
    }

    let summary = &manifest["required_source_contract"]["summary_exact"];
    assert_eq!(summary["persona_count"].as_u64(), Some(5));
    assert_eq!(summary["failure_taxonomy_count"].as_u64(), Some(11));
    assert_eq!(summary["workload_count"].as_u64(), Some(11));
    assert_eq!(summary["negative_claim_test_count"].as_u64(), Some(11));
    assert_eq!(summary["rows_with_strict_and_hardened"].as_u64(), Some(11));
    assert_eq!(summary["rows_with_l0_l1_l2_l3"].as_u64(), Some(11));

    let texts = source_texts(&root, &manifest)?;
    for source in manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or("test_sources must be object")?
        .values()
    {
        for test_ref in source["required_test_refs"]
            .as_array()
            .ok_or("required_test_refs must be array")?
        {
            let name = test_ref.as_str().ok_or("test ref must be string")?;
            assert!(
                texts.iter().any(|text| text.contains(name)),
                "required test ref {name} missing from source text"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_validates_source_gate_and_emits_completion_report() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "report")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("user_workload_acceptance_matrix_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("user_workload_acceptance_matrix_completion_contract.report.v1")
    );
    assert_eq!(report["source_bead"].as_str(), Some("bd-bp8fl.10.1"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.10.1.1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_report_status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["persona_count"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["failure_taxonomy_count"].as_u64(),
        Some(11)
    );
    assert_eq!(report["summary"]["workload_count"].as_u64(), Some(11));
    assert_eq!(
        report["summary"]["negative_claim_test_count"].as_u64(),
        Some(11)
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(3));

    for check in [
        "json_parse",
        "top_level_shape",
        "required_log_fields",
        "personas",
        "failure_taxonomy",
        "workload_rows",
        "domain_coverage",
        "taxonomy_coverage",
        "summary_counts",
        "negative_claim_policy",
    ] {
        assert_eq!(
            report["source_checks"][check].as_str(),
            Some("pass"),
            "source check {check} should pass"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_valid_structured_log_rows() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "log")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let records = log_records(
        &out_dir.join("user_workload_acceptance_matrix_completion_contract.log.jsonl"),
    )?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    for event in [
        "user_workload_acceptance_completion_summary",
        "user_workload_acceptance_source_gate_bound",
        "user_workload_acceptance_completion_contract_pass",
    ] {
        assert!(events.contains(&event), "missing event {event}");
    }

    for record in records {
        for field in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "bead_id",
            "stream",
            "gate",
            "scenario_id",
            "runtime_mode",
            "replacement_level",
            "api_family",
            "symbol",
            "oracle_kind",
            "expected",
            "actual",
            "outcome",
            "latency_ns",
            "artifact_refs",
            "source_commit",
            "target_dir",
            "failure_signature",
        ] {
            assert!(
                !record[field].is_null(),
                "log record missing {field}: {record}"
            );
        }
        let serialized = serde_json::to_string(&record)?;
        validate_log_line(&serialized, 1).map_err(|errors| {
            format!(
                "completion log should satisfy structured_log contract: {errors:?}; row={serialized}"
            )
        })?;
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_required_log_field() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_log_field")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["required_log_fields"]
        .as_array_mut()
        .ok_or("required_log_fields must be array")?
        .push(json!("definitely_missing_structured_log_field"));
    let mutated = out_dir.join("contract_missing_log_field.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing required log field:\n{}",
        output_text(&output)
    );
    let report = load_json(
        &out_dir.join("user_workload_acceptance_matrix_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("definitely_missing_structured_log_field")),
        "expected missing log field error in report: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_telemetry")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let bindings = manifest["missing_item_bindings"]
        .as_array_mut()
        .ok_or("missing_item_bindings must be array")?;
    bindings.retain(|binding| binding["id"].as_str() != Some("telemetry.primary"));
    let mutated = out_dir.join("contract_missing_telemetry.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry binding:\n{}",
        output_text(&output)
    );
    let report = load_json(
        &out_dir.join("user_workload_acceptance_matrix_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("telemetry.primary")),
        "expected missing telemetry binding error in report: {report}"
    );

    Ok(())
}
