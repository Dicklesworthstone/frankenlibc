use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
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
    root.join("tests/conformance/perf_regression_prevention_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_perf_regression_prevention_completion_contract.sh")
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "perf_regression_prevention_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_PERF_REGRESSION_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_PERF_REGRESSION_COMPLETION_REPORT",
            out_dir.join("perf_regression_prevention_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_PERF_REGRESSION_COMPLETION_LOG",
            out_dir.join("perf_regression_prevention_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_PERF_REGRESSION_COMPLETION_SOURCE_REPORT",
            out_dir.join("perf_regression_prevention_completion_contract.source_report.json"),
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
fn manifest_binds_unit_e2e_and_telemetry_evidence() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("perf_regression_prevention_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1qfc"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-1qfc.1"));

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
        "telemetry.primary",
    ] {
        assert!(
            item_ids.contains(&required),
            "missing item binding {required}"
        );
    }

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
fn checker_validates_generated_perf_report() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("perf_regression_prevention_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-1qfc"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-1qfc.1"));
    assert_eq!(report["summary"]["total_suites_in_spec"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["suites_with_bench_files"].as_u64(),
        Some(5)
    );
    assert_eq!(
        report["summary"]["baseline_slot_fill_pct"].as_f64(),
        Some(100.0)
    );
    assert_eq!(report["summary"]["total_issues"].as_u64(), Some(0));
    assert_eq!(report["summary"]["total_warnings"].as_u64(), Some(0));
    assert!(report["gate_wiring"]["features"]["event_logging"].as_bool() == Some(true));

    let generated = load_json(
        &out_dir.join("perf_regression_prevention_completion_contract.source_report.json"),
    )?;
    assert_eq!(generated["schema_version"].as_str(), Some("v1"));
    assert_eq!(generated["bead"].as_str(), Some("bd-1qfc"));
    assert_eq!(
        generated["summary"]["suites_with_full_baselines"].as_u64(),
        Some(5)
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("perf_regression_prevention_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("perf_regression_prevention_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(3));
    assert_eq!(report["dashboard_row_count"].as_u64(), Some(10));

    let records =
        log_records(&out_dir.join("perf_regression_prevention_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert!(events.contains(&"perf_regression_prevention_completion_summary"));
    assert!(events.contains(&"perf_regression_prevention_gate_wiring_preserved"));
    assert!(events.contains(&"perf_regression_prevention_completion_contract_pass"));

    for record in records {
        for field in [
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "source_report",
            "outcome",
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
fn checker_rejects_missing_gate_feature_binding() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_feature")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_report"]["required_gate_features"]
        .as_array_mut()
        .ok_or("required_gate_features must be array")?
        .push(json!("definitely_missing_gate_feature"));
    let mutated = out_dir.join("contract_missing_gate_feature.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing gate feature:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("perf_regression_prevention_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("definitely_missing_gate_feature")),
        "expected missing gate feature failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_log_field() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_log_field")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_log_fields"]
        .as_array_mut()
        .ok_or("required_log_fields must be array")?
        .push(json!("missing_log_field"));
    let mutated = out_dir.join("contract_missing_log_field.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry field:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("perf_regression_prevention_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("missing_log_field")),
        "expected missing telemetry log field failure, got {report}"
    );

    Ok(())
}
