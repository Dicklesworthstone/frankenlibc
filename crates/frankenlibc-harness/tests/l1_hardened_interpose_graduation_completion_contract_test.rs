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
    root.join("tests/conformance/l1_hardened_interpose_graduation_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_l1_hardened_interpose_graduation_completion_contract.sh")
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "l1_hardened_interpose_graduation_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_COMPLETION_REPORT",
            out_dir.join("l1_hardened_interpose_graduation_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_COMPLETION_LOG",
            out_dir.join("l1_hardened_interpose_graduation_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_SOURCE_REPORT",
            out_dir.join("replacement_levels_l1_gate.source.report.json"),
        )
        .env(
            "FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_SOURCE_LOG",
            out_dir.join("replacement_levels_l1_gate.source.log.jsonl"),
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
fn manifest_binds_unit_e2e_fuzz_conformance_and_telemetry_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("l1_hardened_interpose_graduation_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-gtf.4"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-gtf.4.1")
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
        "tests.fuzz.primary",
        "tests.conformance.primary",
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
fn checker_validates_existing_l1_gate_artifacts() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("l1_hardened_interpose_graduation_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-gtf.4"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-gtf.4.1"));
    assert_eq!(report["summary"]["current_level"].as_str(), Some("L1"));
    assert_eq!(
        report["summary"]["current_release_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        report["summary"]["objective_gate_status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["summary"]["objective_obligation_count"].as_u64(),
        Some(8)
    );
    assert_eq!(
        report["summary"]["objective_outcomes"]["pass"].as_u64(),
        Some(8)
    );
    assert!(report["summary"]["objective_outcomes"]["blocked"].is_null());
    assert_eq!(
        report["summary"]["l1_crt_proof_row_count"].as_u64(),
        Some(11)
    );
    assert_eq!(
        report["summary"]["l1_crt_blocked_row_count"].as_u64(),
        Some(0)
    );
    assert_eq!(report["source_log_row_count"].as_u64(), Some(38));

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl_with_source_gate_rows() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("l1_hardened_interpose_graduation_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("l1_hardened_interpose_graduation_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(4));
    let source_gate_report = report["source_gate_report"]
        .as_str()
        .ok_or("source_gate_report must be a string")?;
    assert!(
        source_gate_report.ends_with("/replacement_levels_l1_gate.source.report.json"),
        "unexpected source_gate_report: {source_gate_report}"
    );

    let records = log_records(
        &out_dir.join("l1_hardened_interpose_graduation_completion_contract.log.jsonl"),
    )?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert!(events.contains(&"l1_hardened_interpose_completion_summary"));
    assert!(events.contains(&"l1_hardened_interpose_source_gate_bindings"));
    assert!(events.contains(&"l1_hardened_interpose_objective_gate_bindings"));
    assert!(events.contains(&"l1_hardened_interpose_completion_contract_pass"));

    for record in records {
        for field in [
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "outcome",
        ] {
            assert!(
                !record[field].is_null(),
                "log record missing {field}: {record}"
            );
        }
        assert_eq!(record["status"].as_str(), Some("pass"));
    }

    let source_records = log_records(&out_dir.join("replacement_levels_l1_gate.source.log.jsonl"))?;
    assert_eq!(source_records.len(), 38);
    assert!(
        source_records
            .iter()
            .any(|record| record["source"].as_str() == Some("objective_gate"))
    );
    assert!(
        source_records
            .iter()
            .any(|record| record["source"].as_str() == Some("l1_crt_startup_tls_proof_matrix"))
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_objective_obligation() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_obligation")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["required_objective_obligations"]
        .as_array_mut()
        .ok_or("required_objective_obligations must be array")?
        .push(json!("definitely_missing_l1_objective_obligation"));
    let mutated = out_dir.join("contract_missing_obligation.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing objective obligation:\n{}",
        output_text(&output)
    );
    let report = load_json(
        &out_dir.join("l1_hardened_interpose_graduation_completion_contract.report.json"),
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
                .contains("definitely_missing_l1_objective_obligation")),
        "expected missing objective obligation failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_wrong_current_level_expectation() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "wrong_current_level")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["current_level"] = json!("L0");
    let mutated = out_dir.join("contract_wrong_current_level.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject wrong current level expectation:\n{}",
        output_text(&output)
    );
    let report = load_json(
        &out_dir.join("l1_hardened_interpose_graduation_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("current_level")),
        "expected current_level failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events must be array")?
        .push(json!("missing_l1_hardened_interpose_completion_event"));
    let mutated = out_dir.join("contract_missing_event.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event:\n{}",
        output_text(&output)
    );
    let report = load_json(
        &out_dir.join("l1_hardened_interpose_graduation_completion_contract.report.json"),
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
                .contains("missing_l1_hardened_interpose_completion_event")),
        "expected missing telemetry event failure, got {report}"
    );

    Ok(())
}
