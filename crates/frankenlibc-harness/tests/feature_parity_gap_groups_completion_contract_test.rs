use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .ok_or_else(|| format!("crate directory has no workspace parent: {manifest}"))?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("workspace parent has no repo parent: {manifest}").into())
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
    root.join("tests/conformance/feature_parity_gap_groups_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_feature_parity_gap_groups_completion_contract.sh")
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "feature_parity_gap_groups_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS_COMPLETION_REPORT",
            out_dir.join("feature_parity_gap_groups_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS_COMPLETION_LOG",
            out_dir.join("feature_parity_gap_groups_completion_contract.log.jsonl"),
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
        Some("feature_parity_gap_groups_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.3.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.3.1.1")
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
fn checker_validates_existing_feature_parity_gap_group_gate() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("feature_parity_gap_groups_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-bp8fl.3.1"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.3.1.1")
    );
    assert_eq!(report["summary"]["ledger_gap_count"].as_u64(), Some(110));
    assert_eq!(report["summary"]["batch_count"].as_u64(), Some(10));
    assert_eq!(report["summary"]["batched_gap_count"].as_u64(), Some(110));
    assert_eq!(report["summary"]["unbatched_gap_count"].as_u64(), Some(0));
    assert_eq!(report["source_log_row_count"].as_u64(), Some(121));
    assert_eq!(
        report["checks"]["exact_gap_coverage"].as_str(),
        Some("pass")
    );
    assert_eq!(
        report["checks"]["owner_bead_coverage"].as_str(),
        Some("pass")
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
        load_json(&out_dir.join("feature_parity_gap_groups_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("feature_parity_gap_groups_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(3));
    let source_gate_report = report["source_gate_report"]
        .as_str()
        .ok_or("source_gate_report must be string")?;
    assert!(
        source_gate_report.ends_with("feature_parity_gap_groups.source.report.json"),
        "source_gate_report should point at isolated replay artifact, got {source_gate_report}"
    );
    assert!(
        root.join(source_gate_report).exists(),
        "source_gate_report artifact missing at {source_gate_report}"
    );

    let records =
        log_records(&out_dir.join("feature_parity_gap_groups_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert!(events.contains(&"feature_parity_gap_groups_completion_summary"));
    assert!(events.contains(&"feature_parity_gap_groups_source_gate_bindings"));
    assert!(events.contains(&"feature_parity_gap_groups_completion_contract_pass"));

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

    Ok(())
}

#[test]
fn checker_rejects_missing_required_batch() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_batch")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["required_batches"]
        .as_array_mut()
        .ok_or("required_batches must be array")?
        .push(json!("definitely_missing_batch"));
    let mutated = out_dir.join("contract_missing_batch.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing required batch:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("feature_parity_gap_groups_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("definitely_missing_batch")),
        "expected missing batch failure, got {report}"
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
        .push(json!("missing_feature_parity_gap_groups_event"));
    let mutated = out_dir.join("contract_missing_event.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("feature_parity_gap_groups_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_feature_parity_gap_groups_event")),
        "expected missing telemetry event failure, got {report}"
    );

    Ok(())
}
