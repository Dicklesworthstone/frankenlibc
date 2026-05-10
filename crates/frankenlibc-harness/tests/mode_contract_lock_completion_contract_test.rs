use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn gate_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/mode_contract_lock_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_mode_contract_lock_completion_contract.sh")
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "mode_contract_lock_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_MODE_CONTRACT_LOCK_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_MODE_CONTRACT_LOCK_COMPLETION_REPORT",
            out_dir.join("mode_contract_lock_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_MODE_CONTRACT_LOCK_COMPLETION_LOG",
            out_dir.join("mode_contract_lock_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_MODE_CONTRACT_LOCK_RUNTIME_EVIDENCE_REPORT",
            out_dir.join("runtime_mode_evidence_logging_coverage.report.json"),
        )
        .env(
            "FRANKENLIBC_MODE_CONTRACT_LOCK_RUNTIME_EVIDENCE_LOG",
            out_dir.join("runtime_mode_evidence_logging_coverage.log.jsonl"),
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
        .filter(|line| !line.trim().is_empty())
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
        Some("mode_contract_lock_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-w2c3.3.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-w2c3.3.3.1")
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
        "telemetry.primary",
    ] {
        assert!(
            item_ids.contains(&required),
            "missing item binding {required}"
        );
    }

    for implementation_ref in manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .ok_or("implementation_refs must be array")?
    {
        let path = implementation_ref["path"]
            .as_str()
            .ok_or("implementation ref path must be string")?;
        let text = std::fs::read_to_string(root.join(path))?;
        for needle in implementation_ref["required_text"]
            .as_array()
            .ok_or("required_text must be array")?
        {
            let needle = needle.as_str().ok_or("needle must be string")?;
            assert!(
                text.contains(needle),
                "implementation ref {path} missing {needle}"
            );
        }
    }

    let texts = source_texts(&root, &manifest)?;
    let config_text =
        std::fs::read_to_string(root.join("crates/frankenlibc-membrane/src/config.rs"))?;
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
                texts.iter().any(|text| text.contains(name)) || config_text.contains(name),
                "required test ref {name} missing from source text"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_validates_existing_mode_contract_lock_gate() -> TestResult {
    let _lock = gate_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("mode_contract_lock_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-w2c3.3.3"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-w2c3.3.3.1")
    );
    assert_eq!(
        report["summary"]["env_key"].as_str(),
        Some("FRANKENLIBC_MODE")
    );
    assert_eq!(
        report["summary"]["allowed_values"]
            .as_array()
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec!["strict", "hardened"])
    );
    assert_eq!(
        report["summary"]["required_provenance_fields"].as_u64(),
        Some(12)
    );
    assert_eq!(
        report["summary"]["startup_reentrant_anchors"].as_u64(),
        Some(3)
    );
    assert_eq!(
        report["summary"]["runtime_evidence_coverage_rows"].as_u64(),
        Some(7)
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl_with_source_gate_rows() -> TestResult {
    let _lock = gate_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("mode_contract_lock_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("mode_contract_lock_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(4));
    assert_eq!(
        report["source_log_row_counts"]["mode_contract_lock"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["source_log_row_counts"]["runtime_mode_evidence"].as_u64(),
        Some(1)
    );

    let runtime_report =
        load_json(&out_dir.join("runtime_mode_evidence_logging_coverage.report.json"))?;
    assert_eq!(runtime_report["outcome"].as_str(), Some("pass"));

    let records = log_records(&out_dir.join("mode_contract_lock_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert!(events.contains(&"mode_contract_lock_completion_summary"));
    assert!(events.contains(&"mode_contract_lock_source_gate_bindings"));
    assert!(events.contains(&"mode_contract_lock_runtime_evidence_bindings"));
    assert!(events.contains(&"mode_contract_lock_completion_contract_pass"));

    for record in records {
        for field in [
            "timestamp",
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "source_commit",
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
fn checker_rejects_missing_startup_anchor() -> TestResult {
    let _lock = gate_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_anchor")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let missing_anchor = format!(
        "missing_mode_contract_lock_anchor_{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    manifest["required_source_contract"]["startup_anchor_names"]
        .as_array_mut()
        .ok_or("startup_anchor_names must be array")?
        .push(json!(missing_anchor));
    let mutated = out_dir.join("contract_missing_anchor.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing startup anchor:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("mode_contract_lock_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains(&missing_anchor)),
        "expected missing anchor failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_wrong_allowed_mode_expectation() -> TestResult {
    let _lock = gate_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "wrong_allowed_mode")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_source_contract"]["allowed_values"] = json!(["strict", "hardened", "off"]);
    let mutated = out_dir.join("contract_wrong_allowed_mode.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject wrong allowed mode expectation:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("mode_contract_lock_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("allowed_values")),
        "expected allowed_values failure, got {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let _lock = gate_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events must be array")?
        .push(json!("missing_mode_contract_lock_completion_event"));
    let mutated = out_dir.join("contract_missing_event.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("mode_contract_lock_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_mode_contract_lock_completion_event")),
        "expected missing telemetry event failure, got {report}"
    );

    Ok(())
}
