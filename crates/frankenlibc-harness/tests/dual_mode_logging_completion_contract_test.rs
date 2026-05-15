use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn checker_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    root.join("tests/conformance/dual_mode_logging_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_dual_mode_logging_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "dual_mode_logging_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_DUAL_MODE_LOGGING_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_DUAL_MODE_LOGGING_COMPLETION_REPORT",
            out_dir.join("dual_mode_logging_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_DUAL_MODE_LOGGING_COMPLETION_LOG",
            out_dir.join("dual_mode_logging_completion_contract.log.jsonl"),
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
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let values = value.as_array().ok_or("expected string array")?;
    let mut result = BTreeSet::new();
    for value in values {
        result.insert(value.as_str().ok_or("expected string")?.to_string());
    }
    Ok(result)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref
        .rsplit_once(':')
        .ok_or("file-line ref should contain ':'")?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "line number must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(root: &Path, manifest: &Value) -> TestResult<Vec<String>> {
    let sources = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    let mut texts = Vec::new();
    for path in sources.values() {
        let path = path.as_str().ok_or("source path string")?;
        texts.push(std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

#[test]
fn manifest_binds_dual_mode_logging_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("dual_mode_logging_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-oai.6"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-oai.6.1")
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "telemetry.primary",
            "tests.e2e.primary",
            "tests.unit.primary"
        ])
    );

    for file_line_ref in manifest["implementation_refs"]
        .as_array()
        .ok_or("implementation_refs array")?
    {
        assert_file_line_ref_exists(&root, file_line_ref.as_str().ok_or("ref string")?)?;
    }

    let events = string_set(&manifest["logging_contract"]["required_events"])?;
    for event in [
        "runtime_mode_switch_attempt",
        "runtime_mode_dispatch",
        "runtime_decision",
        "runtime_evidence_emitted",
        "runtime_calibration",
        "runtime_snapshot",
        "runtime_snapshot_field_out_of_range",
    ] {
        assert!(events.contains(event), "missing required event {event}");
    }

    let fields = string_set(&manifest["logging_contract"]["required_fields"])?;
    for field in [
        "trace_id",
        "decision_id",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(fields.contains(field), "missing required field {field}");
    }

    Ok(())
}

#[test]
fn source_anchors_and_required_test_refs_exist() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;

    for (key, anchors) in manifest["source_anchors"]
        .as_object()
        .ok_or("source_anchors object")?
    {
        let rel = source_artifacts[key]
            .as_str()
            .ok_or("source artifact path string")?;
        let text = std::fs::read_to_string(root.join(rel))?;
        for anchor in anchors.as_array().ok_or("anchor array")? {
            let anchor = anchor.as_str().ok_or("anchor string")?;
            assert!(text.contains(anchor), "{key} missing anchor {anchor}");
        }
    }

    let blobs = source_texts(&root, &manifest)?;
    for binding in manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?
    {
        for test_name in binding["required_test_refs"]
            .as_array()
            .ok_or("required_test_refs array")?
        {
            let test_name = test_name.as_str().ok_or("test name string")?;
            assert!(
                blobs
                    .iter()
                    .any(|blob| blob.contains(&format!("fn {test_name}"))),
                "required test ref missing from source artifacts: {test_name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_validates_dual_mode_logging_completion_contract() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("dual_mode_logging_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("dual_mode_logging_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-oai.6"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-oai.6.1"));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(3));
    assert!(report["summary"]["logging_event_count"]
        .as_u64()
        .is_some_and(|count| count >= 8));
    assert!(report["summary"]["resolved_test_ref_count"]
        .as_u64()
        .is_some_and(|count| count >= 9));

    let records = log_records(&out_dir.join("dual_mode_logging_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    for event in [
        "dual_mode_logging_source_bound",
        "dual_mode_logging_unit_bound",
        "dual_mode_logging_e2e_bound",
        "dual_mode_logging_telemetry_bound",
        "dual_mode_logging_completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing log event {event}");
    }
    for record in records {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "status",
            "source_commit",
            "original_bead",
            "completion_debt_bead",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(record.get(field).is_some(), "log row missing {field}");
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_required_logging_event() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let events = manifest["logging_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events array")?;
    events.retain(|event| event.as_str() != Some("runtime_snapshot_field_out_of_range"));

    let out_dir = unique_out_dir(&root, "missing-event")?;
    let mutated = out_dir.join("dual_mode_logging_completion_contract.mutated.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "mutated contract should fail\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("logging_event_missing"),
        "failure should identify missing logging event\n{}",
        output_text(&output)
    );

    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_command() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let command = manifest["missing_item_bindings"][0]["required_commands"][0]
        .as_str()
        .ok_or("required command string")?
        .replace("rch exec -- env CARGO_TARGET_DIR=<target> ", "");
    manifest["missing_item_bindings"][0]["required_commands"][0] = Value::String(command);

    let out_dir = unique_out_dir(&root, "non-rch")?;
    let mutated = out_dir.join("dual_mode_logging_completion_contract.mutated.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "mutated contract should fail\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cargo_not_rch"),
        "failure should identify local cargo command\n{}",
        output_text(&output)
    );

    Ok(())
}
