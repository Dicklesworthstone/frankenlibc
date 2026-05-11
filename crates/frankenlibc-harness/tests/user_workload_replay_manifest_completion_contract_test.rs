use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_ITEMS: &[&str] = &[
    "telemetry.primary",
    "tests.conformance.primary",
    "tests.unit.primary",
];

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_bindings_validated",
    "source_gate_replayed",
    "telemetry_rows_validated",
    "user_workload_replay_manifest_completion_contract_pass",
];

const REQUIRED_FAILURE_SIGNATURES: &[&str] = &[
    "workload_replay_invalid_command_argv",
    "workload_replay_invalid_env_overlay",
    "workload_replay_timeout_policy_invalid",
    "workload_replay_optional_skip_missing",
    "workload_replay_stale_source_commit",
];

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("missing workspace root")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/user_workload_replay_manifest_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_user_workload_replay_manifest_completion_contract.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("user_workload_replay_manifest_completion_contract.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("user_workload_replay_manifest_completion_contract.log.jsonl")
}

fn source_log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("user_workload_replay_manifest_completion_contract.source.log.jsonl")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?;
    Ok(array
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))
        })
        .collect::<Result<_, _>>()?)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("user-workload-replay-completion-{label}-{nanos}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> io::Result<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .arg(contract)
        .env(
            "FRANKENLIBC_USER_WORKLOAD_REPLAY_MANIFEST_COMPLETION_OUT_DIR",
            out_dir,
        )
        .current_dir(root)
        .output()
}

fn mutated_contract(
    root: &Path,
    out_dir: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value),
) -> TestResult<PathBuf> {
    let mut manifest = read_json(&contract_path(root))?;
    mutate(&mut manifest);
    let path = out_dir.join(format!(
        "user_workload_replay_manifest_completion_contract.{label}.json"
    ));
    std::fs::write(&path, serde_json::to_string_pretty(&manifest)? + "\n")?;
    Ok(path)
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed\n{}",
        output_text(output)
    );
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry["signature"].as_str())
        .map(ToString::to_string)
        .collect()
}

#[test]
fn manifest_binds_user_workload_replay_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("user_workload_replay_manifest_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-b92jd.3.1.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-b92jd.3.1"));

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing bindings"))?;
    assert_eq!(bindings.len(), 3);
    let specs: BTreeSet<String> = bindings
        .iter()
        .filter_map(|binding| binding["spec_item"].as_str())
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        specs,
        REQUIRED_ITEMS.iter().map(|item| item.to_string()).collect()
    );

    let runtime = &manifest["user_workload_replay_manifest_contract"];
    assert_eq!(runtime["expected_workload_count"].as_u64(), Some(5));
    assert_eq!(runtime["expected_matrix_row_count"].as_u64(), Some(15));
    assert_eq!(
        runtime["expected_optional_workload_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        string_set(&runtime["required_failure_signatures"])?,
        REQUIRED_FAILURE_SIGNATURES
            .iter()
            .map(|signature| signature.to_string())
            .collect()
    );

    for artifact in manifest["source_artifacts"].as_array().unwrap() {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path missing"))?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }
    Ok(())
}

#[test]
fn checker_validates_user_workload_replay_manifest_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&report_path(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["workload_count"].as_u64(), Some(5));
    assert_eq!(report["summary"]["matrix_row_count"].as_u64(), Some(15));
    assert_eq!(report["summary"]["telemetry_row_count"].as_u64(), Some(15));
    assert_eq!(
        report["summary"]["failure_signature_count"].as_u64(),
        Some(5)
    );
    assert!(report["errors"].as_array().unwrap().is_empty());

    let events: BTreeSet<String> = read_jsonl(&log_path(&out_dir))?
        .iter()
        .filter_map(|row| row["event"].as_str())
        .map(ToString::to_string)
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(*event), "missing event {event}");
    }

    let source_rows = read_jsonl(&source_log_path(&out_dir))?;
    assert_eq!(source_rows.len(), 15);
    assert!(source_rows.iter().any(|row| {
        row["workload_id"].as_str() == Some("optional_sqlite_version_probe")
            && row["skip_reason"].as_str() == Some("optional_tool_missing:sqlite3")
    }));
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let contract = mutated_contract(&root, &out_dir, "missing-unit", |manifest| {
        let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
            .as_array_mut()
            .expect("bindings array");
        bindings.retain(|binding| binding["spec_item"].as_str() != Some("tests.unit.primary"));
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("missing_completion_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_log_field() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-log-field")?;
    let contract = mutated_contract(&root, &out_dir, "missing-log-field", |manifest| {
        let fields = manifest["user_workload_replay_manifest_contract"]["required_log_fields"]
            .as_array_mut()
            .expect("required_log_fields array");
        fields.retain(|field| field.as_str() != Some("trace_id"));
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("telemetry_contract_drift"));
    Ok(())
}

#[test]
fn checker_rejects_missing_negative_fixture_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-negative")?;
    let contract = mutated_contract(&root, &out_dir, "missing-negative", |manifest| {
        manifest["user_workload_replay_manifest_contract"]["required_failure_signatures"][0] =
            json!("missing_failure_signature");
    })?;

    let output = run_checker(&root, &contract, &out_dir)?;
    assert_checker_failed(&output);

    let report = read_json(&report_path(&out_dir))?;
    let signatures = failure_signatures(&report);
    assert!(signatures.contains("unit_binding_drift"));
    Ok(())
}
