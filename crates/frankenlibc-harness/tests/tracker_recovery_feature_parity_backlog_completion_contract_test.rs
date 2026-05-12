//! Completion contract tests for bd-bp8fl.2.10.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/tracker_recovery_feature_parity_backlog_completion_contract.v1.json";
const CHECKER_REL: &str =
    "scripts/check_tracker_recovery_feature_parity_backlog_completion_contract.sh";
const EXPECTED_SCHEMA: &str = "tracker_recovery_feature_parity_backlog_completion_contract.v1";
const EXPECTED_REPORT_SCHEMA: &str =
    "tracker_recovery_feature_parity_backlog_completion_contract.report.v1";
const EXPECTED_GATE_COUNT: usize = 8;
const EXPECTED_EVENTS: &[&str] = &[
    "tracker_recovery_backlog.sources_validated",
    "tracker_recovery_backlog.bindings_validated",
    "tracker_recovery_backlog.source_gates_replayed",
    "tracker_recovery_backlog.completion_contract_pass",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("manifest should live below workspace root"))?
        .to_path_buf())
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "tracker-recovery-backlog-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("events.jsonl")
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env(
            "FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_LOG",
            checker_log(out_dir),
        )
        .env(
            "FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_SOURCE_GATE_DIR",
            out_dir.join("source_gates"),
        )
        .output()?)
}

fn expect_checker_success(root: &Path, out_dir: &Path) -> TestResult<Output> {
    let output = run_checker(root, &root.join(CONTRACT_REL), out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn expect_checker_failure(output: Output, signature: &str) {
    assert!(
        !output.status.success(),
        "checker unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(signature),
        "checker failure missing signature {signature:?}\n{combined}"
    );
}

fn string_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} string missing")).into()
    })
}

fn array_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} array missing")).into()
    })
}

fn object_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} object missing")).into()
    })
}

fn string_set(values: &[Value]) -> TestResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| {
            value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "expected string value").into()
            })
        })
        .collect()
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            validate_log_line(line, index + 1).map_err(|errors| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("structured log line {} failed: {errors:?}", index + 1),
                )
            })?;
            Ok(serde_json::from_str(line)?)
        })
        .collect()
}

#[test]
fn contract_binds_tracker_recovery_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-bp8fl.2.10");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-bp8fl.2");

    let completion = manifest
        .get("completion_contract")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion contract missing"))?;
    assert_eq!(
        string_set(array_field(completion, "missing_item_ids")?)?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert_eq!(
        array_field(completion, "required_source_gates")?.len(),
        EXPECTED_GATE_COUNT
    );

    for (_key, value) in object_field(&manifest, "source_artifacts")? {
        let path = value.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source path must be string")
        })?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let binding_ids = array_field(&manifest, "missing_item_bindings")?
        .iter()
        .map(|binding| string_field(binding, "id").map(ToOwned::to_owned))
        .collect::<TestResult<BTreeSet<_>>>()?;
    assert_eq!(
        binding_ids,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    Ok(())
}

#[test]
fn checker_accepts_tracker_recovery_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS: tracker recovery feature parity backlog completion contract"));

    let report = read_json(&checker_report(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version")?,
        EXPECTED_REPORT_SCHEMA
    );
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        report
            .pointer("/summary/source_gate_count")
            .and_then(Value::as_u64),
        Some(EXPECTED_GATE_COUNT as u64)
    );
    assert_eq!(
        report
            .pointer("/summary/binding_count")
            .and_then(Value::as_u64),
        Some(4)
    );

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names = events
        .iter()
        .filter_map(|event| event.get("event").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for expected in EXPECTED_EVENTS {
        assert!(event_names.contains(expected), "missing event {expected}");
    }
    Ok(())
}

#[test]
fn checker_replays_all_source_gates() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "source-gates")?;
    expect_checker_success(&root, &out_dir)?;

    let report = read_json(&checker_report(&out_dir))?;
    let source_gates = object_field(&report, "source_gates")?;
    assert_eq!(source_gates.len(), EXPECTED_GATE_COUNT);
    for gate_id in [
        "tracker_health",
        "br_bv_disagreement",
        "ambition_graph_readiness",
        "crypt_dashboard",
        "feature_parity_closure",
        "hard_parts_replay",
        "workstream_done_templates",
        "reality_bridge_reconciliation",
    ] {
        let gate = source_gates.get(gate_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("{gate_id} missing"))
        })?;
        assert_eq!(string_field(gate, "status")?, "pass");
        let report_path = string_field(gate, "report")?;
        assert!(
            root.join(report_path).exists(),
            "source report missing: {report_path}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-binding")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    let bindings = contract
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bindings missing"))?;
    bindings
        .retain(|binding| binding.get("id").and_then(Value::as_str) != Some("telemetry.primary"));

    let contract_path = out_dir.join("contract.json");
    write_json(&contract_path, &contract)?;
    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(output, "missing_item_bindings mismatch");
    Ok(())
}

#[test]
fn checker_rejects_missing_source_artifact() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-source")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    contract["source_artifacts"]["tracker_health_manifest"] =
        json!("tests/conformance/nonexistent_tracker_health_report.v1.json");

    let contract_path = out_dir.join("contract.json");
    write_json(&contract_path, &contract)?;
    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(
        output,
        "source_artifacts.tracker_health_manifest references missing path",
    );
    Ok(())
}

#[test]
fn checker_rejects_source_gate_status_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "status-drift")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    let gates = contract
        .pointer_mut("/completion_contract/required_source_gates")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source gates missing"))?;
    gates[0]["expected_report_status"] = json!("fail");

    let contract_path = out_dir.join("contract.json");
    write_json(&contract_path, &contract)?;
    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(output, "source_gate_status_mismatch");
    Ok(())
}
