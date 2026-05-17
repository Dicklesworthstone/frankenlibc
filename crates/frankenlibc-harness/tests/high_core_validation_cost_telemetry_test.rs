//! Deterministic high-core validation cost telemetry gate (bd-whlqo).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_PATH: &str = "tests/conformance/high_core_validation_shards.v1.json";
const CONTRACT_PATH: &str = "tests/conformance/high_core_validation_cost_telemetry.v1.json";
const AGGREGATE_SCRIPT: &str = "scripts/aggregate_high_core_validation_costs.sh";

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            test_error(format!(
                "could not derive workspace root from {}",
                manifest_dir.display()
            ))
        })
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock before Unix epoch: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)
        .map_err(|err| test_error(format!("create {} failed: {err}", dir.display())))?;
    Ok(dir)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&body)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|err| {
                test_error(format!("{} has invalid JSONL row: {err}", path.display()))
            })
        })
        .collect()
}

fn write_jsonl(path: &Path, rows: &[Value]) -> TestResult {
    let mut body = String::new();
    for row in rows {
        body.push_str(
            &serde_json::to_string(row)
                .map_err(|err| test_error(format!("serialize JSONL row failed: {err}")))?,
        );
        body.push('\n');
    }
    std::fs::write(path, body)
        .map_err(|err| test_error(format!("write {} failed: {err}", path.display())))
}

fn committed_manifest_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join(MANIFEST_PATH))
}

fn committed_contract_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join(CONTRACT_PATH))
}

fn first_manifest_unit_ids(count: usize) -> TestResult<Vec<String>> {
    let manifest = load_json(&committed_manifest_path()?)?;
    let units = manifest
        .get("units")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("manifest.units must be array"))?;
    let mut ids = Vec::new();
    for unit in units.iter().take(count) {
        let unit_id = unit
            .get("unit_id")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("manifest unit_id must be string"))?;
        ids.push(unit_id.to_owned());
    }
    if ids.len() != count {
        return Err(test_error(format!(
            "manifest should contain at least {count} units"
        )));
    }
    Ok(ids)
}

fn run_aggregator(log_path: &Path, label: &str) -> TestResult<(PathBuf, PathBuf, Output)> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let report = dir.join("costs.report.json");
    let events = dir.join("costs.events.log.jsonl");
    let output = Command::new("bash")
        .arg(root.join(AGGREGATE_SCRIPT))
        .env(
            "HIGH_CORE_VALIDATION_SHARD_MANIFEST",
            committed_manifest_path()?,
        )
        .env(
            "HIGH_CORE_VALIDATION_COST_CONTRACT",
            committed_contract_path()?,
        )
        .env("HIGH_CORE_VALIDATION_COST_LOG", log_path)
        .env("HIGH_CORE_VALIDATION_COST_REPORT", &report)
        .env("HIGH_CORE_VALIDATION_COST_EVENTS", &events)
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("failed to run cost telemetry aggregator: {err}")))?;
    Ok((report, events, output))
}

fn assert_success(output: &Output) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(test_error(format!(
            "aggregator failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn assert_failure(output: &Output) -> TestResult {
    if output.status.success() {
        Err(test_error(format!(
            "aggregator unexpectedly passed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    } else {
        Ok(())
    }
}

fn assert_failure_signature(report: &Value, expected: &str) -> TestResult {
    let signatures = report
        .get("failure_signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("failure report missing failure_signatures"))?;
    if signatures
        .iter()
        .any(|entry| entry.as_str().is_some_and(|actual| actual.eq(expected)))
    {
        Ok(())
    } else {
        Err(test_error(format!(
            "expected failure signature {expected}; report={report:#?}"
        )))
    }
}

fn write_cost_rows(label: &str, rows: &[Value]) -> TestResult<PathBuf> {
    let dir = unique_temp_dir(label)?;
    let path = dir.join("costs.log.jsonl");
    write_jsonl(&path, rows)?;
    Ok(path)
}

fn write_raw_log(label: &str, body: &str) -> TestResult<PathBuf> {
    let dir = unique_temp_dir(label)?;
    let path = dir.join("costs.log.jsonl");
    std::fs::write(&path, body)
        .map_err(|err| test_error(format!("write {} failed: {err}", path.display())))?;
    Ok(path)
}

fn cost_row(
    run_number: u64,
    unit_id: &str,
    status: &str,
    exit_code: i64,
    duration_ms: u64,
    artifact_bytes: u64,
    failure_count: u64,
) -> Value {
    json!({
        "run_id": format!("run-{run_number:04}"),
        "unit_id": unit_id,
        "shard_id": "shard-00",
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "worker_id": "rch-worker-001",
        "cache_state": "hit",
        "artifact_count": 2,
        "artifact_bytes": artifact_bytes,
        "failure_count": failure_count,
    })
}

fn unit_report<'a>(report: &'a Value, unit_id: &str) -> TestResult<&'a Value> {
    let per_unit = report
        .get("per_unit")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("report.per_unit must be array"))?;
    per_unit
        .iter()
        .find(|entry| entry.get("unit_id").and_then(Value::as_str) == Some(unit_id))
        .ok_or_else(|| test_error(format!("missing per-unit report for {unit_id}")))
}

#[test]
fn cost_telemetry_contract_defines_required_row_schema() -> TestResult {
    let contract = load_json(&committed_contract_path()?)?;
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-whlqo"));
    assert_eq!(
        contract["log_contract"]["cost_log"].as_str(),
        Some("target/conformance/high_core_validation/costs.log.jsonl")
    );

    let required_fields = contract["log_contract"]["required_row_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_row_fields must be array"))?;
    for field in [
        "run_id",
        "unit_id",
        "duration_ms",
        "worker_id",
        "cache_state",
        "artifact_count",
        "artifact_bytes",
        "failure_count",
    ] {
        assert!(
            required_fields
                .iter()
                .any(|entry| entry.as_str().is_some_and(|actual| actual.eq(field))),
            "required row field missing: {field}"
        );
    }
    Ok(())
}

#[test]
fn cost_telemetry_e2e_aggregates_synthetic_log() -> TestResult {
    let unit_ids = first_manifest_unit_ids(2)?;
    let rows = vec![
        cost_row(1, &unit_ids[0], "passed", 0, 100, 1024, 0),
        cost_row(2, &unit_ids[0], "failed", 1, 300, 2048, 1),
        cost_row(3, &unit_ids[1], "passed", 0, 800, 4096, 0),
    ];
    let log_path = write_cost_rows("hcvs-cost-e2e", &rows)?;
    let (report_path, events_path, output) = run_aggregator(&log_path, "hcvs-cost-e2e")?;
    assert_success(&output)?;

    let report = load_json(&report_path)?;
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-whlqo"));
    assert_eq!(report["status"].as_str(), Some("passed"));
    assert_eq!(report["summary"]["sample_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["unit_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["failed_sample_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["failure_count"].as_u64(), Some(1));
    assert_eq!(
        report["summary"]["total_artifact_bytes"].as_u64(),
        Some(7168)
    );

    let first_unit = unit_report(&report, &unit_ids[0])?;
    assert_eq!(first_unit["sample_count"].as_u64(), Some(2));
    assert_eq!(first_unit["duration_ms_p95"].as_u64(), Some(300));
    assert_eq!(first_unit["failure_frequency"].as_f64(), Some(0.5));
    assert_eq!(first_unit["artifact_bytes_p95"].as_u64(), Some(2048));

    let events = load_jsonl(&events_path)?;
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"].as_str() == Some("cost_row_recorded"))
            .count(),
        3
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"].as_str() == Some("cost_telemetry_summary")),
        "summary event is required"
    );
    Ok(())
}

#[test]
fn cost_telemetry_rejects_malformed_jsonl_row() -> TestResult {
    let log_path = write_raw_log("hcvs-cost-malformed", "{\"run_id\":\"run-0001\"\n")?;
    let (report_path, _events_path, output) = run_aggregator(&log_path, "hcvs-cost-malformed")?;
    assert_failure(&output)?;
    let report = load_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("failed"));
    assert_failure_signature(&report, "malformed_jsonl")
}

#[test]
fn cost_telemetry_rejects_unknown_unit_id() -> TestResult {
    let rows = vec![cost_row(
        1,
        "hcvs-not-a-real-unit",
        "passed",
        0,
        100,
        1024,
        0,
    )];
    let log_path = write_cost_rows("hcvs-cost-unknown-unit", &rows)?;
    let (report_path, _events_path, output) = run_aggregator(&log_path, "hcvs-cost-unknown-unit")?;
    assert_failure(&output)?;
    let report = load_json(&report_path)?;
    assert_failure_signature(&report, "unknown_unit_id")
}

#[test]
fn cost_telemetry_rejects_nonmonotonic_run_ids() -> TestResult {
    let unit_ids = first_manifest_unit_ids(1)?;
    let rows = vec![
        cost_row(2, &unit_ids[0], "passed", 0, 100, 1024, 0),
        cost_row(1, &unit_ids[0], "passed", 0, 120, 1024, 0),
    ];
    let log_path = write_cost_rows("hcvs-cost-run-order", &rows)?;
    let (report_path, _events_path, output) = run_aggregator(&log_path, "hcvs-cost-run-order")?;
    assert_failure(&output)?;
    let report = load_json(&report_path)?;
    assert_failure_signature(&report, "nonmonotonic_run_id")
}

#[test]
fn cost_telemetry_rejects_unbounded_artifact_size() -> TestResult {
    let unit_ids = first_manifest_unit_ids(1)?;
    let rows = vec![cost_row(
        1,
        &unit_ids[0],
        "passed",
        0,
        100,
        1_073_741_825,
        0,
    )];
    let log_path = write_cost_rows("hcvs-cost-artifact-bound", &rows)?;
    let (report_path, _events_path, output) =
        run_aggregator(&log_path, "hcvs-cost-artifact-bound")?;
    assert_failure(&output)?;
    let report = load_json(&report_path)?;
    assert_failure_signature(&report, "unbounded_artifact_size")
}

#[test]
fn cost_telemetry_report_is_deterministic() -> TestResult {
    let unit_ids = first_manifest_unit_ids(2)?;
    let rows = vec![
        cost_row(1, &unit_ids[1], "passed", 0, 450, 2048, 0),
        cost_row(2, &unit_ids[0], "passed", 0, 125, 1024, 0),
        cost_row(3, &unit_ids[1], "failed", 1, 500, 4096, 2),
    ];
    let log_path = write_cost_rows("hcvs-cost-deterministic", &rows)?;
    let (report_a_path, _events_a_path, output_a) =
        run_aggregator(&log_path, "hcvs-cost-deterministic-a")?;
    let (report_b_path, _events_b_path, output_b) =
        run_aggregator(&log_path, "hcvs-cost-deterministic-b")?;
    assert_success(&output_a)?;
    assert_success(&output_b)?;

    let report_a = load_json(&report_a_path)?;
    let report_b = load_json(&report_b_path)?;
    assert_eq!(report_a, report_b, "cost aggregation report must be stable");
    let per_unit = report_a["per_unit"]
        .as_array()
        .ok_or_else(|| test_error("report.per_unit must be array"))?;
    let mut sorted_unit_ids = per_unit
        .iter()
        .map(|entry| {
            entry
                .get("unit_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| test_error("per_unit unit_id must be string"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let observed = sorted_unit_ids.clone();
    sorted_unit_ids.sort();
    assert_eq!(observed, sorted_unit_ids, "per-unit rows must be sorted");
    Ok(())
}
