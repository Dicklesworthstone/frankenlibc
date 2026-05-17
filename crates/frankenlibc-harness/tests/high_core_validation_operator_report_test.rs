//! Operator report coverage for high-core validation evidence (bd-2syj4).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_PATH: &str = "tests/conformance/high_core_validation_operator_report.v1.json";
const REPORT_SCRIPT: &str = "scripts/generate_high_core_validation_operator_report.sh";

struct ReportRun {
    json_report: PathBuf,
    markdown_report: PathBuf,
    event_log: PathBuf,
    output: Output,
}

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

fn write_json(path: &Path, value: &Value) -> TestResult {
    let body = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("serialize {} failed: {err}", path.display())))?;
    std::fs::write(path, format!("{body}\n"))
        .map_err(|err| test_error(format!("write {} failed: {err}", path.display())))
}

fn committed_contract_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join(CONTRACT_PATH))
}

fn assert_success(output: &Output) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(test_error(format!(
            "operator report command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn command_for(unit: &str) -> Vec<&'static str> {
    match unit {
        "hcvs-failed" => vec![
            "env",
            "RCH_FORCE_REMOTE=true",
            "rch",
            "--no-self-healing",
            "exec",
            "--",
            "cargo",
            "test",
            "-p",
            "frankenlibc-harness",
            "--test",
            "failed_lane_test",
        ],
        "hcvs-skipped" => vec![
            "env",
            "RCH_FORCE_REMOTE=true",
            "rch",
            "--no-self-healing",
            "exec",
            "--",
            "cargo",
            "test",
            "-p",
            "frankenlibc-harness",
            "--test",
            "skipped_lane_test",
        ],
        _ => vec![
            "env",
            "RCH_FORCE_REMOTE=true",
            "rch",
            "--no-self-healing",
            "exec",
            "--",
            "cargo",
            "test",
            "-p",
            "frankenlibc-harness",
            "--test",
            "passed_lane_test",
        ],
    }
}

fn synthetic_merge_report() -> Value {
    json!({
        "schema_version": "v1",
        "bead": "bd-31d38",
        "status": "failed",
        "summary": {
            "planned_unit_count": 4,
            "passed_count": 2,
            "failed_count": 1,
            "skipped_count": 1
        },
        "results": [
            {
                "run_id": "run-1",
                "unit_id": "hcvs-passed",
                "shard_id": "shard-00",
                "lane_index": 0,
                "command_template": command_for("hcvs-passed"),
                "reproduction_command": command_for("hcvs-passed").join(" "),
                "status": "passed",
                "exit_code": 0,
                "duration_ms": 100,
                "artifact_refs": [{"path": "target/conformance/high_core_validation/passed.report.json", "status": "present"}],
                "failure_signature": ""
            },
            {
                "run_id": "run-2",
                "unit_id": "hcvs-failed",
                "shard_id": "shard-01",
                "lane_index": 1,
                "command_template": command_for("hcvs-failed"),
                "reproduction_command": command_for("hcvs-failed").join(" "),
                "status": "failed",
                "exit_code": 17,
                "duration_ms": 800,
                "artifact_refs": [{"path": "target/conformance/high_core_validation/failed.report.json", "status": "failed"}],
                "failure_signature": "fixture_failed"
            },
            {
                "run_id": "run-3",
                "unit_id": "hcvs-skipped",
                "shard_id": "shard-02",
                "lane_index": 2,
                "command_template": command_for("hcvs-skipped"),
                "reproduction_command": command_for("hcvs-skipped").join(" "),
                "status": "skipped",
                "exit_code": 0,
                "duration_ms": 0,
                "artifact_refs": [{"path": "target/conformance/high_core_validation/skipped.report.json", "status": "present"}],
                "failure_signature": "worker_unavailable"
            },
            {
                "run_id": "run-4",
                "unit_id": "hcvs-stale-expensive",
                "shard_id": "shard-03",
                "lane_index": 3,
                "command_template": command_for("hcvs-stale-expensive"),
                "reproduction_command": command_for("hcvs-stale-expensive").join(" "),
                "status": "passed",
                "exit_code": 0,
                "duration_ms": 1000,
                "artifact_refs": [{"path": "target/conformance/high_core_validation/stale.report.json", "status": "stale"}],
                "failure_signature": ""
            }
        ],
        "failure_index": [
            {
                "unit_id": "hcvs-failed",
                "shard_id": "shard-01",
                "lane_index": 1,
                "failure_signature": "fixture_failed",
                "first_failing_artifact": "target/conformance/high_core_validation/failed.report.json",
                "reproduction_command": command_for("hcvs-failed").join(" "),
                "detail": "exit_code=17 duration_ms=800"
            }
        ]
    })
}

fn synthetic_cost_report() -> Value {
    json!({
        "schema_version": "v1",
        "bead": "bd-whlqo",
        "status": "passed",
        "per_unit": [
            {"unit_id": "hcvs-passed", "duration_ms_p95": 100, "current_cost_class": "cheap", "suggested_cost_class": "cheap"},
            {"unit_id": "hcvs-failed", "duration_ms_p95": 800, "current_cost_class": "cheap", "suggested_cost_class": "cheap"},
            {"unit_id": "hcvs-skipped", "duration_ms_p95": 0, "current_cost_class": "cheap", "suggested_cost_class": "cheap"},
            {"unit_id": "hcvs-stale-expensive", "duration_ms_p95": 900000, "current_cost_class": "expensive", "suggested_cost_class": "expensive"}
        ]
    })
}

fn run_report(label: &str, merge: &Value, cost: &Value) -> TestResult<ReportRun> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let merge_path = dir.join("merge.report.json");
    let cost_path = dir.join("costs.report.json");
    let json_report = dir.join("operator.report.json");
    let markdown_report = dir.join("operator.report.md");
    let event_log = dir.join("operator.events.log.jsonl");
    write_json(&merge_path, merge)?;
    write_json(&cost_path, cost)?;
    let output = Command::new("bash")
        .arg(root.join(REPORT_SCRIPT))
        .env(
            "HIGH_CORE_VALIDATION_OPERATOR_CONTRACT",
            committed_contract_path()?,
        )
        .env("HIGH_CORE_VALIDATION_MERGE_REPORT", &merge_path)
        .env("HIGH_CORE_VALIDATION_COST_REPORT", &cost_path)
        .env("HIGH_CORE_VALIDATION_OPERATOR_JSON", &json_report)
        .env("HIGH_CORE_VALIDATION_OPERATOR_MARKDOWN", &markdown_report)
        .env("HIGH_CORE_VALIDATION_OPERATOR_EVENTS", &event_log)
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("failed to run operator report generator: {err}")))?;
    Ok(ReportRun {
        json_report,
        markdown_report,
        event_log,
        output,
    })
}

fn array_len(value: &Value, field: &str) -> TestResult<usize> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| test_error(format!("{field} must be array")))
}

#[test]
fn operator_contract_defines_required_sections() -> TestResult {
    let contract = load_json(&committed_contract_path()?)?;
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-2syj4"));
    let sections = contract["required_sections"]
        .as_array()
        .ok_or_else(|| test_error("required_sections must be array"))?;
    for section in [
        "lane_health",
        "recent_p95_cost",
        "failed_units",
        "skipped_units",
        "stale_artifact_warnings",
        "rch_rerun_commands",
    ] {
        assert!(
            sections
                .iter()
                .any(|entry| entry.as_str().is_some_and(|actual| actual == section)),
            "missing required section {section}"
        );
    }
    Ok(())
}

#[test]
fn operator_report_surfaces_failed_skipped_stale_and_expensive_lanes() -> TestResult {
    let run = run_report(
        "hcvs-operator-mixed",
        &synthetic_merge_report(),
        &synthetic_cost_report(),
    )?;
    assert_success(&run.output)?;
    let report = load_json(&run.json_report)?;
    assert_eq!(report["status"].as_str(), Some("failed"));
    assert_eq!(array_len(&report, "failed_units")?, 1);
    assert_eq!(array_len(&report, "skipped_units")?, 1);
    assert_eq!(array_len(&report, "stale_artifact_warnings")?, 1);
    assert_eq!(report["summary"]["expensive_unit_count"].as_u64(), Some(1));

    let failed = &report["failed_units"][0];
    assert_eq!(failed["unit_id"].as_str(), Some("hcvs-failed"));
    assert_eq!(failed["failure_signature"].as_str(), Some("fixture_failed"));
    assert!(
        failed["reproduction_command"]
            .as_str()
            .is_some_and(|command| command.contains("RCH_FORCE_REMOTE=true"))
    );

    let skipped = &report["skipped_units"][0];
    assert_eq!(skipped["unit_id"].as_str(), Some("hcvs-skipped"));
    assert_eq!(
        skipped["failure_signature"].as_str(),
        Some("worker_unavailable")
    );
    Ok(())
}

#[test]
fn operator_report_does_not_hide_skipped_units_behind_green_aggregate() -> TestResult {
    let mut merge = synthetic_merge_report();
    merge["status"] = Value::String("passed".to_owned());
    merge["failure_index"] = Value::Array(Vec::new());
    let results = merge["results"]
        .as_array_mut()
        .ok_or_else(|| test_error("results must be mutable array"))?;
    for row in results {
        if row["unit_id"].as_str() == Some("hcvs-failed") {
            row["status"] = Value::String("passed".to_owned());
            row["exit_code"] = Value::from(0);
            row["failure_signature"] = Value::String(String::new());
        }
    }
    let run = run_report(
        "hcvs-operator-skipped-green",
        &merge,
        &synthetic_cost_report(),
    )?;
    assert_success(&run.output)?;
    let report = load_json(&run.json_report)?;
    assert_eq!(report["status"].as_str(), Some("warning"));
    assert_eq!(array_len(&report, "failed_units")?, 0);
    assert_eq!(array_len(&report, "skipped_units")?, 1);
    assert_eq!(report["summary"]["skipped_unit_count"].as_u64(), Some(1));
    Ok(())
}

#[test]
fn operator_report_derives_failed_units_when_failure_index_is_missing() -> TestResult {
    let mut merge = synthetic_merge_report();
    merge["failure_index"] = Value::Array(Vec::new());
    let run = run_report(
        "hcvs-operator-derived-failure",
        &merge,
        &synthetic_cost_report(),
    )?;
    assert_success(&run.output)?;
    let report = load_json(&run.json_report)?;
    assert_eq!(report["status"].as_str(), Some("failed"));
    assert_eq!(array_len(&report, "failed_units")?, 1);
    assert_eq!(
        report["failed_units"][0]["failure_signature"].as_str(),
        Some("fixture_failed")
    );
    Ok(())
}

#[test]
fn operator_report_markdown_includes_failed_units_and_rerun_commands() -> TestResult {
    let run = run_report(
        "hcvs-operator-markdown",
        &synthetic_merge_report(),
        &synthetic_cost_report(),
    )?;
    assert_success(&run.output)?;
    let markdown = std::fs::read_to_string(&run.markdown_report).map_err(|err| {
        test_error(format!(
            "read {} failed: {err}",
            run.markdown_report.display()
        ))
    })?;
    for required in [
        "High-Core Validation Operator Report",
        "hcvs-failed",
        "fixture_failed",
        "hcvs-skipped",
        "worker_unavailable",
        "RCH_FORCE_REMOTE=true",
    ] {
        assert!(
            markdown.contains(required),
            "markdown report missing {required}"
        );
    }
    Ok(())
}

#[test]
fn operator_report_is_deterministic() -> TestResult {
    let merge = synthetic_merge_report();
    let cost = synthetic_cost_report();
    let run_a = run_report("hcvs-operator-stable-a", &merge, &cost)?;
    let run_b = run_report("hcvs-operator-stable-b", &merge, &cost)?;
    assert_success(&run_a.output)?;
    assert_success(&run_b.output)?;
    assert_eq!(
        load_json(&run_a.json_report)?,
        load_json(&run_b.json_report)?
    );
    Ok(())
}

#[test]
fn operator_report_emits_structured_event_log() -> TestResult {
    let run = run_report(
        "hcvs-operator-event",
        &synthetic_merge_report(),
        &synthetic_cost_report(),
    )?;
    assert_success(&run.output)?;
    let event_body = std::fs::read_to_string(&run.event_log)
        .map_err(|err| test_error(format!("read {} failed: {err}", run.event_log.display())))?;
    let event: Value = serde_json::from_str(event_body.trim())
        .map_err(|err| test_error(format!("event log row should parse: {err}")))?;
    assert_eq!(event["event"].as_str(), Some("operator_report_generated"));
    assert_eq!(event["failed_unit_count"].as_u64(), Some(1));
    assert_eq!(event["skipped_unit_count"].as_u64(), Some(1));
    Ok(())
}
