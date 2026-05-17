//! Deterministic high-core validation shard merge gate (bd-31d38).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_PATH: &str = "tests/conformance/high_core_validation_shards.v1.json";
const PLANNER_SCRIPT: &str = "scripts/plan_high_core_validation_shards.sh";
const MERGE_SCRIPT: &str = "scripts/merge_high_core_validation_shards.sh";

#[derive(Clone, Debug)]
struct PlannedUnit {
    unit_id: String,
    shard_id: String,
    command_template: Vec<String>,
    required_artifacts: Vec<String>,
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

fn assert_success(output: &Output) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(test_error(format!(
            "command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn run_planner(lane_count: usize, label: &str) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let plan = dir.join("shard_plan.report.json");
    let log = dir.join("events.log.jsonl");
    let output = Command::new("bash")
        .arg(root.join(PLANNER_SCRIPT))
        .env(
            "HIGH_CORE_VALIDATION_SHARD_MANIFEST",
            committed_manifest_path()?,
        )
        .env("HIGH_CORE_VALIDATION_SHARD_PLAN", &plan)
        .env("HIGH_CORE_VALIDATION_SHARD_LOG", &log)
        .env("HIGH_CORE_VALIDATION_SHARD_LANES", lane_count.to_string())
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("failed to run shard planner: {err}")))?;
    assert_success(&output)?;
    Ok(plan)
}

fn run_merge(
    plan: &Path,
    inputs: &[PathBuf],
    label: &str,
) -> TestResult<(PathBuf, PathBuf, Output)> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let report = dir.join("merge.report.json");
    let log = dir.join("merge.log.jsonl");
    let input_list = inputs
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(":");
    let output = Command::new("bash")
        .arg(root.join(MERGE_SCRIPT))
        .env("HIGH_CORE_VALIDATION_SHARD_PLAN", plan)
        .env("HIGH_CORE_VALIDATION_RESULT_INPUTS", input_list)
        .env("HIGH_CORE_VALIDATION_MERGE_REPORT", &report)
        .env("HIGH_CORE_VALIDATION_MERGE_LOG", &log)
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("failed to run shard merger: {err}")))?;
    Ok((report, log, output))
}

fn string_array(value: &Value, context: &str) -> TestResult<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context} entries must be strings")))
        })
        .collect()
}

fn planned_units(plan: &Value) -> TestResult<Vec<PlannedUnit>> {
    let lanes = plan["lanes"]
        .as_array()
        .ok_or_else(|| test_error("plan.lanes must be array"))?;
    let mut units = Vec::new();
    for lane in lanes {
        let shard_id = lane["shard_id"]
            .as_str()
            .ok_or_else(|| test_error("lane.shard_id missing"))?
            .to_owned();
        let lane_units = lane["units"]
            .as_array()
            .ok_or_else(|| test_error("lane.units must be array"))?;
        for unit in lane_units {
            units.push(PlannedUnit {
                unit_id: unit["unit_id"]
                    .as_str()
                    .ok_or_else(|| test_error("unit_id missing"))?
                    .to_owned(),
                shard_id: shard_id.clone(),
                command_template: string_array(&unit["command_template"], "command_template")?,
                required_artifacts: string_array(
                    &unit["required_artifacts"],
                    "required_artifacts",
                )?,
            });
        }
    }
    units.sort_by(|left, right| {
        left.unit_id
            .cmp(&right.unit_id)
            .then_with(|| left.shard_id.cmp(&right.shard_id))
    });
    Ok(units)
}

fn result_for(
    unit: &PlannedUnit,
    status: &str,
    exit_code: i64,
    failure_signature: Option<&str>,
) -> Value {
    json!({
        "run_id": format!("run-{}-{}", unit.unit_id, unit.shard_id),
        "unit_id": unit.unit_id,
        "shard_id": unit.shard_id,
        "command_template": unit.command_template,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": 125,
        "artifact_refs": unit.required_artifacts,
        "failure_signature": failure_signature.unwrap_or(""),
    })
}

fn write_results(label: &str, rows: &[Value]) -> TestResult<PathBuf> {
    let dir = unique_temp_dir(label)?;
    let path = dir.join("results.jsonl");
    write_jsonl(&path, rows)?;
    Ok(path)
}

fn assert_failure_signature(report: &Value, expected: &str) -> TestResult {
    let signatures = report["failure_signatures"]
        .as_array()
        .ok_or_else(|| test_error("failure_signatures must be array"))?;
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

#[test]
fn merge_happy_path_is_stable_and_ordered() -> TestResult {
    let plan_path = run_planner(8, "hcvs-merge-plan-happy")?;
    let plan = load_json(&plan_path)?;
    let units = planned_units(&plan)?;
    let mut rows = units
        .iter()
        .rev()
        .map(|unit| result_for(unit, "passed", 0, None))
        .collect::<Vec<_>>();
    let midpoint = rows.len() / 2;
    let second_half = rows.split_off(midpoint);
    let input_a = write_results("hcvs-merge-happy-a", &rows)?;
    let input_b = write_results("hcvs-merge-happy-b", &second_half)?;

    let (report_a_path, log_a_path, output_a) = run_merge(
        &plan_path,
        &[input_b.clone(), input_a.clone()],
        "hcvs-merge-a",
    )?;
    let (report_b_path, _log_b_path, output_b) =
        run_merge(&plan_path, &[input_a, input_b], "hcvs-merge-b")?;
    assert_success(&output_a)?;
    assert_success(&output_b)?;

    let report_a = load_json(&report_a_path)?;
    let report_b = load_json(&report_b_path)?;
    assert_eq!(
        report_a, report_b,
        "merge output must not depend on input order"
    );
    assert_eq!(report_a["status"].as_str(), Some("passed"));
    assert_eq!(
        report_a["summary"]["planned_unit_count"].as_u64(),
        Some(units.len() as u64)
    );
    assert_eq!(report_a["summary"]["failure_index_count"].as_u64(), Some(0));

    let result_keys = report_a["results"]
        .as_array()
        .ok_or_else(|| test_error("results must be array"))?
        .iter()
        .map(|row| {
            Ok((
                row["unit_id"]
                    .as_str()
                    .ok_or_else(|| test_error("result unit_id missing"))?
                    .to_owned(),
                row["shard_id"]
                    .as_str()
                    .ok_or_else(|| test_error("result shard_id missing"))?
                    .to_owned(),
            ))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut sorted = result_keys.clone();
    sorted.sort();
    assert_eq!(result_keys, sorted, "results must be stable sorted");

    let log_body = std::fs::read_to_string(&log_a_path)
        .map_err(|err| test_error(format!("read {} failed: {err}", log_a_path.display())))?;
    assert!(
        log_body.contains("\"event\": \"merge_summary\"")
            || log_body.contains("\"event\":\"merge_summary\""),
        "merge_summary event is required"
    );
    Ok(())
}

#[test]
fn merge_emits_compact_failure_index_for_failed_unit() -> TestResult {
    let plan_path = run_planner(4, "hcvs-merge-plan-failure")?;
    let plan = load_json(&plan_path)?;
    let units = planned_units(&plan)?;
    let mut rows = units
        .iter()
        .map(|unit| result_for(unit, "passed", 0, None))
        .collect::<Vec<_>>();
    rows[0] = result_for(&units[0], "failed", 17, Some("fixture_failed"));
    let input = write_results("hcvs-merge-failure", &rows)?;
    let (report_path, _log_path, output) = run_merge(&plan_path, &[input], "hcvs-merge-fail")?;
    assert!(
        !output.status.success(),
        "merge unexpectedly passed with failed unit"
    );
    let report = load_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("failed"));
    let failures = report["failure_index"]
        .as_array()
        .ok_or_else(|| test_error("failure_index must be array"))?;
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0]["unit_id"].as_str(),
        Some(units[0].unit_id.as_str())
    );
    assert_eq!(
        failures[0]["failure_signature"].as_str(),
        Some("fixture_failed")
    );
    assert!(
        failures[0]["reproduction_command"].as_str().is_some(),
        "failure index must include reproduction_command"
    );
    assert!(
        failures[0]["first_failing_artifact"].as_str().is_some(),
        "failure index must name first_failing_artifact"
    );
    Ok(())
}

#[test]
fn merge_fails_closed_when_planned_unit_has_no_result() -> TestResult {
    let plan_path = run_planner(4, "hcvs-merge-plan-missing")?;
    let plan = load_json(&plan_path)?;
    let units = planned_units(&plan)?;
    let rows = units
        .iter()
        .take(units.len() - 1)
        .map(|unit| result_for(unit, "passed", 0, None))
        .collect::<Vec<_>>();
    let input = write_results("hcvs-merge-missing", &rows)?;
    let (report_path, _log_path, output) = run_merge(&plan_path, &[input], "hcvs-merge-missing")?;
    assert!(
        !output.status.success(),
        "merge unexpectedly passed with missing result"
    );
    let report = load_json(&report_path)?;
    assert_failure_signature(&report, "missing_result")?;
    assert_eq!(report["summary"]["missing_result_count"].as_u64(), Some(1));
    Ok(())
}

#[test]
fn merge_fails_closed_on_unplanned_result() -> TestResult {
    let plan_path = run_planner(4, "hcvs-merge-plan-unplanned")?;
    let plan = load_json(&plan_path)?;
    let units = planned_units(&plan)?;
    let mut rows = units
        .iter()
        .map(|unit| result_for(unit, "passed", 0, None))
        .collect::<Vec<_>>();
    rows.push(json!({
        "run_id": "run-unplanned",
        "unit_id": "hcvs-not-in-plan",
        "shard_id": "shard-99",
        "command_template": ["env", "RCH_FORCE_REMOTE=true", "rch", "--no-self-healing", "exec", "--", "cargo", "test"],
        "status": "passed",
        "exit_code": 0,
        "duration_ms": 1,
        "artifact_refs": [],
        "failure_signature": "",
    }));
    let input = write_results("hcvs-merge-unplanned", &rows)?;
    let (report_path, _log_path, output) = run_merge(&plan_path, &[input], "hcvs-merge-unplanned")?;
    assert!(
        !output.status.success(),
        "merge unexpectedly passed with unplanned result"
    );
    let report = load_json(&report_path)?;
    assert_failure_signature(&report, "unplanned_result")?;
    assert_eq!(
        report["summary"]["unplanned_result_count"].as_u64(),
        Some(1)
    );
    Ok(())
}

#[test]
fn merge_fails_closed_on_duplicate_result_disagreement() -> TestResult {
    let plan_path = run_planner(4, "hcvs-merge-plan-duplicate")?;
    let plan = load_json(&plan_path)?;
    let units = planned_units(&plan)?;
    let mut rows = units
        .iter()
        .map(|unit| result_for(unit, "passed", 0, None))
        .collect::<Vec<_>>();
    rows.push(result_for(
        &units[0],
        "failed",
        2,
        Some("duplicate_disagrees"),
    ));
    let input = write_results("hcvs-merge-duplicate", &rows)?;
    let (report_path, _log_path, output) = run_merge(&plan_path, &[input], "hcvs-merge-duplicate")?;
    assert!(
        !output.status.success(),
        "merge unexpectedly passed with disagreeing duplicate"
    );
    let report = load_json(&report_path)?;
    assert_failure_signature(&report, "duplicate_result_disagreement")?;
    assert_eq!(
        report["summary"]["duplicate_disagreement_count"].as_u64(),
        Some(1)
    );
    Ok(())
}

#[test]
fn merge_fails_closed_on_malformed_jsonl_row() -> TestResult {
    let plan_path = run_planner(4, "hcvs-merge-plan-malformed")?;
    let dir = unique_temp_dir("hcvs-merge-malformed")?;
    let input = dir.join("bad.jsonl");
    std::fs::write(&input, "{not-json\n")
        .map_err(|err| test_error(format!("write {} failed: {err}", input.display())))?;
    let (report_path, _log_path, output) = run_merge(&plan_path, &[input], "hcvs-merge-malformed")?;
    assert!(
        !output.status.success(),
        "merge unexpectedly passed with malformed JSONL"
    );
    let report = load_json(&report_path)?;
    assert_failure_signature(&report, "malformed_jsonl")
}

#[test]
fn merge_result_set_matches_planned_units_exactly() -> TestResult {
    let plan_path = run_planner(8, "hcvs-merge-plan-coverage")?;
    let plan = load_json(&plan_path)?;
    let units = planned_units(&plan)?;
    let rows = units
        .iter()
        .map(|unit| result_for(unit, "passed", 0, None))
        .collect::<Vec<_>>();
    let input = write_results("hcvs-merge-coverage", &rows)?;
    let (report_path, _log_path, output) = run_merge(&plan_path, &[input], "hcvs-merge-coverage")?;
    assert_success(&output)?;
    let report = load_json(&report_path)?;
    let planned = units
        .iter()
        .map(|unit| format!("{}/{}", unit.unit_id, unit.shard_id))
        .collect::<BTreeSet<_>>();
    let merged = report["results"]
        .as_array()
        .ok_or_else(|| test_error("results must be array"))?
        .iter()
        .map(|row| {
            Ok(format!(
                "{}/{}",
                row["unit_id"]
                    .as_str()
                    .ok_or_else(|| test_error("result unit_id missing"))?,
                row["shard_id"]
                    .as_str()
                    .ok_or_else(|| test_error("result shard_id missing"))?
            ))
        })
        .collect::<TestResult<BTreeSet<_>>>()?;
    assert_eq!(merged, planned);
    Ok(())
}
