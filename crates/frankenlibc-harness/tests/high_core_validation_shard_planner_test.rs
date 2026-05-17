//! Deterministic high-core validation shard planner gate (bd-qa87u).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST_PATH: &str = "tests/conformance/high_core_validation_shards.v1.json";
const PLANNER_SCRIPT: &str = "scripts/plan_high_core_validation_shards.sh";
const SUPPORTED_LANES: &[usize] = &[1, 2, 4, 8, 16, 32, 64];

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

fn run_planner(
    manifest: &Path,
    lane_count: usize,
    label: &str,
) -> TestResult<(PathBuf, PathBuf, Output)> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let plan = dir.join("shard_plan.report.json");
    let log = dir.join("events.log.jsonl");
    let output = Command::new("bash")
        .arg(root.join(PLANNER_SCRIPT))
        .env("HIGH_CORE_VALIDATION_SHARD_MANIFEST", manifest)
        .env("HIGH_CORE_VALIDATION_SHARD_PLAN", &plan)
        .env("HIGH_CORE_VALIDATION_SHARD_LOG", &log)
        .env("HIGH_CORE_VALIDATION_SHARD_LANES", lane_count.to_string())
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("failed to run shard planner: {err}")))?;
    Ok((plan, log, output))
}

fn committed_manifest_path() -> TestResult<PathBuf> {
    Ok(workspace_root()?.join(MANIFEST_PATH))
}

fn load_committed_manifest() -> TestResult<Value> {
    load_json(&committed_manifest_path()?)
}

fn manifest_unit_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    let units = manifest
        .get("units")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("manifest.units must be array"))?;
    units
        .iter()
        .map(|unit| {
            unit.get("unit_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| test_error("unit_id must be string"))
        })
        .collect()
}

fn planned_unit_ids(report: &Value) -> TestResult<BTreeSet<String>> {
    let lanes = report
        .get("lanes")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("report.lanes must be array"))?;
    let mut ids = BTreeSet::new();
    for lane in lanes {
        for unit in lane
            .get("units")
            .and_then(Value::as_array)
            .ok_or_else(|| test_error("lane.units must be array"))?
        {
            let unit_id = unit
                .get("unit_id")
                .and_then(Value::as_str)
                .ok_or_else(|| test_error("planned unit_id must be string"))?;
            if !ids.insert(unit_id.to_owned()) {
                return Err(test_error(format!("duplicate planned unit {unit_id}")));
            }
        }
    }
    Ok(ids)
}

fn log_events(path: &Path) -> TestResult<Vec<Value>> {
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

fn assert_success(output: &Output) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(test_error(format!(
            "planner failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn assert_failure_signature(report: &Value, expected: &str) -> TestResult {
    let signatures = report
        .get("failure_signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("failure report missing failure_signatures"))?;
    if signatures
        .iter()
        .any(|item| item.as_str() == Some(expected))
    {
        Ok(())
    } else {
        Err(test_error(format!(
            "expected failure signature {expected}; report={report:#?}"
        )))
    }
}

fn write_manifest_variant(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut manifest = load_committed_manifest()?;
    mutate(&mut manifest)?;
    let dir = unique_temp_dir(label)?;
    let path = dir.join("high_core_validation_shards.v1.json");
    write_json(&path, &manifest)?;
    Ok(path)
}

#[test]
fn planner_emits_stable_eight_lane_plan() -> TestResult {
    let manifest_path = committed_manifest_path()?;
    let manifest = load_committed_manifest()?;
    let (plan_a, log_a, output_a) = run_planner(&manifest_path, 8, "hcvs-plan-a")?;
    let (plan_b, _log_b, output_b) = run_planner(&manifest_path, 8, "hcvs-plan-b")?;
    assert_success(&output_a)?;
    assert_success(&output_b)?;

    let report_a = load_json(&plan_a)?;
    let report_b = load_json(&plan_b)?;
    assert_eq!(report_a, report_b, "planner output must be deterministic");
    assert_eq!(report_a["schema_version"].as_str(), Some("v1"));
    assert_eq!(report_a["bead"].as_str(), Some("bd-qa87u"));
    assert_eq!(report_a["status"].as_str(), Some("passed"));
    assert_eq!(report_a["summary"]["lane_count"].as_u64(), Some(8));
    assert_eq!(planned_unit_ids(&report_a)?, manifest_unit_ids(&manifest)?);

    let events = log_events(&log_a)?;
    let unit_event_count = events
        .iter()
        .filter(|event| event["event"].as_str() == Some("unit_assigned"))
        .count();
    assert_eq!(
        unit_event_count as u64,
        report_a["summary"]["unit_count"]
            .as_u64()
            .ok_or_else(|| test_error("summary.unit_count missing"))?
    );
    assert!(
        events
            .iter()
            .any(|event| event["event"].as_str() == Some("planner_summary")),
        "planner_summary event is required"
    );
    Ok(())
}

#[test]
fn planner_supports_all_declared_lane_counts_including_sixty_four() -> TestResult {
    let manifest_path = committed_manifest_path()?;
    let manifest = load_committed_manifest()?;
    let expected_ids = manifest_unit_ids(&manifest)?;

    for lane_count in SUPPORTED_LANES {
        let (plan, _log, output) = run_planner(
            &manifest_path,
            *lane_count,
            &format!("hcvs-plan-{lane_count}"),
        )?;
        assert_success(&output)?;
        let report = load_json(&plan)?;
        assert_eq!(
            report["summary"]["lane_count"].as_u64(),
            Some(*lane_count as u64)
        );
        assert_eq!(
            report["lanes"]
                .as_array()
                .ok_or_else(|| test_error("lanes must be array"))?
                .len(),
            *lane_count
        );
        assert_eq!(planned_unit_ids(&report)?, expected_ids);
    }
    Ok(())
}

#[test]
fn planner_cost_balancing_matches_stable_lpt_policy() -> TestResult {
    let manifest_path = committed_manifest_path()?;
    let manifest = load_committed_manifest()?;
    let (plan, _log, output) = run_planner(&manifest_path, 2, "hcvs-balance")?;
    assert_success(&output)?;
    let report = load_json(&plan)?;

    let mut expected_loads = [0u64, 0u64];
    let mut expected_units = [Vec::<String>::new(), Vec::<String>::new()];
    let mut units = manifest["units"]
        .as_array()
        .ok_or_else(|| test_error("manifest.units must be array"))?
        .iter()
        .map(|unit| {
            let unit_id = unit["unit_id"]
                .as_str()
                .ok_or_else(|| test_error("unit_id missing"))?
                .to_owned();
            let cost = unit["estimated_cost"]["cost_points"]
                .as_u64()
                .ok_or_else(|| test_error("cost_points missing"))?;
            Ok((unit_id, cost))
        })
        .collect::<TestResult<Vec<_>>>()?;
    units.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (unit_id, cost) in units {
        let lane = if expected_loads[0] <= expected_loads[1] {
            0
        } else {
            1
        };
        expected_loads[lane] += cost;
        expected_units[lane].push(unit_id);
    }

    let mut actual = BTreeMap::<usize, (u64, Vec<String>)>::new();
    for lane in report["lanes"]
        .as_array()
        .ok_or_else(|| test_error("report.lanes must be array"))?
    {
        let lane_index = lane["lane_index"]
            .as_u64()
            .ok_or_else(|| test_error("lane_index missing"))? as usize;
        let cost = lane["estimated_cost"]["cost_points"]
            .as_u64()
            .ok_or_else(|| test_error("lane cost missing"))?;
        let units = lane["units"]
            .as_array()
            .ok_or_else(|| test_error("lane.units missing"))?
            .iter()
            .map(|unit| {
                unit["unit_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| test_error("planned unit_id missing"))
            })
            .collect::<TestResult<Vec<_>>>()?;
        actual.insert(lane_index, (cost, units));
    }
    for lane in 0..2 {
        let (actual_cost, actual_units) = actual
            .get(&lane)
            .ok_or_else(|| test_error(format!("missing lane {lane}")))?;
        let mut expected_lane_units = expected_units[lane].clone();
        expected_lane_units.sort();
        assert_eq!(*actual_cost, expected_loads[lane]);
        assert_eq!(actual_units, &expected_lane_units);
    }
    Ok(())
}

#[test]
fn planner_rejects_invalid_lane_count() -> TestResult {
    let (plan, _log, output) = run_planner(&committed_manifest_path()?, 3, "hcvs-bad-lanes")?;
    assert!(
        !output.status.success(),
        "unsupported lane count unexpectedly passed"
    );
    let report = load_json(&plan)?;
    assert_failure_signature(&report, "unsupported_lane_count")
}

#[test]
fn planner_rejects_duplicate_unit_ids() -> TestResult {
    let manifest_path = write_manifest_variant("hcvs-duplicate-unit", |manifest| {
        let units = manifest["units"]
            .as_array_mut()
            .ok_or_else(|| test_error("manifest.units must be mutable array"))?;
        let first_id = units[0]["unit_id"]
            .as_str()
            .ok_or_else(|| test_error("first unit_id missing"))?
            .to_owned();
        units[1]["unit_id"] = Value::String(first_id);
        Ok(())
    })?;
    let (plan, _log, output) = run_planner(&manifest_path, 8, "hcvs-duplicate-unit-plan")?;
    assert!(
        !output.status.success(),
        "duplicate unit id unexpectedly passed"
    );
    let report = load_json(&plan)?;
    assert_failure_signature(&report, "duplicate_unit_id")
}
