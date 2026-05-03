//! Integration test: tracker-health report gate (bd-bp8fl.2.3)
//!
//! The gate makes DB, bv, and dashboard degradation explicit so JSONL-visible
//! work is not mistaken for backlog exhaustion.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "bead",
    "generated_at_utc",
    "trace_id",
    "source_commit",
    "status",
    "scenario_count",
    "scenario_results",
    "summary",
    "artifact_refs",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "command",
    "exit_status",
    "duration_ms",
    "tracker_state",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_STATES: &[&str] = &["healthy", "tracker_failure", "tool_timeout", "split_brain"];

const REQUIRED_DISCREPANCIES: &[&str] = &[
    "db_jsonl_count_mismatch",
    "exact_id_split_brain",
    "timeout",
    "stale_blocked_cache",
    "already_shipped_but_open",
    "conflicting_ready_lists",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .parent()
        .ok_or_else(|| test_error("crate manifest should have a crates/ parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have a workspace parent"))?
        .to_path_buf();
    Ok(root)
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_temp_dir(prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_artifact() -> TestResult<serde_json::Value> {
    load_json(&workspace_root()?.join("tests/conformance/tracker_health_report.v1.json"))
}

#[test]
fn artifact_defines_report_and_log_contracts() -> TestResult {
    let artifact = load_artifact()?;
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.2.3"));
    assert_eq!(
        artifact["source_of_truth_policy"]["primary"].as_str(),
        Some("br --no-db list --status open --json")
    );

    let report_fields: Vec<_> = artifact["required_report_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_report_fields should be array"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_report_fields values should be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(report_fields, REQUIRED_REPORT_FIELDS);

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_log_fields should be array"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields values should be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
    Ok(())
}

#[test]
fn scenarios_cover_tracker_failure_modes() -> TestResult {
    let artifact = load_artifact()?;
    let scenarios = artifact["scenarios"]
        .as_array()
        .ok_or_else(|| test_error("scenarios should be array"))?;
    assert!(scenarios.len() >= 5);

    let states: HashSet<_> = scenarios
        .iter()
        .filter_map(|scenario| scenario["expected_tracker_state"].as_str())
        .collect();
    for state in REQUIRED_STATES {
        assert!(states.contains(state), "missing state {state}");
    }

    let mut discrepancies = HashSet::new();
    for scenario in scenarios {
        let snapshot = &scenario["snapshot"];
        if snapshot["jsonl_records"] != snapshot["db_records"] {
            discrepancies.insert("db_jsonl_count_mismatch");
        }
        if snapshot["exact_id_split_brain"].as_bool() == Some(true) {
            discrepancies.insert("exact_id_split_brain");
        }
        if snapshot["stale_blocked_cache"].as_bool() == Some(true) {
            discrepancies.insert("stale_blocked_cache");
        }
        if snapshot["already_shipped_but_open"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
        {
            discrepancies.insert("already_shipped_but_open");
        }
        for command in scenario["commands"]
            .as_array()
            .ok_or_else(|| test_error("scenario commands should be array"))?
        {
            match command["failure_signature"].as_str() {
                Some("timeout") => {
                    discrepancies.insert("timeout");
                }
                Some("conflicting_ready_lists") => {
                    discrepancies.insert("conflicting_ready_lists");
                }
                _ => {}
            }
        }
    }

    for discrepancy in REQUIRED_DISCREPANCIES {
        assert!(
            discrepancies.contains(discrepancy),
            "missing discrepancy {discrepancy}"
        );
    }
    Ok(())
}

#[test]
fn fixture_replay_emits_report_and_structured_logs() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("tracker-health-report")?;
    let report = temp.join("tracker_health_report.report.json");
    let log = temp.join("tracker_health_report.log.jsonl");

    let output = Command::new(root.join("scripts/check_tracker_health_report.sh"))
        .arg("--fixture-replay")
        .current_dir(&root)
        .env("FRANKENLIBC_TRACKER_HEALTH_TARGET_DIR", &temp)
        .env("FRANKENLIBC_TRACKER_HEALTH_REPORT", &report)
        .env("FRANKENLIBC_TRACKER_HEALTH_LOG", &log)
        .output()?;

    assert!(
        output.status.success(),
        "tracker-health gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["scenario_count"].as_u64(), Some(5));
    assert_eq!(
        report_json["summary"]["open_work_visible_in_degraded_modes"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report_json["summary"]["tool_failures_are_not_code_failures"].as_bool(),
        Some(true)
    );

    let log_content = std::fs::read_to_string(&log)?;
    let rows: Vec<serde_json::Value> = log_content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(rows.len() >= 8);

    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-bp8fl.2.3"));
    }

    let signatures: HashSet<_> = rows
        .iter()
        .filter_map(|row| row["failure_signature"].as_str())
        .collect();
    assert!(signatures.contains("stale_blocked_cache"));
    assert!(signatures.contains("zero_ready_nonzero_open"));
    assert!(signatures.contains("timeout"));
    assert!(signatures.contains("exact_id_split_brain"));
    Ok(())
}
