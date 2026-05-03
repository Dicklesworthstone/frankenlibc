//! Integration test: br/bv disagreement dashboard gate (bd-bp8fl.2.7)
//!
//! The gate ensures dashboard rows keep tracker disagreement actionable instead
//! of translating stale br/bv evidence into backlog exhaustion or code failure.

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
    "dashboard_rows",
    "summary",
    "artifact_refs",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "tracker_run_id",
    "command",
    "exit_status",
    "duration_ms",
    "source",
    "bead_id",
    "discrepancy_type",
    "expected",
    "actual",
    "source_commit",
    "artifact_refs",
    "failure_signature",
];

const REQUIRED_DISCREPANCIES: &[&str] = &[
    "db_jsonl_count_mismatch",
    "exact_id_split_brain",
    "timeout",
    "stale_blocked_cache",
    "already_shipped_but_open_bead",
    "conflicting_ready_lists",
    "cycle_report_disagreement",
    "missing_issue_record",
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
    load_json(&workspace_root()?.join("tests/conformance/br_bv_disagreement_dashboard.v1.json"))
}

#[test]
fn artifact_defines_dashboard_and_log_contracts() -> TestResult {
    let artifact = load_artifact()?;
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.2.7"));
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
fn fixture_scenarios_cover_disagreement_taxonomy() -> TestResult {
    let artifact = load_artifact()?;
    let scenarios = artifact["scenarios"]
        .as_array()
        .ok_or_else(|| test_error("scenarios should be array"))?;
    assert!(scenarios.len() >= 8);

    let mut covered = HashSet::new();
    let mut source_modes = HashSet::new();
    for scenario in scenarios {
        for discrepancy in scenario["expected_discrepancies"]
            .as_array()
            .ok_or_else(|| test_error("expected_discrepancies should be array"))?
        {
            covered.insert(
                discrepancy
                    .as_str()
                    .ok_or_else(|| test_error("discrepancy values should be strings"))?,
            );
        }
        source_modes.insert(
            scenario["expected_current_source_of_truth"]
                .as_str()
                .ok_or_else(|| test_error("source of truth should be string"))?,
        );
    }

    for discrepancy in REQUIRED_DISCREPANCIES {
        assert!(
            covered.contains(discrepancy),
            "missing discrepancy {discrepancy}"
        );
    }
    assert!(source_modes.contains("agreement"));
    assert!(source_modes.contains("br_no_db_jsonl"));
    assert!(source_modes.contains("br_no_db_show"));
    assert!(source_modes.contains("inconclusive"));
    assert!(source_modes.contains("blocked_graph"));
    Ok(())
}

#[test]
fn fixture_replay_emits_dashboard_rows_and_structured_logs() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("br-bv-disagreement-dashboard")?;
    let report = temp.join("br_bv_disagreement_dashboard.report.json");
    let log = temp.join("br_bv_disagreement_dashboard.log.jsonl");

    let output = Command::new(root.join("scripts/check_br_bv_disagreement_dashboard.sh"))
        .arg("--fixture-replay")
        .current_dir(&root)
        .env("FRANKENLIBC_BR_BV_DASHBOARD_TARGET_DIR", &temp)
        .env("FRANKENLIBC_BR_BV_DASHBOARD_REPORT", &report)
        .env("FRANKENLIBC_BR_BV_DASHBOARD_LOG", &log)
        .output()?;

    assert!(
        output.status.success(),
        "br/bv dashboard gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(
        report_json["dashboard_rows"].as_array().map(Vec::len),
        Some(8)
    );
    assert_eq!(
        report_json["summary"]["implementation_may_continue_on_unrelated_jsonl_beads"].as_bool(),
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
    }

    let log_discrepancies: HashSet<_> = rows
        .iter()
        .filter_map(|row| row["discrepancy_type"].as_str())
        .collect();
    assert!(log_discrepancies.contains("conflicting_ready_lists"));
    assert!(log_discrepancies.contains("db_jsonl_count_mismatch"));
    assert!(log_discrepancies.contains("timeout"));
    assert!(log_discrepancies.contains("cycle_report_disagreement"));
    Ok(())
}
