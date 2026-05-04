//! Integration test: workspace validation dashboard gate (bd-bp8fl.7.3)
//!
//! The dashboard must keep broad fmt/check/clippy/test status visible without
//! turning unrelated or stale validation failures into a green workspace claim.

use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_RECORD_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "command",
    "exit_status",
    "validation_scope",
    "owner",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_SCOPES: &[&str] = &[
    "workspace-fmt",
    "workspace-check",
    "workspace-clippy",
    "workspace-test",
    "changed-surface-ubs",
    "br-bv-health",
];

const REQUIRED_SCENARIO_CLASSES: &[&str] = &[
    "clean",
    "unrelated_failure",
    "bead_owned_failure",
    "stale_report",
    "timeout",
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

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn artifact() -> TestResult<Value> {
    load_json(&workspace_root()?.join("tests/conformance/workspace_validation_dashboard.v1.json"))
}

#[test]
fn artifact_declares_validation_dashboard_contract() -> TestResult {
    let doc = artifact()?;
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-bp8fl.7.3"));
    assert_eq!(
        doc["trace_id"].as_str(),
        Some("bd-bp8fl-7-3-workspace-validation-dashboard-v1")
    );

    let fields: Vec<_> = doc["required_record_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_record_fields should be array"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_record_fields values should be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(fields, REQUIRED_RECORD_FIELDS);

    let scopes: HashSet<_> = doc["dashboard_records"]
        .as_array()
        .ok_or_else(|| test_error("dashboard_records should be array"))?
        .iter()
        .filter_map(|record| record["validation_scope"].as_str())
        .collect();
    for scope in REQUIRED_SCOPES {
        assert!(scopes.contains(scope), "missing validation scope {scope}");
    }
    Ok(())
}

#[test]
fn dashboard_preserves_current_failures_and_passes() -> TestResult {
    let doc = artifact()?;
    let records = doc["dashboard_records"]
        .as_array()
        .ok_or_else(|| test_error("dashboard_records should be array"))?;

    assert!(
        records
            .iter()
            .any(|record| record["status"].as_str() == Some("fail")),
        "dashboard should preserve current failure rows"
    );
    assert!(
        records
            .iter()
            .any(|record| record["status"].as_str() == Some("pass")),
        "dashboard should preserve current passing rows"
    );
    assert!(
        records.iter().any(|record| {
            record["validation_scope"].as_str() == Some("workspace-clippy")
                && record["status"].as_str() == Some("pass")
        }),
        "workspace clippy pass should be explicit"
    );
    assert!(
        records.iter().any(|record| {
            record["validation_scope"].as_str() == Some("workspace-fmt")
                && record["failure_signature"].as_str() == Some("rustfmt_drift_set_mismatch")
        }),
        "workspace fmt mismatch should be explicit"
    );
    Ok(())
}

#[test]
fn failure_ledger_names_unrelated_stale_and_not_run_states() -> TestResult {
    let doc = artifact()?;
    let ledger = doc["failure_ledger"]
        .as_array()
        .ok_or_else(|| test_error("failure_ledger should be array"))?;
    let classes: HashSet<_> = ledger
        .iter()
        .filter_map(|entry| entry["classification"].as_str())
        .collect();

    for class in ["unrelated_failure", "stale_report", "not_run"] {
        assert!(classes.contains(class), "missing failure class {class}");
    }
    assert!(ledger.iter().any(|entry| {
        entry["file_path"].as_str()
            == Some("crates/frankenlibc-harness/tests/runtime_evidence_replay_gate_test.rs")
    }));
    Ok(())
}

#[test]
fn fixture_scenarios_cover_clean_degraded_failed_and_inconclusive_paths() -> TestResult {
    let doc = artifact()?;
    let scenarios = doc["fixture_replay_scenarios"]
        .as_array()
        .ok_or_else(|| test_error("fixture_replay_scenarios should be array"))?;
    let classes: HashSet<_> = scenarios
        .iter()
        .filter_map(|scenario| scenario["classification"].as_str())
        .collect();

    for class in REQUIRED_SCENARIO_CLASSES {
        assert!(classes.contains(class), "missing scenario class {class}");
    }
    Ok(())
}

#[test]
fn gate_script_emits_report_and_structured_log() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_output_dir(&root, "workspace-validation-dashboard")?;
    let report = temp.join("workspace_validation_dashboard.report.json");
    let log = temp.join("workspace_validation_dashboard.log.jsonl");

    let output = Command::new(root.join("scripts/check_workspace_validation_dashboard.sh"))
        .current_dir(&root)
        .env("FRANKENLIBC_WORKSPACE_VALIDATION_TARGET_DIR", &temp)
        .env("FRANKENLIBC_WORKSPACE_VALIDATION_REPORT", &report)
        .env("FRANKENLIBC_WORKSPACE_VALIDATION_LOG", &log)
        .output()?;

    assert!(
        output.status.success(),
        "workspace validation dashboard gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["current_gate_state"].as_str(), Some("degraded"));
    assert_eq!(report_json["dashboard_record_count"].as_u64(), Some(6));
    assert_eq!(report_json["failure_ledger_count"].as_u64(), Some(3));

    let log_content = std::fs::read_to_string(&log)?;
    let rows: Vec<Value> = log_content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(rows.len() >= 9);

    for row in &rows {
        for field in REQUIRED_RECORD_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
    }
    assert!(
        rows.iter()
            .any(|row| { row["failure_signature"].as_str() == Some("rustfmt_drift_set_mismatch") })
    );
    assert!(rows.iter().any(|row| {
        row["failure_signature"].as_str() == Some("workspace_test_sweep_not_refreshed")
    }));
    Ok(())
}
