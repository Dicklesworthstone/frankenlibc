//! Integration test: crypt dashboard reconciliation gate (bd-bp8fl.2.4)
//!
//! The gate keeps the historical crypt divergence visible when tracker or
//! dashboard state claims zero open work without current parity evidence.

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
    "crypt_issue_id",
    "source",
    "expected_state",
    "actual_state",
    "dashboard_state",
    "tracker_state",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REQUIRED_STATES: &[&str] = &[
    "crypt_gap_visible",
    "reconciled_closed",
    "crypt_gap_untracked",
    "stale_evidence",
    "duplicate_conflict",
    "exact_id_split_brain",
];

const REQUIRED_FAILURE_SIGNATURES: &[&str] = &[
    "ok",
    "dashboard_zero_open_with_open_crypt_gap",
    "missing_crypt_issue_record",
    "stale_crypt_evidence",
    "duplicate_crypt_issue_rows",
    "exact_id_lookup_failure",
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

fn field<'a>(value: &'a serde_json::Value, name: &str) -> TestResult<&'a serde_json::Value> {
    value
        .get(name)
        .ok_or_else(|| test_error(format!("missing JSON field {name}")))
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
    load_json(&workspace_root()?.join("tests/conformance/crypt_dashboard_reconciliation.v1.json"))
}

#[test]
fn artifact_defines_crypt_reconciliation_contract() -> TestResult {
    let artifact = load_artifact()?;
    assert_eq!(field(&artifact, "schema_version")?.as_str(), Some("v1"));
    assert_eq!(field(&artifact, "bead")?.as_str(), Some("bd-bp8fl.2.4"));
    assert_eq!(
        field(&artifact, "crypt_issue_id")?.as_str(),
        Some("bd-fd42da")
    );
    let source_policy = field(&artifact, "source_of_truth_policy")?;
    assert_eq!(
        field(source_policy, "primary_open_rows")?.as_str(),
        Some("br --no-db list --status open --json")
    );
    assert_eq!(
        field(source_policy, "named_crypt_row")?.as_str(),
        Some("br --no-db show bd-fd42da --json")
    );

    let report_fields: Vec<_> = field(&artifact, "required_report_fields")?
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

    let log_fields: Vec<_> = field(&artifact, "required_log_fields")?
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
fn scenarios_cover_reconciliation_branches() -> TestResult {
    let artifact = load_artifact()?;
    let scenarios = field(&artifact, "scenarios")?
        .as_array()
        .ok_or_else(|| test_error("scenarios should be array"))?;
    assert_eq!(scenarios.len(), 6);

    let mut states = HashSet::new();
    let mut signatures = HashSet::new();
    for scenario in scenarios {
        states.insert(
            field(scenario, "expected_state")?
                .as_str()
                .ok_or_else(|| test_error("expected_state should be string"))?,
        );
        signatures.insert(
            field(scenario, "expected_failure_signature")?
                .as_str()
                .ok_or_else(|| test_error("expected_failure_signature should be string"))?,
        );
    }
    for state in REQUIRED_STATES {
        assert!(states.contains(state), "missing state {state}");
    }

    for signature in REQUIRED_FAILURE_SIGNATURES {
        assert!(
            signatures.contains(signature),
            "missing signature {signature}"
        );
    }

    let mut covers_zero_open_block = false;
    let mut covers_current_parity_closure = false;
    for scenario in scenarios {
        covers_zero_open_block |= field(scenario, "expected_dashboard_state")?.as_str()
            == Some("contradictory_zero_open")
            && field(scenario, "expected_tracker_state")?.as_str() == Some("tracker_failure");
        let inputs = field(scenario, "inputs")?;
        covers_current_parity_closure |= field(scenario, "expected_state")?.as_str()
            == Some("reconciled_closed")
            && field(inputs, "crypt_divergence_count")?.as_u64() == Some(0)
            && field(inputs, "evidence_current")?.as_bool() == Some(true);
    }
    assert!(covers_zero_open_block);
    assert!(covers_current_parity_closure);
    Ok(())
}

#[test]
fn fixture_replay_emits_report_and_structured_logs() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("crypt-dashboard-reconciliation")?;
    let report = temp.join("crypt_dashboard_reconciliation.report.json");
    let log = temp.join("crypt_dashboard_reconciliation.log.jsonl");

    let output = Command::new(root.join("scripts/check_crypt_dashboard_reconciliation.sh"))
        .arg("--fixture-replay")
        .current_dir(&root)
        .env("FRANKENLIBC_CRYPT_DASHBOARD_TARGET_DIR", &temp)
        .env("FRANKENLIBC_CRYPT_DASHBOARD_REPORT", &report)
        .env("FRANKENLIBC_CRYPT_DASHBOARD_LOG", &log)
        .output()?;

    assert!(
        output.status.success(),
        "crypt dashboard reconciliation gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(field(&report_json, "status")?.as_str(), Some("pass"));
    assert_eq!(field(&report_json, "scenario_count")?.as_u64(), Some(6));
    let summary = field(&report_json, "summary")?;
    assert_eq!(
        field(summary, "zero_open_dashboard_blocked_for_known_crypt_gap")?.as_bool(),
        Some(true)
    );
    assert_eq!(
        field(summary, "current_parity_required_before_closure")?.as_bool(),
        Some(true)
    );
    assert_eq!(
        field(summary, "stale_or_missing_evidence_fails_closed")?.as_bool(),
        Some(true)
    );

    let log_content = std::fs::read_to_string(&log)?;
    let rows: Vec<serde_json::Value> = log_content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 6);

    for row in &rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
        assert_eq!(field(row, "bead_id")?.as_str(), Some("bd-bp8fl.2.4"));
        assert_eq!(field(row, "crypt_issue_id")?.as_str(), Some("bd-fd42da"));
    }

    let mut signatures = HashSet::new();
    for row in &rows {
        signatures.insert(
            field(row, "failure_signature")?
                .as_str()
                .ok_or_else(|| test_error("failure_signature should be string"))?,
        );
    }
    assert!(signatures.contains("dashboard_zero_open_with_open_crypt_gap"));
    assert!(signatures.contains("missing_crypt_issue_record"));
    assert!(signatures.contains("stale_crypt_evidence"));
    assert!(signatures.contains("duplicate_crypt_issue_rows"));
    assert!(signatures.contains("exact_id_lookup_failure"));
    Ok(())
}
