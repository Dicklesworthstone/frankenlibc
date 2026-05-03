//! Integration test: reality-check bridge import reconciliation (bd-bp8fl.2.2)

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NEGATIVE_CASES: &[&str] = &[
    "duplicate_source_row",
    "missing_required_field",
    "stale_source_snapshot",
    "missing_dependency",
    "missing_acceptance",
    "no_feature_loss",
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

fn artifact() -> TestResult<serde_json::Value> {
    load_json(
        &workspace_root()?.join("tests/conformance/reality_bridge_import_reconciliation.v1.json"),
    )
}

#[test]
fn artifact_defines_import_mapping_contract() -> TestResult {
    let doc = artifact()?;
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-bp8fl.2.2"));
    assert_eq!(
        doc["trace_id"].as_str(),
        Some("bd-bp8fl-2-2-reality-bridge-import-v1")
    );
    assert!(
        doc["import_mapping_contract"]["dependency_policy"]
            .as_str()
            .ok_or_else(|| test_error("dependency_policy should be a string"))?
            .contains("bd-bp8fl.3.1")
    );
    assert_eq!(
        doc["import_mapping_contract"]["source_freshness_policy"]["stale_source_snapshots_fail"]
            .as_bool(),
        Some(true)
    );
    Ok(())
}

#[test]
fn backlog_and_feature_gap_rows_are_preserved_without_rejections() -> TestResult {
    let doc = artifact()?;
    let summary = &doc["summary"];
    assert_eq!(summary["backlog_source_rows"].as_u64(), Some(10));
    assert_eq!(summary["backlog_import_rows"].as_u64(), Some(10));
    assert_eq!(summary["feature_ledger_rows"].as_u64(), Some(170));
    assert_eq!(
        summary["feature_ledger_unresolved_gaps"].as_u64(),
        Some(111)
    );
    assert_eq!(summary["feature_gap_import_rows"].as_u64(), Some(111));
    assert_eq!(summary["rejected_row_count"].as_u64(), Some(0));
    assert_eq!(summary["missing_target_issue_count"].as_u64(), Some(0));
    assert_eq!(summary["missing_acceptance_target_count"].as_u64(), Some(0));
    assert_eq!(summary["missing_dependency_count"].as_u64(), Some(0));
    assert_eq!(summary["stale_source_snapshot_count"].as_u64(), Some(0));
    assert_eq!(summary["lost_feature_gap_count"].as_u64(), Some(0));
    assert_eq!(summary["unique_target_issue_count"].as_u64(), Some(64));

    assert_eq!(
        doc["rejected_rows"]
            .as_array()
            .ok_or_else(|| test_error("rejected_rows should be an array"))?
            .len(),
        0
    );

    let mut backlog_ids = HashSet::new();
    for row in doc["backlog_import_rows"]
        .as_array()
        .ok_or_else(|| test_error("backlog_import_rows should be array"))?
    {
        assert_eq!(row["failure_signature"].as_str(), Some("ok"));
        assert_eq!(row["source_freshness"]["state"].as_str(), Some("fresh"));
        assert!(
            row["artifact_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "backlog row should preserve artifact refs"
        );
        let source_row_id = row["source_row_id"]
            .as_str()
            .ok_or_else(|| test_error("source_row_id should be string"))?;
        assert!(backlog_ids.insert(source_row_id.to_string()));
    }
    assert_eq!(backlog_ids.len(), 10);

    let mut gap_ids = HashSet::new();
    for row in doc["feature_gap_import_rows"]
        .as_array()
        .ok_or_else(|| test_error("feature_gap_import_rows should be array"))?
    {
        assert_eq!(row["failure_signature"].as_str(), Some("ok"));
        assert_eq!(row["source_freshness"]["state"].as_str(), Some("fresh"));
        assert!(
            row["missing_dependencies"]
                .as_array()
                .is_some_and(|deps| deps.is_empty()),
            "feature gap target should preserve dependencies"
        );
        let gap_id = row["source_row_id"]
            .as_str()
            .ok_or_else(|| test_error("gap source_row_id should be string"))?;
        assert!(gap_ids.insert(gap_id.to_string()));
    }
    assert_eq!(gap_ids.len(), 111);
    Ok(())
}

#[test]
fn fixture_replay_emits_report_logs_and_negative_cases() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("reality-bridge-import")?;
    let report = temp.join("reality_bridge_import_reconciliation.report.json");
    let log = temp.join("reality_bridge_import_reconciliation.log.jsonl");
    let fixture = temp.join("reality_bridge_import_reconciliation.fixture_tracker.jsonl");

    let output = Command::new(root.join("scripts/check_reality_bridge_import_reconciliation.sh"))
        .arg("--fixture-replay")
        .current_dir(&root)
        .env("FRANKENLIBC_REALITY_BRIDGE_IMPORT_TARGET_DIR", &temp)
        .env("FRANKENLIBC_REALITY_BRIDGE_IMPORT_REPORT", &report)
        .env("FRANKENLIBC_REALITY_BRIDGE_IMPORT_LOG", &log)
        .env(
            "FRANKENLIBC_REALITY_BRIDGE_IMPORT_FIXTURE_TRACKER",
            &fixture,
        )
        // rch mirrors can omit .beads; this test validates artifact replay, while
        // the standalone gate keeps live tracker regeneration strict by default.
        .env("FRANKENLIBC_REALITY_BRIDGE_IMPORT_VERIFY_GENERATOR", "0")
        .output()?;

    assert!(
        output.status.success(),
        "reality bridge import gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(
        report_json["fixture_tracker"]["issue_count"].as_u64(),
        Some(64)
    );
    assert_eq!(report_json["log"]["row_count"].as_u64(), Some(181));

    let cases = report_json["negative_case_results"]
        .as_array()
        .ok_or_else(|| test_error("negative_case_results should be array"))?;
    let observed_cases: HashSet<_> = cases
        .iter()
        .filter_map(|case| case["case_id"].as_str())
        .collect();
    for case_id in NEGATIVE_CASES {
        assert!(
            observed_cases.contains(case_id),
            "missing negative case {case_id}"
        );
    }
    for case in cases {
        assert_eq!(case["status"].as_str(), Some("pass"));
        assert!(
            case["actual_failure_signatures"]
                .as_array()
                .is_some_and(|signatures| !signatures.is_empty()),
            "negative case should emit a failure signature"
        );
    }

    let log_content = std::fs::read_to_string(&log)?;
    let rows: Vec<serde_json::Value> = log_content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 181);
    for row in &rows {
        assert_eq!(
            row["trace_id"].as_str(),
            Some("bd-bp8fl-2-2-reality-bridge-import-v1")
        );
        assert_eq!(row["bead_id"].as_str(), Some("bd-bp8fl.2.2"));
        for field in [
            "import_source",
            "source_row_id",
            "target_issue_id",
            "action",
            "expected",
            "actual",
            "artifact_refs",
            "source_commit",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "missing log field {field}");
        }
    }

    let fixture_lines = std::fs::read_to_string(&fixture)?;
    assert_eq!(fixture_lines.lines().count(), 64);
    Ok(())
}
