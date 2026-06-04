//! Contract tests for bd-bp8fl.2.2.1 reality bridge import completion evidence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

fn manifest() -> TestResult<Value> {
    load_json(
        &workspace_root()?
            .join("tests/conformance/reality_bridge_import_completion_contract.v1.json"),
    )
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

fn json_string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| test_error("expected JSON array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        let text = item
            .as_str()
            .ok_or_else(|| test_error("expected JSON string"))?;
        set.insert(text.to_string());
    }
    Ok(set)
}

#[test]
fn manifest_binds_reality_bridge_completion_evidence() -> TestResult {
    let doc = manifest()?;
    assert_eq!(
        doc["schema_version"].as_str(),
        Some("reality_bridge_import_completion_contract.v1")
    );
    assert_eq!(
        doc["manifest_id"].as_str(),
        Some("bd-bp8fl.2.2.1-reality-bridge-import-completion-contract")
    );
    assert_eq!(doc["bead"].as_str(), Some("bd-bp8fl.2.2"));

    let evidence = &doc["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-bp8fl.2.2.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-bp8fl.2.2"));

    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("conformance_primary", "tests.conformance.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        assert_eq!(
            evidence[section]["missing_item_id"].as_str(),
            Some(missing_item),
            "{section} should bind {missing_item}"
        );
    }

    let artifacts = json_string_set(&evidence["conformance_primary"]["required_artifacts"])?;
    for artifact in [
        "tests/conformance/reality_bridge_import_reconciliation.v1.json",
        "tests/conformance/reality_check_bridge_backlog.v1.json",
        "tests/conformance/feature_parity_gap_ledger.v1.json",
        "tests/conformance/feature_parity_gap_bead_coverage.v1.json",
    ] {
        assert!(artifacts.contains(artifact), "missing artifact {artifact}");
    }

    let counts = &evidence["conformance_primary"]["required_counts"];
    assert_eq!(counts["backlog_source_rows"].as_u64(), Some(10));
    assert_eq!(counts["feature_ledger_rows"].as_u64(), Some(170));
    assert_eq!(counts["feature_gap_import_rows"].as_u64(), Some(110));
    assert_eq!(counts["unique_target_issue_count"].as_u64(), Some(64));
    assert_eq!(counts["lost_feature_gap_count"].as_u64(), Some(0));

    let telemetry_fields = json_string_set(&evidence["telemetry_primary"]["required_fields"])?;
    for field in [
        "trace_id",
        "event",
        "completion_debt_bead",
        "original_bead",
        "source_commit",
        "missing_items_bound",
        "artifact_refs",
        "feature_gap_import_rows",
        "failure_signature",
    ] {
        assert!(
            telemetry_fields.contains(field),
            "telemetry should require field {field}"
        );
    }
    Ok(())
}

#[test]
fn checker_emits_completion_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("reality-bridge-import-completion")?;
    let report = temp.join("reality_bridge_import_completion_contract.report.json");
    let log = temp.join("reality_bridge_import_completion_contract.log.jsonl");

    let output =
        Command::new(root.join("scripts/check_reality_bridge_import_completion_contract.sh"))
            .current_dir(&root)
            .env(
                "FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_REPORT",
                &report,
            )
            .env("FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_LOG", &log)
            .output()?;

    assert!(
        output.status.success(),
        "completion checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(
        report_json["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.2.2.1")
    );
    assert_eq!(report_json["original_bead"].as_str(), Some("bd-bp8fl.2.2"));
    assert_eq!(
        report_json["required_counts"]["feature_gap_import_rows"].as_u64(),
        Some(110)
    );
    assert_eq!(
        report_json["required_counts"]["unique_target_issue_count"].as_u64(),
        Some(64)
    );

    let log_content = std::fs::read_to_string(&log)?;
    let log_row: Value = serde_json::from_str(
        log_content
            .lines()
            .next()
            .ok_or_else(|| test_error("completion log should contain one row"))?,
    )?;
    assert_eq!(
        log_row["event"].as_str(),
        Some("reality_bridge_import_completion_contract_validated")
    );
    assert_eq!(
        log_row["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.2.2.1")
    );
    assert_eq!(log_row["feature_gap_import_rows"].as_u64(), Some(110));
    assert!(
        log_row["artifact_refs"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| {
                item.as_str()
                    == Some("tests/conformance/reality_bridge_import_reconciliation.v1.json")
            })),
        "completion log should reference the source reconciliation artifact"
    );
    Ok(())
}

#[test]
fn checker_rejects_lost_feature_gap_binding() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("reality-bridge-import-completion-mutation")?;
    let fixture = temp.join("mutated_reality_bridge_import_completion_contract.json");
    let report = temp.join("mutated.report.json");
    let log = temp.join("mutated.log.jsonl");
    let mut doc = manifest()?;

    doc["completion_debt_evidence"]["conformance_primary"]["required_counts"]["feature_gap_import_rows"] =
        json!(109);
    std::fs::write(&fixture, serde_json::to_string_pretty(&doc)? + "\n")?;

    let output =
        Command::new(root.join("scripts/check_reality_bridge_import_completion_contract.sh"))
            .current_dir(&root)
            .env(
                "FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_CONTRACT",
                &fixture,
            )
            .env(
                "FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_REPORT",
                &report,
            )
            .env("FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_LOG", &log)
            .output()?;

    assert!(
        !output.status.success(),
        "mutated completion contract should fail"
    );
    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .ok_or_else(|| test_error("failure report should include errors"))?;
    assert!(
        errors.iter().any(|message| message
            .as_str()
            .is_some_and(|text| text.contains("feature_gap_import_rows"))),
        "failure report should mention feature_gap_import_rows drift"
    );

    let log_content = std::fs::read_to_string(&log)?;
    let log_row: Value = serde_json::from_str(
        log_content
            .lines()
            .next()
            .ok_or_else(|| test_error("failure log should contain one row"))?,
    )?;
    assert_eq!(
        log_row["event"].as_str(),
        Some("reality_bridge_import_completion_contract_failed")
    );
    assert_eq!(
        log_row["failure_signature"].as_str(),
        Some("reality_bridge_import_completion_contract_failed")
    );
    Ok(())
}
