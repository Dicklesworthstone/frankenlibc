//! Integration test: architecture TODO reconciliation gate.
//!
//! Validates:
//! 1) the report-only reconciliation artifact covers every TODO/NEXT ledger row.
//! 2) the checker script emits structured report/log artifacts.
//! 3) the checker fails deterministically on count drift, missing row mappings,
//!    and unknown target bead references.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_script() -> MutexGuard<'static, ()> {
    script_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("jsonl should be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl row should parse"))
        .collect()
}

fn write_mutation(root: &Path, name: &str, value: &serde_json::Value) -> PathBuf {
    let path = root.join("target/conformance").join(format!(
        "architecture_todo_reconciliation_{name}_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path
}

fn assert_failure_outputs(root: &Path, expected_signature: &str) {
    let report_path = root.join("target/conformance/architecture_todo_reconciliation.report.json");
    let log_path = root.join("target/conformance/architecture_todo_reconciliation.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some(expected_signature)
    );
    for key in [
        "trace_id",
        "todo_id",
        "evidence_ref",
        "br_issue_ref",
        "classification",
        "failure_signature",
    ] {
        assert!(report.get(key).is_some(), "failure report missing {key}");
    }

    let log_rows = load_jsonl(&log_path);
    let event = log_rows
        .iter()
        .find(|row| row["event"].as_str() == Some("architecture_todo_reconciliation_failed"))
        .expect("failure log row should be present");
    assert_eq!(event["outcome"].as_str(), Some("fail"));
    assert_eq!(
        event["failure_signature"].as_str(),
        Some(expected_signature)
    );
    for key in [
        "trace_id",
        "todo_id",
        "evidence_ref",
        "br_issue_ref",
        "classification",
        "failure_signature",
    ] {
        assert!(event.get(key).is_some(), "failure log row missing {key}");
    }
}

fn run_checker(root: &Path, artifact: Option<&Path>) -> std::process::Output {
    let script = root.join("scripts/check_architecture_todo_reconciliation.sh");
    let mut command = Command::new(&script);
    command.current_dir(root);
    if let Some(path) = artifact {
        command.env("ARCH_TODO_RECONCILIATION_ARTIFACT", path);
    }
    command
        .output()
        .expect("failed to run architecture TODO reconciliation checker")
}

#[test]
fn artifact_has_required_report_only_shape() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );
    let artifact = load_json(&artifact_path);

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("architecture_todo_reconciliation.v1")
    );
    assert_eq!(artifact["generated_by_bead"].as_str(), Some("bd-0agsk.1"));
    assert_eq!(artifact["claim_status"].as_str(), Some("report_only"));
    assert_eq!(
        artifact["promotion_policy"]["replacement_level_change"].as_str(),
        Some("forbidden")
    );
    assert_eq!(
        artifact["source_ledger_policy"]["status"].as_str(),
        Some("archived_historical_snapshot")
    );
    let archive_tokens = artifact["source_ledger_policy"]["archive_notice_required_tokens"]
        .as_array()
        .expect("archive notice tokens");
    assert!(
        archive_tokens
            .iter()
            .any(|token| token.as_str() == Some("Archived historical investigation ledger")),
        "archive notice must require the historical-ledger marker"
    );

    let counts = &artifact["ledger_counts"];
    let row_count = counts["row_count"].as_u64().expect("row_count");
    let completed = counts["status_completed"].as_u64().expect("completed");
    let pending = counts["status_pending"].as_u64().expect("pending");
    let in_progress = counts["status_in_progress"].as_u64().expect("in_progress");
    assert_eq!(
        row_count,
        completed + pending + in_progress,
        "ledger counts must be self-consistent"
    );

    let mapped_count: usize = artifact["row_mappings"]
        .as_array()
        .expect("row_mappings array")
        .iter()
        .map(|row| row["ids"].as_array().expect("ids array").len())
        .sum();
    assert_eq!(
        row_count as usize, mapped_count,
        "row mappings must cover every ledger row"
    );
}

#[test]
fn completion_debt_evidence_binds_conformance_and_telemetry_items() {
    let artifact_path =
        workspace_root().join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let artifact = load_json(&artifact_path);
    let evidence = &artifact["completion_debt_evidence"];

    assert_eq!(evidence["bead"].as_str(), Some("bd-0agsk.2.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-0agsk.2"));
    assert_eq!(
        evidence["test_source"].as_str(),
        Some("crates/frankenlibc-harness/tests/architecture_todo_reconciliation_test.rs")
    );

    let conformance_tests: HashSet<_> = evidence["conformance_primary"]["required_test_names"]
        .as_array()
        .expect("conformance test names should be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("conformance test name should be string")
        })
        .collect();
    assert_eq!(
        conformance_tests,
        HashSet::from([
            "artifact_has_required_report_only_shape",
            "checker_passes_and_emits_report_and_log",
            "checker_fails_on_row_count_drift",
            "checker_fails_on_completed_row_claiming_open_route",
            "checker_fails_on_unsupported_done_row_without_evidence",
            "checker_fails_when_ledger_mapping_is_missing",
            "checker_fails_when_scan_finding_target_bead_is_unknown",
            "completion_debt_evidence_resolves_original_close_reason_wording",
            "checker_fails_when_close_reason_wording_resolution_drifts",
        ])
    );

    let telemetry_events: HashSet<_> = evidence["telemetry_primary"]["required_events"]
        .as_array()
        .expect("telemetry events should be an array")
        .iter()
        .map(|value| value.as_str().expect("telemetry event should be string"))
        .collect();
    assert_eq!(
        telemetry_events,
        HashSet::from([
            "architecture_todo_reconciliation_validated",
            "architecture_todo_reconciliation_row_validated",
            "architecture_todo_reconciliation_failed",
        ])
    );

    let telemetry_fields: HashSet<_> = evidence["telemetry_primary"]["required_fields"]
        .as_array()
        .expect("telemetry fields should be an array")
        .iter()
        .map(|value| value.as_str().expect("telemetry field should be string"))
        .collect();
    for field in [
        "timestamp",
        "trace_id",
        "level",
        "event",
        "bead_id",
        "artifact_refs",
        "outcome",
        "duration_ms",
        "details",
        "failure_signature",
        "todo_id",
        "evidence_ref",
        "br_issue_ref",
        "classification",
        "completion_debt_bead",
        "original_bead",
    ] {
        assert!(
            telemetry_fields.contains(field),
            "telemetry evidence missing required field {field}"
        );
    }
}

#[test]
fn completion_debt_evidence_resolves_original_close_reason_wording() {
    let artifact_path =
        workspace_root().join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let artifact = load_json(&artifact_path);
    let wording = &artifact["completion_debt_evidence"]["close_reason_wording_resolution"];

    assert_eq!(
        wording["status"].as_str(),
        Some("resolved_by_structured_evidence")
    );
    assert_eq!(wording["blocked_bead"].as_str(), Some("bd-0agsk.2"));
    assert_eq!(wording["completion_bead"].as_str(), Some("bd-0agsk.2.1"));

    let flagged_terms: HashSet<_> = wording["flagged_terms"]
        .as_array()
        .expect("flagged_terms should be an array")
        .iter()
        .map(|value| value.as_str().expect("flagged term should be string"))
        .collect();
    assert_eq!(flagged_terms, HashSet::from(["TODO"]));

    let allowed_contexts = wording["allowed_contexts"]
        .as_array()
        .expect("allowed_contexts should be an array");
    assert!(
        allowed_contexts.len() >= 3,
        "wording resolution should list the accepted contexts"
    );

    let required_report_fields: HashSet<_> = wording["required_report_fields"]
        .as_array()
        .expect("required_report_fields should be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("required report field should be string")
        })
        .collect();
    assert_eq!(
        required_report_fields,
        HashSet::from([
            "completion_debt_bead",
            "original_bead",
            "close_reason_wording_resolution",
        ])
    );
}

#[test]
fn checker_passes_and_emits_report_and_log() {
    let _guard = lock_script();
    let root = workspace_root();
    let script = root.join("scripts/check_architecture_todo_reconciliation.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_architecture_todo_reconciliation.sh must be executable"
        );
    }

    let output = run_checker(&root, None);
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/architecture_todo_reconciliation.report.json");
    let log_path = root.join("target/conformance/architecture_todo_reconciliation.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(
        report["schema_version"].as_str(),
        Some("architecture_todo_reconciliation.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.2.1"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-0agsk.2.1")
    );
    assert_eq!(report["original_bead"].as_str(), Some("bd-0agsk.2"));
    assert_eq!(
        report["close_reason_wording_resolution"]["status"].as_str(),
        Some("resolved_by_structured_evidence")
    );
    for check in [
        "schema_valid",
        "ledger_rows_exhaustive",
        "ledger_counts_consistent",
        "classification_counts_consistent",
        "target_beads_known",
        "promotion_policy_report_only",
        "source_ledger_archived",
        "completion_debt_evidence_bound",
        "close_reason_wording_resolution_bound",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }
    assert_eq!(report["summary"]["row_count"].as_u64(), Some(73));
    assert_eq!(report["summary"]["mapped_rows"].as_u64(), Some(73));
    let row_events = report["row_events"].as_array().expect("row_events array");
    assert_eq!(row_events.len(), 73);
    let todo_row = row_events
        .iter()
        .find(|row| row["todo_id"].as_str() == Some("TODO-0102"))
        .expect("TODO-0102 row event should be present");
    for key in [
        "trace_id",
        "todo_id",
        "evidence_ref",
        "br_issue_ref",
        "classification",
        "failure_signature",
    ] {
        assert!(todo_row.get(key).is_some(), "row event missing {key}");
    }

    let log_rows = load_jsonl(&log_path);
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let artifact = load_json(&artifact_path);
    let required_fields: Vec<_> =
        artifact["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
            .as_array()
            .expect("required telemetry fields")
            .iter()
            .map(|value| value.as_str().expect("required telemetry field"))
            .collect();
    let event = log_rows
        .iter()
        .find(|row| row["event"].as_str() == Some("architecture_todo_reconciliation_validated"))
        .expect("summary log row should be present");
    for key in &required_fields {
        assert!(event.get(key).is_some(), "log row missing {key}");
    }
    let row_log = log_rows
        .iter()
        .find(|row| row["event"].as_str() == Some("architecture_todo_reconciliation_row_validated"))
        .expect("row log should be present");
    for key in &required_fields {
        assert!(row_log.get(key).is_some(), "row log missing {key}");
    }
}

#[test]
fn checker_fails_on_row_count_drift() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    artifact["ledger_counts"]["row_count"] = serde_json::Value::from(999_u64);
    let mutation_path = write_mutation(&root, "row_count_drift", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail on row_count drift"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("row_count_mismatch") || stderr.contains("row_count_arithmetic"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn checker_fails_when_archive_notice_is_not_in_ledger() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    artifact["source_ledger_policy"]["archive_notice_required_tokens"] =
        serde_json::json!(["definitely missing archive notice token"]);
    let mutation_path = write_mutation(&root, "missing_archive_notice", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail when the archive notice token is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("source_ledger_archive_notice_missing"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "source_ledger_archive_notice_missing");
}

#[test]
fn checker_fails_on_completed_row_claiming_open_route() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    let closed = artifact["row_mappings"]
        .as_array_mut()
        .expect("row_mappings must be array")
        .iter_mut()
        .find(|row| {
            row["ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some("TODO-0102")))
        })
        .expect("TODO-0102 closed mapping should exist");
    closed["live_classification"] = serde_json::Value::from("routed_to_new_open_bead");
    closed["target_beads"] = serde_json::json!(["bd-0agsk.3"]);
    let mutation_path = write_mutation(&root, "completed_claiming_open_route", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail when a completed row claims an open route"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("routed_mapping_status_mismatch"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "routed_mapping_status_mismatch");
}

#[test]
fn checker_fails_on_unsupported_done_row_without_evidence() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    let closed = artifact["row_mappings"]
        .as_array_mut()
        .expect("row_mappings must be array")
        .iter_mut()
        .find(|row| {
            row["ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some("TODO-0001")))
        })
        .expect("TODO-0001 closed mapping should exist");
    closed["evidence_refs"] = serde_json::json!([]);
    let mutation_path = write_mutation(&root, "unsupported_done_without_evidence", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail when a done row has no evidence"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("closed_mapping_missing_evidence"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "closed_mapping_missing_evidence");
}

#[test]
fn checker_fails_when_ledger_mapping_is_missing() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    let first_mapping = artifact["row_mappings"][0]
        .as_object_mut()
        .expect("first row mapping must be object");
    let ids = first_mapping
        .get_mut("ids")
        .and_then(|value| value.as_array_mut())
        .expect("ids must be array");
    ids.retain(|value| value.as_str() != Some("TODO-0001"));
    let mutation_path = write_mutation(&root, "missing_mapping", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail when a ledger mapping is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ledger_id_set_mismatch"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn checker_fails_when_scan_finding_target_bead_is_unknown() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    let finding = artifact["scan_findings"]
        .as_array_mut()
        .expect("scan_findings must be array")
        .iter_mut()
        .find(|row| row["kind"].as_str() == Some("placeholder_fixture_output_comment"))
        .expect("expected placeholder scan finding");
    finding["target_beads"] = serde_json::json!(["bd-unknown-target"]);
    let mutation_path = write_mutation(&root, "unknown_target", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail when a target bead is unknown"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("scan_finding_unknown_target"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn checker_fails_when_completion_debt_telemetry_binding_drifts() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    let fields = artifact["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .expect("telemetry required_fields should exist");
    fields.retain(|field| field.as_str() != Some("br_issue_ref"));
    let mutation_path = write_mutation(&root, "completion_debt_telemetry_drift", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail when completion-debt telemetry binding drifts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completion_debt_telemetry_missing_field"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "completion_debt_telemetry_missing_field");
}

#[test]
fn checker_fails_when_close_reason_wording_resolution_drifts() {
    let _guard = lock_script();
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/architecture_todo_reconciliation.v1.json");
    let mut artifact = load_json(&artifact_path);
    artifact["completion_debt_evidence"]["close_reason_wording_resolution"]["status"] =
        serde_json::Value::from("unresolved");
    let mutation_path = write_mutation(&root, "close_reason_wording_resolution_drift", &artifact);

    let output = run_checker(&root, Some(&mutation_path));
    assert!(
        !output.status.success(),
        "checker should fail when close-reason wording resolution drifts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completion_debt_close_reason_wording_status"),
        "unexpected stderr: {stderr}"
    );
    assert_failure_outputs(&root, "completion_debt_close_reason_wording_status");
}
