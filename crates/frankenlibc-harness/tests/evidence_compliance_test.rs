//! Integration tests: evidence compliance gate (bd-33p.3)
//!
//! Validates:
//! 1. Index completeness + structured-log schema checks pass on valid bundles.
//! 2. Failure events without `artifact_refs` fail deterministically.
//! 3. Schema defects produce actionable `log.schema_violation` diagnostics.
//! 4. CLI triage output includes violation_code/offending_event/expected_fields/remediation_hint.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_harness::evidence_compliance::validate_evidence_bundle;
use frankenlibc_harness::structured_log::{ArtifactIndex, LogEntry, LogLevel, Outcome, StreamKind};
use sha2::Digest;

fn unique_tmp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read artifact for sha");
    let digest = sha2::Sha256::digest(&bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_valid_index(run_dir: &Path, artifact_rel: &str, run_id: &str, bead_id: &str) -> PathBuf {
    let artifact_path = run_dir.join(artifact_rel);
    std::fs::write(&artifact_path, "diagnostic-bytes").expect("write artifact");
    let sha = sha256_hex(&artifact_path);

    let mut index = ArtifactIndex::new(run_id, bead_id);
    index.add(artifact_rel, "diagnostic", sha);
    let index_path = run_dir.join("artifact_index.json");
    std::fs::write(&index_path, index.to_json().expect("serialize index")).expect("write index");
    index_path
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let body = std::fs::read_to_string(path).expect("jsonl file should be readable");
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl line should parse"))
        .collect()
}

fn write_legacy_index(run_dir: &Path, artifact_rel: &str, bead_id: &str) -> PathBuf {
    let artifact_path = run_dir.join(artifact_rel);
    std::fs::write(&artifact_path, "legacy-diagnostic-bytes").expect("write legacy artifact");
    let sha = sha256_hex(&artifact_path);
    let index_path = run_dir.join("artifact_index.json");
    let legacy = serde_json::json!({
        "index_version": 1,
        "bead_id": bead_id,
        "generated_utc": "2026-02-11T00:00:00.000Z",
        "artifacts": [
            {
                "path": artifact_rel,
                "kind": "diagnostic",
                "sha256": sha,
                "join_keys": {
                    "trace_id": format!("{bead_id}::legacy-run::001"),
                    "decision_id": 9,
                    "policy_id": 3,
                    "evidence_seqno": 77
                }
            }
        ]
    });
    std::fs::write(
        &index_path,
        serde_json::to_string_pretty(&legacy).expect("serialize legacy index"),
    )
    .expect("write legacy index");
    index_path
}

#[test]
fn valid_bundle_passes() {
    let run_dir = unique_tmp_dir("evidence-compliance-valid");
    let log_path = run_dir.join("log.jsonl");
    let index_path = write_valid_index(&run_dir, "diag.txt", "run-valid", "bd-33p.3");

    let line = LogEntry::new("bd-33p.3::run-valid::001", LogLevel::Info, "gate_result")
        .with_stream(StreamKind::Release)
        .with_gate("evidence_compliance")
        .with_outcome(Outcome::Pass)
        .with_artifacts(vec!["diag.txt".to_string()])
        .to_jsonl()
        .expect("serialize log entry");
    std::fs::write(&log_path, format!("{line}\n")).expect("write log");

    let report = validate_evidence_bundle(&run_dir, &log_path, &index_path);
    assert!(report.ok, "valid evidence bundle should pass: {report:?}");
    assert!(
        report.violations.is_empty(),
        "valid evidence bundle should have no violations"
    );

    let _ = std::fs::remove_dir_all(run_dir);
}

#[test]
fn legacy_index_without_run_id_still_passes_and_emits_migration_warning() {
    let run_dir = unique_tmp_dir("evidence-compliance-legacy-index");
    let log_path = run_dir.join("log.jsonl");
    let index_path = write_legacy_index(&run_dir, "diag.txt", "bd-33p.3");

    let line = LogEntry::new("bd-33p.3::legacy-run::001", LogLevel::Info, "gate_result")
        .with_stream(StreamKind::Release)
        .with_gate("evidence_compliance")
        .with_outcome(Outcome::Pass)
        .with_artifacts(vec!["diag.txt".to_string()])
        .to_jsonl()
        .expect("serialize log entry");
    std::fs::write(&log_path, format!("{line}\n")).expect("write log");

    let report = validate_evidence_bundle(&run_dir, &log_path, &index_path);
    assert!(report.ok, "legacy v1 index should still pass: {report:?}");

    let proof_log_path = run_dir.join("evidence_compliance.proof.log.jsonl");
    let events = read_jsonl(&proof_log_path);
    assert!(
        events.iter().any(|entry| entry["event"].as_str()
            == Some("evidence_compliance.artifact_index_legacy_defaults")
            && entry["level"].as_str() == Some("warn")),
        "proof log should record legacy-index migration defaults"
    );

    let _ = std::fs::remove_dir_all(run_dir);
}

#[test]
fn failure_event_without_artifacts_fails_deterministically() {
    let run_dir = unique_tmp_dir("evidence-compliance-missing-refs");
    let log_path = run_dir.join("log.jsonl");
    let index_path = write_valid_index(&run_dir, "diag.txt", "run-fail", "bd-33p.3");

    let line = LogEntry::new("bd-33p.3::run-fail::001", LogLevel::Error, "test_failure")
        .with_stream(StreamKind::E2e)
        .with_gate("e2e_suite")
        .with_outcome(Outcome::Fail)
        .to_jsonl()
        .expect("serialize log entry");
    std::fs::write(&log_path, format!("{line}\n")).expect("write log");

    let report = validate_evidence_bundle(&run_dir, &log_path, &index_path);
    assert!(
        !report.ok,
        "bundle should fail when failure refs are missing"
    );
    let found = report
        .violations
        .iter()
        .find(|v| v.code == "failure_event.missing_artifact_refs")
        .expect("expected failure_event.missing_artifact_refs");
    assert!(
        found
            .remediation_hint
            .as_deref()
            .is_some_and(|h| h.contains("artifact_refs")),
        "remediation_hint should mention artifact_refs"
    );

    let _ = std::fs::remove_dir_all(run_dir);
}

#[test]
fn malformed_log_line_reports_schema_violation() {
    let run_dir = unique_tmp_dir("evidence-compliance-schema");
    let log_path = run_dir.join("log.jsonl");
    let index_path = write_valid_index(&run_dir, "diag.txt", "run-schema", "bd-33p.3");

    std::fs::write(&log_path, "{}\n").expect("write malformed log line");

    let report = validate_evidence_bundle(&run_dir, &log_path, &index_path);
    assert!(!report.ok, "malformed log line should fail compliance");

    let violations: Vec<_> = report
        .violations
        .iter()
        .filter(|v| v.code == "log.schema_violation")
        .collect();
    assert!(
        !violations.is_empty(),
        "expected at least one log.schema_violation entry"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.message.contains("required field missing")),
        "schema violation should include missing required field diagnostics"
    );

    let _ = std::fs::remove_dir_all(run_dir);
}

#[test]
fn ambition_evidence_row_passes_with_full_contract() {
    let run_dir = unique_tmp_dir("evidence-compliance-ambition-full");
    let log_path = run_dir.join("log.jsonl");
    let index_path = write_valid_index(&run_dir, "diag.txt", "run-ambition", "bd-bp8fl.7.5");

    let line = LogEntry::new(
        "bd-bp8fl.7.5::run-ambition::001",
        LogLevel::Info,
        "ambition_evidence",
    )
    .with_bead("bd-bp8fl.7.5")
    .with_stream(StreamKind::E2e)
    .with_gate("ambition_evidence")
    .with_scenario_id("full-contract-positive")
    .with_runtime_mode("strict")
    .with_replacement_level("L0")
    .with_api("evidence", "structured_log")
    .with_oracle_kind("unit")
    .with_expected_actual(
        serde_json::json!({"required_fields":"present"}),
        serde_json::json!({"required_fields":"present"}),
    )
    .with_errno(0)
    .with_decision_path("schema->validator->pass")
    .with_healing_action("None")
    .with_latency_ns(1)
    .with_source_commit("0123456789abcdef")
    .with_target_dir("target/rch/bd-bp8fl.7.5")
    .with_failure_signature("none")
    .with_outcome(Outcome::Pass)
    .with_artifacts(vec!["diag.txt".to_string()])
    .to_jsonl()
    .expect("serialize ambition evidence row");
    std::fs::write(&log_path, format!("{line}\n")).expect("write log");

    let report = validate_evidence_bundle(&run_dir, &log_path, &index_path);
    assert!(
        report.ok,
        "complete ambition evidence row should pass bundle validation: {report:?}"
    );

    let _ = std::fs::remove_dir_all(run_dir);
}

#[test]
fn ambition_evidence_missing_runtime_mode_fails_deterministically() {
    let run_dir = unique_tmp_dir("evidence-compliance-ambition-missing-mode");
    let log_path = run_dir.join("log.jsonl");
    let index_path = write_valid_index(
        &run_dir,
        "diag.txt",
        "run-ambition-missing-mode",
        "bd-bp8fl.7.5",
    );

    let line = serde_json::json!({
        "timestamp": "2026-05-01T00:00:00.000Z",
        "trace_id": "bd-bp8fl.7.5::run-ambition-missing-mode::001",
        "level": "info",
        "event": "ambition_evidence",
        "bead_id": "bd-bp8fl.7.5",
        "stream": "e2e",
        "gate": "ambition_evidence",
        "scenario_id": "missing-runtime-mode",
        "mode": "strict",
        "replacement_level": "L0",
        "api_family": "evidence",
        "symbol": "structured_log",
        "oracle_kind": "unit",
        "expected": {"required_fields": "present"},
        "actual": {"required_fields": "present"},
        "errno": 0,
        "decision_path": "schema->validator->fail",
        "healing_action": "None",
        "latency_ns": 1,
        "source_commit": "0123456789abcdef",
        "target_dir": "target/rch/bd-bp8fl.7.5",
        "failure_signature": "none",
        "outcome": "pass",
        "artifact_refs": ["diag.txt"]
    });
    std::fs::write(&log_path, format!("{line}\n")).expect("write log");

    let report = validate_evidence_bundle(&run_dir, &log_path, &index_path);
    assert!(
        !report.ok,
        "missing runtime_mode must fail ambition evidence validation"
    );
    assert!(
        report.violations.iter().any(|v| {
            v.code == "log.schema_violation"
                && v.remediation_hint
                    .as_deref()
                    .is_some_and(|hint| hint.contains("runtime_mode"))
        }),
        "schema violation should point at runtime_mode: {report:?}"
    );

    let _ = std::fs::remove_dir_all(run_dir);
}

#[test]
fn hash_mismatch_emits_debug_and_error_proof_logs() {
    let run_dir = unique_tmp_dir("evidence-compliance-hash-mismatch");
    let log_path = run_dir.join("log.jsonl");
    let artifact_rel = "diag.txt";
    let artifact_path = run_dir.join(artifact_rel);
    std::fs::write(&artifact_path, "artifact-content").expect("write artifact");

    let mut index = ArtifactIndex::new("run-hash-mismatch", "bd-34s.7");
    index.add(
        artifact_rel,
        "diagnostic",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let index_path = run_dir.join("artifact_index.json");
    std::fs::write(&index_path, index.to_json().expect("serialize index")).expect("write index");

    let line = LogEntry::new(
        "bd-34s.7::run-hash-mismatch::001",
        LogLevel::Info,
        "proof_input",
    )
    .with_stream(StreamKind::Release)
    .with_gate("evidence_compliance")
    .with_outcome(Outcome::Pass)
    .with_artifacts(vec![artifact_rel.to_string()])
    .to_jsonl()
    .expect("serialize log entry");
    std::fs::write(&log_path, format!("{line}\n")).expect("write log");

    let report = validate_evidence_bundle(&run_dir, &log_path, &index_path);
    assert!(!report.ok, "hash mismatch should fail compliance");
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.code == "artifact_index.sha_mismatch"),
        "expected artifact_index.sha_mismatch violation"
    );

    let proof_log_path = run_dir.join("evidence_compliance.proof.log.jsonl");
    assert!(
        proof_log_path.exists(),
        "proof log sidecar should be emitted for evidence compliance runs"
    );
    let events = read_jsonl(&proof_log_path);
    assert!(
        events.iter().any(|entry| entry["event"].as_str()
            == Some("evidence_compliance.artifact_hash_compute")
            && entry["level"].as_str() == Some("debug")),
        "proof log should include DEBUG hash-compute events"
    );
    assert!(
        events.iter().any(|entry| entry["event"].as_str()
            == Some("evidence_compliance.artifact_hash_mismatch")
            && entry["level"].as_str() == Some("error")),
        "proof log should include ERROR hash-mismatch events"
    );
    assert!(
        events
            .iter()
            .any(|entry| entry["event"].as_str() == Some("evidence_compliance.proof_summary")),
        "proof log should include summary event"
    );

    let _ = std::fs::remove_dir_all(run_dir);
}

#[test]
fn cli_emits_triage_format_with_required_fields() {
    let run_dir = unique_tmp_dir("evidence-compliance-cli");
    let log_path = run_dir.join("log.jsonl");
    let index_path = write_valid_index(&run_dir, "diag.txt", "run-cli", "bd-33p.3");

    let line = LogEntry::new("bd-33p.3::run-cli::001", LogLevel::Error, "test_failure")
        .with_stream(StreamKind::E2e)
        .with_gate("e2e_suite")
        .with_outcome(Outcome::Fail)
        .with_artifacts(vec!["missing.txt".to_string()])
        .to_jsonl()
        .expect("serialize log entry");
    std::fs::write(&log_path, format!("{line}\n")).expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .arg("evidence-compliance")
        .arg("--workspace-root")
        .arg(&run_dir)
        .arg("--log")
        .arg(&log_path)
        .arg("--artifact-index")
        .arg(&index_path)
        .output()
        .expect("harness evidence-compliance should execute");

    assert!(
        !output.status.success(),
        "bad evidence bundle should return non-zero"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let triage: serde_json::Value =
        serde_json::from_str(&stdout).expect("CLI should emit JSON triage report");
    assert_eq!(triage["ok"].as_bool(), Some(false));
    assert!(
        triage["violation_count"].as_u64().unwrap_or(0) > 0,
        "expected non-zero violation_count"
    );

    let violations = triage["violations"]
        .as_array()
        .expect("violations should be an array");
    assert!(!violations.is_empty(), "violations must not be empty");

    let first = &violations[0];
    for key in [
        "violation_code",
        "offending_event",
        "expected_fields",
        "remediation_hint",
        "artifact_pointer",
    ] {
        assert!(
            first.get(key).is_some(),
            "triage violation is missing required key '{key}'"
        );
    }

    let _ = std::fs::remove_dir_all(run_dir);
}
