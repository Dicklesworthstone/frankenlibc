use frankenlibc_harness::runtime_evidence_verifier::{
    RuntimeEvidenceExpectation, RuntimeEvidenceVerifierConfig, verify_runtime_evidence_jsonl,
};
use frankenlibc_membrane::runtime_math::evidence::RUNTIME_EVIDENCE_JSONL_SCHEMA_V1;
use serde_json::{Value, json};

const CURRENT_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn verifier_config() -> RuntimeEvidenceVerifierConfig {
    RuntimeEvidenceVerifierConfig::new(CURRENT_COMMIT)
}

fn runtime_row(mode: &str, action: &str, timestamp_mono_ns: u64) -> Value {
    let decision_path = match action {
        "Allow" => "mode->runtime_math_kernel->allow",
        "FullValidate" => "mode->runtime_math_kernel->full_validate",
        "Repair" => "mode->runtime_math_kernel->repair",
        "Deny" => "mode->runtime_math_kernel->deny",
        _ => "mode->runtime_math_kernel->unknown",
    };
    let healing_action = if action == "Repair" {
        json!("ReturnSafeDefault")
    } else {
        Value::Null
    };
    json!({
        "schema": RUNTIME_EVIDENCE_JSONL_SCHEMA_V1,
        "schema_version": "1.0",
        "timestamp": "2026-05-04T15:55:00.000Z",
        "timestamp_mono_ns": timestamp_mono_ns,
        "trace_id": format!("runtime-test::{mode}::{timestamp_mono_ns}"),
        "bead_id": "bd-b92jd.4.2",
        "scenario_id": "verifier-test",
        "level": if action == "Deny" { "error" } else { "info" },
        "event": "runtime_evidence",
        "controller_id": "runtime_math_kernel.v1",
        "decision_id": timestamp_mono_ns,
        "policy_id": 7,
        "evidence_seqno": timestamp_mono_ns,
        "mode": mode,
        "runtime_mode": mode,
        "validation_profile": if action == "Allow" { "Fast" } else { "Full" },
        "decision_path": decision_path,
        "decision_action": action,
        "healing_action": healing_action,
        "denied": action == "Deny",
        "latency_ns": 17,
        "api_family": "allocator",
        "symbol": "runtime_math::allocator",
        "source_commit": CURRENT_COMMIT,
        "context": {
            "addr_hint_redacted": true,
            "requested_bytes": 64,
            "is_write": true,
            "contention_hint": 0,
            "bloom_negative": false
        },
        "artifact_refs": ["crates/frankenlibc-membrane/src/runtime_math/evidence.rs"]
    })
}

fn jsonl(rows: &[Value]) -> String {
    let mut out = String::new();
    for row in rows {
        out.push_str(&serde_json::to_string(row).expect("fixture row serializes"));
        out.push('\n');
    }
    out
}

fn assert_signature(row: Value, signature: &str) {
    let report = verify_runtime_evidence_jsonl(&jsonl(&[row]), &verifier_config());
    assert!(!report.passed(), "negative fixture should fail");
    assert!(
        report.has_failure_signature(signature),
        "expected {signature}, got {:#?}",
        report.failures
    );
}

#[test]
fn verifier_accepts_valid_runtime_evidence_jsonl_and_report_json() {
    let rows = [
        runtime_row("strict", "Allow", 10),
        runtime_row("hardened", "Repair", 20),
    ];
    let config = verifier_config()
        .with_expectation(RuntimeEvidenceExpectation::new(
            "runtime_math::allocator",
            "strict",
            "Allow",
            false,
        ))
        .with_expectation(RuntimeEvidenceExpectation::new(
            "runtime_math::allocator",
            "hardened",
            "Repair",
            false,
        ));

    let report = verify_runtime_evidence_jsonl(&jsonl(&rows), &config);
    assert!(report.passed(), "{report:#?}");
    assert_eq!(report.total_rows, 2);
    assert_eq!(report.observed_expectations.len(), 2);

    let json = report.to_json().expect("report serializes");
    let parsed: Value = serde_json::from_str(&json).expect("report JSON parses");
    assert_eq!(
        parsed["schema"].as_str(),
        Some("runtime_evidence_verifier.v1")
    );
    assert_eq!(parsed["status"].as_str(), Some("pass"));
}

#[test]
fn verifier_fails_closed_for_corrupt_jsonl_fixture() {
    let report = verify_runtime_evidence_jsonl("{not-json}\n", &verifier_config());
    assert!(!report.passed());
    assert!(report.has_failure_signature("runtime_evidence_corrupt_jsonl"));
}

#[test]
fn verifier_fails_closed_for_stale_source_commit_fixture() {
    let mut row = runtime_row("strict", "Allow", 10);
    row["source_commit"] = json!("ffffffffffffffffffffffffffffffffffffffff");
    assert_signature(row, "runtime_evidence_stale_source_commit");
}

#[test]
fn verifier_fails_closed_for_invalid_mode_and_latency_fixtures() {
    let mut invalid_mode = runtime_row("strict", "Allow", 10);
    invalid_mode["runtime_mode"] = json!("repair");
    assert_signature(invalid_mode, "runtime_evidence_invalid_mode");

    let mut invalid_latency = runtime_row("strict", "Allow", 10);
    invalid_latency["latency_ns"] = json!("17ms");
    assert_signature(invalid_latency, "runtime_evidence_invalid_latency");
}

#[test]
fn verifier_fails_closed_for_impossible_transition_fixture() {
    let mut row = runtime_row("strict", "Allow", 10);
    row["decision_path"] = json!("mode->runtime_math_kernel->deny");
    assert_signature(row, "runtime_evidence_impossible_transition");
}

#[test]
fn verifier_fails_closed_for_missing_repair_healing_action_fixture() {
    let mut row = runtime_row("hardened", "Repair", 10);
    row["healing_action"] = Value::Null;
    assert_signature(row, "runtime_evidence_missing_healing_action");
}

#[test]
fn verifier_fails_closed_for_unexpected_denial_fixture() {
    let row = runtime_row("hardened", "Deny", 10);
    let config = verifier_config().deny_unexpected_denials();
    let report = verify_runtime_evidence_jsonl(&jsonl(&[row]), &config);
    assert!(!report.passed());
    assert!(report.has_failure_signature("runtime_evidence_unexpected_denial"));
}

#[test]
fn verifier_fails_closed_for_out_of_order_timestamp_fixture() {
    let rows = [
        runtime_row("strict", "Allow", 20),
        runtime_row("hardened", "Repair", 10),
    ];
    let report = verify_runtime_evidence_jsonl(&jsonl(&rows), &verifier_config());
    assert!(!report.passed());
    assert!(report.has_failure_signature("runtime_evidence_out_of_order_timestamp"));
}
