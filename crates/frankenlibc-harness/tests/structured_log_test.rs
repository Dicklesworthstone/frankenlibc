//! Integration test: structured logging contract (bd-144)
//!
//! Validates that:
//! 1. log_schema.json exists and is well-formed.
//! 2. The Rust structured_log module produces valid JSONL.
//! 3. The validation function catches schema violations.
//! 4. LogEmitter writes correct JSONL to files.
//! 5. ArtifactIndex serializes correctly.
//!
//! Run: cargo test -p frankenlibc-harness --test structured_log_test

use std::path::{Path, PathBuf};

use frankenlibc_harness::report::DecisionTraceReport;
use frankenlibc_harness::structured_log::{
    ArtifactIndex, Decision, LogEmitter, LogEntry, LogLevel, Outcome, StreamKind,
    validate_log_file, validate_log_line,
};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn log_schema_exists_and_valid() {
    let root = workspace_root();
    let schema_path = root.join("tests/conformance/log_schema.json");

    assert!(
        schema_path.exists(),
        "log_schema.json must exist at tests/conformance/"
    );

    let content = std::fs::read_to_string(&schema_path).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(&content).expect("log_schema.json should be valid JSON");

    let schema_version = schema["schema_version"]
        .as_u64()
        .expect("schema_version must be an integer");
    assert!(
        schema_version >= 2,
        "Expected log schema_version >= 2, got {schema_version}"
    );

    // Required top-level keys
    for key in [
        "schema_version",
        "required_fields",
        "optional_fields",
        "artifact_index_schema",
        "examples",
    ] {
        assert!(
            schema[key] != serde_json::Value::Null,
            "Schema missing key: {}",
            key
        );
    }

    // Required fields must include the mandatory four
    let req = schema["required_fields"].as_object().unwrap();
    for field in ["timestamp", "trace_id", "level", "event"] {
        assert!(req.contains_key(field), "Missing required field: {}", field);
    }
}

#[test]
fn schema_examples_validate() {
    let root = workspace_root();
    let content = std::fs::read_to_string(root.join("tests/conformance/log_schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&content).unwrap();

    let examples = schema["examples"].as_object().unwrap();
    for (name, example) in examples {
        // artifact_index is a different schema, skip it
        if name == "artifact_index" {
            continue;
        }
        let json = serde_json::to_string(example).unwrap();
        let result = validate_log_line(&json, 0);
        assert!(
            result.is_ok(),
            "Schema example '{}' should validate: {:?}",
            name,
            result.err()
        );
    }
}

#[test]
fn artifact_index_schema_example_roundtrips() {
    let root = workspace_root();
    let content = std::fs::read_to_string(root.join("tests/conformance/log_schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&content).unwrap();

    let example = schema["examples"]["artifact_index"].clone();
    let parsed: ArtifactIndex = serde_json::from_value(example).expect("artifact index example");
    assert_eq!(parsed.index_version, 1);
    assert_eq!(parsed.run_id, "run-001");
    assert_eq!(parsed.bead_id, "bd-144");
    assert_eq!(parsed.artifacts.len(), 2);

    let join_keys = parsed.artifacts[0]
        .join_keys
        .as_ref()
        .expect("example should include join keys");
    assert_eq!(join_keys.trace_ids, vec!["bd-144::run-001::003"]);
    assert_eq!(
        join_keys.span_ids,
        vec!["abi::realloc::decision::000000000000002a"]
    );
    assert_eq!(join_keys.decision_ids, vec![42]);
    assert_eq!(join_keys.policy_ids, vec![7]);
    assert_eq!(join_keys.evidence_seqnos, vec![11]);
}

#[test]
fn emitter_writes_valid_jsonl() {
    let dir = std::env::temp_dir().join("frankenlibc_log_test");
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("test_output.jsonl");

    {
        let mut emitter = LogEmitter::to_file(&log_path, "bd-test", "run-integ").unwrap();
        emitter.emit(LogLevel::Info, "test_start").unwrap();
        emitter
            .emit_entry(
                LogEntry::new("", LogLevel::Info, "validation_pass")
                    .with_mode("strict")
                    .with_api("string", "memcpy")
                    .with_outcome(Outcome::Pass)
                    .with_latency_ns(15),
            )
            .unwrap();
        emitter.emit(LogLevel::Info, "test_end").unwrap();
        emitter.flush().unwrap();
    }

    // Validate the output file
    let (line_count, errors) = validate_log_file(&log_path).unwrap();
    assert_eq!(line_count, 3, "Expected 3 log lines");
    assert!(
        errors.is_empty(),
        "Emitter output should validate: {:?}",
        errors
    );

    // Verify trace_id sequencing
    let content = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<serde_json::Value> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(lines[0]["trace_id"].as_str().unwrap().ends_with("::001"));
    assert!(lines[1]["trace_id"].as_str().unwrap().ends_with("::002"));
    assert!(lines[2]["trace_id"].as_str().unwrap().ends_with("::003"));

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn validation_catches_missing_fields() {
    // Missing trace_id
    let line = r#"{"timestamp":"2026-01-01T00:00:00Z","level":"info","event":"test"}"#;
    let result = validate_log_line(line, 1);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.field == "trace_id"));

    // Missing timestamp
    let line = r#"{"trace_id":"a::b::c","level":"info","event":"test"}"#;
    let result = validate_log_line(line, 2);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.field == "timestamp"));

    // Missing both level and event
    let line = r#"{"timestamp":"2026-01-01T00:00:00Z","trace_id":"a::b::c"}"#;
    let result = validate_log_line(line, 3);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.len() >= 2);
}

#[test]
fn validation_catches_invalid_enums() {
    // Invalid level
    let line = r#"{"timestamp":"T","trace_id":"a::b::c","level":"critical","event":"e"}"#;
    let result = validate_log_line(line, 1);
    assert!(result.is_err());

    // Invalid mode
    let line =
        r#"{"timestamp":"T","trace_id":"a::b::c","level":"info","event":"e","mode":"turbo"}"#;
    let result = validate_log_line(line, 2);
    assert!(result.is_err());

    // Invalid outcome
    let line =
        r#"{"timestamp":"T","trace_id":"a::b::c","level":"info","event":"e","outcome":"maybe"}"#;
    let result = validate_log_line(line, 3);
    assert!(result.is_err());
}

#[test]
fn artifact_index_roundtrip() {
    let mut idx = ArtifactIndex::new("run-001", "bd-144");
    idx.add("logs/test.jsonl", "log", "abc123def456");
    idx.add("golden/snapshot.json", "golden", "789abc");

    let json = idx.to_json().unwrap();
    let restored: ArtifactIndex = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.index_version, 1);
    assert_eq!(restored.run_id, "run-001");
    assert_eq!(restored.bead_id, "bd-144");
    assert_eq!(restored.artifacts.len(), 2);
    assert_eq!(restored.artifacts[0].kind, "log");
    assert_eq!(restored.artifacts[1].kind, "golden");
}

#[test]
fn artifact_index_accepts_legacy_v1_shape() {
    let legacy = serde_json::json!({
        "index_version": 1,
        "bead_id": "bd-legacy",
        "artifacts": [
            {
                "path": "logs/test.jsonl",
                "kind": "log",
                "sha256": "abc123",
                "join_keys": {
                    "trace_id": "bd-legacy::run-001::007",
                    "decision_id": 9,
                    "policy_id": 3,
                    "evidence_seqno": 77
                }
            }
        ]
    });

    let mut parsed: ArtifactIndex = serde_json::from_value(legacy).expect("legacy index");
    let compatibility = parsed.normalize_legacy_defaults();
    assert!(compatibility.synthesized_run_id);
    assert!(compatibility.synthesized_generated_utc);
    assert_eq!(parsed.run_id, "legacy::bd-legacy");

    let join_keys = parsed.artifacts[0]
        .join_keys
        .as_ref()
        .expect("legacy join keys");
    assert_eq!(join_keys.trace_ids, vec!["bd-legacy::run-001::007"]);
    assert_eq!(join_keys.decision_ids, vec![9]);
    assert_eq!(join_keys.policy_ids, vec![3]);
    assert_eq!(join_keys.evidence_seqnos, vec![77]);
}

#[test]
fn valid_log_line_accepts_minimal_entry() {
    let line = r#"{"timestamp":"2026-02-11T00:00:00Z","trace_id":"bd-test::run::001","level":"info","event":"ping"}"#;
    let result = validate_log_line(line, 1);
    assert!(result.is_ok());
}

#[test]
fn valid_log_line_accepts_full_entry() {
    let line = r#"{"timestamp":"2026-02-11T00:00:00Z","trace_id":"bd-144::run-1::005","level":"error","event":"test_failure","bead_id":"bd-144","mode":"hardened","api_family":"malloc","symbol":"realloc","decision":"Deny","controller_id":"runtime_math_kernel.v1","decision_action":"Deny","risk_inputs":{"requested_bytes":4096,"bloom_negative":true},"outcome":"fail","errno":12,"latency_ns":150,"artifact_refs":["path/bt"],"details":{"note":"oom"}}"#;
    let result = validate_log_line(line, 1);
    assert!(
        result.is_ok(),
        "Full entry should validate: {:?}",
        result.err()
    );
}

#[test]
fn decision_event_without_explainability_is_rejected() {
    let line = r#"{"timestamp":"2026-02-11T00:00:00Z","trace_id":"bd-144::run-1::006","level":"error","event":"runtime_decision","decision":"Deny","outcome":"fail"}"#;
    let result = validate_log_line(line, 1);
    assert!(result.is_err(), "Missing explainability should fail");
}

#[test]
fn bd_33p_2_completion_debt_e2e_failure_trace_chain_is_joinable() {
    let trace_id = "bd-33p.2::e2e-failure::001";
    let span_id = "abi::free::decision::000000000000002a";
    let parent_span_id = "abi::free::entry::000000000000002a";
    let line = LogEntry::new(trace_id, LogLevel::Error, "runtime_decision")
        .with_bead("bd-33p.2")
        .with_stream(StreamKind::E2e)
        .with_gate("e2e_failure_path")
        .with_mode("hardened")
        .with_api("malloc", "free")
        .with_span(span_id, Some(parent_span_id.to_string()))
        .with_join_keys(Some(42), Some(7), Some(11))
        .with_decision(Decision::Deny)
        .with_decision_explainability(
            "runtime_math_kernel.v1",
            "Deny",
            serde_json::json!({
                "requested_bytes": 0,
                "addr_hint": 3735928559_u64,
                "is_write": true,
                "bloom_negative": true,
                "contention_hint": 4
            }),
        )
        .with_outcome(Outcome::Fail)
        .with_errno(22)
        .with_failure_signature("foreign_free_rejected")
        .with_artifacts(vec![
            "tests/conformance/logs/bd-33p.2-e2e.jsonl".to_string(),
        ])
        .to_jsonl()
        .expect("runtime decision row serializes");

    validate_log_line(&line, 1).expect("complete failure-path decision row validates");
    let report = DecisionTraceReport::from_jsonl_str(&line);
    assert_eq!(report.decision_events, 1);
    assert_eq!(report.explainable_decision_events, 1);
    assert!(report.fully_explainable());

    let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
    assert_eq!(parsed["trace_id"], trace_id);
    assert_eq!(parsed["span_id"], span_id);
    assert_eq!(parsed["parent_span_id"], parent_span_id);
    assert_eq!(parsed["symbol"], "free");
    assert_eq!(parsed["decision"], "Deny");
    assert_eq!(parsed["decision_id"], 42);
    assert_eq!(parsed["policy_id"], 7);
    assert_eq!(parsed["evidence_seqno"], 11);
    assert_eq!(parsed["controller_id"], "runtime_math_kernel.v1");
    assert_eq!(parsed["decision_action"], "Deny");
    assert!(parsed["risk_inputs"].is_object());
}

#[test]
fn bd_33p_2_completion_debt_e2e_rejects_missing_parent_span() {
    let line = r#"{"timestamp":"2026-02-12T00:00:00Z","trace_id":"bd-33p.2::e2e-failure::002","span_id":"abi::free::decision::000000000000002b","level":"error","event":"runtime_decision","symbol":"free","decision":"Deny","decision_id":43,"policy_id":7,"evidence_seqno":12,"controller_id":"runtime_math_kernel.v1","decision_action":"Deny","risk_inputs":{"requested_bytes":0,"bloom_negative":true},"outcome":"fail"}"#;
    let errors = validate_log_line(line, 1).expect_err("parent span is required");
    assert!(
        errors
            .iter()
            .any(|e| matches!(e.field.as_str(), "parent_span_id"))
    );

    let report = DecisionTraceReport::from_jsonl_str(line);
    assert_eq!(report.explainable_decision_events, 0);
    assert_eq!(report.missing_explainability, 1);
    assert!(report.findings[0].reason.contains("parent_span_id"));
}
