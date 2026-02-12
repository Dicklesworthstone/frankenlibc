//! Integration test: structured logging contract (bd-144)
//!
//! Validates that:
//! 1. log_schema.json exists and is well-formed.
//! 2. The Rust structured_log module produces valid JSONL.
//! 3. The validation function catches schema violations.
//! 4. LogEmitter writes correct JSONL to files.
//! 5. ArtifactIndex serializes correctly.
//!
//! Run: cargo test -p glibc-rs-harness --test structured_log_test

use std::path::{Path, PathBuf};

use frankenlibc_harness::structured_log::{
    ArtifactIndex, LogEmitter, LogEntry, LogLevel, Outcome, validate_log_file, validate_log_line,
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
fn emitter_writes_valid_jsonl() {
    let dir = std::env::temp_dir().join("glibc_rust_log_test");
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
fn valid_log_line_accepts_minimal_entry() {
    let line = r#"{"timestamp":"2026-02-11T00:00:00Z","trace_id":"bd-test::run::001","level":"info","event":"ping"}"#;
    let result = validate_log_line(line, 1);
    assert!(result.is_ok());
}

#[test]
fn valid_log_line_accepts_full_entry() {
    let line = r#"{"timestamp":"2026-02-11T00:00:00Z","trace_id":"bd-144::run-1::005","level":"error","event":"test_failure","bead_id":"bd-144","mode":"hardened","api_family":"malloc","symbol":"realloc","decision":"Deny","outcome":"fail","errno":12,"latency_ns":150,"artifact_refs":["path/bt"],"details":{"note":"oom"}}"#;
    let result = validate_log_line(line, 1);
    assert!(
        result.is_ok(),
        "Full entry should validate: {:?}",
        result.err()
    );
}
