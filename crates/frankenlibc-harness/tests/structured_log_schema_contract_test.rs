//! Conformance gate for the structured-logging schema (bd-144 /
//! completion-debt bd-144.1).
//!
//! Pins, at conformance level, that frankenlibc-harness's
//! `structured_log` module:
//! 1. Exposes the canonical [`LogEntry`] struct with 4 required
//!    fields (timestamp, trace_id, level, event).
//! 2. Exposes `validate_log_line` (per-line validator) and
//!    `validate_log_file` (multi-line e2e validator).
//! 3. Carries a curated telemetry-correlation vocabulary covering
//!    bead/trace/span correlation, decision explainability, and the
//!    artifact_refs index.
//! 4. Has 7 primary unit tests covering the happy path + each
//!    rejection class (missing field, invalid level, invalid JSON,
//!    bad trace_id format, missing decision explainability fields,
//!    zero join ids).
//! 5. Validates a synthetic multi-line JSONL file end-to-end through
//!    validate_log_file — the e2e closure point.

use std::io::Write;
use std::path::{Path, PathBuf};

use frankenlibc_harness::structured_log::{
    LogEntry, LogLevel, validate_log_file, validate_log_line,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("structured_log_schema_contract.v1.json")
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = manifest_path(&root);
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn read_file(root: &Path, rel: &str) -> TestResult<String> {
    let p = root.join(rel);
    std::fs::read_to_string(&p).map_err(|e| format!("read {p:?}: {e}"))
}

#[test]
fn manifest_anchors_to_144_with_completion_debt_bead() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "structured-log-schema-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-144", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-144.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "schema_struct")? == "frankenlibc_harness::structured_log::LogEntry",
        "schema_struct",
    )?;
    require(
        json_string(&m, "schema_file")? == "crates/frankenlibc-harness/src/structured_log.rs",
        "schema_file",
    )?;
    require(
        json_string(&m, "validator_line_function")?
            == "frankenlibc_harness::structured_log::validate_log_line",
        "validator_line_function",
    )?;
    require(
        json_string(&m, "validator_file_function")?
            == "frankenlibc_harness::structured_log::validate_log_file",
        "validator_file_function",
    )?;
    require(
        json_string(&m, "e2e_validation_function")?
            == "frankenlibc_harness::structured_log::validate_log_file",
        "e2e_validation_function",
    )
}

#[test]
fn manifest_audit_reference_pins_pre_repair_score_and_three_missing_items() -> TestResult {
    let m = load_manifest()?;
    let aref = m
        .get("audit_reference")
        .ok_or_else(|| "missing audit_reference".to_string())?;
    require(
        json_string(aref, "pass")? == "2026-05-10T03-16-16Z",
        "audit_reference.pass",
    )?;
    let missing: Vec<&str> = json_array(aref, "missing_item_ids")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for k in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
        require(
            missing.contains(&k),
            format!("audit_reference.missing_item_ids missing {k}"),
        )?;
    }
    require(
        aref.get("score_before").and_then(Value::as_u64) == Some(470),
        "score_before",
    )?;
    require(
        aref.get("score_threshold").and_then(Value::as_u64) == Some(700),
        "score_threshold",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let m = load_manifest()?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "fail_closed_when_required_field_missing",
        "fail_closed_when_validator_function_missing",
        "fail_closed_when_decision_lacks_explainability_fields",
        "fail_closed_when_join_ids_are_zero",
        "telemetry_correlation_fields_must_be_present_in_log_entry_struct",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn log_entry_struct_carries_required_fields() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-harness/src/structured_log.rs")?;
    let m = load_manifest()?;
    // Each required field must appear declared inside LogEntry.
    // We read the LogEntry struct body via the `pub struct LogEntry`
    // anchor and confirm the field appears as a typed declaration.
    let header = "pub struct LogEntry {";
    let start = src
        .find(header)
        .ok_or_else(|| "could not locate `pub struct LogEntry {` anchor".to_string())?;
    let body_start = start + header.len();
    // Body ends at the matching closing brace. Brace match.
    let bytes = src.as_bytes();
    let mut depth: i32 = 1;
    let mut end = body_start;
    for (i, &b) in bytes.iter().enumerate().skip(body_start) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &src[body_start..end];
    let required: Vec<&str> = json_array(&m, "required_log_entry_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for f in required {
        // The declaration is `pub <field>: ...,` since LogEntry is a
        // public struct with public fields.
        let anchor = format!("pub {f}:");
        require(
            body.contains(&anchor),
            format!("LogEntry struct missing required field declaration `{anchor}`"),
        )?;
    }
    Ok(())
}

#[test]
fn log_entry_struct_carries_telemetry_correlation_fields() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-harness/src/structured_log.rs")?;
    let m = load_manifest()?;
    let telemetry: Vec<&str> = json_array(&m, "telemetry_correlation_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for f in telemetry {
        // Each correlation field must appear in the file as `pub
        // <field>:`. Some are required (no Option), some are
        // Optional<...> — both share the `pub <field>:` prefix.
        let anchor = format!("pub {f}:");
        require(
            src.contains(&anchor),
            format!("structured_log.rs missing telemetry correlation field `{anchor}`"),
        )?;
    }
    Ok(())
}

#[test]
fn primary_unit_tests_exist_in_structured_log_rs() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-harness/src/structured_log.rs")?;
    let m = load_manifest()?;
    let tests: Vec<&str> = json_array(&m, "primary_unit_tests")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for t in tests {
        let anchor = format!("fn {t}(");
        require(
            src.contains(&anchor),
            format!("structured_log.rs missing primary unit test `{anchor}`"),
        )?;
    }
    Ok(())
}

#[test]
fn validator_line_round_trip_accepts_well_formed_log_entry() -> TestResult {
    let entry = LogEntry::new("bd-144::run::001", LogLevel::Info, "test_event");
    let json = entry
        .to_jsonl()
        .map_err(|e| format!("to_jsonl failed: {e}"))?;
    let parsed = validate_log_line(&json, 1)
        .map_err(|errs| format!("validate_log_line rejected a well-formed entry: {errs:?}"))?;
    require(parsed.event == "test_event", "round-trip event")?;
    require(parsed.trace_id == "bd-144::run::001", "round-trip trace_id")
}

#[test]
fn validator_line_rejects_missing_trace_id() -> TestResult {
    let json = r#"{"timestamp":"2026-05-10T00:00:00Z","level":"info","event":"missing_tid"}"#;
    let result = validate_log_line(json, 1);
    let errs = result
        .err()
        .ok_or_else(|| "expected errors but got Ok".to_string())?;
    require(
        errs.iter().any(|e| e.field == "trace_id"),
        format!("expected `trace_id` error; got {errs:?}"),
    )
}

#[test]
fn validator_file_e2e_validates_multiline_jsonl() -> TestResult {
    // Build 3 well-formed entries + persist as JSONL + validate via
    // validate_log_file. This is the e2e closure point the audit
    // wants pinned (tests.e2e.primary).
    let tmp = tempfile_path("bd_144_e2e_jsonl")?;
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create temp: {e}"))?;
    for i in 0..3 {
        let entry = LogEntry::new(
            format!("bd-144::e2e::{i:03}"),
            LogLevel::Info,
            format!("e2e_event_{i}"),
        );
        let line = entry
            .to_jsonl()
            .map_err(|e| format!("to_jsonl line {i}: {e}"))?;
        writeln!(f, "{line}").map_err(|e| format!("write line {i}: {e}"))?;
    }
    drop(f);
    let res = validate_log_file(&tmp);
    let cleanup_err = std::fs::remove_file(&tmp).err().map(|e| format!("{e}"));
    let (lines, errors) = res.map_err(|e| format!("validate_log_file io error: {e}"))?;
    require(
        errors.is_empty(),
        format!("validate_log_file reported errors: {errors:?}"),
    )?;
    require(
        lines == 3,
        format!("expected 3 validated lines; got {lines}"),
    )?;
    if let Some(c) = cleanup_err {
        return Err(format!("cleanup of {tmp:?} failed: {c}"));
    }
    Ok(())
}

#[test]
fn validator_file_e2e_surfaces_a_malformed_line_at_the_correct_line_number() -> TestResult {
    // 1st line valid, 2nd line invalid (missing trace_id), 3rd line
    // valid. validate_log_file must report the 2nd-line error at
    // line_number=2.
    let tmp = tempfile_path("bd_144_e2e_malformed")?;
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create temp: {e}"))?;
    let good = LogEntry::new("bd-144::malformed::001", LogLevel::Info, "ok")
        .to_jsonl()
        .map_err(|e| format!("to_jsonl: {e}"))?;
    writeln!(f, "{good}").map_err(|e| format!("write good 1: {e}"))?;
    writeln!(
        f,
        r#"{{"timestamp":"2026-05-10T00:00:00Z","level":"info","event":"missing_trace"}}"#
    )
    .map_err(|e| format!("write bad: {e}"))?;
    writeln!(f, "{good}").map_err(|e| format!("write good 3: {e}"))?;
    drop(f);
    let res = validate_log_file(&tmp);
    let cleanup_err = std::fs::remove_file(&tmp).err().map(|e| format!("{e}"));
    let (lines, errors) = res.map_err(|e| format!("validate_log_file io error: {e}"))?;
    require(
        lines == 3,
        format!("expected 3 lines processed; got {lines}"),
    )?;
    require(
        errors
            .iter()
            .any(|e| e.line_number == 2 && e.field == "trace_id"),
        format!("expected line=2 trace_id error; got {errors:?}"),
    )?;
    if let Some(c) = cleanup_err {
        return Err(format!("cleanup of {tmp:?} failed: {c}"));
    }
    Ok(())
}

fn tempfile_path(stem: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir();
    // Mix in PID + nanos so concurrent test invocations don't collide.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(dir.join(format!("{stem}_{pid}_{nanos}.jsonl")))
}
