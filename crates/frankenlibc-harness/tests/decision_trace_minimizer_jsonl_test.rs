//! Conformance gate for the decision-trace minimizer JSONL
//! serializer + parser (bd-yhvim).
//!
//! Validates the manifest's `serialization_contract` block matches
//! the lib's `MINIMIZED_TRACE_REQUIRED_FIELDS` const + exercises a
//! round trip through `serialize_minimized_trace_jsonl` and
//! `parse_minimized_trace_jsonl`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use frankenlibc_harness::decision_trace_minimizer::{
    MINIMIZED_TRACE_REQUIRED_FIELDS, MinimizerSerError, TraceRow, minimize,
    parse_minimized_trace_jsonl, serialize_minimized_trace_jsonl,
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
        .join("strict_hardened_decision_trace_minimizer.v1.json")
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

fn row(
    scenario: &str,
    api_family: &str,
    symbol: &str,
    decision_path: &str,
    input_class: &str,
    strict: &str,
    hardened: &str,
) -> TraceRow {
    TraceRow {
        schema_version: "v1".to_string(),
        scenario: scenario.to_string(),
        api_family: api_family.to_string(),
        symbol: symbol.to_string(),
        decision_path: decision_path.to_string(),
        input_class: input_class.to_string(),
        mode_strict_decision: strict.to_string(),
        mode_hardened_decision: hardened.to_string(),
        source_commit: "abc1234567890abc1234567890abc1234567890a".to_string(),
        artifact_refs: vec!["target/conformance/replay.log.jsonl".to_string()],
    }
}

#[test]
fn manifest_serialization_contract_required_fields_match_lib_const() -> TestResult {
    let m = load_manifest()?;
    let block = m
        .get("serialization_contract")
        .ok_or_else(|| "missing serialization_contract".to_string())?;
    let manifest_fields: BTreeSet<&str> = block
        .get("required_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| "required_fields".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let lib_fields: BTreeSet<&str> = MINIMIZED_TRACE_REQUIRED_FIELDS.iter().copied().collect();
    require(
        manifest_fields == lib_fields,
        format!(
            "manifest required_fields must match MINIMIZED_TRACE_REQUIRED_FIELDS; lib={lib_fields:?}, manifest={manifest_fields:?}"
        ),
    )?;
    require(
        block.get("serializer_function").and_then(Value::as_str)
            == Some(
                "frankenlibc_harness::decision_trace_minimizer::serialize_minimized_trace_jsonl",
            ),
        "serializer_function path",
    )?;
    require(
        block.get("parser_function").and_then(Value::as_str)
            == Some("frankenlibc_harness::decision_trace_minimizer::parse_minimized_trace_jsonl"),
        "parser_function path",
    )?;
    Ok(())
}

#[test]
fn manifest_serialization_contract_pins_fail_closed_kinds() -> TestResult {
    let m = load_manifest()?;
    let block = m
        .get("serialization_contract")
        .ok_or_else(|| "missing serialization_contract".to_string())?;
    for f in [
        "fail_closed_when_required_field_missing",
        "fail_closed_when_field_type_wrong",
        "fail_closed_when_json_invalid",
    ] {
        require(
            block.get(f).and_then(Value::as_bool) == Some(true),
            format!("{f} must be true"),
        )?;
    }
    let kinds: BTreeSet<&str> = block
        .get("rejected_serialization_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "rejected_serialization_kinds".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for k in [
        "missing_required_field",
        "wrong_field_type",
        "invalid_json",
        "unexpected_kind",
    ] {
        require(
            kinds.contains(k),
            format!("rejected_serialization_kinds must include {k}"),
        )?;
    }
    Ok(())
}

#[test]
fn round_trip_preserves_summary_fields_for_divergence_input() -> TestResult {
    let rows = vec![
        row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow"),
        row(
            "s",
            "stdio",
            "fread",
            "slow",
            "adversarial",
            "Allow",
            "Repair",
        ),
    ];
    let m = minimize(&rows).map_err(|e| format!("{e}"))?;
    let line = serialize_minimized_trace_jsonl(&m);
    let summary = parse_minimized_trace_jsonl(&line).map_err(|e| format!("{e}"))?;
    require(
        summary.expected_failure_signature == m.expected_failure_signature,
        "expected_failure_signature",
    )?;
    require(summary.replay_command == m.replay_command, "replay_command")?;
    require(summary.source_commit == m.source_commit, "source_commit")?;
    require(
        summary.dropped_row_count == m.dropped_row_count,
        "dropped_row_count",
    )?;
    require(summary.has_divergence == m.has_divergence, "has_divergence")?;
    require(
        summary.minimized_rows_len == m.minimized_rows.len(),
        "minimized_rows_len",
    )
}

#[test]
fn parser_rejects_missing_required_field_with_kind_label() -> TestResult {
    let bad = r#"{"replay_command":"x","source_commit":"y"}"#;
    match parse_minimized_trace_jsonl(bad) {
        Err(MinimizerSerError::MissingField(name)) => {
            require(name == "kind", format!("expected `kind`; got {name}"))
        }
        other => Err(format!("expected MissingField; got {other:?}")),
    }
}

#[test]
fn parser_rejects_invalid_json() -> TestResult {
    let bad = "{not-json";
    match parse_minimized_trace_jsonl(bad) {
        Err(MinimizerSerError::InvalidJson(_)) => Ok(()),
        other => Err(format!("expected InvalidJson; got {other:?}")),
    }
}
