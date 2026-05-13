//! Conformance gate for the harness binary `validate-structured-log`
//! subcommand (bd-0ojzh).

use std::path::{Path, PathBuf};
use std::process::Command;

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
        .join("validate_structured_log_cli_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
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

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn cargo_target_dir_for_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(p)
    } else if let Ok(p) = std::env::var("CARGO_MANIFEST_DIR") {
        Path::new(&p)
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join("target"))
            .unwrap_or_else(|| PathBuf::from("target"))
    } else {
        PathBuf::from("target")
    }
}

fn find_harness_binary() -> Option<PathBuf> {
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_0ojzh_{stem}_{}_{ts}.jsonl", std::process::id())))
}

fn run_cli(bin: &Path, jsonl: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("validate-structured-log")
        .arg("--jsonl")
        .arg(jsonl)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_single_record(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read jsonl: {e}"))?;
    let lines = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>();
    require(
        lines.len() == 1,
        format!("expected exactly 1 JSONL record; got {}", lines.len()),
    )?;
    serde_json::from_str(lines[0]).map_err(|e| format!("parse output record: {e}"))
}

#[test]
fn manifest_anchors_to_0ojzh_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "validate-structured-log-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-0ojzh", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "validate-structured-log",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::structured_log::validate_log_file",
        "underlying_lib_function",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "must_emit_exactly_one_jsonl_record",
        "ok_true_iff_errors_array_empty",
        "exit_non_zero_when_ok_false",
        "empty_jsonl_must_pass",
        "io_error_must_fail_closed",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_validate_structured_log_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ValidateStructuredLog {"),
        "harness.rs must declare ValidateStructuredLog Command variant",
    )?;
    require(
        src.contains("structured_log::validate_log_file"),
        "main() must import structured_log::validate_log_file",
    )?;
    require(
        src.contains("\"kind\": \"structured_log_validation\""),
        "ValidateStructuredLog arm must emit kind=structured_log_validation",
    )
}

#[test]
fn cli_passes_on_empty_jsonl() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("empty_in")?;
    let output = unique_tmp("empty_out")?;
    std::fs::write(&jsonl, "").map_err(|e| format!("write input: {e}"))?;
    let out = run_cli(&bin, &jsonl, &output)?;
    if !out.status.success() {
        return Err(format!(
            "validate-structured-log failed on empty log: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_single_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "structured_log_validation",
        "kind must be structured_log_validation",
    )?;
    require(json_bool(&parsed, "ok")?, "empty jsonl must yield ok=true")?;
    require(
        json_u64(&parsed, "total_lines")? == 0,
        "empty jsonl must yield total_lines=0",
    )?;
    require(
        json_array(&parsed, "errors")?.is_empty(),
        "empty jsonl must yield errors=[]",
    )
}

#[test]
fn cli_passes_on_valid_row() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("valid_in")?;
    let output = unique_tmp("valid_out")?;
    std::fs::write(
        &jsonl,
        r#"{"timestamp":"2026-05-13T00:00:00.000Z","trace_id":"bd-0ojzh::run-1::001","level":"info","event":"test_start"}"#,
    )
    .map_err(|e| format!("write input: {e}"))?;
    let out = run_cli(&bin, &jsonl, &output)?;
    if !out.status.success() {
        return Err(format!(
            "validate-structured-log failed on valid row: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_single_record(&output)?;
    require(json_bool(&parsed, "ok")?, "valid row must yield ok=true")?;
    require(
        json_u64(&parsed, "total_lines")? == 1,
        "valid row must yield total_lines=1",
    )?;
    require(
        json_array(&parsed, "errors")?.is_empty(),
        "valid row must yield errors=[]",
    )
}

#[test]
fn cli_fails_on_invalid_json_row_with_json_field() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("invalid_json_in")?;
    let output = unique_tmp("invalid_json_out")?;
    std::fs::write(&jsonl, "this is not json\n").map_err(|e| format!("write input: {e}"))?;
    let out = run_cli(&bin, &jsonl, &output)?;
    require(
        !out.status.success(),
        "invalid JSON row must yield non-zero exit",
    )?;
    let parsed = read_single_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "invalid JSON row must yield ok=false",
    )?;
    let errors = json_array(&parsed, "errors")?;
    require(
        errors
            .iter()
            .any(|e| e.get("field").and_then(Value::as_str) == Some("<json>")),
        "errors must include field=<json>",
    )
}

#[test]
fn cli_fails_on_missing_required_field_and_names_field() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("missing_field_in")?;
    let output = unique_tmp("missing_field_out")?;
    std::fs::write(
        &jsonl,
        r#"{"timestamp":"2026-05-13T00:00:00.000Z","trace_id":"bd-0ojzh::run-1::001","level":"info"}"#,
    )
    .map_err(|e| format!("write input: {e}"))?;
    let out = run_cli(&bin, &jsonl, &output)?;
    require(
        !out.status.success(),
        "missing required field must yield non-zero exit",
    )?;
    let parsed = read_single_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "missing required field must yield ok=false",
    )?;
    let errors = json_array(&parsed, "errors")?;
    require(
        errors
            .iter()
            .any(|e| e.get("field").and_then(Value::as_str) == Some("event")),
        "errors must name missing required field `event`",
    )
}

#[test]
fn cli_fails_closed_on_missing_input() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("never_exists")?;
    let output = unique_tmp("missing_out")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    require(
        !out.status.success(),
        "missing input must yield non-zero exit",
    )?;
    let parsed = read_single_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "missing input must yield ok=false",
    )?;
    let errors = json_array(&parsed, "errors")?;
    require(
        errors
            .iter()
            .any(|e| e.get("field").and_then(Value::as_str) == Some("<io>")),
        "missing input must include field=<io>",
    )
}
