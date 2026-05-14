//! Conformance gate for the harness binary `decode-decision-payload`
//! subcommand (bd-3o3tw).

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
        .join("decode_decision_payload_cli_contract.v1.json")
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

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    let records: Vec<&str> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    require(
        records.len() == 1,
        format!(
            "{} must contain exactly one JSONL record, found {}",
            out_path.display(),
            records.len()
        ),
    )?;
    let record = records
        .first()
        .ok_or_else(|| "missing JSONL record after record-count check".to_string())?;
    serde_json::from_str(record).map_err(|e| format!("parse: {e}"))
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

fn unique_tmp(stem: &str, ext: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_3o3tw_{stem}_{}_{ts}.{ext}", std::process::id())))
}

#[test]
fn manifest_anchors_to_3o3tw_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "decode-decision-payload-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-3o3tw", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "decode-decision-payload",
        "subcommand_name",
    )?;
    require(
        m.get("payload_size_bytes").and_then(Value::as_u64) == Some(128),
        "payload_size_bytes must be 128",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for (field, message) in [
        (
            "must_emit_exactly_one_jsonl_record",
            "must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "ok_true_iff_decode_succeeds",
            "ok_true_iff_decode_succeeds must be true",
        ),
        (
            "exit_non_zero_when_ok_false",
            "exit_non_zero_when_ok_false must be true",
        ),
        (
            "wrong_payload_size_must_fail_closed",
            "wrong_payload_size_must_fail_closed must be true",
        ),
        (
            "zero_bytes_payload_must_fail_with_BadMagic",
            "zero_bytes_payload_must_fail_with_BadMagic must be true",
        ),
        (
            "missing_payload_file_must_fail_closed",
            "missing_payload_file_must_fail_closed must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_decode_decision_payload_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("DecodeDecisionPayload {"),
        "harness.rs must declare DecodeDecisionPayload Command variant",
    )?;
    require(
        src.contains("decode_decision_payload_v1") && src.contains("EVIDENCE_SYMBOL_SIZE_T"),
        "main() must import decode_decision_payload_v1 + EVIDENCE_SYMBOL_SIZE_T",
    )?;
    require(
        src.contains("\"kind\": \"decision_payload_decode\""),
        "DecodeDecisionPayload arm must emit kind=decision_payload_decode",
    )
}

fn run_cli(bin: &Path, payload: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("decode-decision-payload")
        .arg("--payload")
        .arg(payload)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

#[test]
fn cli_wrong_payload_size_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let payload = unique_tmp("wrong_size", "bin")?;
    let output = unique_tmp("wrong_size", "jsonl")?;
    // 64 bytes — half the expected 128.
    std::fs::write(&payload, vec![0_u8; 64]).map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &payload, &output)?;
    require(
        !out.status.success(),
        "wrong payload size must yield non-zero exit",
    )?;
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "decision_payload_decode",
        "kind must be decision_payload_decode",
    )?;
    require(!json_bool(&parsed, "ok")?, "wrong size must yield ok=false")?;
    require(
        json_string(&parsed, "error")?.contains("payload size"),
        "size error must mention payload size",
    )
}

#[test]
fn cli_zero_bytes_yields_bad_magic_error() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let payload = unique_tmp("zero128", "bin")?;
    let output = unique_tmp("zero128", "jsonl")?;
    std::fs::write(&payload, vec![0_u8; 128]).map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &payload, &output)?;
    require(
        !out.status.success(),
        "128 zero bytes must yield non-zero exit (BadMagic)",
    )?;
    let parsed = read_record(&output)?;
    require(!json_bool(&parsed, "ok")?, "zero bytes must yield ok=false")?;
    require(
        json_string(&parsed, "error")?.contains("BadMagic"),
        "zero bytes must produce BadMagic error",
    )
}

#[test]
fn cli_fails_closed_on_missing_payload_file() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let payload = unique_tmp("missing", "bin")?;
    let output = unique_tmp("missing", "jsonl")?;
    // payload deliberately not created.
    let out = run_cli(&bin, &payload, &output)?;
    require(
        !out.status.success(),
        "missing payload file must yield non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("read --payload"),
        "stderr must surface the read failure",
    )
}
