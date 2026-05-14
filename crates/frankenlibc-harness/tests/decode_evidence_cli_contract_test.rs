//! Conformance gate for the harness binary `decode-evidence`
//! subcommand (bd-d2dpm).

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::runtime_math::evidence::{
    EVIDENCE_SYMBOL_SIZE_T, EvidenceSymbolRecord, FLAG_SYSTEMATIC,
};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction, ValidationProfile};
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
        .join("decode_evidence_cli_contract.v1.json")
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
    if let Some(bin) = option_env!("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(bin));
    }
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
    Ok(std::env::temp_dir().join(format!("bd_d2dpm_{stem}_{}_{ts}.{ext}", std::process::id())))
}

fn synthetic_record(epoch_id: u64, seqno: u64, payload_byte: u8) -> EvidenceSymbolRecord {
    let payload = [payload_byte; EVIDENCE_SYMBOL_SIZE_T];
    EvidenceSymbolRecord::build_v1(
        epoch_id,
        seqno,
        0x9e37_79b9_7f4a_7c15,
        ApiFamily::PointerValidation,
        SafetyLevel::Hardened,
        MembraneAction::Allow,
        ValidationProfile::Fast,
        FLAG_SYSTEMATIC,
        0,
        1,
        0,
        0,
        &payload,
        None,
    )
}

fn write_records(path: &Path, records: &[EvidenceSymbolRecord]) -> TestResult {
    let mut bytes = Vec::with_capacity(records.len() * 256);
    for rec in records {
        bytes.extend_from_slice(rec.as_bytes());
    }
    std::fs::write(path, bytes).map_err(|e| format!("write evidence input: {e}"))
}

fn run_cli(bin: &Path, input: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("decode-evidence")
        .arg("--input")
        .arg(input)
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn harness decode-evidence: {e}"))
}

#[test]
fn manifest_anchors_to_d2dpm_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "decode-evidence-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-d2dpm", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "decode-evidence",
        "subcommand_name",
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
        "valid_systematic_record_must_decode_to_success",
        "epoch_id_filter_must_exclude_non_matching_epochs",
        "empty_input_must_fail_closed",
        "misaligned_input_must_fail_closed",
        "unknown_format_must_fail_closed",
        "json_format_must_emit_pretty_decode_report",
    ] {
        require(json_bool(policy, f)?, f)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_decode_evidence_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("DecodeEvidence {"),
        "harness.rs must declare DecodeEvidence Command variant",
    )?;
    require(
        src.contains("evidence_decode::decode_evidence_file"),
        "DecodeEvidence arm must call evidence_decode::decode_evidence_file",
    )?;
    require(
        src.contains("evidence_decode_render::render_plain"),
        "DecodeEvidence arm must expose plain rendering",
    )
}

#[test]
fn cli_decodes_valid_systematic_record_to_success_json() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("valid_record", "bin")?;
    let output = unique_tmp("valid_record", "json")?;
    write_records(&input, &[synthetic_record(0xA11C_E001, 0, 7)])?;

    let out = run_cli(&bin, &input, &output)?;
    require(
        out.status.success(),
        format!(
            "decode-evidence valid record failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;

    let parsed = load_json(&output)?;
    let epochs = parsed
        .get("epochs")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing epochs array".to_string())?;
    require(epochs.len() == 1, "valid input must emit one epoch")?;
    let epoch = epochs
        .first()
        .ok_or_else(|| "valid input must emit one epoch".to_string())?;
    require(json_u64(epoch, "epoch_id")? == 0xA11C_E001, "epoch_id")?;
    require(json_u64(epoch, "records_total")? == 1, "records_total")?;
    require(
        json_u64(epoch, "decoded_systematic")? == 1,
        "decoded_systematic",
    )?;
    require(
        epoch
            .get("status")
            .and_then(|v| v.get("kind"))
            .and_then(Value::as_str)
            == Some("Success"),
        "status.kind must be Success",
    )
}

#[test]
fn cli_epoch_filter_keeps_only_matching_epoch() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("epoch_filter", "bin")?;
    let output = unique_tmp("epoch_filter", "json")?;
    write_records(
        &input,
        &[
            synthetic_record(0xD2D0_0001, 0, 1),
            synthetic_record(0xD2D0_0002, 0, 2),
        ],
    )?;

    let out = Command::new(&bin)
        .arg("decode-evidence")
        .arg("--input")
        .arg(&input)
        .arg("--epoch-id")
        .arg("3536846850")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn harness decode-evidence: {e}"))?;
    require(
        out.status.success(),
        format!(
            "decode-evidence epoch filter failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;

    let parsed = load_json(&output)?;
    let epochs = parsed
        .get("epochs")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing epochs array".to_string())?;
    require(epochs.len() == 1, "epoch filter must emit one epoch")?;
    require(
        json_u64(
            epochs
                .first()
                .ok_or_else(|| "epoch filter must emit one epoch".to_string())?,
            "epoch_id",
        )? == 0xD2D0_0002,
        "epoch filter returned wrong epoch",
    )
}

#[test]
fn cli_fails_closed_on_empty_input() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("empty", "bin")?;
    let output = unique_tmp("empty", "json")?;
    std::fs::write(&input, b"").map_err(|e| format!("write empty input: {e}"))?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "empty input must fail closed")
}

#[test]
fn cli_fails_closed_on_misaligned_input() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("misaligned", "bin")?;
    let output = unique_tmp("misaligned", "json")?;
    std::fs::write(&input, [1_u8, 2, 3]).map_err(|e| format!("write misaligned input: {e}"))?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "misaligned input must fail closed")
}

#[test]
fn cli_fails_closed_on_unknown_format() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let input = unique_tmp("unknown_format", "bin")?;
    let output = unique_tmp("unknown_format", "json")?;
    write_records(&input, &[synthetic_record(0xD2D0_FF00, 0, 5)])?;
    let out = Command::new(&bin)
        .arg("decode-evidence")
        .arg("--input")
        .arg(&input)
        .arg("--format")
        .arg("xml")
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn harness decode-evidence: {e}"))?;
    require(!out.status.success(), "unknown format must fail closed")
}
