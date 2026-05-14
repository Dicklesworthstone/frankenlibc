//! Conformance gate for the harness binary `generate-repair-payloads`
//! subcommand (bd-d5jjz).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const SYMBOL_SIZE: usize = 128;

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
        .join("generate_repair_payloads_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_d5jjz_{stem}_{}_{ts}.{ext}", std::process::id())))
}

fn make_source_payloads(k: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(k * SYMBOL_SIZE);
    for i in 0..k {
        for j in 0..SYMBOL_SIZE {
            out.push(((i * 0x11) + j) as u8);
        }
    }
    out
}

fn write_bin(stem: &str, body: &[u8]) -> TestResult<PathBuf> {
    let p = unique_tmp(stem, "bin")?;
    std::fs::write(&p, body).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p)
}

fn read_records(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let mut records = Vec::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let record = match serde_json::from_str(line) {
            Ok(record) => record,
            Err(_) => return Err("parse JSONL record".into()),
        };
        records.push(record);
    }
    require(
        !records.is_empty(),
        format!("{} must contain at least one JSONL record", path.display()),
    )?;
    Ok(records)
}

fn split_payload_records(records: &[Value]) -> TestResult<(&[Value], &Value)> {
    let Some((summary, payloads)) = records.split_last() else {
        return Err("CLI output must contain a summary record".into());
    };
    Ok((payloads, summary))
}

fn json_u64_vec(value: &Value, field: &str) -> TestResult<Vec<u64>> {
    let mut out = Vec::new();
    for entry in json_array(value, field)? {
        let Some(raw) = entry.as_u64() else {
            return Err("array entries must be u64".into());
        };
        out.push(raw);
    }
    Ok(out)
}

fn run_cli(
    bin: &Path,
    epoch_seed: u64,
    source_payloads: &Path,
    overhead_percent: u16,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("generate-repair-payloads")
        .arg("--epoch-seed")
        .arg(epoch_seed.to_string())
        .arg("--source-payloads")
        .arg(source_payloads)
        .arg("--overhead-percent")
        .arg(overhead_percent.to_string())
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

#[test]
fn manifest_anchors_to_d5jjz_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "generate-repair-payloads-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-d5jjz", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "generate-repair-payloads",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::evidence::generate_repair_payloads_v1",
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
    for (field, message) in [
        (
            "must_emit_one_record_per_repair_payload_plus_summary",
            "must_emit_one_record_per_repair_payload_plus_summary must be true",
        ),
        (
            "echoes_inputs_into_records",
            "echoes_inputs_into_records must be true",
        ),
        (
            "deterministic_given_inputs",
            "deterministic_given_inputs must be true",
        ),
        (
            "esis_are_contiguous_from_k_source",
            "esis_are_contiguous_from_k_source must be true",
        ),
        (
            "repair_count_matches_summary_esis_length",
            "repair_count_matches_summary_esis_length must be true",
        ),
        (
            "each_payload_hex_is_256_lowercase_hex_chars",
            "each_payload_hex_is_256_lowercase_hex_chars must be true",
        ),
        (
            "non_multiple_of_128_input_file_is_rejected",
            "non_multiple_of_128_input_file_is_rejected must be true",
        ),
        (
            "k_zero_input_is_rejected",
            "k_zero_input_is_rejected must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_generate_repair_payloads_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("GenerateRepairPayloads {"),
        "harness.rs must declare GenerateRepairPayloads variant",
    )?;
    require(
        src.contains("evidence::generate_repair_payloads_v1")
            || src.contains("generate_repair_payloads_v1"),
        "match arm must import generate_repair_payloads_v1",
    )?;
    require(
        src.contains("\"kind\": \"repair_payload\"")
            && src.contains("\"kind\": \"repair_payload_summary\""),
        "match arm must emit per-repair + summary records",
    )
}

#[test]
fn cli_esis_are_contiguous_from_k_source() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("contig_srcs", &srcs)?;
    let output = unique_tmp("contig", "jsonl")?;
    let out = run_cli(&bin, 1, &srcs_path, 100, &output)?;
    if !out.status.success() {
        return Err("generate-repair-payloads CLI invocation must succeed".into());
    }
    let recs = read_records(&output)?;
    let (payloads, summary) = split_payload_records(&recs)?;
    let r = payloads.len();
    require(r > 0, "must emit at least 1 repair record")?;
    for (i, rec) in payloads.iter().enumerate() {
        require(
            json_string(rec, "kind")? == "repair_payload",
            "payload record kind",
        )?;
        let esi = json_u64(rec, "esi")?;
        let expected = 4 + (i as u64);
        require(
            esi == expected,
            "payload esi must be contiguous from k_source",
        )?;
    }
    require(
        json_string(summary, "kind")? == "repair_payload_summary",
        "summary kind",
    )?;
    let esis = json_u64_vec(summary, "esis")?;
    let expected: Vec<u64> = (0..r as u64).map(|i| 4 + i).collect();
    require(esis == expected, "summary esis must match payload records")
}

#[test]
fn cli_repair_count_matches_summary_esis_length() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs = make_source_payloads(8);
    let srcs_path = write_bin("count_srcs", &srcs)?;
    let output = unique_tmp("count", "jsonl")?;
    let out = run_cli(&bin, 42, &srcs_path, 50, &output)?;
    if !out.status.success() {
        return Err("generate-repair-payloads CLI invocation must succeed".into());
    }
    let recs = read_records(&output)?;
    let (payloads, summary) = split_payload_records(&recs)?;
    let count = json_u64(summary, "repair_count")?;
    let esis = json_array(summary, "esis")?;
    let emitted = payloads.len();
    require(
        count as usize == esis.len(),
        "repair_count must equal summary esis length",
    )?;
    require(
        count as usize == emitted,
        "repair_count must equal emitted payload records",
    )
}

#[test]
fn cli_each_payload_hex_is_256_lowercase_hex_chars() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("hex_srcs", &srcs)?;
    let output = unique_tmp("hex", "jsonl")?;
    let out = run_cli(&bin, 999, &srcs_path, 100, &output)?;
    if !out.status.success() {
        return Err("generate-repair-payloads CLI invocation must succeed".into());
    }
    let recs = read_records(&output)?;
    let (payloads, _) = split_payload_records(&recs)?;
    for rec in payloads {
        let hex = json_string(rec, "payload_hex")?;
        require(hex.len() == 256, "payload_hex must be 256 chars")?;
        require(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "payload_hex must be lowercase hex",
        )?;
    }
    Ok(())
}

#[test]
fn cli_non_multiple_of_128_input_is_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs_path = write_bin("short_srcs", b"short")?;
    let output = unique_tmp("reject_len", "jsonl")?;
    let out = run_cli(&bin, 1, &srcs_path, 25, &output)?;
    require(
        !out.status.success(),
        "non-multiple-of-128 file must exit non-zero",
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("not a multiple of 128"),
        format!("stderr must mention 128 multiple: {stderr}"),
    )
}

#[test]
fn cli_k_zero_input_is_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs_path = write_bin("empty_srcs", b"")?;
    let output = unique_tmp("k_zero", "jsonl")?;
    let out = run_cli(&bin, 1, &srcs_path, 25, &output)?;
    require(!out.status.success(), "k=0 (empty file) must exit non-zero")
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("det_srcs", &srcs)?;
    let a = unique_tmp("det_a", "jsonl")?;
    let b = unique_tmp("det_b", "jsonl")?;
    let r_a = run_cli(&bin, 12345, &srcs_path, 75, &a)?;
    let r_b = run_cli(&bin, 12345, &srcs_path, 75, &b)?;
    require(
        r_a.status.success() && r_b.status.success(),
        "both runs must succeed",
    )?;
    let pa = read_records(&a)?;
    let pb = read_records(&b)?;
    require(pa == pb, "same inputs must produce identical output")
}
