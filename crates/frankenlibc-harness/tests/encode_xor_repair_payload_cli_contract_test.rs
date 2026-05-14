//! Conformance gate for the harness binary `encode-xor-repair-payload`
//! subcommand (bd-3nygl).

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
        .join("encode_xor_repair_payload_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_3nygl_{stem}_{}_{ts}.{ext}", std::process::id())))
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

fn xor_symbols(srcs: &[u8], indices: &[u16]) -> TestResult<Vec<u8>> {
    let mut out = vec![0u8; SYMBOL_SIZE];
    for &idx in indices {
        let off = (idx as usize) * SYMBOL_SIZE;
        let end = match off.checked_add(SYMBOL_SIZE) {
            Some(end) => end,
            None => return Err("scheduled source offset overflow".into()),
        };
        let source = match srcs.get(off..end) {
            Some(source) => source,
            None => return Err("scheduled source index must be in bounds".into()),
        };
        for (slot, byte) in out.iter_mut().zip(source.iter()) {
            *slot ^= *byte;
        }
    }
    Ok(out)
}

fn write_bin(stem: &str, body: &[u8]) -> TestResult<PathBuf> {
    let p = unique_tmp(stem, "bin")?;
    std::fs::write(&p, body).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p)
}

fn parse_hex(s: &str) -> TestResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex length {} not even", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let Some((&hi_byte, &lo_byte)) = pair.first().zip(pair.get(1)) else {
            return Err("hex pair must contain two bytes".into());
        };
        let hi = match hex_nibble(hi_byte) {
            Some(nibble) => nibble,
            None => return Err("hex parse failed".into()),
        };
        let lo = match hex_nibble(lo_byte) {
            Some(nibble) => nibble,
            None => return Err("hex parse failed".into()),
        };
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[test]
fn manifest_anchors_to_3nygl_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "encode-xor-repair-payload-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-3nygl", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "encode-xor-repair-payload",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::evidence::encode_xor_repair_payload_v1",
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
        "echoes_inputs_into_output_record",
        "deterministic_given_inputs",
        "payload_hex_is_256_lowercase_hex_chars",
        "single_index_schedule_yields_source_payload_at_that_index",
        "multi_index_schedule_yields_xor_of_source_payloads_at_indices",
        "repair_esi_below_k_source_is_rejected",
        "non_multiple_of_128_input_file_is_rejected",
    ] {
        require(json_bool(policy, f)?, "policy invariant must be true")?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_encode_xor_repair_payload_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("EncodeXorRepairPayload {"),
        "harness.rs must declare EncodeXorRepairPayload variant",
    )?;
    require(
        src.contains("evidence::encode_xor_repair_payload_v1")
            || src.contains("encode_xor_repair_payload_v1"),
        "match arm must import encode_xor_repair_payload_v1",
    )?;
    require(
        src.contains("\"kind\": \"xor_repair_payload\""),
        "match arm must emit kind=xor_repair_payload",
    )
}

fn run_cli(
    bin: &Path,
    epoch_seed: u64,
    source_payloads: &Path,
    repair_esi: u16,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("encode-xor-repair-payload")
        .arg("--epoch-seed")
        .arg(epoch_seed.to_string())
        .arg("--source-payloads")
        .arg(source_payloads)
        .arg("--repair-esi")
        .arg(repair_esi.to_string())
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
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

fn schedule_indices(value: &Value) -> TestResult<Vec<u16>> {
    let values = value
        .get("schedule_indices")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing schedule_indices".to_string())?;
    let mut out = Vec::with_capacity(values.len());
    for entry in values {
        let raw = match entry.as_u64() {
            Some(raw) => raw,
            None => return Err("schedule index must be u64".into()),
        };
        let idx = match u16::try_from(raw) {
            Ok(idx) => idx,
            Err(_) => return Err("schedule index out of u16 range".into()),
        };
        out.push(idx);
    }
    Ok(out)
}

#[test]
fn cli_payload_hex_is_256_lowercase_hex_chars() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("hex_srcs", &srcs)?;
    let output = unique_tmp("hex", "jsonl")?;
    let out = run_cli(&bin, 42, &srcs_path, 4, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let hex = json_string(&parsed, "payload_hex")?;
    require(
        hex.len() == 256,
        format!("payload_hex must be 256 chars, got {}", hex.len()),
    )?;
    require(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "payload_hex must be lowercase hex",
    )
}

#[test]
fn cli_single_index_schedule_yields_source_payload_at_index() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // seed=42 with k=4 + repair_esi=4 yields schedule [3] (single index).
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("single_srcs", &srcs)?;
    let output = unique_tmp("single", "jsonl")?;
    let out = run_cli(&bin, 42, &srcs_path, 4, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let sched = schedule_indices(&parsed)?;
    require(
        sched.len() == 1,
        "seed=42 must produce single-index schedule",
    )?;
    let hex = json_string(&parsed, "payload_hex")?;
    let payload = parse_hex(hex)?;
    let expected = xor_symbols(&srcs, &sched)?;
    require(
        payload == expected,
        "single-index schedule: payload must equal source at scheduled index",
    )
}

#[test]
fn cli_multi_index_schedule_yields_xor_of_indices() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // seed=1000 with k=4 + repair_esi=4 yields schedule [2,1,3,0] (all 4 indices).
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("multi_srcs", &srcs)?;
    let output = unique_tmp("multi", "jsonl")?;
    let out = run_cli(&bin, 1000, &srcs_path, 4, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let sched = schedule_indices(&parsed)?;
    require(
        sched.len() >= 2,
        "seed=1000 must produce multi-index schedule",
    )?;
    let hex = json_string(&parsed, "payload_hex")?;
    let payload = parse_hex(hex)?;
    let expected = xor_symbols(&srcs, &sched)?;
    require(
        payload == expected,
        "multi-index schedule: payload must equal XOR of sources at scheduled indices",
    )
}

#[test]
fn cli_repair_esi_below_k_source_is_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("reject_srcs", &srcs)?;
    let output = unique_tmp("reject", "jsonl")?;
    let out = run_cli(&bin, 12345, &srcs_path, 2, &output)?;
    require(
        !out.status.success(),
        "repair_esi=2 with k=4 must exit non-zero",
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("repair_esi") && stderr.contains("k_source"),
        format!("stderr must mention repair_esi and k_source: {stderr}"),
    )
}

#[test]
fn cli_non_multiple_of_128_input_is_rejected() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs_path = write_bin("short_srcs", b"short")?;
    let output = unique_tmp("reject_len", "jsonl")?;
    let out = run_cli(&bin, 1, &srcs_path, 1, &output)?;
    require(
        !out.status.success(),
        "non-multiple-of-128 file must exit non-zero",
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("not a multiple of 128"),
        format!("stderr must mention 128-byte multiple: {stderr}"),
    )
}

#[test]
fn cli_echoes_inputs_into_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let srcs = make_source_payloads(4);
    let srcs_path = write_bin("echo_srcs", &srcs)?;
    let output = unique_tmp("echo", "jsonl")?;
    let out = run_cli(&bin, 9876, &srcs_path, 5, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(json_u64(&parsed, "epoch_seed")? == 9876, "epoch_seed echo")?;
    require(json_u64(&parsed, "k_source")? == 4, "k_source echo")?;
    require(json_u64(&parsed, "repair_esi")? == 5, "repair_esi echo")
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
    let r_a = run_cli(&bin, 12345, &srcs_path, 4, &a)?;
    let r_b = run_cli(&bin, 12345, &srcs_path, 4, &b)?;
    require(
        r_a.status.success() && r_b.status.success(),
        "both runs must succeed",
    )?;
    let pa = read_record(&a)?;
    let pb = read_record(&b)?;
    require(pa == pb, "same inputs must produce identical output")
}
