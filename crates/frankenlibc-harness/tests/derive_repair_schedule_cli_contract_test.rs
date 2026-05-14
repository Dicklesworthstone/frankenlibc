//! Conformance gate for the harness binary `derive-repair-schedule`
//! subcommand (bd-sef4y).

use std::collections::BTreeSet;
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
        .join("derive_repair_schedule_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_sef4y_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_sef4y_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "derive-repair-schedule-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-sef4y", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "derive-repair-schedule",
        "subcommand_name",
    )?;
    require(
        m.get("repair_max_degree_v1").and_then(Value::as_u64) == Some(16),
        "repair_max_degree_v1 must be 16",
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
        "indices_array_length_equals_degree",
        "degree_zero_when_k_source_zero",
        "degree_at_or_below_REPAIR_MAX_DEGREE_V1",
        "degree_at_or_below_k_source_when_positive",
        "indices_all_below_k_source_when_positive",
        "indices_all_distinct",
        "deterministic_given_seed_inputs",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_derive_repair_schedule_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("DeriveRepairSchedule {"),
        "harness.rs must declare DeriveRepairSchedule Command variant",
    )?;
    require(
        src.contains("derive_repair_schedule_v1"),
        "main() must import derive_repair_schedule_v1",
    )?;
    require(
        src.contains("\"kind\": \"repair_schedule\""),
        "DeriveRepairSchedule arm must emit kind=repair_schedule",
    )
}

fn run_cli(
    bin: &Path,
    epoch_seed: u64,
    k_source: u16,
    repair_esi: u16,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("derive-repair-schedule")
        .arg("--epoch-seed")
        .arg(epoch_seed.to_string())
        .arg("--k-source")
        .arg(k_source.to_string())
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
            "expected exactly one JSONL record in {}, got {}",
            out_path.display(),
            records.len()
        ),
    )?;
    let record = records
        .first()
        .ok_or_else(|| "missing JSONL record after count check".to_string())?;
    serde_json::from_str(record).map_err(|e| format!("parse: {e}"))
}

#[test]
fn cli_zero_k_source_yields_zero_degree_and_empty_indices() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("zero")?;
    let out = run_cli(&bin, 42, 0, 0, &output)?;
    if !out.status.success() {
        return Err(format!(
            "derive-repair-schedule failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_u64(&parsed, "degree")? == 0,
        "k_source=0 must yield degree=0",
    )?;
    require(
        json_array(&parsed, "indices")?.is_empty(),
        "k_source=0 must yield empty indices",
    )
}

#[test]
fn cli_baseline_invariants_hold_for_k_source_16() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("k16")?;
    let out = run_cli(&bin, 0xdeadbeef, 16, 7, &output)?;
    if !out.status.success() {
        return Err(format!(
            "derive-repair-schedule failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "repair_schedule",
        "kind must be repair_schedule",
    )?;
    // Echo of inputs.
    require(
        json_u64(&parsed, "epoch_seed")? == 0xdeadbeef
            && json_u64(&parsed, "k_source")? == 16
            && json_u64(&parsed, "repair_esi")? == 7,
        "record must echo inputs",
    )?;
    let degree = json_u64(&parsed, "degree")?;
    let indices = json_array(&parsed, "indices")?;
    require(
        degree as usize == indices.len(),
        format!(
            "indices.len ({}) must equal degree ({})",
            indices.len(),
            degree
        ),
    )?;
    require(
        degree <= 16,
        format!("degree {degree} must be <= REPAIR_MAX_DEGREE_V1=16"),
    )?;
    require(
        degree <= 16,
        format!("degree {degree} must be <= k_source=16"),
    )?;
    let raw_indices: Vec<u64> = indices.iter().filter_map(Value::as_u64).collect();
    require(
        raw_indices.iter().all(|&i| i < 16),
        format!("all indices must be < k_source=16; got {raw_indices:?}"),
    )?;
    let distinct: BTreeSet<u64> = raw_indices.iter().copied().collect();
    require(
        distinct.len() == raw_indices.len(),
        format!("indices must all be distinct; got {raw_indices:?}"),
    )
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = unique_tmp("det_a")?;
    let b = unique_tmp("det_b")?;
    let out_a = run_cli(&bin, 12345, 32, 3, &a)?;
    let out_b = run_cli(&bin, 12345, 32, 3, &b)?;
    require(
        out_a.status.success() && out_b.status.success(),
        format!(
            "both runs must succeed; got status a={:?} b={:?}",
            out_a.status, out_b.status
        ),
    )?;
    let pa = read_record(&a)?;
    let pb = read_record(&b)?;
    require(
        pa == pb,
        format!("same inputs must produce identical output; got {pa:?} vs {pb:?}"),
    )
}
