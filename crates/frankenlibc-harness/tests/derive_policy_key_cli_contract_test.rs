//! Conformance gate for the harness binary `derive-policy-key`
//! subcommand (bd-87vkk).

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
        .join("derive_policy_key_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_87vkk_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_87vkk_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "derive-policy-key-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-87vkk", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "derive-policy-key",
        "subcommand_name",
    )?;
    let constants = m
        .get("discretization_constants")
        .ok_or_else(|| "missing discretization_constants".to_string())?;
    require(
        json_u64(constants, "total_table_len")? == 20480,
        "total_table_len must be 20480 (2 modes * 20 families * 16 risk * 8 budget * 4 consistency)",
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
        ("risk_bucket_in_0_15", "risk_bucket_in_0_15 must be true"),
        ("budget_bucket_in_0_7", "budget_bucket_in_0_7 must be true"),
        (
            "consistency_bucket_in_0_3",
            "consistency_bucket_in_0_3 must be true",
        ),
        (
            "key_index_below_total_table_len",
            "key_index_below_total_table_len must be true",
        ),
        (
            "mode_off_maps_to_same_index_as_strict",
            "mode_off_maps_to_same_index_as_strict must be true",
        ),
        (
            "deterministic_given_inputs",
            "deterministic_given_inputs must be true",
        ),
        (
            "fail_closed_on_unknown_mode",
            "fail_closed_on_unknown_mode must be true",
        ),
        (
            "fail_closed_on_unknown_family",
            "fail_closed_on_unknown_family must be true",
        ),
        (
            "risk_ppm_zero_yields_bucket_zero",
            "risk_ppm_zero_yields_bucket_zero must be true",
        ),
        (
            "risk_ppm_999999_yields_bucket_15",
            "risk_ppm_999999_yields_bucket_15 must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_derive_policy_key_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("DerivePolicyKey {"),
        "harness.rs must declare DerivePolicyKey Command variant",
    )?;
    for needle in [
        "risk_bucket_v1",
        "budget_bucket_v1",
        "consistency_bucket_v1",
        "key_v1_index",
    ] {
        require(src.contains(needle), "main() must import policy key helper")?;
    }
    require(
        src.contains("\"kind\": \"policy_key\""),
        "DerivePolicyKey arm must emit kind=policy_key",
    )
}

fn run_cli(
    bin: &Path,
    mode: &str,
    family: &str,
    risk_ppm: u32,
    flags: &[&str],
    output: &Path,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("derive-policy-key")
        .arg("--mode")
        .arg(mode)
        .arg("--family")
        .arg(family)
        .arg("--risk-ppm")
        .arg(risk_ppm.to_string());
    for f in flags {
        cmd.arg(f);
    }
    cmd.arg("--output").arg(output);
    cmd.output().map_err(|e| format!("spawn: {e}"))
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

#[test]
fn cli_baseline_strict_allocator_zero_risk_known_index() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("baseline")?;
    let out = run_cli(&bin, "strict", "Allocator", 0, &[], &output)?;
    if !out.status.success() {
        return Err(format!(
            "derive-policy-key failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "policy_key",
        "kind must be policy_key",
    )?;
    // Known math: strict=mode_idx 0, Allocator=family_idx 1.
    // key_index = (((0*20 + 1) * 16 + 0) * 8 + 0) * 4 + 0 = 512.
    require(
        json_u64(&parsed, "key_index")? == 512,
        format!(
            "strict+Allocator+risk_ppm=0 → key_index=512; got {}",
            json_u64(&parsed, "key_index")?
        ),
    )?;
    require(
        json_u64(&parsed, "risk_bucket")? == 0,
        "risk_ppm=0 must yield risk_bucket=0",
    )?;
    require(
        json_u64(&parsed, "budget_bucket")? == 0,
        "no over-budget flags must yield budget_bucket=0",
    )?;
    require(
        json_u64(&parsed, "consistency_bucket")? == 0,
        "consistency_faults=0 must yield consistency_bucket=0",
    )
}

#[test]
fn cli_max_edge_hardened_poll_all_flags_max_consistency_yields_last_index() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("max_edge")?;
    let out = Command::new(&bin)
        .arg("derive-policy-key")
        .arg("--mode")
        .arg("hardened")
        .arg("--family")
        .arg("Poll")
        .arg("--risk-ppm")
        .arg("999999")
        .arg("--fast-over-budget")
        .arg("--full-over-budget")
        .arg("--pareto-exhausted")
        .arg("--consistency-faults")
        .arg("100")
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "derive-policy-key failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    // Known math: hardened=mode_idx 1, Poll=family_idx 19, all flags →
    // budget_bucket=7, consistency_faults=100 → bucket 3, risk 999999 → 15.
    // key_index = (((1*20+19)*16+15)*8+7)*4+3 = 20479.
    require(
        json_u64(&parsed, "key_index")? == 20479,
        format!(
            "max-edge inputs → key_index=20479; got {}",
            json_u64(&parsed, "key_index")?
        ),
    )?;
    require(
        json_u64(&parsed, "risk_bucket")? == 15,
        "risk_ppm=999999 must yield risk_bucket=15",
    )?;
    require(
        json_u64(&parsed, "budget_bucket")? == 7,
        "all three over-budget flags must yield budget_bucket=7",
    )?;
    require(
        json_u64(&parsed, "consistency_bucket")? == 3,
        "consistency_faults=100 must yield consistency_bucket=3 (>=4)",
    )?;
    // Pin upper bound: index strictly < total_table_len (20480).
    require(
        json_u64(&parsed, "key_index")? < 20480,
        "key_index must be < total_table_len=20480",
    )
}

#[test]
fn cli_mode_off_and_strict_produce_identical_key_index() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = unique_tmp("off")?;
    let b = unique_tmp("strict")?;
    let out_a = run_cli(&bin, "off", "Stdio", 250_000, &[], &a)?;
    let out_b = run_cli(&bin, "strict", "Stdio", 250_000, &[], &b)?;
    require(
        out_a.status.success() && out_b.status.success(),
        format!(
            "both runs must succeed; got status off={:?} strict={:?}",
            out_a.status, out_b.status
        ),
    )?;
    let pa = read_record(&a)?;
    let pb = read_record(&b)?;
    require(
        json_u64(&pa, "key_index")? == json_u64(&pb, "key_index")?,
        format!(
            "mode=off must map to same key_index as strict; got off={} strict={}",
            json_u64(&pa, "key_index")?,
            json_u64(&pb, "key_index")?
        ),
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
    let out_a = run_cli(
        &bin,
        "hardened",
        "VirtualMemory",
        500_000,
        &["--fast-over-budget"],
        &a,
    )?;
    let out_b = run_cli(
        &bin,
        "hardened",
        "VirtualMemory",
        500_000,
        &["--fast-over-budget"],
        &b,
    )?;
    require(
        out_a.status.success() && out_b.status.success(),
        "both runs must succeed",
    )?;
    let pa = read_record(&a)?;
    let pb = read_record(&b)?;
    require(pa == pb, "same inputs must produce identical output")
}

#[test]
fn cli_fails_closed_on_unknown_mode() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("bad_mode")?;
    let out = run_cli(&bin, "ludicrous", "Allocator", 0, &[], &output)?;
    require(
        !out.status.success(),
        "unknown --mode must yield non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("--mode must be strict|hardened|off"),
        "stderr must explain valid --mode values",
    )
}

#[test]
fn cli_fails_closed_on_unknown_family() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("bad_family")?;
    let out = run_cli(&bin, "strict", "NotARealFamily", 0, &[], &output)?;
    require(
        !out.status.success(),
        "unknown --family must yield non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("unknown ApiFamily"),
        "stderr must explain unknown family",
    )
}
