//! Conformance gate for the harness binary `derive-repair-math`
//! subcommand (bd-qxh1x).

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
        .join("derive_repair_math_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_qxh1x_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_qxh1x_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "derive-repair-math-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-qxh1x", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "derive-repair-math",
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
    for (field, message) in [
        (
            "must_emit_exactly_one_jsonl_record",
            "must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "r_repair_zero_when_k_source_zero",
            "r_repair_zero_when_k_source_zero must be true",
        ),
        (
            "loss_fraction_zero_when_k_source_zero",
            "loss_fraction_zero_when_k_source_zero must be true",
        ),
        (
            "loss_fraction_max_ppm_at_or_below_1_000_000",
            "loss_fraction_max_ppm_at_or_below_1_000_000 must be true",
        ),
        (
            "r_repair_at_or_above_slack_decode_when_k_source_positive",
            "r_repair_at_or_above_slack_decode_when_k_source_positive must be true",
        ),
        (
            "echoes_inputs_into_output_record",
            "echoes_inputs_into_output_record must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_derive_repair_math_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("DeriveRepairMath {"),
        "harness.rs must declare DeriveRepairMath Command variant",
    )?;
    require(
        src.contains("derive_repair_symbol_count_v1") && src.contains("loss_fraction_max_ppm_v1"),
        "main() must import both repair-math helpers",
    )?;
    require(
        src.contains("\"kind\": \"repair_math\""),
        "DeriveRepairMath arm must emit kind=repair_math",
    )
}

fn run_cli(
    bin: &Path,
    k_source: &str,
    overhead_percent: &str,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("derive-repair-math")
        .arg("--k-source")
        .arg(k_source)
        .arg("--overhead-percent")
        .arg(overhead_percent)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

#[test]
fn cli_zero_k_source_yields_zero_r_repair_and_loss_fraction() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("zero")?;
    let out = run_cli(&bin, "0", "10", &output)?;
    if !out.status.success() {
        return Err(format!(
            "derive-repair-math failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "repair_math",
        "kind must be repair_math",
    )?;
    require(
        json_u64(&parsed, "k_source")? == 0 && json_u64(&parsed, "overhead_percent")? == 10,
        "inputs must round-trip",
    )?;
    require(
        json_u64(&parsed, "r_repair")? == 0,
        "k_source=0 must yield r_repair=0",
    )?;
    require(
        json_u64(&parsed, "loss_fraction_max_ppm")? == 0,
        "k_source=0 must yield loss_fraction_max_ppm=0",
    )
}

#[test]
fn cli_baseline_k_source_100_overhead_10_matches_known_math() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("baseline")?;
    let out = run_cli(&bin, "100", "10", &output)?;
    if !out.status.success() {
        return Err(format!(
            "derive-repair-math failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    // R = max(slack_decode=2, ceil(100*10/100)=10) = 10.
    require(
        json_u64(&parsed, "r_repair")? == 10,
        format!(
            "k_source=100 overhead=10 must yield r_repair=10; got {}",
            json_u64(&parsed, "r_repair")?
        ),
    )?;
    // loss_fraction = (R - slack) / (K + R) = 8/110 ≈ 72727ppm.
    require(
        json_u64(&parsed, "loss_fraction_max_ppm")? == 72727,
        format!(
            "k_source=100 overhead=10 must yield loss_fraction_max_ppm=72727; got {}",
            json_u64(&parsed, "loss_fraction_max_ppm")?
        ),
    )?;
    require(
        json_u64(&parsed, "slack_decode")? == 2,
        "slack_decode constant must echo 2",
    )
}

#[test]
fn cli_loss_fraction_clamped_at_ppm_cap_for_high_overhead() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("ppm_cap")?;
    // Drive r_repair high enough that the algebraic loss fraction
    // approaches 1.0 — saturating arithmetic + the explicit min(...,
    // 1_000_000) cap inside loss_fraction_max_ppm_v1 must not produce
    // a value above the ppm cap.
    let out = run_cli(&bin, "1", "65535", &output)?;
    if !out.status.success() {
        return Err(format!(
            "derive-repair-math failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_u64(&parsed, "loss_fraction_max_ppm")? <= 1_000_000,
        format!(
            "loss_fraction_max_ppm must not exceed 1_000_000; got {}",
            json_u64(&parsed, "loss_fraction_max_ppm")?
        ),
    )
}

#[test]
fn cli_r_repair_at_or_above_slack_decode_for_positive_k_source() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("slack_floor")?;
    // overhead=0 with k_source>0 must still yield r_repair>=slack_decode (=2).
    let out = run_cli(&bin, "50", "0", &output)?;
    if !out.status.success() {
        return Err(format!(
            "derive-repair-math failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_u64(&parsed, "r_repair")? >= json_u64(&parsed, "slack_decode")?,
        "r_repair must not fall below slack_decode for k_source>0",
    )?;
    require(
        json_u64(&parsed, "r_repair")? == 2,
        "overhead=0 + k_source>0 must yield r_repair=slack_decode=2",
    )
}
