//! Conformance gate for the harness binary `seqlock-model-check`
//! subcommand (bd-gdotb).

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
        .join("seqlock_model_check_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_gdotb_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_gdotb_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "seqlock-model-check-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-gdotb", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "seqlock-model-check",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::concurrency_model_check::check_seqlock",
        "underlying_lib_function",
    )?;
    require(
        m.get("write_count_cap").and_then(Value::as_u64) == Some(4),
        "write_count_cap must be 4",
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
        "invariant_violation_count_must_be_zero_for_all_well_formed_inputs",
        "stable_outcomes_plus_retry_outcomes_must_equal_schedules_explored",
        "schedules_explored_must_be_positive",
        "fail_closed_on_write_count_zero",
        "fail_closed_on_write_count_above_cap",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_seqlock_model_check_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("SeqlockModelCheck {"),
        "harness.rs must declare SeqlockModelCheck Command variant",
    )?;
    require(
        src.contains("concurrency_model_check::{")
            && src.contains("InvariantViolation, check_seqlock"),
        "main() must import InvariantViolation + check_seqlock",
    )?;
    require(
        src.contains("\"kind\": \"seqlock_model_report\""),
        "SeqlockModelCheck arm must emit kind=seqlock_model_report",
    )
}

fn run_cli(bin: &Path, write_count: &str, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("seqlock-model-check")
        .arg("--write-count")
        .arg(write_count)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

#[test]
fn cli_zero_violations_and_partition_balance_for_write_count_two() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("ok")?;
    let out = run_cli(&bin, "2", &tmp)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "seqlock-model-check failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = std::fs::read_to_string(&tmp).map_err(|e| format!("read jsonl: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    require(
        lines.len() == 1,
        format!("expected exactly 1 JSONL record; got {}", lines.len()),
    )?;
    let parsed: Value = serde_json::from_str(lines[0]).map_err(|e| format!("parse: {e}"))?;
    require(
        json_string(&parsed, "kind")? == "seqlock_model_report",
        "kind must be seqlock_model_report",
    )?;
    require(
        json_u64(&parsed, "write_count")? == 2,
        "write_count must round-trip",
    )?;
    let explored = json_u64(&parsed, "schedules_explored")?;
    let stable = json_u64(&parsed, "stable_outcomes")?;
    let retry = json_u64(&parsed, "retry_outcomes")?;
    require(explored > 0, "schedules_explored must be positive")?;
    require(
        stable + retry == explored,
        format!(
            "stable_outcomes + retry_outcomes must equal schedules_explored; got {stable}+{retry} != {explored}"
        ),
    )?;
    require(
        json_u64(&parsed, "invariant_violation_count")? == 0,
        "well-formed inputs must produce zero invariant violations",
    )?;
    require(
        json_array(&parsed, "invariant_violations")?.is_empty(),
        "invariant_violations array must be empty when count is zero",
    )
}

#[test]
fn cli_fails_closed_on_write_count_zero() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("zero")?;
    let out = run_cli(&bin, "0", &tmp)?;
    let _ = std::fs::remove_file(&tmp);
    require(
        !out.status.success(),
        "seqlock-model-check must exit non-zero when --write-count=0",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("--write-count must be > 0"),
        "stderr must explain why --write-count=0 is rejected",
    )
}

#[test]
fn cli_fails_closed_on_write_count_above_cap() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("cap")?;
    let out = run_cli(&bin, "5", &tmp)?;
    let _ = std::fs::remove_file(&tmp);
    require(
        !out.status.success(),
        "seqlock-model-check must exit non-zero when --write-count exceeds cap",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("must be <= 4"),
        "stderr must explain why --write-count above cap is rejected",
    )
}
