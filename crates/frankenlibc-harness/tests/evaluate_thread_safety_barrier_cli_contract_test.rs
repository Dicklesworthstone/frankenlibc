//! Conformance gate for the harness binary `evaluate-thread-safety-barrier`
//! subcommand (bd-fq2t0).

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
        .join("evaluate_thread_safety_barrier_cli_contract.v1.json")
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

fn json_i64(value: &Value, field: &str) -> TestResult<i64> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing or non-i64 `{field}`"))
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
    Ok(std::env::temp_dir().join(format!("bd_fq2t0_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_fq2t0_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "evaluate-thread-safety-barrier-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-fq2t0", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "evaluate-thread-safety-barrier",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::sos_barrier::evaluate_thread_safety_barrier",
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
            "must_emit_exactly_one_jsonl_record",
            "must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "echoes_inputs_into_output_record",
            "echoes_inputs_into_output_record must be true",
        ),
        (
            "safe_iff_headroom_at_or_above_zero",
            "safe_iff_headroom_at_or_above_zero must be true",
        ),
        (
            "deterministic_given_inputs",
            "deterministic_given_inputs must be true",
        ),
        (
            "all_zero_inputs_certified_safe",
            "all_zero_inputs_certified_safe must be true",
        ),
        (
            "owner_conflict_with_max_telemetry_violates_certificate",
            "owner_conflict_with_max_telemetry_violates_certificate must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_evaluate_thread_safety_barrier_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("EvaluateThreadSafetyBarrier {"),
        "harness.rs must declare EvaluateThreadSafetyBarrier Command variant",
    )?;
    require(
        src.contains("sos_barrier::evaluate_thread_safety_barrier"),
        "main() must import sos_barrier::evaluate_thread_safety_barrier",
    )?;
    require(
        src.contains("\"kind\": \"thread_safety_barrier\""),
        "EvaluateThreadSafetyBarrier arm must emit kind=thread_safety_barrier",
    )
}

#[allow(clippy::too_many_arguments)]
fn run_cli(
    bin: &Path,
    thread_count: u32,
    concurrent_writers: u32,
    arena_owner_conflict: bool,
    free_list_skew_ppm: u32,
    allocation_epoch_lag_ppm: u32,
    output: &Path,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("evaluate-thread-safety-barrier")
        .arg("--thread-count")
        .arg(thread_count.to_string())
        .arg("--concurrent-writers")
        .arg(concurrent_writers.to_string())
        .arg("--free-list-skew-ppm")
        .arg(free_list_skew_ppm.to_string())
        .arg("--allocation-epoch-lag-ppm")
        .arg(allocation_epoch_lag_ppm.to_string());
    if arena_owner_conflict {
        cmd.arg("--arena-owner-conflict");
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
fn cli_all_zero_inputs_certified_safe() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("safe")?;
    let out = run_cli(&bin, 0, 0, false, 0, 0, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "thread_safety_barrier",
        "kind must be thread_safety_barrier",
    )?;
    require(
        json_bool(&parsed, "safe")?,
        "all-zero inputs must yield safe=true",
    )?;
    require(
        json_i64(&parsed, "headroom")? >= 0,
        "safe=true requires headroom >= 0",
    )
}

#[test]
fn cli_owner_conflict_with_max_telemetry_violates() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("violate")?;
    let out = run_cli(&bin, 10_000, 10_000, true, 1_000_000, 1_000_000, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "safe")?,
        "max-stress inputs must yield safe=false",
    )?;
    require(
        json_i64(&parsed, "headroom")? < 0,
        "safe=false requires headroom < 0",
    )
}

#[test]
fn cli_safe_flag_matches_headroom_sign() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    for (label, t, w, conflict, skew, lag) in [
        ("sign_nominal", 1u32, 1u32, false, 0u32, 0u32),
        ("sign_moderate", 100, 5, false, 50_000, 100_000),
        ("sign_conflict", 1000, 50, true, 500_000, 500_000),
        ("sign_boundary", 4, 4, true, 999_999, 999_999),
    ] {
        let output = unique_tmp(label)?;
        let out = run_cli(&bin, t, w, conflict, skew, lag, &output)?;
        if !out.status.success() {
            return Err("sign-case CLI invocation must succeed".into());
        }
        let parsed = read_record(&output)?;
        let headroom = json_i64(&parsed, "headroom")?;
        let safe = json_bool(&parsed, "safe")?;
        require(
            safe == (headroom >= 0),
            "safe flag must match headroom sign for every sign-case input",
        )?;
    }
    Ok(())
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = unique_tmp("det_a")?;
    let b = unique_tmp("det_b")?;
    let out_a = run_cli(&bin, 50, 8, true, 250_000, 100_000, &a)?;
    let out_b = run_cli(&bin, 50, 8, true, 250_000, 100_000, &b)?;
    require(
        out_a.status.success() && out_b.status.success(),
        "both runs must succeed",
    )?;
    let pa = read_record(&a)?;
    let pb = read_record(&b)?;
    require(pa == pb, "same inputs must produce identical output")
}

#[test]
fn cli_echoes_inputs_into_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("echo")?;
    let out = run_cli(&bin, 42, 7, true, 123_456, 789_012, &output)?;
    require(
        out.status.success(),
        format!("stderr={}", String::from_utf8_lossy(&out.stderr)),
    )?;
    let parsed = read_record(&output)?;
    require(
        parsed.get("thread_count").and_then(Value::as_u64) == Some(42),
        "thread_count must echo",
    )?;
    require(
        parsed.get("concurrent_writers").and_then(Value::as_u64) == Some(7),
        "concurrent_writers must echo",
    )?;
    require(
        parsed.get("arena_owner_conflict").and_then(Value::as_bool) == Some(true),
        "arena_owner_conflict must echo",
    )?;
    require(
        parsed.get("free_list_skew_ppm").and_then(Value::as_u64) == Some(123_456),
        "free_list_skew_ppm must echo",
    )?;
    require(
        parsed
            .get("allocation_epoch_lag_ppm")
            .and_then(Value::as_u64)
            == Some(789_012),
        "allocation_epoch_lag_ppm must echo",
    )
}
