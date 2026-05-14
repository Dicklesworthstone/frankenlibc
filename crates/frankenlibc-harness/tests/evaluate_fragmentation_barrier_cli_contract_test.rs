//! Conformance gate for the harness binary `evaluate-fragmentation-barrier`
//! subcommand (bd-c4w0t).

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
        .join("evaluate_fragmentation_barrier_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_c4w0t_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_c4w0t_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "evaluate-fragmentation-barrier-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-c4w0t", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "evaluate-fragmentation-barrier",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::sos_barrier::evaluate_fragmentation_barrier",
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
            "max_stress_inputs_violate_certificate",
            "max_stress_inputs_violate_certificate must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_evaluate_fragmentation_barrier_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("EvaluateFragmentationBarrier {"),
        "harness.rs must declare EvaluateFragmentationBarrier Command variant",
    )?;
    require(
        src.contains("sos_barrier::evaluate_fragmentation_barrier"),
        "main() must import sos_barrier::evaluate_fragmentation_barrier",
    )?;
    require(
        src.contains("\"kind\": \"fragmentation_barrier\""),
        "EvaluateFragmentationBarrier arm must emit kind=fragmentation_barrier",
    )
}

fn run_cli(
    bin: &Path,
    alloc: u32,
    free: u32,
    size_ppm: u32,
    arena_ppm: u32,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("evaluate-fragmentation-barrier")
        .arg("--allocation-count")
        .arg(alloc.to_string())
        .arg("--free-count")
        .arg(free.to_string())
        .arg("--size-class-dispersion-ppm")
        .arg(size_ppm.to_string())
        .arg("--arena-utilization-ppm")
        .arg(arena_ppm.to_string())
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
fn cli_all_zero_inputs_certified_safe() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("safe")?;
    let out = run_cli(&bin, 0, 0, 0, 0, &output)?;
    if !out.status.success() {
        return Err(format!(
            "evaluate-fragmentation-barrier failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "fragmentation_barrier",
        "kind must be fragmentation_barrier",
    )?;
    require(
        json_bool(&parsed, "safe")?,
        "all-zero inputs must yield safe=true",
    )?;
    require(
        json_i64(&parsed, "headroom")? >= 0,
        format!(
            "safe=true requires headroom >= 0; got {}",
            json_i64(&parsed, "headroom")?
        ),
    )
}

#[test]
fn cli_max_stress_inputs_violate_certificate() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("stress")?;
    // Severe imbalance (1M allocs, 0 frees) + max size-class dispersion
    // + max arena utilization → certificate violation.
    let out = run_cli(&bin, 1_000_000, 0, 1_000_000, 1_000_000, &output)?;
    if !out.status.success() {
        return Err(format!(
            "evaluate-fragmentation-barrier failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "safe")?,
        "max-stress inputs must yield safe=false",
    )?;
    require(
        json_i64(&parsed, "headroom")? < 0,
        format!(
            "safe=false requires headroom < 0; got {}",
            json_i64(&parsed, "headroom")?
        ),
    )
}

#[test]
fn cli_safe_flag_matches_headroom_sign() -> TestResult {
    // Drive several arbitrary inputs and verify safe tracks nonnegative headroom.
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    for (label, alloc, free, size, arena) in [
        ("sign_balanced", 100u32, 100u32, 100u32, 100u32),
        ("sign_defragmenting", 50_000, 100_000, 500_000, 500_000),
        ("sign_minimal", 1, 1, 1, 1),
        ("sign_stressed", 10, 100_000, 999_999, 999_999),
    ] {
        let output = unique_tmp(label)?;
        let out = run_cli(&bin, alloc, free, size, arena, &output)?;
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
    let out_a = run_cli(&bin, 12345, 6789, 200_000, 750_000, &a)?;
    let out_b = run_cli(&bin, 12345, 6789, 200_000, 750_000, &b)?;
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
    let out = run_cli(&bin, 100, 200, 300_000, 400_000, &output)?;
    require(
        out.status.success(),
        format!(
            "evaluate-fragmentation-barrier failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    let parsed = read_record(&output)?;
    require(
        parsed.get("allocation_count").and_then(Value::as_u64) == Some(100),
        "allocation_count must echo",
    )?;
    require(
        parsed.get("free_count").and_then(Value::as_u64) == Some(200),
        "free_count must echo",
    )?;
    require(
        parsed
            .get("size_class_dispersion_ppm")
            .and_then(Value::as_u64)
            == Some(300_000),
        "size_class_dispersion_ppm must echo",
    )?;
    require(
        parsed.get("arena_utilization_ppm").and_then(Value::as_u64) == Some(400_000),
        "arena_utilization_ppm must echo",
    )
}
