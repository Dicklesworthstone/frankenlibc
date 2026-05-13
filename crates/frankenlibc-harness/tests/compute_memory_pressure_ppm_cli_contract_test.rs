//! Conformance gate for the harness binary `compute-memory-pressure-ppm`
//! subcommand (bd-vd6rg).

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
        .join("compute_memory_pressure_ppm_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_vd6rg_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_vd6rg_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "compute-memory-pressure-ppm-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-vd6rg", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "compute-memory-pressure-ppm",
        "subcommand_name",
    )?;
    let funcs = m
        .get("underlying_lib_functions")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing underlying_lib_functions".to_string())?;
    let want = [
        "frankenlibc_membrane::runtime_math::sos_barrier::depth_to_arena_utilization_ppm",
        "frankenlibc_membrane::runtime_math::sos_barrier::compose_memory_pressure_ppm",
    ];
    for w in want {
        require(
            funcs.iter().any(|v| v.as_str() == Some(w)),
            format!("missing {w}"),
        )?;
    }
    Ok(())
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
        "depth_at_or_below_floor_yields_zero_arena_ppm",
        "depth_at_max_yields_maximum_arena_ppm",
        "depth_arena_ppm_is_monotone_nondecreasing_in_depth",
        "composed_ppm_at_or_above_depth_arena_ppm",
        "composed_ppm_clamped_to_unit_ppm_max",
        "all_zero_pressure_with_floor_depth_yields_zero_composed",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_compute_memory_pressure_ppm_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ComputeMemoryPressurePpm {"),
        "harness.rs must declare ComputeMemoryPressurePpm Command variant",
    )?;
    require(
        src.contains("sos_barrier::depth_to_arena_utilization_ppm")
            || src.contains("depth_to_arena_utilization_ppm,"),
        "match arm must import depth_to_arena_utilization_ppm",
    )?;
    require(
        src.contains("compose_memory_pressure_ppm"),
        "match arm must import compose_memory_pressure_ppm",
    )?;
    require(
        src.contains("\"kind\": \"memory_pressure_ppm\""),
        "ComputeMemoryPressurePpm arm must emit kind=memory_pressure_ppm",
    )
}

fn run_cli(
    bin: &Path,
    depth: u32,
    pressure_score_milli: u64,
    pressure_raw_score_milli: u64,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("compute-memory-pressure-ppm")
        .arg("--depth")
        .arg(depth.to_string())
        .arg("--pressure-score-milli")
        .arg(pressure_score_milli.to_string())
        .arg("--pressure-raw-score-milli")
        .arg(pressure_raw_score_milli.to_string())
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))
}

fn run_and_parse(bin: &Path, depth: u32, score: u64, raw: u64, label: &str) -> TestResult<Value> {
    let output = unique_tmp(label)?;
    let out = run_cli(bin, depth, score, raw, &output)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    Ok(parsed)
}

#[test]
fn cli_depth_at_floor_yields_zero_depth_ppm() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // depth=64 is the clamp floor -> normalized to 0 ppm.
    let parsed = run_and_parse(&bin, 64, 0, 0, "floor")?;
    require(
        json_string(&parsed, "kind")? == "memory_pressure_ppm",
        "kind must be memory_pressure_ppm",
    )?;
    require(
        json_u64(&parsed, "depth_arena_utilization_ppm")? == 0,
        "depth=64 (floor) must yield depth_arena_utilization_ppm=0",
    )?;
    // With all-zero pressure inputs at floor depth, composed must also be 0.
    require(
        json_u64(&parsed, "composed_pressure_ppm")? == 0,
        "all-zero pressure at floor depth must yield composed=0",
    )
}

#[test]
fn cli_depth_below_floor_clamps_to_zero() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // depth=32 is below the [64, 65536] clamp floor -> still 0 ppm.
    let parsed = run_and_parse(&bin, 32, 0, 0, "below_floor")?;
    require(
        json_u64(&parsed, "depth_arena_utilization_ppm")? == 0,
        "depth=32 (below floor) must clamp to 0",
    )
}

#[test]
fn cli_depth_at_max_yields_unit_ppm() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // depth=65536 is the clamp ceiling -> normalized to 1_000_000 ppm.
    let parsed = run_and_parse(&bin, 65_536, 0, 0, "ceiling")?;
    require(
        json_u64(&parsed, "depth_arena_utilization_ppm")? == 1_000_000,
        "depth=65536 must yield depth_arena_utilization_ppm=1_000_000",
    )
}

#[test]
fn cli_depth_ppm_monotone_nondecreasing() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let mut prev: u64 = 0;
    for &d in &[64u32, 1024, 8192, 32768, 65_536] {
        let parsed = run_and_parse(&bin, d, 0, 0, &format!("mono_{d}"))?;
        let p = json_u64(&parsed, "depth_arena_utilization_ppm")?;
        require(
            p >= prev,
            format!("depth_ppm must be nondecreasing: depth={d} prev={prev} got={p}"),
        )?;
        prev = p;
    }
    Ok(())
}

#[test]
fn cli_composed_at_or_above_depth_ppm_and_clamped_to_unit_ppm() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    for (i, (depth, score, raw)) in [
        (1024u32, 10_000u64, 12_000u64),
        (60_000, 90_000, 99_999),
        (8_192, 50_000, 100_000),
        (32_768, 0, 100_000),
        (65_536, 100_000, 100_000),
    ]
    .iter()
    .enumerate()
    {
        let parsed = run_and_parse(&bin, *depth, *score, *raw, &format!("comp_{i}"))?;
        let depth_ppm = json_u64(&parsed, "depth_arena_utilization_ppm")?;
        let composed = json_u64(&parsed, "composed_pressure_ppm")?;
        require(
            composed >= depth_ppm,
            format!(
                "case {i} (d={depth},s={score},r={raw}): composed={composed} must be >= depth_ppm={depth_ppm}"
            ),
        )?;
        require(
            composed <= 1_000_000,
            format!(
                "case {i} (d={depth},s={score},r={raw}): composed={composed} must be <= 1_000_000"
            ),
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
    let a = run_and_parse(&bin, 4096, 25_000, 30_000, "det_a")?;
    let b = run_and_parse(&bin, 4096, 25_000, 30_000, "det_b")?;
    require(a == b, "same inputs must produce identical output")
}

#[test]
fn cli_echoes_inputs_into_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, 13_579, 24_680, 35_791, "echo")?;
    require(json_u64(&parsed, "depth")? == 13_579, "depth must echo")?;
    require(
        json_u64(&parsed, "pressure_score_milli")? == 24_680,
        "pressure_score_milli must echo",
    )?;
    require(
        json_u64(&parsed, "pressure_raw_score_milli")? == 35_791,
        "pressure_raw_score_milli must echo",
    )
}
