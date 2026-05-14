//! Conformance gate for the harness binary `evaluate-provenance-barrier`
//! subcommand (bd-u5khi).

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
        .join("evaluate_provenance_barrier_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_u5khi_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_u5khi_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "evaluate-provenance-barrier-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-u5khi", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "evaluate-provenance-barrier",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::sos_barrier::evaluate_provenance_barrier",
        "underlying_lib_function",
    )?;
    let source_commit = json_string(&m, "source_commit")?;
    require(
        source_commit.len() == 40 && source_commit.chars().all(|c| c.is_ascii_hexdigit()),
        "source_commit must be a 40-character hex commit",
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
        "safe_iff_headroom_at_or_above_zero",
        "deterministic_given_inputs",
        "low_risk_full_validation_certified_safe",
        "high_risk_fast_path_with_bad_bloom_violates_certificate",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_evaluate_provenance_barrier_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("EvaluateProvenanceBarrier {"),
        "harness.rs must declare EvaluateProvenanceBarrier Command variant",
    )?;
    require(
        src.contains("sos_barrier::evaluate_provenance_barrier"),
        "main() must import sos_barrier::evaluate_provenance_barrier",
    )?;
    require(
        src.contains("\"kind\": \"provenance_barrier\""),
        "EvaluateProvenanceBarrier arm must emit kind=provenance_barrier",
    )
}

fn run_cli(
    bin: &Path,
    risk_ppm: u32,
    validation_depth_ppm: u32,
    bloom_fp_rate_ppm: u32,
    arena_pressure_ppm: u32,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("evaluate-provenance-barrier")
        .arg("--risk-ppm")
        .arg(risk_ppm.to_string())
        .arg("--validation-depth-ppm")
        .arg(validation_depth_ppm.to_string())
        .arg("--bloom-fp-rate-ppm")
        .arg(bloom_fp_rate_ppm.to_string())
        .arg("--arena-pressure-ppm")
        .arg(arena_pressure_ppm.to_string())
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
fn cli_low_risk_full_validation_certified_safe() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("safe")?;
    // No risk, full validation, clean bloom, low pressure -> safe.
    let out = run_cli(&bin, 0, 1_000_000, 0, 0, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "provenance_barrier",
        "kind must be provenance_barrier",
    )?;
    require(
        json_bool(&parsed, "safe")?,
        "low risk + full validation must yield safe=true",
    )?;
    require(
        json_i64(&parsed, "headroom")? >= 0,
        "safe=true requires headroom >= 0",
    )
}

#[test]
fn cli_high_risk_fast_path_with_bad_bloom_violates() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("violate")?;
    // Max risk + fast path + bad bloom + max arena pressure -> violation.
    let out = run_cli(&bin, 1_000_000, 0, 1_000_000, 1_000_000, &output)?;
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
    for (i, (r, v, b, p)) in [
        (50_000u32, 1_000_000u32, 1_000u32, 100_000u32),
        (200_000, 500_000, 100_000, 500_000),
        (500_000, 200_000, 500_000, 800_000),
        (1_000_000, 1_000_000, 0, 0),
    ]
    .iter()
    .enumerate()
    {
        let output = unique_tmp(&format!("sign_{i}"))?;
        let out = run_cli(&bin, *r, *v, *b, *p, &output)?;
        if !out.status.success() {
            return Err(format!(
                "case {i} stderr={}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let parsed = read_record(&output)?;
        let headroom = json_i64(&parsed, "headroom")?;
        let safe = json_bool(&parsed, "safe")?;
        require(
            safe == (headroom >= 0),
            format!(
                "case {i} ({r},{v},{b},{p}): safe={safe} headroom={headroom}; safe iff headroom>=0 broken"
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
    let a = unique_tmp("det_a")?;
    let b = unique_tmp("det_b")?;
    let out_a = run_cli(&bin, 100_000, 500_000, 200_000, 300_000, &a)?;
    let out_b = run_cli(&bin, 100_000, 500_000, 200_000, 300_000, &b)?;
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
    let out = run_cli(&bin, 11_111, 22_222, 33_333, 44_444, &output)?;
    require(
        out.status.success(),
        format!("stderr={}", String::from_utf8_lossy(&out.stderr)),
    )?;
    let parsed = read_record(&output)?;
    require(
        parsed.get("risk_ppm").and_then(Value::as_u64) == Some(11_111),
        "risk_ppm must echo",
    )?;
    require(
        parsed.get("validation_depth_ppm").and_then(Value::as_u64) == Some(22_222),
        "validation_depth_ppm must echo",
    )?;
    require(
        parsed.get("bloom_fp_rate_ppm").and_then(Value::as_u64) == Some(33_333),
        "bloom_fp_rate_ppm must echo",
    )?;
    require(
        parsed.get("arena_pressure_ppm").and_then(Value::as_u64) == Some(44_444),
        "arena_pressure_ppm must echo",
    )
}
