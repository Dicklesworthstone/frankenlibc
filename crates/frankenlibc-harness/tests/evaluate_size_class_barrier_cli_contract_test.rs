//! Conformance gate for the harness binary `evaluate-size-class-barrier`
//! subcommand (bd-51q2g).

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
        .join("evaluate_size_class_barrier_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_51q2g_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_51q2g_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "evaluate-size-class-barrier-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-51q2g", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "evaluate-size-class-barrier",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::sos_barrier::evaluate_size_class_barrier",
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
        "safe_iff_headroom_at_or_above_zero",
        "deterministic_given_inputs",
        "exact_class_size_match_with_valid_membership_certified_safe",
        "invalid_class_membership_violates_certificate",
        "underflow_violation_when_mapped_smaller_than_requested",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_evaluate_size_class_barrier_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("EvaluateSizeClassBarrier {"),
        "harness.rs must declare EvaluateSizeClassBarrier Command variant",
    )?;
    require(
        src.contains("sos_barrier::evaluate_size_class_barrier"),
        "main() must import sos_barrier::evaluate_size_class_barrier",
    )?;
    require(
        src.contains("\"kind\": \"size_class_barrier\""),
        "EvaluateSizeClassBarrier arm must emit kind=size_class_barrier",
    )
}

fn run_cli(
    bin: &Path,
    requested_size: usize,
    mapped_class_size: usize,
    membership_valid: bool,
    output: &Path,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("evaluate-size-class-barrier")
        .arg("--requested-size")
        .arg(requested_size.to_string())
        .arg("--mapped-class-size")
        .arg(mapped_class_size.to_string());
    if membership_valid {
        cmd.arg("--class-membership-valid");
    }
    cmd.arg("--output").arg(output);
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))
}

#[test]
fn cli_exact_size_with_valid_membership_certified_safe() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("safe")?;
    let out = run_cli(&bin, 64, 64, true, &output)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        json_string(&parsed, "kind")? == "size_class_barrier",
        "kind must be size_class_barrier",
    )?;
    require(
        json_bool(&parsed, "safe")?,
        "exact size + valid membership must yield safe=true",
    )?;
    require(
        json_i64(&parsed, "headroom")? >= 0,
        "safe=true requires headroom >= 0",
    )
}

#[test]
fn cli_invalid_class_membership_violates() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("invalid_mem")?;
    // Exact size match but invalid membership → violation via the
    // membership_violation_ppm penalty.
    let out = run_cli(&bin, 64, 64, false, &output)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !json_bool(&parsed, "safe")?,
        "invalid membership must yield safe=false",
    )?;
    require(
        json_i64(&parsed, "headroom")? < 0,
        "safe=false requires headroom < 0",
    )
}

#[test]
fn cli_underflow_mapped_smaller_than_requested_violates() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("underflow")?;
    // Requested 64 but mapped only 8 → underflow_violation_ppm fires.
    let out = run_cli(&bin, 64, 8, true, &output)?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&output);
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        !json_bool(&parsed, "safe")?,
        "underflow must yield safe=false",
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
    for (i, (req, mapped, valid)) in [
        (16usize, 16usize, true),
        (32, 64, true), // 100% waste
        (128, 128, false),
        (1, 1, true),
        (4096, 8192, true),
    ]
    .iter()
    .enumerate()
    {
        let output = unique_tmp(&format!("sign_{i}"))?;
        let out = run_cli(&bin, *req, *mapped, *valid, &output)?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&output);
            return Err(format!(
                "case {i} stderr={}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let parsed = read_record(&output)?;
        let _ = std::fs::remove_file(&output);
        let headroom = json_i64(&parsed, "headroom")?;
        let safe = json_bool(&parsed, "safe")?;
        require(
            safe == (headroom >= 0),
            format!(
                "case {i} ({req},{mapped},{valid}): safe={safe} headroom={headroom}; safe iff headroom>=0 broken"
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
    let out_a = run_cli(&bin, 100, 128, true, &a)?;
    let out_b = run_cli(&bin, 100, 128, true, &b)?;
    require(
        out_a.status.success() && out_b.status.success(),
        "both runs must succeed",
    )?;
    let pa = read_record(&a)?;
    let pb = read_record(&b)?;
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    require(pa == pb, "same inputs must produce identical output")
}

#[test]
fn cli_echoes_inputs_into_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let output = unique_tmp("echo")?;
    let out = run_cli(&bin, 256, 512, true, &output)?;
    require(
        out.status.success(),
        format!("stderr={}", String::from_utf8_lossy(&out.stderr)),
    )?;
    let parsed = read_record(&output)?;
    let _ = std::fs::remove_file(&output);
    require(
        parsed.get("requested_size").and_then(Value::as_u64) == Some(256),
        "requested_size must echo",
    )?;
    require(
        parsed.get("mapped_class_size").and_then(Value::as_u64) == Some(512),
        "mapped_class_size must echo",
    )?;
    require(
        parsed
            .get("class_membership_valid")
            .and_then(Value::as_bool)
            == Some(true),
        "class_membership_valid must echo",
    )
}
