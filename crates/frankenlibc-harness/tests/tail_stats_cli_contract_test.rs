//! Conformance gate for the harness binary `tail-stats`
//! subcommand (bd-t3fcw).

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
        .join("tail_stats_cli_contract.v1.json")
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

fn json_f64(value: &Value, field: &str) -> TestResult<f64> {
    value
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing or non-number `{field}`"))
}

fn harness_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_harness"))
}

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_t3fcw_{stem}_{}_{ts}.jsonl", std::process::id())))
}

fn write_samples(path: &Path, body: &str) -> TestResult {
    std::fs::write(path, body).map_err(|e| format!("write {path:?}: {e}"))
}

fn run_cli(bin: &Path, samples: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("tail-stats")
        .arg("--samples-json")
        .arg(samples)
        .arg("--seed")
        .arg("12345")
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_single_record(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read jsonl: {e}"))?;
    let lines = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>();
    require(
        lines.len() == 1,
        format!("expected exactly 1 JSONL record; got {}", lines.len()),
    )?;
    let line = lines
        .first()
        .copied()
        .ok_or_else(|| "missing output JSONL record".to_string())?;
    serde_json::from_str(line).map_err(|e| format!("parse output record: {e}"))
}

fn assert_failure_kind(record: &Value, expected: &str) -> TestResult {
    require(
        !json_bool(record, "ok")?,
        format!("{expected} case must yield ok=false"),
    )?;
    require(
        record.get("error_kind").and_then(Value::as_str) == Some(expected),
        format!(
            "expected error_kind={expected}; got {:?}",
            record.get("error_kind")
        ),
    )
}

fn approx_eq(a: f64, b: f64) -> bool {
    (a - b).abs() < 1.0e-9
}

#[test]
fn manifest_anchors_to_t3fcw_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "tail-stats-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-t3fcw", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "tail-stats",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")? == "frankenlibc_harness::tail_stats::compute",
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
            "ok_true_iff_error_kind_is_null",
            "ok_true_iff_error_kind_is_null must be true",
        ),
        (
            "exit_non_zero_when_ok_false",
            "exit_non_zero_when_ok_false must be true",
        ),
        (
            "missing_file_must_fail_closed",
            "missing_file_must_fail_closed must be true",
        ),
        (
            "invalid_json_must_fail_closed",
            "invalid_json_must_fail_closed must be true",
        ),
        (
            "non_array_root_must_fail_closed",
            "non_array_root_must_fail_closed must be true",
        ),
        (
            "empty_samples_must_fail_closed",
            "empty_samples_must_fail_closed must be true",
        ),
        (
            "non_numeric_samples_must_fail_closed",
            "non_numeric_samples_must_fail_closed must be true",
        ),
        (
            "same_samples_and_seed_must_be_deterministic",
            "same_samples_and_seed_must_be_deterministic must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_tail_stats_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("TailStats {"),
        "harness.rs must declare TailStats Command variant",
    )?;
    for (anchor, message) in [
        (
            "        samples_json",
            "TailStats variant missing field `samples_json`",
        ),
        ("        seed", "TailStats variant missing field `seed`"),
        ("        output", "TailStats variant missing field `output`"),
    ] {
        require(src.contains(anchor), message)?;
    }
    require(
        src.contains("tail_stats::compute"),
        "main() arm must call tail_stats::compute",
    )
}

#[test]
fn manifest_error_enum_covers_parser_and_compute_errors() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let kinds = json_array(
        m.get("jsonl_output_contract")
            .ok_or_else(|| "missing output contract".to_string())?,
        "error_kind_enum",
    )?;
    for (expected, message) in [
        ("io", "error_kind_enum missing io"),
        ("json", "error_kind_enum missing json"),
        ("root", "error_kind_enum missing root"),
        ("invalid_sample", "error_kind_enum missing invalid_sample"),
        (
            "non_finite_sample",
            "error_kind_enum missing non_finite_sample",
        ),
        ("empty", "error_kind_enum missing empty"),
        (
            "invalid_quantile",
            "error_kind_enum missing invalid_quantile",
        ),
    ] {
        require(kinds.iter().any(|v| v.as_str() == Some(expected)), message)?;
    }
    Ok(())
}

#[test]
fn cli_emits_tail_stats_for_valid_samples() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("ok_in")?;
    let output = unique_tmp("ok_out")?;
    write_samples(&input, "[10,20,30,40,50]")?;
    let out = run_cli(&bin, &input, &output)?;
    if !out.status.success() {
        return Err(format!(
            "tail-stats failed on valid samples: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_single_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "tail_stats_report",
        "kind must be tail_stats_report",
    )?;
    require(
        json_bool(&parsed, "ok")?,
        "valid samples must yield ok=true",
    )?;
    require(
        parsed.get("error_kind").is_some_and(Value::is_null),
        "ok=true must carry error_kind=null",
    )?;
    require(json_u64(&parsed, "n")? == 5, "n must be 5")?;
    require(
        json_u64(&parsed, "sample_count")? == 5,
        "sample_count must be 5",
    )?;
    require(approx_eq(json_f64(&parsed, "p50")?, 30.0), "p50")?;
    require(approx_eq(json_f64(&parsed, "p95")?, 48.0), "p95")?;
    require(approx_eq(json_f64(&parsed, "p99")?, 49.6), "p99")?;
    require(approx_eq(json_f64(&parsed, "p999")?, 49.96), "p999")?;
    require(
        json_f64(&parsed, "p99_ci_low")? <= json_f64(&parsed, "p99_ci_high")?,
        "p99 CI must be ordered",
    )?;
    require(
        !json_bool(&parsed, "sufficient_for_p99")?,
        "small sample must not be sufficient_for_p99",
    )?;
    require(
        json_u64(&parsed, "bootstrap_iters")? == 1000,
        "bootstrap_iters",
    )
}

#[test]
fn cli_is_deterministic_for_same_samples_and_seed() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("det_in")?;
    let output_a = unique_tmp("det_a_out")?;
    let output_b = unique_tmp("det_b_out")?;
    write_samples(&input, "[1,2,3,4,5,6,7,8,9,10]")?;
    let a = run_cli(&bin, &input, &output_a)?;
    let b = run_cli(&bin, &input, &output_b)?;
    require(a.status.success(), "first deterministic run failed")?;
    require(b.status.success(), "second deterministic run failed")?;
    require(
        read_single_record(&output_a)? == read_single_record(&output_b)?,
        "same samples and seed must emit identical JSON records",
    )
}

#[test]
fn cli_fails_closed_on_missing_file() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("missing_in")?;
    let output = unique_tmp("missing_out")?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "missing input must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "io")
}

#[test]
fn cli_fails_closed_on_invalid_json() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("json_in")?;
    let output = unique_tmp("json_out")?;
    write_samples(&input, "not json")?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "invalid JSON must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "json")
}

#[test]
fn cli_fails_closed_on_non_array_root() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("root_in")?;
    let output = unique_tmp("root_out")?;
    write_samples(&input, r#"{"samples":[1,2,3]}"#)?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "non-array root must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "root")
}

#[test]
fn cli_fails_closed_on_empty_samples() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("empty_in")?;
    let output = unique_tmp("empty_out")?;
    write_samples(&input, "[]")?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "empty samples must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "empty")
}

#[test]
fn cli_fails_closed_on_non_numeric_sample() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("sample_in")?;
    let output = unique_tmp("sample_out")?;
    write_samples(&input, r#"[1,"2",3]"#)?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "non-numeric sample must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "invalid_sample")
}
