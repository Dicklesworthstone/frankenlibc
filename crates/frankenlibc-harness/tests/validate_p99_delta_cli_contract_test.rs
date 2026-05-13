//! Conformance gate for the harness binary `validate-p99-delta`
//! subcommand (bd-gfhc9).

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
        .join("validate_p99_delta_cli_contract.v1.json")
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

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn harness_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_harness"))
}

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_gfhc9_{stem}_{}_{ts}.jsonl", std::process::id())))
}

fn write_delta(path: &Path, body: &str) -> TestResult {
    std::fs::write(path, body).map_err(|e| format!("write {path:?}: {e}"))
}

fn run_cli(bin: &Path, jsonl: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("validate-p99-delta")
        .arg("--jsonl")
        .arg(jsonl)
        .arg("--allowed-budget-ns")
        .arg("100")
        .arg("--amplification-threshold")
        .arg("2.0")
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
    serde_json::from_str(lines[0]).map_err(|e| format!("parse output record: {e}"))
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

#[test]
fn manifest_anchors_to_gfhc9_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "validate-p99-delta-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-gfhc9", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "validate-p99-delta",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::tail_stats::validate_p99_delta_against_budget",
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
        "ok_true_iff_error_kind_is_null",
        "exit_non_zero_when_ok_false",
        "missing_file_must_fail_closed",
        "wrong_kind_must_fail_closed",
        "invalid_bool_must_fail_closed",
        "invalid_amplification_threshold_must_fail_closed",
        "insufficient_samples_must_fail_closed",
        "over_budget_must_fail_closed",
        "ci_indistinguishable_over_budget_must_fail_closed",
        "amplification_above_threshold_must_fail_closed",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_validate_p99_delta_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ValidateP99Delta {"),
        "harness.rs must declare ValidateP99Delta Command variant",
    )?;
    for field in [
        "jsonl",
        "allowed_budget_ns",
        "amplification_threshold",
        "output",
    ] {
        let anchor = format!("        {field}");
        require(
            src.contains(&anchor),
            format!("ValidateP99Delta variant missing field `{field}`"),
        )?;
    }
    require(
        src.contains("validate_p99_delta_against_budget"),
        "main() arm must call tail_stats::validate_p99_delta_against_budget",
    )
}

#[test]
fn manifest_error_enum_covers_validator_variants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let kinds = json_array(
        m.get("jsonl_output_contract")
            .ok_or_else(|| "missing output contract".to_string())?,
        "error_kind_enum",
    )?;
    for expected in [
        "over_budget",
        "amplification_above_threshold",
        "insufficient_samples",
        "ci_indistinguishable_but_over_budget",
    ] {
        require(
            kinds.iter().any(|v| v.as_str() == Some(expected)),
            format!("error_kind_enum missing {expected}"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_accepts_within_budget_delta() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("ok_in")?;
    let output = unique_tmp("ok_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","profile_id":"bd-gfhc9","p99_delta_ns":42.0,"ci_disjoint":true,"amplification_ratio":1.2,"sufficient_samples":true}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    if !out.status.success() {
        return Err(format!(
            "validate-p99-delta failed on valid row: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_single_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "p99_delta_validation",
        "kind must be p99_delta_validation",
    )?;
    require(json_bool(&parsed, "ok")?, "valid delta must yield ok=true")?;
    require(
        parsed.get("error_kind").is_some_and(Value::is_null),
        "ok=true must carry error_kind=null",
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
    write_delta(&input, "not json")?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "invalid JSON must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "json")
}

#[test]
fn cli_fails_closed_on_wrong_kind() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("kind_in")?;
    let output = unique_tmp("kind_out")?;
    write_delta(
        &input,
        r#"{"kind":"live_measurement_row","p99_delta_ns":1.0,"ci_disjoint":true,"amplification_ratio":1.0,"sufficient_samples":true}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "wrong kind must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "wrong_kind")
}

#[test]
fn cli_fails_closed_on_invalid_numeric_field() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("number_in")?;
    let output = unique_tmp("number_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","p99_delta_ns":"42","ci_disjoint":true,"amplification_ratio":1.0,"sufficient_samples":true}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    require(
        !out.status.success(),
        "invalid numeric field must fail closed",
    )?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "invalid_number")
}

#[test]
fn cli_fails_closed_on_invalid_bool_field() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("bool_in")?;
    let output = unique_tmp("bool_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","p99_delta_ns":42.0,"ci_disjoint":"true","amplification_ratio":1.0,"sufficient_samples":true}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "invalid bool field must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "invalid_bool")
}

#[test]
fn cli_fails_closed_on_invalid_amplification_threshold() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("threshold_in")?;
    let output = unique_tmp("threshold_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","p99_delta_ns":42.0,"ci_disjoint":true,"amplification_ratio":1.0,"sufficient_samples":true}"#,
    )?;
    let out = Command::new(&bin)
        .arg("validate-p99-delta")
        .arg("--jsonl")
        .arg(&input)
        .arg("--allowed-budget-ns")
        .arg("100")
        .arg("--amplification-threshold")
        .arg("0")
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "invalid amplification threshold must fail closed",
    )?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "invalid_amplification_threshold")
}

#[test]
fn cli_fails_closed_on_insufficient_samples() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("samples_in")?;
    let output = unique_tmp("samples_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","p99_delta_ns":1.0,"ci_disjoint":true,"amplification_ratio":1.0,"sufficient_samples":false}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    require(
        !out.status.success(),
        "insufficient samples must fail closed",
    )?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "insufficient_samples")
}

#[test]
fn cli_fails_closed_on_over_budget_delta() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("budget_in")?;
    let output = unique_tmp("budget_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","p99_delta_ns":101.0,"ci_disjoint":true,"amplification_ratio":1.0,"sufficient_samples":true}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    require(!out.status.success(), "over budget delta must fail closed")?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "over_budget")
}

#[test]
fn cli_fails_closed_on_ci_indistinguishable_over_budget_delta() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("ci_in")?;
    let output = unique_tmp("ci_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","p99_delta_ns":101.0,"ci_disjoint":false,"amplification_ratio":1.0,"sufficient_samples":true}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    require(
        !out.status.success(),
        "CI-indistinguishable over budget delta must fail closed",
    )?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "ci_indistinguishable_but_over_budget")
}

#[test]
fn cli_fails_closed_on_amplification_above_threshold() -> TestResult {
    let bin = harness_binary();
    let input = unique_tmp("amplification_in")?;
    let output = unique_tmp("amplification_out")?;
    write_delta(
        &input,
        r#"{"kind":"p99_delta","p99_delta_ns":1.0,"ci_disjoint":true,"amplification_ratio":2.1,"sufficient_samples":true}"#,
    )?;
    let out = run_cli(&bin, &input, &output)?;
    require(
        !out.status.success(),
        "amplification above threshold must fail closed",
    )?;
    let parsed = read_single_record(&output)?;
    assert_failure_kind(&parsed, "amplification_above_threshold")
}
