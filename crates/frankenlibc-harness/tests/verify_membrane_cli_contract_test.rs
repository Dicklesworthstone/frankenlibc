//! Conformance gate for the harness binary `verify-membrane` subcommand (bd-ofe1b).
//!
//! Pins the CLI bridge over the healing-oracle pipeline:
//! - `frankenlibc_harness::healing_oracle::HealingOracleMode::from_str_loose`
//! - `frankenlibc_harness::healing_oracle::HealingOracleSuite::canonical`
//! - `frankenlibc_harness::healing_oracle::build_healing_oracle_report`

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
        .join("verify_membrane_cli_contract.v1.json")
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
    if let Some(bin) = option_env!("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(bin));
    }
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn tmp_dir() -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bd_ofe1b_{}_{ts}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_verify(
    bin: &Path,
    out: &Path,
    log: &Path,
    mode: &str,
    campaign: &str,
    fail_on_mismatch: bool,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("verify-membrane")
        .arg("--output")
        .arg(out)
        .arg("--log")
        .arg(log)
        .arg("--mode")
        .arg(mode)
        .arg("--campaign")
        .arg(campaign);
    if fail_on_mismatch {
        cmd.arg("--fail-on-mismatch");
    }
    cmd.output().map_err(|e| format!("spawn harness: {e}"))
}

#[test]
fn manifest_anchors_to_ofe1b_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "verify-membrane-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-ofe1b", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "verify-membrane",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "binary_target")? == "harness",
        "binary_target mismatch",
    )?;
    Ok(())
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_write_json_report_file",
        "must_write_jsonl_log_file",
        "report_mode_field_reflects_cli_mode",
        "report_campaign_field_reflects_cli_campaign",
        "summary_total_cases_equals_rows_length_per_active_mode",
        "mode_both_runs_strict_and_hardened_passes",
        "fail_on_mismatch_promotes_any_case_failure_to_nonzero_exit",
        "default_invocation_succeeds_with_zero_failed_cases",
        "unknown_mode_rejected_with_nonzero_exit",
        "deterministic_given_same_mode_campaign",
        "all_cases_pass_under_canonical_suite",
    ] {
        require(
            json_bool(policy, key)?,
            format!("policy.{key} must be true (manifest pin)"),
        )?;
    }
    Ok(())
}

#[test]
fn manifest_underlying_lib_functions_are_pinned() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let funcs = m
        .get("underlying_lib_functions")
        .and_then(Value::as_array)
        .ok_or("underlying_lib_functions missing")?;
    let names: Vec<&str> = funcs.iter().filter_map(Value::as_str).collect();
    for expected in [
        "frankenlibc_harness::healing_oracle::HealingOracleMode::from_str_loose",
        "frankenlibc_harness::healing_oracle::HealingOracleSuite::canonical",
        "frankenlibc_harness::healing_oracle::build_healing_oracle_report",
    ] {
        require(names.contains(&expected), format!("{expected} not pinned"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_verify_membrane_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::VerifyMembrane"),
        "harness.rs must register Command::VerifyMembrane match arm",
    )?;
    require(
        body.contains("build_healing_oracle_report"),
        "harness.rs must call build_healing_oracle_report",
    )?;
    require(
        body.contains("HealingOracleSuite::canonical"),
        "harness.rs must call HealingOracleSuite::canonical",
    )?;
    Ok(())
}

#[test]
fn cli_default_invocation_succeeds_with_zero_failures() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out = dir.join("report.json");
    let log = dir.join("trace.jsonl");
    let result = run_verify(&bin, &out, &log, "both", "gate_default", false)?;
    require(
        result.status.success(),
        format!("harness exit failed: {:?}", result.status),
    )?;
    require(out.exists(), "report file must be written")?;
    require(log.exists(), "log file must be written")?;
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&out).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    require(
        json_string(&report, "mode")? == "both",
        "report.mode must be both",
    )?;
    require(
        json_string(&report, "campaign")? == "gate_default",
        "report.campaign must roundtrip",
    )?;
    let summary = report.get("summary").ok_or("missing summary")?;
    require(
        json_u64(summary, "failed")? == 0,
        "canonical suite must report zero failures",
    )?;
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("missing cases array")?;
    require(
        cases.len() as u64 == json_u64(summary, "total_cases")?,
        "summary.total_cases must equal cases length",
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_mode_strict_only_passes_strict_rows() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out = dir.join("strict.json");
    let log = dir.join("strict.jsonl");
    let result = run_verify(&bin, &out, &log, "strict", "gate_strict", true)?;
    require(result.status.success(), "harness exit failed in strict")?;
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&out).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    require(
        json_string(&report, "mode")? == "strict",
        "report.mode must be strict",
    )?;
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("missing cases array")?;
    for case in cases {
        require(
            json_string(case, "mode")? == "strict",
            "every case row must have mode=strict",
        )?;
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_mode_hardened_only_passes_hardened_rows() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out = dir.join("hardened.json");
    let log = dir.join("hardened.jsonl");
    let result = run_verify(&bin, &out, &log, "hardened", "gate_hardened", true)?;
    require(result.status.success(), "harness exit failed in hardened")?;
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&out).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    require(
        json_string(&report, "mode")? == "hardened",
        "report.mode must be hardened",
    )?;
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("missing cases array")?;
    for case in cases {
        require(
            json_string(case, "mode")? == "hardened",
            "every case row must have mode=hardened",
        )?;
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_unknown_mode_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out = dir.join("bogus.json");
    let log = dir.join("bogus.jsonl");
    let result = run_verify(&bin, &out, &log, "lemonade", "gate_bogus", false)?;
    require(
        !result.status.success(),
        "harness must exit non-zero on unknown mode",
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_deterministic_given_same_mode_campaign() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out_a = dir.join("det_a.json");
    let out_b = dir.join("det_b.json");
    let log_a = dir.join("det_a.jsonl");
    let log_b = dir.join("det_b.jsonl");
    let _ = run_verify(&bin, &out_a, &log_a, "both", "gate_det", false)?;
    let _ = run_verify(&bin, &out_b, &log_b, "both", "gate_det", false)?;
    let a: Value =
        serde_json::from_str(&std::fs::read_to_string(&out_a).map_err(|e| format!("read a: {e}"))?)
            .map_err(|e| format!("parse a: {e}"))?;
    let b: Value =
        serde_json::from_str(&std::fs::read_to_string(&out_b).map_err(|e| format!("read b: {e}"))?)
            .map_err(|e| format!("parse b: {e}"))?;
    let strip = |mut v: Value| -> Value {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("generated_at_utc");
        }
        v
    };
    require(
        strip(a) == strip(b),
        "report bodies must match across runs (ignoring generated_at_utc)",
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_summary_total_cases_equals_rows_length() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out = dir.join("tally.json");
    let log = dir.join("tally.jsonl");
    let _ = run_verify(&bin, &out, &log, "both", "gate_tally", false)?;
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&out).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    let summary = report.get("summary").ok_or("missing summary")?;
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("missing cases")?;
    require(
        cases.len() as u64 == json_u64(summary, "total_cases")?,
        "summary.total_cases must equal cases length",
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
