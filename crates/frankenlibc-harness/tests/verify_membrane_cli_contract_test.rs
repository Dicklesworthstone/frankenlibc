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

fn json_usize(value: &Value, field: &str) -> TestResult<usize> {
    let raw = json_u64(value, field)?;
    usize::try_from(raw).map_err(|_| format!("`{field}` does not fit usize"))
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

fn find_harness_binary() -> TestResult<PathBuf> {
    if let Some(bin) = std::env::var_os("FRANKENLIBC_HARNESS_BIN") {
        return Ok(PathBuf::from(bin));
    }
    if let Some(bin) = option_env!("CARGO_BIN_EXE_harness") {
        return Ok(PathBuf::from(bin));
    }
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("harness binary not built; this gate cannot pass without execution".into())
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
    let library = std::env::var_os("FRANKENLIBC_HEALING_LIBRARY")
        .ok_or("set FRANKENLIBC_HEALING_LIBRARY to the fresh release ABI library")?;
    let probe = std::env::var_os("FRANKENLIBC_HEALING_PROBE")
        .ok_or("set FRANKENLIBC_HEALING_PROBE to fixture_malloc compiled with -fno-builtin -ldl")?;
    cmd.arg("verify-membrane")
        .arg("--library")
        .arg(library)
        .arg("--probe")
        .arg(probe)
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
    for (key, message) in [
        (
            "must_write_json_report_file",
            "policy.must_write_json_report_file must be true (manifest pin)",
        ),
        (
            "must_write_jsonl_log_file",
            "policy.must_write_jsonl_log_file must be true (manifest pin)",
        ),
        (
            "report_mode_field_reflects_cli_mode",
            "policy.report_mode_field_reflects_cli_mode must be true (manifest pin)",
        ),
        (
            "report_campaign_field_reflects_cli_campaign",
            "policy.report_campaign_field_reflects_cli_campaign must be true (manifest pin)",
        ),
        (
            "summary_total_cases_equals_rows_length_per_active_mode",
            "policy.summary_total_cases_equals_rows_length_per_active_mode must be true (manifest pin)",
        ),
        (
            "mode_both_runs_strict_and_hardened_passes",
            "policy.mode_both_runs_strict_and_hardened_passes must be true (manifest pin)",
        ),
        (
            "fail_on_mismatch_promotes_any_case_failure_to_nonzero_exit",
            "policy.fail_on_mismatch_promotes_any_case_failure_to_nonzero_exit must be true (manifest pin)",
        ),
        (
            "default_invocation_with_artifacts_succeeds_with_zero_failed_cases",
            "valid explicit artifacts must produce a successful default run",
        ),
        (
            "missing_artifacts_or_observations_fail_by_default",
            "missing evidence must fail without an optional flag",
        ),
        (
            "unknown_mode_rejected_with_nonzero_exit",
            "policy.unknown_mode_rejected_with_nonzero_exit must be true (manifest pin)",
        ),
        (
            "deterministic_contract_outcomes_given_same_artifacts_mode_campaign",
            "contract outcomes must be deterministic for the same artifacts and inputs",
        ),
        (
            "all_cases_pass_under_canonical_suite",
            "policy.all_cases_pass_under_canonical_suite must be true (manifest pin)",
        ),
    ] {
        require(json_bool(policy, key)?, message)?;
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
    for (expected, message) in [
        (
            "frankenlibc_harness::healing_oracle::HealingOracleMode::from_str_loose",
            "HealingOracleMode::from_str_loose not pinned",
        ),
        (
            "frankenlibc_harness::healing_oracle::HealingOracleSuite::canonical",
            "HealingOracleSuite::canonical not pinned",
        ),
        (
            "frankenlibc_harness::healing_oracle::build_healing_oracle_report",
            "build_healing_oracle_report not pinned",
        ),
    ] {
        require(names.contains(&expected), message)?;
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
    let bin = find_harness_binary()?;
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
        cases.len() == 28 && cases.len() == json_usize(summary, "total_cases")?,
        "summary.total_cases must equal cases length",
    )?;
    Ok(())
}

#[test]
fn cli_mode_strict_only_passes_strict_rows() -> TestResult {
    let bin = find_harness_binary()?;
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
    require(
        cases.len() == 14,
        "strict gate must execute fourteen controls",
    )?;
    for case in cases {
        require(
            json_string(case, "mode")? == "strict",
            "every case row must have mode=strict",
        )?;
    }
    Ok(())
}

#[test]
fn cli_mode_hardened_only_passes_hardened_rows() -> TestResult {
    let bin = find_harness_binary()?;
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
    require(
        cases.len() == 14,
        "hardened gate must execute fourteen faults",
    )?;
    for case in cases {
        require(
            json_string(case, "mode")? == "hardened",
            "every case row must have mode=hardened",
        )?;
    }
    Ok(())
}

#[test]
fn cli_unknown_mode_rejected_with_nonzero_exit() -> TestResult {
    let bin = find_harness_binary()?;
    let dir = tmp_dir()?;
    let out = dir.join("bogus.json");
    let log = dir.join("bogus.jsonl");
    let result = run_verify(&bin, &out, &log, "lemonade", "gate_bogus", false)?;
    require(
        !result.status.success(),
        "harness must exit non-zero on unknown mode",
    )?;
    Ok(())
}

#[test]
fn cli_deterministic_given_same_mode_campaign() -> TestResult {
    let bin = find_harness_binary()?;
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
        // ASLR-dependent allocation canaries are raw evidence, not a stable
        // answer. Each execution separately checks that its canary is intact.
        if let Some(cases) = v.get_mut("cases").and_then(Value::as_array_mut) {
            for case in cases {
                if let Some(raw) = case.get_mut("observation").and_then(Value::as_object_mut) {
                    raw.remove("guard_before");
                    raw.remove("guard_after");
                }
            }
        }
        v
    };
    require(
        strip(a) == strip(b),
        "report bodies must match across runs (ignoring generated_at_utc)",
    )?;
    Ok(())
}

#[test]
fn cli_summary_total_cases_equals_rows_length() -> TestResult {
    let bin = find_harness_binary()?;
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
        cases.len() == json_usize(summary, "total_cases")?,
        "summary.total_cases must equal cases length",
    )?;
    Ok(())
}

#[test]
fn cli_missing_artifacts_is_not_a_green_default() -> TestResult {
    let output = Command::new(find_harness_binary()?)
        .arg("verify-membrane")
        .output()
        .map_err(|e| e.to_string())?;
    require(!output.status.success(), "missing artifacts must fail")
}

#[test]
fn cli_empty_observations_fail_even_without_fail_flag() -> TestResult {
    let dir = tmp_dir()?;
    let report = dir.join("empty.json");
    let output = Command::new(find_harness_binary()?)
        .args([
            "verify-membrane",
            "--library",
            "/bin/true",
            "--probe",
            "/bin/true",
        ])
        .arg("--output")
        .arg(&report)
        .arg("--log")
        .arg(dir.join("empty.jsonl"))
        .output()
        .map_err(|e| e.to_string())?;
    require(
        !output.status.success(),
        "zero-exit empty output must fail by default",
    )?;
    let body = load_json(&report)?;
    require(
        body["summary"]["passed"] == 0 && body["summary"]["failed"] == 28,
        "every unobserved case must fail",
    )
}

#[test]
fn cli_wrong_provider_fails_real_probe() -> TestResult {
    let dir = tmp_dir()?;
    let probe = std::env::var_os("FRANKENLIBC_HEALING_PROBE")
        .ok_or("set FRANKENLIBC_HEALING_PROBE for the live provider-negative gate")?;
    let report = dir.join("wrong-provider.json");
    let output = Command::new(find_harness_binary()?)
        .args(["verify-membrane", "--library", "/bin/true", "--probe"])
        .arg(probe)
        .arg("--output")
        .arg(&report)
        .arg("--log")
        .arg(dir.join("wrong-provider.jsonl"))
        .output()
        .map_err(|e| e.to_string())?;
    require(
        !output.status.success(),
        "host execution must not pass as FrankenLibC",
    )?;
    let body = load_json(&report)?;
    require(
        body["summary"]["passed"] == 0 && body["summary"]["failed"] == 28,
        "wrong-provider cases must all fail",
    )
}
