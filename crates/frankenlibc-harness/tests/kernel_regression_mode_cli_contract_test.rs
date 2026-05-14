//! Conformance gate for the harness binary `kernel-regression-mode` subcommand (bd-borw4).
//!
//! Pins the CLI bridge over
//! `frankenlibc_harness::kernel_regression_report::collect_mode_metrics`. The
//! subcommand exists as a per-process boundary because SafetyLevel is cached
//! once at process start from `FRANKENLIBC_MODE`; this gate validates that
//! invariant + the JSON shape on stdout.

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
        .join("kernel_regression_mode_cli_contract.v1.json")
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

struct ModeCli<'a> {
    mode: &'a str,
    seed: &'a str,
    steps: u32,
    samples: u32,
    iters: u32,
    warmup: u32,
    env_mode: Option<&'a str>,
}

fn run_mode(bin: &Path, cli: &ModeCli<'_>) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("kernel-regression-mode")
        .arg("--mode")
        .arg(cli.mode)
        .arg("--seed")
        .arg(cli.seed)
        .arg("--steps")
        .arg(cli.steps.to_string())
        .arg("--warmup-iters")
        .arg(cli.warmup.to_string())
        .arg("--samples")
        .arg(cli.samples.to_string())
        .arg("--iters")
        .arg(cli.iters.to_string());
    cmd.env_remove("FRANKENLIBC_MODE");
    if let Some(em) = cli.env_mode {
        cmd.env("FRANKENLIBC_MODE", em);
    }
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

#[test]
fn manifest_anchors_to_borw4_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "kernel-regression-mode-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-borw4", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "kernel-regression-mode",
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
        "must_emit_exactly_one_pretty_json_record_to_stdout",
        "no_output_file_flag",
        "mode_field_in_record_reflects_cli_mode",
        "seed_field_in_record_reflects_cli_seed",
        "steps_field_in_record_reflects_cli_steps",
        "frankenlibc_mode_env_var_mismatch_rejected_with_nonzero_exit",
        "unknown_mode_rejected_with_nonzero_exit",
        "missing_required_mode_flag_rejected_with_nonzero_exit",
        "deterministic_given_same_seed_steps_microbench_iters",
    ] {
        require(
            json_bool(policy, key)?,
            format!("policy.{key} must be true (manifest pin)"),
        )?;
    }
    Ok(())
}

#[test]
fn manifest_underlying_lib_function_is_pinned() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let funcs = m
        .get("underlying_lib_functions")
        .and_then(Value::as_array)
        .ok_or("underlying_lib_functions missing")?;
    let names: Vec<&str> = funcs.iter().filter_map(Value::as_str).collect();
    require(
        names.contains(&"frankenlibc_harness::kernel_regression_report::collect_mode_metrics"),
        "collect_mode_metrics not pinned",
    )?;
    Ok(())
}

#[test]
fn harness_source_registers_kernel_regression_mode_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::KernelRegressionMode"),
        "harness.rs must register Command::KernelRegressionMode match arm",
    )?;
    require(
        body.contains("collect_mode_metrics"),
        "harness.rs must call collect_mode_metrics",
    )?;
    Ok(())
}

#[test]
fn cli_strict_mode_with_matching_env_emits_metrics_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let result = run_mode(
        &bin,
        &ModeCli {
            mode: "strict",
            seed: "0xDEAD_BEEF",
            steps: 32,
            samples: 4,
            iters: 256,
            warmup: 256,
            env_mode: Some("strict"),
        },
    )?;
    require(
        result.status.success(),
        format!(
            "harness exit failed: {:?}; stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ),
    )?;
    let body = String::from_utf8_lossy(&result.stdout);
    let record: Value =
        serde_json::from_str(&body).map_err(|e| format!("stdout is not JSON: {e}\n{body}"))?;
    require(
        json_string(&record, "mode")? == "strict",
        "record.mode must be strict",
    )?;
    require(
        json_u64(&record, "steps")? == 32,
        "record.steps must roundtrip",
    )?;
    require(
        record.get("bench").is_some(),
        "record must contain bench block",
    )?;
    require(
        record.get("snapshot").is_some(),
        "record must contain snapshot block",
    )?;
    Ok(())
}

#[test]
fn cli_hardened_mode_with_matching_env_emits_metrics_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let result = run_mode(
        &bin,
        &ModeCli {
            mode: "hardened",
            seed: "0x42",
            steps: 32,
            samples: 4,
            iters: 256,
            warmup: 256,
            env_mode: Some("hardened"),
        },
    )?;
    require(
        result.status.success(),
        format!(
            "harness exit failed: {:?}; stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ),
    )?;
    let body = String::from_utf8_lossy(&result.stdout);
    let record: Value = serde_json::from_str(&body).map_err(|e| format!("parse: {e}"))?;
    require(
        json_string(&record, "mode")? == "hardened",
        "record.mode must be hardened",
    )?;
    Ok(())
}

#[test]
fn cli_env_mode_mismatch_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    // Pass --mode=strict but set FRANKENLIBC_MODE=hardened, exposing the
    // process-immutable parity check inside collect_mode_metrics.
    let result = run_mode(
        &bin,
        &ModeCli {
            mode: "strict",
            seed: "0xDEAD_BEEF",
            steps: 16,
            samples: 2,
            iters: 64,
            warmup: 128,
            env_mode: Some("hardened"),
        },
    )?;
    require(
        !result.status.success(),
        "harness must exit non-zero when FRANKENLIBC_MODE != --mode",
    )?;
    Ok(())
}

#[test]
fn cli_unknown_mode_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let result = Command::new(&bin)
        .arg("kernel-regression-mode")
        .arg("--mode")
        .arg("totally-not-a-mode")
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !result.status.success(),
        "harness must exit non-zero on unknown mode",
    )?;
    Ok(())
}

#[test]
fn cli_missing_mode_flag_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let result = Command::new(&bin)
        .arg("kernel-regression-mode")
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !result.status.success(),
        "harness must exit non-zero when --mode is omitted",
    )?;
    Ok(())
}

#[test]
fn cli_deterministic_given_same_seed_steps_microbench_iters() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let cli = ModeCli {
        mode: "strict",
        seed: "0xBEEF",
        steps: 24,
        samples: 4,
        iters: 256,
        warmup: 256,
        env_mode: Some("strict"),
    };
    let a = run_mode(&bin, &cli)?;
    let b = run_mode(&bin, &cli)?;
    require(
        a.status.success() && b.status.success(),
        "both runs must succeed",
    )?;
    let body_a = String::from_utf8_lossy(&a.stdout);
    let body_b = String::from_utf8_lossy(&b.stdout);
    let rec_a: Value = serde_json::from_str(&body_a).map_err(|e| format!("parse a: {e}"))?;
    let rec_b: Value = serde_json::from_str(&body_b).map_err(|e| format!("parse b: {e}"))?;
    // bench latencies include real wall-clock measurements; check only the
    // deterministic structural fields are equal.
    for f in [
        "mode",
        "seed",
        "steps",
        "actions",
        "risk",
        "family_diagnostics",
        "snapshot",
        "pareto_trend",
    ] {
        require(
            rec_a.get(f) == rec_b.get(f),
            format!("field `{f}` must be deterministic across runs"),
        )?;
    }
    Ok(())
}
