//! Conformance gate for the harness binary `kernel-regression-report` subcommand
//! (bd-hmkxe). Sister gate of bd-borw4 (kernel-regression-mode).

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
        .join("kernel_regression_report_cli_contract.v1.json")
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
    let dir = std::env::temp_dir().join(format!("bd_hmkxe_{}_{ts}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

// Use minimal microbench iters so the gate is fast; the production
// defaults take ~10s per invocation.
fn run_report(bin: &Path, output: Option<&Path>, seed: &str) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("kernel-regression-report")
        .arg("--seed")
        .arg(seed)
        .arg("--steps")
        .arg("16")
        .arg("--warmup-iters")
        .arg("8")
        .arg("--samples")
        .arg("2")
        .arg("--iters")
        .arg("32")
        .arg("--trend-stride")
        .arg("4");
    if let Some(p) = output {
        cmd.arg("--output").arg(p);
    }
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

#[test]
fn manifest_anchors_to_hmkxe_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "kernel-regression-report-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-hmkxe", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "kernel-regression-report",
        "subcommand_name mismatch",
    )?;
    Ok(())
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "without_output_flag_renders_markdown_to_stdout",
        "with_output_flag_writes_markdown_to_output_path",
        "with_output_flag_writes_json_sibling_at_output_path_with_json_extension",
        "spawns_two_subprocesses_strict_and_hardened",
        "report_contains_strict_and_hardened_metrics_blocks",
        "json_sibling_includes_both_modes_with_their_safety_levels",
        "deterministic_seed_steps_microbench_iters_roundtrip_to_each_mode_block",
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
        names
            .contains(&"frankenlibc_harness::kernel_regression_report::render_regression_markdown"),
        "render_regression_markdown not pinned",
    )?;
    Ok(())
}

#[test]
fn harness_source_registers_kernel_regression_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::KernelRegressionReport"),
        "harness.rs must register Command::KernelRegressionReport match arm",
    )?;
    require(
        body.contains("render_regression_markdown"),
        "harness.rs must call render_regression_markdown",
    )?;
    require(
        body.contains("run_kernel_mode_subprocess"),
        "harness.rs must spawn run_kernel_mode_subprocess",
    )?;
    Ok(())
}

#[test]
fn cli_without_output_prints_markdown_to_stdout() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let result = run_report(&bin, None, "0xDEAD_BEEF")?;
    require(
        result.status.success(),
        format!(
            "harness exit failed: {:?}; stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ),
    )?;
    let body = String::from_utf8_lossy(&result.stdout);
    require(!body.is_empty(), "stdout must contain markdown body")?;
    require(
        body.contains("strict") && body.contains("hardened"),
        "markdown body must mention both modes",
    )?;
    Ok(())
}

#[test]
fn cli_with_output_writes_markdown_and_json_sibling() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out_md = dir.join("kernel_regression_report.md");
    let result = run_report(&bin, Some(&out_md), "0xDEAD_BEEF")?;
    require(
        result.status.success(),
        format!(
            "harness exit failed: {:?}; stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ),
    )?;
    require(out_md.exists(), "markdown output must be written")?;
    let out_json = out_md.with_extension("json");
    require(out_json.exists(), "json sibling must be written")?;
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&out_json).map_err(|e| format!("read json: {e}"))?,
    )
    .map_err(|e| format!("parse json: {e}"))?;
    require(
        report.get("strict").is_some(),
        "report.strict block must be present",
    )?;
    require(
        report.get("hardened").is_some(),
        "report.hardened block must be present",
    )?;
    let strict = report.get("strict").unwrap();
    let hardened = report.get("hardened").unwrap();
    require(
        json_string(strict, "mode")? == "strict",
        "report.strict.mode must be strict",
    )?;
    require(
        json_string(hardened, "mode")? == "hardened",
        "report.hardened.mode must be hardened",
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_seed_roundtrips_to_each_mode_block() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let out_md = dir.join("seed_check.md");
    let result = run_report(&bin, Some(&out_md), "0xCAFEBABE")?;
    require(result.status.success(), "harness exit failed")?;
    let out_json = out_md.with_extension("json");
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&out_json).map_err(|e| format!("read: {e}"))?,
    )
    .map_err(|e| format!("parse: {e}"))?;
    let expected_seed: u64 = 0xCAFEBABE;
    for mode in ["strict", "hardened"] {
        let block = report.get(mode).ok_or(format!("missing {mode}"))?;
        let seed = block
            .get("seed")
            .and_then(Value::as_u64)
            .ok_or(format!("{mode}.seed missing"))?;
        require(
            seed == expected_seed,
            format!("{mode}.seed must roundtrip ({seed} != {expected_seed})"),
        )?;
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
