//! Conformance gate for the harness binary `runtime-math-hji-viability-proofs`
//! subcommand (bd-dgznw).

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
        .join("runtime_math_hji_viability_proofs_cli_contract.v1.json")
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
    let dir = std::env::temp_dir().join(format!("bd_dgznw_{}_{ts}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

#[test]
fn manifest_anchors_to_dgznw_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "runtime-math-hji-viability-proofs-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-dgznw", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "runtime-math-hji-viability-proofs",
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
        "must_write_jsonl_log_file_at_log_path",
        "must_write_json_report_file_at_report_path",
        "creates_parent_directories_for_log_and_report_paths_if_missing",
        "exits_nonzero_when_summary_failed_nonzero",
        "exits_zero_when_summary_failed_count_is_zero",
        "report_contains_summary_with_checks_count",
        "uses_workspace_root_for_source_paths",
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
        names.contains(&"frankenlibc_harness::runtime_math_hji_viability_proofs::run_and_write"),
        "run_and_write not pinned",
    )?;
    Ok(())
}

#[test]
fn harness_source_registers_runtime_math_hji_viability_proofs_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::RuntimeMathHjiViabilityProofs"),
        "harness.rs must register Command::RuntimeMathHjiViabilityProofs",
    )?;
    require(
        body.contains("runtime_math_hji_viability_proofs::run_and_write"),
        "harness.rs must call runtime_math_hji_viability_proofs::run_and_write",
    )?;
    Ok(())
}

#[test]
fn cli_writes_log_and_report_files() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let dir = tmp_dir()?;
    let log = dir.join("hji.log.jsonl");
    let report = dir.join("hji.report.json");
    let root = workspace_root()?;
    let result = Command::new(&bin)
        .arg("runtime-math-hji-viability-proofs")
        .arg("--workspace-root")
        .arg(&root)
        .arg("--log")
        .arg(&log)
        .arg("--report")
        .arg(&report)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        result.status.success(),
        format!(
            "harness exit failed: {:?}; stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ),
    )?;
    require(log.exists(), "log file must be written")?;
    require(report.exists(), "report file must be written")?;
    let report_value: Value =
        serde_json::from_str(&std::fs::read_to_string(&report).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    let summary = report_value
        .get("summary")
        .ok_or("report.summary missing")?;
    require(
        summary.get("checks").and_then(Value::as_u64).is_some(),
        "summary.checks must be u64",
    )?;
    require(
        summary.get("failed").and_then(Value::as_u64) == Some(0),
        "summary.failed must be 0 on a clean tree",
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
