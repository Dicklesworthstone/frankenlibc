//! Conformance gate for the harness binary `runtime-math-determinism-proofs`
//! subcommand (bd-lb5e3).
//!
//! Pins the CLI bridge over
//! `frankenlibc_harness::runtime_math_determinism_proofs::run_and_write`.

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
        .join("runtime_math_determinism_proofs_cli_contract.v1.json")
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

fn unique_out_dir(root: &Path) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("clock: {err}"))?
        .as_nanos();
    let dir = root.join("target").join("conformance").join(format!(
        "runtime_math_determinism_proofs_cli_contract_test_{}_{}",
        std::process::id(),
        ts
    ));
    std::fs::create_dir_all(&dir).map_err(|err| format!("mkdir {dir:?}: {err}"))?;
    Ok(dir)
}

#[test]
fn manifest_anchors_to_lb5e3_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "runtime-math-determinism-proofs-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-lb5e3", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "runtime-math-determinism-proofs",
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
            "must_write_structured_jsonl_log_at_log_path",
            "must_write_structured_jsonl_log_at_log_path must be true",
        ),
        (
            "must_write_json_report_at_report_path",
            "must_write_json_report_at_report_path must be true",
        ),
        (
            "uses_workspace_root_for_source_paths",
            "uses_workspace_root_for_source_paths must be true",
        ),
        (
            "runs_strict_and_hardened_modes",
            "runs_strict_and_hardened_modes must be true",
        ),
        (
            "report_summary_failed_zero_on_success",
            "report_summary_failed_zero_on_success must be true",
        ),
        (
            "report_summary_modes_equals_two",
            "report_summary_modes_equals_two must be true",
        ),
        (
            "log_contains_required_determinism_events",
            "log_contains_required_determinism_events must be true",
        ),
        (
            "nonzero_exit_when_any_mode_fails",
            "nonzero_exit_when_any_mode_fails must be true",
        ),
    ] {
        require(json_bool(policy, key)?, message)?;
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
        names.contains(&"frankenlibc_harness::runtime_math_determinism_proofs::run_and_write"),
        "run_and_write not pinned",
    )?;
    Ok(())
}

#[test]
fn harness_source_registers_runtime_math_determinism_proofs_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|err| format!("read harness.rs: {err}"))?;
    require(
        body.contains("Command::RuntimeMathDeterminismProofs"),
        "harness.rs must register Command::RuntimeMathDeterminismProofs match arm",
    )?;
    require(
        body.contains("frankenlibc_harness::runtime_math_determinism_proofs::run_and_write"),
        "harness.rs must call runtime_math_determinism_proofs::run_and_write",
    )?;
    require(
        body.contains("rep.summary.failed != 0"),
        "harness.rs must fail closed when any mode fails",
    )?;
    Ok(())
}

#[test]
fn cli_writes_structured_log_and_report_to_requested_paths() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root)?;
    let log_path = out_dir.join("determinism.log.jsonl");
    let report_path = out_dir.join("determinism.report.json");

    let output = Command::new(&bin)
        .arg("runtime-math-determinism-proofs")
        .arg("--workspace-root")
        .arg(&root)
        .arg("--log")
        .arg(&log_path)
        .arg("--report")
        .arg(&report_path)
        .output()
        .map_err(|err| format!("spawn: {err}"))?;
    require(
        output.status.success(),
        format!(
            "harness exit failed: {:?}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    require(log_path.exists(), "log path must be written")?;
    require(report_path.exists(), "report path must be written")?;

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .map_err(|err| format!("validate log: {err}"))?;
    require(
        errors.is_empty(),
        format!("structured log validation errors: {errors:#?}"),
    )?;
    require(
        line_count >= 6,
        format!("expected multiple log rows, got {line_count}"),
    )?;

    let log_body = std::fs::read_to_string(&log_path).map_err(|err| format!("read log: {err}"))?;
    let events: Vec<Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| format!("parse log row: {err}")))
        .collect::<Result<_, _>>()?;
    for (expected, message) in [
        (
            "runtime_math.determinism.proof_step",
            "missing required log event runtime_math.determinism.proof_step",
        ),
        (
            "runtime_math.determinism.gram_eigenvalue_check",
            "missing required log event runtime_math.determinism.gram_eigenvalue_check",
        ),
        (
            "runtime_math.determinism.boundary_assumption",
            "missing required log event runtime_math.determinism.boundary_assumption",
        ),
        (
            "runtime_math.determinism.mode_finish",
            "missing required log event runtime_math.determinism.mode_finish",
        ),
    ] {
        require(
            events
                .iter()
                .any(|entry| entry.get("event").and_then(Value::as_str) == Some(expected)),
            message,
        )?;
    }

    let report = load_json(&report_path)?;
    require(
        json_string(&report, "schema_version")? == "v1",
        "report schema_version must be v1",
    )?;
    require(
        json_string(&report, "bead")? == "bd-1fk1",
        "underlying proof report bead must remain bd-1fk1",
    )?;
    let summary = report
        .get("summary")
        .ok_or_else(|| "missing summary".to_string())?;
    require(json_u64(summary, "modes")? == 2, "summary.modes must be 2")?;
    require(
        json_u64(summary, "failed")? == 0,
        "summary.failed must be 0",
    )?;
    require(
        json_array(&report, "modes")?.len() == 2,
        "report must include strict and hardened mode rows",
    )?;
    Ok(())
}
