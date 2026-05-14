//! Conformance gate for the harness binary `render-diff`
//! subcommand (bd-bdi7r).

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
        .join("render_diff_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_bdi7r_{stem}_{}_{ts}.txt", std::process::id())))
}

#[test]
fn manifest_anchors_to_bdi7r_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "render-diff-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-bdi7r", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "render-diff",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")? == "frankenlibc_harness::diff::render_diff",
        "underlying_lib_function",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for (field, message) in [
        (
            "identical_inputs_produce_identical_marker_default_features",
            "identical_inputs_produce_identical_marker_default_features must be true",
        ),
        (
            "divergent_inputs_start_with_minus_minus_minus_expected_header_default_features",
            "divergent_inputs_start_with_minus_minus_minus_expected_header_default_features must be true",
        ),
        (
            "missing_expected_file_must_fail_closed",
            "missing_expected_file_must_fail_closed must be true",
        ),
        (
            "missing_actual_file_must_fail_closed",
            "missing_actual_file_must_fail_closed must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_render_diff_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("RenderDiff {"),
        "harness.rs must declare RenderDiff Command variant",
    )?;
    require(
        src.contains("diff::render_diff"),
        "main() must import diff::render_diff",
    )
}

fn run_cli(
    bin: &Path,
    expected: &Path,
    actual: &Path,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("render-diff")
        .arg("--expected")
        .arg(expected)
        .arg("--actual")
        .arg(actual)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

#[test]
fn cli_identical_inputs_produce_identical_marker() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let expected = unique_tmp("ident_exp")?;
    let actual = unique_tmp("ident_act")?;
    let output = unique_tmp("ident_out")?;
    let text = "line1\nline2\nline3\n";
    std::fs::write(&expected, text).map_err(|e| format!("write expected: {e}"))?;
    std::fs::write(&actual, text).map_err(|e| format!("write actual: {e}"))?;
    let out = run_cli(&bin, &expected, &actual, &output)?;
    if !out.status.success() {
        return Err(format!(
            "render-diff failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = std::fs::read_to_string(&output).map_err(|e| format!("read: {e}"))?;
    require(
        body == "[identical]",
        format!("identical inputs must produce literal '[identical]' marker; got {body:?}"),
    )
}

#[test]
fn cli_divergent_inputs_start_with_expected_actual_header() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let expected = unique_tmp("div_exp")?;
    let actual = unique_tmp("div_act")?;
    let output = unique_tmp("div_out")?;
    std::fs::write(&expected, "hello\n").map_err(|e| format!("write: {e}"))?;
    std::fs::write(&actual, "world\n").map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &expected, &actual, &output)?;
    if !out.status.success() {
        return Err(format!(
            "render-diff failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = std::fs::read_to_string(&output).map_err(|e| format!("read: {e}"))?;
    require(
        body.starts_with("--- expected\n+++ actual\n"),
        format!("divergent inputs must start with diff header; got {body:?}"),
    )?;
    require(
        body.contains("-hello") && body.contains("+world"),
        "diff body must surface the divergent lines",
    )
}

#[test]
fn cli_fails_closed_on_missing_expected_file() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let expected = unique_tmp("missing")?;
    let actual = unique_tmp("act")?;
    let output = unique_tmp("out")?;
    std::fs::write(&actual, "x").map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &expected, &actual, &output)?;
    require(
        !out.status.success(),
        "missing --expected must cause non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("read --expected"),
        "stderr must explain the read failure",
    )
}

#[test]
fn cli_fails_closed_on_missing_actual_file() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let expected = unique_tmp("exp")?;
    let actual = unique_tmp("missing")?;
    let output = unique_tmp("out")?;
    std::fs::write(&expected, "x").map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &expected, &actual, &output)?;
    require(
        !out.status.success(),
        "missing --actual must cause non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("read --actual"),
        "stderr must explain the read failure",
    )
}
