//! Conformance gate for the harness binary `tooling-contract`
//! subcommand (bd-38wu3).

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
        .join("tooling_contract_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_38wu3_{stem}_{}_{ts}.jsonl", std::process::id())))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read jsonl: {e}"))?;
    let records: Vec<&str> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    require(
        records.len() == 1,
        format!(
            "{} must contain exactly one JSONL record, found {}",
            out_path.display(),
            records.len()
        ),
    )?;
    let record = records
        .first()
        .ok_or_else(|| "missing JSONL record after record-count check".to_string())?;
    serde_json::from_str(record).map_err(|e| format!("parse jsonl: {e}"))
}

#[test]
fn manifest_anchors_to_38wu3_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "tooling-contract-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-38wu3", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "tooling-contract",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::explainability_workbench::tooling_contract",
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
            "must_emit_exactly_one_jsonl_record",
            "must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "all_contract_fields_must_be_booleans",
            "all_contract_fields_must_be_booleans must be true",
        ),
        (
            "has_asupersync_dependency_must_be_true_in_default_build",
            "has_asupersync_dependency_must_be_true_in_default_build must be true",
        ),
        (
            "asupersync_feature_present_must_be_true",
            "asupersync_feature_present_must_be_true must be true",
        ),
        (
            "default_enables_asupersync_tooling_must_be_true",
            "default_enables_asupersync_tooling_must_be_true must be true",
        ),
        (
            "frankentui_feature_present_must_be_true",
            "frankentui_feature_present_must_be_true must be true",
        ),
        (
            "frankentui_dependency_set_complete_must_be_true",
            "frankentui_dependency_set_complete_must_be_true must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_tooling_contract_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ToolingContract {"),
        "harness.rs must declare ToolingContract Command variant",
    )?;
    require(
        src.contains("explainability_workbench::tooling_contract"),
        "main() must import explainability_workbench::tooling_contract",
    )?;
    require(
        src.contains("\"kind\": \"tooling_contract\""),
        "ToolingContract arm must emit kind=tooling_contract",
    )
}

#[test]
fn cli_emits_exactly_one_record_with_all_boolean_fields() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("fields")?;
    let out = Command::new(&bin)
        .arg("tooling-contract")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tooling-contract failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&tmp)?;
    require(
        json_string(&parsed, "kind")? == "tooling_contract",
        "kind must be tooling_contract",
    )?;
    let m = load_json(&manifest_path(&workspace_root()?))?;
    let contract = m
        .get("jsonl_output_contract")
        .ok_or_else(|| "missing jsonl_output_contract".to_string())?;
    for f in json_array(contract, "required_fields")?
        .iter()
        .filter_map(Value::as_str)
    {
        require(parsed.get(f).is_some(), "record missing required field")?;
    }
    for f in json_array(contract, "boolean_fields")?
        .iter()
        .filter_map(Value::as_str)
    {
        require(
            parsed.get(f).and_then(Value::as_bool).is_some(),
            "field must be a JSON boolean",
        )?;
    }
    Ok(())
}

#[test]
fn cli_pins_invariant_truths_for_default_build() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp("invariants")?;
    let out = Command::new(&bin)
        .arg("tooling-contract")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tooling-contract failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&tmp)?;
    // These fields are compile-time constants pinned `true` in
    // tooling_contract() — they describe Cargo.toml shape, not the
    // active build's --features flags. Any false here = the source
    // pins were edited without updating downstream gates.
    for f in [
        "has_asupersync_dependency",
        "asupersync_feature_present",
        "default_enables_asupersync_tooling",
        "frankentui_feature_present",
        "frankentui_dependency_set_complete",
    ] {
        require(
            json_bool(&parsed, f)?,
            "pinned tooling contract field must be true",
        )?;
    }
    Ok(())
}
