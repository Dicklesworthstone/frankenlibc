//! Conformance gate for the harness binary `asupersync-detect`
//! subcommand (bd-dxztd).

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
        .join("asupersync_detect_cli_contract.v1.json")
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

fn read_single_jsonl_record(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read jsonl: {e}"))?;
    let mut lines = body.lines().filter(|line| !line.trim().is_empty());
    let Some(record) = lines.next() else {
        return Err("expected exactly one JSONL record".into());
    };
    require(lines.next().is_none(), "expected exactly one JSONL record")?;
    serde_json::from_str(record).map_err(|_| "parse jsonl".into())
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

#[test]
fn manifest_anchors_to_dxztd_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "asupersync-detect-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-dxztd", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "asupersync-detect",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::asupersync_lab_replay::detect_asupersync_available",
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
        "override_var_flag_takes_precedence_over_process_env",
        "detection_reason_must_be_one_of_enum",
    ] {
        require(json_bool(policy, f)?, "policy invariant must be true")?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_asupersync_detect_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("AsupersyncDetect {"),
        "harness.rs must declare AsupersyncDetect Command variant",
    )?;
    for anchor in [
        "        override_var",
        "        asupersync_dir",
        "        path_search_paths",
        "        output",
    ] {
        require(src.contains(anchor), "AsupersyncDetect missing field")?;
    }
    require(
        src.contains("detect_asupersync_available(&env)"),
        "main() must call detect_asupersync_available",
    )
}

#[test]
fn cli_emits_one_record_with_enum_detection_reason() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = std::env::temp_dir().join(format!(
        "bd_dxztd_{}_{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("clock: {e}"))?
            .as_nanos()
    ));
    // Use --override-var=0 to force the deterministic
    // env_override_disabled branch (no filesystem read needed).
    let output = Command::new(&bin)
        .arg("asupersync-detect")
        .arg("--override-var")
        .arg("0")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "asupersync-detect failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let parsed = read_single_jsonl_record(&tmp)?;
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
    require(
        json_string(&parsed, "kind")? == "lab_availability",
        "kind must be lab_availability",
    )?;
    require(
        parsed.get("available").and_then(Value::as_bool) == Some(false),
        "override_var=0 must produce available=false",
    )?;
    let reason = json_string(&parsed, "detection_reason")?;
    let valid: Vec<&str> = json_array(contract, "valid_detection_reasons")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(valid.contains(&reason), "detection_reason must be in enum")?;
    require(
        reason == "env_override_disabled",
        "override_var=0 must give env_override_disabled",
    )
}

#[test]
fn cli_override_var_enabled_produces_enabled_reason() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = std::env::temp_dir().join(format!("bd_dxztd_enabled_{}.jsonl", std::process::id()));
    let output = Command::new(&bin)
        .arg("asupersync-detect")
        .arg("--override-var")
        .arg("1")
        .arg("--output")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "asupersync-detect failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let parsed = read_single_jsonl_record(&tmp)?;
    require(
        parsed.get("available").and_then(Value::as_bool) == Some(true),
        "override_var=1 must produce available=true",
    )?;
    require(
        json_string(&parsed, "detection_reason")? == "env_override_enabled",
        "override_var=1 must give env_override_enabled",
    )
}
