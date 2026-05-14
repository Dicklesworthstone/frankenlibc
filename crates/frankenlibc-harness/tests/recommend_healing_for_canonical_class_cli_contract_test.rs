//! Conformance gate for the harness binary `recommend-healing-for-canonical-class`
//! subcommand (bd-6noe6).

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
        .join("recommend_healing_for_canonical_class_cli_contract.v1.json")
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

fn expected_action_table_key_error() -> String {
    "expected_action_table key must parse as u8".to_owned()
}

fn expected_action_label_missing() -> String {
    "expected action label missing".to_owned()
}

fn expected_action_missing() -> String {
    "expected action missing".to_owned()
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

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_6noe6_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_6noe6_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "recommend-healing-for-canonical-class-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-6noe6", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "recommend-healing-for-canonical-class",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::heal::recommended_healing_for_canonical_class",
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
    for (field, message) in [
        (
            "must_emit_exactly_one_jsonl_record",
            "must_emit_exactly_one_jsonl_record must be true",
        ),
        (
            "echoes_class_id_into_output_record",
            "echoes_class_id_into_output_record must be true",
        ),
        (
            "deterministic_given_inputs",
            "deterministic_given_inputs must be true",
        ),
        (
            "none_class_yields_none_action",
            "none_class_yields_none_action must be true",
        ),
        (
            "temporal_class_yields_return_safe_default",
            "temporal_class_yields_return_safe_default must be true",
        ),
        (
            "congestion_class_yields_clamp_size",
            "congestion_class_yields_clamp_size must be true",
        ),
        (
            "topological_class_yields_upgrade_to_safe_variant",
            "topological_class_yields_upgrade_to_safe_variant must be true",
        ),
        (
            "regime_class_yields_return_safe_default",
            "regime_class_yields_return_safe_default must be true",
        ),
        (
            "numeric_class_yields_clamp_size",
            "numeric_class_yields_clamp_size must be true",
        ),
        (
            "admissibility_class_yields_upgrade_to_safe_variant",
            "admissibility_class_yields_upgrade_to_safe_variant must be true",
        ),
        (
            "compound_class_yields_return_safe_default",
            "compound_class_yields_return_safe_default must be true",
        ),
        (
            "out_of_range_class_id_falls_through_to_return_safe_default",
            "out_of_range_class_id_falls_through_to_return_safe_default must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_recommend_healing_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("RecommendHealingForCanonicalClass {"),
        "harness.rs must declare RecommendHealingForCanonicalClass variant",
    )?;
    require(
        src.contains("heal::recommended_healing_for_canonical_class")
            || src.contains("recommended_healing_for_canonical_class"),
        "match arm must import recommended_healing_for_canonical_class",
    )?;
    require(
        src.contains("\"kind\": \"recommended_healing\""),
        "match arm must emit kind=recommended_healing",
    )
}

fn run_cli(bin: &Path, class_id: u8, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("recommend-healing-for-canonical-class")
        .arg("--class-id")
        .arg(class_id.to_string())
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
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
    serde_json::from_str(record).map_err(|e| format!("parse: {e}"))
}

fn run_and_parse(bin: &Path, class_id: u8, label: &str) -> TestResult<Value> {
    let output = unique_tmp(label)?;
    let out = run_cli(bin, class_id, &output)?;
    if !out.status.success() {
        return Err("recommend-healing-for-canonical-class CLI invocation must succeed".into());
    }
    read_record(&output)
}

#[test]
fn cli_full_action_table_matches_manifest() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let table = manifest
        .get("expected_action_table")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing expected_action_table".to_string())?;
    for (id_str, want) in table {
        let id: u8 = id_str
            .parse()
            .map_err(|_| expected_action_table_key_error())?;
        let want_label = want
            .get("label")
            .and_then(Value::as_str)
            .ok_or_else(expected_action_label_missing)?;
        let want_action = want
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(expected_action_missing)?;
        let parsed = run_and_parse(&bin, id, "table")?;
        require(
            json_string(&parsed, "kind")? == "recommended_healing",
            "kind must be recommended_healing",
        )?;
        require(
            json_u64(&parsed, "class_id")? == u64::from(id),
            "class_id must echo manifest table id",
        )?;
        require(
            json_string(&parsed, "class_label")? == want_label,
            "class label must match manifest table",
        )?;
        require(
            json_string(&parsed, "action")? == want_action,
            "action must match manifest table",
        )?;
    }
    Ok(())
}

#[test]
fn cli_none_class_yields_none_action() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, 0, "none")?;
    require(
        json_string(&parsed, "action")? == "none",
        "class_id=0 must yield action=none",
    )?;
    require(
        parsed
            .get("action_args")
            .map(Value::is_null)
            .unwrap_or(false),
        "none action_args must be null",
    )
}

#[test]
fn cli_congestion_class_yields_clamp_size() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, 2, "congestion")?;
    require(
        json_string(&parsed, "action")? == "clamp-size",
        "congestion must map to clamp-size",
    )?;
    let args = parsed
        .get("action_args")
        .ok_or_else(|| "missing action_args".to_string())?;
    require(
        args.get("requested").and_then(Value::as_u64) == Some(0)
            && args.get("clamped").and_then(Value::as_u64) == Some(0),
        "clamp-size action_args must include requested+clamped",
    )
}

#[test]
fn cli_out_of_range_falls_through_to_return_safe_default() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // 99 is outside the 0..=7 canonical class range; should hit the catch-all
    // return-safe-default path per the lib's compound-default behavior.
    let parsed = run_and_parse(&bin, 99, "oor")?;
    require(
        json_string(&parsed, "action")? == "return-safe-default",
        "out-of-range must fall through to return-safe-default",
    )
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let a = run_and_parse(&bin, 6, "det_a")?;
    let b = run_and_parse(&bin, 6, "det_b")?;
    require(a == b, "same inputs must produce identical output")
}
