//! Conformance gate for the harness binary `canonical-class-from-support`
//! subcommand (bd-dk8bl).

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
        .join("canonical_class_from_support_cli_contract.v1.json")
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

fn bool_vec(value: &Value, field: &str) -> TestResult<Vec<bool>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))?
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            item.as_bool()
                .ok_or_else(|| format!("`{field}`[{idx}] is not a bool"))
        })
        .collect()
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
    Ok(std::env::temp_dir().join(format!("bd_dk8bl_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_dk8bl_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "canonical-class-from-support-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-dk8bl", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "canonical-class-from-support",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::grobner::canonical_class_from_support",
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
        "echoes_active_support_vector_into_output_record",
        "deterministic_given_inputs",
        "empty_support_yields_none_class",
        "single_cause_support_yields_matching_class",
        "temporal_regime_reduces_to_regime",
        "congestion_numeric_reduces_to_congestion",
        "topological_admissibility_reduces_to_admissibility",
        "unreduced_multi_cause_support_yields_compound",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_canonical_class_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("CanonicalClassFromSupport {"),
        "harness.rs must declare CanonicalClassFromSupport variant",
    )?;
    require(
        src.contains("grobner::canonical_class_from_support")
            || src.contains("canonical_class_from_support"),
        "match arm must import canonical_class_from_support",
    )?;
    require(
        src.contains("\"kind\": \"canonical_class_from_support\""),
        "CanonicalClassFromSupport arm must emit kind=canonical_class_from_support",
    )
}

fn run_cli(bin: &Path, active: &[bool], output: &Path) -> TestResult<std::process::Output> {
    let flags = [
        "--c0-temporal",
        "--c1-congestion",
        "--c2-topological",
        "--c3-regime",
        "--c4-numeric",
        "--c5-admissibility",
    ];
    let mut cmd = Command::new(bin);
    cmd.arg("canonical-class-from-support");
    for (flag, on) in flags.iter().zip(active.iter().copied()) {
        if on {
            cmd.arg(flag);
        }
    }
    cmd.arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

fn read_record(out_path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(out_path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("parse: {e}"))
}

fn run_and_parse(bin: &Path, active: &[bool], label: &str) -> TestResult<Value> {
    let output = unique_tmp(label)?;
    let out = run_cli(bin, active, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    read_record(&output)
}

#[test]
fn cli_expected_class_table_matches_manifest() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let table = manifest
        .get("expected_class_table")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing expected_class_table".to_string())?;
    for entry in table {
        let case = json_string(entry, "case")?;
        let active = bool_vec(entry, "active")?;
        require(
            active.len() == 6,
            format!("{case}: active must have 6 bools"),
        )?;
        let parsed = run_and_parse(&bin, &active, case)?;
        require(
            json_string(&parsed, "kind")? == "canonical_class_from_support",
            "kind must be canonical_class_from_support",
        )?;
        require(
            bool_vec(&parsed, "active")? == active,
            format!("{case}: active vector must be echoed"),
        )?;
        require(
            json_u64(&parsed, "class_id")? == json_u64(entry, "class_id")?,
            format!("{case}: class_id drift"),
        )?;
        require(
            json_string(&parsed, "class_label")? == json_string(entry, "class_label")?,
            format!("{case}: class_label drift"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_temporal_regime_reduces_to_regime() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(
        &bin,
        &[true, false, false, true, false, false],
        "temporal_regime",
    )?;
    require(json_u64(&parsed, "class_id")? == 4, "class_id must be 4")?;
    require(
        json_string(&parsed, "class_label")? == "regime",
        "class_label must be regime",
    )
}

#[test]
fn cli_unreduced_pair_is_compound() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(
        &bin,
        &[true, true, false, false, false, false],
        "compound_pair",
    )?;
    require(json_u64(&parsed, "class_id")? == 7, "class_id must be 7")?;
    require(
        json_string(&parsed, "class_label")? == "compound",
        "class_label must be compound",
    )
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let active = [false, true, false, false, true, false];
    let a = run_and_parse(&bin, &active, "det_a")?;
    let b = run_and_parse(&bin, &active, "det_b")?;
    require(a == b, "same inputs must produce identical output")
}
