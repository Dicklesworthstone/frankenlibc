//! Conformance gate for the harness binary `reduce-mask` subcommand
//! (bd-f9mnb).

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
        .join("reduce_mask_cli_contract.v1.json")
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

fn unique_tmp(stem: &str, ext: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_f9mnb_{stem}_{}_{ts}.{ext}", std::process::id())))
}

fn write_rules(stem: &str, body: &str) -> TestResult<PathBuf> {
    let p = unique_tmp(stem, "json")?;
    std::fs::write(&p, body).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p)
}

#[test]
fn manifest_anchors_to_f9mnb_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "reduce-mask-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-f9mnb", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "reduce-mask",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::grobner::reduce_mask_with_limit",
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
        "echoes_inputs_into_output_record",
        "deterministic_given_inputs",
        "identity_with_empty_rule_table",
        "drops_redundant_atom_a_or_b_to_a",
        "canonical_root_cause_c0_and_c3_to_c3",
        "canonical_full_support_reduces_to_disjoint_class_union",
        "step_limit_exceeded_preserves_input_mask_and_flags_error",
    ] {
        require(json_bool(policy, f)?, "policy invariant must be true")?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_reduce_mask_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ReduceMask {"),
        "harness.rs must declare ReduceMask Command variant",
    )?;
    require(
        src.contains("frankenlibc_membrane::grobner::") || src.contains("grobner::reduce_mask"),
        "match arm must import grobner::reduce_mask_with_limit",
    )?;
    require(
        src.contains("\"kind\": \"reduce_mask\""),
        "ReduceMask arm must emit kind=reduce_mask",
    )
}

fn run_cli(
    bin: &Path,
    mask: u128,
    rules_path: &Path,
    step_limit: u32,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("reduce-mask")
        .arg("--mask")
        .arg(mask.to_string())
        .arg("--rules")
        .arg(rules_path)
        .arg("--step-limit")
        .arg(step_limit.to_string())
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

fn run_and_parse(
    bin: &Path,
    mask: u128,
    rules_body: &str,
    step_limit: u32,
    label: &str,
) -> TestResult<Value> {
    let rules_path = write_rules(label, rules_body)?;
    let output = unique_tmp(label, "jsonl")?;
    let out = run_cli(bin, mask, &rules_path, step_limit, &output)?;
    if !out.status.success() {
        return Err(format!("stderr={}", String::from_utf8_lossy(&out.stderr)));
    }
    read_record(&output)
}

#[test]
fn cli_identity_with_empty_rule_table() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, 5, "[]", 64, "identity")?;
    require(
        json_string(&parsed, "kind")? == "reduce_mask",
        "kind must be reduce_mask",
    )?;
    require(
        json_string(&parsed, "reduced_mask")? == "5",
        "identity must preserve input mask",
    )?;
    require(json_u64(&parsed, "steps")? == 0, "steps must be 0")?;
    require(
        json_bool(&parsed, "reached_fixpoint")?,
        "fixpoint must be reached",
    )?;
    require(
        parsed.get("error").map(Value::is_null).unwrap_or(false),
        "error must be null",
    )
}

#[test]
fn cli_drops_redundant_atom_a_or_b_to_a() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // Rule: lhs=3 (A|B) -> rhs=1 (A); mask=3 reduces to 1.
    let parsed = run_and_parse(&bin, 3, r#"[{"lhs":3,"rhs":1}]"#, 64, "drop")?;
    require(
        json_string(&parsed, "reduced_mask")? == "1",
        "a|b -> a must yield reduced_mask=1",
    )?;
    require(json_u64(&parsed, "steps")? >= 1, "at least one step")?;
    require(
        json_bool(&parsed, "reached_fixpoint")?,
        "fixpoint must be reached",
    )
}

#[test]
fn cli_canonical_root_cause_c0_and_c3_to_c3() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // Canonical: c0&c3 -> c3, c1&c4 -> c1, c2&c5 -> c5; mask=9 (c0|c3) -> 8 (c3).
    let rules = r#"[{"lhs":9,"rhs":8},{"lhs":18,"rhs":2},{"lhs":36,"rhs":32}]"#;
    let parsed = run_and_parse(&bin, 9, rules, 64, "canonical_c0c3")?;
    require(
        json_string(&parsed, "reduced_mask")? == "8",
        "c0&c3 must collapse to c3",
    )
}

#[test]
fn cli_canonical_full_support_reduces_to_disjoint_class_union() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // Full support 0x3F (63) under canonical rules collapses to
    // c1 | c3 | c5 = 2 | 8 | 32 = 42.
    let rules = r#"[{"lhs":9,"rhs":8},{"lhs":18,"rhs":2},{"lhs":36,"rhs":32}]"#;
    let parsed = run_and_parse(&bin, 63, rules, 64, "canonical_full")?;
    require(
        json_string(&parsed, "reduced_mask")? == "42",
        "full support must reduce to c1|c3|c5=42",
    )?;
    require(
        json_bool(&parsed, "reached_fixpoint")?,
        "must reach fixpoint within bound",
    )
}

#[test]
fn cli_step_limit_exceeded_preserves_input_and_flags_error() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    // Cyclic rules a->b, b->a with step_limit=2 will exceed.
    let rules = r#"[{"lhs":1,"rhs":2},{"lhs":2,"rhs":1}]"#;
    let parsed = run_and_parse(&bin, 1, rules, 2, "stepcap")?;
    require(
        json_string(&parsed, "reduced_mask")? == "1",
        "on step_limit_exceeded reduced_mask must echo input_mask",
    )?;
    require(
        !json_bool(&parsed, "reached_fixpoint")?,
        "reached_fixpoint must be false",
    )?;
    let err = parsed
        .get("error")
        .and_then(Value::as_str)
        .ok_or_else(|| "error field must be a string on step_limit_exceeded".to_string())?;
    require(
        err == "step_limit_exceeded",
        "error must be step_limit_exceeded",
    )
}

#[test]
fn cli_deterministic_given_same_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let rules = r#"[{"lhs":9,"rhs":8},{"lhs":18,"rhs":2},{"lhs":36,"rhs":32}]"#;
    let a = run_and_parse(&bin, 27, rules, 64, "det_a")?;
    let b = run_and_parse(&bin, 27, rules, 64, "det_b")?;
    require(a == b, "same inputs must produce identical output")
}

#[test]
fn cli_echoes_inputs_into_record() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let parsed = run_and_parse(&bin, 7, r#"[{"lhs":3,"rhs":1}]"#, 99, "echo")?;
    require(
        json_string(&parsed, "input_mask")? == "7",
        "input_mask must echo",
    )?;
    require(
        json_u64(&parsed, "rule_count")? == 1,
        "rule_count must echo",
    )?;
    require(
        json_u64(&parsed, "step_limit")? == 99,
        "step_limit must echo",
    )
}
