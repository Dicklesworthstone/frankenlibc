//! Conformance gate for the harness binary `verify-pcpt`
//! subcommand (bd-toeyn).

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
        .join("verify_pcpt_cli_contract.v1.json")
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

fn unique_tmp(stem: &str, ext: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_toeyn_{stem}_{}_{ts}.{ext}", std::process::id())))
}

#[test]
fn manifest_anchors_to_toeyn_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "verify-pcpt-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-toeyn", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "verify-pcpt",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_membrane::runtime_math::policy_table::verify_pcpt",
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
        "ok_true_iff_verify_pcpt_succeeds",
        "exit_non_zero_when_ok_false",
        "too_short_input_must_fail_closed_with_TooShort_error",
        "non_magic_bytes_must_fail_closed_with_BadMagic_error",
        "missing_pcpt_file_must_fail_closed",
    ] {
        require(json_bool(policy, f)?, "policy invariant must be true")?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_verify_pcpt_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("VerifyPcpt {"),
        "harness.rs must declare VerifyPcpt Command variant",
    )?;
    require(
        src.contains("policy_table::verify_pcpt"),
        "main() must import policy_table::verify_pcpt",
    )?;
    require(
        src.contains("\"kind\": \"pcpt_verification\""),
        "VerifyPcpt arm must emit kind=pcpt_verification",
    )
}

fn run_cli(bin: &Path, pcpt: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("verify-pcpt")
        .arg("--pcpt")
        .arg(pcpt)
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
            "expected exactly one JSONL record in {}, got {}",
            out_path.display(),
            records.len()
        ),
    )?;
    let record = records
        .first()
        .ok_or_else(|| "missing JSONL record after count check".to_string())?;
    serde_json::from_str(record).map_err(|e| format!("parse: {e}"))
}

#[test]
fn cli_too_short_input_yields_too_short_error_and_non_zero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let pcpt = unique_tmp("too_short", "bin")?;
    let output = unique_tmp("too_short", "jsonl")?;
    std::fs::write(&pcpt, b"").map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &pcpt, &output)?;
    require(
        !out.status.success(),
        "too-short input must yield non-zero exit",
    )?;
    let parsed = read_record(&output)?;
    require(
        matches!(json_string(&parsed, "kind")?, "pcpt_verification"),
        "kind must be pcpt_verification",
    )?;
    require(!json_bool(&parsed, "ok")?, "too-short must yield ok=false")?;
    require(
        json_string(&parsed, "error")?.contains("TooShort"),
        format!(
            "too-short error must mention TooShort variant; got {:?}",
            parsed.get("error")
        ),
    )
}

#[test]
fn cli_bad_magic_yields_bad_magic_error() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let pcpt = unique_tmp("bad_magic", "bin")?;
    let output = unique_tmp("bad_magic", "jsonl")?;
    // HEADER_LEN is 119 bytes; allocate well past it with zeros so
    // we get BadMagic (not TooShort).
    std::fs::write(&pcpt, vec![0_u8; 256]).map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &pcpt, &output)?;
    require(
        !out.status.success(),
        "bad-magic input must yield non-zero exit",
    )?;
    let parsed = read_record(&output)?;
    require(!json_bool(&parsed, "ok")?, "bad-magic must yield ok=false")?;
    require(
        json_string(&parsed, "error")?.contains("BadMagic"),
        format!(
            "bad-magic error must mention BadMagic variant; got {:?}",
            parsed.get("error")
        ),
    )
}

#[test]
fn cli_fails_closed_on_missing_pcpt_file() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let pcpt = unique_tmp("missing", "bin")?;
    let output = unique_tmp("missing", "jsonl")?;
    // pcpt file deliberately not created.
    let out = run_cli(&bin, &pcpt, &output)?;
    require(
        !out.status.success(),
        "missing --pcpt file must yield non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("read --pcpt"),
        "stderr must surface the read failure",
    )
}
