//! Conformance gate for the harness binary `validate-stdio-evidence`
//! subcommand (bd-2t33m).

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
        .join("validate_stdio_evidence_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!("bd_2t33m_{stem}_{}_{ts}.jsonl", std::process::id())))
}

#[test]
fn manifest_anchors_to_2t33m_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "validate-stdio-evidence-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-2t33m", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "validate-stdio-evidence",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::stdio_evidence::parse_stdio_evidence_file",
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
        "ok_true_iff_errors_array_is_empty",
        "exit_non_zero_when_ok_false",
        "empty_jsonl_must_pass",
        "supports_current_schema_version",
        "io_failure_to_open_input_must_be_reported",
    ] {
        require(json_bool(policy, f)?, "policy invariant must be true")?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_validate_stdio_evidence_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ValidateStdioEvidence {"),
        "harness.rs must declare ValidateStdioEvidence Command variant",
    )?;
    require(
        src.contains("stdio_evidence::{") && src.contains("ParseError, parse_stdio_evidence_file"),
        "main() must import ParseError + parse_stdio_evidence_file",
    )?;
    require(
        src.contains("\"kind\": \"stdio_evidence_validation\""),
        "ValidateStdioEvidence arm must emit kind=stdio_evidence_validation",
    )
}

fn run_cli(bin: &Path, jsonl: &Path, output: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("validate-stdio-evidence")
        .arg("--jsonl")
        .arg(jsonl)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
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
    serde_json::from_str(record).map_err(|e| format!("parse: {e}"))
}

#[test]
fn cli_passes_on_empty_jsonl() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("empty_in")?;
    let output = unique_tmp("empty_out")?;
    std::fs::write(&jsonl, "").map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &jsonl, &output)?;
    if !out.status.success() {
        return Err(format!(
            "validate-stdio-evidence failed on empty log: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "kind")? == "stdio_evidence_validation",
        "kind must be stdio_evidence_validation",
    )?;
    require(json_bool(&parsed, "ok")?, "empty jsonl must yield ok=true")?;
    require(
        json_u64(&parsed, "total_rows")? == 0,
        "empty jsonl must yield total_rows=0",
    )?;
    require(
        json_array(&parsed, "errors")?.is_empty(),
        "empty jsonl must yield errors=[]",
    )
}

#[test]
fn cli_fails_on_corrupt_json_row() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("corrupt_in")?;
    let output = unique_tmp("corrupt_out")?;
    std::fs::write(&jsonl, "this is not json\n").map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &jsonl, &output)?;
    require(
        !out.status.success(),
        "corrupt JSON row must yield non-zero exit",
    )?;
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "corrupt JSON row must yield ok=false",
    )?;
    let errors = json_array(&parsed, "errors")?;
    require(
        errors
            .iter()
            .any(|e| e.get("kind").and_then(Value::as_str) == Some("json")),
        "errors must include a kind=json entry",
    )
}

#[test]
fn cli_fails_on_unsupported_schema_version() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("future_in")?;
    let output = unique_tmp("future_out")?;
    // Set schema_version to u32::MAX so it's definitely > the current
    // SCHEMA_VERSION; the envelope check rejects without needing the
    // rest of the row to deserialize.
    std::fs::write(
        &jsonl,
        "{\"schema_version\":4294967295,\"trace_id\":1,\"foo\":\"bar\"}\n",
    )
    .map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &jsonl, &output)?;
    require(
        !out.status.success(),
        "unsupported schema version must yield non-zero exit",
    )?;
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "unsupported schema version must yield ok=false",
    )?;
    let errors = json_array(&parsed, "errors")?;
    require(
        errors
            .iter()
            .any(|e| e.get("kind").and_then(Value::as_str) == Some("unsupported_version")),
        "errors must include a kind=unsupported_version entry",
    )
}

#[test]
fn cli_reports_io_error_for_missing_input() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("never_exists")?;
    let output = unique_tmp("io_out")?;
    let out = run_cli(&bin, &jsonl, &output)?;
    require(
        !out.status.success(),
        "missing input must yield non-zero exit",
    )?;
    let parsed = read_record(&output)?;
    require(
        !json_bool(&parsed, "ok")?,
        "missing input must yield ok=false",
    )?;
    let errors = json_array(&parsed, "errors")?;
    require(
        errors
            .iter()
            .any(|e| e.get("kind").and_then(Value::as_str) == Some("io")),
        "errors must include a kind=io entry",
    )
}
