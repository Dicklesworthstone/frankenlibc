//! Conformance gate for the harness binary `verify-runtime-evidence`
//! subcommand (bd-5mczh).

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
        .join("verify_runtime_evidence_cli_contract.v1.json")
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

fn read_record(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read jsonl: {e}"))?;
    let records: Vec<&str> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    require(
        records.len() == 1,
        format!(
            "{} must contain exactly one JSONL record, found {}",
            path.display(),
            records.len()
        ),
    )?;
    let record = records
        .first()
        .ok_or_else(|| "missing JSONL record after record-count check".to_string())?;
    serde_json::from_str(record).map_err(|e| format!("parse: {e}"))
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
    Ok(std::env::temp_dir().join(format!("bd_5mczh_{stem}_{}_{ts}.{ext}", std::process::id())))
}

#[test]
fn manifest_anchors_to_5mczh_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "verify-runtime-evidence-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-5mczh", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "verify-runtime-evidence",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "underlying_lib_function")?
            == "frankenlibc_harness::runtime_evidence_verifier::verify_runtime_evidence_jsonl",
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
        "status_pass_iff_failure_count_zero",
        "exit_non_zero_when_status_fail",
        "fail_closed_when_expected_source_commit_blank",
        "output_schema_must_be_runtime_evidence_verifier_v1",
    ] {
        require(json_bool(policy, f)?, "policy invariant must be true")?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_verify_runtime_evidence_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("VerifyRuntimeEvidence {"),
        "harness.rs must declare VerifyRuntimeEvidence Command variant",
    )?;
    require(
        src.contains("verify_runtime_evidence_jsonl"),
        "main() must import verify_runtime_evidence_jsonl",
    )?;
    require(
        src.contains("RuntimeEvidenceExpectation") && src.contains("RuntimeEvidenceVerifierConfig"),
        "main() must import RuntimeEvidenceExpectation + RuntimeEvidenceVerifierConfig",
    )
}

fn run_cli(
    bin: &Path,
    jsonl: &Path,
    expected_source_commit: &str,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("verify-runtime-evidence")
        .arg("--jsonl")
        .arg(jsonl)
        .arg("--expected-source-commit")
        .arg(expected_source_commit)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

#[test]
fn cli_passes_on_empty_jsonl_log() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("empty", "jsonl")?;
    let output = unique_tmp("empty_out", "jsonl")?;
    std::fs::write(&jsonl, "").map_err(|e| format!("write empty jsonl: {e}"))?;
    let out = run_cli(&bin, &jsonl, "1".repeat(40).as_str(), &output)?;
    if !out.status.success() {
        return Err(format!(
            "verify-runtime-evidence failed on empty log: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "schema")? == "runtime_evidence_verifier.v1",
        "output schema must be runtime_evidence_verifier.v1",
    )?;
    require(
        json_string(&parsed, "status")? == "pass",
        "empty log must produce status=pass",
    )?;
    require(
        json_u64(&parsed, "total_rows")? == 0,
        "empty log must yield total_rows=0",
    )?;
    require(
        json_u64(&parsed, "failure_count")? == 0,
        "empty log must yield failure_count=0",
    )
}

#[test]
fn cli_fails_on_corrupt_jsonl_row() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("corrupt", "jsonl")?;
    let output = unique_tmp("corrupt_out", "jsonl")?;
    std::fs::write(&jsonl, "this is not json\n").map_err(|e| format!("write: {e}"))?;
    let out = run_cli(&bin, &jsonl, "1".repeat(40).as_str(), &output)?;
    require(
        !out.status.success(),
        "corrupt JSONL must cause verify-runtime-evidence to exit non-zero",
    )?;
    // Output file still written before the non-zero exit.
    let parsed = read_record(&output)?;
    require(
        json_string(&parsed, "status")? == "fail",
        "corrupt row must yield status=fail",
    )?;
    require(
        json_u64(&parsed, "failure_count")? >= 1,
        "corrupt row must yield failure_count >= 1",
    )?;
    let failures = parsed
        .get("failures")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing failures array".to_string())?;
    require(
        failures.iter().any(|f| {
            f.get("failure_signature").and_then(Value::as_str)
                == Some("runtime_evidence_corrupt_jsonl")
        }),
        "failures must include runtime_evidence_corrupt_jsonl signature",
    )
}

#[test]
fn cli_fails_closed_on_blank_expected_source_commit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let jsonl = unique_tmp("blank", "jsonl")?;
    let output = unique_tmp("blank_out", "jsonl")?;
    std::fs::write(&jsonl, "").map_err(|e| format!("write: {e}"))?;
    let out = Command::new(&bin)
        .arg("verify-runtime-evidence")
        .arg("--jsonl")
        .arg(&jsonl)
        .arg("--expected-source-commit")
        .arg("")
        .arg("--output")
        .arg(&output)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "blank --expected-source-commit must cause non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("--expected-source-commit must not be empty"),
        "stderr must explain blank --expected-source-commit rejection",
    )
}
