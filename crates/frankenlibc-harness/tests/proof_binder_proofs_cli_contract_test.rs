//! Conformance gate for the harness binary `proof-binder-proofs`
//! subcommand.

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
        .join("proof_binder_proofs_cli_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| format!("parse jsonl: {err}")))
        .collect()
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

fn unique_tmp_dir(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "proof_binder_proofs_cli_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_proof_binder_cli(bin: &Path, dir: &Path) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("proof-binder-proofs")
        .arg("--workspace-root")
        .arg(&root)
        .arg("--log")
        .arg(dir.join("proof_binder.log.jsonl"))
        .arg("--report")
        .arg(dir.join("proof_binder.report.json"))
        .arg("--validator-report")
        .arg(dir.join("proof_binder.validator.json"))
        .output()
        .map_err(|e| format!("spawn harness proof-binder-proofs: {e}"))
}

#[test]
fn manifest_anchors_to_proof_binder_proofs_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "proof-binder-proofs-cli-contract",
        "manifest_id mismatch",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "proof-binder-proofs",
        "subcommand_name mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-l19e4", "bead mismatch")?;
    require(
        json_string(&m, "io_pattern")? == "jsonl_log_plus_json_report_plus_validator_snapshot",
        "io_pattern mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_write_jsonl_log_file_at_log_path",
        "must_write_json_report_file_at_report_path",
        "must_write_validator_snapshot_at_validator_report_path",
        "creates_parent_directories_for_output_paths_if_missing",
        "exits_nonzero_when_summary_failed_nonzero",
        "exits_zero_when_summary_failed_count_is_zero",
        "report_schema_version_must_be_v1",
        "report_bead_must_remain_bd_34s_5",
        "log_must_include_scope_validator_python_tests_regression_and_summary_events",
        "scope_boundary_must_state_non_claim_about_unrepresented_proof_artifacts",
    ] {
        require(json_bool(policy, key)?, key)?;
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
        names.contains(&"frankenlibc_harness::proof_binder_proofs::run_and_write"),
        "proof_binder_proofs::run_and_write not pinned",
    )
}

#[test]
fn harness_source_registers_proof_binder_proofs_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = root.join("crates/frankenlibc-harness/src/bin/harness.rs");
    let body = std::fs::read_to_string(&src).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::ProofBinderProofs"),
        "harness.rs must register ProofBinderProofs",
    )?;
    require(
        body.contains("proof_binder_proofs::run_and_write"),
        "ProofBinderProofs arm must call proof_binder_proofs::run_and_write",
    )?;
    require(
        body.contains("proof binder proofs FAILED"),
        "ProofBinderProofs arm must fail closed on failed checks",
    )
}

#[test]
fn cli_writes_log_report_and_validator_snapshot() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("ok")?;
    let out = run_proof_binder_cli(&bin, &dir)?;
    require(
        out.status.success(),
        format!(
            "proof-binder-proofs failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;

    let log = dir.join("proof_binder.log.jsonl");
    let report = dir.join("proof_binder.report.json");
    let validator = dir.join("proof_binder.validator.json");
    require(log.exists(), "log path must exist")?;
    require(report.exists(), "report path must exist")?;
    require(validator.exists(), "validator snapshot path must exist")?;

    let report_value = load_json(&report)?;
    require(
        report_value.get("schema_version").and_then(Value::as_str) == Some("v1"),
        "report schema_version must be v1",
    )?;
    require(
        report_value.get("bead").and_then(Value::as_str) == Some("bd-34s.5"),
        "report bead must remain bd-34s.5",
    )?;
    require(
        report_value
            .get("summary")
            .and_then(|v| v.get("failed"))
            .and_then(Value::as_u64)
            == Some(0),
        "summary.failed must be zero",
    )?;
    require(
        report_value
            .get("validator")
            .and_then(|v| v.get("ok"))
            .and_then(Value::as_bool)
            == Some(true),
        "validator command must pass",
    )?;
    require(
        report_value
            .get("python_tests")
            .and_then(|v| v.get("ok"))
            .and_then(Value::as_bool)
            == Some(true),
        "python test pack must pass",
    )
}

#[test]
fn cli_log_includes_required_proof_events() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = unique_tmp_dir("events")?;
    let out = run_proof_binder_cli(&bin, &dir)?;
    require(
        out.status.success(),
        format!(
            "proof-binder-proofs failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    let rows = load_jsonl(&dir.join("proof_binder.log.jsonl"))?;
    for event in [
        "proof_binder.scope_boundary",
        "proof_binder.validator",
        "proof_binder.python_tests",
        "proof_binder.snapshot_regression",
        "proof_binder.summary",
    ] {
        require(
            rows.iter()
                .any(|row| row.get("event").and_then(Value::as_str) == Some(event)),
            event,
        )?;
    }
    require(
        rows.iter().any(|row| {
            row.get("event").and_then(Value::as_str) == Some("proof_binder.scope_boundary")
                && row
                    .get("details")
                    .and_then(|v| v.get("non_claim"))
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.contains("not prove Lean/Coq/Kani artifacts"))
        }),
        "scope boundary must retain explicit non-claim",
    )
}

#[test]
fn cli_unknown_workspace_root_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = unique_tmp_dir("bad_root")?;
    let bad_root = dir.join("does-not-exist");
    let out = Command::new(&bin)
        .arg("proof-binder-proofs")
        .arg("--workspace-root")
        .arg(&bad_root)
        .arg("--log")
        .arg(dir.join("bad.log.jsonl"))
        .arg("--report")
        .arg(dir.join("bad.report.json"))
        .arg("--validator-report")
        .arg(dir.join("bad.validator.json"))
        .output()
        .map_err(|e| format!("spawn harness proof-binder-proofs: {e}"))?;
    require(
        !out.status.success(),
        "invalid workspace root must fail closed",
    )
}
