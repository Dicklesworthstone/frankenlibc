//! Conformance gate for the harness binary `proof-chain-e2e` subcommand.

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
        .join("proof_chain_e2e_cli_contract.v1.json")
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
        "proof_chain_e2e_cli_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_proof_chain_cli(bin: &Path, dir: &Path) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("proof-chain-e2e")
        .arg("--workspace-root")
        .arg(&root)
        .arg("--log")
        .arg(dir.join("proof_chain.log.jsonl"))
        .arg("--report")
        .arg(dir.join("proof_chain.report.json"))
        .arg("--binder-log")
        .arg(dir.join("proof_chain.binder.log.jsonl"))
        .arg("--binder-report")
        .arg(dir.join("proof_chain.binder.report.json"))
        .arg("--validator-report")
        .arg(dir.join("proof_chain.validator.json"))
        .arg("--cross-report")
        .arg(dir.join("proof_chain.cross_report.json"))
        .output()
        .map_err(|e| format!("spawn harness proof-chain-e2e: {e}"))
}

#[test]
fn manifest_anchors_to_proof_chain_e2e_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "proof-chain-e2e-cli-contract",
        "manifest_id mismatch",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "proof-chain-e2e",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "jsonl_log_plus_json_report_plus_nested_binder_and_cross_report_artifacts",
        "io_pattern mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_write_top_level_jsonl_log_file",
        "must_write_top_level_json_report_file",
        "must_write_nested_binder_log_and_report_files",
        "must_write_validator_snapshot_and_cross_report_files",
        "creates_parent_directories_for_output_paths_if_missing",
        "exits_nonzero_when_summary_failed_nonzero",
        "exits_zero_when_summary_failed_count_is_zero",
        "report_schema_version_must_be_v1",
        "report_bead_must_remain_bd_34s_6",
        "log_must_include_scope_binder_integrity_dashboard_cross_report_and_summary_events",
        "scope_boundary_must_state_non_claim_about_theorem_level_completeness",
    ] {
        require(json_bool(policy, key)?, key)?;
    }
    Ok(())
}

#[test]
fn manifest_underlying_lib_functions_are_pinned() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let funcs = m
        .get("underlying_lib_functions")
        .and_then(Value::as_array)
        .ok_or("underlying_lib_functions missing")?;
    let names: Vec<&str> = funcs.iter().filter_map(Value::as_str).collect();
    require(
        names.contains(&"frankenlibc_harness::proof_chain_e2e::run_and_write"),
        "proof_chain_e2e::run_and_write not pinned",
    )?;
    require(
        names.contains(&"frankenlibc_harness::proof_binder_proofs::run_and_write"),
        "nested proof_binder_proofs::run_and_write not pinned",
    )
}

#[test]
fn harness_source_registers_proof_chain_e2e_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = root.join("crates/frankenlibc-harness/src/bin/harness.rs");
    let body = std::fs::read_to_string(&src).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::ProofChainE2e"),
        "harness.rs must register ProofChainE2e",
    )?;
    require(
        body.contains("proof_chain_e2e::run_and_write"),
        "ProofChainE2e arm must call proof_chain_e2e::run_and_write",
    )?;
    require(
        body.contains("proof chain e2e FAILED"),
        "ProofChainE2e arm must fail closed on failed checks",
    )
}

#[test]
fn cli_writes_all_chain_artifacts() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("ok")?;
    let out = run_proof_chain_cli(&bin, &dir)?;
    require(
        out.status.success(),
        format!(
            "proof-chain-e2e failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;

    for (label, artifact) in [
        ("top-level log", dir.join("proof_chain.log.jsonl")),
        ("top-level report", dir.join("proof_chain.report.json")),
        (
            "nested binder log",
            dir.join("proof_chain.binder.log.jsonl"),
        ),
        (
            "nested binder report",
            dir.join("proof_chain.binder.report.json"),
        ),
        ("validator snapshot", dir.join("proof_chain.validator.json")),
        ("cross report", dir.join("proof_chain.cross_report.json")),
    ] {
        require(artifact.exists(), label)?;
    }

    let report = load_json(&dir.join("proof_chain.report.json"))?;
    require(
        report.get("schema_version").and_then(Value::as_str) == Some("v1"),
        "schema_version must be v1",
    )?;
    require(
        report.get("bead").and_then(Value::as_str) == Some("bd-34s.6"),
        "report bead must remain bd-34s.6",
    )?;
    require(
        report
            .get("summary")
            .and_then(|v| v.get("failed"))
            .and_then(Value::as_u64)
            == Some(0),
        "summary.failed must be zero",
    )?;
    for component in [
        "proof_binder",
        "chain_integrity",
        "dashboard",
        "cross_report_consistency",
    ] {
        require(
            report
                .get(component)
                .and_then(|v| v.get("ok"))
                .and_then(Value::as_bool)
                == Some(true),
            component,
        )?;
    }
    Ok(())
}

#[test]
fn cli_log_includes_required_chain_events() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = unique_tmp_dir("events")?;
    let out = run_proof_chain_cli(&bin, &dir)?;
    require(
        out.status.success(),
        format!(
            "proof-chain-e2e failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    let rows = load_jsonl(&dir.join("proof_chain.log.jsonl"))?;
    for event in [
        "proof_chain.scope_boundary",
        "proof_chain.proof_binder",
        "proof_chain.chain_integrity",
        "proof_chain.dashboard",
        "proof_chain.cross_report_consistency",
        "proof_chain.summary",
    ] {
        require(
            rows.iter()
                .any(|row| row.get("event").and_then(Value::as_str) == Some(event)),
            event,
        )?;
    }
    require(
        rows.iter().any(|row| {
            row.get("event").and_then(Value::as_str) == Some("proof_chain.scope_boundary")
                && row
                    .get("details")
                    .and_then(|v| v.get("non_claim"))
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.contains("theorem-level mechanized proof"))
        }),
        "scope boundary must retain explicit theorem-level non-claim",
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
        .arg("proof-chain-e2e")
        .arg("--workspace-root")
        .arg(&bad_root)
        .arg("--log")
        .arg(dir.join("bad.log.jsonl"))
        .arg("--report")
        .arg(dir.join("bad.report.json"))
        .arg("--binder-log")
        .arg(dir.join("bad.binder.log.jsonl"))
        .arg("--binder-report")
        .arg(dir.join("bad.binder.report.json"))
        .arg("--validator-report")
        .arg(dir.join("bad.validator.json"))
        .arg("--cross-report")
        .arg(dir.join("bad.cross_report.json"))
        .output()
        .map_err(|e| format!("spawn harness proof-chain-e2e: {e}"))?;
    require(
        !out.status.success(),
        "invalid workspace root must fail closed",
    )
}
