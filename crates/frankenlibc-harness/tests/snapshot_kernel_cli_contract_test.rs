//! Conformance gate for the harness binary `snapshot-kernel` subcommand (bd-7br45).
//!
//! Pins the CLI bridge that exposes
//! `frankenlibc_harness::kernel_snapshot::build_kernel_snapshot_fixture` /
//! `SnapshotMode::from_str_loose` as a deterministic fixture producer
//! used for snapshot diffing and sha256 gating.

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
        .join("snapshot_kernel_cli_contract.v1.json")
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

fn unique_tmp(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("bd_7br45_{stem}_{}_{ts}.json", std::process::id())))
}

fn run_snapshot(
    bin: &Path,
    output: &Path,
    mode: &str,
    seed: &str,
    steps: u32,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("snapshot-kernel")
        .arg("--output")
        .arg(output)
        .arg("--mode")
        .arg(mode)
        .arg("--seed")
        .arg(seed)
        .arg("--steps")
        .arg(steps.to_string())
        .output()
        .map_err(|e| format!("spawn harness snapshot-kernel: {e}"))
}

#[test]
fn manifest_anchors_to_7br45_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "snapshot-kernel-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-7br45", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "snapshot-kernel",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "binary_target")? == "harness",
        "binary_target mismatch",
    )?;
    Ok(())
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for (key, message) in [
        (
            "must_write_one_output_file_at_output_path",
            "policy.must_write_one_output_file_at_output_path must be true (manifest pin)",
        ),
        (
            "no_stdout_jsonl_records_emitted",
            "policy.no_stdout_jsonl_records_emitted must be true (manifest pin)",
        ),
        (
            "mode_strict_emits_strict_only",
            "policy.mode_strict_emits_strict_only must be true (manifest pin)",
        ),
        (
            "mode_hardened_emits_hardened_only",
            "policy.mode_hardened_emits_hardened_only must be true (manifest pin)",
        ),
        (
            "mode_both_emits_both_blocks",
            "policy.mode_both_emits_both_blocks must be true (manifest pin)",
        ),
        (
            "deterministic_given_same_seed_steps_mode",
            "policy.deterministic_given_same_seed_steps_mode must be true (manifest pin)",
        ),
        (
            "no_timestamps_in_fixture",
            "policy.no_timestamps_in_fixture must be true (manifest pin)",
        ),
        (
            "stable_ordering_across_runs",
            "policy.stable_ordering_across_runs must be true (manifest pin)",
        ),
        (
            "scenario_families_count_is_seven",
            "policy.scenario_families_count_is_seven must be true (manifest pin)",
        ),
        (
            "version_field_is_v1",
            "policy.version_field_is_v1 must be true (manifest pin)",
        ),
        (
            "unknown_mode_rejected_with_nonzero_exit",
            "policy.unknown_mode_rejected_with_nonzero_exit must be true (manifest pin)",
        ),
    ] {
        require(json_bool(policy, key)?, message)?;
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
        names.contains(&"frankenlibc_harness::kernel_snapshot::build_kernel_snapshot_fixture"),
        "build_kernel_snapshot_fixture not pinned",
    )?;
    require(
        names.contains(&"frankenlibc_harness::kernel_snapshot::SnapshotMode::from_str_loose"),
        "SnapshotMode::from_str_loose not pinned",
    )?;
    Ok(())
}

#[test]
fn harness_source_registers_snapshot_kernel_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::SnapshotKernel"),
        "harness.rs must register Command::SnapshotKernel match arm",
    )?;
    require(
        body.contains("build_kernel_snapshot_fixture"),
        "harness.rs must call build_kernel_snapshot_fixture",
    )?;
    Ok(())
}

#[test]
fn cli_mode_both_emits_both_blocks() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let out = unique_tmp("both")?;
    let result = run_snapshot(&bin, &out, "both", "0xDEADBEEF", 32)?;
    require(
        result.status.success(),
        format!("harness exit failed: {:?}", result.status),
    )?;
    let body = std::fs::read_to_string(&out).map_err(|e| format!("read fixture: {e}"))?;
    let fixture: Value = serde_json::from_str(&body).map_err(|e| format!("parse fixture: {e}"))?;
    require(
        json_string(&fixture, "version")? == "v1",
        "version must be v1",
    )?;
    require(fixture.get("strict").is_some(), "strict block missing")?;
    require(fixture.get("hardened").is_some(), "hardened block missing")?;
    Ok(())
}

#[test]
fn cli_mode_strict_emits_strict_only() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let out = unique_tmp("strict")?;
    let result = run_snapshot(&bin, &out, "strict", "0x1234", 16)?;
    require(result.status.success(), "harness exit failed")?;
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(&out).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    require(fixture.get("strict").is_some(), "strict block missing")?;
    require(
        fixture.get("hardened").is_none() || fixture.get("hardened") == Some(&Value::Null),
        "hardened block must be omitted in strict mode",
    )?;
    Ok(())
}

#[test]
fn cli_mode_hardened_emits_hardened_only() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let out = unique_tmp("hardened")?;
    let result = run_snapshot(&bin, &out, "hardened", "0x42", 16)?;
    require(result.status.success(), "harness exit failed")?;
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(&out).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    require(fixture.get("hardened").is_some(), "hardened block missing")?;
    require(
        fixture.get("strict").is_none() || fixture.get("strict") == Some(&Value::Null),
        "strict block must be omitted in hardened mode",
    )?;
    Ok(())
}

#[test]
fn cli_scenario_id_and_families_match_manifest() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let out = unique_tmp("scenario")?;
    let result = run_snapshot(&bin, &out, "both", "0xDEAD_BEEF", 64)?;
    require(result.status.success(), "harness exit failed")?;
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(&out).map_err(|e| format!("read: {e}"))?)
            .map_err(|e| format!("parse: {e}"))?;
    let scenario = fixture.get("scenario").ok_or("scenario block missing")?;
    let expected_id = m
        .get("output_file_contract")
        .and_then(|c| c.get("scenario_id_value"))
        .and_then(Value::as_str)
        .ok_or("manifest missing scenario_id_value")?;
    require(
        json_string(scenario, "id")? == expected_id,
        format!("scenario.id must be {expected_id}"),
    )?;
    require(json_u64(scenario, "steps")? == 64, "steps must roundtrip")?;
    let families = scenario
        .get("families")
        .and_then(Value::as_array)
        .ok_or("scenario.families missing")?;
    let expected_order = m
        .get("output_file_contract")
        .and_then(|c| c.get("scenario_families_order"))
        .and_then(Value::as_array)
        .ok_or("manifest missing scenario_families_order")?;
    let actual: Vec<&str> = families.iter().filter_map(Value::as_str).collect();
    let expected: Vec<&str> = expected_order.iter().filter_map(Value::as_str).collect();
    require(
        actual == expected,
        format!("families order mismatch: actual={actual:?} expected={expected:?}"),
    )?;
    require(actual.len() == 7, "families must have exactly 7 entries")?;
    Ok(())
}

#[test]
fn cli_deterministic_for_same_seed_steps_mode() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let out_a = unique_tmp("det_a")?;
    let out_b = unique_tmp("det_b")?;
    let _ = run_snapshot(&bin, &out_a, "both", "0xBEEF", 24)?;
    let _ = run_snapshot(&bin, &out_b, "both", "0xBEEF", 24)?;
    let body_a = std::fs::read_to_string(&out_a).map_err(|e| format!("read a: {e}"))?;
    let body_b = std::fs::read_to_string(&out_b).map_err(|e| format!("read b: {e}"))?;
    require(
        body_a == body_b,
        "fixture bytes must match for same seed+steps+mode",
    )?;
    Ok(())
}

#[test]
fn cli_unknown_mode_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let out = unique_tmp("bogus")?;
    let result = Command::new(&bin)
        .arg("snapshot-kernel")
        .arg("--output")
        .arg(&out)
        .arg("--mode")
        .arg("totally-not-a-mode")
        .arg("--steps")
        .arg("4")
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !result.status.success(),
        "harness must exit non-zero on unknown mode",
    )?;
    Ok(())
}
