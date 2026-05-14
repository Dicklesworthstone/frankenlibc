//! Conformance gate for the harness binary `diff-kernel-snapshot`
//! subcommand.

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_harness::kernel_snapshot::{RuntimeKernelSnapshotFixtureV1, SnapshotMode};
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
        .join("diff_kernel_snapshot_cli_contract.v1.json")
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
    Ok(std::env::temp_dir().join(format!(
        "bd_diff_kernel_{stem}_{}_{ts}.json",
        std::process::id()
    )))
}

fn write_fixture(path: &Path, fixture: &RuntimeKernelSnapshotFixtureV1) -> TestResult {
    let body = serde_json::to_string_pretty(fixture).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(path, body).map_err(|e| format!("write fixture: {e}"))
}

fn write_value(path: &Path, value: &Value) -> TestResult {
    let body = serde_json::to_string_pretty(value).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(path, body).map_err(|e| format!("write fixture: {e}"))
}

fn fixture(mode: SnapshotMode) -> RuntimeKernelSnapshotFixtureV1 {
    frankenlibc_harness::kernel_snapshot::build_kernel_snapshot_fixture(0xD1FF, 16, mode)
}

fn current_with_alert_delta() -> TestResult<Value> {
    let mut value = serde_json::to_value(fixture(SnapshotMode::Both))
        .map_err(|e| format!("fixture to value: {e}"))?;
    let field = value
        .get_mut("strict")
        .and_then(|v| v.get_mut("snapshot"))
        .and_then(|v| v.get_mut("full_validation_trigger_ppm"))
        .ok_or_else(|| "missing strict.snapshot.full_validation_trigger_ppm".to_string())?;
    *field = Value::from(
        field
            .as_u64()
            .ok_or_else(|| "full_validation_trigger_ppm must be u64".to_string())?
            + 25_000,
    );
    Ok(value)
}

fn run_diff(
    bin: &Path,
    golden: &Path,
    current: &Path,
    mode: &str,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("diff-kernel-snapshot")
        .arg("--golden")
        .arg(golden)
        .arg("--current")
        .arg(current)
        .arg("--mode")
        .arg(mode)
        .output()
        .map_err(|e| format!("spawn harness diff-kernel-snapshot: {e}"))
}

#[test]
fn manifest_anchors_to_diff_kernel_snapshot_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "diff-kernel-snapshot-cli-contract",
        "manifest_id",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "diff-kernel-snapshot",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "io_pattern")? == "stdout_plain_report_no_output_file",
        "io_pattern",
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
        "identical_fixtures_must_render_ok_rows",
        "changed_threshold_field_must_render_alert",
        "unknown_mode_must_fail_closed",
        "missing_selected_mode_must_fail_closed",
        "missing_current_fixture_may_be_synthesized_from_golden_scenario",
        "plain_output_must_include_mode_and_scenario",
    ] {
        require(json_bool(policy, f)?, f)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_diff_kernel_snapshot_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("DiffKernelSnapshot {"),
        "harness.rs must declare DiffKernelSnapshot Command variant",
    )?;
    require(
        src.contains("snapshot_diff::diff_kernel_snapshots"),
        "DiffKernelSnapshot arm must call snapshot_diff::diff_kernel_snapshots",
    )?;
    require(
        src.contains("snapshot_diff::render_plain"),
        "DiffKernelSnapshot arm must expose plain rendering",
    )
}

#[test]
fn cli_identical_fixtures_render_ok_plain_report() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let golden = unique_tmp("identical_golden")?;
    let current = unique_tmp("identical_current")?;
    let fix = fixture(SnapshotMode::Both);
    write_fixture(&golden, &fix)?;
    write_fixture(&current, &fix)?;

    let out = run_diff(&bin, &golden, &current, "strict")?;
    require(
        out.status.success(),
        format!(
            "diff-kernel-snapshot identical fixtures failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    require(
        stdout.contains("runtime_math snapshot diff (mode=strict"),
        "plain report must include mode header",
    )?;
    require(
        stdout.contains("field"),
        "plain report must include field column",
    )?;
    require(
        stdout.contains("status"),
        "plain report must include status column",
    )?;
    require(
        stdout.contains("OK"),
        "identical fixtures must render OK rows",
    )
}

#[test]
fn cli_threshold_change_renders_alert() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let golden = unique_tmp("alert_golden")?;
    let current = unique_tmp("alert_current")?;
    write_fixture(&golden, &fixture(SnapshotMode::Both))?;
    write_value(&current, &current_with_alert_delta()?)?;

    let out = run_diff(&bin, &golden, &current, "strict")?;
    require(
        out.status.success(),
        "changed fixtures should diff successfully",
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    require(
        stdout.contains("full_validation_trigger_ppm"),
        "threshold field must be present in default key fields",
    )?;
    require(
        stdout.contains("ALERT"),
        "large threshold delta must render ALERT",
    )
}

#[test]
fn cli_unknown_mode_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let golden = unique_tmp("unknown_mode_golden")?;
    let current = unique_tmp("unknown_mode_current")?;
    let fix = fixture(SnapshotMode::Both);
    write_fixture(&golden, &fix)?;
    write_fixture(&current, &fix)?;

    let out = run_diff(&bin, &golden, &current, "both")?;
    require(!out.status.success(), "unknown diff mode must fail closed")
}

#[test]
fn cli_missing_selected_mode_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let golden = unique_tmp("missing_mode_golden")?;
    let current = unique_tmp("missing_mode_current")?;
    let fix = fixture(SnapshotMode::Strict);
    write_fixture(&golden, &fix)?;
    write_fixture(&current, &fix)?;

    let out = run_diff(&bin, &golden, &current, "hardened")?;
    require(
        !out.status.success(),
        "missing selected hardened mode must fail closed",
    )
}

#[test]
fn cli_missing_current_fixture_is_synthesized_from_golden_scenario() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let golden = unique_tmp("synth_golden")?;
    let current = unique_tmp("synth_current_missing")?;
    write_fixture(&golden, &fixture(SnapshotMode::Both))?;

    let out = run_diff(&bin, &golden, &current, "strict")?;
    require(
        out.status.success(),
        format!(
            "missing current fixture should be synthesized: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    require(
        stdout.contains("runtime_math snapshot diff"),
        "synthesized current fixture must still render a report",
    )
}
