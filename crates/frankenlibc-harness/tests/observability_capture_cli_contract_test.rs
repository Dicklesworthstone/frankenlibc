//! Conformance gate for the harness binary `observability-capture` subcommand (bd-wn47r).
//!
//! Pins the CLI bridge that exposes
//! `frankenlibc_harness::observability_dashboard::capture_bundle` as a single
//! end-to-end observability bundle generator.

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
        .join("observability_capture_cli_contract.v1.json")
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

fn tmp_dir() -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bd_wn47r_{}_{ts}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_capture(
    bin: &Path,
    out_dir: &Path,
    bead_id: &str,
    run_id: &str,
    mode: &str,
    seed_sample: bool,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("observability-capture")
        .arg("--out-dir")
        .arg(out_dir)
        .arg("--bead-id")
        .arg(bead_id)
        .arg("--run-id")
        .arg(run_id)
        .arg("--mode")
        .arg(mode);
    if seed_sample {
        cmd.arg("--seed-sample");
    }
    cmd.output().map_err(|e| format!("spawn harness: {e}"))
}

#[test]
fn manifest_anchors_to_wn47r_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "observability-capture-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-wn47r", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "observability-capture",
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
    for key in [
        "must_create_out_dir_inputs_subdir",
        "must_emit_three_jsonl_input_files",
        "must_emit_five_dashboard_bundle_artifacts",
        "seed_sample_renders_deterministic_inputs_modulo_timestamps_and_latency",
        "unknown_mode_rejected_with_nonzero_exit",
        "mode_label_in_inputs_matches_cli_mode",
        "bead_id_recorded_in_jsonl_rows",
        "run_id_recorded_in_jsonl_rows",
        "default_invocation_succeeds_when_input_dir_writable",
    ] {
        require(
            json_bool(policy, key)?,
            format!("policy.{key} must be true (manifest pin)"),
        )?;
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
        names.contains(&"frankenlibc_harness::observability_dashboard::capture_bundle"),
        "capture_bundle not pinned",
    )?;
    Ok(())
}

#[test]
fn harness_source_registers_observability_capture_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::ObservabilityCapture"),
        "harness.rs must register Command::ObservabilityCapture match arm",
    )?;
    require(
        body.contains("capture_bundle"),
        "harness.rs must call capture_bundle",
    )?;
    Ok(())
}

#[test]
fn cli_emits_inputs_subdir_and_three_jsonl_files() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let dir = tmp_dir()?;
    let result = run_capture(&bin, &dir, "bd-wn47r-gate", "gate_run", "hardened", true)?;
    require(
        result.status.success(),
        format!("harness exit failed: {:?}", result.status),
    )?;
    let inputs = dir.join("inputs");
    require(inputs.exists(), "inputs subdir must exist")?;
    for name in [
        "membrane_metrics.jsonl",
        "allocator_metrics.jsonl",
        "runtime_math.jsonl",
    ] {
        require(
            inputs.join(name).exists(),
            format!("inputs/{name} must exist"),
        )?;
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_emits_five_dashboard_bundle_artifacts() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let result = run_capture(&bin, &dir, "bd-wn47r-gate", "gate_run", "hardened", true)?;
    require(result.status.success(), "harness exit failed")?;
    for name in [
        "observability_dashboard.current.v1.json",
        "observability_dashboard.prom",
        "observability_dashboard.statsd",
        "observability_dashboard.grafana.json",
        "observability_dashboard.alerts.yaml",
    ] {
        require(dir.join(name).exists(), format!("{name} must be written"))?;
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_unknown_mode_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let result = run_capture(&bin, &dir, "bd-wn47r-bogus", "gate_bogus", "mango", true)?;
    require(
        !result.status.success(),
        "harness must exit non-zero on unknown mode",
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn strip_volatile_fields(body: &str) -> String {
    const VOLATILE_FIELDS: &[&str] = &["timestamp", "latency_ns", "snapshot_capture_latency_ns"];
    body.lines()
        .map(|line| match serde_json::from_str::<Value>(line) {
            Ok(mut v) => {
                if let Some(obj) = v.as_object_mut() {
                    for f in VOLATILE_FIELDS {
                        obj.remove(*f);
                    }
                }
                serde_json::to_string(&v).unwrap_or_else(|_| line.to_string())
            }
            Err(_) => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn cli_seed_sample_renders_deterministic_inputs_modulo_timestamps_and_latency() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let a = tmp_dir()?;
    let b = tmp_dir()?;
    let _ = run_capture(&bin, &a, "bd-wn47r-det", "gate_det", "strict", true)?;
    let _ = run_capture(&bin, &b, "bd-wn47r-det", "gate_det", "strict", true)?;
    for name in [
        "membrane_metrics.jsonl",
        "allocator_metrics.jsonl",
        "runtime_math.jsonl",
    ] {
        let body_a = std::fs::read_to_string(a.join("inputs").join(name))
            .map_err(|e| format!("read a/{name}: {e}"))?;
        let body_b = std::fs::read_to_string(b.join("inputs").join(name))
            .map_err(|e| format!("read b/{name}: {e}"))?;
        require(
            strip_volatile_fields(&body_a) == strip_volatile_fields(&body_b),
            format!(
                "seeded inputs/{name} must be byte-identical across runs modulo timestamps + latency"
            ),
        )?;
    }
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
    Ok(())
}

#[test]
fn cli_bead_id_and_run_id_recorded_in_membrane_jsonl() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let bead = "bd-wn47r-record";
    let run = "gate_record_42";
    let _ = run_capture(&bin, &dir, bead, run, "hardened", true)?;
    let body = std::fs::read_to_string(dir.join("inputs").join("membrane_metrics.jsonl"))
        .map_err(|e| format!("read membrane_metrics.jsonl: {e}"))?;
    require(
        body.contains(bead),
        format!("membrane_metrics.jsonl must contain bead_id={bead}"),
    )?;
    require(
        body.contains(run),
        format!("membrane_metrics.jsonl must contain run_id={run}"),
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
