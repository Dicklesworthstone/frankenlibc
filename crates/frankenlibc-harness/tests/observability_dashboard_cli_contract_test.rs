//! Conformance gate for the harness binary `observability-dashboard` subcommand (bd-djtar).
//!
//! Pins the CLI bridge exposing
//! `frankenlibc_harness::observability_dashboard::write_bundle` as a CLI that
//! ingests JSONL metric/evidence inputs and writes 5 dashboard artifacts.
//! Companion downstream of `observability-capture` (bd-wn47r).

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
        .join("observability_dashboard_cli_contract.v1.json")
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
    let dir = std::env::temp_dir().join(format!("bd_djtar_{}_{ts}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

// Produce a minimal valid JSONL metric input by invoking observability-capture
// (bd-wn47r) into a scratch directory and returning its 3 input file paths.
fn seed_inputs_via_capture(bin: &Path, dir: &Path) -> TestResult<Vec<PathBuf>> {
    let result = Command::new(bin)
        .arg("observability-capture")
        .arg("--out-dir")
        .arg(dir)
        .arg("--bead-id")
        .arg("bd-djtar-seed")
        .arg("--run-id")
        .arg("gate_seed")
        .arg("--mode")
        .arg("hardened")
        .arg("--seed-sample")
        .output()
        .map_err(|e| format!("seed capture spawn: {e}"))?;
    require(
        result.status.success(),
        format!("seed capture failed: {:?}", result.status),
    )?;
    let inputs = dir.join("inputs");
    Ok(vec![
        inputs.join("membrane_metrics.jsonl"),
        inputs.join("allocator_metrics.jsonl"),
        inputs.join("runtime_math.jsonl"),
    ])
}

#[test]
fn manifest_anchors_to_djtar_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "observability-dashboard-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-djtar", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "observability-dashboard",
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
    for (field, message) in [
        (
            "must_write_summary_json_at_output_path",
            "must_write_summary_json_at_output_path must be true",
        ),
        (
            "must_write_prometheus_exposition_at_prometheus_output_path",
            "must_write_prometheus_exposition_at_prometheus_output_path must be true",
        ),
        (
            "must_write_statsd_lines_at_statsd_output_path",
            "must_write_statsd_lines_at_statsd_output_path must be true",
        ),
        (
            "must_write_grafana_dashboard_at_grafana_output_path",
            "must_write_grafana_dashboard_at_grafana_output_path must be true",
        ),
        (
            "must_write_alert_rules_yaml_at_alerts_output_path",
            "must_write_alert_rules_yaml_at_alerts_output_path must be true",
        ),
        (
            "summary_records_total_rows_count",
            "summary_records_total_rows_count must be true",
        ),
        (
            "summary_records_invalid_rows_count",
            "summary_records_invalid_rows_count must be true",
        ),
        (
            "accepts_multiple_input_files_via_repeated_flag",
            "accepts_multiple_input_files_via_repeated_flag must be true",
        ),
        (
            "allow_current_dir_mutation",
            "allow_current_dir_mutation must be true",
        ),
        (
            "default_output_paths_when_overrides_omitted",
            "default_output_paths_when_overrides_omitted must be true",
        ),
        (
            "nonexistent_input_path_rejected_with_nonzero_exit",
            "nonexistent_input_path_rejected_with_nonzero_exit must be true",
        ),
        (
            "missing_required_input_flag_rejected_with_nonzero_exit",
            "missing_required_input_flag_rejected_with_nonzero_exit must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
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
        names.contains(&"frankenlibc_harness::observability_dashboard::write_bundle"),
        "write_bundle not pinned",
    )?;
    Ok(())
}

#[test]
fn harness_source_registers_observability_dashboard_subcommand() -> TestResult {
    let root = workspace_root()?;
    let source = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("src")
        .join("bin")
        .join("harness.rs");
    let body = std::fs::read_to_string(&source).map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        body.contains("Command::ObservabilityDashboard"),
        "harness.rs must register Command::ObservabilityDashboard match arm",
    )?;
    require(
        body.contains("write_bundle"),
        "harness.rs must call write_bundle",
    )?;
    Ok(())
}

#[test]
fn cli_writes_all_five_bundle_artifacts_from_three_inputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("harness binary not built; gracefully skipping");
        return Ok(());
    };
    let dir = tmp_dir()?;
    let inputs = seed_inputs_via_capture(&bin, &dir)?;
    let out_summary = dir.join("summary.json");
    let out_prom = dir.join("metrics.prom");
    let out_statsd = dir.join("metrics.statsd");
    let out_grafana = dir.join("dashboard.json");
    let out_alerts = dir.join("alerts.yaml");
    let mut cmd = Command::new(&bin);
    cmd.arg("observability-dashboard")
        .arg("--output")
        .arg(&out_summary)
        .arg("--prometheus-output")
        .arg(&out_prom)
        .arg("--statsd-output")
        .arg(&out_statsd)
        .arg("--grafana-output")
        .arg(&out_grafana)
        .arg("--alerts-output")
        .arg(&out_alerts);
    for p in &inputs {
        cmd.arg("--input").arg(p);
    }
    let result = cmd.output().map_err(|e| format!("spawn: {e}"))?;
    require(
        result.status.success(),
        format!(
            "harness exit failed: {:?}; stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ),
    )?;
    require(out_summary.exists(), "summary output file must be written")?;
    require(out_prom.exists(), "prometheus output file must be written")?;
    require(out_statsd.exists(), "statsd output file must be written")?;
    require(out_grafana.exists(), "grafana output file must be written")?;
    require(out_alerts.exists(), "alerts output file must be written")?;
    let summary = load_json(&out_summary)?;
    require(
        summary.get("summary").is_some(),
        "summary file must have a 'summary' top-level field",
    )?;
    Ok(())
}

#[test]
fn cli_missing_input_flag_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let result = Command::new(&bin)
        .arg("observability-dashboard")
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !result.status.success(),
        "harness must exit non-zero when --input is missing",
    )?;
    Ok(())
}

#[test]
fn cli_nonexistent_input_path_rejected_with_nonzero_exit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let bogus = dir.join("does-not-exist.jsonl");
    let result = Command::new(&bin)
        .arg("observability-dashboard")
        .arg("--input")
        .arg(&bogus)
        .arg("--output")
        .arg(dir.join("summary.json"))
        .arg("--prometheus-output")
        .arg(dir.join("metrics.prom"))
        .arg("--statsd-output")
        .arg(dir.join("metrics.statsd"))
        .arg("--grafana-output")
        .arg(dir.join("dashboard.json"))
        .arg("--alerts-output")
        .arg(dir.join("alerts.yaml"))
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !result.status.success(),
        "harness must exit non-zero on nonexistent input path",
    )?;
    Ok(())
}

#[test]
fn cli_summary_records_total_and_invalid_row_counts() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let inputs = seed_inputs_via_capture(&bin, &dir)?;
    let out_summary = dir.join("summary.json");
    let out_prom = dir.join("metrics.prom");
    let out_statsd = dir.join("metrics.statsd");
    let out_grafana = dir.join("dashboard.json");
    let out_alerts = dir.join("alerts.yaml");
    let mut cmd = Command::new(&bin);
    cmd.arg("observability-dashboard")
        .arg("--output")
        .arg(&out_summary)
        .arg("--prometheus-output")
        .arg(&out_prom)
        .arg("--statsd-output")
        .arg(&out_statsd)
        .arg("--grafana-output")
        .arg(&out_grafana)
        .arg("--alerts-output")
        .arg(&out_alerts);
    for p in &inputs {
        cmd.arg("--input").arg(p);
    }
    let result = cmd.output().map_err(|e| format!("spawn: {e}"))?;
    require(result.status.success(), "harness exit failed")?;
    let summary = load_json(&out_summary)?;
    let s = summary
        .get("summary")
        .ok_or("summary.summary block missing")?;
    let total_rows = s
        .get("total_rows")
        .and_then(Value::as_u64)
        .ok_or("summary.total_rows must be u64")?;
    require(
        total_rows >= 3,
        "summary.total_rows must account for the three seeded JSONL inputs",
    )?;
    require(
        s.get("invalid_rows").and_then(Value::as_u64) == Some(0),
        "summary.invalid_rows must stay zero for seeded inputs",
    )?;
    Ok(())
}

#[test]
fn cli_uses_default_output_paths_when_overrides_omitted() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = tmp_dir()?;
    let inputs = seed_inputs_via_capture(&bin, &dir)?;
    let cwd = dir.join("default_cwd");
    std::fs::create_dir_all(&cwd).map_err(|e| format!("mkdir {cwd:?}: {e}"))?;
    let mut cmd = Command::new(&bin);
    cmd.current_dir(&cwd).arg("observability-dashboard");
    for p in &inputs {
        cmd.arg("--input").arg(p);
    }
    let result = cmd.output().map_err(|e| format!("spawn: {e}"))?;
    require(
        result.status.success(),
        format!(
            "harness default-output invocation failed: {:?}; stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ),
    )?;
    let default_dir = cwd.join("target").join("conformance");
    require(
        default_dir
            .join("observability_dashboard.current.v1.json")
            .exists(),
        "default summary output must be written",
    )?;
    require(
        default_dir.join("observability_dashboard.prom").exists(),
        "default prometheus output must be written",
    )?;
    require(
        default_dir.join("observability_dashboard.statsd").exists(),
        "default statsd output must be written",
    )?;
    require(
        default_dir
            .join("observability_dashboard.grafana.json")
            .exists(),
        "default grafana output must be written",
    )?;
    require(
        default_dir
            .join("observability_dashboard.alerts.yaml")
            .exists(),
        "default alerts output must be written",
    )?;
    Ok(())
}
