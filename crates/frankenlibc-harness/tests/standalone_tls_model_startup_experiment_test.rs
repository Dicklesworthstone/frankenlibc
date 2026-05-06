//! Integration test: standalone TLS model/startup experiment (bd-84m77).
//!
//! Captures the current report-only TLS model probes so profile-only TLS changes
//! cannot be mistaken for standalone replacement evidence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const TLS_SYMBOL: &str = "__tls_get_addr@GLIBC_2.3";
const TLS_VERSION_REQUIREMENT: &str = "ld-linux-x86-64.so.2:GLIBC_2.3";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_standalone_tls_model_startup_experiment.sh")
}

fn experiment_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_tls_model_startup_experiment.v1.json")
}

fn diagnostic_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_tls_blocker_diagnostics.v1.json")
}

fn version_burndown_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_host_version_requirement_burndown.v1.json")
}

fn load_json_path(path: &Path) -> TestResult<Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| format!("{field} must be present"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    let array = if let Some(array) = value.as_array() {
        array
    } else {
        json_array(value, field)?
    };
    array
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn run_checker(root: &Path, experiment: &Path, label: &str) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target").join("conformance").join(format!(
        "standalone_tls_model_startup_experiment.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_TLS_MODEL_EXPERIMENT", experiment)
        .env(
            "FRANKENLIBC_STANDALONE_TLS_MODEL_EXPERIMENT_REPORT",
            &report,
        )
        .current_dir(root)
        .output()
        .map_err(|err| format!("failed to run TLS model experiment checker: {err}"))?;
    Ok((output, report))
}

fn format_output(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_checker_failure(experiment: &Path, label: &str, expected_error: &str) -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, experiment, label)?;
    require(
        !output.status.success(),
        format!("checker unexpectedly passed\n{}", format_output(&output)),
    )?;
    let report_json = load_json_path(&report)?;
    let errors = json_array(&report_json, "errors")?;
    require(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(expected_error)),
        format!("expected error {expected_error:?}; report={report_json:?}"),
    )
}

fn unique_label(prefix: &str) -> TestResult<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time before UNIX_EPOCH: {err}"))?
        .as_nanos();
    Ok(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn write_mutated_experiment(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut experiment = load_json_path(&experiment_manifest_path(&root))?;
    mutate(&mut experiment)?;
    let dir = root
        .join("target")
        .join("conformance")
        .join("mutated-tls-model-experiments");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&experiment)
        .map_err(|err| format!("failed to serialize mutated experiment: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn set_object_field(value: &mut Value, field: &str, replacement: Value) -> TestResult {
    value
        .as_object_mut()
        .ok_or_else(|| "value must be an object".to_string())?
        .insert(field.to_owned(), replacement);
    Ok(())
}

fn lane_mut<'a>(experiment: &'a mut Value, lane_id: &str) -> TestResult<&'a mut Value> {
    experiment
        .get_mut("experiment_lanes")
        .ok_or_else(|| "experiment_lanes must be present".to_string())?
        .as_array_mut()
        .ok_or_else(|| "experiment_lanes must be an array".to_string())?
        .iter_mut()
        .find(|lane| lane.get("lane_id").and_then(Value::as_str) == Some(lane_id))
        .ok_or_else(|| format!("missing lane {lane_id}"))
}

#[test]
fn tls_model_experiment_records_probe_limits() -> TestResult {
    let root = workspace_root()?;
    let experiment = load_json_path(&experiment_manifest_path(&root))?;
    let diagnostic = load_json_path(&diagnostic_manifest_path(&root))?;
    let version = load_json_path(&version_burndown_manifest_path(&root))?;

    require(
        json_string(&experiment, "manifest_id")? == "standalone-tls-model-startup-experiment",
        "manifest id",
    )?;
    require(json_string(&experiment, "bead")? == "bd-84m77", "bead")?;
    let controls = json_field(&experiment, "artifact_controls")?;
    let clearance = string_set(controls, "required_absence_before_clearance")?;
    require(
        clearance.contains("nm -D reports no undefined __tls_get_addr symbol"),
        "clearance must require nm absence",
    )?;
    require(
        clearance.contains("readelf -Ws reports no undefined __tls_get_addr symbol"),
        "clearance must require readelf symbol absence",
    )?;

    let lanes = json_array(&experiment, "experiment_lanes")?;
    require(lanes.len() == 3, "lane count")?;
    let initial = lanes
        .iter()
        .find(|lane| json_string(lane, "lane_id").ok() == Some("initial-exec-tls-model-probe"))
        .ok_or_else(|| "initial-exec lane must be present".to_string())?;
    require(
        json_string(initial, "build_status")? == "pass",
        "initial-exec build status",
    )?;
    require(
        string_set(
            json_field(initial, "undefined_tls_symbols")?,
            "initial TLS symbols",
        )? == BTreeSet::from([TLS_SYMBOL.to_owned()]),
        "initial-exec must keep TLS blocker",
    )?;
    require(
        string_set(
            json_field(initial, "host_version_requirements")?,
            "initial host version requirements",
        )? == BTreeSet::from([TLS_VERSION_REQUIREMENT.to_owned()]),
        "initial-exec must keep TLS version requirement",
    )?;
    let local = lanes
        .iter()
        .find(|lane| json_string(lane, "lane_id").ok() == Some("local-exec-tls-model-probe"))
        .ok_or_else(|| "local-exec lane must be present".to_string())?;
    require(
        json_string(local, "failure_signature")?
            .contains("non_pic_tls_relocation_in_shared_dependency"),
        "local-exec failure signature",
    )?;
    require(
        json_field(local, "artifact_produced")?.as_bool() == Some(false),
        "local-exec artifact production",
    )?;

    require(
        json_field(
            json_field(&diagnostic, "summary")?,
            "undefined_tls_symbol_count",
        )?
        .as_u64()
            == Some(1),
        "diagnostic TLS positive control",
    )?;
    let version_row = json_array(&version, "version_requirement_matrix")?
        .iter()
        .find(|row| json_string(row, "requirement_id").ok() == Some(TLS_VERSION_REQUIREMENT))
        .ok_or_else(|| "TLS version row must exist".to_string())?;
    require(
        string_set(
            json_field(version_row, "observed_symbols")?,
            "observed symbols",
        )?
        .contains(TLS_SYMBOL),
        "version row must tie to TLS symbol",
    )
}

#[test]
fn checker_materializes_tls_model_report() -> TestResult {
    let root = workspace_root()?;
    let experiment = experiment_manifest_path(&root);
    let (output, report) = run_checker(&root, &experiment, "canonical")?;
    require(
        output.status.success(),
        format!("checker failed\n{}", format_output(&output)),
    )?;
    let report = load_json_path(&report)?;
    require(json_string(&report, "status")? == "pass", "report status")?;
    require(
        json_string(&report, "claim_status")? == "report_only",
        "claim status",
    )?;
    require(
        json_string(&report, "standalone_claim_status")? == "claim_blocked",
        "standalone claim status",
    )?;
    let summary = json_field(&report, "summary")?;
    require(
        json_string(summary, "initial_exec_delta_classification")? == "unchanged",
        "initial-exec delta",
    )?;
    require(
        json_string(summary, "local_exec_failure_signature")?
            == "non_pic_tls_relocation_in_shared_dependency",
        "local-exec failure",
    )
}

#[test]
fn checker_rejects_stale_source_commit() -> TestResult {
    let mutated = write_mutated_experiment("stale-source", |experiment| {
        set_object_field(
            experiment,
            "source_commit",
            Value::String("0000000000000000000000000000000000000000".to_owned()),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "stale-source",
        "experiment source_commit must be 'current' or match current git HEAD",
    )
}

#[test]
fn checker_rejects_initial_exec_tls_overclaim() -> TestResult {
    let mutated = write_mutated_experiment("initial-exec-overclaim", |experiment| {
        let lane = lane_mut(experiment, "initial-exec-tls-model-probe")?;
        set_object_field(lane, "undefined_tls_symbols", Value::Array(vec![]))
    })?;
    expect_checker_failure(
        &mutated,
        "initial-exec-overclaim",
        "initial-exec lane must keep __tls_get_addr@GLIBC_2.3 as an active blocker",
    )
}

#[test]
fn checker_rejects_local_exec_promotion_claim() -> TestResult {
    let mutated = write_mutated_experiment("local-exec-promotion", |experiment| {
        let lane = lane_mut(experiment, "local-exec-tls-model-probe")?;
        set_object_field(lane, "build_status", Value::String("pass".to_owned()))?;
        set_object_field(lane, "artifact_produced", Value::Bool(true))
    })?;
    expect_checker_failure(
        &mutated,
        "local-exec-promotion",
        "local-exec lane must remain a failed cdylib-inapplicable negative control",
    )
}

#[test]
fn checker_rejects_standalone_promotion_claim() -> TestResult {
    let mutated = write_mutated_experiment("promotion-overclaim", |experiment| {
        let summary = experiment
            .get_mut("summary")
            .ok_or_else(|| "summary must be present".to_string())?;
        set_object_field(
            summary,
            "standalone_claim_status",
            Value::String("standalone_evidence_passed".to_owned()),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "promotion-overclaim",
        "summary.standalone_claim_status must be claim_blocked",
    )
}

#[test]
fn checker_rejects_missing_artifact_controls() -> TestResult {
    let mutated = write_mutated_experiment("missing-controls", |experiment| {
        let controls = experiment
            .get_mut("artifact_controls")
            .ok_or_else(|| "artifact_controls must be present".to_string())?;
        set_object_field(
            controls,
            "required_absence_before_clearance",
            Value::Array(vec![Value::String(
                "artifact_state.dependency_breakdown.undefined_tls_symbols is empty".to_owned(),
            )]),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "missing-controls",
        "artifact_controls must require nm/readelf absence before clearance",
    )
}
