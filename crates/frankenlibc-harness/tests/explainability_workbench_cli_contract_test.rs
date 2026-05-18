//! Conformance gate for the harness binary `explainability-workbench`
//! subcommand.

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_harness::structured_log::{
    ArtifactIndex, ArtifactJoinKeys, LogEntry, LogLevel, Outcome,
};
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
        .join("explainability_workbench_cli_contract.v1.json")
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
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(path));
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

fn unique_tmp_dir(label: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc_explainability_workbench_cli_contract_{label}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    Ok(dir)
}

fn sample_entry(
    trace_id: &str,
    scenario_id: &str,
    mode: &str,
    outcome: Outcome,
    decision_id: u64,
    artifact_ref: &str,
) -> LogEntry {
    LogEntry::new(trace_id, LogLevel::Info, "case_result")
        .with_bead("bd-cli-contract")
        .with_scenario_id(scenario_id)
        .with_mode(mode)
        .with_api("malloc", "explainability_workbench_cli")
        .with_decision_path("validator->fingerprint->repair")
        .with_controller_id("runtime_math_kernel.v1")
        .with_decision_action(if outcome == Outcome::Pass {
            "Allow"
        } else {
            "Repair"
        })
        .with_healing_action(if outcome == Outcome::Pass {
            "None"
        } else {
            "ClampSize"
        })
        .with_decision_id(decision_id)
        .with_policy_id(9)
        .with_outcome(outcome)
        .with_artifacts(vec![artifact_ref.to_string()])
        .with_details(serde_json::json!({
            "failure_signature": format!("{scenario_id}_{mode}_signature"),
        }))
}

fn write_sample_inputs(dir: &Path) -> TestResult<(PathBuf, PathBuf)> {
    let log_path = dir.join("workbench.log.jsonl");
    let index_path = dir.join("workbench.artifacts.json");
    let strict = sample_entry(
        "bd-cli-contract::demo::001",
        "demo",
        "strict",
        Outcome::Fail,
        501,
        "artifacts/strict.log",
    );
    let hardened = sample_entry(
        "bd-cli-contract::demo::002",
        "demo",
        "hardened",
        Outcome::Pass,
        502,
        "artifacts/hardened.log",
    );
    let other = sample_entry(
        "bd-cli-contract::other::003",
        "other",
        "strict",
        Outcome::Pass,
        601,
        "artifacts/other.log",
    );
    std::fs::write(
        &log_path,
        format!(
            "{}\n{}\n{}\n",
            strict.to_jsonl().map_err(|e| e.to_string())?,
            hardened.to_jsonl().map_err(|e| e.to_string())?,
            other.to_jsonl().map_err(|e| e.to_string())?
        ),
    )
    .map_err(|e| format!("write {log_path:?}: {e}"))?;

    let mut index = ArtifactIndex::new("demo", "bd-cli-contract");
    index.add_with_join_keys(
        "reports/root-cause.json",
        "report",
        "deadbeef",
        ArtifactJoinKeys {
            decision_ids: vec![501],
            ..ArtifactJoinKeys::default()
        },
    );
    std::fs::write(&index_path, index.to_json().map_err(|e| e.to_string())?)
        .map_err(|e| format!("write {index_path:?}: {e}"))?;
    Ok((log_path, index_path))
}

#[test]
fn manifest_anchors_explainability_workbench_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "explainability-workbench-cli-contract",
        "manifest_id",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "explainability-workbench",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "binary_target")? == "harness",
        "binary_target",
    )?;
    let required_flags: Vec<&str> = json_array(&m, "required_flags")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(required_flags == ["--log"], "required_flags must pin --log")
}

#[test]
fn manifest_policy_pins_cli_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for (field, message) in [
        (
            "must_register_explainability_workbench_subcommand",
            "must_register_explainability_workbench_subcommand must be true",
        ),
        (
            "must_accept_log_only_input",
            "must_accept_log_only_input must be true",
        ),
        (
            "must_join_artifact_index_by_decision_id",
            "must_join_artifact_index_by_decision_id must be true",
        ),
        (
            "must_filter_by_scenario_id",
            "must_filter_by_scenario_id must be true",
        ),
        (
            "must_write_output_when_output_path_is_supplied",
            "must_write_output_when_output_path_is_supplied must be true",
        ),
        (
            "must_preserve_tooling_contract_in_json_output",
            "must_preserve_tooling_contract_in_json_output must be true",
        ),
        (
            "unknown_format_must_fail_closed_without_panic",
            "unknown_format_must_fail_closed_without_panic must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    let output = m
        .get("output_contract")
        .ok_or_else(|| "missing output_contract".to_string())?;
    let formats: Vec<&str> = json_array(output, "supported_formats")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(
        formats == ["json", "plain", "ftui"],
        "supported_formats must pin json/plain/ftui",
    )
}

#[test]
fn harness_source_registers_explainability_workbench_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ExplainabilityWorkbench {"),
        "harness.rs must declare ExplainabilityWorkbench Command variant",
    )?;
    for (anchor, message) in [
        ("        log", "ExplainabilityWorkbench missing field `log`"),
        (
            "        artifact_index",
            "ExplainabilityWorkbench missing field `artifact_index`",
        ),
        (
            "        trace_id",
            "ExplainabilityWorkbench missing field `trace_id`",
        ),
        (
            "        scenario_id",
            "ExplainabilityWorkbench missing field `scenario_id`",
        ),
        (
            "        format",
            "ExplainabilityWorkbench missing field `format`",
        ),
        (
            "        output",
            "ExplainabilityWorkbench missing field `output`",
        ),
        (
            "        ansi",
            "ExplainabilityWorkbench missing field `ansi`",
        ),
        (
            "        width",
            "ExplainabilityWorkbench missing field `width`",
        ),
    ] {
        require(src.contains(anchor), message)?;
    }
    require(
        src.contains("explainability_workbench::build_report"),
        "main() must call build_report",
    )?;
    require(
        src.contains("explainability_workbench::render_plain"),
        "main() must retain plain renderer fallback",
    )?;
    require(
        src.contains("explainability_workbench::render_ftui"),
        "main() must retain ftui renderer path",
    )
}

#[test]
fn cli_writes_json_report_with_joined_artifact_links() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp_dir("json")?;
    let (log_path, index_path) = write_sample_inputs(&tmp)?;
    let output_path = tmp.join("workbench.report.json");

    let run = Command::new(&bin)
        .arg("explainability-workbench")
        .arg("--log")
        .arg(&log_path)
        .arg("--artifact-index")
        .arg(&index_path)
        .arg("--scenario-id")
        .arg("demo")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&output_path)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if !run.status.success() {
        return Err(format!(
            "explainability-workbench failed: status={:?} stderr={}",
            run.status,
            String::from_utf8_lossy(&run.stderr)
        ));
    }

    let report = load_json(&output_path)?;
    require(
        json_string(&report, "bead")? == "bd-26xb.4",
        "report must preserve the workbench bead id",
    )?;
    let scenarios = json_array(&report, "scenarios")?;
    require(
        scenarios.len() == 1,
        format!(
            "scenario-id filter must keep one scenario; got {}",
            scenarios.len()
        ),
    )?;
    let scenario = scenarios
        .first()
        .ok_or_else(|| "scenario-id filter must keep one scenario".to_string())?;
    require(
        json_string(scenario, "scenario_id")? == "demo",
        "scenario_id filter must keep demo",
    )?;
    let mode_divergence = json_array(scenario, "mode_divergence")?;
    let first_divergence = mode_divergence
        .first()
        .ok_or_else(|| "mode_divergence must contain a row".to_string())?;
    let differing_fields = json_array(first_divergence, "differing_fields")?;
    let first_differing_field = differing_fields
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| "differing_fields must contain a string".to_string())?;
    require(
        first_differing_field == "outcome",
        "strict/hardened outcome divergence must be reported",
    )?;
    require(
        json_array(scenario, "artifact_links")?
            .iter()
            .any(|artifact| {
                artifact.get("path").and_then(Value::as_str) == Some("reports/root-cause.json")
            }),
        "artifact index must join by decision_id",
    )?;
    let tooling_contract = report
        .get("tooling_contract")
        .ok_or_else(|| "missing tooling_contract".to_string())?;
    require(
        json_bool(tooling_contract, "default_enables_asupersync_tooling")?,
        "json output must preserve tooling_contract",
    )
}

#[test]
fn cli_unknown_format_fails_closed_without_panic() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let tmp = unique_tmp_dir("unknown_format")?;
    let (log_path, _) = write_sample_inputs(&tmp)?;
    let output_path = tmp.join("workbench.report.txt");

    let run = Command::new(&bin)
        .arg("explainability-workbench")
        .arg("--log")
        .arg(&log_path)
        .arg("--scenario-id")
        .arg("demo")
        .arg("--format")
        .arg("surprise")
        .arg("--output")
        .arg(&output_path)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(!run.status.success(), "unknown format must return nonzero")?;
    let stderr = String::from_utf8_lossy(&run.stderr);
    require(
        stderr.contains("Unsupported format 'surprise', expected json|plain|ftui"),
        format!("unknown format must fail closed with diagnostic; stderr={stderr}"),
    )
}
