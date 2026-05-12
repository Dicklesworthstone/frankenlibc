//! Completion-contract tests for bd-4ia.1 stub priority evidence.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/stub_priority_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_stub_priority_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "stub-priority-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_STUB_PRIORITY_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_STUB_PRIORITY_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STUB_PRIORITY_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_STUB_PRIORITY_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_STUB_PRIORITY_COMPLETION_GATE_STDOUT",
            out_dir.join("gate_stdout.txt"),
        )
        .env(
            "FRANKENLIBC_STUB_PRIORITY_COMPLETION_GATE_STDERR",
            out_dir.join("gate_stderr.txt"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("value should be array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["failure_signature"].as_str().map(str::to_owned))
        .collect()
}

fn mutated_manifest(root: &Path, label: &str, manifest: &Value) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, label)?;
    let path = out_dir.join("contract.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

#[test]
fn manifest_binds_unit_e2e_and_telemetry_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("stub_priority_completion_contract.v1")
    );
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-4ia.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-4ia"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );
    assert_eq!(
        manifest["unit_primary"]["required_harness_tests"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );
    assert_eq!(
        manifest["telemetry_primary"]["required_completion_events"]
            .as_array()
            .map(Vec::len),
        Some(6)
    );
    Ok(())
}

#[test]
fn source_artifacts_bind_existing_stub_priority_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    let ids = artifacts
        .iter()
        .filter_map(|artifact| artifact["id"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids,
        BTreeSet::from([
            "completion_contract".to_string(),
            "completion_gate".to_string(),
            "completion_harness".to_string(),
            "ld_preload_smoke_e2e_index".to_string(),
            "ld_preload_smoke_summary".to_string(),
            "support_matrix".to_string(),
            "stub_priority_gate".to_string(),
            "stub_priority_generator".to_string(),
            "stub_priority_harness".to_string(),
            "stub_priority_ranking".to_string(),
            "verification_matrix".to_string(),
            "workload_matrix".to_string(),
        ])
    );
    for artifact in artifacts {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| test_error("artifact path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in artifact["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required_needles should be array"))?
        {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                text.contains(needle),
                "{path} should contain required needle {needle}"
            );
        }
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS stub priority completion contract"),
        "{}",
        output_text(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("stub_priority_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-4ia.1"));
    assert_eq!(report["source_count"].as_u64(), Some(12));
    assert_eq!(report["unit_test_count"].as_u64(), Some(8));
    assert_eq!(
        report["ranking_summary"]["total_non_implemented"].as_u64(),
        Some(0)
    );
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert!(out_dir.join("gate_stdout.txt").is_file());
    assert!(
        fs::read_to_string(out_dir.join("gate_stdout.txt"))?.contains("check_stub_priority: PASS")
    );

    let events = load_jsonl(&out_dir.join("events.jsonl"))?;
    let names = events
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for required in [
        "stub_priority_completion.source_artifacts",
        "stub_priority_completion.unit_bindings",
        "stub_priority_completion.e2e_gate_replayed",
        "stub_priority_completion.telemetry_contract",
        "stub_priority_completion.completion_contract_validated",
    ] {
        assert!(names.contains(required), "missing event {required}");
    }
    for (index, event) in events.iter().enumerate() {
        let line = serde_json::to_string(event)?;
        validate_log_line(&line, index + 1)
            .map_err(|errors| test_error(format!("invalid structured log row: {errors:?}")))?;
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_harness_tests"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_harness_tests should be array"))?
        .retain(|name| name.as_str() != Some("scores_match_formula"));
    let (path, out_dir) = mutated_manifest(&root, "missing-unit", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("missing_unit_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_stdout_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["e2e_primary"]["required_gate_stdout"][0] =
        json!("PASS: impossible stub priority stdout marker");
    let (path, out_dir) = mutated_manifest(&root, "missing-e2e", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("missing_e2e_binding"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["telemetry_primary"]["required_log_fields"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_log_fields should be array"))?
        .retain(|field| field.as_str() != Some("latency_ns"));
    let (path, out_dir) = mutated_manifest(&root, "missing-telemetry", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("missing_telemetry_binding"));
    Ok(())
}
