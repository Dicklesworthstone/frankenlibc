//! Completion-contract tests for bd-pz1g1.3 unistd/process/filesystem wave-02.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/unistd_process_filesystem_wave2_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_unistd_process_filesystem_wave2_completion_contract.sh";
const EXPECTED_EVENTS: &[&str] = &[
    "coverage_truth_bound",
    "dependency_proof_bound",
    "fixture_wave_bound",
    "unistd_wave2_completion_contract_validated",
    "validation_commands_bound",
];
const EXPECTED_SYMBOLS: &[&str] = &[
    "__sched_cpualloc",
    "__sched_cpucount",
    "__sched_cpufree",
    "__sched_rr_get_interval",
    "__sched_setparam",
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__xpg_basename",
    "__xstat",
    "__xstat64",
    "add_key",
    "addmntent",
];

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn checker_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "unistd-wave2-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_UNISTD_WAVE2_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_UNISTD_WAVE2_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_UNISTD_WAVE2_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_UNISTD_WAVE2_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("expected string array"))?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("expected string item"))
        })
        .collect()
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["failure_signature"].as_str().map(str::to_owned))
        .collect()
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join(CONTRACT_REL)
}

fn run_checker_with_manifest(
    root: &Path,
    manifest: &Value,
    label: &str,
) -> TestResult<(Output, PathBuf)> {
    let out_dir = unique_output_dir(root, label)?;
    let manifest_copy = out_dir.join("contract.json");
    write_json(&manifest_copy, manifest)?;
    let output = run_checker(root, &manifest_copy, &out_dir)?;
    Ok((output, out_dir))
}

#[test]
fn manifest_binds_unistd_wave2_sources_and_commands() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&manifest_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("unistd_process_filesystem_wave2_completion_contract.v1")
    );
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-pz1g1.3"));
    assert_eq!(manifest["parent_bead"].as_str(), Some("bd-pz1g1"));
    assert_eq!(manifest["fixture_bead"].as_str(), Some("bd-pz1g1.1"));
    assert_eq!(manifest["coverage_bead"].as_str(), Some("bd-pz1g1.2"));
    assert_eq!(
        manifest["campaign_id"].as_str(),
        Some("fcq-unistd-process-filesystem")
    );
    assert_eq!(
        manifest["wave_id"].as_str(),
        Some("wave-02-unistd-process-filesystem")
    );

    assert_eq!(
        string_set(&manifest["first_wave_symbols"])?,
        EXPECTED_SYMBOLS
            .iter()
            .map(|symbol| (*symbol).to_owned())
            .collect()
    );

    let artifact_ids = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be an array"))?
        .iter()
        .map(|artifact| {
            let path = artifact["path"]
                .as_str()
                .ok_or_else(|| test_error("source artifact path missing"))?;
            assert!(
                root.join(path).exists(),
                "source artifact should exist: {path}"
            );
            artifact["id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("source artifact id missing"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    for required in [
        "wave_fixture",
        "wave_harness",
        "conformance_executor",
        "symbol_fixture_coverage",
        "fixture_coverage_prioritizer",
        "completion_checker",
        "completion_harness_test",
    ] {
        assert!(
            artifact_ids.contains(required),
            "missing artifact id {required}"
        );
    }

    let commands = string_set(&manifest["validation_commands"])?;
    for command in &commands {
        if command.contains("cargo ") {
            assert!(
                command.starts_with("rch exec -- "),
                "cargo validation must be rch-backed: {command}"
            );
        }
    }
    assert!(
        commands
            .iter()
            .any(|cmd| cmd == "AGENT_NAME=BrownTern br --no-db dep cycles --json")
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "valid")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("unistd_process_filesystem_wave2_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-pz1g1.3"));
    assert_eq!(report["summary"]["error_count"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["required_symbol_count"].as_u64(),
        Some(EXPECTED_SYMBOLS.len() as u64)
    );

    let rows = read_jsonl(&out_dir.join("events.jsonl"))?;
    let seen = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(seen, EXPECTED_EVENTS.iter().copied().collect());
    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "bead_id",
            "parent_bead",
            "campaign_id",
            "wave_id",
            "event",
            "status",
            "source_commit",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "log row missing {field}");
        }
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_wave_symbol() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&manifest_path(&root))?;
    manifest["first_wave_symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("first_wave_symbols array"))?
        .pop();

    let (output, out_dir) = run_checker_with_manifest(&root, &manifest, "missing-symbol")?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("missing_wave_symbol"));
    Ok(())
}

#[test]
fn checker_rejects_stale_coverage_count() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&manifest_path(&root))?;
    manifest["coverage_requirements"]["min_target_covered"] = Value::from(9999);

    let (output, out_dir) = run_checker_with_manifest(&root, &manifest, "stale-coverage")?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("stale_coverage_count"));
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&manifest_path(&root))?;
    manifest["validation_commands"]
        .as_array_mut()
        .ok_or_else(|| test_error("validation_commands array"))?
        .push(Value::from(
            "cargo test -p frankenlibc-harness --test unistd_process_filesystem_wave2_completion_contract_test",
        ));

    let (output, out_dir) = run_checker_with_manifest(&root, &manifest, "non-rch")?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("non_rch_cargo_validation"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&manifest_path(&root))?;
    let events = manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_events array"))?;
    events.retain(|row| row.as_str() != Some("coverage_truth_bound"));

    let (output, out_dir) = run_checker_with_manifest(&root, &manifest, "missing-telemetry")?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("missing_telemetry_event"));
    Ok(())
}

#[test]
fn checker_rejects_stale_source_commit() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&manifest_path(&root))?;
    manifest["source_commits"]["fixture_wave"] =
        Value::from("0000000000000000000000000000000000000000");

    let (output, out_dir) = run_checker_with_manifest(&root, &manifest, "stale-source")?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("stale_source_commit"));
    Ok(())
}

#[test]
fn checker_rejects_missing_dependency_proof() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let mut manifest = read_json(&manifest_path(&root))?;
    manifest["dependency_proof"]["expected_empty"] = Value::from(false);

    let (output, out_dir) = run_checker_with_manifest(&root, &manifest, "dependency-proof")?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("dependency_proof_drift"));
    Ok(())
}
