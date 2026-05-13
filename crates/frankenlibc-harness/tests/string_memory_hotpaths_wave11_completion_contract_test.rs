//! Completion-contract tests for bd-trfzu string/memory wave-11 evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "string_wave11_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "string_wave11_completion_contract_validated",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/string_memory_hotpaths_wave11_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_string_memory_hotpaths_wave11_completion_contract.sh")
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("string_memory_hotpaths_wave11_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("string_memory_hotpaths_wave11_completion_contract.events.jsonl")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_STRING_WAVE11_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_STRING_WAVE11_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STRING_WAVE11_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_STRING_WAVE11_COMPLETION_LOG",
            checker_log(out_dir),
        )
        .output()?)
}

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn failure_signatures(report: &Value) -> BTreeSet<&str> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .collect()
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("expected array"))?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array must contain strings"))
        })
        .collect::<Result<_, _>>()
}

#[test]
fn contract_binds_string_wave11_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("string_memory_hotpaths_wave11_completion_contract.v1")
    );
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-trfzu"));

    let artifacts: BTreeSet<_> = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts array"))?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "beads_ledger",
        "string_wave11_fixture",
        "fixture_executor",
        "string_wave11_harness_test",
        "symbol_fixture_coverage",
        "per_symbol_fixture_tests",
        "fixture_coverage_prioritizer",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }

    let completion = &manifest["completion_contract"];
    assert_eq!(
        completion["campaign_id"].as_str(),
        Some("fcq-string-memory-hotpaths")
    );
    assert_eq!(
        completion["wave_id"].as_str(),
        Some("wave-11-string-memory-hotpaths")
    );
    assert_eq!(
        completion["source_fixture_commit"].as_str(),
        Some("4dcd65f9")
    );
    assert_eq!(
        completion["coverage_refresh_commit"].as_str(),
        Some("eb256972")
    );
    assert_eq!(
        completion["coverage_close_commit"].as_str(),
        Some("650e6ad8")
    );
    let symbols = string_set(&completion["required_first_wave_symbols"])?;
    assert_eq!(symbols.len(), 12);
    assert!(symbols.contains("memset_explicit"));
    assert!(symbols.contains("timingsafe_memcmp"));
    assert_eq!(
        completion["expected_coverage"]["string_target_covered"].as_u64(),
        Some(113)
    );
    Ok(())
}

#[test]
fn checker_accepts_string_wave11_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-wave11-completion-check")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("string_memory_hotpaths_wave11_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["string_wave11_symbol_count"].as_u64(),
        Some(12)
    );
    assert_eq!(report["summary"]["fixture_case_count"].as_u64(), Some(24));
    assert!(report["errors"].as_array().unwrap().is_empty());
    Ok(())
}

#[test]
fn checker_emits_structured_string_wave11_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-wave11-completion-telemetry")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let rows = load_jsonl(&checker_log(&out_dir))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(events.contains(required), "missing event {required}");
    }
    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "bead_id",
            "event",
            "status",
            "source_commit",
            "target_dir",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "missing telemetry field {field}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-trfzu"));
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_string_wave11_fixture_symbol() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-wave11-missing-symbol")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_contract"]["required_first_wave_symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("required symbols should be array"))?
        .retain(|symbol| symbol.as_str() != Some("timingsafe_memcmp"));
    let mutated = out_dir.join("missing_symbol_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("string_wave11_fixture_symbol_coverage"));
    Ok(())
}

#[test]
fn checker_rejects_stale_string_wave11_coverage_accounting() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-wave11-stale-coverage")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_contract"]["expected_coverage"]["string_target_covered"] =
        serde_json::json!(101);
    let mutated = out_dir.join("stale_coverage_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("coverage_accounting_drift"));
    Ok(())
}

#[test]
fn checker_rejects_non_remote_rch_cargo_validation_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-wave11-non-rch")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_contract"]["required_validation_commands"][0] = serde_json::json!(
        "cargo test -p frankenlibc-harness --test string_memory_hotpaths_wave11_completion_contract_test"
    );
    let mutated = out_dir.join("non_rch_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("non_rch_validation_command"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-wave11-missing-telemetry")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_contract"]["required_telemetry_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required telemetry events should be array"))?
        .retain(|event| event.as_str() != Some("coverage_accounting_validated"));
    let mutated = out_dir.join("missing_telemetry_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_telemetry_event"));
    Ok(())
}
