//! Completion-contract tests for bd-yy970.3 string/memory fixture wave evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "dependency_proofs_validated",
    "string_memory_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "string_memory_hotpath_fixture_wave_completion_contract_validated",
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
    root.join("tests/conformance/string_memory_hotpath_fixture_wave_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_string_memory_hotpath_fixture_wave_completion_contract.sh")
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("string_memory_hotpath_fixture_wave_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("string_memory_hotpath_fixture_wave_completion_contract.events.jsonl")
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

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<BTreeSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain only strings")))
        })
        .collect::<Result<_, _>>()
}

fn artifact_path<'a>(manifest: &'a Value, artifact_id: &str) -> TestResult<&'a str> {
    array_field(manifest, "source_artifacts", "manifest")?
        .iter()
        .find(|row| row.get("id").and_then(Value::as_str) == Some(artifact_id))
        .and_then(|row| row.get("path").and_then(Value::as_str))
        .ok_or_else(|| test_error(format!("missing source artifact path for {artifact_id}")))
}

fn set_artifact_path(manifest: &mut Value, artifact_id: &str, path: &Path) -> TestResult {
    let artifacts = manifest
        .get_mut("source_artifacts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.source_artifacts must be an array"))?;
    let artifact = artifacts
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some(artifact_id))
        .ok_or_else(|| test_error(format!("missing source artifact {artifact_id}")))?;
    artifact["path"] = Value::String(path.display().to_string());
    Ok(())
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_LOG",
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

#[test]
fn contract_binds_string_memory_hotpath_fixture_wave_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "string_memory_hotpath_fixture_wave_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-yy970.3"
    );
    assert_eq!(string_field(&manifest, "epic_id", "manifest")?, "bd-yy970");

    let artifacts: BTreeSet<_> = array_field(&manifest, "source_artifacts", "manifest")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "beads_ledger",
        "fixture_coverage_prioritizer",
        "symbol_fixture_coverage",
        "string_memory_fixture",
        "fixture_executor",
        "string_memory_fixture_harness_test",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }

    let completion = field(&manifest, "completion_contract", "manifest")?;
    assert_eq!(
        string_field(completion, "campaign_id", "completion_contract")?,
        "fcq-string-memory-hotpaths"
    );
    assert_eq!(
        string_field(completion, "wave_id", "completion_contract")?,
        "wave-04-string-memory-hotpaths"
    );
    let symbols = string_set(
        completion,
        "required_first_wave_symbols",
        "completion_contract",
    )?;
    assert_eq!(symbols.len(), 12);
    assert!(symbols.contains("__strcspn_c2"));
    assert!(symbols.contains("__strsep_2c"));

    let modes = string_set(completion, "required_modes", "completion_contract")?;
    assert_eq!(
        modes,
        BTreeSet::from(["hardened".to_string(), "strict".to_string()])
    );

    let proofs = array_field(
        completion,
        "required_dependency_proofs",
        "completion_contract",
    )?;
    let proof_ids: BTreeSet<_> = proofs
        .iter()
        .filter_map(|row| row.get("bead_id").and_then(Value::as_str))
        .collect();
    assert!(proof_ids.contains("bd-yy970.1"));
    assert!(proof_ids.contains("bd-yy970.2"));
    Ok(())
}

#[test]
fn checker_accepts_string_memory_hotpath_fixture_wave_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-memory-fixture-wave-check")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("string_memory_hotpath_fixture_wave_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["string_memory_first_wave_symbol_count"].as_u64(),
        Some(12)
    );
    assert_eq!(report["summary"]["required_mode_count"].as_u64(), Some(2));
    for check in [
        "source_artifacts",
        "dependency_proofs",
        "string_memory_fixture",
        "coverage_accounting",
        "validation_commands",
        "test_surfaces",
        "telemetry",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "checker {check} should pass"
        );
    }
    Ok(())
}

#[test]
fn checker_emits_structured_string_memory_completion_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-memory-fixture-wave-log")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let rows = load_jsonl(&checker_log(&out_dir))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(
            events.contains(required),
            "missing telemetry event {required}"
        );
    }
    for row in rows {
        for key in [
            "timestamp",
            "trace_id",
            "bead_id",
            "event",
            "status",
            "source_commit",
            "target_dir",
            "failure_signature",
        ] {
            assert!(row.get(key).is_some(), "telemetry row missing {key}");
        }
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_string_memory_fixture_symbol() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-memory-fixture-wave-missing-symbol")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let fixture_path = root.join(artifact_path(&manifest, "string_memory_fixture")?);
    let mut fixture = load_json(&fixture_path)?;
    fixture["campaign"]["first_wave_symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("fixture first_wave_symbols must be an array"))?
        .retain(|value| value.as_str() != Some("__strsep_2c"));
    let mutated_fixture = out_dir.join("mutated_string_memory_hotpaths.json");
    write_json(&mutated_fixture, &fixture)?;
    set_artifact_path(&mut manifest, "string_memory_fixture", &mutated_fixture)?;
    let mutated_manifest = out_dir.join("mutated_contract.json");
    write_json(&mutated_manifest, &manifest)?;

    let output = run_checker(&root, &mutated_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(
        failure_signatures(&report).contains("string_memory_fixture_symbol_coverage"),
        "missing symbol must fail fixture symbol coverage"
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_string_memory_coverage_accounting() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-memory-fixture-wave-stale-coverage")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let coverage_path = root.join(artifact_path(&manifest, "symbol_fixture_coverage")?);
    let mut coverage = load_json(&coverage_path)?;
    let symbols = coverage["symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("coverage symbols must be an array"))?;
    let row = symbols
        .iter_mut()
        .find(|row| row.get("symbol").and_then(Value::as_str) == Some("__strcspn_c2"))
        .ok_or_else(|| test_error("__strcspn_c2 coverage row must exist"))?;
    row["covered"] = Value::Bool(false);
    let mutated_coverage = out_dir.join("mutated_symbol_fixture_coverage.v1.json");
    write_json(&mutated_coverage, &coverage)?;
    set_artifact_path(&mut manifest, "symbol_fixture_coverage", &mutated_coverage)?;
    let mutated_manifest = out_dir.join("mutated_contract.json");
    write_json(&mutated_manifest, &manifest)?;

    let output = run_checker(&root, &mutated_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(
        failure_signatures(&report).contains("coverage_accounting_drift"),
        "stale coverage must fail coverage accounting"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-memory-fixture-wave-local-cargo")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let commands = manifest["completion_contract"]["runtime_validation"]
        .as_array_mut()
        .ok_or_else(|| test_error("runtime_validation must be an array"))?;
    let cargo_command = commands
        .iter_mut()
        .find(|value| {
            value
                .as_str()
                .is_some_and(|command| command.contains("cargo test"))
        })
        .ok_or_else(|| test_error("contract must contain cargo test command"))?;
    *cargo_command = Value::String(
        "cargo test -p frankenlibc-harness --test string_memory_hotpath_fixture_wave_completion_contract_test".to_string(),
    );
    let mutated_manifest = out_dir.join("mutated_contract.json");
    write_json(&mutated_manifest, &manifest)?;

    let output = run_checker(&root, &mutated_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(
        failure_signatures(&report).contains("non_rch_validation_command"),
        "local cargo command must fail"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_required_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "string-memory-fixture-wave-missing-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_contract"]["required_telemetry_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_telemetry_events must be an array"))?
        .retain(|value| value.as_str() != Some("coverage_accounting_validated"));
    let mutated_manifest = out_dir.join("mutated_contract.json");
    write_json(&mutated_manifest, &manifest)?;

    let output = run_checker(&root, &mutated_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(
        failure_signatures(&report).contains("missing_telemetry_event"),
        "missing telemetry event must fail"
    );
    Ok(())
}
