//! Completion-contract tests for bd-bp8fl.4.1.1 fixture coverage prioritizer evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_contract_shape_validated",
    "missing_item_bindings_validated",
    "prioritizer_artifact_validated",
    "generator_and_gate_validated",
    "base_fixture_coverage_prioritizer_gate_replayed",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "fixture_coverage_prioritizer_completion_contract_validated",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn checker_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    root.join("tests/conformance/fixture_coverage_prioritizer_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fixture_coverage_prioritizer_completion_contract.sh")
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

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    let _lock = checker_lock();
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_REPORT",
            out_dir.join("fixture_coverage_prioritizer_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_LOG",
            out_dir.join("fixture_coverage_prioritizer_completion_contract.events.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("fixture_coverage_prioritizer_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("fixture_coverage_prioritizer_completion_contract.events.jsonl")
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

fn remove_binding(manifest: &mut Value, missing_item_id: &str) -> TestResult {
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("missing_item_bindings should be an array"))?;
    bindings
        .retain(|row| row.get("missing_item_id").and_then(Value::as_str) != Some(missing_item_id));
    Ok(())
}

fn set_required_summary_value(manifest: &mut Value, key: &str, value: u64) -> TestResult {
    let obj = manifest
        .get_mut("completion_contract")
        .and_then(Value::as_object_mut)
        .and_then(|contract| contract.get_mut("required_prioritizer_summary"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            test_error("completion_contract.required_prioritizer_summary should be an object")
        })?;
    obj.insert(key.to_owned(), Value::from(value));
    Ok(())
}

#[test]
fn contract_binds_fixture_coverage_prioritizer_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "fixture_coverage_prioritizer_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.4.1.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-bp8fl.4.1"
    );

    let artifacts: BTreeSet<_> = array_field(&manifest, "source_artifacts", "manifest")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "prioritizer_artifact",
        "prioritizer_generator",
        "prioritizer_gate",
        "symbol_fixture_coverage",
        "per_symbol_fixture_tests",
        "feature_gap_groups",
        "prioritizer_harness_test",
        "e2e_suite",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }

    let completion = field(&manifest, "completion_contract", "manifest")?;
    let missing_items = string_set(completion, "missing_item_ids", "completion_contract")?;
    assert!(missing_items.contains("tests.unit.primary"));
    assert!(missing_items.contains("tests.e2e.primary"));
    assert!(missing_items.contains("tests.conformance.primary"));
    assert!(missing_items.contains("telemetry.primary"));

    let summary = field(
        completion,
        "required_prioritizer_summary",
        "completion_contract",
    )?;
    assert_eq!(summary["campaign_count"].as_u64(), Some(8));
    assert_eq!(summary["deferred_module_count"].as_u64(), Some(15));
    assert_eq!(
        summary["selected_target_uncovered_symbols"].as_u64(),
        Some(1737)
    );
    assert_eq!(summary["total_first_wave_fixture_count"].as_u64(), Some(88));
    Ok(())
}

#[test]
fn checker_accepts_fixture_coverage_prioritizer_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "fixture-coverage-prioritizer-check")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS fixture coverage prioritizer completion contract")
    );

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "fixture_coverage_prioritizer_completion_contract.report.v1"
    );
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    Ok(())
}

#[test]
fn checker_emits_structured_fixture_coverage_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "fixture-coverage-prioritizer-telemetry")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names: BTreeSet<_> = events
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(
            event_names.contains(required),
            "missing checker event {required}"
        );
    }
    for row in &events {
        assert_eq!(string_field(row, "bead_id", "event")?, "bd-bp8fl.4.1.1");
        assert!(
            string_field(row, "trace_id", "event")?
                .starts_with("bd-bp8fl.4.1.1::fixture-coverage-prioritizer::completion::v1::")
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_binding(&mut manifest, "tests.e2e.primary")?;

    let out_dir = unique_output_dir(&root, "fixture-coverage-prioritizer-missing-e2e")?;
    let bad_manifest = out_dir.join("bad_missing_e2e.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_e2e_binding"));
    Ok(())
}

#[test]
fn checker_rejects_prioritizer_summary_drift() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    set_required_summary_value(&mut manifest, "campaign_count", 19)?;

    let out_dir = unique_output_dir(&root, "fixture-coverage-prioritizer-summary-drift")?;
    let bad_manifest = out_dir.join("bad_summary_drift.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("prioritizer_summary_drift"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_binding(&mut manifest, "telemetry.primary")?;

    let out_dir = unique_output_dir(&root, "fixture-coverage-prioritizer-missing-telemetry")?;
    let bad_manifest = out_dir.join("bad_missing_telemetry.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_telemetry_binding"));
    Ok(())
}
