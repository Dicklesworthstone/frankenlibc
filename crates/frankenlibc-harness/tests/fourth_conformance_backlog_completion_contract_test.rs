//! Completion-contract tests for bd-gmbqy.12 fourth conformance backlog closeout.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "fourth_conformance_backlog.source_artifacts_validated",
    "fourth_conformance_backlog.child_closeouts_validated",
    "fourth_conformance_backlog.coverage_artifacts_validated",
    "fourth_conformance_backlog.completed_wave_fixtures_validated",
    "fourth_conformance_backlog.prioritizer_advancement_validated",
    "fourth_conformance_backlog.base_gates_validated",
    "fourth_conformance_backlog.test_surface_validated",
    "fourth_conformance_backlog.completion_contract_validated",
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
    root.join("tests/conformance/fourth_conformance_backlog_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fourth_conformance_backlog_completion_contract.sh")
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

fn checker_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    let _guard = checker_lock()
        .lock()
        .map_err(|_| test_error("fourth backlog checker lock poisoned"))?;
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_REPORT",
            out_dir.join("fourth_conformance_backlog_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_LOG",
            out_dir.join("fourth_conformance_backlog_completion_contract.events.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("fourth_conformance_backlog_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("fourth_conformance_backlog_completion_contract.events.jsonl")
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
fn contract_binds_fourth_conformance_backlog_closeout() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "fourth_conformance_backlog_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-gmbqy.12"
    );
    assert_eq!(
        string_field(&manifest, "parent_bead", "manifest")?,
        "bd-gmbqy"
    );

    let artifacts: BTreeSet<_> = array_field(&manifest, "source_artifacts", "manifest")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "symbol_fixture_coverage",
        "per_symbol_fixture_tests",
        "fixture_coverage_prioritizer",
        "symbol_fixture_coverage_gate",
        "per_symbol_fixture_tests_gate",
        "fixture_coverage_prioritizer_gate",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }

    let snapshot = field(&manifest, "tracker_snapshot", "manifest")?;
    let child_ids = string_set(snapshot, "required_child_ids", "tracker_snapshot")?;
    assert_eq!(child_ids.len(), 11);
    assert!(child_ids.contains("bd-gmbqy.11"));

    let coverage = field(&manifest, "coverage_expectations", "manifest")?;
    assert_eq!(
        field(coverage, "symbol_fixture_coverage", "coverage_expectations")?
            ["target_covered_symbols"]
            .as_u64(),
        Some(859)
    );
    assert_eq!(
        field(
            coverage,
            "per_symbol_fixture_tests",
            "coverage_expectations"
        )?["total_cases"]
            .as_u64(),
        Some(2787)
    );

    let advancement = field(&manifest, "prioritizer_advancement", "manifest")?;
    assert_eq!(
        field(
            advancement,
            "completed_wave_symbol_count",
            "prioritizer_advancement"
        )?
        .as_u64(),
        Some(115)
    );
    Ok(())
}

#[test]
fn checker_accepts_fourth_conformance_backlog_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "fourth-conformance-backlog-check")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS fourth conformance backlog completion contract")
    );

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "fourth_conformance_backlog_completion_contract.report.v1"
    );
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    Ok(())
}

#[test]
fn checker_emits_completion_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "fourth-conformance-backlog-telemetry")?;
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
        assert_eq!(string_field(row, "bead_id", "event")?, "bd-gmbqy.12");
        assert_eq!(string_field(row, "parent_bead", "event")?, "bd-gmbqy");
        assert!(
            string_field(row, "trace_id", "event")?
                .starts_with("bd-gmbqy.12::fourth-conformance-backlog::completion::v1::")
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_child_commit_ref() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let closeouts = manifest
        .get_mut("tracker_snapshot")
        .and_then(Value::as_object_mut)
        .and_then(|snapshot| snapshot.get_mut("child_closeouts"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("tracker_snapshot.child_closeouts should be an array"))?;
    let rpc = closeouts
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some("bd-gmbqy.11"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("bd-gmbqy.11 closeout should exist"))?;
    rpc.insert("commit_refs".to_owned(), Value::Array(Vec::new()));

    let out_dir = unique_output_dir(&root, "fourth-conformance-backlog-missing-commit")?;
    let bad_manifest = out_dir.join("bad_missing_commit.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("child_closeout_drift"));
    Ok(())
}

#[test]
fn checker_rejects_stale_completed_wave_symbol() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let advancement = manifest
        .get_mut("prioritizer_advancement")
        .and_then(Value::as_object_mut)
        .and_then(|advancement| advancement.get_mut("current_campaign_first_wave"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            test_error("prioritizer_advancement.current_campaign_first_wave should be an array")
        })?;
    let unistd = advancement
        .iter_mut()
        .find(|row| {
            row.get("campaign_id").and_then(Value::as_str) == Some("fcq-unistd-process-filesystem")
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("unistd campaign should exist"))?;
    unistd.insert(
        "first_wave_symbols".to_owned(),
        serde_json::json!(["fchdir"]),
    );

    let out_dir = unique_output_dir(&root, "fourth-conformance-backlog-stale-wave")?;
    let bad_manifest = out_dir.join("bad_stale_wave.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("prioritizer_stale_wave"));
    Ok(())
}

#[test]
fn checker_rejects_per_symbol_case_count_drift() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let per_symbol = manifest
        .get_mut("coverage_expectations")
        .and_then(Value::as_object_mut)
        .and_then(|coverage| coverage.get_mut("per_symbol_fixture_tests"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            test_error("coverage_expectations.per_symbol_fixture_tests should be an object")
        })?;
    per_symbol.insert("total_cases".to_owned(), Value::from(2786));

    let out_dir = unique_output_dir(&root, "fourth-conformance-backlog-case-drift")?;
    let bad_manifest = out_dir.join("bad_case_count.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("coverage_artifact_drift"));
    Ok(())
}
