//! Contract tests for bd-ldj.9 symbol coverage epic completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "symbol_coverage_epic.source_artifacts_validated",
    "symbol_coverage_epic.symbol_universe_validated",
    "symbol_coverage_epic.support_matrix_validated",
    "symbol_coverage_epic.conformance_matrix_validated",
    "symbol_coverage_epic.fixture_coverage_validated",
    "symbol_coverage_epic.telemetry_validated",
    "symbol_coverage_epic.completion_contract_validated",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/symbol_coverage_epic_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_symbol_coverage_epic_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("value should be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be a string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "symbol-coverage-epic-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env(
            "FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .current_dir(root)
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

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line)?;
            row["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn assert_file_line_ref_exists(root: &Path, value: &str) -> TestResult {
    let (path, line) = value
        .rsplit_once(':')
        .ok_or_else(|| test_error("file line ref should contain ':'"))?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "line ref must be positive");
    let full_path = root.join(path);
    assert!(full_path.is_file(), "file-line ref missing path {value}");
    let line_count = fs::read_to_string(full_path)?.lines().count();
    assert!(line_no <= line_count, "file-line ref outside file: {value}");
    Ok(())
}

#[test]
fn contract_anchors_symbol_coverage_epic_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("symbol_coverage_epic_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-ldj"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-ldj.9"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert_eq!(
        manifest["audit_reference"]["score_before"].as_u64(),
        Some(685)
    );
    assert!(
        manifest["audit_reference"]["score_threshold"]
            .as_u64()
            .unwrap_or(0)
            >= 800
    );
    Ok(())
}

#[test]
fn source_artifacts_and_implementation_refs_exist() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    let ids = sources
        .iter()
        .map(|source| {
            source["id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("source id should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        ids,
        BTreeSet::from([
            "completion_checker".to_string(),
            "completion_harness".to_string(),
            "conformance_matrix".to_string(),
            "conformance_matrix_checker".to_string(),
            "support_matrix_checker".to_string(),
            "support_matrix_maintenance_report".to_string(),
            "symbol_fixture_coverage".to_string(),
            "symbol_fixture_coverage_checker".to_string(),
            "symbol_universe".to_string(),
            "symbol_universe_checker".to_string(),
        ])
    );

    for source in sources {
        let path = source["path"]
            .as_str()
            .ok_or_else(|| test_error("source path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in source["required_needles"]
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

    for reference in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| test_error("implementation_refs should be array"))?
    {
        assert_file_line_ref_exists(
            &root,
            reference
                .as_str()
                .ok_or_else(|| test_error("implementation ref should be string"))?,
        )?;
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accept")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS symbol coverage epic completion contract")
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("symbol_coverage_epic_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-ldj.9"));
    assert_eq!(
        report["summaries"]["symbol_universe"]["total_symbols"].as_u64(),
        Some(4119)
    );
    assert_eq!(
        report["summaries"]["support_matrix_maintenance"]["status_invalid"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summaries"]["conformance_matrix"]["failed"].as_u64(),
        Some(0)
    );

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in REQUIRED_EVENTS {
        assert!(events.contains(*event), "missing telemetry event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_symbol_universe_total_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "symbol-drift")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["artifact_invariants"]["symbol_universe"]["min_total_symbols"] =
        serde_json::json!(999_999);
    let bad_manifest = out_dir.join("symbol-drift.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted symbol universe drift"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("symbol_universe"),
        "expected symbol_universe failure\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("symbol_coverage_epic_completion_contract_failed")
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_completion_item_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-item")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["missing_items_closed"] = serde_json::json!([
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.conformance.primary"
    ]);
    let bad_manifest = out_dir.join("missing-item.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing telemetry binding"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing_items_closed"),
        "expected missing_items_closed failure\n{}",
        output_text(&output)
    );
    Ok(())
}
