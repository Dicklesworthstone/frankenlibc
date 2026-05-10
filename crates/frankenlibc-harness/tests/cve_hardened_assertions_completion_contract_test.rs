//! Completion-contract tests for bd-1m5.6.1 hardened CVE assertion evidence.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_MISSING_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
];

const EXPECTED_EVENTS: &[&str] = &[
    "cve_hardened_assertions_completion_contract_validated",
    "cve_hardened_assertions_generator_replayed",
    "cve_hardened_assertions_conformance_mapping_verified",
    "cve_hardened_assertions_completion_summary",
];

const REQUIRED_SOURCE_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "bead_id",
    "scenario_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "event",
    "outcome",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/cve_arena/results/hardened_assertions_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_cve_hardened_assertions_completion_contract.sh")
}

fn source_report_path(root: &Path) -> PathBuf {
    root.join("tests/cve_arena/results/hardened_assertions.v1.json")
}

fn corpus_report_path(root: &Path) -> PathBuf {
    root.join("tests/cve_arena/results/corpus_normalization.v1.json")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "cve-hardened-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    source_report: &Path,
    corpus_report: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_CVE_HARDENED_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_CVE_HARDENED_COMPLETION_SOURCE_REPORT",
            source_report,
        )
        .env(
            "FRANKENLIBC_CVE_HARDENED_COMPLETION_CORPUS_REPORT",
            corpus_report,
        )
        .env(
            "FRANKENLIBC_CVE_HARDENED_COMPLETION_REPORT",
            out_dir.join("hardened_assertions_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_CVE_HARDENED_COMPLETION_LOG",
            out_dir.join("hardened_assertions_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_CVE_HARDENED_COMPLETION_REPLAY",
            out_dir.join("hardened_assertions_completion_contract.replay.v1.json"),
        )
        .env(
            "FRANKENLIBC_CVE_HARDENED_COMPLETION_SOURCE_LOG",
            out_dir.join("hardened_assertions_completion_contract.source.log.jsonl"),
        )
        .output()?)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let text = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = text.lines().collect();
    assert!(
        line_no <= lines.len(),
        "file-line ref outside file: {file_line_ref}"
    );
    assert!(
        !lines[line_no - 1].trim().is_empty(),
        "file-line ref should not cite a blank line: {file_line_ref}"
    );
    Ok(())
}

fn source_text(root: &Path, path: &str) -> TestResult<String> {
    Ok(std::fs::read_to_string(root.join(path))?)
}

fn assert_checker_failed(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn manifest_binds_missing_items_and_hardened_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("cve_hardened_assertions_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-1m5.6.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1m5.6"));

    for path in manifest["source_artifacts"].as_object().unwrap().values() {
        let rel = path.as_str().unwrap();
        assert!(
            root.join(rel).exists(),
            "source artifact should exist: {rel}"
        );
    }

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|binding| binding["missing_item_id"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        bindings,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    for item in manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .unwrap()
    {
        assert_file_line_ref_exists(&root, item.as_str().unwrap())?;
    }

    let contract = &manifest["completion_debt_evidence"]["required_hardened_assertion_contract"];
    assert_eq!(contract["original_bead"].as_str(), Some("bd-1m5.6"));
    assert_eq!(contract["source_corpus_bead"].as_str(), Some("bd-1m5.5"));
    assert_eq!(contract["minimum_total_assertions"].as_u64(), Some(12));
    assert_eq!(contract["minimum_unique_healing_actions"].as_u64(), Some(8));
    assert_eq!(
        string_set(&contract["required_source_log_fields"])?,
        REQUIRED_SOURCE_LOG_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect()
    );
    Ok(())
}

#[test]
fn source_gate_and_tests_are_anchored() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let evidence = &manifest["completion_debt_evidence"];
    let test_sources = evidence["test_sources"].as_object().unwrap();

    let mut source_texts = std::collections::BTreeMap::new();
    for (key, path) in test_sources {
        source_texts.insert(key.as_str(), source_text(&root, path.as_str().unwrap())?);
    }

    for section in ["unit_primary", "e2e_primary", "conformance_primary"] {
        let item = &evidence[section];
        assert_eq!(
            item["missing_item_id"].as_str(),
            Some(match section {
                "unit_primary" => "tests.unit.primary",
                "e2e_primary" => "tests.e2e.primary",
                "conformance_primary" => "tests.conformance.primary",
                _ => unreachable!(),
            })
        );
        for test_ref in item["required_test_refs"].as_array().unwrap() {
            let source = test_ref["source"].as_str().unwrap();
            let name = test_ref["name"].as_str().unwrap();
            let source_text = source_texts.get(source).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown source {source}"),
                )
            })?;
            assert!(
                source_text.contains(&format!("fn {name}")),
                "{source} should define {name}"
            );
        }
        let commands = item["required_commands"].as_array().unwrap();
        assert!(
            commands
                .iter()
                .any(|command| command.as_str().unwrap().contains("rch exec")),
            "{section} should require rch-routed cargo validation"
        );
    }
    Ok(())
}

#[test]
fn checker_runs_generator_and_emits_completion_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &source_report_path(&root),
        &corpus_report_path(&root),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(&out_dir.join("hardened_assertions_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["source_summary"]["total_assertions"].as_u64(),
        Some(12)
    );
    assert_eq!(
        report["mapping_summary"]["mapped_assertions"].as_u64(),
        Some(12)
    );
    assert_eq!(
        report["source_summary"]["assertion_digest"],
        report["replay_summary"]["assertion_digest"]
    );

    let events = string_set(&report["events"])?;
    assert_eq!(
        events,
        EXPECTED_EVENTS
            .iter()
            .map(|event| (*event).to_string())
            .collect()
    );

    let source_log =
        read_jsonl(&out_dir.join("hardened_assertions_completion_contract.source.log.jsonl"))?;
    assert_eq!(source_log.len(), 13);
    assert_eq!(
        source_log
            .iter()
            .filter(|row| row["event"] == "cve_hardened_assertion")
            .count(),
        12
    );
    Ok(())
}

#[test]
fn completion_logs_validate_against_structured_schema() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "log-schema")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &source_report_path(&root),
        &corpus_report_path(&root),
        &out_dir,
    )?;
    assert!(output.status.success());

    let log_path = out_dir.join("hardened_assertions_completion_contract.log.jsonl");
    let lines = std::fs::read_to_string(&log_path)?;
    let mut events = BTreeSet::new();
    for (index, line) in lines.lines().enumerate() {
        let entry = validate_log_line(line, index + 1).map_err(|errors| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid structured log row {}: {errors:?}", index + 1),
            )
        })?;
        assert_eq!(entry.bead_id.as_deref(), Some("bd-1m5.6.1"));
        assert_eq!(entry.mode.as_deref(), Some("hardened"));
        assert_eq!(entry.runtime_mode.as_deref(), Some("hardened"));
        assert_eq!(
            entry.outcome,
            Some(frankenlibc_harness::structured_log::Outcome::Pass)
        );
        events.insert(entry.event);
    }
    assert_eq!(
        events,
        EXPECTED_EVENTS
            .iter()
            .map(|event| (*event).to_string())
            .collect()
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-binding")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array_mut()
        .unwrap()
        .retain(|binding| binding["missing_item_id"] != "tests.conformance.primary");
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &source_report_path(&root),
        &corpus_report_path(&root),
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing_item_bindings mismatch"));
    Ok(())
}

#[test]
fn checker_rejects_report_with_crashing_hardened_cve() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "crashing-cve")?;
    let mut report = read_json(&source_report_path(&root))?;
    report["assertion_matrix"][0]["hardened_expectations"]["crashes"] = Value::Bool(true);
    report["summary"]["no_crash_in_hardened"] = Value::from(11);
    report["regression_detection"]["all_no_crash"] = Value::Bool(false);
    let bad_report = out_dir.join("bad_hardened_report.json");
    write_json(&bad_report, &report)?;

    let output = run_checker(
        &root,
        &contract_path(&root),
        &bad_report,
        &corpus_report_path(&root),
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("must not crash in hardened mode"));
    Ok(())
}

#[test]
fn checker_rejects_missing_corpus_mapping() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-corpus")?;
    let mut corpus = read_json(&corpus_report_path(&root))?;
    corpus["corpus_index"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["cve_id"] != "CVE-2024-2961");
    let bad_corpus = out_dir.join("bad_corpus.json");
    write_json(&bad_corpus, &corpus)?;

    let output = run_checker(
        &root,
        &contract_path(&root),
        &source_report_path(&root),
        &bad_corpus,
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing from corpus normalization report"));
    Ok(())
}
