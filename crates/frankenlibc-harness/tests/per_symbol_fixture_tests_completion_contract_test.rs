//! Completion contract tests for bd-ldj.5.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str = "tests/conformance/per_symbol_fixture_tests_completion_contract.v1.json";
const SOURCE_REPORT_REL: &str = "tests/conformance/per_symbol_fixture_tests.v1.json";
const BASELINE_REL: &str = "tests/conformance/conformance_coverage_baseline.v1.json";
const CHECKER_REL: &str = "scripts/check_per_symbol_fixture_tests_completion_contract.sh";
const EXPECTED_MISSING_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.golden.primary",
    "tests.conformance.primary",
];
const EXPECTED_EVENTS: &[&str] = &[
    "per_symbol_fixture_completion_contract_validated",
    "per_symbol_fixture_golden_report_validated",
    "per_symbol_fixture_generator_roundtrip_validated",
    "per_symbol_fixture_completion_summary",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("manifest should have a crates parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("manifest should live under the workspace root"))?;
    Ok(root.to_path_buf())
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "per-symbol-fixture-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_REPORT",
            root.join(SOURCE_REPORT_REL),
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_BASELINE",
            root.join(BASELINE_REL),
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_GENERATED",
            out_dir.join("generated.v1.json"),
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_ROUNDTRIP",
            out_dir.join("roundtrip.v1.json"),
        )
        .output()?)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &Value) -> TestResult {
    let path = file_line_ref["path"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref path missing"))?;
    let line = file_line_ref["line"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref line missing"))?;
    assert!(line > 0, "line must be positive for {path}");
    let full_path = root.join(path);
    assert!(full_path.exists(), "ref path should exist: {path}");
    if full_path.is_file() {
        let text = std::fs::read_to_string(&full_path)?;
        let lines: Vec<_> = text.lines().collect();
        assert!(
            (line as usize) <= lines.len(),
            "ref line outside file: {path}:{line}"
        );
        let anchor = file_line_ref["anchor"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref anchor missing"))?;
        assert!(text.contains(anchor), "{path} missing anchor {anchor}");
    }
    Ok(())
}

fn function_exists(source_text: &str, name: &str) -> bool {
    source_text.contains(&format!("fn {name}")) || source_text.contains(&format!("def {name}"))
}

fn string_set(values: &Value) -> TestResult<BTreeSet<String>> {
    let array = values
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for value in array {
        set.insert(
            value
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

#[test]
fn manifest_binds_unit_golden_and_conformance_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("per_symbol_fixture_tests_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-ldj.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-ldj.5.1")
    );

    let audit_items = string_set(&manifest["audit"]["missing_items"])?;
    assert_eq!(
        audit_items,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let source_paths = manifest["source_paths"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_paths missing"))?;
    for path in source_paths.values() {
        let rel = path.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source path must be string")
        })?;
        assert!(root.join(rel).exists(), "source path should exist: {rel}");
    }

    let refs = manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs missing"))?;
    assert!(refs.len() >= 20, "expected concrete implementation refs");
    for item in refs {
        assert_file_line_ref_exists(&root, item)?;
    }

    let coverage = manifest["completion_coverage"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion_coverage missing"))?;
    let covered_items = coverage
        .iter()
        .map(|section| {
            section["missing_item_id"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered_items,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let mut source_texts = std::collections::BTreeMap::new();
    for section in coverage {
        assert_eq!(section["status"].as_str(), Some("covered"));
        assert!(
            section["implementation_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite implementation refs"
        );
        assert!(
            section["test_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "coverage section should cite test refs"
        );
        for command in section["validation_commands"]
            .as_array()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "validation commands missing")
            })?
            .iter()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(command.contains("rch "), "cargo command must use rch");
                assert!(
                    command.contains("CARGO_TARGET_DIR="),
                    "cargo command must use an isolated target dir"
                );
            }
        }
        for test_ref in section["test_refs"].as_array().unwrap() {
            let source = test_ref["source"].as_str().unwrap_or_default();
            let name = test_ref["name"].as_str().unwrap_or_default();
            let rel = source_paths[source].as_str().unwrap_or_default();
            let source_text = source_texts
                .entry(source.to_string())
                .or_insert_with(|| std::fs::read_to_string(root.join(rel)).unwrap());
            assert!(
                function_exists(source_text, name),
                "test ref should exist: {rel}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn fixture_report_contract_binds_canonical_golden() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    let report = read_json(&root.join(SOURCE_REPORT_REL))?;
    let baseline = read_json(&root.join(BASELINE_REL))?;
    let contract = &manifest["fixture_report_contract"];
    let summary = &report["summary"];

    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-ldj.5"));
    assert!(
        report["report_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() >= 8)
    );
    assert_eq!(summary["total_format_issues"].as_u64(), Some(0));
    assert!(
        summary["total_symbols"].as_u64().unwrap_or_default()
            >= contract["min_total_symbols"].as_u64().unwrap_or_default()
    );
    assert!(
        summary["total_cases"].as_u64().unwrap_or_default()
            >= contract["min_total_cases"].as_u64().unwrap_or_default()
    );
    assert!(
        summary["symbols_with_edge_cases"]
            .as_u64()
            .unwrap_or_default()
            >= contract["min_symbols_with_edge_cases"]
                .as_u64()
                .unwrap_or_default()
    );

    let coverage = summary["fixture_coverage_pct"].as_f64().unwrap_or_default();
    let baseline_coverage = baseline["summary"]["coverage_pct"]
        .as_f64()
        .unwrap_or_default();
    let slack = contract["baseline_coverage_slack_pct"]
        .as_f64()
        .unwrap_or_default();
    assert!(
        coverage + slack >= baseline_coverage,
        "golden fixture coverage regressed below baseline"
    );

    let per_symbol = report["per_symbol_report"].as_array().unwrap();
    assert_eq!(
        per_symbol.len() as u64,
        summary["total_symbols"].as_u64().unwrap_or_default()
    );
    assert!(
        report["fixture_file_analyses"]
            .as_array()
            .is_some_and(|rows| rows.len() >= 50),
        "golden report should keep fixture file analyses"
    );

    Ok(())
}

#[test]
fn checker_emits_structured_completion_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &root.join(CONTRACT_REL), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-ldj.5.1"));
    assert!(out_dir.join("generated.v1.json").is_file());
    assert!(out_dir.join("roundtrip.v1.json").is_file());

    let log_text = std::fs::read_to_string(out_dir.join("events.jsonl"))?;
    let events = log_text
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let value: Value = serde_json::from_str(line)?;
            validate_log_line(line, index + 1)
                .map_err(|errs| io::Error::new(io::ErrorKind::InvalidData, format!("{errs:?}")))?;
            Ok(value["event"].as_str().unwrap_or_default().to_string())
        })
        .collect::<TestResult<BTreeSet<_>>>()?;
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
fn checker_rejects_missing_golden_report_anchor() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "negative")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["source_anchors"]["generator"][0] = Value::String("missing anchor".to_string());
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for a missing source anchor"
    );
    let report = read_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("missing anchor"))),
        "failure report should name the missing source anchor"
    );

    Ok(())
}
