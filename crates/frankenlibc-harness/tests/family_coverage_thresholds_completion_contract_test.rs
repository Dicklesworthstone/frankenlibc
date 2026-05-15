//! Completion contract tests for bd-bp8fl.4.3.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/family_coverage_thresholds_completion_contract.v1.json";
const ARTIFACT_REL: &str = "tests/conformance/family_coverage_thresholds.v1.json";
const SYMBOL_COVERAGE_REL: &str = "tests/conformance/symbol_fixture_coverage.v1.json";
const CHECKER_REL: &str = "scripts/check_family_coverage_thresholds_completion_contract.sh";
const EXPECTED_SCHEMA: &str = "family_coverage_thresholds_completion_contract.v1";
const EXPECTED_MISSING_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
];
const EXPECTED_EVENTS: &[&str] = &[
    "family_coverage_thresholds_completion_contract_validated",
    "family_coverage_thresholds_artifact_validated",
    "family_coverage_thresholds_source_gate_validated",
    "family_coverage_thresholds_completion_summary",
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
        "family-coverage-thresholds-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_ARTIFACT",
            root.join(ARTIFACT_REL),
        )
        .env(
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_SYMBOL_COVERAGE",
            root.join(SYMBOL_COVERAGE_REL),
        )
        .env(
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_SOURCE_REPORT",
            out_dir.join("source-report.json"),
        )
        .env(
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_SOURCE_LOG",
            out_dir.join("source-events.jsonl"),
        )
        .output()?)
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?;
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

fn function_exists(source_text: &str, name: &str) -> bool {
    source_text.contains(&format!("fn {name}")) || source_text.contains(&format!("def {name}"))
}

fn assert_file_line_ref_exists(root: &Path, item: &Value) -> TestResult {
    let path = item["path"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref path missing"))?;
    let line = item["line"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref line missing"))?;
    let anchor = item["anchor"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref anchor missing"))?;
    assert!(line > 0, "line must be positive for {path}");
    let full = root.join(path);
    assert!(full.is_file(), "ref path should exist: {path}");
    let text = std::fs::read_to_string(&full)?;
    assert!(
        (line as usize) <= text.lines().count(),
        "ref line should be inside {path}"
    );
    assert!(text.contains(anchor), "{path} missing anchor {anchor}");
    Ok(())
}

#[test]
fn manifest_binds_unit_e2e_conformance_and_telemetry_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(manifest["schema_version"].as_str(), Some(EXPECTED_SCHEMA));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.4.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.4.3.1")
    );
    assert_eq!(
        string_set(&manifest["audit"]["missing_items"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let source_paths = manifest["source_paths"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_paths missing"))?;
    for path in source_paths.values() {
        let rel = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path missing"))?;
        assert!(root.join(rel).exists(), "source path should exist: {rel}");
    }

    let refs = manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs missing"))?;
    assert!(refs.len() >= 25, "expected concrete implementation refs");
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
                io::Error::new(io::ErrorKind::InvalidData, "validation_commands missing")
            })?
            .iter()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(command.contains("rch "), "cargo command must use rch");
                assert!(
                    command.contains("CARGO_TARGET_DIR="),
                    "cargo command must use isolated target dir"
                );
            }
        }
        let test_refs = section["test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_refs missing"))?;
        for test_ref in test_refs {
            let source = test_ref["source"].as_str().unwrap_or_default();
            let name = test_ref["name"].as_str().unwrap_or_default();
            let rel = source_paths[source].as_str().unwrap_or_default();
            if !source_texts.contains_key(source) {
                source_texts.insert(source.to_string(), std::fs::read_to_string(root.join(rel))?);
            }
            let source_text = source_texts
                .get(source)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source text missing"))?;
            assert!(
                function_exists(source_text, name),
                "test ref should exist: {rel}::{name}"
            );
        }
    }
    Ok(())
}

#[test]
fn checker_passes_and_emits_structured_report() -> TestResult {
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
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.4.3.1"));
    assert_eq!(report["summary"]["family_count"].as_u64(), Some(40));
    assert_eq!(report["summary"]["fail_count"].as_u64(), Some(37));
    assert_eq!(
        report["summary"]["claim_gate_decision"].as_str(),
        Some("blocked")
    );

    let log = std::fs::read_to_string(out_dir.join("events.jsonl"))?;
    let mut events = BTreeSet::new();
    for (index, line) in log.lines().enumerate() {
        let entry = validate_log_line(line, index + 1)
            .map_err(|errors| io::Error::new(io::ErrorKind::InvalidData, format!("{errors:?}")))?;
        events.insert(entry.event);
    }
    assert_eq!(
        events,
        EXPECTED_EVENTS
            .iter()
            .map(|event| (*event).to_string())
            .collect()
    );

    let source_report = read_json(&out_dir.join("source-report.json"))?;
    assert_eq!(source_report["status"].as_str(), Some("pass"));
    assert_eq!(source_report["bead"].as_str(), Some("bd-bp8fl.4.3"));
    let source_log = std::fs::read_to_string(out_dir.join("source-events.jsonl"))?;
    assert_eq!(
        source_log.lines().filter(|line| !line.is_empty()).count(),
        40
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_conformance_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "negative")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let missing_items = manifest["audit"]["missing_items"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing_items not array"))?;
    missing_items.retain(|item| item.as_str() != Some("tests.conformance.primary"));
    let bad_contract = out_dir.join("bad-contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail when conformance audit binding is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit.missing_items mismatch"),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}
