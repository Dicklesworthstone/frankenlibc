//! Completion-contract tests for bd-15n.1.1 symbol fixture coverage evidence.

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
    "tests.integration.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
];

const EXPECTED_EVENTS: &[&str] = &[
    "symbol_fixture_coverage_completion_contract_validated",
    "symbol_fixture_coverage_source_gate_replayed",
    "symbol_fixture_coverage_generator_roundtrip",
    "symbol_fixture_coverage_completion_summary",
];

const REQUIRED_SOURCE_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "mode",
    "family",
    "covered_count",
    "uncovered_count",
    "severity",
    "artifact_ref",
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
    root.join("tests/conformance/symbol_fixture_coverage_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_symbol_fixture_coverage_completion_contract.sh")
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

fn json_object<'a>(
    value: &'a Value,
    description: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value.as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be an object"),
        )
        .into()
    })
}

fn json_array<'a>(value: &'a Value, description: &str) -> TestResult<&'a Vec<Value>> {
    value.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be an array"),
        )
        .into()
    })
}

fn json_array_mut<'a>(value: &'a mut Value, description: &str) -> TestResult<&'a mut Vec<Value>> {
    value.as_array_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be a mutable array"),
        )
        .into()
    })
}

fn json_str<'a>(value: &'a Value, description: &str) -> TestResult<&'a str> {
    value.as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be a string"),
        )
        .into()
    })
}

fn json_u64(value: &Value, description: &str) -> TestResult<u64> {
    value.as_u64().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be an unsigned integer"),
        )
        .into()
    })
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "symbol-fixture-coverage-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    source_matrix: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_SOURCE_MATRIX",
            source_matrix,
        )
        .env(
            "FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_REPORT",
            out_dir.join("symbol_fixture_coverage_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_LOG",
            out_dir.join("symbol_fixture_coverage_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_GENERATED",
            out_dir.join("symbol_fixture_coverage_completion_contract.generated.v1.json"),
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
fn manifest_binds_missing_items_and_coverage_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("symbol_fixture_coverage_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-15n.1.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-15n.1"));

    for path in json_object(&manifest["source_artifacts"], "source_artifacts")?.values() {
        let rel = json_str(path, "source artifact path")?;
        assert!(
            root.join(rel).exists(),
            "source artifact should exist: {rel}"
        );
    }

    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing_item_bindings array"))?
        .iter()
        .map(|binding| Ok(json_str(&binding["missing_item_id"], "missing_item_id")?.to_string()))
        .collect::<TestResult<BTreeSet<_>>>()?;
    assert_eq!(
        bindings,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    for item in manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation_refs array"))?
    {
        assert_file_line_ref_exists(&root, json_str(item, "implementation ref")?)?;
    }

    let contract = &manifest["completion_debt_evidence"]["required_coverage_matrix_contract"];
    assert_eq!(contract["bead"].as_str(), Some("bd-15n.1"));
    assert_eq!(contract["schema_version"].as_u64(), Some(1));
    assert_eq!(
        contract["minimum_total_exported_symbols"].as_u64(),
        Some(4000)
    );
    assert_eq!(
        string_set(&contract["required_source_gate_log_fields"])?,
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
    let test_sources = json_object(&evidence["test_sources"], "test_sources")?;

    let mut source_texts = std::collections::BTreeMap::new();
    for (key, path) in test_sources {
        source_texts.insert(
            key.as_str(),
            source_text(&root, json_str(path, "test source path")?)?,
        );
    }

    for (section, missing_item_id) in [
        ("unit_primary", "tests.unit.primary"),
        ("integration_primary", "tests.integration.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("conformance_primary", "tests.conformance.primary"),
    ] {
        let item = &evidence[section];
        assert_eq!(item["missing_item_id"].as_str(), Some(missing_item_id));
        for test_ref in json_array(&item["required_test_refs"], "required_test_refs")? {
            let source = json_str(&test_ref["source"], "test source")?;
            let name = json_str(&test_ref["name"], "test name")?;
            let text = source_texts.get(source).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("test source should exist for {source}::{name}"),
                )
            })?;
            assert!(
                text.contains(&format!("fn {name}")),
                "missing test ref {source}::{name}"
            );
        }
        for command in json_array(&item["required_commands"], "required_commands")? {
            let command = json_str(command, "required command")?;
            if command.contains("cargo ") {
                assert!(
                    command.contains("rch exec --"),
                    "cargo command must be routed through rch: {command}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checker_runs_source_gate_and_emits_completion_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &root.join("tests/conformance/symbol_fixture_coverage.v1.json"),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        read_json(&out_dir.join("symbol_fixture_coverage_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-15n.1.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-15n.1"));
    assert_eq!(
        string_set(&report["summary"]["missing_items_bound"])?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );
    assert!(
        json_u64(
            &report["summary"]["source_gate_log_rows"],
            "source_gate_log_rows"
        )? >= 1,
        "source gate should emit at least one structured row"
    );
    assert!(
        json_u64(
            &report["summary"]["matrix"]["fixture_json_cases"],
            "fixture_json_cases",
        )? >= 1200
    );
    assert!(
        out_dir
            .join("symbol_fixture_coverage_completion_contract.generated.v1.json")
            .is_file(),
        "generator roundtrip artifact should be written"
    );

    let rows = read_jsonl(&out_dir.join("symbol_fixture_coverage_completion_contract.log.jsonl"))?;
    let events = rows
        .iter()
        .map(|row| Ok(json_str(&row["event"], "completion log event")?.to_string()))
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
fn completion_logs_validate_against_structured_schema() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "log-schema")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &root.join("tests/conformance/symbol_fixture_coverage.v1.json"),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = out_dir.join("symbol_fixture_coverage_completion_contract.log.jsonl");
    for (index, line) in std::fs::read_to_string(log_path)?.lines().enumerate() {
        let errors = validate_log_line(line, index + 1).map_err(|errors| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("log line {} failed schema: {errors:?}", index + 1),
            )
        });
        assert!(errors.is_ok());
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut manifest["completion_debt_evidence"]["missing_item_bindings"],
        "missing_item_bindings",
    )?
    .retain(|binding| binding["missing_item_id"].as_str() != Some("tests.e2e.primary"));

    let out_dir = unique_output_dir(&root, "missing-binding")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(
        &root,
        &mutated,
        &root.join("tests/conformance/symbol_fixture_coverage.v1.json"),
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing item bindings mismatch"),
        "stderr should explain missing binding: {stderr}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_source_gate_log_field() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut manifest["completion_debt_evidence"]["required_coverage_matrix_contract"]
            ["required_source_gate_log_fields"],
        "required_source_gate_log_fields",
    )?
    .push(Value::String("nonexistent_source_gate_field".to_string()));

    let out_dir = unique_output_dir(&root, "missing-source-log-field")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(
        &root,
        &mutated,
        &root.join("tests/conformance/symbol_fixture_coverage.v1.json"),
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("source gate stdout JSON line"),
        "stderr should explain missing source gate field: {stderr}"
    );
    Ok(())
}

#[test]
fn coverage_matrix_contract_rejects_understated_fixture_inventory() -> TestResult {
    let root = workspace_root()?;
    let mut matrix = read_json(&root.join("tests/conformance/symbol_fixture_coverage.v1.json"))?;
    matrix["fixture_inventory"]["fixture_json_cases"] = Value::from(1);

    let out_dir = unique_output_dir(&root, "understated-inventory")?;
    let mutated_matrix = out_dir.join("mutated_symbol_fixture_coverage.v1.json");
    write_json(&mutated_matrix, &matrix)?;

    let output = run_checker(&root, &contract_path(&root), &mutated_matrix, &out_dir)?;
    assert_checker_failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fixture_json_cases is below completion minimum"),
        "stderr should explain fixture inventory failure: {stderr}"
    );
    Ok(())
}
