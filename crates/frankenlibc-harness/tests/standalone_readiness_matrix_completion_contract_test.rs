//! Completion-contract tests for bd-bp8fl.6.6.1 standalone readiness matrix evidence.

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
    "telemetry.primary",
];

const EXPECTED_EVENTS: &[&str] = &[
    "standalone_readiness_matrix_completion_contract_validated",
    "standalone_readiness_matrix_completion_contract_failed",
    "standalone_readiness_matrix_replayed",
    "standalone_readiness_l2_l3_blockers_preserved",
    "standalone_readiness_completion_summary",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "proof_row_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "artifact_refs",
    "required_evidence",
    "present_evidence",
    "missing_evidence",
    "expected_decision",
    "actual_decision",
    "source_commit",
    "target_dir",
    "failure_signature",
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
    root.join("tests/conformance/standalone_readiness_matrix_completion_contract.v1.json")
}

fn matrix_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_readiness_proof_matrix.v1.json")
}

fn levels_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/replacement_levels.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_standalone_readiness_matrix_completion_contract.sh")
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

fn report_errors_contain(report: &Value, needle: &str) -> TestResult<bool> {
    Ok(json_array(&report["errors"], "report errors")?
        .iter()
        .filter_map(Value::as_str)
        .any(|error| error.contains(needle)))
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "standalone-readiness-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    matrix: &Path,
    levels: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_STANDALONE_READINESS_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_STANDALONE_READINESS_COMPLETION_MATRIX", matrix)
        .env("FRANKENLIBC_STANDALONE_READINESS_COMPLETION_LEVELS", levels)
        .env(
            "FRANKENLIBC_STANDALONE_READINESS_COMPLETION_REPORT",
            out_dir.join("standalone_readiness_matrix_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_STANDALONE_READINESS_COMPLETION_LOG",
            out_dir.join("standalone_readiness_matrix_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_STANDALONE_READINESS_COMPLETION_SOURCE_REPORT",
            out_dir.join("standalone_readiness_matrix_completion_contract.source.report.json"),
        )
        .env(
            "FRANKENLIBC_STANDALONE_READINESS_COMPLETION_SOURCE_LOG",
            out_dir.join("standalone_readiness_matrix_completion_contract.source.log.jsonl"),
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
fn manifest_binds_missing_items_and_matrix_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("standalone_readiness_matrix_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.6.6.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.6.6"));

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

    let contract = &manifest["completion_debt_evidence"]["required_matrix_contract"];
    assert_eq!(contract["bead"].as_str(), Some("bd-bp8fl.6.6"));
    assert_eq!(
        contract["replacement_levels_current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(contract["minimum_proof_row_count"].as_u64(), Some(14));
    assert_eq!(
        string_set(&contract["required_log_fields"])?,
        REQUIRED_LOG_FIELDS
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
    let source_harness = source_text(
        &root,
        json_str(
            &evidence["test_sources"]["source_harness"],
            "source_harness path",
        )?,
    )?;
    let completion_harness = source_text(
        &root,
        json_str(
            &evidence["test_sources"]["completion_harness"],
            "completion_harness path",
        )?,
    )?;
    let checker = source_text(
        &root,
        json_str(
            &manifest["source_artifacts"]["completion_gate"],
            "completion_gate path",
        )?,
    )?;

    for section in [
        "unit_primary",
        "e2e_primary",
        "conformance_primary",
        "telemetry_primary",
    ] {
        for test_ref in json_array(
            &evidence[section]["required_test_refs"],
            "required_test_refs",
        )? {
            let source_name = json_str(&test_ref["source"], "test source")?;
            let test_name = json_str(&test_ref["name"], "test name")?;
            let source = if source_name == "source_harness" {
                &source_harness
            } else {
                &completion_harness
            };
            assert!(
                source.contains(&format!("fn {test_name}")),
                "{section} references missing test {source_name}::{test_name}"
            );
        }
    }

    for needle in [
        "check_standalone_readiness_matrix.sh",
        "required_matrix_contract",
        "claim_blocked",
        "standalone_readiness_matrix_replayed",
    ] {
        assert!(checker.contains(needle), "checker missing {needle}");
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
        &matrix_path(&root),
        &levels_path(&root),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        read_json(&out_dir.join("standalone_readiness_matrix_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        json_array(&report["missing_items_bound"], "missing_items_bound")?.len(),
        EXPECTED_MISSING_ITEMS.len()
    );
    assert_eq!(
        report["readiness_summary"]["proof_row_count"].as_u64(),
        Some(14)
    );
    assert_eq!(
        report["readiness_summary"]["claim_blocked_proof_row_count"].as_u64(),
        Some(14)
    );

    let completion_rows =
        read_jsonl(&out_dir.join("standalone_readiness_matrix_completion_contract.log.jsonl"))?;
    let completion_events = completion_rows
        .iter()
        .map(|row| Ok(json_str(&row["event"], "completion log event")?.to_string()))
        .collect::<TestResult<BTreeSet<_>>>()?;
    for event in EXPECTED_EVENTS
        .iter()
        .filter(|event| **event != "standalone_readiness_matrix_completion_contract_failed")
    {
        assert!(completion_events.contains(*event), "missing event {event}");
    }
    for (index, row) in completion_rows.iter().enumerate() {
        let line = serde_json::to_string(row)?;
        let errors = validate_log_line(&line, index + 1)
            .err()
            .unwrap_or_default();
        assert!(
            errors.is_empty(),
            "completion log row {index} rejected: {errors:?}"
        );
    }

    let source_report = read_json(
        &out_dir.join("standalone_readiness_matrix_completion_contract.source.report.json"),
    )?;
    assert_eq!(source_report["status"].as_str(), Some("pass"));
    let source_rows = read_jsonl(
        &out_dir.join("standalone_readiness_matrix_completion_contract.source.log.jsonl"),
    )?;
    assert_eq!(source_rows.len(), 14);
    Ok(())
}

#[test]
fn checker_rejects_missing_required_log_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-log-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut manifest["completion_debt_evidence"]["required_matrix_contract"]
            ["required_log_fields"],
        "required_log_fields",
    )?
    .retain(|field| field.as_str() != Some("source_commit"));
    let bad_contract = out_dir.join("bad-contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("standalone_readiness_matrix_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(report_errors_contain(&report, "required_log_fields")?);
    Ok(())
}

#[test]
fn checker_rejects_unblocked_l2_claim() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "unblocked-l2")?;
    let mut matrix = read_json(&matrix_path(&root))?;
    let readiness = json_array_mut(&mut matrix["readiness_levels"], "readiness_levels")?;
    let l2 = readiness
        .iter_mut()
        .find(|entry| entry["level"].as_str() == Some("L2"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing L2 readiness row"))?;
    l2["current_claim_status"] = serde_json::json!("supported");
    let bad_matrix = out_dir.join("bad-matrix.json");
    write_json(&bad_matrix, &matrix)?;

    let output = run_checker(
        &root,
        &contract_path(&root),
        &bad_matrix,
        &levels_path(&root),
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("standalone_readiness_matrix_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(report_errors_contain(&report, "current_claim_status")?);
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let mut manifest = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"],
        "required_events",
    )?
    .retain(|event| event.as_str() != Some("standalone_readiness_matrix_replayed"));
    let bad_contract = out_dir.join("bad-contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &matrix_path(&root),
        &levels_path(&root),
        &out_dir,
    )?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("standalone_readiness_matrix_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(report_errors_contain(&report, "required_events")?);
    Ok(())
}
