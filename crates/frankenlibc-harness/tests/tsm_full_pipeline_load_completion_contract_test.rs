//! Completion-debt contract tests for bd-32e.6 / bd-32e.6.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest must have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest must live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/tsm_full_pipeline_load_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_tsm_full_pipeline_load_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn jsonl_rows(path: &Path) -> TestResult<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "tsm_full_pipeline_load_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_TSM_FULL_PIPELINE_LOAD_CONTRACT", contract)
        .env(
            "FRANKENLIBC_TSM_FULL_PIPELINE_LOAD_REPORT",
            out_dir.join("tsm_full_pipeline_load_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_TSM_FULL_PIPELINE_LOAD_LOG",
            out_dir.join("tsm_full_pipeline_load_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn strings(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string").into())
                .map(str::to_owned)
        })
        .collect()
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
        full_path.exists(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(&full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

#[test]
fn manifest_binds_unit_e2e_and_load_dimensions() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&contract_path(&root))?;
    let evidence = &manifest["completion_debt_evidence"];

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("tsm_full_pipeline_load_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-32e.6"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-32e.6.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-32e.6"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next-audit threshold"
    );

    for source in manifest["source_modules"]
        .as_array()
        .ok_or("source_modules must be array")?
    {
        let source = source.as_str().ok_or("source path string")?;
        assert!(
            root.join(source).exists(),
            "source module should exist: {source}"
        );
    }

    let sources = evidence["test_sources"]
        .as_object()
        .ok_or("test_sources should be object")?;
    let mut source_texts = std::collections::BTreeMap::new();
    for (key, path) in sources {
        let path = path.as_str().ok_or("test source path string")?;
        source_texts.insert(key.as_str(), std::fs::read_to_string(root.join(path))?);
    }

    for (section, missing_item_id) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item_id),
            "{section} should bind its audit missing item"
        );
        let refs = section_value["required_test_refs"]
            .as_array()
            .ok_or("required_test_refs should be array")?;
        assert!(!refs.is_empty(), "{section} should name required tests");
        for test_ref in refs {
            let source = test_ref["source"].as_str().ok_or("source string")?;
            let name = test_ref["name"].as_str().ok_or("name string")?;
            let text = source_texts.get(source).ok_or("declared test source")?;
            assert!(
                text.contains(&format!("fn {name}")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    let refs = evidence["implementation_refs"]
        .as_array()
        .ok_or("implementation refs missing")?;
    assert!(
        refs.len() >= 15,
        "implementation refs should cover validator, arena, e2e, checker, and harness surfaces"
    );
    for file_line_ref in refs {
        assert_file_line_ref_exists(&root, file_line_ref.as_str().ok_or("ref string")?)?;
    }

    let workload = &evidence["workload_contract"];
    let dimensions = strings(&workload["required_dimensions"])?;
    for dimension in [
        "null_validation",
        "foreign_pointer_validation",
        "allocation_lifecycle",
        "uaf_temporal_violation",
        "double_free_detection",
        "latency_budget_guard",
        "monotone_lattice_transition",
        "concurrent_alloc_validate_free",
        "concurrent_mixed_workload",
        "adversarial_fault_matrix",
    ] {
        assert!(
            dimensions.contains(dimension),
            "workload contract should require {dimension}"
        );
    }

    let modes = strings(&workload["required_modes"])?;
    assert!(modes.contains("strict"), "strict mode should be required");
    assert!(
        modes.contains("hardened"),
        "hardened mode should be required"
    );
    assert_eq!(
        workload["latency_budget"]["strict_target_ns"].as_u64(),
        Some(20)
    );
    assert_eq!(
        workload["latency_budget"]["hardened_target_ns"].as_u64(),
        Some(200)
    );
    assert_eq!(
        workload["latency_budget"]["ci_guard_ns"].as_u64(),
        Some(50000)
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl_scenario_rows() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("tsm_full_pipeline_load_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("tsm_full_pipeline_load_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-32e.6.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-32e.6"));
    assert_eq!(report["scenario_count"].as_u64(), Some(4));

    let covered = strings(&report["covered_dimensions"])?;
    for dimension in [
        "deterministic_mixed_workload",
        "concurrent_read_validation",
        "double_free_detection",
        "latency_budget_guard",
        "adversarial_fault_matrix",
    ] {
        assert!(
            covered.contains(dimension),
            "report should cover dimension {dimension}"
        );
    }

    let rows = jsonl_rows(&out_dir.join("tsm_full_pipeline_load_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 5, "four scenario rows plus one summary row");
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    assert!(events.contains("tsm_pipeline_load_scenario"));
    assert!(events.contains("tsm_full_pipeline_load_completion_contract_validated"));

    let modes: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["runtime_mode"].as_str())
        .collect();
    assert!(
        modes.contains("strict"),
        "log should include strict mode rows"
    );
    assert!(
        modes.contains("hardened"),
        "log should include hardened mode rows"
    );

    for (index, row) in rows.iter().enumerate() {
        for field in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "mode",
            "runtime_mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
            "bead_id",
            "completion_debt_bead",
            "original_bead",
            "source_commit",
            "scenario_id",
            "coverage_dimensions",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "row {index} missing {field}");
        }
        let line = serde_json::to_string(row)?;
        validate_log_line(&line, index + 1).map_err(|errors| {
            io::Error::other(format!("structured log row {index} rejected: {errors:?}"))
        })?;
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_concurrency_dimension() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "missing_concurrency")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["workload_contract"]["required_dimensions"] = json!([
        "null_validation",
        "low_address_rejection",
        "foreign_pointer_validation",
        "allocation_lifecycle",
        "uaf_temporal_violation",
        "double_free_detection",
        "foreign_pointer_free",
        "bounds_remaining",
        "tls_cache_repeated_validation",
        "pipeline_metrics",
        "deterministic_mixed_workload",
        "concurrent_read_validation",
        "concurrent_mixed_workload",
        "latency_budget_guard",
        "monotone_lattice_transition",
        "adversarial_fault_matrix"
    ]);
    let bad_contract = out_dir.join("missing_concurrent_alloc_validate_free.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing concurrency dimension"
    );

    let report =
        load_json(&out_dir.join("tsm_full_pipeline_load_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"].as_array().ok_or("errors array")?;
    assert!(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|message| message.contains("required_dimensions missing")),
        "failure report should mention missing required dimension"
    );

    let rows = jsonl_rows(&out_dir.join("tsm_full_pipeline_load_completion_contract.log.jsonl"))?;
    assert!(
        rows.iter().any(|row| {
            row["event"].as_str() == Some("tsm_full_pipeline_load_completion_contract_failed")
                && row["failure_signature"]
                    .as_str()
                    .is_some_and(|value| value.contains("required_dimensions missing"))
        }),
        "failure log should include required-dimension drift signature"
    );

    Ok(())
}
