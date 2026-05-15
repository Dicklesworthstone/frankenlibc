//! Completion-debt contract for bd-2icq.14 / bd-2icq.14.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_SCENARIOS: &[&str] = &[
    "single_package",
    "build_wave",
    "test_suite",
    "full_pipeline",
    "failure_recovery",
    "progress_reporting",
];

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir
        .parent()
        .ok_or("crate directory has workspace parent")?;
    let root = workspace
        .parent()
        .ok_or("workspace parent has repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/full_validation_pipeline_logging_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_full_validation_pipeline_logging_completion_contract.sh")
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
        "full_validation_pipeline_logging_completion_contract_{label}_{}_{}",
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
        .env(
            "FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_REPORT",
            out_dir.join("full_validation_pipeline_logging_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_LOG",
            out_dir.join("full_validation_pipeline_logging_completion_contract.log.jsonl"),
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
        .ok_or("expected array")?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| "expected string".into())
                .map(str::to_owned)
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()
}

#[test]
fn manifest_binds_all_e2e_scenarios_and_missing_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("full_validation_pipeline_logging_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2icq.14"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2icq.14.1")
    );

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in artifacts {
        let path = path.as_str().ok_or("artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let scenario_ids: BTreeSet<_> = manifest["scenario_contracts"]
        .as_array()
        .ok_or("scenario_contracts must be array")?
        .iter()
        .filter_map(|scenario| scenario["id"].as_str())
        .collect();
    for scenario in REQUIRED_SCENARIOS {
        assert!(
            scenario_ids.contains(scenario),
            "missing e2e scenario {scenario}"
        );
    }

    let item_ids: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for item in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
        assert!(item_ids.contains(item), "missing item binding {item}");
    }

    let test_source = std::fs::read_to_string(root.join(file!()))?;
    for test_ref in manifest["completion_debt_evidence"]["required_test_refs"]
        .as_array()
        .ok_or("required_test_refs must be array")?
    {
        let test_ref = test_ref.as_str().ok_or("test ref must be string")?;
        assert!(
            test_source.contains(&format!("fn {test_ref}")),
            "required test ref {test_ref} missing from this source"
        );
    }

    Ok(())
}

#[test]
fn shared_logging_library_pins_timestamp_steps_and_summary_fields() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    let common = &manifest["common_logging_contract"];
    let common_path = root.join(common["script"].as_str().ok_or("common script")?);
    let source = std::fs::read_to_string(common_path)?;

    for function_name in common["required_functions"]
        .as_array()
        .ok_or("required_functions must be array")?
    {
        let function_name = function_name.as_str().ok_or("function name string")?;
        assert!(
            source.contains(&format!("{function_name}()")),
            "common logging library missing function {function_name}"
        );
    }

    for needle in common["required_needles"]
        .as_array()
        .ok_or("required_needles must be array")?
    {
        let needle = needle.as_str().ok_or("needle string")?;
        assert!(
            source.contains(needle),
            "common logging library missing needle {needle}"
        );
    }

    let summary_fields = strings(&common["required_summary_fields"])?;
    for field in [
        "test_name",
        "result",
        "duration_seconds",
        "timestamp",
        "log_file",
        "image",
        "mode",
    ] {
        assert!(summary_fields.contains(field), "summary missing {field}");
        assert!(
            source.contains(&format!("\"{field}\"")),
            "summary writer missing field {field}"
        );
    }

    Ok(())
}

#[test]
fn checker_validates_scripts_run_all_registry_and_emits_artifacts() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("full_validation_pipeline_logging_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("full_validation_pipeline_logging_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-2icq.14"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-2icq.14.1")
    );
    assert_eq!(report["summary"]["scenario_count"].as_u64(), Some(6));
    assert_eq!(
        report["summary"]["expected_scenario_count"].as_u64(),
        Some(6)
    );
    assert!(
        report["run_all_contract"]["all_tests"]
            .as_array()
            .ok_or("all_tests array")?
            .iter()
            .any(|entry| entry.as_str() == Some("full_pipeline:test_full_pipeline.sh:30")),
        "run_all gate should bind full_pipeline entry"
    );

    let rows = jsonl_rows(
        &out_dir.join("full_validation_pipeline_logging_completion_contract.log.jsonl"),
    )?;
    assert!(
        rows.len() >= 8,
        "expected scenario, common, run_all, and summary rows"
    );
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for event in [
        "full_validation_pipeline_logging_source_gate",
        "full_validation_pipeline_logging_common_gate",
        "full_validation_pipeline_logging_run_all_gate",
        "full_validation_pipeline_logging_completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing log event {event}");
    }

    for (index, row) in rows.iter().enumerate() {
        for field in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "bead_id",
            "stream",
            "gate",
            "scenario_id",
            "runtime_mode",
            "replacement_level",
            "api_family",
            "symbol",
            "oracle_kind",
            "expected",
            "actual",
            "source_commit",
            "target_dir",
            "failure_signature",
            "artifact_refs",
        ] {
            assert!(row.get(field).is_some(), "row {index} missing {field}");
        }
        let line = serde_json::to_string(row)?;
        validate_log_line(&line, index + 1).map_err(|errors| {
            std::io::Error::other(format!("structured log row {index} rejected: {errors:?}"))
        })?;
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_required_scenario() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_scenario")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let scenarios = manifest["scenario_contracts"]
        .as_array_mut()
        .ok_or("scenario_contracts array")?;
    scenarios.retain(|scenario| scenario["id"].as_str() != Some("progress_reporting"));
    let bad_contract = out_dir.join("missing_progress_reporting_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing scenario\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("progress_reporting"),
        "failure should name missing progress_reporting scenario"
    );

    let report = load_json(
        &out_dir.join("full_validation_pipeline_logging_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or_default()
                .contains("progress_reporting")),
        "report should retain missing scenario error"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_trace_id() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_trace_id")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["required_log_fields"]
        .as_array_mut()
        .ok_or("required_log_fields array")?;
    fields.retain(|field| field.as_str() != Some("trace_id"));
    let bad_contract = out_dir.join("missing_trace_id_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing trace_id\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("trace_id"),
        "failure should mention missing trace_id"
    );

    let rows = jsonl_rows(
        &out_dir.join("full_validation_pipeline_logging_completion_contract.log.jsonl"),
    )?;
    assert!(
        rows.iter().any(|row| row["event"].as_str()
            == Some("full_validation_pipeline_logging_completion_contract_failed")),
        "failure run should emit failed completion event"
    );

    Ok(())
}
