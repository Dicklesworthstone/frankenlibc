//! Contract tests for bd-wud.1 mode semantics matrix completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
    root.join("tests/conformance/mode_semantics_matrix_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_mode_semantics_matrix_completion_contract.sh")
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
        .ok_or_else(|| test_error("value should be array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "mode-semantics-matrix-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_MODE_SEMANTICS_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_MODE_SEMANTICS_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_MODE_SEMANTICS_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_MODE_SEMANTICS_COMPLETION_LOG",
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
fn contract_anchors_mode_semantics_matrix_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("mode_semantics_matrix_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-wud"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-wud.1"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert_eq!(
        manifest["matrix_expectations"]["total_families"].as_u64(),
        Some(20)
    );
    assert_eq!(
        manifest["matrix_expectations"]["total_heals_call_sites"].as_u64(),
        Some(141)
    );
    for reference in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| test_error("implementation refs should be array"))?
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
fn source_artifacts_bind_mode_semantics_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source artifacts should be array"))?;
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
            "completion_contract".to_string(),
            "completion_harness".to_string(),
            "mode_semantics_gate".to_string(),
            "mode_semantics_harness".to_string(),
            "mode_semantics_matrix".to_string(),
            "verification_matrix_record".to_string(),
        ])
    );
    for source in sources {
        let path = source["path"]
            .as_str()
            .ok_or_else(|| test_error("source path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in source["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required needles should be array"))?
        {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(text.contains(needle), "{path} missing needle {needle}");
        }
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
        "checker failed\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS mode semantics matrix completion contract")
    );
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("mode_semantics_matrix_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(7));
    assert_eq!(report["binding_count"].as_u64(), Some(3));
    assert_eq!(report["family_count"].as_u64(), Some(20));
    assert_eq!(report["total_heals_call_sites"].as_u64(), Some(141));
    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("mode_semantics_matrix.source_artifacts_validated"));
    assert!(events.contains("mode_semantics_matrix.matrix_expectations_validated"));
    assert!(events.contains("mode_semantics_matrix.unit_binding_validated"));
    assert!(events.contains("mode_semantics_matrix.e2e_binding_validated"));
    assert!(events.contains("mode_semantics_matrix.telemetry_binding_validated"));
    assert!(events.contains("mode_semantics_matrix.completion_contract_validated"));
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["missing_items_closed"] = Value::Array(vec![
        Value::String("tests.e2e.primary".to_string()),
        Value::String("telemetry.primary".to_string()),
    ]);
    let bad_manifest = out_dir.join("missing_unit.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing unit binding\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("missing_items_closed drifted"),
        "expected missing unit failure\n{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    if let Some(bindings) = manifest["completion_bindings"].as_array_mut()
        && let Some(telemetry) = bindings
            .iter_mut()
            .find(|row| row["missing_item_id"].as_str() == Some("telemetry.primary"))
    {
        telemetry["required_completion_events"] = Value::Array(vec![
            Value::String("mode_semantics_matrix.source_artifacts_validated".to_string()),
            Value::String("mode_semantics_matrix.completion_contract_validated".to_string()),
        ]);
    }
    let bad_manifest = out_dir.join("missing_telemetry_event.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event binding\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("required_completion_events missing"),
        "expected missing telemetry event failure\n{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_matrix_expectation_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "matrix-drift")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["matrix_expectations"]["total_families"] = Value::from(21);
    let bad_manifest = out_dir.join("matrix_drift.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject matrix expectation drift\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("matrix total_families expectation drifted"),
        "expected matrix expectation failure\n{}",
        output_text(&output)
    );
    Ok(())
}
