//! Contract tests for bd-wv5ym.1 printf star width/precision evidence.

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
    root.join("tests/conformance/printf_star_width_precision_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_printf_star_width_precision_completion_contract.sh")
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
        "printf-star-width-precision-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_PRINTF_STAR_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_PRINTF_STAR_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_PRINTF_STAR_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_PRINTF_STAR_COMPLETION_LOG",
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
fn contract_anchors_printf_star_width_precision_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("printf_star_width_precision_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-wv5ym"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-wv5ym.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from(["tests.conformance.primary".to_string()])
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
fn source_artifacts_bind_printf_star_surfaces() -> TestResult {
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
            "discrepancy_record".to_string(),
            "glibc_differential_conformance".to_string(),
            "printf_abi_implementation".to_string(),
            "stdio_abi_regressions".to_string(),
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
            .contains("PASS printf star width precision completion contract")
    );
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("printf_star_width_precision_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(7));
    assert_eq!(report["test_binding_count"].as_u64(), Some(5));
    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("printf_star_width_precision.source_artifacts_validated"));
    assert!(events.contains("printf_star_width_precision.conformance_binding_validated"));
    assert!(events.contains("printf_star_width_precision.completion_contract_validated"));
    Ok(())
}

#[test]
fn checker_rejects_missing_conformance_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-conformance")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["missing_items_closed"] = Value::Array(vec![]);
    let bad_manifest = out_dir.join("missing_conformance.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing conformance binding\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("missing_items_closed must bind tests.conformance.primary"),
        "expected missing conformance failure\n{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_differential_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-diff")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["conformance_primary"]["required_test_refs"] = Value::Array(vec![
        serde_json::json!({"source":"stdio_abi_regressions","name":"snprintf_normalizes_positional_negative_star_width"}),
        serde_json::json!({"source":"stdio_abi_regressions","name":"snprintf_normalizes_positional_negative_star_precision"}),
        serde_json::json!({"source":"stdio_abi_regressions","name":"vsprintf_normalizes_negative_star_width_from_va_list"}),
        serde_json::json!({"source":"completion_harness","name":"checker_accepts_contract_and_emits_telemetry"}),
    ]);
    let bad_manifest = out_dir.join("missing_diff.json");
    write_json(&bad_manifest, &manifest)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing differential test binding\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("conformance_primary.required_test_refs missing"),
        "expected missing diff test failure\n{}",
        output_text(&output)
    );
    Ok(())
}
