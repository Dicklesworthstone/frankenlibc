//! Completion-contract tests for bd-4rdz8.1 aio_suspend timespec evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/aio_suspend_timespec_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_aio_suspend_timespec_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "aio-suspend-timespec-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_AIO_SUSPEND_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_AIO_SUSPEND_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_AIO_SUSPEND_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_AIO_SUSPEND_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
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

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["failure_signature"].as_str().map(str::to_owned))
        .collect()
}

fn mutated_manifest(root: &Path, label: &str, manifest: &Value) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, label)?;
    let path = out_dir.join("contract.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

#[test]
fn manifest_binds_unit_and_golden_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("aio_suspend_timespec_completion_contract.v1")
    );
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-4rdz8.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-4rdz8"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.golden.primary".to_string(),
        ])
    );
    assert_eq!(
        manifest["unit_primary"]["required_harness_tests"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    assert_eq!(
        manifest["golden_primary"]["required_case_ids"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS aio_suspend timespec completion contract"),
        "{}",
        output_text(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("aio_suspend_timespec_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-4rdz8.1"));
    assert_eq!(report["source_count"].as_u64(), Some(6));
    assert_eq!(report["unit_test_count"].as_u64(), Some(4));
    assert_eq!(report["golden_case_count"].as_u64(), Some(4));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));

    let events = load_jsonl(&out_dir.join("events.jsonl"))?;
    let names = events
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for required in [
        "aio_suspend_timespec_completion.source_artifacts",
        "aio_suspend_timespec_completion.unit_bindings",
        "aio_suspend_timespec_completion.golden_bindings",
        "aio_suspend_timespec_completion.validated",
    ] {
        assert!(names.contains(required), "missing event {required}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_harness_tests"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_harness_tests should be array"))?
        .retain(|name| name.as_str() != Some("aio_suspend_rejects_oversize_tv_nsec"));
    let (path, out_dir) = mutated_manifest(&root, "missing-unit", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("missing_unit_binding"));
    Ok(())
}

#[test]
fn checker_rejects_golden_case_drift() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["golden_primary"]["required_case_ids"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_case_ids should be array"))?
        .retain(|name| name.as_str() != Some("negative_tv_nsec"));
    let (path, out_dir) = mutated_manifest(&root, "missing-golden", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&out_dir.join("report.json"))?;
    assert!(failure_signatures(&report).contains("missing_golden_binding"));
    Ok(())
}

#[test]
fn golden_artifact_pins_invalid_input_cases() -> TestResult {
    let root = workspace_root()?;
    let golden = load_json(
        &root.join("tests/conformance/golden/aio_suspend_timespec_invalid_inputs.v1.json"),
    )?;
    assert_eq!(
        golden["schema_version"].as_str(),
        Some("aio_suspend_timespec_invalid_inputs.golden.v1")
    );
    let cases = golden["cases"]
        .as_array()
        .ok_or_else(|| test_error("cases should be array"))?;
    let ids = cases
        .iter()
        .filter_map(|case| case["id"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids,
        BTreeSet::from([
            "empty_list_precedes_timeout".to_string(),
            "negative_tv_nsec".to_string(),
            "negative_tv_sec".to_string(),
            "oversize_tv_nsec".to_string(),
        ])
    );
    for case in cases {
        assert_eq!(case["expected"]["return_value"].as_i64(), Some(-1));
        assert_eq!(case["expected"]["errno"].as_str(), Some("EINVAL"));
        assert_eq!(case["expected"]["errno_value"].as_i64(), Some(22));
        assert_eq!(case["expected"]["no_panic"].as_bool(), Some(true));
    }
    Ok(())
}
