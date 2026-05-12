//! Completion-contract tests for bd-h7ede.1 printf float precision evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "completion_contract_shape_validated",
    "missing_item_bindings_validated",
    "precision_cap_validated",
    "printf_conformance_fixture_validated",
    "test_surfaces_validated",
    "printf_float_precision_completion_contract_validated",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/printf_float_precision_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_printf_float_precision_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<BTreeSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain only strings")))
        })
        .collect::<Result<_, _>>()
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_REPORT",
            out_dir.join("printf_float_precision_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_LOG",
            out_dir.join("printf_float_precision_completion_contract.events.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("printf_float_precision_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("printf_float_precision_completion_contract.events.jsonl")
}

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn failure_signatures(report: &Value) -> BTreeSet<&str> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .collect()
}

fn remove_binding(manifest: &mut Value, missing_item_id: &str) -> TestResult {
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("missing_item_bindings should be an array"))?;
    bindings
        .retain(|row| row.get("missing_item_id").and_then(Value::as_str) != Some(missing_item_id));
    Ok(())
}

fn set_required_cap_value(manifest: &mut Value, key: &str, value: u64) -> TestResult {
    let obj = manifest
        .get_mut("completion_contract")
        .and_then(Value::as_object_mut)
        .and_then(|contract| contract.get_mut("required_precision_cap"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            test_error("completion_contract.required_precision_cap should be an object")
        })?;
    obj.insert(key.to_owned(), Value::from(value));
    Ok(())
}

#[test]
fn contract_binds_printf_float_precision_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "printf_float_precision_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-h7ede.1"
    );
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-h7ede"
    );

    let artifacts: BTreeSet<_> = array_field(&manifest, "source_artifacts", "manifest")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "printf_core",
        "printf_conformance_fixture",
        "printf_conformance_harness_test",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }

    let completion = field(&manifest, "completion_contract", "manifest")?;
    let missing_items = string_set(completion, "missing_item_ids", "completion_contract")?;
    assert!(missing_items.contains("tests.unit.primary"));
    assert!(missing_items.contains("tests.conformance.primary"));

    let cap = field(completion, "required_precision_cap", "completion_contract")?;
    assert_eq!(cap["cap"].as_u64(), Some(65_535));
    assert_eq!(cap["first_panicking_precision"].as_u64(), Some(65_536));
    assert_eq!(cap["required_output_len_at_cap"].as_u64(), Some(65_537));
    Ok(())
}

#[test]
fn checker_accepts_printf_float_precision_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "printf-float-precision-check")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS printf float precision completion contract")
    );

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "printf_float_precision_completion_contract.report.v1"
    );
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    Ok(())
}

#[test]
fn checker_emits_structured_printf_precision_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "printf-float-precision-telemetry")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names: BTreeSet<_> = events
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(
            event_names.contains(required),
            "missing checker event {required}"
        );
    }
    for row in &events {
        assert_eq!(string_field(row, "bead_id", "event")?, "bd-h7ede.1");
        assert!(
            string_field(row, "trace_id", "event")?
                .starts_with("bd-h7ede.1::printf-float-precision::completion::v1::")
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_binding(&mut manifest, "tests.unit.primary")?;

    let out_dir = unique_output_dir(&root, "printf-float-precision-missing-unit")?;
    let bad_manifest = out_dir.join("bad_missing_unit.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_unit_binding"));
    Ok(())
}

#[test]
fn checker_rejects_precision_cap_drift() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    set_required_cap_value(&mut manifest, "cap", 65_536)?;

    let out_dir = unique_output_dir(&root, "printf-float-precision-cap-drift")?;
    let bad_manifest = out_dir.join("bad_cap_drift.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("precision_cap_drift"));
    Ok(())
}

#[test]
fn checker_rejects_missing_conformance_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    remove_binding(&mut manifest, "tests.conformance.primary")?;

    let out_dir = unique_output_dir(&root, "printf-float-precision-missing-conformance")?;
    let bad_manifest = out_dir.join("bad_missing_conformance.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_conformance_binding"));
    Ok(())
}
