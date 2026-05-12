//! Completion contract tests for bd-ypst.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str = "tests/conformance/stdio_abi_teardown_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_stdio_abi_teardown_completion_contract.sh";
const EXPECTED_SCHEMA: &str = "stdio_abi_teardown_completion_contract.v1";
const EXPECTED_REPORT_SCHEMA: &str = "stdio_abi_teardown_completion_contract.report.v1";
const EXPECTED_EVENTS: &[&str] = &[
    "stdio_abi_teardown.sources_validated",
    "stdio_abi_teardown.implementation_markers_validated",
    "stdio_abi_teardown.test_surface_validated",
    "stdio_abi_teardown.bindings_validated",
    "stdio_abi_teardown.completion_contract_pass",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("manifest should live below workspace root"))?
        .to_path_buf())
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
        "stdio-abi-teardown-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("events.jsonl")
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env(
            "FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_LOG",
            checker_log(out_dir),
        )
        .output()?)
}

fn expect_checker_success(root: &Path, out_dir: &Path) -> TestResult<Output> {
    let output = run_checker(root, &root.join(CONTRACT_REL), out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn expect_checker_failure(output: Output, signature: &str) {
    assert!(
        !output.status.success(),
        "checker unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(signature),
        "checker failure missing signature {signature:?}\n{combined}"
    );
}

fn string_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} string missing")).into()
    })
}

fn array_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} array missing")).into()
    })
}

fn object_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} object missing")).into()
    })
}

fn string_set(values: &[Value]) -> TestResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| {
            value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "expected string value").into()
            })
        })
        .collect()
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            validate_log_line(line, index + 1).map_err(|errors| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("structured log line {} failed: {errors:?}", index + 1),
                )
            })?;
            Ok(serde_json::from_str(line)?)
        })
        .collect()
}

#[test]
fn contract_binds_stdio_teardown_conformance_surface() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-ypst.1");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-ypst");

    let completion = manifest
        .get("completion_contract")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion contract missing"))?;
    assert_eq!(
        string_set(array_field(completion, "missing_item_ids")?)?,
        BTreeSet::from(["tests.conformance.primary".to_string()])
    );
    let test_contract = object_field(completion, "test_contract")?;
    assert_eq!(
        test_contract
            .get("minimum_test_count")
            .and_then(Value::as_u64),
        Some(99)
    );
    assert_eq!(
        test_contract
            .get("required_ignore_count")
            .and_then(Value::as_u64),
        Some(25)
    );
    Ok(())
}

#[test]
fn checker_accepts_stdio_abi_teardown_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: stdio ABI teardown completion contract"),
        "pass marker missing from stdout: {stdout}"
    );

    let report = read_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "schema_version")?,
        EXPECTED_REPORT_SCHEMA
    );
    let summary = object_field(&report, "summary")?;
    assert!(
        summary
            .get("stdio_abi_test_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count >= 99)
    );
    assert_eq!(
        summary
            .get("stdio_abi_ignore_count")
            .and_then(Value::as_u64),
        Some(25)
    );

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names = events
        .iter()
        .map(|event| Ok(string_field(event, "event")?.to_owned()))
        .collect::<TestResult<BTreeSet<_>>>()?;
    for expected in EXPECTED_EVENTS {
        assert!(
            event_names.contains(*expected),
            "missing completion event {expected}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_host_libio_patch_marker() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-marker")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    contract["completion_contract"]["implementation_markers"]["io_internal_abi"][0] =
        json!("not a real stdio ABI teardown marker");
    let contract_path = out_dir.join("contract-missing-marker.json");
    write_json(&contract_path, &contract)?;

    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(output, "missing implementation marker");
    Ok(())
}

#[test]
fn checker_rejects_stdio_abi_test_count_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "test-count-drift")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    contract["completion_contract"]["test_contract"]["minimum_test_count"] = json!(9999);
    let contract_path = out_dir.join("contract-test-count-drift.json");
    write_json(&contract_path, &contract)?;

    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(output, "stdio_abi_test test count below contract");
    Ok(())
}

#[test]
fn checker_rejects_missing_conformance_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-binding")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    contract["missing_item_bindings"] = json!([]);
    let contract_path = out_dir.join("contract-missing-binding.json");
    write_json(&contract_path, &contract)?;

    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(output, "missing_item_bindings mismatch");
    Ok(())
}
