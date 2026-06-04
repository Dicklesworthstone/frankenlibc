//! Completion contract tests for bd-2hh.1.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str = "tests/conformance/fixture_capture_pipeline_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_fixture_capture_pipeline_completion_contract.sh";
const PIPELINE_REPORT_REL: &str = "tests/conformance/fixture_pipeline.v1.json";
const GOLDEN_SUITE_REL: &str =
    "tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json";
const EXPECTED_SCHEMA: &str = "fixture_capture_pipeline_completion_contract.v1";
const EXPECTED_TRACE_ID: &str = "bd-2hh.1.1::fixture-capture-pipeline::completion::v1";
const GENERATED_PIPELINE_NAME: &str = "fixture_pipeline.generated.v1.json";
const GENERATED_UNIT_NAME: &str = "fixture_unit_tests.generated.v1.json";
const GENERATED_UNIT_LOG_NAME: &str = "fixture_unit_tests.generated.log.jsonl";

const EXPECTED_MISSING_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.golden.primary",
    "tests.conformance.primary",
];

const EXPECTED_SOURCE_ARTIFACT_IDS: &[&str] = &[
    "capture_impl",
    "fixture_loader_impl",
    "fixture_runner_impl",
    "fixture_exec_boundary",
    "fixture_pipeline_report",
    "fixture_pipeline_generator",
    "fixture_pipeline_gate",
    "fixture_pipeline_test",
    "fixture_unit_report",
    "fixture_unit_generator",
    "fixture_unit_gate",
    "fixture_unit_test",
    "fixture_schema_contract",
    "fixture_schema_gate",
    "fixture_schema_test",
    "fixture_executor_golden_contract",
    "fixture_executor_golden_gate",
    "fixture_executor_golden_test",
    "fixture_verify_golden_suite",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
];

const EXPECTED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "fixture_pipeline_report_validated",
    "fixture_pipeline_probe_generated",
    "fixture_unit_report_validated",
    "fixture_unit_probe_generated",
    "fixture_schema_inventory_validated",
    "fixture_golden_contract_validated",
    "missing_item_bindings_validated",
    "base_fixture_gates_replayed",
    "test_surfaces_validated",
    "fixture_capture_pipeline_completion_contract_validated",
    "fixture_capture_pipeline_completion_summary",
];

const REQUIRED_POSITIVE_TESTS: &[&str] = &[
    "contract_binds_fixture_capture_completion_items",
    "checker_accepts_fixture_capture_completion_contract",
    "completion_contract_generates_pipeline_and_unit_probes",
];

const REQUIRED_NEGATIVE_TESTS: &[&str] = &[
    "checker_rejects_missing_golden_binding",
    "checker_rejects_fixture_pipeline_count_drift",
    "checker_rejects_golden_suite_failure_drift",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("manifest should have a crates parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("manifest should live under workspace root"))?;
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
        "fixture-capture-pipeline-completion-{label}-{}-{nanos}",
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

fn generated_pipeline(out_dir: &Path) -> PathBuf {
    out_dir.join(GENERATED_PIPELINE_NAME)
}

fn generated_unit(out_dir: &Path) -> PathBuf {
    out_dir.join(GENERATED_UNIT_NAME)
}

fn generated_unit_log(out_dir: &Path) -> PathBuf {
    out_dir.join(GENERATED_UNIT_LOG_NAME)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    out_dir: &Path,
    env_overrides: &[(&str, &Path)],
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_LOG",
            checker_log(out_dir),
        )
        .env(
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_GENERATED_PIPELINE",
            generated_pipeline(out_dir),
        )
        .env(
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_GENERATED_UNIT",
            generated_unit(out_dir),
        )
        .env(
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_GENERATED_UNIT_LOG",
            generated_unit_log(out_dir),
        );
    for (key, value) in env_overrides {
        command.env(key, value);
    }
    Ok(command.output()?)
}

fn expect_checker_success(root: &Path, out_dir: &Path) -> TestResult<Output> {
    let output = run_checker(root, &root.join(CONTRACT_REL), out_dir, &[])?;
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

fn object_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} object missing")).into()
    })
}

fn array_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} array missing")).into()
    })
}

fn string_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} string missing")).into()
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

fn artifact_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    array_field(manifest, "source_artifacts")?
        .iter()
        .map(|artifact| Ok(string_field(artifact, "id")?.to_owned()))
        .collect()
}

fn binding_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    array_field(manifest, "missing_item_bindings")?
        .iter()
        .map(|binding| Ok(string_field(binding, "missing_item_id")?.to_owned()))
        .collect()
}

fn required_function_set(manifest: &Value, key: &str) -> TestResult<BTreeSet<String>> {
    let required = object_field(manifest, "required_test_functions")?;
    let values = required.get(key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("required {key} tests missing"),
        )
    })?;
    string_set(values.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{key} tests must be an array"),
        )
    })?)
}

fn insert_object_value(
    value: &mut Value,
    object_key: &str,
    field_key: &str,
    new_value: Value,
) -> TestResult {
    let object = value
        .get_mut(object_key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{object_key} object missing"),
            )
        })?;
    object.insert(field_key.to_string(), new_value);
    Ok(())
}

#[test]
fn contract_binds_fixture_capture_completion_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-2hh.1.1");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-2hh.1");
    assert_eq!(string_field(&manifest, "trace_id")?, EXPECTED_TRACE_ID);

    assert_eq!(
        artifact_ids(&manifest)?,
        EXPECTED_SOURCE_ARTIFACT_IDS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let source_artifacts = array_field(&manifest, "source_artifacts")?;
    for artifact in source_artifacts {
        let path = string_field(artifact, "path")?;
        assert!(
            root.join(path).exists(),
            "source artifact path should exist: {path}"
        );
        assert!(
            !string_field(artifact, "evidence")?.is_empty(),
            "source artifact evidence should be non-empty"
        );
    }

    let contract = manifest
        .get("completion_contract")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion contract missing"))?;
    assert_eq!(
        string_set(array_field(contract, "missing_item_ids")?)?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );
    let required_golden = object_field(contract, "required_golden")?;
    assert_eq!(
        required_golden
            .get("verify_suite_total")
            .and_then(Value::as_u64),
        Some(3369)
    );
    assert_eq!(
        required_golden
            .get("executor_case_count")
            .and_then(Value::as_u64),
        Some(7)
    );

    assert_eq!(
        binding_ids(&manifest)?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );
    for binding in array_field(&manifest, "missing_item_bindings")? {
        let missing_item_id = string_field(binding, "missing_item_id")?;
        for key in ["implementation_refs", "test_refs", "runtime_validation"] {
            assert!(
                array_field(binding, key)?.iter().any(Value::is_string),
                "{missing_item_id}.{key} should cite at least one string ref"
            );
        }
    }

    assert_eq!(
        required_function_set(&manifest, "positive")?,
        REQUIRED_POSITIVE_TESTS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );
    assert_eq!(
        required_function_set(&manifest, "negative")?,
        REQUIRED_NEGATIVE_TESTS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    Ok(())
}

#[test]
fn checker_accepts_fixture_capture_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: fixture capture pipeline completion contract files=127"),
        "pass marker missing from stdout: {stdout}"
    );

    let report = read_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(string_field(&report, "schema_version")?, EXPECTED_SCHEMA);

    let summary = object_field(&report, "summary")?;
    assert_eq!(
        summary.get("total_fixture_files").and_then(Value::as_u64),
        Some(127)
    );
    assert_eq!(
        summary.get("total_fixture_cases").and_then(Value::as_u64),
        Some(2792)
    );
    assert_eq!(
        summary.get("unit_total_cases").and_then(Value::as_u64),
        Some(2797)
    );
    assert_eq!(
        summary.get("golden_case_count").and_then(Value::as_u64),
        Some(7)
    );
    assert_eq!(
        summary.get("suite_total").and_then(Value::as_u64),
        Some(3369)
    );
    assert_eq!(
        summary.get("binding_count").and_then(Value::as_u64),
        Some(4)
    );

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names = events
        .iter()
        .map(|event| Ok(string_field(event, "event")?.to_owned()))
        .collect::<TestResult<BTreeSet<_>>>()?;
    for expected in EXPECTED_EVENTS {
        assert!(
            event_names.contains(*expected),
            "missing completion log event {expected}"
        );
    }

    Ok(())
}

#[test]
fn completion_contract_generates_pipeline_and_unit_probes() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "probes")?;
    expect_checker_success(&root, &out_dir)?;

    let pipeline = read_json(&generated_pipeline(&out_dir))?;
    let pipeline_summary = object_field(&pipeline, "summary")?;
    assert_eq!(
        pipeline_summary
            .get("total_fixture_files")
            .and_then(Value::as_u64),
        Some(127)
    );
    assert_eq!(
        pipeline_summary
            .get("total_fixture_cases")
            .and_then(Value::as_u64),
        Some(2792)
    );

    let unit = read_json(&generated_unit(&out_dir))?;
    let unit_summary = object_field(&unit, "summary")?;
    assert_eq!(
        unit_summary
            .get("total_fixture_files")
            .and_then(Value::as_u64),
        Some(127)
    );
    assert_eq!(
        unit_summary.get("total_cases").and_then(Value::as_u64),
        Some(2797)
    );

    let unit_log = std::fs::read_to_string(generated_unit_log(&out_dir))?;
    assert!(
        unit_log
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
            >= 2,
        "generated fixture unit log should contain JSONL telemetry"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_golden_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-golden")?;
    let contract_path = out_dir.join("contract.missing-golden.json");
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing_item_bindings missing")
        })?;
    bindings.retain(|binding| {
        binding.get("missing_item_id").and_then(Value::as_str) != Some("tests.golden.primary")
    });
    write_json(&contract_path, &manifest)?;

    let output = run_checker(&root, &contract_path, &out_dir, &[])?;
    expect_checker_failure(output, "missing_golden_binding");
    Ok(())
}

#[test]
fn checker_rejects_fixture_pipeline_count_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pipeline-drift")?;
    let pipeline_path = out_dir.join("fixture_pipeline.drift.json");
    let mut pipeline = read_json(&root.join(PIPELINE_REPORT_REL))?;
    insert_object_value(&mut pipeline, "summary", "total_fixture_files", json!(57))?;
    write_json(&pipeline_path, &pipeline)?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_PIPELINE_REPORT",
            pipeline_path.as_path(),
        )],
    )?;
    expect_checker_failure(output, "fixture_pipeline_drift");
    Ok(())
}

#[test]
fn checker_rejects_golden_suite_failure_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "golden-drift")?;
    let suite_path = out_dir.join("fixture_verify_strict_hardened.drift.json");
    let mut suite = read_json(&root.join(GOLDEN_SUITE_REL))?;
    if let Some(object) = suite.as_object_mut() {
        object.insert("passed".to_string(), json!(1816));
        object.insert("failed".to_string(), json!(1));
    } else {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "golden suite must be object").into(),
        );
    }
    write_json(&suite_path, &suite)?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_VERIFY_GOLDEN_SUITE",
            suite_path.as_path(),
        )],
    )?;
    expect_checker_failure(output, "fixture_golden_drift");
    Ok(())
}
