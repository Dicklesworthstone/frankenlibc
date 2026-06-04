//! Completion contract tests for bd-l93x.1.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/fixture_capture_remaining_symbols_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_fixture_capture_remaining_symbols_completion_contract.sh";
const PER_SYMBOL_REPORT_REL: &str = "tests/conformance/per_symbol_fixture_tests.v1.json";
const GOLDEN_SUITE_REL: &str =
    "tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json";
const EXPECTED_SCHEMA: &str = "fixture_capture_remaining_symbols_completion_contract.v1";
const EXPECTED_REPORT_SCHEMA: &str =
    "fixture_capture_remaining_symbols_completion_contract.report.v1";
const EXPECTED_TRACE_ID: &str = "bd-l93x.1.1::fixture-capture-remaining-symbols::completion::v1";
const GENERATED_PER_SYMBOL_NAME: &str = "per_symbol_fixture_tests.generated.v1.json";

const EXPECTED_MISSING_ITEMS: &[&str] = &["telemetry.primary", "tests.golden.primary"];

const EXPECTED_SOURCE_ARTIFACT_IDS: &[&str] = &[
    "symbol_fixture_coverage_matrix",
    "symbol_fixture_coverage_gate",
    "symbol_fixture_coverage_harness",
    "per_symbol_fixture_report",
    "per_symbol_fixture_generator",
    "per_symbol_fixture_gate",
    "per_symbol_fixture_harness",
    "fixture_pipeline_report",
    "fixture_capture_pipeline_completion_contract",
    "fixture_capture_pipeline_completion_gate",
    "fixture_capture_pipeline_completion_harness",
    "golden_fixture_protocol",
    "golden_fixture_protocol_completion_contract",
    "golden_fixture_protocol_completion_gate",
    "golden_fixture_protocol_completion_harness",
    "golden_fixture_verify_suite",
    "completion_checker",
    "completion_harness",
];

const EXPECTED_EVENTS: &[&str] = &[
    "fixture_remaining_symbol_sources_validated",
    "fixture_remaining_symbol_matrix_validated",
    "fixture_remaining_symbol_report_validated",
    "fixture_remaining_symbol_probe_generated",
    "fixture_remaining_symbol_golden_validated",
    "fixture_remaining_symbol_bindings_validated",
    "fixture_remaining_symbol_source_gates_replayed",
    "fixture_remaining_symbol_completion_contract_pass",
];

const REQUIRED_POSITIVE_TESTS: &[&str] = &[
    "contract_binds_golden_and_telemetry_items",
    "checker_accepts_remaining_symbols_contract",
    "checker_generates_per_symbol_probe",
];

const REQUIRED_NEGATIVE_TESTS: &[&str] = &[
    "checker_rejects_missing_telemetry_binding",
    "checker_rejects_understated_fixture_case_inventory",
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
        "fixture-capture-remaining-symbols-{label}-{}-{nanos}",
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

fn generated_per_symbol(out_dir: &Path) -> PathBuf {
    out_dir.join(GENERATED_PER_SYMBOL_NAME)
}

fn source_gate_dir(out_dir: &Path) -> PathBuf {
    out_dir.join("source_gates")
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
        .env(
            "FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_LOG",
            checker_log(out_dir),
        )
        .env(
            "FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_GENERATED_PER_SYMBOL",
            generated_per_symbol(out_dir),
        )
        .env(
            "FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_GATE_DIR",
            source_gate_dir(out_dir),
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

fn binding_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    array_field(manifest, "missing_item_bindings")?
        .iter()
        .map(|binding| Ok(string_field(binding, "id")?.to_owned()))
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
fn contract_binds_golden_and_telemetry_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "bd-l93x.1.1-fixture-capture-remaining-symbols-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-l93x.1.1");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-l93x.1");
    assert_eq!(string_field(&manifest, "trace_id")?, EXPECTED_TRACE_ID);

    let source_artifacts = object_field(&manifest, "source_artifacts")?;
    assert_eq!(
        source_artifacts.keys().cloned().collect::<BTreeSet<_>>(),
        EXPECTED_SOURCE_ARTIFACT_IDS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );
    for (artifact_id, path) in source_artifacts {
        let path = path.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{artifact_id} path should be a string"),
            )
        })?;
        assert!(
            root.join(path).exists(),
            "source artifact path should exist: {artifact_id} -> {path}"
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
    assert_eq!(
        binding_ids(&manifest)?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let telemetry = object_field(&manifest, "telemetry_contract")?;
    assert_eq!(
        telemetry
            .get("report_schema_version")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "report schema version missing"
            ))?,
        EXPECTED_REPORT_SCHEMA
    );
    let events = string_set(
        telemetry
            .get("required_events")
            .and_then(Value::as_array)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required events missing"))?,
    )?;
    for expected in EXPECTED_EVENTS {
        assert!(
            events.contains(*expected),
            "telemetry contract missing event {expected}"
        );
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
fn checker_accepts_remaining_symbols_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: fixture capture remaining-symbol completion contract symbols=4119"),
        "pass marker missing from stdout: {stdout}"
    );

    let report = read_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "schema_version")?,
        EXPECTED_REPORT_SCHEMA
    );

    let summary = object_field(&report, "summary")?;
    assert_eq!(
        summary
            .get("total_exported_symbols")
            .and_then(Value::as_u64),
        Some(4119)
    );
    assert_eq!(
        summary
            .get("covered_exported_symbols")
            .and_then(Value::as_u64),
        Some(1166)
    );
    assert_eq!(
        summary
            .get("uncovered_action_count")
            .and_then(Value::as_u64),
        Some(1952)
    );
    assert_eq!(
        summary.get("total_cases").and_then(Value::as_u64),
        Some(2787)
    );
    assert_eq!(
        summary.get("golden_total").and_then(Value::as_u64),
        Some(3369)
    );
    assert_eq!(
        summary.get("binding_count").and_then(Value::as_u64),
        Some(2)
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

    let source_gates = object_field(&report, "source_gate_results")?;
    assert!(
        source_gates.contains_key("symbol_fixture_coverage_gate"),
        "symbol fixture coverage gate result should be recorded"
    );
    assert!(
        source_gates.contains_key("golden_fixture_protocol_completion_gate"),
        "golden fixture gate result should be recorded"
    );

    Ok(())
}

#[test]
fn checker_generates_per_symbol_probe() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "probe")?;
    expect_checker_success(&root, &out_dir)?;

    let generated = read_json(&generated_per_symbol(&out_dir))?;
    let summary = object_field(&generated, "summary")?;
    assert_eq!(
        summary.get("total_symbols").and_then(Value::as_u64),
        Some(4119)
    );
    assert_eq!(
        summary.get("symbols_with_fixtures").and_then(Value::as_u64),
        Some(1164)
    );
    assert_eq!(
        summary.get("total_cases").and_then(Value::as_u64),
        Some(2787)
    );
    assert_eq!(
        summary
            .get("uncovered_action_count")
            .and_then(Value::as_u64),
        Some(1952)
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let contract_path = out_dir.join("contract.missing-telemetry.json");
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing_item_bindings missing")
        })?;
    bindings
        .retain(|binding| binding.get("id").and_then(Value::as_str) != Some("telemetry.primary"));
    write_json(&contract_path, &manifest)?;

    let output = run_checker(&root, &contract_path, &out_dir, &[])?;
    expect_checker_failure(output, "missing_telemetry_binding");
    Ok(())
}

#[test]
fn checker_rejects_understated_fixture_case_inventory() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "case-drift")?;
    let report_path = out_dir.join("per_symbol_fixture_tests.drift.json");
    let mut report = read_json(&root.join(PER_SYMBOL_REPORT_REL))?;
    let summary = report
        .get_mut("summary")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "summary missing"))?;
    summary.insert("total_cases".to_string(), json!(2786));
    write_json(&report_path, &report)?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_PER_SYMBOL_REPORT",
            report_path.as_path(),
        )],
    )?;
    expect_checker_failure(output, "per_symbol_fixture_drift");
    Ok(())
}

#[test]
fn checker_rejects_golden_suite_failure_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "golden-drift")?;
    let suite_path = out_dir.join("fixture_verify_strict_hardened.drift.json");
    let mut suite = read_json(&root.join(GOLDEN_SUITE_REL))?;
    let suite_obj = suite
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "golden suite must be object"))?;
    suite_obj.insert("passed".to_string(), json!(3368));
    suite_obj.insert("failed".to_string(), json!(1));
    write_json(&suite_path, &suite)?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_GOLDEN_SUITE",
            suite_path.as_path(),
        )],
    )?;
    expect_checker_failure(output, "golden_fixture_drift");
    Ok(())
}
