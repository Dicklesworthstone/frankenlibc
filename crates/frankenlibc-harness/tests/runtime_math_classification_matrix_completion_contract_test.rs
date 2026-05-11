//! Completion contract tests for bd-2k6b.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/runtime_math_classification_matrix_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_runtime_math_classification_matrix_completion_contract.sh";
const MATRIX_REL: &str = "tests/runtime_math/runtime_math_classification_matrix.v1.json";
const CLASSIFICATION_LOG_REL: &str =
    "target/conformance/runtime_math_classification_matrix.log.jsonl";
const EXPECTED_SCHEMA: &str = "runtime_math_classification_matrix_completion_contract.v1";
const EXPECTED_TRACE_ID: &str = "bd-2k6b.1::runtime-math-classification-matrix::completion::v1";

const EXPECTED_SOURCE_ARTIFACT_IDS: &[&str] = &[
    "classification_matrix",
    "classification_gate",
    "classification_test",
    "math_governance",
    "runtime_math_linkage",
    "production_kernel_manifest",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
];

const REQUIRED_UNIT_TESTS: &[&str] = &[
    "matrix_exists_and_valid",
    "matrix_module_coverage_matches_sources",
    "matrix_rows_match_governance_and_linkage",
    "research_rows_have_transition_notes",
    "summary_consistent",
    "manifest_references_matrix",
    "gate_script_exists_and_executable",
    "gate_script_emits_structured_logs",
];

const EXPECTED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "classification_matrix_validated",
    "classification_sources_validated",
    "missing_item_binding_validated",
    "classification_gate_replayed",
    "classification_gate_outputs_validated",
    "test_surfaces_validated",
    "runtime_math_classification_matrix_completion_validated",
    "runtime_math_classification_matrix_completion_summary",
];

const REQUIRED_POSITIVE_TESTS: &[&str] = &[
    "contract_binds_runtime_math_classification_unit_item",
    "checker_accepts_runtime_math_classification_completion_contract",
    "checker_replays_classification_gate_and_log",
];

const REQUIRED_NEGATIVE_TESTS: &[&str] = &[
    "checker_rejects_missing_unit_binding",
    "checker_rejects_matrix_count_drift",
    "checker_rejects_classification_log_drift",
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
        "runtime-math-classification-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_LOG",
            checker_log(out_dir),
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

#[test]
fn contract_binds_runtime_math_classification_unit_item() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;

    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-2k6b.1");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-2k6b");
    assert_eq!(string_field(&manifest, "trace_id")?, EXPECTED_TRACE_ID);
    assert_eq!(
        artifact_ids(&manifest)?,
        EXPECTED_SOURCE_ARTIFACT_IDS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    for artifact in array_field(&manifest, "source_artifacts")? {
        let path = string_field(artifact, "path")?;
        assert!(
            root.join(path).exists(),
            "artifact path should exist: {path}"
        );
    }

    let contract = manifest
        .get("completion_contract")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion_contract missing"))?;
    assert_eq!(
        string_set(array_field(contract, "missing_item_ids")?)?,
        ["tests.unit.primary".to_string()].into_iter().collect()
    );

    let required_matrix = object_field(contract, "required_matrix")?;
    assert_eq!(
        required_matrix.get("total_modules").and_then(Value::as_u64),
        Some(69)
    );
    let classification_counts = required_matrix
        .get("classification_counts")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "classification_counts missing")
        })?;
    assert_eq!(
        classification_counts
            .get("production_core")
            .and_then(Value::as_u64),
        Some(12)
    );
    assert_eq!(
        classification_counts
            .get("production_monitor")
            .and_then(Value::as_u64),
        Some(13)
    );
    assert_eq!(
        classification_counts
            .get("research")
            .and_then(Value::as_u64),
        Some(44)
    );

    assert_eq!(
        string_set(array_field(contract, "required_unit_test_functions")?)?,
        REQUIRED_UNIT_TESTS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );
    assert_eq!(
        binding_ids(&manifest)?,
        ["tests.unit.primary".to_string()].into_iter().collect()
    );
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
fn checker_accepts_runtime_math_classification_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: runtime_math classification matrix completion contract modules=69"),
        "pass marker missing from stdout: {stdout}"
    );

    let report = read_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    let summary = object_field(&report, "summary")?;
    assert_eq!(
        summary.get("total_modules").and_then(Value::as_u64),
        Some(69)
    );
    assert_eq!(
        summary.get("production_core").and_then(Value::as_u64),
        Some(12)
    );
    assert_eq!(
        summary.get("production_monitor").and_then(Value::as_u64),
        Some(13)
    );
    assert_eq!(summary.get("research").and_then(Value::as_u64), Some(44));
    assert_eq!(summary.get("log_rows").and_then(Value::as_u64), Some(69));
    assert_eq!(
        summary.get("binding_count").and_then(Value::as_u64),
        Some(1)
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
fn checker_replays_classification_gate_and_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gate-log")?;
    expect_checker_success(&root, &out_dir)?;

    let classification_log = root.join(CLASSIFICATION_LOG_REL);
    let rows: Vec<Value> = std::fs::read_to_string(&classification_log)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        rows.len(),
        69,
        "classification gate should emit one row per module"
    );
    assert!(
        rows.iter()
            .all(|row| row.get("event").and_then(Value::as_str)
                == Some("runtime_math.classification_decision")),
        "all classification log rows should use the classification event"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let contract_path = out_dir.join("contract.missing-unit.json");
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing_item_bindings missing")
        })?;
    bindings.clear();
    write_json(&contract_path, &manifest)?;

    let output = run_checker(&root, &contract_path, &out_dir, &[])?;
    expect_checker_failure(output, "missing_unit_binding");
    Ok(())
}

#[test]
fn checker_rejects_matrix_count_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "matrix-drift")?;
    let matrix_path = out_dir.join("runtime_math_classification_matrix.drift.json");
    let mut matrix = read_json(&root.join(MATRIX_REL))?;
    let modules = matrix
        .get_mut("modules")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "matrix modules missing"))?;
    let _ = modules.pop();
    write_json(&matrix_path, &matrix)?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_MATRIX",
            matrix_path.as_path(),
        )],
    )?;
    expect_checker_failure(output, "matrix_count_drift");
    Ok(())
}

#[test]
fn checker_rejects_classification_log_drift() -> TestResult {
    let root = workspace_root()?;
    let seed_out_dir = unique_output_dir(&root, "seed-log")?;
    expect_checker_success(&root, &seed_out_dir)?;

    let out_dir = unique_output_dir(&root, "log-drift")?;
    let log_path = out_dir.join("runtime_math_classification_matrix.drift.jsonl");
    let content = std::fs::read_to_string(root.join(CLASSIFICATION_LOG_REL))?;
    let mut lines = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if !lines.is_empty() {
        lines.remove(0);
    }
    std::fs::write(&log_path, lines.join("\n") + "\n")?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_CLASSIFICATION_LOG",
            log_path.as_path(),
        )],
    )?;
    expect_checker_failure(output, "classification_log_drift");
    Ok(())
}
