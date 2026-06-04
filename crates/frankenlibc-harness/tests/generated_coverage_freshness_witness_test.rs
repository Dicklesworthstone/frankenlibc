//! Freshness witness tests for bd-j1u6u.3 generated conformance coverage artifacts.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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

fn witness_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/generated_coverage_freshness_witness.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_generated_coverage_freshness_witness.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("generated_coverage_freshness_witness.report.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
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

fn run_checker(root: &Path, witness: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_GENERATED_COVERAGE_FRESHNESS_WITNESS", witness)
        .env("FRANKENLIBC_GENERATED_COVERAGE_FRESHNESS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_GENERATED_COVERAGE_FRESHNESS_REPORT",
            report_path(out_dir),
        )
        .output()?)
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

#[test]
fn witness_binds_generated_coverage_state() -> TestResult {
    let root = workspace_root()?;
    let witness = load_json(&witness_path(&root))?;
    assert_eq!(
        string_field(&witness, "schema_version", "witness")?,
        "generated_coverage_freshness_witness.v1"
    );
    assert_eq!(string_field(&witness, "bead_id", "witness")?, "bd-j1u6u.3");

    let source_ids: BTreeSet<_> = array_field(&witness, "source_files", "witness")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "symbol_fixture_coverage",
        "per_symbol_fixture_tests",
        "fixture_coverage_prioritizer",
        "executor_dispatch",
    ] {
        assert!(
            source_ids.contains(required),
            "missing source id {required}"
        );
    }

    let corpus = field(&witness, "fixture_corpus", "witness")?;
    assert_eq!(
        field(corpus, "json_file_count", "fixture_corpus")?.as_u64(),
        Some(127)
    );
    assert_eq!(
        field(corpus, "total_case_count", "fixture_corpus")?.as_u64(),
        Some(2787)
    );
    assert_eq!(
        field(corpus, "unique_function_count", "fixture_corpus")?.as_u64(),
        Some(1181)
    );

    let symbols = field(&witness, "symbol_counts", "witness")?;
    assert_eq!(
        field(symbols, "target_covered_symbols", "symbol_counts")?.as_u64(),
        Some(848)
    );
    assert_eq!(
        field(symbols, "target_uncovered_symbols", "symbol_counts")?.as_u64(),
        Some(1949)
    );
    Ok(())
}

#[test]
fn checker_accepts_generated_coverage_freshness_witness() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "generated-coverage-freshness-check")?;
    let output = run_checker(&root, &witness_path(&root), &out_dir)?;
    expect_checker_success(&output)?;
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS generated coverage freshness witness")
    );
    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "generated_coverage_freshness_witness.report.v1"
    );
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_source_hash() -> TestResult {
    let root = workspace_root()?;
    let mut witness = load_json(&witness_path(&root))?;
    let first_source = witness
        .get_mut("source_files")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("source_files[0] should be an object"))?;
    first_source.insert("sha256".to_owned(), Value::String("0".repeat(64)));

    let out_dir = unique_output_dir(&root, "generated-coverage-freshness-stale-hash")?;
    let bad_witness = out_dir.join("bad_stale_hash.json");
    write_json(&bad_witness, &witness)?;
    let output = run_checker(&root, &bad_witness, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("source_hash_drift"));
    Ok(())
}

#[test]
fn checker_rejects_fixture_case_count_drift() -> TestResult {
    let root = workspace_root()?;
    let mut witness = load_json(&witness_path(&root))?;
    let corpus = witness
        .get_mut("fixture_corpus")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("fixture_corpus should be an object"))?;
    corpus.insert("total_case_count".to_owned(), Value::from(2701));

    let out_dir = unique_output_dir(&root, "generated-coverage-freshness-case-drift")?;
    let bad_witness = out_dir.join("bad_case_drift.json");
    write_json(&bad_witness, &witness)?;
    let output = run_checker(&root, &bad_witness, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("fixture_corpus_drift"));
    Ok(())
}

#[test]
fn checker_rejects_missing_generator_command() -> TestResult {
    let root = workspace_root()?;
    let mut witness = load_json(&witness_path(&root))?;
    let commands = witness
        .get_mut("generator_command_lines")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("generator_command_lines should be an array"))?;
    commands.pop();

    let out_dir = unique_output_dir(&root, "generated-coverage-freshness-missing-command")?;
    let bad_witness = out_dir.join("bad_missing_command.json");
    write_json(&bad_witness, &witness)?;
    let output = run_checker(&root, &bad_witness, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&report_path(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_generator_command"));
    Ok(())
}
