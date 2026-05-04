//! Integration tests for string/malloc perf baseline fill gate (bd-b92jd.2.1).

use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "benchmark_id",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "threshold_ns_op",
    "regression_pct",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "failure_signature",
];

const REQUIRED_STRING_BENCHMARKS: &[&str] = &[
    "memcpy_16",
    "memcpy_64",
    "memcpy_256",
    "memcpy_1024",
    "memcpy_4096",
    "memcpy_65536",
    "strlen_16",
    "strlen_256",
];

const REQUIRED_MALLOC_BENCHMARKS: &[&str] = &["alloc_free_cycle", "alloc_burst"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/string_malloc_perf_baseline_fill.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_string_malloc_perf_baseline_fill.sh")
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn object_mut<'a>(
    value: &'a mut Value,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))
}

fn mutable_rows(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("baseline_rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.baseline_rows must be mutable array"))
}

fn mutable_row(manifest: &mut Value, index: usize) -> TestResult<&mut Value> {
    mutable_rows(manifest)?
        .get_mut(index)
        .ok_or_else(|| test_error(format!("manifest.baseline_rows[{index}] must exist")))
}

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FLC_STRING_MALLOC_PERF_OUT_DIR", out_dir)
        .env(
            "FLC_STRING_MALLOC_PERF_REPORT",
            out_dir.join("string-malloc-perf.report.json"),
        )
        .env(
            "FLC_STRING_MALLOC_PERF_LOG",
            out_dir.join("string-malloc-perf.log.jsonl"),
        )
        .env("FLC_STRING_MALLOC_PERF_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_STRING_MALLOC_PERF_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run string/malloc perf gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("string-malloc-perf.report.json");
    write_json(&manifest_fixture, manifest)?;
    let output = run_gate(root, Some(&manifest_fixture), &out_dir)?;
    ensure(
        !output.status.success(),
        format!(
            "{case_name}: gate should fail\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    load_json(&report_path)
}

fn assert_failure(report: &Value, expected: &str) -> TestResult {
    let errors = array_field(report, "errors", "report")?;
    ensure(!errors.is_empty(), "negative report should include errors")?;
    ensure(
        errors.iter().any(|row| {
            row.get("failure_signature")
                .and_then(Value::as_str)
                .is_some_and(|value| value == expected)
        }),
        format!("expected failure_signature {expected}, got {errors:?}"),
    )
}

#[test]
fn manifest_names_all_required_string_and_malloc_baseline_slots() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    ensure(
        manifest["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    ensure(
        manifest["bead_id"].as_str() == Some("bd-b92jd.2.1"),
        "bead_id must be bd-b92jd.2.1",
    )?;

    let rows = array_field(&manifest, "baseline_rows", "manifest")?;
    ensure(rows.len() == 20, "baseline_rows must contain 20 rows")?;
    let mut seen = HashSet::new();
    for row in rows {
        let family = row["api_family"]
            .as_str()
            .ok_or_else(|| test_error("baseline row api_family must be string"))?;
        let mode = row["runtime_mode"]
            .as_str()
            .ok_or_else(|| test_error("baseline row runtime_mode must be string"))?;
        let bench = row["benchmark_id"]
            .as_str()
            .ok_or_else(|| test_error("baseline row benchmark_id must be string"))?;
        ensure(
            ["strict", "hardened"].contains(&mode),
            format!("invalid mode {mode}"),
        )?;
        ensure(
            match family {
                "string" => REQUIRED_STRING_BENCHMARKS.contains(&bench),
                "malloc" => REQUIRED_MALLOC_BENCHMARKS.contains(&bench),
                _ => false,
            },
            format!("unexpected row {family}/{mode}/{bench}"),
        )?;
        ensure(
            seen.insert((family.to_owned(), mode.to_owned(), bench.to_owned())),
            format!("duplicate row {family}/{mode}/{bench}"),
        )?;
        ensure(row["latency_ns"].as_f64().is_some(), "latency_ns missing")?;
        ensure(
            row["threshold_ns_op"].as_f64().is_some(),
            "threshold_ns_op missing",
        )?;
        ensure(
            row["regression_pct"].as_f64() == Some(0.0),
            "regression_pct must be 0.0",
        )?;
        ensure(
            row["artifact_refs"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "artifact_refs must be non-empty",
        )?;
    }

    for mode in ["strict", "hardened"] {
        for bench in REQUIRED_STRING_BENCHMARKS {
            ensure(
                seen.contains(&("string".to_owned(), mode.to_owned(), (*bench).to_owned())),
                format!("missing string/{mode}/{bench}"),
            )?;
        }
        for bench in REQUIRED_MALLOC_BENCHMARKS {
            ensure(
                seen.contains(&("malloc".to_owned(), mode.to_owned(), (*bench).to_owned())),
                format!("missing malloc/{mode}/{bench}"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn gate_emits_structured_report_and_jsonl_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("string-malloc-perf-pass")?;
    let report_path = out_dir.join("string-malloc-perf.report.json");
    let log_path = out_dir.join("string-malloc-perf.log.jsonl");
    let output = run_gate(&root, None, &out_dir)?;
    ensure(
        output.status.success(),
        format!(
            "gate should pass\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&report_path)?;
    ensure(
        report["summary"]["baseline_row_count"].as_u64() == Some(20),
        "report baseline_row_count must be 20",
    )?;
    ensure(
        report["summary"]["error_count"].as_u64() == Some(0),
        "report error_count must be 0",
    )?;

    let log_content = std::fs::read_to_string(&log_path)?;
    let mut log_rows = 0usize;
    for raw in log_content.lines().filter(|line| !line.trim().is_empty()) {
        let row: Value = serde_json::from_str(raw)
            .map_err(|err| test_error(format!("log row must parse as JSON: {err}")))?;
        log_rows += 1;
        for field in REQUIRED_LOG_FIELDS {
            ensure(
                row.get(*field).is_some(),
                format!("log row missing {field}"),
            )?;
        }
        ensure(
            row["bead_id"].as_str() == Some("bd-b92jd.2.1"),
            "log row bead_id mismatch",
        )?;
        ensure(
            row["failure_signature"].as_str() == Some("none"),
            "passing log rows should have failure_signature=none",
        )?;
    }
    ensure(
        log_rows == 20,
        format!("expected 20 log rows, got {log_rows}"),
    )
}

#[test]
fn negative_cases_fail_closed_with_stable_signatures() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;

    let mut missing_commit = manifest.clone();
    object_mut(mutable_row(&mut missing_commit, 0)?, "row")?.remove("source_commit");
    let report = run_negative_case(&root, "string-malloc-missing-commit", &missing_commit)?;
    assert_failure(&report, "missing_source_commit")?;

    let mut missing_artifacts = manifest.clone();
    object_mut(mutable_row(&mut missing_artifacts, 1)?, "row")?
        .insert("artifact_refs".to_owned(), Value::Array(Vec::new()));
    let report = run_negative_case(&root, "string-malloc-missing-artifacts", &missing_artifacts)?;
    assert_failure(&report, "missing_artifact_refs")?;

    let mut missing_row = manifest.clone();
    mutable_rows(&mut missing_row)?.pop();
    let report = run_negative_case(&root, "string-malloc-missing-row", &missing_row)?;
    assert_failure(&report, "missing_required_slot")?;

    let mut wrong_latency = manifest.clone();
    object_mut(mutable_row(&mut wrong_latency, 2)?, "row")?
        .insert("latency_ns".to_owned(), Value::from(99999.0));
    let report = run_negative_case(&root, "string-malloc-wrong-latency", &wrong_latency)?;
    assert_failure(&report, "baseline_value_mismatch")?;

    let mut bad_sample = manifest;
    let samples = bad_sample
        .get_mut("benchmark_log_samples")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("benchmark_log_samples must be mutable array"))?;
    object_mut(
        samples
            .get_mut(0)
            .ok_or_else(|| test_error("benchmark_log_samples[0] must exist"))?,
        "sample",
    )?
    .insert("line".to_owned(), Value::from("not a benchmark row"));
    let report = run_negative_case(&root, "string-malloc-bad-sample", &bad_sample)?;
    assert_failure(&report, "benchmark_log_parse_error")
}
