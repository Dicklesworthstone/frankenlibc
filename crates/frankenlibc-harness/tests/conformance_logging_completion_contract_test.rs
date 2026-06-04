use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
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
    root.join("tests/conformance/conformance_logging_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_conformance_logging_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn object_field<'a>(
    value: &'a Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("{field} must be an object")))
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
    let dir = root
        .join("target/conformance")
        .join(format!("{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_CONFORMANCE_LOGGING_CONTRACT", manifest)
        .env("FRANKENLIBC_CONFORMANCE_LOGGING_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CONFORMANCE_LOGGING_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_CONFORMANCE_LOGGING_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

#[test]
fn contract_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("conformance-logging-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2hh.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2hh.7.1")
    );

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert!(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );
    Ok(())
}

#[test]
fn logging_expectations_bind_shadow_and_structured_log_artifacts() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let logging = object_field(&manifest, "logging_expectations")?;
    assert!(string_set(&logging["required_shadow_report_fields"])?.contains("artifact_refs"));
    assert!(
        string_set(&logging["required_shadow_artifacts"])?
            .contains("shadow_divergence_report.json")
    );
    assert!(
        string_set(&logging["required_shadow_log_events"])?
            .contains("conformance.shadow_run_divergence")
    );
    assert!(string_set(&logging["required_structured_log_fields"])?.contains("trace_id"));
    assert!(string_set(&logging["required_stream_kinds"])?.contains("Conformance"));
    Ok(())
}

#[test]
fn conformance_expectations_cover_fixtures_and_benchmarks() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let expectations = object_field(&manifest, "conformance_expectations")?;
    let fixture_path = expectations["fixture_pipeline"]["path"]
        .as_str()
        .ok_or_else(|| test_error("fixture path missing"))?;
    let fixture_json = load_json(&root.join(fixture_path))?;
    assert!(
        fixture_json["summary"]["total_fixture_cases"]
            .as_u64()
            .is_some_and(|count| count >= 1000)
    );

    let perf_path = expectations["perf_results"]["path"]
        .as_str()
        .ok_or_else(|| test_error("perf path missing"))?;
    let perf_json = load_json(&root.join(perf_path))?;
    assert!(
        perf_json["packages"]
            .as_array()
            .is_some_and(|packages| !packages.is_empty())
    );

    let benchmark_completion = load_json(
        &root.join("tests/conformance/benchmark_coverage_inventory_completion_contract.v1.json"),
    )?;
    let canonical_inventory_rows =
        benchmark_completion["inventory_expectations"]["inventory_row_count"]
            .as_u64()
            .ok_or_else(|| test_error("canonical inventory_row_count missing"))?;
    assert_eq!(
        expectations["benchmark_inventory"]["minimum_inventory_rows"].as_u64(),
        Some(canonical_inventory_rows)
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "conformance-logging")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("conformance_logging_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(6));

    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    for event in [
        "conformance_logging_source",
        "conformance_logging_shadow",
        "conformance_logging_fixture",
        "conformance_logging_benchmark",
        "conformance_logging_summary",
    ] {
        assert!(log.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_shadow_test() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "conformance-missing-shadow-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_artifacts"][1]["required_needles"] =
        json!(["nonexistent_shadow_run_test_marker"]);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted incomplete shadow test source needles"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonexistent_shadow_run_test_marker"));
    Ok(())
}

#[test]
fn checker_rejects_missing_perf_latency_field() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "conformance-missing-latency")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let latency_fields =
        manifest["conformance_expectations"]["perf_results"]["required_latency_fields"]
            .as_array_mut()
            .ok_or_else(|| test_error("required_latency_fields should be array"))?;
    latency_fields.push(json!("nonexistent_latency_field"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing perf latency field"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonexistent_latency_field"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_item() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "conformance-missing-telemetry")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let missing = manifest["completion_debt_evidence"]["missing_items_closed"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_items_closed should be array"))?;
    missing.retain(|item| item.as_str() != Some("telemetry.primary"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing telemetry closure"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing_items_closed must be"));
    Ok(())
}
