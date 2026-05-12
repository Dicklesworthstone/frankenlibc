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
    root.join("tests/conformance/thread_safety_sos_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_thread_safety_sos_completion_contract.sh")
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
        .env("FRANKENLIBC_THREAD_SAFETY_SOS_CONTRACT", manifest)
        .env("FRANKENLIBC_THREAD_SAFETY_SOS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_THREAD_SAFETY_SOS_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_THREAD_SAFETY_SOS_LOG",
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
        Some("thread-safety-sos-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2ste.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2ste.2.1")
    );

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert!(
        manifest["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );
    Ok(())
}

#[test]
fn manifest_binds_certificate_artifact_and_runtime_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let expectations = object_field(&manifest, "certificate_expectations")?;
    assert_eq!(expectations["certificate"].as_str(), Some("thread_safety"));
    assert_eq!(expectations["dimension"].as_u64(), Some(5));
    assert_eq!(expectations["barrier_budget_milli"].as_u64(), Some(900_000));

    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    let ids = artifacts
        .iter()
        .filter_map(|entry| entry["artifact_id"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids,
        BTreeSet::from([
            "arch_independence_tests",
            "runtime_sos_barrier",
            "sos_build_generator",
            "thread_safety_task",
        ])
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "thread-safety-sos")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("thread_safety_sos_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(4));

    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    for event in [
        "thread_safety_sos_source",
        "thread_safety_sos_certificate",
        "thread_safety_sos_tests",
        "thread_safety_sos_summary",
    ] {
        assert!(log.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_thread_safety_unit_test() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "thread-safety-missing-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_names"][0] =
        json!("nonexistent_thread_safety_test_marker");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing unit test"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonexistent_thread_safety_test_marker"));
    Ok(())
}

#[test]
fn checker_rejects_bad_certificate_dimension() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "thread-safety-bad-dimension")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["certificate_expectations"]["dimension"] = json!(4);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted wrong certificate dimension"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("certificate dimension mismatch"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "thread-safety-missing-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"] =
        json!(["thread_safety_sos_source"]);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted incomplete telemetry event list"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("telemetry_primary.required_events"));
    Ok(())
}
