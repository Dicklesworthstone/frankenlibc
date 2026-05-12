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
    root.join("tests/conformance/concurrency_signal_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_concurrency_signal_completion_contract.sh")
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
        .env("FRANKENLIBC_CONCURRENCY_SIGNAL_CONTRACT", manifest)
        .env("FRANKENLIBC_CONCURRENCY_SIGNAL_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CONCURRENCY_SIGNAL_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_CONCURRENCY_SIGNAL_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn artifact_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?
        .iter()
        .map(|entry| {
            entry["artifact_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("source artifact missing artifact_id"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

#[test]
fn contract_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("concurrency-signal-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2tq.6"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2tq.6.1")
    );

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.fuzz.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert_eq!(manifest["next_audit_score_threshold"].as_u64(), Some(900));
    Ok(())
}

#[test]
fn source_artifacts_cover_signal_pthread_fuzz_and_telemetry() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        artifact_ids(&manifest)?,
        BTreeSet::from([
            "fuzz_gap_contract".to_string(),
            "pthread_abi_test".to_string(),
            "pthread_fixture_pack".to_string(),
            "pthread_native_script".to_string(),
            "signal_abi_test".to_string(),
            "signal_diff_test".to_string(),
            "signal_fixture_pack".to_string(),
            "signal_native_script".to_string(),
        ])
    );

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    let fuzz = evidence
        .get("fuzz_primary")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("fuzz_primary must be an object"))?;
    assert_eq!(
        string_set(&fuzz["required_modules"])?,
        BTreeSet::from(["pthread".to_string(), "signal".to_string()])
    );
    assert!(
        string_set(&fuzz["required_targets"])?.contains("fuzz_pthread_sync_misc"),
        "pthread sync fuzz target should be bound"
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "concurrency-signal")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("concurrency_signal_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(8));
    assert_eq!(report["missing_item_count"].as_u64(), Some(5));

    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    for event in [
        "concurrency_signal_source",
        "concurrency_signal_tests",
        "concurrency_signal_e2e",
        "concurrency_signal_fuzz",
        "concurrency_signal_conformance",
        "concurrency_signal_telemetry",
        "concurrency_signal_summary",
    ] {
        assert!(log.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_signal_test() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "concurrency-signal-missing-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["test_groups"][0]["test_names"][0] =
        json!("nonexistent_signal_contract_test_marker");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing signal test"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonexistent_signal_contract_test_marker"));
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_module() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "concurrency-signal-missing-fuzz")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["fuzz_primary"]["required_modules"] =
        json!(["signal", "missing_pthread_module"]);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing fuzz module"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fuzz_primary missing module missing_pthread_module"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "concurrency-signal-missing-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"] =
        json!(["concurrency_signal_source"]);
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
