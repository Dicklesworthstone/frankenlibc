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
    root.join("tests/conformance/stub_census_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_stub_census_completion_contract.sh")
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
        .env("FRANKENLIBC_STUB_CENSUS_CONTRACT", manifest)
        .env("FRANKENLIBC_STUB_CENSUS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STUB_CENSUS_REPORT",
            out_dir.join("report.json"),
        )
        .env("FRANKENLIBC_STUB_CENSUS_LOG", out_dir.join("events.jsonl"))
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
        Some("stub-census-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2vb"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-2vb.1"));

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert_eq!(manifest["next_audit_score_threshold"].as_u64(), Some(900));
    Ok(())
}

#[test]
fn source_artifacts_cover_census_guard_and_debt_artifacts() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        artifact_ids(&manifest)?,
        BTreeSet::from([
            "stub_census_artifact".to_string(),
            "stub_census_script".to_string(),
            "stub_guard_script".to_string(),
            "stub_guard_test".to_string(),
            "stub_todo_debt_census".to_string(),
            "stub_todo_generator".to_string(),
        ])
    );

    let expectations = object_field(&manifest, "inventory_expectations")?;
    assert_eq!(expectations["reachable_stubs"].as_u64(), Some(0));
    assert_eq!(
        expectations["exported_non_implemented_count"].as_u64(),
        Some(0)
    );
    assert_eq!(expectations["priority_item_count"].as_u64(), Some(0));
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stub-census")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stub_census_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(6));
    assert_eq!(report["missing_item_count"].as_u64(), Some(3));

    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    for event in [
        "stub_census_source",
        "stub_census_inventory",
        "stub_census_tests",
        "stub_census_e2e",
        "stub_census_telemetry",
        "stub_census_summary",
    ] {
        assert!(log.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_guard_test() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stub-census-missing-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_names"][0] =
        json!("nonexistent_stub_guard_test_marker");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing test"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonexistent_stub_guard_test_marker"));
    Ok(())
}

#[test]
fn checker_rejects_nonzero_reachable_stub_expectation() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stub-census-reachable-stub")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["inventory_expectations"]["reachable_stubs"] = json!(1);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted wrong reachable stub expectation"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stub_census.summary.reachable_stubs"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stub-census-missing-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"] =
        json!(["stub_census_source"]);
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
