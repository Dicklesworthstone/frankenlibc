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
    root.join("tests/conformance/sos_thread_safety_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_sos_thread_safety_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "sos-thread-safety-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_SOS_THREAD_SAFETY_CONTRACT", manifest)
        .env("FRANKENLIBC_SOS_THREAD_SAFETY_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_SOS_THREAD_SAFETY_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_SOS_THREAD_SAFETY_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
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

fn parse_task_field<'a>(task: &'a str, key: &str) -> TestResult<&'a str> {
    task.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find_map(|(field, value)| (field.trim() == key).then_some(value.trim()))
        .ok_or_else(|| test_error(format!("task missing {key}")))
}

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line)?;
            value["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect()
}

#[test]
fn contract_anchors_sos_thread_safety_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("sos-thread-safety-completion-contract")
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
        evidence["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );
    Ok(())
}

#[test]
fn certificate_task_contract_matches_checked_in_sos_artifact() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let certificate = object_field(&manifest, "certificate_artifact")?;
    let task_path = certificate["path"]
        .as_str()
        .ok_or_else(|| test_error("certificate path missing"))?;
    let task = fs::read_to_string(root.join(task_path))?;

    assert_eq!(parse_task_field(&task, "solver_family")?, "mosek");
    assert_eq!(parse_task_field(&task, "certificate")?, "thread_safety");
    assert_eq!(
        parse_task_field(&task, "dimension")?.parse::<u64>()?,
        certificate["expected_dimension"]
            .as_u64()
            .ok_or_else(|| test_error("expected_dimension missing"))?
    );
    assert_eq!(
        parse_task_field(&task, "monomial_degree")?.parse::<u64>()?,
        certificate["expected_monomial_degree"]
            .as_u64()
            .ok_or_else(|| test_error("expected_monomial_degree missing"))?
    );
    assert_eq!(
        parse_task_field(&task, "barrier_budget_milli")?.parse::<u64>()?,
        certificate["expected_barrier_budget_milli"]
            .as_u64()
            .ok_or_else(|| test_error("expected_barrier_budget_milli missing"))?
    );
    assert_eq!(
        string_set(&certificate["required_variables"])?.len(),
        certificate["expected_dimension"]
            .as_u64()
            .ok_or_else(|| test_error("expected_dimension missing"))? as usize
    );
    Ok(())
}

#[test]
fn source_artifacts_bind_runtime_certificate_and_concurrent_allocator_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    assert_eq!(artifacts.len(), 4);

    let artifact_ids = artifacts
        .iter()
        .map(|artifact| {
            artifact["artifact_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("artifact_id should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        artifact_ids,
        BTreeSet::from([
            "allocator_concurrency_evidence".to_string(),
            "sos_arch_independence".to_string(),
            "sos_barrier_runtime".to_string(),
            "sos_build_pipeline".to_string(),
        ])
    );

    for artifact in artifacts {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| test_error("artifact path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in artifact["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required_needles should be array"))?
        {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                text.contains(needle),
                "{path} should contain required needle {needle}"
            );
        }
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sos_thread_safety_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(4));
    assert_eq!(report["matrix_dimension"].as_u64(), Some(5));
    assert_eq!(report["barrier_budget_milli"].as_u64(), Some(900_000));
    assert_eq!(report["certificate"].as_str(), Some("thread_safety"));

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "sos_thread_safety_certificate_source",
        "sos_thread_safety_certificate_task",
        "sos_thread_safety_runtime_binding",
        "sos_thread_safety_completion_summary",
    ] {
        assert!(events.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_certificate_dimension() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-dimension")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["certificate_artifact"]
        .as_object_mut()
        .ok_or_else(|| test_error("certificate_artifact should be object"))?
        .remove("expected_dimension");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing certificate dimension"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("expected_dimension missing"));
    Ok(())
}

#[test]
fn checker_rejects_non_symmetric_gram_matrix() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "nonsymmetric")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let task_path = manifest["certificate_artifact"]["path"]
        .as_str()
        .ok_or_else(|| test_error("certificate path missing"))?;
    let altered_task = fs::read_to_string(root.join(task_path))?.replacen(
        "40,1200,900,80,80",
        "41,1200,900,80,80",
        1,
    );
    let altered_task_path = out_dir.join("thread_safety_certificate_nonsymmetric.task");
    fs::write(&altered_task_path, altered_task)?;
    manifest["certificate_artifact"]["path"] = json!(
        altered_task_path
            .strip_prefix(&root)
            .unwrap_or(&altered_task_path)
            .to_string_lossy()
            .to_string()
    );
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted non-symmetric Gram matrix"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("not symmetric"));
    Ok(())
}

#[test]
fn checker_rejects_missing_runtime_source_needle() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-source-needle")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_artifacts"][1]["required_needles"] =
        json!(["nonexistent_thread_safety_sos_runtime_marker"]);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted stale source-artifact needle"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonexistent_thread_safety_sos_runtime_marker"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_item() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
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
