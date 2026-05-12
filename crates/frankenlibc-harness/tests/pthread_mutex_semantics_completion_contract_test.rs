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
    root.join("tests/conformance/pthread_mutex_semantics_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_pthread_mutex_semantics_completion_contract.sh")
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
        "pthread-mutex-semantics-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_CONTRACT", manifest)
        .env("FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn checker_output(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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
fn contract_anchors_bd327_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("pthread_mutex_semantics_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-327"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-327.1"));

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-327"));
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "telemetry.primary".to_string(),
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
fn source_artifacts_bind_mutex_semantics_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;

    let ids = artifacts
        .iter()
        .map(|artifact| {
            artifact["id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("artifact id should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        ids,
        BTreeSet::from([
            "core_mutex".to_string(),
            "abi_pthread_mutex".to_string(),
            "abi_pthread_mutex_core_test".to_string(),
            "conformance_fixture".to_string(),
            "conformance_harness".to_string(),
            "existing_state_invariants_contract".to_string(),
            "completion_checker".to_string(),
            "completion_harness".to_string(),
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
fn conformance_matrix_covers_posix_mutex_operations_and_aliases() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let conformance = &manifest["conformance_primary"];
    assert_eq!(
        string_set(&conformance["required_fixture_cases"])?,
        BTreeSet::from([
            "mutex_init_default".to_string(),
            "mutex_lock_unlock".to_string(),
            "mutex_trylock_unlocked".to_string(),
            "mutex_trylock_locked_ebusy".to_string(),
            "mutex_unlock".to_string(),
            "alias_mutex_trylock_unlocked".to_string(),
            "alias_mutex_unlock".to_string(),
            "mutex_destroy".to_string(),
            "mutex_init_null_attr_default_type".to_string(),
            "mutex_contention_two_threads".to_string(),
        ])
    );
    assert!(
        string_set(&conformance["required_harness_tests"])?
            .contains("pthread_mutex_fixture_executes_via_isolated_harness")
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", checker_output(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pthread_mutex_semantics_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-327.1"));
    assert_eq!(report["source_count"].as_u64(), Some(8));
    assert_eq!(report["unit_test_ref_count"].as_u64(), Some(12));
    assert_eq!(report["fixture_case_count"].as_u64(), Some(10));
    assert_eq!(report["conformance_test_ref_count"].as_u64(), Some(13));

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "pthread_mutex_semantics.source_artifact",
        "pthread_mutex_semantics.unit_binding",
        "pthread_mutex_semantics.conformance_case",
        "pthread_mutex_semantics.telemetry_contract",
        "pthread_mutex_semantics.completion_contract_validated",
    ] {
        assert!(events.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_ref() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit-ref")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_test_refs"][0]["name"] =
        json!("missing_mutex_semantics_unit_test");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing unit ref"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unit refs must be") || stderr.contains("is not present"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_fixture_case() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-fixture-case")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["conformance_primary"]["required_fixture_cases"]
        .as_array_mut()
        .ok_or_else(|| test_error("fixture cases should be array"))?
        .retain(|case| case.as_str() != Some("mutex_contention_two_threads"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing fixture case"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fixture cases must be"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["telemetry_primary"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required events should be array"))?
        .retain(|event| event.as_str() != Some("pthread_mutex_semantics.unit_binding"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("telemetry events must be"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}
