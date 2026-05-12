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
    root.join("tests/conformance/proof_logging_integrity_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_proof_logging_integrity_completion_contract.sh")
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
        "proof-logging-integrity-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_PROOF_LOGGING_CONTRACT", manifest)
        .env("FRANKENLIBC_PROOF_LOGGING_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_PROOF_LOGGING_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_PROOF_LOGGING_LOG",
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
fn contract_anchors_bd34s7_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("proof_logging_integrity_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-34s.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-34s.7.1")
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-34s.7"));
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
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
fn source_artifacts_bind_proof_logging_surfaces() -> TestResult {
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
            "evidence_compliance_module".to_string(),
            "evidence_compliance_tests".to_string(),
            "harness_cli".to_string(),
            "proof_binder_gate".to_string(),
            "proof_chain_gate".to_string(),
            "proof_chain_e2e_tests".to_string(),
            "evidence_compliance_completion_contract".to_string(),
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
fn telemetry_contract_requires_proof_and_completion_events() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let telemetry = &manifest["telemetry_primary"];
    let proof_events = string_set(&telemetry["required_proof_events"])?;
    for event in [
        "evidence_compliance.proof_start",
        "evidence_compliance.artifact_hash_mismatch",
        "evidence_compliance.proof_failure",
        "proof_chain.proof_binder",
        "proof_chain.cross_report_consistency",
        "proof_chain.summary",
    ] {
        assert!(proof_events.contains(event), "missing proof event {event}");
    }
    let completion_events = string_set(&telemetry["required_completion_events"])?;
    assert!(completion_events.contains("proof_logging_integrity.completion_contract_validated"));
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", checker_output(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("proof_logging_integrity_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-34s.7.1"));
    assert_eq!(report["source_count"].as_u64(), Some(9));
    assert_eq!(report["unit_test_ref_count"].as_u64(), Some(5));
    assert_eq!(report["e2e_test_ref_count"].as_u64(), Some(3));
    assert_eq!(report["proof_event_count"].as_u64(), Some(13));

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "proof_logging_integrity.source_artifact",
        "proof_logging_integrity.unit_binding",
        "proof_logging_integrity.e2e_binding",
        "proof_logging_integrity.telemetry_contract",
        "proof_logging_integrity.completion_contract_validated",
    ] {
        assert!(events.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_ref() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit-ref")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_test_refs"][0]["name"] =
        json!("missing_proof_logging_unit_test");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bad unit ref"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unit_primary.required_test_refs"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_proof_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-proof-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["telemetry_primary"]["required_proof_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("proof events should be array"))?
        .retain(|event| event.as_str() != Some("evidence_compliance.artifact_hash_mismatch"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing proof event"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("proof events must be"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_gate_script() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-gate")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["e2e_primary"]["required_gate_scripts"]
        .as_array_mut()
        .ok_or_else(|| test_error("gate scripts should be array"))?
        .retain(|script| script.as_str() != Some("scripts/check_proof_chain_e2e.sh"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing gate"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("gate scripts mismatch"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}
