use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_harness::fault_injection::{
    FaultDomain, FaultManifest, FaultRunConfig, run_manifest_with_default_executor,
};
use frankenlibc_harness::structured_log::{ArtifactIndex, validate_log_file};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(format!("frankenlibc-{label}-{suffix}"));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn canonical_fault_catalog_covers_requested_domains() {
    let manifest_path = repo_root().join("tests/conformance/fault_injection_scenarios.v1.yaml");
    let manifest = FaultManifest::from_path(&manifest_path).expect("fault manifest");

    assert_eq!(manifest.schema_version, "v1");
    assert_eq!(manifest.manifest_id, "bd-3fil-franken-fault-catalog");
    assert!(manifest.scenario("memory.oom_budget").is_some());
    assert!(manifest.scenario("time.virtual_drift").is_some());
    assert!(
        manifest
            .scenario("concurrency.cancellation_window")
            .is_some()
    );

    let mut domains = manifest.scenarios.iter().map(|scenario| scenario.domain);
    assert!(domains.any(|domain| domain == FaultDomain::Memory));
    assert!(
        manifest
            .scenarios
            .iter()
            .any(|scenario| scenario.domain == FaultDomain::Time)
    );
    assert!(
        manifest
            .scenarios
            .iter()
            .any(|scenario| scenario.domain == FaultDomain::Concurrency)
    );
}

#[test]
fn default_runner_writes_valid_artifacts_for_full_catalog() {
    let root = repo_root();
    let manifest_path = root.join("tests/conformance/fault_injection_scenarios.v1.yaml");
    let manifest = FaultManifest::from_path(&manifest_path).expect("fault manifest");
    let tmp = unique_temp_dir("fault-framework");

    let mut config = FaultRunConfig::new(tmp.clone());
    config.report_path = tmp.join("fault_report.json");
    config.log_path = tmp.join("fault_log.jsonl");
    config.artifact_index_path = tmp.join("fault_artifacts.json");
    config.run_id = "fault-framework-test".to_string();
    config.manifest_ref = Some(manifest_path.to_string_lossy().into_owned());

    let report = run_manifest_with_default_executor(
        &manifest,
        None,
        &["strict".to_string(), "hardened".to_string()],
        &config,
    )
    .expect("fault injection run");

    assert_eq!(report.summary.failed, 0, "report: {report:#?}");
    assert_eq!(report.summary.false_negatives, 0, "report: {report:#?}");
    assert!(report.summary.total_cases >= 30, "report: {report:#?}");
    assert!(config.report_path.exists());
    assert!(config.log_path.exists());
    assert!(config.artifact_index_path.exists());

    let (line_count, errors) = validate_log_file(&config.log_path).expect("validate log");
    assert_eq!(line_count, report.summary.total_cases);
    assert!(errors.is_empty(), "log validation errors: {errors:?}");

    let artifact_index: ArtifactIndex =
        serde_json::from_str(&fs::read_to_string(&config.artifact_index_path).unwrap())
            .expect("artifact index json");
    assert_eq!(artifact_index.run_id, "fault-framework-test");
    assert!(
        artifact_index
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "log")
    );
    assert!(
        artifact_index
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "report")
    );

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn harness_cli_runs_single_fault_scenario() {
    let root = repo_root();
    let manifest_path = root.join("tests/conformance/fault_injection_scenarios.v1.yaml");
    let tmp = unique_temp_dir("fault-cli");
    let report_path = tmp.join("report.json");
    let log_path = tmp.join("log.jsonl");
    let artifact_index_path = tmp.join("artifacts.json");

    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .current_dir(&root)
        .args([
            "fault-inject",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--scenario",
            "memory.use_after_free",
            "--report",
            report_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            "--artifact-index",
            artifact_index_path.to_str().unwrap(),
            "--mode",
            "both",
            "--fail-on-mismatch",
        ])
        .output()
        .expect("fault-inject cli");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report_path).unwrap()).expect("report json");
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(report["summary"]["scenario_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["total_cases"].as_u64(), Some(6));

    let artifact_index: ArtifactIndex =
        serde_json::from_str(&fs::read_to_string(&artifact_index_path).unwrap())
            .expect("artifact index json");
    let log_join_keys = artifact_index
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "log")
        .and_then(|artifact| artifact.join_keys.as_ref())
        .expect("log artifact join keys");
    assert_eq!(log_join_keys.trace_ids.len(), 6);
    assert!(
        artifact_index
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "manifest")
    );

    fs::remove_dir_all(&tmp).ok();
}
