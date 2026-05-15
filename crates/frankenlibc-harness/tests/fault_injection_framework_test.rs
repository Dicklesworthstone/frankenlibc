use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{error::Error, fmt};

use frankenlibc_harness::fault_injection::{
    FaultDomain, FaultManifest, FaultRunConfig, run_manifest_with_default_executor,
};
use frankenlibc_harness::structured_log::{ArtifactIndex, validate_log_file};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct TestFailure(String);

impl fmt::Display for TestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TestFailure {}

fn test_failure(message: impl Into<String>) -> TestFailure {
    TestFailure(message.into())
}

fn repo_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir
        .parent()
        .ok_or_else(|| test_failure("manifest dir must have a crate parent"))?;
    let repo_root = crate_dir
        .parent()
        .ok_or_else(|| test_failure("crate dir must have a repo parent"))?;
    Ok(repo_root.to_path_buf())
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| test_failure(format!("system clock before unix epoch: {err}")))?
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(format!("frankenlibc-{label}-{suffix}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn canonical_fault_catalog_covers_requested_domains() -> TestResult {
    let manifest_path = repo_root()?.join("tests/conformance/fault_injection_scenarios.v1.yaml");
    let manifest = FaultManifest::from_path(&manifest_path)?;

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
    Ok(())
}

#[test]
fn default_runner_writes_valid_artifacts_for_full_catalog() -> TestResult {
    let root = repo_root()?;
    let manifest_path = root.join("tests/conformance/fault_injection_scenarios.v1.yaml");
    let manifest = FaultManifest::from_path(&manifest_path)?;
    let tmp = unique_temp_dir("fault-framework")?;

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
    )?;

    assert_eq!(report.summary.failed, 0, "report: {report:#?}");
    assert_eq!(report.summary.false_negatives, 0, "report: {report:#?}");
    assert!(report.summary.total_cases >= 30, "report: {report:#?}");
    assert!(config.report_path.exists());
    assert!(config.log_path.exists());
    assert!(config.artifact_index_path.exists());

    let (line_count, errors) = validate_log_file(&config.log_path)?;
    assert_eq!(line_count, report.summary.total_cases);
    assert!(errors.is_empty(), "log validation errors: {errors:?}");

    let artifact_index: ArtifactIndex =
        serde_json::from_str(&fs::read_to_string(&config.artifact_index_path)?)?;
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

    Ok(())
}

#[test]
fn harness_cli_runs_single_fault_scenario() -> TestResult {
    let root = repo_root()?;
    let manifest_path = root.join("tests/conformance/fault_injection_scenarios.v1.yaml");
    let tmp = unique_temp_dir("fault-cli")?;
    let report_path = tmp.join("report.json");
    let log_path = tmp.join("log.jsonl");
    let artifact_index_path = tmp.join("artifacts.json");

    let output = Command::new(env!("CARGO_BIN_EXE_harness"))
        .current_dir(&root)
        .arg("fault-inject")
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--scenario")
        .arg("memory.use_after_free")
        .arg("--report")
        .arg(&report_path)
        .arg("--log")
        .arg(&log_path)
        .arg("--artifact-index")
        .arg(&artifact_index_path)
        .arg("--mode")
        .arg("both")
        .arg("--fail-on-mismatch")
        .output()?;

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_str(&fs::read_to_string(&report_path)?)?;
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(report["summary"]["scenario_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["total_cases"].as_u64(), Some(6));

    let artifact_index: ArtifactIndex =
        serde_json::from_str(&fs::read_to_string(&artifact_index_path)?)?;
    let log_join_keys = artifact_index
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "log")
        .and_then(|artifact| artifact.join_keys.as_ref())
        .ok_or_else(|| test_failure("log artifact join keys missing"))?;
    assert_eq!(log_join_keys.trace_ids.len(), 6);
    assert!(
        artifact_index
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "manifest")
    );

    Ok(())
}
