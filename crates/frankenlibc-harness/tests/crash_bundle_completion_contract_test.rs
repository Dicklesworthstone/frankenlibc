//! Contract tests for bd-6yd.1 crash bundle completion evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest must have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest must live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    let path = root.join("tests/conformance/crash_bundle_completion_contract.v1.json");
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn json_string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
    let values = value.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "value should be a JSON array of strings",
        )
    })?;
    let mut result = BTreeSet::new();
    for item in values {
        let text = item.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "array entry should be a string")
        })?;
        result.insert(text.to_string());
    }
    Ok(result)
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.exists(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let text = std::fs::read_to_string(&full_path)?;
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        line_no <= lines.len(),
        "file-line ref outside file: {file_line_ref}"
    );
    assert!(
        !lines[line_no - 1].trim().is_empty(),
        "file-line ref should not point at a blank line: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(
    root: &Path,
    sources: &serde_json::Map<String, serde_json::Value>,
) -> TestResult<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (key, path) in sources {
        let path = path.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "test source path should be a string",
            )
        })?;
        result.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(result)
}

#[test]
fn manifest_binds_crash_bundle_completion_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    let evidence = &manifest["completion_debt_evidence"];
    let unit = &evidence["unit_primary"];
    let e2e = &evidence["e2e_primary"];
    let telemetry = &evidence["telemetry_primary"];

    assert_eq!(manifest["bead"].as_str(), Some("bd-6yd.1"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-6yd.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-6yd"));
    assert_eq!(
        json_string_set(&evidence["missing_items"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    let sources = evidence["test_sources"].as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "test_sources should be an object",
        )
    })?;
    let source_texts = source_texts(&root, sources)?;

    let spec: serde_json::Value = serde_json::from_str(
        source_texts
            .get("spec")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "spec source missing"))?,
    )?;
    assert_eq!(spec["bead"].as_str(), Some("bd-6yd"));
    assert_eq!(
        spec["integration"]["log_schema_ref"].as_str(),
        Some("tests/conformance/log_schema.json")
    );
    assert_eq!(
        spec["integration"]["evidence_system_ref"].as_str(),
        Some("crates/frankenlibc-membrane/src/runtime_math/evidence.rs")
    );

    let expected_artifacts = BTreeSet::from([
        "allocator_stats.json".to_string(),
        "backtrace.txt".to_string(),
        "bundle.meta".to_string(),
        "command.shline".to_string(),
        "env.txt".to_string(),
        "evidence_snapshot.jsonl".to_string(),
        "proc_self_maps.txt".to_string(),
        "stderr.txt".to_string(),
        "stdout.txt".to_string(),
    ]);
    assert_eq!(
        json_string_set(&unit["required_spec_artifacts"])?,
        expected_artifacts
    );
    let spec_artifacts: BTreeSet<String> = spec["bundle_format"]["required_artifacts"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required artifacts missing"))?
        .iter()
        .filter_map(|artifact| artifact["filename"].as_str().map(str::to_string))
        .collect();
    assert!(
        expected_artifacts.is_subset(&spec_artifacts),
        "crash bundle spec should contain all required artifacts"
    );

    let unit_text = source_texts
        .get("unit")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unit source missing"))?;
    let unit_refs = json_string_set(&unit["required_test_refs"])?;
    assert_eq!(unit_refs.len(), 9, "contract should bind nine unit refs");
    for name in &unit_refs {
        assert!(
            unit_text.contains(&format!("fn {name}")),
            "contract references missing crash_bundle_test::{name}"
        );
    }

    let gate_text = source_texts
        .get("gate")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "gate source missing"))?;
    assert_eq!(
        e2e["gate_script"].as_str(),
        Some("scripts/check_crash_bundle.sh")
    );
    assert!(gate_text.contains("check_crash_bundle: PASS"));
    assert_eq!(
        telemetry["required_artifact"].as_str(),
        Some("evidence_snapshot.jsonl")
    );
    assert_eq!(
        json_string_set(&telemetry["required_artifact_kinds"])?,
        BTreeSet::from([
            "backtrace".to_string(),
            "log".to_string(),
            "snapshot".to_string(),
        ])
    );

    let implementation_refs = evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs missing"))?;
    assert!(
        implementation_refs.len() >= 20,
        "implementation refs should cover spec, gate, and unit coverage"
    );
    for file_line_ref in implementation_refs {
        let file_line_ref = file_line_ref.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "implementation ref should be a string",
            )
        })?;
        assert_file_line_ref_exists(&root, file_line_ref)?;
    }

    Ok(())
}

#[test]
fn checker_script_passes_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let report = root.join("target/conformance/crash_bundle_completion_contract.test.report.json");
    let log = root.join("target/conformance/crash_bundle_completion_contract.test.log.jsonl");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_crash_bundle_completion_contract.sh"))
        .env("FRANKENLIBC_CRASH_BUNDLE_COMPLETION_REPORT", &report)
        .env("FRANKENLIBC_CRASH_BUNDLE_COMPLETION_LOG", &log)
        .current_dir(&root)
        .output()?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report)?)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["bead"].as_str(), Some("bd-6yd.1"));
    assert_eq!(report_json["original_bead"].as_str(), Some("bd-6yd"));
    assert_eq!(
        json_string_set(&report_json["missing_items_bound"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert_eq!(
        report_json["required_artifacts"]
            .as_array()
            .map_or(0, |v| v.len()),
        9
    );
    assert_eq!(
        report_json["unit_refs"].as_array().map_or(0, |v| v.len()),
        9
    );
    assert_eq!(
        report_json["telemetry_artifact"].as_str(),
        Some("evidence_snapshot.jsonl")
    );
    assert_eq!(
        report_json["failure_signature"].as_str(),
        Some("crash_bundle_completion_missing_unit_e2e_or_telemetry_evidence")
    );

    let log_text = std::fs::read_to_string(&log)?;
    let last_line = log_text
        .lines()
        .last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "log should not be empty"))?;
    let event: serde_json::Value = serde_json::from_str(last_line)?;
    assert_eq!(
        event["event"].as_str(),
        Some("crash_bundle_completion_contract_validated")
    );
    assert_eq!(event["status"].as_str(), Some("pass"));
    Ok(())
}
