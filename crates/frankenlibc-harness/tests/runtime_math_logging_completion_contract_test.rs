//! Completion-contract tests for bd-5vr.8.1 runtime-math logging evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/runtime_math_logging_completion_contract.v1.json")
}

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(
        manifest_path(root),
    )?)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "runtime-math-logging-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_runtime_math_logging_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_MATH_LOGGING_CONTRACT", contract)
        .env(
            "FRANKENLIBC_RUNTIME_MATH_LOGGING_REPORT",
            out_dir.join("runtime_math_logging_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_LOGGING_LOG",
            out_dir.join("runtime_math_logging_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
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
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(root: &Path, manifest: &serde_json::Value) -> TestResult<BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

fn remove_string(array: &mut serde_json::Value, target: &str) -> TestResult {
    let values = array
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?;
    values.retain(|value| value.as_str() != Some(target));
    Ok(())
}

#[test]
fn manifest_binds_runtime_math_logging_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-5vr.8"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-5vr.8.1")
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-5vr.8.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-5vr.8"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    for file_line_ref in evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
    {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref string"))?,
        )?;
    }

    let artifacts = evidence["artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifacts object"))?;
    for path in artifacts.values() {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path string"))?;
        assert!(root.join(path).is_file(), "artifact should exist: {path}");
    }

    let contract = &evidence["logging_contract"];
    let required_events = string_set(&contract["required_jsonl_events"])?;
    for event in [
        "runtime_decision",
        "runtime_calibration",
        "runtime_snapshot",
        "runtime_certificate_loaded",
        "runtime_regret_alert",
        "runtime_drift_alert",
    ] {
        assert!(required_events.contains(event), "missing event {event}");
    }
    let required_fields = string_set(&contract["required_jsonl_fields"])?;
    for field in [
        "trace_id",
        "decision_path",
        "healing_action",
        "latency_ns",
        "artifact_refs",
        "snapshot_capture_latency_ns",
        "pareto_cap_enforcements",
        "padic_drift_count",
    ] {
        assert!(required_fields.contains(field), "missing field {field}");
    }
    let observability = string_set(&contract["required_observability_exports"])?;
    for anchor in [
        "build_runtime_export",
        "capture_bundle",
        "kernel.export_runtime_math_log_jsonl",
    ] {
        assert!(observability.contains(anchor), "missing anchor {anchor}");
    }

    let source_texts = source_texts(&root, &manifest)?;
    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item)
        );
        let refs = section_value["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?;
        assert!(!refs.is_empty(), "{section} should name test refs");
        for test_ref in refs {
            let source = test_ref["source"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source string"))?;
            let name = test_ref["name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name string"))?;
            let text = source_texts.get(source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "source should be declared")
            })?;
            assert!(
                text.contains(&format!("fn {name}")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_runtime_math_logging_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let contract = manifest_path(&root);
    let out_dir = unique_output_dir(&root, "report")?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("jsonl_events=14"));
    assert!(stdout.contains("jsonl_fields=39"));
    assert!(stdout.contains("unit_tests=6"));
    assert!(stdout.contains("e2e_tests=4"));

    let report = read_json(&out_dir.join("runtime_math_logging_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["jsonl_event_count"].as_u64(), Some(14));
    assert_eq!(report["summary"]["jsonl_field_count"].as_u64(), Some(39));
    assert_eq!(
        report["summary"]["observability_anchor_count"].as_u64(),
        Some(5)
    );

    let rows = read_jsonl(&out_dir.join("runtime_math_logging_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 5);
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(ToString::to_string))
        .collect();
    for event in [
        "runtime_math_logging_source_bound",
        "runtime_math_logging_unit_bound",
        "runtime_math_logging_e2e_bound",
        "runtime_math_logging_telemetry_bound",
        "runtime_math_logging_completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    for row in &rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "completion_debt_bead",
            "original_bead",
            "source_commit",
            "status",
            "gate",
            "missing_item_id",
            "jsonl_event_count",
            "jsonl_field_count",
            "unit_test_count",
            "e2e_test_count",
            "telemetry_event_count",
            "observability_anchor_count",
            "test_refs",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "telemetry row missing {field}");
        }
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-5vr.8.1"));
        assert_eq!(row["original_bead"].as_str(), Some("bd-5vr.8"));
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert!(
            row["trace_id"]
                .as_str()
                .is_some_and(|trace_id| trace_id.starts_with("bd-5vr.8.1::runtime_math_logging::"))
        );
    }

    let summary_row = rows
        .iter()
        .find(|row| {
            row["event"].as_str() == Some("runtime_math_logging_completion_contract_validated")
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "summary row missing"))?;
    assert!(
        summary_row["test_refs"]
            .as_array()
            .is_some_and(|refs| refs.iter().any(|value| value
                .as_str()
                .is_some_and(|name| name.contains(
                    "runtime_math_mod::runtime_math_log_jsonl_exports_snapshot_regret_and_drift_alerts"
                )))),
        "log should include the runtime-math regret/drift test ref"
    );
    assert!(
        summary_row["artifact_refs"]
            .as_array()
            .is_some_and(|refs| refs.iter().any(|value| value.as_str().is_some_and(
                |name| name == "crates/frankenlibc-harness/src/observability_dashboard.rs"
            ))),
        "log should include the observability dashboard artifact"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_runtime_log_event() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_manifest(&root)?;
    remove_string(
        &mut manifest["completion_debt_evidence"]["logging_contract"]["required_jsonl_events"],
        "runtime_drift_alert",
    )?;
    let out_dir = unique_output_dir(&root, "missing-event")?;
    let mutated = out_dir.join("missing_event.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "checker should fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("logging_contract.required_jsonl_events missing runtime_drift_alert"),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_observability_export_anchor() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_manifest(&root)?;
    remove_string(
        &mut manifest["completion_debt_evidence"]["logging_contract"]["required_observability_exports"],
        "kernel.export_runtime_math_log_jsonl",
    )?;
    let out_dir = unique_output_dir(&root, "missing-observability")?;
    let mutated = out_dir.join("missing_observability.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "checker should fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "logging_contract.required_observability_exports missing kernel.export_runtime_math_log_jsonl"
        ),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_manifest(&root)?;
    remove_string(
        &mut manifest["completion_debt_evidence"]["telemetry_primary"]["required_fields"],
        "failure_signature",
    )?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let mutated = out_dir.join("missing_telemetry.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "checker should fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("telemetry_primary.required_fields missing failure_signature"),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}
