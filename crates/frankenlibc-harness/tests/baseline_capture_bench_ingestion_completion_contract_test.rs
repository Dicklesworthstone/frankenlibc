//! Contract tests for bd-3h1u.1.1.1 baseline-capture bench-ingestion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
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
    root.join("tests/conformance/baseline_capture_bench_ingestion_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_baseline_capture_bench_ingestion_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
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
    let path = root.join("target/conformance").join(format!(
        "baseline-capture-bench-ingestion-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_BASELINE_CAPTURE_CONTRACT", manifest)
        .env("FRANKENLIBC_BASELINE_CAPTURE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_BASELINE_CAPTURE_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_BASELINE_CAPTURE_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_BASELINE_CAPTURE_SYMBOL_REPORT",
            out_dir.join("symbol_latency_report.json"),
        )
        .env(
            "FRANKENLIBC_BASELINE_CAPTURE_SYMBOL_LOG",
            out_dir.join("symbol_latency_events.jsonl"),
        )
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line)?;
            row["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn assert_file_line_ref_exists(root: &Path, value: &str) -> TestResult {
    let (path, line) = value
        .rsplit_once(':')
        .ok_or_else(|| test_error("file line ref should contain ':'"))?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "line ref must be positive");
    let full_path = root.join(path);
    assert!(full_path.is_file(), "file-line ref missing path {value}");
    let line_count = fs::read_to_string(full_path)?.lines().count();
    assert!(line_no <= line_count, "file-line ref outside file: {value}");
    Ok(())
}

#[test]
fn contract_anchors_completion_debt_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("baseline_capture_bench_ingestion_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3h1u.1.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-3h1u.1.1.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.conformance.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );
    assert!(
        manifest["audit_reference"]["score_threshold"]
            .as_u64()
            .unwrap_or(0)
            >= 800
    );
    for reference in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| test_error("implementation refs should be array"))?
    {
        assert_file_line_ref_exists(
            &root,
            reference
                .as_str()
                .ok_or_else(|| test_error("implementation ref should be string"))?,
        )?;
    }
    Ok(())
}

#[test]
fn source_artifacts_bind_existing_baseline_ingestion_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source artifacts should be array"))?;
    let ids = sources
        .iter()
        .map(|source| {
            source["id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("source id should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        ids,
        BTreeSet::from([
            "baseline_checker".to_string(),
            "baseline_generator".to_string(),
            "baseline_harness".to_string(),
            "canonical_baseline".to_string(),
            "capture_map".to_string(),
            "completion_checker".to_string(),
            "completion_harness".to_string(),
            "perf_budget_policy".to_string(),
            "sample_ingester".to_string(),
            "sample_log".to_string(),
        ])
    );

    for source in sources {
        let path = source["path"]
            .as_str()
            .ok_or_else(|| test_error("source path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in source["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required needles should be array"))?
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
fn conformance_contract_requires_deterministic_replay_coverage() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let conformance = &manifest["conformance_primary"];
    assert_eq!(
        conformance["missing_item_id"].as_str(),
        Some("tests.conformance.primary")
    );
    let requirements = &conformance["required_baseline_summary"];
    assert!(
        requirements["minimum_total_symbols"]
            .as_u64()
            .is_some_and(|value| value >= 4000)
    );
    assert_eq!(
        requirements["minimum_measured_symbols_per_mode"].as_u64(),
        Some(16)
    );
    assert_eq!(requirements["minimum_updated_symbols"].as_u64(), Some(16));
    assert_eq!(requirements["minimum_updated_modes"].as_u64(), Some(48));

    let baseline = load_json(&root.join("tests/conformance/symbol_latency_baseline.v1.json"))?;
    assert_eq!(baseline["summary"]["total_symbols"].as_u64(), Some(4119));
    assert_eq!(baseline["ingestion"]["updated_symbols"].as_u64(), Some(16));
    assert_eq!(baseline["ingestion"]["updated_modes"].as_u64(), Some(48));
    for mode in ["raw", "strict", "hardened"] {
        assert_eq!(
            baseline["summary"]["mode_percentile_measured_counts"][mode]["p50"].as_u64(),
            Some(16)
        );
    }
    Ok(())
}

#[test]
fn telemetry_contract_binds_budget_gate_rows() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let telemetry = &manifest["telemetry_primary"];
    assert_eq!(
        telemetry["missing_item_id"].as_str(),
        Some("telemetry.primary")
    );
    let symbol_events = string_set(&telemetry["required_symbol_latency_events"])?;
    assert!(symbol_events.contains("ci.symbol_latency_budget.pass"));
    assert!(symbol_events.contains("ci.symbol_latency_budget.waived_target_violation"));
    let completion_events = string_set(&telemetry["required_completion_events"])?;
    for event in [
        "baseline_capture.source_artifacts_validated",
        "baseline_capture.conformance_binding_validated",
        "baseline_capture.telemetry_validated",
        "baseline_capture.symbol_latency_gate_replayed",
        "baseline_capture.completion_contract_validated",
        "baseline_capture.completion_contract_failed",
    ] {
        assert!(completion_events.contains(event), "missing event {event}");
    }
    let fields = string_set(&telemetry["required_report_fields"])?;
    for field in [
        "source_commit",
        "capture_map_source_count",
        "measured_symbol_count",
        "updated_symbols",
        "updated_modes",
        "symbol_latency_report",
        "symbol_latency_log",
        "failure_signature",
    ] {
        assert!(fields.contains(field), "missing report field {field}");
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("baseline_capture_bench_ingestion_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("baseline_capture_bench_ingestion_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-3h1u.1.1.1")
    );
    assert_eq!(report["source_count"].as_u64(), Some(10));
    assert_eq!(report["capture_map_source_count"].as_u64(), Some(5));
    assert_eq!(report["measured_symbol_count"].as_u64(), Some(16));
    assert_eq!(report["updated_symbols"].as_u64(), Some(16));
    assert_eq!(report["updated_modes"].as_u64(), Some(48));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("baseline_capture.source_artifacts_validated"));
    assert!(events.contains("baseline_capture.symbol_latency_gate_replayed"));
    assert!(events.contains("baseline_capture.completion_contract_validated"));

    let symbol_report = load_json(&out_dir.join("symbol_latency_report.json"))?;
    assert_eq!(
        symbol_report["summary"]["gate_passed"].as_bool(),
        Some(true)
    );
    let symbol_events = read_log_events(&out_dir.join("symbol_latency_events.jsonl"))?;
    assert!(symbol_events.contains("ci.symbol_latency_budget.pass"));
    assert!(symbol_events.contains("ci.symbol_latency_budget.waived_target_violation"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let events = manifest["telemetry_primary"]["required_completion_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required completion events should be array"))?;
    events.retain(|event| event.as_str() != Some("baseline_capture.telemetry_validated"));

    let out_dir = unique_output_dir(&root, "missing-event")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject mutated contract"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completion events missing"),
        "unexpected stderr: {}",
        output_text(&output)
    );
    Ok(())
}
