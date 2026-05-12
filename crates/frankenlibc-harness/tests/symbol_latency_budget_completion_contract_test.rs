//! Contract tests for bd-l93x.5.1 symbol-latency budget completion evidence.

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
    root.join("tests/conformance/symbol_latency_budget_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_symbol_latency_budget_completion_contract.sh")
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
        "symbol-latency-budget-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env(
            "FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_CONTRACT",
            manifest,
        )
        .env(
            "FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_LATENCY_BUDGET_SYMBOL_REPORT",
            out_dir.join("symbol_latency_report.json"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_LATENCY_BUDGET_SYMBOL_LOG",
            out_dir.join("symbol_latency_events.jsonl"),
        )
        .env(
            "FRANKENLIBC_SYMBOL_LATENCY_BUDGET_SYMBOL_GENERATED",
            out_dir.join("symbol_latency_baseline.generated.v1.json"),
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
fn contract_anchors_symbol_latency_budget_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("symbol_latency_budget_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-l93x.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-l93x.5.1")
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
fn source_artifacts_bind_symbol_latency_budget_surfaces() -> TestResult {
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
            "baseline_harness".to_string(),
            "benchmark_gate".to_string(),
            "canonical_baseline".to_string(),
            "ci_wiring".to_string(),
            "completion_checker".to_string(),
            "completion_contract".to_string(),
            "completion_harness".to_string(),
            "perf_budget_policy".to_string(),
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
fn checker_accepts_contract_and_replays_budget_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accept")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS symbol latency budget completion contract")
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("symbol_latency_budget_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-l93x.5.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-l93x.5"));
    assert_eq!(report["source_count"].as_u64(), Some(9));
    assert!(
        report["implementation_ref_count"].as_u64().unwrap_or(0) >= 10,
        "expected existing file:line implementation refs"
    );
    assert!(
        report["measured_symbol_count"].as_u64().unwrap_or(0) >= 16,
        "expected replayed budget gate measured symbols"
    );
    assert!(
        report["evaluated_mode_count"].as_u64().unwrap_or(0) >= 8,
        "expected replayed budget gate evaluated modes"
    );
    assert!(out_dir.join("symbol_latency_report.json").is_file());
    assert!(out_dir.join("symbol_latency_events.jsonl").is_file());
    Ok(())
}

#[test]
fn checker_emits_structured_symbol_latency_completion_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "telemetry")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker should pass\n{}",
        output_text(&output)
    );

    let completion_events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "symbol_latency_budget.source_artifacts_validated",
        "symbol_latency_budget.conformance_binding_validated",
        "symbol_latency_budget.telemetry_validated",
        "symbol_latency_budget.budget_gate_replayed",
        "symbol_latency_budget.completion_contract_validated",
    ] {
        assert!(
            completion_events.contains(event),
            "missing completion event {event}"
        );
    }

    let symbol_events = read_log_events(&out_dir.join("symbol_latency_events.jsonl"))?;
    assert!(symbol_events.contains("ci.symbol_latency_budget.pass"));
    assert!(symbol_events.contains("ci.symbol_latency_budget.waived_target_violation"));

    let symbol_report = load_json(&out_dir.join("symbol_latency_report.json"))?;
    assert_eq!(symbol_report["bead"].as_str(), Some("bd-l93x.5"));
    assert_eq!(
        symbol_report["summary"]["gate_passed"].as_bool(),
        Some(true)
    );
    assert!(
        string_set(&symbol_report["summary"]["active_waiver_beads"])?.contains("bd-242"),
        "current policy waiver should be reported"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["missing_items_closed"] =
        Value::Array(vec![Value::from("tests.conformance.primary")]);
    let bad_manifest = out_dir.join("missing_telemetry.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry binding\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("missing_items_closed must bind telemetry.primary"),
        "expected missing telemetry failure\n{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_budget_event_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-event")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["telemetry_primary"]["required_symbol_latency_events"] =
        Value::Array(vec![Value::from("ci.symbol_latency_budget.pass")]);
    let bad_manifest = out_dir.join("missing_budget_event.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing budget event binding\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("telemetry_primary.required_symbol_latency_events missing"),
        "expected missing budget event failure\n{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_policy_budget_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "policy-drift")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["telemetry_primary"]["required_policy_budgets"]["strict_hotpath"]["strict_mode_ns"] =
        Value::from(21);
    let bad_manifest = out_dir.join("policy_drift.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject policy budget drift\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains(
            "telemetry_primary.required_policy_budgets strict_hotpath.strict_mode_ns drifted"
        ),
        "expected policy budget drift failure\n{}",
        output_text(&output)
    );
    Ok(())
}
