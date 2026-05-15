//! Completion contract tests for bd-1x3.2.1 trace-weighted stub ranking evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir.parent().ok_or_else(|| {
        test_error(format!(
            "{} has no parent directory",
            manifest_dir.display()
        ))
    })?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| test_error(format!("{} has no parent directory", crates_dir.display())))?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/trace_weighted_stub_ranking_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_trace_weighted_stub_ranking_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "trace-weighted-stub-ranking-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_TRACE_WEIGHTED_STUB_RANKING_CONTRACT", contract)
        .env(
            "FRANKENLIBC_TRACE_WEIGHTED_STUB_RANKING_REPORT",
            out_dir.join("trace_weighted_stub_ranking_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_TRACE_WEIGHTED_STUB_RANKING_LOG",
            out_dir.join("trace_weighted_stub_ranking_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_message(output: &std::process::Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let out_dir = unique_out_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(output.status.success(), "{}", checker_message(&output));
    Ok(out_dir)
}

fn json_array<'a>(value: &'a Value, label: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{label} should be an array")))
}

fn json_array_mut<'a>(value: &'a mut Value, label: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| test_error(format!("{label} should be a mutable array")))
}

fn json_str<'a>(value: &'a Value, label: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| test_error(format!("{label} should be a string")))
}

fn string_set(value: &Value, label: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, label)?
        .iter()
        .map(|value| json_str(value, label).map(str::to_string))
        .collect()
}

#[test]
fn manifest_binds_all_bd1x32_completion_items() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("trace_weighted_stub_ranking_completion_contract.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-1x3.2"));
    assert_eq!(
        contract["completion_debt_bead"].as_str(),
        Some("bd-1x3.2.1")
    );

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-1x3.2"));
    assert_eq!(evidence["next_audit_score_threshold"].as_u64(), Some(900));

    let missing_items: BTreeSet<String> = json_array(
        &evidence["missing_item_bindings"],
        "completion_debt_evidence.missing_item_bindings",
    )?
    .iter()
    .map(|binding| json_str(&binding["missing_item_id"], "missing item id").map(str::to_string))
    .collect::<TestResult<_>>()?;
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.fuzz.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );

    assert!(
        json_array(
            &evidence["unit_primary"]["required_test_refs"],
            "unit_primary.required_test_refs"
        )?
        .len()
            >= 8
    );
    assert_eq!(
        evidence["fuzz_primary"]["minimum_seed_count"].as_u64(),
        Some(10)
    );
    assert_eq!(
        json_array(
            &evidence["fuzz_primary"]["deterministic_seed_replay"],
            "fuzz_primary.deterministic_seed_replay",
        )?
        .len(),
        10
    );
    assert_eq!(
        evidence["conformance_primary"]["minimum_fixture_count"].as_u64(),
        Some(40)
    );

    let telemetry_events = string_set(
        &evidence["telemetry_primary"]["required_events"],
        "telemetry_primary.required_events",
    )?;
    for required in [
        "trace_weighted_stub_ranking_completion.source_ref",
        "trace_weighted_stub_ranking_completion.missing_item_bound",
        "trace_weighted_stub_ranking_completion.deterministic_fuzz_seed_replayed",
        "trace_weighted_stub_ranking_completion.conformance_artifact_bound",
        "trace_weighted_stub_ranking_completion.telemetry_bound",
        "trace_weighted_stub_ranking_completion.validated",
    ] {
        assert!(telemetry_events.contains(required));
    }

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report =
        read_json(&out_dir.join("trace_weighted_stub_ranking_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["event"].as_str(),
        Some("trace_weighted_stub_ranking_completion.validated")
    );
    assert_eq!(
        json_array(&report["missing_items"], "report.missing_items")?.len(),
        5
    );
    assert!(report["unit_test_ref_count"].as_u64().unwrap_or_default() >= 8);
    assert!(report["e2e_artifact_count"].as_u64().unwrap_or_default() >= 6);
    assert_eq!(
        report["deterministic_fuzz_seed_count"]
            .as_u64()
            .unwrap_or_default(),
        10
    );
    assert!(
        report["conformance_test_ref_count"]
            .as_u64()
            .unwrap_or_default()
            >= 3
    );
    assert!(report["fixture_count"].as_u64().unwrap_or_default() >= 40);

    let rows =
        read_jsonl(&out_dir.join("trace_weighted_stub_ranking_completion_contract.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    for required in [
        "trace_weighted_stub_ranking_completion.source_ref",
        "trace_weighted_stub_ranking_completion.missing_item_bound",
        "trace_weighted_stub_ranking_completion.deterministic_fuzz_seed_replayed",
        "trace_weighted_stub_ranking_completion.conformance_artifact_bound",
        "trace_weighted_stub_ranking_completion.telemetry_bound",
        "trace_weighted_stub_ranking_completion.validated",
    ] {
        assert!(
            events.contains(required),
            "missing telemetry event {required}: {events:?}"
        );
    }
    for row in rows {
        let serialized = serde_json::to_string(&row)?;
        validate_log_line(&serialized, 1).map_err(|errors| {
            std::io::Error::other(format!("checker log row failed validation: {errors:?}"))
        })?;
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_seed_binding() -> TestResult {
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut contract["completion_debt_evidence"]["fuzz_primary"]["deterministic_seed_replay"],
        "fuzz_primary.deterministic_seed_replay",
    )?
    .retain(|seed| seed["seed_id"].as_str() != Some("wave_plan_top_n_mismatch"));

    let out_dir = unique_out_dir(&root, "missing-fuzz-seed")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing fuzz seed binding"
    );
    let message = checker_message(&output);
    assert!(
        message.contains("fuzz seed count"),
        "unexpected checker output: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event_binding() -> TestResult {
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut contract["completion_debt_evidence"]["telemetry_primary"]["required_events"],
        "telemetry_primary.required_events",
    )?
    .retain(|event| {
        event.as_str() != Some("trace_weighted_stub_ranking_completion.telemetry_bound")
    });

    let out_dir = unique_out_dir(&root, "missing-telemetry-event")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing telemetry event binding"
    );
    let message = checker_message(&output);
    assert!(
        message.contains("telemetry events missing"),
        "unexpected checker output: {message}"
    );
    Ok(())
}
