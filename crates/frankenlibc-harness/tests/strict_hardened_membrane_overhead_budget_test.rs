//! Golden/checker tests for bd-e1eko strict/hardened TSM overhead budgets.

use serde_json::{Value, json};
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

fn golden_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/strict_hardened_membrane_overhead_budget_golden.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_strict_hardened_membrane_overhead_budget.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "strict-hardened-overhead-budget-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, evidence: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_EVIDENCE",
            evidence,
        )
        .env(
            "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_LOG",
            out_dir.join("events.jsonl"),
        )
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

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("expected array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("expected string array item"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn records_mut(packet: &mut Value) -> TestResult<&mut Vec<Value>> {
    packet["records"]
        .as_array_mut()
        .ok_or_else(|| test_error("records must be array"))
}

fn failure_signatures(report: &Value) -> TestResult<BTreeSet<String>> {
    report["failures"]
        .as_array()
        .ok_or_else(|| test_error("failures must be array"))?
        .iter()
        .map(|failure| {
            failure["failure_signature"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("failure missing signature"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn assert_negative_control<F>(root: &Path, label: &str, signature: &str, mutate: F) -> TestResult
where
    F: FnOnce(&mut Value) -> TestResult,
{
    let mut packet = load_json(&golden_path(root))?;
    mutate(&mut packet)?;

    let out_dir = unique_out_dir(root, label)?;
    let evidence = out_dir.join("mutated_evidence.json");
    write_json(&evidence, &packet)?;

    let output = run_checker(root, &evidence, &out_dir)?;
    assert!(
        !output.status.success(),
        "{label} should fail closed for {signature}\n{}",
        output_text(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    let signatures = failure_signatures(&report)?;
    assert!(
        signatures.contains(signature),
        "{label} should report {signature}; got {signatures:?}\n{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn golden_binds_strict_hardened_budget_policy() -> TestResult {
    let root = workspace_root()?;
    let golden = load_json(&golden_path(&root))?;

    assert_eq!(golden["schema_version"].as_str(), Some("v1"));
    assert_eq!(golden["bead_id"].as_str(), Some("bd-wpr1n"));
    assert_eq!(golden["checker_bead_id"].as_str(), Some("bd-e1eko"));
    assert_eq!(
        golden["source_commit_policy"]["failure_signature"].as_str(),
        Some("stale_source_commit")
    );
    assert_eq!(
        golden["budget_policy"]["strict_p99_ns"].as_f64(),
        Some(20.0)
    );
    assert_eq!(
        golden["budget_policy"]["hardened_p99_ns"].as_f64(),
        Some(200.0)
    );

    assert_eq!(
        string_set(&golden["required_modes"])?,
        BTreeSet::from(["strict".to_string(), "hardened".to_string()])
    );
    assert_eq!(
        string_set(&golden["required_families"])?,
        BTreeSet::from([
            "allocator".to_string(),
            "ctype".to_string(),
            "math_fenv".to_string(),
            "pthread_sync".to_string(),
            "runtime_math".to_string(),
            "stdio_buffer".to_string(),
            "string_memory".to_string(),
        ])
    );
    assert_eq!(
        string_set(&golden["required_failure_signatures"])?,
        BTreeSet::from([
            "budget_regression".to_string(),
            "invalid_quantile".to_string(),
            "local_fallback_seen".to_string(),
            "missing_family".to_string(),
            "missing_mode".to_string(),
            "missing_rch_remote".to_string(),
            "missing_runtime_math_telemetry".to_string(),
            "stale_source_commit".to_string(),
        ])
    );
    assert_eq!(golden["record_count"].as_u64(), Some(14));
    assert_eq!(golden["records"].as_array().map(Vec::len), Some(14));

    Ok(())
}

#[test]
fn checker_accepts_valid_strict_hardened_overhead_golden() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &golden_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["schema_version"].as_str(),
        Some("strict_hardened_membrane_overhead_budget_checker.v1")
    );
    assert_eq!(report["checker_bead"].as_str(), Some("bd-e1eko"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-wpr1n"));
    assert_eq!(report["record_count"].as_u64(), Some(14));
    assert_eq!(report["failures"].as_array().map(Vec::len), Some(0));
    assert_eq!(report["events"].as_array().map(Vec::len), Some(14));

    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    assert_eq!(log.lines().count(), 14);

    Ok(())
}

#[test]
fn checker_negative_controls_fail_closed_with_structured_signatures() -> TestResult {
    let root = workspace_root()?;

    assert_negative_control(&root, "stale-source", "stale_source_commit", |packet| {
        packet["source_commit_policy"]["expected_source_commit"] = json!("fresh-source");
        records_mut(packet)?[0]["source_commit"] = json!("stale-source");
        Ok(())
    })?;

    assert_negative_control(&root, "missing-rch", "missing_rch_remote", |packet| {
        records_mut(packet)?[0]["command"] =
            json!("cargo bench -p frankenlibc-bench --bench strict_hardened_overhead_harness");
        Ok(())
    })?;

    assert_negative_control(&root, "local-fallback", "local_fallback_seen", |packet| {
        records_mut(packet)?[0]["command"] = json!(
            "RCH_REQUIRE_REMOTE=1 rch exec -- cargo bench [RCH] local (remote execution failed)"
        );
        Ok(())
    })?;

    assert_negative_control(&root, "missing-family", "missing_family", |packet| {
        let record_count = {
            let records = records_mut(packet)?;
            records.retain(|record| record["api_family"].as_str() != Some("runtime_math"));
            records.len()
        };
        packet["record_count"] = json!(record_count);
        Ok(())
    })?;

    assert_negative_control(&root, "missing-mode", "missing_mode", |packet| {
        let record_count = {
            let records = records_mut(packet)?;
            records.retain(|record| record["runtime_mode"].as_str() != Some("hardened"));
            records.len()
        };
        packet["record_count"] = json!(record_count);
        Ok(())
    })?;

    assert_negative_control(&root, "invalid-quantile", "invalid_quantile", |packet| {
        records_mut(packet)?[0]["p99_ns_op"] = json!(5.0);
        Ok(())
    })?;

    assert_negative_control(&root, "budget-regression", "budget_regression", |packet| {
        records_mut(packet)?[0]["p99_ns_op"] = json!(25.0);
        Ok(())
    })?;

    assert_negative_control(
        &root,
        "missing-telemetry",
        "missing_runtime_math_telemetry",
        |packet| {
            records_mut(packet)?[0]["missing_decision_telemetry"] = json!(true);
            Ok(())
        },
    )?;

    Ok(())
}
