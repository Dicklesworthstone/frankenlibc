//! Integration test: workload latency budget join (bd-fp4tm.4).
//!
//! The join consumes workload replay or smoke latency rows and binds them to
//! perf_budget_policy.json without running benchmarks in the test process.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_OUTPUT_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "workload_id",
    "mode",
    "api_family",
    "symbol_family",
    "latency_ns",
    "budget_policy",
    "latency_threshold_ns",
    "observed_regression_pct",
    "overload_policy",
    "perf_state",
    "decision",
    "user_recommendation",
    "artifact_refs",
    "source_commit",
    "freshness_state",
    "failure_signature",
    "next_safe_action",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn json_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("missing JSON field {key}")))
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn latency_row(workload_id: &str, mode: &str, latency_ns: u64) -> Value {
    json!({
        "trace_id": format!("latency::{workload_id}::{mode}"),
        "bead_id": "bd-b92jd.3.2",
        "workload_id": workload_id,
        "mode": mode,
        "api_family": "stdio",
        "symbol_family": "sort_pipeline",
        "symbol": "sort_pipeline",
        "budget_class": "strict_hotpath",
        "latency_ns": latency_ns,
        "baseline_latency_ns": 100,
        "status": "pass",
        "freshness_state": "current",
        "failure_signature": "none",
        "artifact_refs": [
            "tests/conformance/user_workload_replay_manifest.v1.json"
        ],
        "source_commit": "0123456789abcdef0123456789abcdef01234567"
    })
}

fn overloaded_row(workload_id: &str, mode: &str) -> Value {
    json!({
        "trace_id": format!("latency::{workload_id}::{mode}::overloaded"),
        "bead_id": "bd-b92jd.3.2",
        "workload_id": workload_id,
        "mode": mode,
        "api_family": "stdio",
        "symbol_family": "sort_pipeline",
        "status": "skipped",
        "load_state": "overloaded",
        "skip_reason": "overloaded_host_skip",
        "failure_signature": "overloaded_host_skip",
        "freshness_state": "current",
        "artifact_refs": [
            "tests/conformance/user_workload_replay_manifest.v1.json"
        ],
        "source_commit": "0123456789abcdef0123456789abcdef01234567"
    })
}

fn positive_rows() -> Vec<Value> {
    vec![
        latency_row("uwm-shell-coreutils", "strict", 100_000_000),
        latency_row("uwm-shell-coreutils", "hardened", 150),
        overloaded_row("uwm-shell-coreutils-overloaded", "strict"),
    ]
}

fn write_jsonl(dir: &Path, rows: &[Value]) -> TestResult<PathBuf> {
    let log = dir.join("latency.log.jsonl");
    let mut content = String::new();
    for row in rows {
        content.push_str(&serde_json::to_string(row)?);
        content.push('\n');
    }
    std::fs::write(&log, content)?;
    Ok(log)
}

fn run_gate(root: &Path, dir: &Path, rows: &[Value]) -> TestResult<std::process::Output> {
    let input = write_jsonl(dir, rows)?;
    let output = Command::new("bash")
        .arg(root.join("scripts/check_workload_latency_budget_join.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_WORKLOAD_LATENCY_INPUTS", &input)
        .env("FRANKENLIBC_WORKLOAD_LATENCY_OUT_DIR", dir)
        .env(
            "FRANKENLIBC_WORKLOAD_LATENCY_REPORT",
            dir.join("latency.report.json"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_LATENCY_LOG",
            dir.join("latency.log.out.jsonl"),
        )
        .output()?;
    Ok(output)
}

#[test]
fn contract_declares_latency_join_schema() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&root.join("tests/conformance/workload_latency_budget_join.v1.json"))?;
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-fp4tm.4"));

    let modes: BTreeSet<_> = json_field(&contract, "required_runtime_modes")?
        .as_array()
        .ok_or_else(|| test_error("required_runtime_modes should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(modes.contains("strict"));
    assert!(modes.contains("hardened"));

    let fields: BTreeSet<_> = json_field(&contract, "required_output_fields")?
        .as_array()
        .ok_or_else(|| test_error("required_output_fields should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in REQUIRED_OUTPUT_FIELDS {
        assert!(fields.contains(field), "missing output field {field}");
    }

    let schema = json_field(&contract, "failure_signature_schema")?;
    for signature in [
        "workload_latency_missing_latency",
        "workload_latency_stale_evidence",
        "workload_latency_missing_mode",
        "workload_latency_missing_budget",
        "workload_latency_over_budget",
        "workload_latency_overloaded_skip",
    ] {
        assert!(json_field(schema, signature)?.is_object());
    }
    Ok(())
}

#[test]
fn gate_script_is_executable() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_workload_latency_budget_join.sh");
    assert!(script.exists(), "missing {}", script.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_latency_budget_join.sh must be executable"
        );
    }
    Ok(())
}

#[test]
fn gate_joins_strict_and_hardened_rows_and_distinguishes_overload_skip() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-latency-pass")?;
    let output = run_gate(&root, &dir, &positive_rows())?;
    assert!(
        output.status.success(),
        "latency join failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&dir.join("latency.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["input_row_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["joined_row_count"].as_u64(), Some(3));
    let modes: BTreeSet<_> = report["summary"]["represented_modes"]
        .as_array()
        .ok_or_else(|| test_error("represented_modes should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(modes.contains("strict"));
    assert!(modes.contains("hardened"));
    assert_eq!(
        report["summary"]["decision_counts"]["pass"].as_u64(),
        Some(2)
    );
    assert_eq!(
        report["summary"]["decision_counts"]["skip"].as_u64(),
        Some(1)
    );

    let rows = json_field(&report, "workload_latency_rows")?
        .as_array()
        .ok_or_else(|| test_error("workload_latency_rows should be array"))?;
    for row in rows {
        for field in REQUIRED_OUTPUT_FIELDS {
            assert!(row.get(*field).is_some(), "latency row missing {field}");
        }
    }
    assert!(
        rows.iter()
            .any(|row| row["perf_state"].as_str() == Some("overloaded_skip")
                && row["decision"].as_str() == Some("skip")),
        "overloaded rows must be represented as skip, not pass/fail"
    );

    let log_text = std::fs::read_to_string(dir.join("latency.log.out.jsonl"))?;
    let log_rows: Vec<Value> = log_text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(log_rows.len(), 3);
    Ok(())
}

#[test]
fn over_budget_rows_fail_closed_with_stable_signature() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-latency-over-budget")?;
    let rows = vec![
        latency_row("uwm-shell-coreutils", "strict", 100_000_000),
        latency_row("uwm-shell-coreutils", "hardened", 300),
    ];
    let output = run_gate(&root, &dir, &rows)?;
    assert!(!output.status.success(), "over-budget row should fail");
    let report = load_json(&dir.join("latency.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("workload_latency_over_budget"))
    );
    Ok(())
}

#[test]
fn missing_latency_rows_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-latency-missing")?;
    let mut row = latency_row("uwm-shell-coreutils", "strict", 100);
    row.as_object_mut()
        .ok_or_else(|| test_error("row should be object"))?
        .remove("latency_ns");
    let output = run_gate(
        &root,
        &dir,
        &[row, latency_row("uwm-shell-coreutils", "hardened", 150)],
    )?;
    assert!(!output.status.success(), "missing latency should fail");
    let report = load_json(&dir.join("latency.report.json"))?;
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("workload_latency_missing_latency"))
    );
    Ok(())
}

#[test]
fn stale_latency_rows_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-latency-stale")?;
    let mut row = latency_row("uwm-shell-coreutils", "strict", 100);
    row["freshness_state"] = json!("stale");
    let output = run_gate(
        &root,
        &dir,
        &[row, latency_row("uwm-shell-coreutils", "hardened", 150)],
    )?;
    assert!(!output.status.success(), "stale latency should fail");
    let report = load_json(&dir.join("latency.report.json"))?;
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("workload_latency_stale_evidence"))
    );
    Ok(())
}

#[test]
fn missing_mode_rows_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-latency-missing-mode")?;
    let mut row = latency_row("uwm-shell-coreutils", "strict", 100);
    row.as_object_mut()
        .ok_or_else(|| test_error("row should be object"))?
        .remove("mode");
    let output = run_gate(&root, &dir, &[row])?;
    assert!(!output.status.success(), "missing mode should fail");
    let report = load_json(&dir.join("latency.report.json"))?;
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("workload_latency_missing_mode"))
    );
    Ok(())
}
