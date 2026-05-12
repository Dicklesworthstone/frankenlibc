//! Completion contract tests for bd-zyck1.114.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/crt_tls_atexit_direct_link_proof_dashboard_completion_contract.v1.json";
const CHECKER_REL: &str =
    "scripts/check_crt_tls_atexit_direct_link_proof_dashboard_completion_contract.sh";
const DASHBOARD_REL: &str = "tests/conformance/l1_dry_run_readiness_dashboard.v1.json";
const EXPECTED_SCHEMA: &str = "crt_tls_atexit_direct_link_proof_dashboard_completion_contract.v1";
const EXPECTED_REPORT_SCHEMA: &str =
    "crt_tls_atexit_direct_link_proof_dashboard_completion_contract.report.v1";
const EXPECTED_ROW_COUNT: usize = 42;
const EXPECTED_EVENTS: &[&str] = &[
    "crt_tls_dashboard.sources_validated",
    "crt_tls_dashboard.rows_validated",
    "crt_tls_dashboard.bindings_validated",
    "crt_tls_dashboard.source_gates_replayed",
    "crt_tls_dashboard.completion_contract_pass",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("manifest should live below workspace root"))?
        .to_path_buf())
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "crt-tls-dashboard-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("events.jsonl")
}

fn run_checker(
    root: &Path,
    contract: &Path,
    out_dir: &Path,
    env_overrides: &[(&str, &Path)],
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env(
            "FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_LOG",
            checker_log(out_dir),
        )
        .env(
            "FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_GATE_DIR",
            out_dir.join("source_gates"),
        );
    for (key, value) in env_overrides {
        command.env(key, value);
    }
    Ok(command.output()?)
}

fn expect_checker_success(root: &Path, out_dir: &Path) -> TestResult<Output> {
    let output = run_checker(root, &root.join(CONTRACT_REL), out_dir, &[])?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn expect_checker_failure(output: Output, signature: &str) {
    assert!(
        !output.status.success(),
        "checker unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(signature),
        "checker failure missing signature {signature:?}\n{combined}"
    );
}

fn string_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} string missing")).into()
    })
}

fn array_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} array missing")).into()
    })
}

fn object_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} object missing")).into()
    })
}

fn string_set(values: &[Value]) -> TestResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| {
            value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "expected string value").into()
            })
        })
        .collect()
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            validate_log_line(line, index + 1).map_err(|errors| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("structured log line {} failed: {errors:?}", index + 1),
                )
            })?;
            Ok(serde_json::from_str(line)?)
        })
        .collect()
}

fn crt_tls_rows(dashboard: &Value) -> TestResult<Vec<&Value>> {
    Ok(array_field(dashboard, "rows")?
        .iter()
        .filter(|row| {
            row.get("row_id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with("crt-tls-atexit-direct-link-proof-"))
        })
        .collect())
}

#[test]
fn contract_binds_dashboard_conformance_and_telemetry() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-zyck1.114.1");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-zyck1.114");

    let completion = manifest
        .get("completion_contract")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion contract missing"))?;
    assert_eq!(
        string_set(array_field(completion, "missing_item_ids")?)?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string()
        ])
    );
    let required_dashboard = object_field(completion, "required_dashboard")?;
    assert_eq!(
        required_dashboard
            .get("required_row_ids")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(EXPECTED_ROW_COUNT)
    );

    let dashboard = read_json(&root.join(DASHBOARD_REL))?;
    assert_eq!(crt_tls_rows(&dashboard)?.len(), EXPECTED_ROW_COUNT);
    Ok(())
}

#[test]
fn checker_accepts_dashboard_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: crt tls atexit direct-link proof dashboard completion contract"),
        "pass marker missing from stdout: {stdout}"
    );

    let report = read_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "schema_version")?,
        EXPECTED_REPORT_SCHEMA
    );
    let summary = object_field(&report, "summary")?;
    assert_eq!(
        summary.get("crt_tls_rows").and_then(Value::as_u64),
        Some(EXPECTED_ROW_COUNT as u64)
    );
    assert_eq!(
        summary.get("binding_count").and_then(Value::as_u64),
        Some(2)
    );

    let events = load_jsonl(&checker_log(&out_dir))?;
    let event_names = events
        .iter()
        .map(|event| Ok(string_field(event, "event")?.to_owned()))
        .collect::<TestResult<BTreeSet<_>>>()?;
    for expected in EXPECTED_EVENTS {
        assert!(
            event_names.contains(*expected),
            "missing completion event {expected}"
        );
    }
    Ok(())
}

#[test]
fn checker_replays_crt_tls_source_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "source-gate")?;
    expect_checker_success(&root, &out_dir)?;
    let report = read_json(&checker_report(&out_dir))?;
    let source_results = object_field(&report, "source_gate_results")?;
    let gate = source_results
        .get("crt_tls_gate")
        .and_then(Value::as_object)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "crt_tls_gate missing"))?;
    assert_eq!(gate.get("status").and_then(Value::as_str), Some("pass"));

    let summary = object_field(&report, "summary")?;
    assert_eq!(
        summary
            .get("source_gate_fixture_count")
            .and_then(Value::as_u64),
        Some(8)
    );
    assert_eq!(
        summary
            .get("source_gate_direct_link_execution_rows")
            .and_then(Value::as_u64),
        Some(10)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_dashboard_row() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-row")?;
    let mut dashboard = read_json(&root.join(DASHBOARD_REL))?;
    let rows = dashboard
        .get_mut("rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "dashboard rows missing"))?;
    let index = rows
        .iter()
        .position(|row| {
            row.get("row_id").and_then(Value::as_str)
                == Some("crt-tls-atexit-direct-link-proof-blocked-status")
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target row missing"))?;
    rows.remove(index);
    let dashboard_path = out_dir.join("dashboard-missing-row.json");
    write_json(&dashboard_path, &dashboard)?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_DASHBOARD",
            &dashboard_path,
        )],
    )?;
    expect_checker_failure(output, "dashboard row id set mismatch");
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    let bindings = contract
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bindings missing"))?;
    bindings
        .retain(|binding| binding.get("id").and_then(Value::as_str) != Some("telemetry.primary"));
    let contract_path = out_dir.join("contract-missing-telemetry.json");
    write_json(&contract_path, &contract)?;

    let output = run_checker(&root, &contract_path, &out_dir, &[])?;
    expect_checker_failure(output, "missing_item_bindings mismatch");
    Ok(())
}

#[test]
fn checker_rejects_dashboard_row_count_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "count-drift")?;
    let mut contract = read_json(&root.join(CONTRACT_REL))?;
    contract["completion_contract"]["required_dashboard"]["crt_tls_row_count"] = json!(43);
    let contract_path = out_dir.join("contract-count-drift.json");
    write_json(&contract_path, &contract)?;

    let output = run_checker(&root, &contract_path, &out_dir, &[])?;
    expect_checker_failure(output, "CRT/TLS/atexit dashboard row count mismatch");
    Ok(())
}
