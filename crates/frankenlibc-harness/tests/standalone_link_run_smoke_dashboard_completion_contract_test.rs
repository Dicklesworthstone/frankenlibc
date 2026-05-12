//! Completion contract tests for bd-zyck1.113.1.

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
    "tests/conformance/standalone_link_run_smoke_dashboard_completion_contract.v1.json";
const CHECKER_REL: &str =
    "scripts/check_standalone_link_run_smoke_dashboard_completion_contract.sh";
const DASHBOARD_REL: &str = "tests/conformance/l1_dry_run_readiness_dashboard.v1.json";
const EXPECTED_SCHEMA: &str = "standalone_link_run_smoke_dashboard_completion_contract.v1";
const EXPECTED_REPORT_SCHEMA: &str =
    "standalone_link_run_smoke_dashboard_completion_contract.report.v1";
const EXPECTED_MISSING_ITEMS: &[&str] = &["telemetry.primary", "tests.conformance.primary"];
const EXPECTED_EVENTS: &[&str] = &[
    "standalone_smoke_dashboard_sources_validated",
    "standalone_smoke_dashboard_rows_validated",
    "standalone_smoke_dashboard_bindings_validated",
    "standalone_smoke_dashboard_source_gates_replayed",
    "standalone_smoke_dashboard_completion_contract_pass",
];
const EXPECTED_ROW_COUNT: usize = 35;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("manifest should live under workspace root"))?
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
        "standalone-smoke-dashboard-completion-{label}-{}-{nanos}",
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
            "FRANKENLIBC_STANDALONE_SMOKE_DASHBOARD_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_STANDALONE_SMOKE_DASHBOARD_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_STANDALONE_SMOKE_DASHBOARD_COMPLETION_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_STANDALONE_SMOKE_DASHBOARD_COMPLETION_LOG",
            checker_log(out_dir),
        )
        .env(
            "FRANKENLIBC_STANDALONE_SMOKE_DASHBOARD_COMPLETION_GATE_DIR",
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

fn standalone_rows(dashboard: &Value) -> TestResult<Vec<&Value>> {
    Ok(array_field(dashboard, "rows")?
        .iter()
        .filter(|row| {
            row.get("row_id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with("standalone-link-run-smoke"))
        })
        .collect())
}

#[test]
fn contract_binds_dashboard_conformance_and_telemetry() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-zyck1.113.1");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-zyck1.113");

    let source_artifacts = object_field(&manifest, "source_artifacts")?;
    for (artifact_id, path) in source_artifacts {
        let path = path.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{artifact_id} path should be a string"),
            )
        })?;
        assert!(
            root.join(path).exists(),
            "source artifact should exist: {artifact_id} -> {path}"
        );
    }

    let completion = manifest
        .get("completion_contract")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion contract missing"))?;
    assert_eq!(
        string_set(array_field(completion, "missing_item_ids")?)?,
        EXPECTED_MISSING_ITEMS
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let required_dashboard = object_field(completion, "required_dashboard")?;
    let required_rows = required_dashboard
        .get("required_row_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required rows missing"))?;
    assert_eq!(required_rows.len(), EXPECTED_ROW_COUNT);

    let dashboard = read_json(&root.join(DASHBOARD_REL))?;
    assert_eq!(standalone_rows(&dashboard)?.len(), EXPECTED_ROW_COUNT);
    Ok(())
}

#[test]
fn checker_accepts_dashboard_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: standalone link-run smoke dashboard completion contract"),
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
        summary.get("standalone_smoke_rows").and_then(Value::as_u64),
        Some(35)
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
fn checker_replays_standalone_smoke_source_gates() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "source-gates")?;
    expect_checker_success(&root, &out_dir)?;
    let report = read_json(&checker_report(&out_dir))?;
    let gates = object_field(&report, "source_gate_results")?;
    assert!(gates.contains_key("standalone_smoke_dry_run"));
    assert!(gates.contains_key("standalone_smoke_completion_gate"));
    assert!(
        out_dir
            .join("source_gates/standalone_link_run_smoke.report.json")
            .exists(),
        "standalone smoke dry-run report should be captured"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_dashboard_row() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-row")?;
    let contract_path = out_dir.join("contract.missing-row.json");
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let required_rows = manifest
        .pointer_mut("/completion_contract/required_dashboard/required_row_ids")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required rows missing"))?;
    required_rows.push(json!("standalone-link-run-smoke-nonexistent-row"));
    write_json(&contract_path, &manifest)?;

    let output = run_checker(&root, &contract_path, &out_dir, &[])?;
    expect_checker_failure(output, "missing_dashboard_row");
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let contract_path = out_dir.join("contract.missing-telemetry.json");
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing_item_bindings missing")
        })?;
    bindings
        .retain(|binding| binding.get("id").and_then(Value::as_str) != Some("telemetry.primary"));
    write_json(&contract_path, &manifest)?;

    let output = run_checker(&root, &contract_path, &out_dir, &[])?;
    expect_checker_failure(output, "missing_telemetry_binding");
    Ok(())
}

#[test]
fn checker_rejects_dashboard_row_count_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "row-count-drift")?;
    let dashboard_path = out_dir.join("l1_dashboard.drift.json");
    let mut dashboard = read_json(&root.join(DASHBOARD_REL))?;
    let rows = dashboard
        .get_mut("rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "rows missing"))?;
    rows.retain(|row| {
        row.get("row_id").and_then(Value::as_str)
            != Some("standalone-link-run-smoke-claim-blocked-policy")
    });
    write_json(&dashboard_path, &dashboard)?;

    let output = run_checker(
        &root,
        &root.join(CONTRACT_REL),
        &out_dir,
        &[(
            "FRANKENLIBC_STANDALONE_SMOKE_DASHBOARD_COMPLETION_DASHBOARD",
            dashboard_path.as_path(),
        )],
    )?;
    expect_checker_failure(output, "dashboard_row_count_drift");
    Ok(())
}
