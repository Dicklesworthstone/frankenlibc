//! Conformance gate for the harness binary `conformance-matrix`
//! subcommand.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("conformance_matrix_cli_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn cargo_target_dir_for_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(p)
    } else if let Ok(p) = std::env::var("CARGO_MANIFEST_DIR") {
        Path::new(&p)
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join("target"))
            .unwrap_or_else(|| PathBuf::from("target"))
    } else {
        PathBuf::from("target")
    }
}

fn find_harness_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(path));
    }
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn unique_tmp_dir(label: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc_conformance_matrix_cli_contract_{label}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    Ok(dir)
}

fn write_fixture(dir: &Path, expected_output: &str) -> TestResult<PathBuf> {
    let fixture_path = dir.join("string_ops_cli_contract_fixture.v1.json");
    let fixture = serde_json::json!({
        "version": "v1",
        "family": "cli-contract/string",
        "captured_at": "2026-05-14T00:00:00Z",
        "cases": [
            {
                "name": "strlen_one_byte",
                "function": "strlen",
                "spec_section": "POSIX strlen",
                "inputs": { "s": [97, 0] },
                "expected_output": expected_output,
                "expected_errno": 0,
                "mode": "both"
            }
        ]
    });
    let body = serde_json::to_string_pretty(&fixture).map_err(|err| err.to_string())?;
    std::fs::write(&fixture_path, body).map_err(|e| format!("write {fixture_path:?}: {e}"))?;
    Ok(fixture_path)
}

fn run_conformance_matrix(
    bin: &Path,
    fixture_dir: &Path,
    output: &Path,
    log: &Path,
    mode: &str,
    campaign: &str,
    fail_on_mismatch: bool,
) -> TestResult<Output> {
    let root = workspace_root()?;
    let mut cmd = Command::new(bin);
    cmd.current_dir(root)
        .arg("conformance-matrix")
        .arg("--fixture")
        .arg(fixture_dir)
        .arg("--output")
        .arg(output)
        .arg("--log")
        .arg(log)
        .arg("--mode")
        .arg(mode)
        .arg("--campaign")
        .arg(campaign)
        .arg("--perf-budget-ms")
        .arg("1");
    if fail_on_mismatch {
        cmd.arg("--fail-on-mismatch");
    }
    cmd.output()
        .map_err(|err| format!("run conformance-matrix: {err}"))
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| format!("parse log row: {err}")))
        .collect()
}

#[test]
fn manifest_anchors_conformance_matrix_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "conformance-matrix-cli-contract",
        "manifest_id",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "conformance-matrix",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "binary_target")? == "harness",
        "binary_target",
    )?;
    let required_flags: Vec<&str> = json_array(&m, "required_flags")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(required_flags == ["--fixture"], "required_flags")
}

#[test]
fn manifest_policy_pins_cli_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "must_register_conformance_matrix_subcommand",
        "must_require_fixture_directory",
        "must_reject_unknown_mode_before_writing_outputs",
        "must_write_report_and_log_paths",
        "must_preserve_campaign_and_mode_metadata",
        "must_emit_structured_conformance_log_rows",
        "fail_on_mismatch_must_exit_nonzero_after_artifacts",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }

    let output = m
        .get("output_contract")
        .ok_or_else(|| "missing output_contract".to_string())?;
    let matrix_fields: Vec<&str> = json_array(output, "matrix_required_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in [
        "schema_version",
        "campaign",
        "mode",
        "summary",
        "symbol_matrix",
        "cases",
    ] {
        require(
            matrix_fields.contains(&field),
            format!("matrix_required_fields missing {field}"),
        )?;
    }
    require(
        json_bool(output, "writes_report_before_fail_on_mismatch_exit")?,
        "fail-on-mismatch artifact policy",
    )
}

#[test]
fn cli_writes_matrix_report_and_structured_log() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let tmp = unique_tmp_dir("success")?;
    write_fixture(&tmp, "1")?;
    let report_path = tmp.join("matrix.current.v1.json");
    let log_path = tmp.join("matrix.log.jsonl");

    let run = run_conformance_matrix(
        &bin,
        &tmp,
        &report_path,
        &log_path,
        "strict",
        "cli-contract",
        false,
    )?;
    require(
        run.status.success(),
        format!(
            "conformance-matrix failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        ),
    )?;

    let report = load_json(&report_path)?;
    require(
        report.get("schema_version").and_then(Value::as_str) == Some("v1"),
        "report schema_version",
    )?;
    require(
        report.get("campaign").and_then(Value::as_str) == Some("cli-contract"),
        "report campaign",
    )?;
    require(
        report.get("mode").and_then(Value::as_str) == Some("strict"),
        "report mode",
    )?;
    require(
        report.get("total_fixture_sets").and_then(Value::as_u64) == Some(1),
        "total_fixture_sets",
    )?;
    let summary = report
        .get("summary")
        .ok_or_else(|| "missing summary".to_string())?;
    require(
        summary.get("total_cases").and_then(Value::as_u64) == Some(1),
        "summary.total_cases",
    )?;
    require(
        summary.get("passed").and_then(Value::as_u64) == Some(1),
        "summary.passed",
    )?;
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing cases".to_string())?;
    require(cases.len() == 1, "strict mode should emit one case")?;
    let case = &cases[0];
    require(
        case.get("symbol").and_then(Value::as_str) == Some("strlen"),
        "case symbol",
    )?;
    require(
        case.get("status").and_then(Value::as_str) == Some("pass"),
        "case status",
    )?;
    require(
        case.get("trace_id")
            .and_then(Value::as_str)
            .is_some_and(|trace_id| trace_id.contains("cli-contract")),
        "trace_id campaign",
    )?;

    let rows = read_jsonl(&log_path)?;
    require(!rows.is_empty(), "structured log should not be empty")?;
    let event_names: Vec<&str> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for event in [
        "conformance.runtime_mode_startup",
        "conformance.fixture_execution",
        "conformance.shadow_run_divergence",
        "conformance.fixture_summary",
        "conformance.benchmark_result",
    ] {
        require(
            event_names.contains(&event),
            format!("missing structured log event {event}"),
        )?;
    }
    let case_row = rows
        .iter()
        .find(|row| {
            row.get("event").and_then(Value::as_str) == Some("conformance.fixture_execution")
        })
        .ok_or_else(|| "missing fixture_execution row".to_string())?;
    for field in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "outcome",
        "artifact_refs",
    ] {
        require(
            case_row.get(field).is_some(),
            format!("case log missing {field}"),
        )?;
    }
    Ok(())
}

#[test]
fn cli_rejects_unknown_mode_without_writing_outputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let tmp = unique_tmp_dir("bad_mode")?;
    write_fixture(&tmp, "1")?;
    let report_path = tmp.join("bad-mode-report.json");
    let log_path = tmp.join("bad-mode.log.jsonl");

    let run = run_conformance_matrix(
        &bin,
        &tmp,
        &report_path,
        &log_path,
        "reckless",
        "cli-contract-bad-mode",
        false,
    )?;
    require(!run.status.success(), "unknown mode should fail")?;
    let stderr = String::from_utf8_lossy(&run.stderr);
    require(
        stderr.contains("Unsupported mode 'reckless'"),
        format!("unexpected stderr: {stderr}"),
    )?;
    require(!report_path.exists(), "unknown mode wrote report")?;
    require(!log_path.exists(), "unknown mode wrote log")
}

#[test]
fn fail_on_mismatch_exits_nonzero_after_writing_artifacts() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let tmp = unique_tmp_dir("mismatch")?;
    write_fixture(&tmp, "99")?;
    let report_path = tmp.join("mismatch-report.json");
    let log_path = tmp.join("mismatch.log.jsonl");

    let run = run_conformance_matrix(
        &bin,
        &tmp,
        &report_path,
        &log_path,
        "strict",
        "cli-contract-mismatch",
        true,
    )?;
    require(!run.status.success(), "--fail-on-mismatch should fail")?;
    let stderr = String::from_utf8_lossy(&run.stderr);
    require(
        stderr.contains("Conformance matrix mismatch"),
        format!("unexpected stderr: {stderr}"),
    )?;
    let report = load_json(&report_path)?;
    let summary = report
        .get("summary")
        .ok_or_else(|| "missing summary".to_string())?;
    require(
        summary.get("failed").and_then(Value::as_u64) == Some(1),
        "failed count",
    )?;
    require(
        !read_jsonl(&log_path)?.is_empty(),
        "mismatch run should still write structured log rows",
    )
}
