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

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
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
    let mut cmd = Command::new(bin);
    cmd.arg("conformance-matrix")
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
    for (field, message) in [
        (
            "must_register_conformance_matrix_subcommand",
            "must_register_conformance_matrix_subcommand must be true",
        ),
        (
            "must_require_fixture_directory",
            "must_require_fixture_directory must be true",
        ),
        (
            "must_reject_unknown_mode_before_writing_outputs",
            "must_reject_unknown_mode_before_writing_outputs must be true",
        ),
        (
            "must_write_report_and_log_paths",
            "must_write_report_and_log_paths must be true",
        ),
        (
            "must_preserve_campaign_and_mode_metadata",
            "must_preserve_campaign_and_mode_metadata must be true",
        ),
        (
            "must_emit_structured_conformance_log_rows",
            "must_emit_structured_conformance_log_rows must be true",
        ),
        (
            "fail_on_mismatch_must_exit_nonzero_after_artifacts",
            "fail_on_mismatch_must_exit_nonzero_after_artifacts must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }

    let output = m
        .get("output_contract")
        .ok_or_else(|| "missing output_contract".to_string())?;
    let matrix_fields: Vec<&str> = json_array(output, "matrix_required_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for (field, message) in [
        (
            "schema_version",
            "matrix_required_fields missing schema_version",
        ),
        ("campaign", "matrix_required_fields missing campaign"),
        ("mode", "matrix_required_fields missing mode"),
        ("summary", "matrix_required_fields missing summary"),
        (
            "symbol_matrix",
            "matrix_required_fields missing symbol_matrix",
        ),
        ("cases", "matrix_required_fields missing cases"),
    ] {
        require(matrix_fields.contains(&field), message)?;
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
        json_string(&report, "schema_version")? == "v1",
        "report schema_version",
    )?;
    require(
        json_string(&report, "campaign")? == "cli-contract",
        "report campaign",
    )?;
    require(json_string(&report, "mode")? == "strict", "report mode")?;
    require(
        json_u64(&report, "total_fixture_sets")? == 1,
        "total_fixture_sets",
    )?;
    let summary = report
        .get("summary")
        .ok_or_else(|| "missing summary".to_string())?;
    require(
        json_u64(summary, "total_cases")? == 1,
        "summary.total_cases",
    )?;
    require(json_u64(summary, "passed")? == 1, "summary.passed")?;
    let cases = json_array(&report, "cases")?;
    require(cases.len() == 1, "strict mode should emit one case")?;
    let case = cases
        .first()
        .ok_or_else(|| "strict mode should emit one case".to_string())?;
    require(json_string(case, "symbol")? == "strlen", "case symbol")?;
    require(json_string(case, "status")? == "pass", "case status")?;
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
    for (event, message) in [
        (
            "conformance.runtime_mode_startup",
            "missing structured log event conformance.runtime_mode_startup",
        ),
        (
            "conformance.fixture_execution",
            "missing structured log event conformance.fixture_execution",
        ),
        (
            "conformance.shadow_run_divergence",
            "missing structured log event conformance.shadow_run_divergence",
        ),
        (
            "conformance.fixture_summary",
            "missing structured log event conformance.fixture_summary",
        ),
        (
            "conformance.benchmark_result",
            "missing structured log event conformance.benchmark_result",
        ),
    ] {
        require(event_names.contains(&event), message)?;
    }
    let case_row = rows
        .iter()
        .find(|row| {
            row.get("event").and_then(Value::as_str) == Some("conformance.fixture_execution")
        })
        .ok_or_else(|| "missing fixture_execution row".to_string())?;
    for (field, message) in [
        ("trace_id", "case log missing trace_id"),
        ("mode", "case log missing mode"),
        ("api_family", "case log missing api_family"),
        ("symbol", "case log missing symbol"),
        ("outcome", "case log missing outcome"),
        ("artifact_refs", "case log missing artifact_refs"),
    ] {
        require(case_row.get(field).is_some(), message)?;
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
