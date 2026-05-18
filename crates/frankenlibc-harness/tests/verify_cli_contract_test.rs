//! Conformance gate for the harness binary `verify` subcommand.

use std::path::{Path, PathBuf};
use std::process::Command;

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
        .join("verify_cli_contract.v1.json")
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

fn json_object<'a>(
    value: &'a Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing or non-object `{field}`"))
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
    if let Some(bin) = option_env!("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(bin));
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

fn unique_tmp_dir(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "verify_cli_contract_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn write_fixture_set(dir: &Path, expected_output: &str) -> TestResult<PathBuf> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir fixture dir {dir:?}: {e}"))?;
    let path = dir.join("string_strlen.json");
    let body = format!(
        r#"{{
  "version": "v1",
  "family": "string",
  "captured_at": "2026-05-14T00:00:00Z",
  "cases": [
    {{
      "name": "strlen_one_byte",
      "function": "strlen",
      "spec_section": "POSIX.1-2017 strlen",
      "inputs": {{"s": [65, 0]}},
      "expected_output": "{expected_output}",
      "expected_errno": 0,
      "mode": "both"
    }}
  ]
}}"#
    );
    std::fs::write(&path, body).map_err(|e| format!("write fixture {path:?}: {e}"))?;
    Ok(path)
}

fn run_verify(
    bin: &Path,
    fixture_dir: &Path,
    report: Option<&Path>,
) -> TestResult<std::process::Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("verify")
        .arg("--fixture")
        .arg(fixture_dir)
        .arg("--timestamp")
        .arg("2026-05-14T00:00:00Z");
    if let Some(report) = report {
        cmd.arg("--report").arg(report);
    }
    cmd.output()
        .map_err(|e| format!("spawn harness verify: {e}"))
}

fn validate_success_report(report: &Value) -> TestResult {
    require(
        json_string(report, "title")? == "frankenlibc Conformance Report",
        "title mismatch",
    )?;
    require(
        json_string(report, "mode")? == "strict+hardened",
        "mode mismatch",
    )?;
    require(
        json_string(report, "timestamp")? == "2026-05-14T00:00:00Z",
        "timestamp must preserve CLI input",
    )?;

    let summary = json_object(report, "summary")?;
    require(
        object_u64(summary, "total")? == 2,
        "mode=both fixture must run under strict and hardened",
    )?;
    require(object_u64(summary, "passed")? == 2, "passed count mismatch")?;
    require(object_u64(summary, "failed")? == 0, "failed count mismatch")?;

    let results = summary
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "summary.results must be an array".to_string())?;
    require(results.len() == 2, "expected exactly two mode results")?;
    let modes = results
        .iter()
        .map(|row| {
            row.get("mode")
                .and_then(Value::as_str)
                .ok_or_else(|| "result.mode must be a string".to_string())
        })
        .collect::<TestResult<Vec<_>>>()?;
    require(
        modes == ["hardened", "strict"] || modes == ["strict", "hardened"],
        format!("unexpected mode results: {modes:?}"),
    )?;
    for row in results {
        require(
            row.get("trace_id")
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains("fixture-verify::string::strlen::")),
            "trace_id must include campaign, family, symbol, and mode",
        )?;
        require(
            row.get("case_name")
                .and_then(Value::as_str)
                .is_some_and(|s| {
                    s == "strlen_one_byte [strict]" || s == "strlen_one_byte [hardened]"
                }),
            "mode=both case names must include execution mode suffix",
        )?;
        require(
            row.get("passed").and_then(Value::as_bool) == Some(true),
            "all sample rows must pass",
        )?;
        require(
            row.get("actual").and_then(Value::as_str) == Some("1"),
            "sample strlen output mismatch",
        )?;
    }
    Ok(())
}

fn object_u64(map: &serde_json::Map<String, Value>, field: &str) -> TestResult<u64> {
    map.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
}

#[test]
fn manifest_anchors_to_verify_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "verify-cli-contract",
        "manifest_id mismatch",
    )?;
    require(
        json_string(&m, "bead")? == "pending-tracker-verify-cli-contract",
        "bead mismatch",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "verify",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "fixture_directory_to_markdown_json_and_suite_conformance_report",
        "io_pattern mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_sort_fixture_json_paths",
        "must_skip_malformed_fixture_json_with_diagnostic",
        "must_reject_empty_or_fully_invalid_fixture_directory",
        "must_run_mode_both_cases_under_strict_and_hardened",
        "must_preserve_caller_timestamp",
        "must_write_markdown_report_when_report_flag_is_present",
        "must_write_paired_json_report_when_report_flag_is_present",
        "must_write_asupersync_suite_report_when_feature_enabled",
        "must_emit_nonzero_exit_when_any_case_fails",
        "must_preserve_failure_rows_in_report_before_exit",
    ] {
        require(json_bool(policy, key)?, key)?;
    }
    Ok(())
}

#[test]
fn manifest_underlying_lib_functions_are_pinned() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let functions = json_array(&m, "underlying_lib_functions")?;
    for expected in [
        "frankenlibc_harness::FixtureSet::from_file",
        "frankenlibc_harness::asupersync_orchestrator::run_fixture_verification",
        "frankenlibc_harness::TestRunner::run",
        "frankenlibc_harness::verify::VerificationSummary::from_results",
        "frankenlibc_harness::ConformanceReport::to_markdown",
        "frankenlibc_harness::ConformanceReport::to_json",
    ] {
        require(
            functions.iter().any(|v| v.as_str() == Some(expected)),
            expected,
        )?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_verify_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("Command::Verify {"),
        "harness.rs must register Command::Verify match arm",
    )?;
    require(
        src.contains("FixtureSet::from_file"),
        "verify arm must load fixture JSON via FixtureSet::from_file",
    )?;
    require(
        src.contains("run_fixture_verification"),
        "verify arm must use asupersync orchestration when enabled",
    )?;
    require(
        src.contains("VerificationSummary::from_results"),
        "verify arm must aggregate VerificationSummary",
    )?;
    require(
        src.contains("Conformance verification failed"),
        "verify arm must fail closed when any fixture case fails",
    )
}

#[test]
fn cli_writes_markdown_json_and_suite_reports_for_passing_fixtures() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("pass")?;
    let fixture_dir = dir.join("fixtures");
    write_fixture_set(&fixture_dir, "1")?;
    let report_dir = dir.join("reports");
    std::fs::create_dir_all(&report_dir).map_err(|e| format!("mkdir report dir: {e}"))?;
    let report = report_dir.join("verify.current.md");

    let out = run_verify(&bin, &fixture_dir, Some(&report))?;
    if !out.status.success() {
        return Err(format!(
            "verify command failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("Verifying against fixtures in"),
        "stderr must name fixture directory",
    )?;
    require(
        stderr.contains("Verification complete: total=2, passed=2, failed=0"),
        "stderr must summarize pass totals",
    )?;
    require(report.exists(), "markdown report must be written")?;
    let markdown =
        std::fs::read_to_string(&report).map_err(|e| format!("read markdown report: {e}"))?;
    require(
        markdown.contains("# frankenlibc Conformance Report"),
        "markdown heading mismatch",
    )?;
    require(
        markdown.contains("| `fixture-verify::string::strlen::strict::strlen_one_byte` |"),
        "markdown must include strict trace row",
    )?;
    require(
        markdown.contains("| `fixture-verify::string::strlen::hardened::strlen_one_byte` |"),
        "markdown must include hardened trace row",
    )?;

    let json_report = load_json(&report.with_extension("json"))?;
    validate_success_report(&json_report)?;

    #[cfg(feature = "asupersync-tooling")]
    {
        let suite = load_json(&report.with_extension("suite.json"))?;
        require(
            json_u64(&suite, "total")? == 2,
            "suite report must include both mode executions",
        )?;
        require(json_u64(&suite, "passed")? == 2, "suite passed mismatch")?;
        require(json_u64(&suite, "failed")? == 0, "suite failed mismatch")?;
    }

    Ok(())
}

#[test]
fn cli_empty_fixture_dir_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("empty")?;
    let fixture_dir = dir.join("fixtures");
    std::fs::create_dir_all(&fixture_dir).map_err(|e| format!("mkdir fixture dir: {e}"))?;

    let out = run_verify(&bin, &fixture_dir, None)?;
    require(!out.status.success(), "empty fixture dir must fail")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("No fixture JSON files found in"),
        "stderr must preserve empty fixture diagnostic",
    )
}

#[test]
fn cli_malformed_fixture_is_skipped_but_valid_fixture_still_runs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("malformed")?;
    let fixture_dir = dir.join("fixtures");
    write_fixture_set(&fixture_dir, "1")?;
    let bad_path = fixture_dir.join("bad.json");
    std::fs::write(&bad_path, "{not valid json")
        .map_err(|e| format!("write malformed fixture: {e}"))?;
    let report_dir = dir.join("reports");
    std::fs::create_dir_all(&report_dir).map_err(|e| format!("mkdir report dir: {e}"))?;
    let report = report_dir.join("verify.current.md");

    let out = run_verify(&bin, &fixture_dir, Some(&report))?;
    if !out.status.success() {
        return Err(format!(
            "verify command with one malformed fixture failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("Skipping"),
        "stderr must report skipped malformed fixture",
    )?;
    require(
        stderr.contains("bad.json"),
        "stderr must name malformed fixture path",
    )?;
    validate_success_report(&load_json(&report.with_extension("json"))?)
}

#[test]
fn cli_mismatched_fixture_fails_after_writing_failure_report() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("fail")?;
    let fixture_dir = dir.join("fixtures");
    write_fixture_set(&fixture_dir, "2")?;
    let report_dir = dir.join("reports");
    std::fs::create_dir_all(&report_dir).map_err(|e| format!("mkdir report dir: {e}"))?;
    let report = report_dir.join("verify.current.md");

    let out = run_verify(&bin, &fixture_dir, Some(&report))?;
    require(!out.status.success(), "mismatched fixture must fail")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("Verification complete: total=2, passed=0, failed=2"),
        "stderr must summarize failing totals",
    )?;
    require(
        stderr.contains("Conformance verification failed"),
        "stderr must preserve fail-closed diagnostic",
    )?;

    let json_report = load_json(&report.with_extension("json"))?;
    let summary = json_object(&json_report, "summary")?;
    require(object_u64(summary, "total")? == 2, "failure total mismatch")?;
    require(
        object_u64(summary, "passed")? == 0,
        "failure passed mismatch",
    )?;
    require(
        object_u64(summary, "failed")? == 2,
        "failure failed mismatch",
    )?;
    let rows = summary
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "summary.results must be an array".to_string())?;
    require(
        rows.iter()
            .all(|row| row.get("passed").and_then(Value::as_bool) == Some(false)),
        "all mismatch rows must be marked failed",
    )?;
    require(
        rows.iter().all(|row| row.get("diff").is_some()),
        "all mismatch rows must preserve diff evidence",
    )
}
