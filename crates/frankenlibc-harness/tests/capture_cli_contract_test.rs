//! Conformance gate for the harness binary `capture` subcommand.

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
        .join("capture_cli_contract.v1.json")
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
        "capture_cli_contract_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn write_capture_template(dir: &Path) -> TestResult<PathBuf> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir template dir {dir:?}: {e}"))?;
    let path = dir.join("string_alpha.json");
    let body = r#"{
  "version": "v1",
  "family": "string/narrow",
  "captured_at": "2026-05-14T00:00:00Z",
  "cases": [
    {
      "name": "strict_strlen_two",
      "function": "strlen",
      "spec_section": "POSIX.1-2017 strlen",
      "inputs": {"s": [65, 66, 0]},
      "expected_output": "stale-strict",
      "expected_errno": 0,
      "mode": "strict"
    },
    {
      "name": "hardened_strlen_preserved",
      "function": "strlen",
      "spec_section": "TSM hardened strlen",
      "inputs": {"s": [70, 0]},
      "expected_output": "keep-hardened",
      "expected_errno": 0,
      "mode": "hardened"
    },
    {
      "name": "both_strlen_one",
      "function": "strlen",
      "spec_section": "POSIX.1-2017 strlen",
      "inputs": {"s": [90, 0]},
      "expected_output": "stale-both",
      "expected_errno": 0,
      "mode": "both"
    }
  ]
}"#;
    std::fs::write(&path, body).map_err(|e| format!("write template {path:?}: {e}"))?;
    Ok(path)
}

fn write_unmatched_template(dir: &Path) -> TestResult<PathBuf> {
    let path = dir.join("math_cos.json");
    let body = r#"{
  "version": "v1",
  "family": "math",
  "captured_at": "2026-05-14T00:00:00Z",
  "cases": [
    {
      "name": "cos_zero",
      "function": "unsupported_for_this_contract",
      "spec_section": "C11 cos",
      "inputs": {},
      "expected_output": "stale",
      "expected_errno": 0,
      "mode": "strict"
    }
  ]
}"#;
    std::fs::write(&path, body).map_err(|e| format!("write unmatched template {path:?}: {e}"))?;
    Ok(path)
}

fn write_unsupported_template(dir: &Path) -> TestResult<PathBuf> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir template dir {dir:?}: {e}"))?;
    let path = dir.join("string_unsupported.json");
    let body = r#"{
  "version": "v1",
  "family": "string/unsupported",
  "captured_at": "2026-05-14T00:00:00Z",
  "cases": [
    {
      "name": "unsupported_case",
      "function": "__not_a_fixture_exec_symbol",
      "spec_section": "synthetic unsupported",
      "inputs": {},
      "expected_output": "keep-unsupported",
      "expected_errno": 0,
      "mode": "strict"
    }
  ]
}"#;
    std::fs::write(&path, body).map_err(|e| format!("write unsupported template {path:?}: {e}"))?;
    Ok(path)
}

fn run_capture(
    bin: &Path,
    input: &Path,
    output: &Path,
    family: &str,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("capture")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .arg("--family")
        .arg(family)
        .output()
        .map_err(|e| format!("spawn harness capture: {e}"))
}

fn case_by_name<'a>(cases: &'a [Value], name: &str) -> TestResult<&'a Value> {
    cases
        .iter()
        .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| format!("missing case `{name}`"))
}

#[test]
fn manifest_anchors_to_capture_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "capture-cli-contract",
        "manifest_id mismatch",
    )?;
    require(
        json_string(&m, "bead")? == "pending-tracker-capture-cli-contract",
        "bead mismatch",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "capture",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "fixture_template_directory_to_refreshed_fixture_directory",
        "io_pattern mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_create_output_directory",
        "must_sort_input_json_paths",
        "must_filter_by_family_or_file_stem",
        "must_skip_malformed_fixture_json",
        "must_refresh_strict_cases_from_host_output",
        "must_refresh_mode_both_cases_from_host_output",
        "must_preserve_hardened_only_expected_output",
        "must_report_unsupported_cases_as_skipped_warnings",
        "must_fail_closed_when_no_templates_match",
        "must_preserve_original_fixture_filename",
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
        "frankenlibc_harness::capture::capture_family_fixtures",
        "frankenlibc_harness::FixtureSet::from_file",
        "frankenlibc_harness::FixtureSet::to_json",
        "frankenlibc_fixture_exec::execute_fixture_case",
    ] {
        require(
            functions.iter().any(|v| v.as_str() == Some(expected)),
            expected,
        )?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_capture_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("Command::Capture {"),
        "harness.rs must register Command::Capture match arm",
    )?;
    require(
        src.contains("std::fs::create_dir_all(&output)?"),
        "capture arm must create output directory",
    )?;
    require(
        src.contains("capture::capture_family_fixtures"),
        "capture arm must delegate fixture refresh to capture_family_fixtures",
    )?;
    require(
        src.contains("Capture complete: refreshed_cases={}, skipped_cases={}, warnings={}"),
        "capture arm must emit aggregate summary",
    )
}

#[test]
fn cli_refreshes_strict_and_both_cases_while_preserving_hardened_only() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("refresh")?;
    let template_dir = dir.join("templates");
    write_capture_template(&template_dir)?;
    write_unmatched_template(&template_dir)?;
    std::fs::write(template_dir.join("bad.json"), "{not valid json")
        .map_err(|e| format!("write malformed template: {e}"))?;
    let output_dir = dir.join("nested").join("captured");

    let out = run_capture(&bin, &template_dir, &output_dir, "string")?;
    if !out.status.success() {
        return Err(format!(
            "capture command failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("Capturing family='string'"),
        "stderr must name selected family",
    )?;
    require(
        stderr.contains("wrote")
            && stderr.contains("string_alpha.json")
            && stderr.contains("cases=3, refreshed=2, skipped=0"),
        "stderr must report per-file capture stats",
    )?;
    require(
        stderr.contains("Capture complete: refreshed_cases=2, skipped_cases=0, warnings=0"),
        "stderr must report aggregate capture stats",
    )?;

    let output = output_dir.join("string_alpha.json");
    require(
        output.exists(),
        "capture must preserve original fixture filename",
    )?;
    require(
        !output_dir.join("math_cos.json").exists(),
        "capture must not write unmatched family templates",
    )?;
    let fixture = load_json(&output)?;
    let cases = json_array(&fixture, "cases")?;
    require(
        cases.len() == 3,
        "refreshed fixture must preserve all cases",
    )?;
    require(
        case_by_name(cases, "strict_strlen_two")?
            .get("expected_output")
            .and_then(Value::as_str)
            == Some("2"),
        "strict case must be refreshed from host output",
    )?;
    require(
        case_by_name(cases, "both_strlen_one")?
            .get("expected_output")
            .and_then(Value::as_str)
            == Some("1"),
        "mode=both case must be refreshed from host output",
    )?;
    require(
        case_by_name(cases, "hardened_strlen_preserved")?
            .get("expected_output")
            .and_then(Value::as_str)
            == Some("keep-hardened"),
        "hardened-only expected output must be preserved",
    )
}

#[test]
fn cli_reports_unsupported_cases_as_skipped_warnings() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("unsupported")?;
    let template_dir = dir.join("templates");
    write_unsupported_template(&template_dir)?;
    let output_dir = dir.join("captured");

    let out = run_capture(&bin, &template_dir, &output_dir, "unsupported")?;
    if !out.status.success() {
        return Err(format!(
            "capture unsupported command failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("cases=1, refreshed=0, skipped=1"),
        "unsupported capture must count skipped case",
    )?;
    require(
        stderr.contains("capture warning: string/unsupported:unsupported_case capture error:"),
        "unsupported capture must emit warning details",
    )?;
    require(
        stderr.contains("Capture complete: refreshed_cases=0, skipped_cases=1, warnings=1"),
        "unsupported capture must aggregate warnings",
    )?;

    let fixture = load_json(&output_dir.join("string_unsupported.json"))?;
    let cases = json_array(&fixture, "cases")?;
    require(
        case_by_name(cases, "unsupported_case")?
            .get("expected_output")
            .and_then(Value::as_str)
            == Some("keep-unsupported"),
        "unsupported case must preserve stale expected output",
    )
}

#[test]
fn cli_no_matching_templates_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("nomatch")?;
    let template_dir = dir.join("templates");
    std::fs::create_dir_all(&template_dir).map_err(|e| format!("mkdir template dir: {e}"))?;
    write_unmatched_template(&template_dir)?;
    let output_dir = dir.join("captured");

    let out = run_capture(&bin, &template_dir, &output_dir, "string")?;
    require(!out.status.success(), "no matching templates must fail")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("capture failed: no fixture templates matching family='string'"),
        "stderr must preserve no-matching-template diagnostic",
    )
}
