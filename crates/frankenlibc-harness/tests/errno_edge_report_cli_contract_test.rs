//! Conformance gate for the harness binary `errno-edge-report` subcommand.

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
        .join("errno_edge_report_cli_contract.v1.json")
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

fn json_value_string<'a>(value: &'a Value, context: &str) -> TestResult<&'a str> {
    value.as_str().ok_or_else(|| context.to_owned())
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
        "errno_edge_report_cli_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_errno_edge_report_cli(bin: &Path, output: &Path) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("errno-edge-report")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn harness errno-edge-report: {e}"))
}

#[test]
fn manifest_anchors_to_errno_edge_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "errno-edge-report-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-2tq.5", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "errno-edge-report",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "support_matrix_plus_fixture_catalog_plus_conformance_matrix_to_prioritized_errno_edge_json_report",
        "io_pattern mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_create_parent_directories_for_output",
        "must_write_pretty_json_report",
        "must_preserve_bd_2tq_5_report_bead",
        "must_reject_missing_support_matrix_with_nonzero_exit",
        "must_reject_unreadable_fixture_dir_with_nonzero_exit",
        "must_reject_invalid_conformance_matrix_with_nonzero_exit",
        "must_keep_artifact_refs_repo_relative",
        "must_keep_rows_prioritized_by_priority_score",
    ] {
        require(json_bool(policy, key)?, key)?;
    }
    Ok(())
}

#[test]
fn manifest_underlying_lib_functions_are_pinned() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let funcs = m
        .get("underlying_lib_functions")
        .and_then(Value::as_array)
        .ok_or("underlying_lib_functions missing")?;
    let names: Vec<&str> = funcs.iter().filter_map(Value::as_str).collect();
    require(
        names.contains(&"frankenlibc_harness::report::ErrnoEdgeCaseReport::from_paths"),
        "from_paths not pinned",
    )?;
    require(
        names.contains(&"frankenlibc_harness::report::ErrnoEdgeCaseReport::to_json"),
        "to_json not pinned",
    )
}

#[test]
fn harness_source_registers_errno_edge_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ErrnoEdgeReport {"),
        "harness.rs must declare ErrnoEdgeReport Command variant",
    )?;
    require(
        src.contains("ErrnoEdgeCaseReport::from_paths"),
        "ErrnoEdgeReport arm must call ErrnoEdgeCaseReport::from_paths",
    )?;
    require(
        src.contains("failed generating errno edge report"),
        "ErrnoEdgeReport arm must wrap generation failures",
    )?;
    require(
        src.contains("std::fs::write(&output, report.to_json())"),
        "ErrnoEdgeReport arm must write report.to_json()",
    )
}

#[test]
fn cli_writes_report_with_required_summary_and_rows() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("ok")?;
    let output_path = dir.join("nested").join("errno_edge_report.json");
    let out = run_errno_edge_report_cli(&bin, &output_path)?;
    require(
        out.status.success(),
        format!(
            "errno-edge-report failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    require(output_path.exists(), "report output must exist")?;

    let report = load_json(&output_path)?;
    require(
        json_string(&report, "schema_version")? == "v1",
        "schema_version",
    )?;
    require(json_string(&report, "bead")? == "bd-2tq.5", "bead")?;
    let summary = report.get("summary").ok_or("missing summary")?;
    for field in [
        "tracked_symbols",
        "total_edge_cases",
        "errno_cases",
        "covered_edge_cases",
        "failing_edge_cases",
        "execution_error_cases",
        "missing_execution_cases",
        "symbols_with_failures",
    ] {
        require(summary.get(field).and_then(Value::as_u64).is_some(), field)?;
    }

    let rows = json_array(&report, "rows")?;
    require(!rows.is_empty(), "canonical inputs must produce rows")?;
    let mut previous_score = u64::MAX;
    for row in rows.iter().take(32) {
        let priority = row
            .get("priority_score")
            .and_then(Value::as_u64)
            .ok_or("priority_score must be u64")?;
        require(priority <= previous_score, "rows must be priority sorted")?;
        previous_score = priority;
        for field in [
            "trace_id",
            "symbol",
            "symbol_family",
            "owner",
            "support_status",
            "runtime_mode",
            "case_id",
            "spec_section",
            "edge_class",
            "expected_output",
            "status",
            "failure_kind",
            "diff_ref",
        ] {
            require(row.get(field).and_then(Value::as_str).is_some(), field)?;
        }
        require(
            row.get("expected_errno").and_then(Value::as_i64).is_some(),
            "expected_errno",
        )?;
        require(
            row.get("triage_steps")
                .and_then(Value::as_array)
                .is_some_and(|steps| !steps.is_empty()),
            "triage_steps",
        )?;
        let artifact_refs = row
            .get("artifact_refs")
            .and_then(Value::as_array)
            .ok_or("artifact_refs")?;
        require(!artifact_refs.is_empty(), "artifact_refs must not be empty")?;
        for artifact_ref in artifact_refs {
            let path = json_value_string(artifact_ref, "artifact_ref must be string")?;
            require(
                !Path::new(path).is_absolute(),
                "artifact refs repo-relative",
            )?;
        }
    }
    Ok(())
}

#[test]
fn cli_missing_support_matrix_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let root = workspace_root()?;
    let dir = unique_tmp_dir("bad_input")?;
    let missing = dir.join("missing-support-matrix.json");
    let out = Command::new(&bin)
        .arg("errno-edge-report")
        .arg("--support-matrix")
        .arg(&missing)
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--output")
        .arg(dir.join("bad.json"))
        .output()
        .map_err(|e| format!("spawn harness errno-edge-report: {e}"))?;
    require(!out.status.success(), "missing input must fail closed")?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    require(
        diagnostic.contains("failed generating errno edge report")
            || diagnostic.contains("missing-support-matrix.json"),
        "missing support matrix diagnostic",
    )
}
