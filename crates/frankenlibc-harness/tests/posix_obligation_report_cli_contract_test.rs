//! Conformance gate for the harness binary `posix-obligation-report` subcommand.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value};

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
        .join("posix_obligation_report_cli_contract.v1.json")
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

fn json_object<'a>(value: &'a Value, field: &str) -> TestResult<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing or non-object `{field}`"))
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
        "posix_obligation_report_cli_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_posix_obligation_report_cli(bin: &Path, output: &Path) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("posix-obligation-report")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--c-fixture-spec")
        .arg(root.join("tests/conformance/c_fixture_spec.json"))
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn harness posix-obligation-report: {e}"))
}

#[test]
fn manifest_anchors_to_posix_obligation_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "posix-obligation-report-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-2tq.4", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "posix-obligation-report",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "support_matrix_plus_fixture_catalog_plus_conformance_matrix_plus_c_fixture_spec_to_posix_obligation_json_report",
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
        "must_preserve_bd_2tq_4_report_bead",
        "must_reject_missing_support_matrix_with_nonzero_exit",
        "must_reject_unreadable_fixture_dir_with_nonzero_exit",
        "must_reject_invalid_conformance_matrix_with_nonzero_exit",
        "must_reject_missing_c_fixture_spec_with_nonzero_exit",
        "must_keep_artifact_refs_repo_relative",
        "must_keep_obligations_sorted",
    ] {
        require(json_bool(policy, key)?, format!("{key} must be true"))?;
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
        names.contains(&"frankenlibc_harness::report::PosixObligationMatrixReport::from_paths"),
        "from_paths not pinned",
    )?;
    require(
        names.contains(&"frankenlibc_harness::report::PosixObligationMatrixReport::to_json"),
        "to_json not pinned",
    )
}

#[test]
fn harness_source_registers_posix_obligation_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("PosixObligationReport {"),
        "harness.rs must declare PosixObligationReport Command variant",
    )?;
    require(
        src.contains("PosixObligationMatrixReport::from_paths"),
        "PosixObligationReport arm must call PosixObligationMatrixReport::from_paths",
    )?;
    require(
        src.contains("failed generating POSIX obligation report"),
        "PosixObligationReport arm must wrap generation failures",
    )?;
    require(
        src.contains("std::fs::write(&output, report.to_json())"),
        "PosixObligationReport arm must write report.to_json()",
    )
}

#[test]
fn cli_writes_report_with_required_obligation_and_gap_rows() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("ok")?;
    let output_path = dir
        .join("nested")
        .join("posix_obligation_matrix.current.v1.json");
    let out = run_posix_obligation_report_cli(&bin, &output_path)?;
    require(
        out.status.success(),
        format!(
            "posix-obligation-report failed: status={:?} stderr={}",
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
    require(json_string(&report, "bead")? == "bd-2tq.4", "bead")?;
    let summary = report.get("summary").ok_or("missing summary")?;
    for field in [
        "total_exported",
        "tracked_symbols",
        "total_obligations",
        "covered_obligations",
        "mapped_without_execution",
        "obligations_with_execution_failures",
        "error_condition_obligations",
        "async_concurrency_obligations",
        "symbols_missing_any_mapping",
        "symbols_missing_execution_evidence",
        "symbols_missing_error_conditions",
        "symbols_missing_async_concurrency",
    ] {
        require(summary.get(field).and_then(Value::as_u64).is_some(), field)?;
    }

    let obligations = json_array(&report, "obligations")?;
    require(
        !obligations.is_empty(),
        "canonical inputs must produce obligations",
    )?;
    for (left, right) in obligations.iter().zip(obligations.iter().skip(1)).take(63) {
        let left_symbol = json_string(left, "symbol")?;
        let left_posix_ref = json_string(left, "posix_ref")?;
        let right_symbol = json_string(right, "symbol")?;
        let right_posix_ref = json_string(right, "posix_ref")?;
        require(
            left_symbol < right_symbol
                || (left_symbol == right_symbol && left_posix_ref <= right_posix_ref),
            "obligations must be sorted by symbol then posix_ref",
        )?;
    }
    for row in obligations.iter().take(64) {
        for field in [
            "obligation_id",
            "posix_ref",
            "symbol",
            "symbol_family",
            "owner",
            "support_status",
            "coverage_state",
        ] {
            require(row.get(field).and_then(Value::as_str).is_some(), field)?;
        }
        for field in ["obligation_kinds", "modes", "test_refs", "artifact_refs"] {
            require(row.get(field).and_then(Value::as_array).is_some(), field)?;
        }
        require(
            !json_array(row, "test_refs")?.is_empty(),
            "test_refs must not be empty",
        )?;
        let artifact_refs = json_array(row, "artifact_refs")?;
        for artifact_ref in artifact_refs {
            let path = json_value_string(artifact_ref, "artifact_ref must be string")?;
            require(
                !Path::new(path).is_absolute(),
                "artifact refs repo-relative",
            )?;
        }
        let execution = json_object(row, "execution")?;
        for field in ["total", "pass", "fail", "error", "timeout", "crash"] {
            require(
                execution.get(field).and_then(Value::as_u64).is_some(),
                field,
            )?;
        }
    }

    let gaps = json_array(&report, "gaps")?;
    for gap in gaps.iter().take(64) {
        for field in ["symbol", "symbol_family", "owner", "support_status"] {
            require(gap.get(field).and_then(Value::as_str).is_some(), field)?;
        }
        for field in ["mapped_posix_refs", "test_refs", "gap_reasons"] {
            require(gap.get(field).and_then(Value::as_array).is_some(), field)?;
        }
        require(
            !json_array(gap, "gap_reasons")?.is_empty(),
            "gap_reasons must not be empty",
        )?;
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
        .arg("posix-obligation-report")
        .arg("--support-matrix")
        .arg(&missing)
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--c-fixture-spec")
        .arg(root.join("tests/conformance/c_fixture_spec.json"))
        .arg("--output")
        .arg(dir.join("bad.json"))
        .output()
        .map_err(|e| format!("spawn harness posix-obligation-report: {e}"))?;
    require(!out.status.success(), "missing input must fail closed")?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    require(
        diagnostic.contains("failed generating POSIX obligation report")
            || diagnostic.contains("missing-support-matrix.json"),
        "missing support matrix diagnostic",
    )
}
