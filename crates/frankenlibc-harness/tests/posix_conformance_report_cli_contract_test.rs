//! Conformance gate for the harness binary `posix-conformance-report` subcommand.

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
        .join("posix_conformance_report_cli_contract.v1.json")
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
        "posix_conformance_report_cli_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_posix_conformance_report_cli(bin: &Path, output: &Path) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("posix-conformance-report")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn harness posix-conformance-report: {e}"))
}

#[test]
fn manifest_anchors_to_posix_conformance_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "posix-conformance-report-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-s1amj", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "posix-conformance-report",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "support_matrix_plus_fixture_catalog_plus_conformance_matrix_to_posix_coverage_json_report",
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
        "must_preserve_bd_18qq_7_report_bead",
        "must_reject_missing_support_matrix_with_nonzero_exit",
        "must_reject_unreadable_fixture_dir_with_nonzero_exit",
        "must_reject_invalid_conformance_matrix_with_nonzero_exit",
        "must_keep_symbols_sorted_by_name",
        "must_preserve_case_count_category_accounting",
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
        names.contains(&"frankenlibc_harness::report::PosixConformanceReport::from_paths"),
        "from_paths not pinned",
    )?;
    require(
        names.contains(&"frankenlibc_harness::report::PosixConformanceReport::to_json"),
        "to_json not pinned",
    )
}

#[test]
fn harness_source_registers_posix_conformance_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("PosixConformanceReport {"),
        "harness.rs must declare PosixConformanceReport Command variant",
    )?;
    require(
        src.contains("PosixConformanceReport::from_paths"),
        "PosixConformanceReport arm must call PosixConformanceReport::from_paths",
    )?;
    require(
        src.contains("failed generating POSIX conformance report"),
        "PosixConformanceReport arm must wrap generation failures",
    )?;
    require(
        src.contains("std::fs::write(&output, report.to_json())"),
        "PosixConformanceReport arm must write report.to_json()",
    )
}

#[test]
fn cli_writes_report_with_required_summary_and_symbol_rows() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("ok")?;
    let output_path = dir
        .join("nested")
        .join("posix_conformance_report.current.v1.json");
    let out = run_posix_conformance_report_cli(&bin, &output_path)?;
    require(
        out.status.success(),
        format!(
            "posix-conformance-report failed: status={:?} stderr={}",
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
    require(json_string(&report, "bead")? == "bd-18qq.7", "bead")?;
    let summary = report.get("summary").ok_or("missing summary")?;
    for field in [
        "total_exported",
        "eligible_symbols",
        "symbols_with_cases",
        "symbols_with_all_core_categories",
        "symbols_with_errno_case",
        "symbols_with_missing_spec_traceability",
        "symbols_with_execution_failures",
        "total_fixture_cases",
        "total_execution_cases",
    ] {
        require(summary.get(field).and_then(Value::as_u64).is_some(), field)?;
    }

    let symbols = json_array(&report, "symbols")?;
    require(!symbols.is_empty(), "canonical inputs must produce symbols")?;
    let mut previous_symbol = "";
    for row in symbols.iter().take(64) {
        for field in ["symbol", "status", "module"] {
            require(row.get(field).and_then(Value::as_str).is_some(), field)?;
        }
        for field in ["case_count", "strict_cases", "hardened_cases"] {
            require(row.get(field).and_then(Value::as_u64).is_some(), field)?;
        }
        require(
            row.get("has_errno_case").and_then(Value::as_bool).is_some(),
            "has_errno_case",
        )?;
        require(
            row.get("spec_sections").and_then(Value::as_array).is_some(),
            "spec_sections",
        )?;
        require(
            row.get("quality_flags").and_then(Value::as_array).is_some(),
            "quality_flags",
        )?;

        let symbol = json_string(row, "symbol")?;
        require(
            previous_symbol <= symbol,
            "symbols must be sorted ascending",
        )?;
        previous_symbol = symbol;

        let case_count = row
            .get("case_count")
            .and_then(Value::as_u64)
            .ok_or("case_count")?;
        let categories = json_object(row, "categories")?;
        let mut category_total = 0_u64;
        for field in ["normal", "boundary", "error", "other"] {
            let value = categories.get(field).and_then(Value::as_u64).ok_or(field)?;
            category_total = category_total.saturating_add(value);
        }
        require(
            case_count == category_total,
            "case_count must equal category total",
        )?;

        let execution = json_object(row, "execution")?;
        for field in ["total", "pass", "fail", "error", "timeout", "crash"] {
            require(
                execution.get(field).and_then(Value::as_u64).is_some(),
                field,
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
        .arg("posix-conformance-report")
        .arg("--support-matrix")
        .arg(&missing)
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--output")
        .arg(dir.join("bad.json"))
        .output()
        .map_err(|e| format!("spawn harness posix-conformance-report: {e}"))?;
    require(!out.status.success(), "missing input must fail closed")?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    require(
        diagnostic.contains("failed generating POSIX conformance report")
            || diagnostic.contains("missing-support-matrix.json"),
        "missing support matrix diagnostic",
    )
}
