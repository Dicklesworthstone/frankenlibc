//! Conformance gate for the harness binary `reality-report` subcommand.

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
        .join("reality_report_cli_contract.v1.json")
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

fn object_u64(map: &serde_json::Map<String, Value>, field: &str) -> TestResult<u64> {
    map.get(field)
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
        "reality_report_cli_contract_{stem}_{}_{}",
        std::process::id(),
        ts
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    Ok(dir)
}

fn write_sample_support_matrix(path: &Path) -> TestResult {
    let body = r#"{
  "generated_at_utc": "2026-05-14T00:00:00Z",
  "total_exported": 6,
  "symbols": [
    {"symbol": "zeta", "status": "Stub"},
    {"symbol": "alpha", "status": "Implemented"},
    {"symbol": "beta", "status": "RawSyscall"},
    {"symbol": "gamma", "status": "WrapsHostLibc"},
    {"symbol": "delta", "status": "GlibcCallThrough"},
    {"symbol": "eta", "status": "Stub"}
  ]
}"#;
    std::fs::write(path, body).map_err(|e| format!("write support matrix {path:?}: {e}"))
}

fn run_reality_report(bin: &Path, support_matrix: &Path) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("reality-report")
        .arg("--support-matrix")
        .arg(support_matrix)
        .output()
        .map_err(|e| format!("spawn harness reality-report: {e}"))
}

fn run_reality_report_to_output(
    bin: &Path,
    support_matrix: &Path,
    output: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("reality-report")
        .arg("--support-matrix")
        .arg(support_matrix)
        .arg("--output")
        .arg(output)
        .output()
        .map_err(|e| format!("spawn harness reality-report --output: {e}"))
}

fn validate_sample_report(report: &Value) -> TestResult {
    require(
        json_string(report, "schema_version")? == "v1",
        "schema_version mismatch",
    )?;
    require(
        json_string(report, "generated_at_utc")? == "2026-05-14T00:00:00Z",
        "generated_at_utc must come from support matrix",
    )?;
    require(
        json_u64(report, "total_exported")? == 6,
        "total_exported must come from support matrix",
    )?;

    let counts = json_object(report, "counts")?;
    for (field, expected, message) in [
        ("implemented", 1, "implemented count mismatch"),
        ("raw_syscall", 1, "raw_syscall count mismatch"),
        ("wraps_host_libc", 1, "wraps_host_libc count mismatch"),
        ("glibc_call_through", 1, "glibc_call_through count mismatch"),
        ("stub", 2, "stub count mismatch"),
    ] {
        require(object_u64(counts, field)? == expected, message)?;
    }

    let stubs = json_array(report, "stubs")?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| "stub entry must be a string".to_string())
        })
        .collect::<TestResult<Vec<_>>>()?;
    require(
        stubs == ["eta", "zeta"],
        format!("stub symbols must be sorted; got {stubs:?}"),
    )
}

#[test]
fn manifest_anchors_to_reality_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "reality-report-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-0agsk.3", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "reality-report",
        "subcommand_name mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for (field, message) in [
        (
            "stdout_mode_emits_valid_json",
            "stdout_mode_emits_valid_json must be true",
        ),
        (
            "output_mode_writes_parent_directories",
            "output_mode_writes_parent_directories must be true",
        ),
        (
            "status_counts_must_sum_to_total_exported",
            "status_counts_must_sum_to_total_exported must be true",
        ),
        (
            "stub_symbols_must_be_sorted",
            "stub_symbols_must_be_sorted must be true",
        ),
        (
            "unknown_support_status_must_fail_closed",
            "unknown_support_status_must_fail_closed must be true",
        ),
        (
            "missing_support_matrix_must_fail_closed",
            "missing_support_matrix_must_fail_closed must be true",
        ),
        (
            "support_matrix_symbol_count_mismatch_must_fail_closed",
            "support_matrix_symbol_count_mismatch_must_fail_closed must be true",
        ),
        (
            "must_preserve_support_reality_regeneration_bead",
            "must_preserve_support_reality_regeneration_bead must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }
    Ok(())
}

#[test]
fn manifest_underlying_lib_functions_are_pinned() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let functions = json_array(&m, "underlying_lib_functions")?;
    for (expected, message) in [
        (
            "frankenlibc_harness::report::RealityReport::from_support_matrix_path",
            "missing from_support_matrix_path function",
        ),
        (
            "frankenlibc_harness::report::RealityReport::from_support_matrix_json_str",
            "missing from_support_matrix_json_str function",
        ),
        (
            "frankenlibc_harness::report::RealityReport::to_json",
            "missing to_json function",
        ),
    ] {
        require(
            functions.iter().any(|v| v.as_str() == Some(expected)),
            message,
        )?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_reality_report_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("RealityReport {"),
        "harness.rs must declare RealityReport Command variant",
    )?;
    require(
        src.contains("RealityReport::from_support_matrix_path"),
        "reality-report arm must call RealityReport::from_support_matrix_path",
    )?;
    require(
        src.contains("failed generating reality report"),
        "reality-report arm must preserve fail-closed diagnostic context",
    )
}

#[test]
fn cli_stdout_mode_emits_reality_report_json() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("stdout")?;
    let support_matrix = dir.join("support_matrix.json");
    write_sample_support_matrix(&support_matrix)?;

    let out = run_reality_report(&bin, &support_matrix)?;
    if !out.status.success() {
        return Err(format!(
            "reality-report stdout mode failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let report: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("stdout must be valid JSON: {e}"))?;
    validate_sample_report(&report)
}

#[test]
fn cli_output_mode_creates_parent_and_writes_reality_report_json() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("output")?;
    let support_matrix = dir.join("support_matrix.json");
    let output = dir.join("nested").join("reality_report.current.v1.json");
    write_sample_support_matrix(&support_matrix)?;

    let out = run_reality_report_to_output(&bin, &support_matrix, &output)?;
    if !out.status.success() {
        return Err(format!(
            "reality-report output mode failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    require(output.exists(), "output mode must create the report file")?;
    let report = load_json(&output)?;
    validate_sample_report(&report)
}

#[test]
fn cli_missing_support_matrix_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("missing")?;
    let missing = dir.join("missing_support_matrix.json");
    let out = run_reality_report(&bin, &missing)?;
    require(!out.status.success(), "missing support matrix must fail")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("failed generating reality report"),
        "stderr must preserve generation failure context",
    )?;
    require(
        stderr.contains("failed reading support matrix"),
        "stderr must preserve missing file diagnostic",
    )
}
