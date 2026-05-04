//! Integration test: reverse loader/process ABI standalone gate (bd-bp8fl.3.7).
//!
//! The gate binds loader/process ABI feature-parity gaps to direct-link smoke,
//! versioned-symbol, and negative claim-blocking evidence.

use serde_json::{Value, json};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_GAP_IDS: &[&str] = &[
    "fp-reverse-core-0191894bf973",
    "fp-reverse-core-c16c9c1ae7a4",
    "fp-reverse-core-83ea12557c2f",
    "fp-reverse-core-a764fe234295",
    "fp-reverse-core-3ac0cb0d65a2",
    "fp-reverse-core-757002295174",
    "fp-reverse-core-8f05cebd7805",
    "fp-reverse-core-b4b2f8e772cb",
    "fp-reverse-core-44162ed23382",
    "fp-reverse-core-a559b1461f71",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "gap_id",
    "api_family",
    "symbol",
    "replacement_level",
    "runtime_mode",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const EXPECTED_INPUT_PATHS: &[&str] = &[
    "tests/conformance/feature_parity_gap_ledger.v1.json",
    "tests/conformance/feature_parity_gap_groups.v1.json",
    "tests/conformance/feature_parity_gap_owner_family_groups.v1.md",
    "tests/conformance/standalone_link_run_smoke.v1.json",
    "tests/conformance/standalone_readiness_proof_matrix.v1.json",
    "tests/conformance/loader_dlfcn_relocation_tls_audit.v1.json",
    "tests/conformance/math_fenv_softfp_fixture_pack.v1.json",
    "tests/conformance/e2e_scenario_manifest.v1.json",
    "tests/conformance/hard_parts_e2e_failure_matrix.v1.json",
    "tests/conformance/conformance_matrix.v1.json",
    "crates/frankenlibc-abi/version_scripts/libc.map",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn missing_nested_key_error(context: &str, key: &str) -> Box<dyn Error> {
    test_error(format!("{context}.{key} is missing"))
}

fn log_parse_error(index: usize, err: serde_json::Error) -> Box<dyn Error> {
    test_error(format!("log line {index} should parse: {err}"))
}

fn missing_input_path_error(path: &str) -> Box<dyn Error> {
    test_error(format!("{path} should exist"))
}

fn unknown_input_path_error(path: &str) -> Box<dyn Error> {
    test_error(format!("{path} is not an expected input path"))
}

fn missing_runtime_mode_error(mode: &str) -> Box<dyn Error> {
    test_error(format!("runtime_evidence.{mode} missing"))
}

fn runtime_mismatch_error(mode: &str) -> Box<dyn Error> {
    test_error(format!("{mode} expected/actual mismatch"))
}

fn missing_artifact_refs_error(mode: &str) -> Box<dyn Error> {
    test_error(format!("{mode} artifact refs missing"))
}

fn missing_log_field_error(index: usize, field: &str) -> Box<dyn Error> {
    test_error(format!("log line {index} missing {field}"))
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {:?}, got {:?}",
            context.into(),
            expected,
            actual
        )))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn gate_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/reverse_loader_process_abi_standalone_gate.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/reverse_loader_process_abi_standalone_gate.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/reverse_loader_process_abi_standalone_gate.log.jsonl")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| missing_nested_key_error(context, key))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    field(value, key, context)?
        .as_object()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn known_input_path(root: &Path, rel: &str) -> TestResult<PathBuf> {
    match rel {
        "tests/conformance/feature_parity_gap_ledger.v1.json" => {
            Ok(root.join("tests/conformance/feature_parity_gap_ledger.v1.json"))
        }
        "tests/conformance/feature_parity_gap_groups.v1.json" => {
            Ok(root.join("tests/conformance/feature_parity_gap_groups.v1.json"))
        }
        "tests/conformance/feature_parity_gap_owner_family_groups.v1.md" => {
            Ok(root.join("tests/conformance/feature_parity_gap_owner_family_groups.v1.md"))
        }
        "tests/conformance/standalone_link_run_smoke.v1.json" => {
            Ok(root.join("tests/conformance/standalone_link_run_smoke.v1.json"))
        }
        "tests/conformance/standalone_readiness_proof_matrix.v1.json" => {
            Ok(root.join("tests/conformance/standalone_readiness_proof_matrix.v1.json"))
        }
        "tests/conformance/loader_dlfcn_relocation_tls_audit.v1.json" => {
            Ok(root.join("tests/conformance/loader_dlfcn_relocation_tls_audit.v1.json"))
        }
        "tests/conformance/math_fenv_softfp_fixture_pack.v1.json" => {
            Ok(root.join("tests/conformance/math_fenv_softfp_fixture_pack.v1.json"))
        }
        "tests/conformance/e2e_scenario_manifest.v1.json" => {
            Ok(root.join("tests/conformance/e2e_scenario_manifest.v1.json"))
        }
        "tests/conformance/hard_parts_e2e_failure_matrix.v1.json" => {
            Ok(root.join("tests/conformance/hard_parts_e2e_failure_matrix.v1.json"))
        }
        "tests/conformance/conformance_matrix.v1.json" => {
            Ok(root.join("tests/conformance/conformance_matrix.v1.json"))
        }
        "crates/frankenlibc-abi/version_scripts/libc.map" => {
            Ok(root.join("crates/frankenlibc-abi/version_scripts/libc.map"))
        }
        _ => Err(unknown_input_path_error(rel)),
    }
}

fn unique_temp_path(root: &Path, prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    root.join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}.json", std::process::id()))
}

fn run_checker(
    root: &Path,
    gate: &Path,
    report: &Path,
    log: &Path,
) -> TestResult<std::process::Output> {
    Command::new(root.join("scripts/check_reverse_loader_process_abi_standalone_gate.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_REVERSE_LOADER_GATE", gate)
        .env("FRANKENLIBC_REVERSE_LOADER_REPORT", report)
        .env("FRANKENLIBC_REVERSE_LOADER_LOG", log)
        .output()
        .map_err(|err| test_error(format!("checker should execute: {err}")))
}

fn mutable_rows(gate: &mut Value) -> TestResult<&mut Vec<Value>> {
    gate.get_mut("rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("rows must be mutable array"))
}

fn mutable_row(gate: &mut Value, index: usize) -> TestResult<&mut Value> {
    mutable_rows(gate)?
        .get_mut(index)
        .ok_or_else(|| test_error(format!("row {index} must exist")))
}

fn object_mut<'a>(
    value: &'a mut Value,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))
}

fn set_nested_field(
    value: &mut Value,
    path: &[&str],
    replacement: Value,
    context: &str,
) -> TestResult {
    let (leaf, parents) = path
        .split_last()
        .ok_or_else(|| test_error("nested field path must be non-empty"))?;
    let mut current = value;
    for key in parents {
        current = object_mut(current, context)?
            .get_mut(*key)
            .ok_or_else(|| missing_nested_key_error(context, key))?;
    }
    object_mut(current, context)?.insert((*leaf).to_owned(), replacement);
    Ok(())
}

fn usize_to_u64(value: usize, context: &str) -> TestResult<u64> {
    u64::try_from(value).map_err(|err| test_error(format!("{context} conversion failed: {err}")))
}

#[test]
fn gate_artifact_preserves_loader_process_gap_contract() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path(&root))?;

    ensure_eq(
        string_field(&gate, "schema_version", "gate")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(string_field(&gate, "bead", "gate")?, "bd-bp8fl.3.7", "bead")?;
    ensure_eq(
        string_field(&gate, "owner_family_group", "gate")?,
        "fpg-reverse-loader-process-abi",
        "owner_family_group",
    )?;

    let inputs = object_field(&gate, "inputs", "gate")?;
    for value in inputs.values() {
        let rel = value
            .as_str()
            .ok_or_else(|| test_error("input artifact path must be a string"))?;
        ensure(
            EXPECTED_INPUT_PATHS.contains(&rel),
            "input artifact path must be in expected path set",
        )?;
        if !known_input_path(&root, rel)?.exists() {
            return Err(missing_input_path_error(rel));
        }
    }

    let required_fields: Vec<&str> = array_field(&gate, "required_log_fields", "gate")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<Vec<&str>>>()?;
    ensure_eq(
        required_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let expected_gap_ids: Vec<&str> = array_field(&gate, "expected_gap_ids", "gate")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("expected_gap_ids entries must be strings"))
        })
        .collect::<TestResult<Vec<&str>>>()?;
    ensure_eq(
        expected_gap_ids,
        EXPECTED_GAP_IDS.to_vec(),
        "expected_gap_ids",
    )?;

    let rows = array_field(&gate, "rows", "gate")?;
    ensure_eq(rows.len(), EXPECTED_GAP_IDS.len(), "row count")?;
    for (row, expected_gap_id) in rows.iter().zip(EXPECTED_GAP_IDS) {
        ensure_eq(
            string_field(row, "gap_id", "row")?,
            *expected_gap_id,
            "row.gap_id",
        )?;
        ensure_eq(
            string_field(row, "source_status", "row")?,
            "PLANNED",
            "row.source_status",
        )?;
        ensure_eq(
            string_field(row, "evidence_kind", "row")?,
            "standalone_link_run_and_versioned_symbol_gate",
            "row.evidence_kind",
        )?;
        ensure(
            !array_field(row, "positive_smoke_ids", "row")?.is_empty(),
            "positive smoke ids",
        )?;
        ensure_eq(
            string_field(row, "negative_smoke_id", "row")?,
            "standalone.loader_process_negative_missing_obligation",
            "negative_smoke_id",
        )?;
        ensure(
            !array_field(row, "named_unsupported_or_blocked_cases", "row")?.is_empty(),
            "row must name unsupported or blocked cases",
        )?;
        ensure(
            !array_field(row, "versioned_symbol_requirements", "row")?.is_empty(),
            "row must name versioned symbols",
        )?;
        let runtime = object_field(row, "runtime_evidence", "row")?;
        for mode in ["strict", "hardened"] {
            let evidence = runtime
                .get(mode)
                .ok_or_else(|| missing_runtime_mode_error(mode))?;
            if string_field(evidence, "expected", mode)? != string_field(evidence, "actual", mode)?
            {
                return Err(runtime_mismatch_error(mode));
            }
            if array_field(evidence, "artifact_refs", mode)?.is_empty() {
                return Err(missing_artifact_refs_error(mode));
            }
        }
    }

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_and_logs() -> TestResult {
    let root = workspace_root();
    let report = report_path(&root);
    let log = log_path(&root);
    let output = run_checker(&root, &gate_path(&root), &report, &log)?;
    ensure(
        output.status.success(),
        format!(
            "checker should pass\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report_json = load_json(&report)?;
    ensure_eq(
        string_field(&report_json, "status", "report")?,
        "pass",
        "report.status",
    )?;
    let summary = object_field(&report_json, "summary", "report")?;
    ensure_eq(
        summary
            .get("gap_rows")
            .and_then(Value::as_u64)
            .ok_or_else(|| test_error("summary.gap_rows must be u64"))?,
        usize_to_u64(EXPECTED_GAP_IDS.len(), "gap rows")?,
        "summary.gap_rows",
    )?;
    ensure_eq(
        summary
            .get("structured_log_rows")
            .and_then(Value::as_u64)
            .ok_or_else(|| test_error("summary.structured_log_rows must be u64"))?,
        usize_to_u64(EXPECTED_GAP_IDS.len() * 2, "structured log rows")?,
        "summary.structured_log_rows",
    )?;

    let log_content = std::fs::read_to_string(log)
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let lines: Vec<&str> = log_content.lines().collect();
    ensure_eq(lines.len(), EXPECTED_GAP_IDS.len() * 2, "log line count")?;
    for (idx, line) in lines.iter().enumerate() {
        let entry: Value = serde_json::from_str(line).map_err(|err| log_parse_error(idx, err))?;
        for field in REQUIRED_LOG_FIELDS {
            if entry.get(*field).is_none() {
                return Err(missing_log_field_error(idx, field));
            }
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_gap_row() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    mutable_rows(&mut gate)?.pop();
    let bad_gate = unique_temp_path(&root, "reverse-loader-missing-row");
    write_json(&bad_gate, &gate)?;
    let output = run_checker(
        &root,
        &bad_gate,
        &unique_temp_path(&root, "reverse-loader-missing-row-report"),
        &unique_temp_path(&root, "reverse-loader-missing-row-log"),
    )?;
    ensure(
        !output.status.success(),
        "checker must reject missing gap row",
    )
}

#[test]
fn checker_rejects_stale_source_commit() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    object_mut(&mut gate, "gate")?.insert("source_commit".to_owned(), json!("stale-source"));
    let bad_gate = unique_temp_path(&root, "reverse-loader-stale-source");
    write_json(&bad_gate, &gate)?;
    let output = run_checker(
        &root,
        &bad_gate,
        &unique_temp_path(&root, "reverse-loader-stale-source-report"),
        &unique_temp_path(&root, "reverse-loader-stale-source-log"),
    )?;
    ensure(
        !output.status.success(),
        "checker must reject stale source commit",
    )
}

#[test]
fn checker_rejects_missing_versioned_symbol() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_row(&mut gate, 0)?;
    let version_reqs = row
        .get_mut("versioned_symbol_requirements")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("versioned_symbol_requirements must be mutable"))?;
    let first_req = version_reqs
        .get_mut(0)
        .ok_or_else(|| test_error("first versioned symbol requirement must exist"))?;
    object_mut(first_req, "versioned symbol requirement")?.insert(
        "symbol".to_owned(),
        json!("definitely_missing_loader_process_symbol"),
    );
    let bad_gate = unique_temp_path(&root, "reverse-loader-missing-symbol");
    write_json(&bad_gate, &gate)?;
    let output = run_checker(
        &root,
        &bad_gate,
        &unique_temp_path(&root, "reverse-loader-missing-symbol-report"),
        &unique_temp_path(&root, "reverse-loader-missing-symbol-log"),
    )?;
    ensure(
        !output.status.success(),
        "checker must reject missing versioned symbol",
    )
}

#[test]
fn checker_rejects_missing_negative_row_binding() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    object_mut(mutable_row(&mut gate, 0)?, "row")?.insert(
        "negative_smoke_id".to_owned(),
        json!("standalone.missing_negative_row"),
    );
    let bad_gate = unique_temp_path(&root, "reverse-loader-missing-negative");
    write_json(&bad_gate, &gate)?;
    let output = run_checker(
        &root,
        &bad_gate,
        &unique_temp_path(&root, "reverse-loader-missing-negative-report"),
        &unique_temp_path(&root, "reverse-loader-missing-negative-log"),
    )?;
    ensure(
        !output.status.success(),
        "checker must reject missing negative row binding",
    )
}

#[test]
fn checker_rejects_expected_actual_mismatch() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    set_nested_field(
        mutable_row(&mut gate, 0)?,
        &["runtime_evidence", "strict", "actual"],
        json!("mismatched actual result"),
        "row",
    )?;
    let bad_gate = unique_temp_path(&root, "reverse-loader-mismatch");
    write_json(&bad_gate, &gate)?;
    let output = run_checker(
        &root,
        &bad_gate,
        &unique_temp_path(&root, "reverse-loader-mismatch-report"),
        &unique_temp_path(&root, "reverse-loader-mismatch-log"),
    )?;
    ensure(
        !output.status.success(),
        "checker must reject expected/actual mismatch",
    )
}
