//! Integration test: user environment coverage matrix gate (bd-bp8fl.10.7).
//!
//! Freezes the cross-environment acceptance matrix that prevents blocked,
//! skipped, flaky, unsupported, or stale rows from becoming supported claims.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "environment_id",
    "workload_id",
    "architecture",
    "runtime_mode",
    "replacement_level",
    "scenario_id",
    "expected",
    "actual",
    "errno",
    "status",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "reason_code",
    "failure_signature",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| test_error("manifest should have crates parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| test_error("crates dir should have workspace parent"))?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn load_matrix() -> TestResult<Value> {
    load_json(&workspace_root()?.join("tests/conformance/user_environment_coverage_matrix.v1.json"))
}

fn array_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{field} should be an array")))
}

fn string_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{field} should be a string")))
}

fn unique_temp_dir(prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_gate_with_matrix(
    matrix: &Path,
    prefix: &str,
) -> TestResult<(PathBuf, PathBuf, std::process::Output)> {
    let root = workspace_root()?;
    let temp = unique_temp_dir(prefix)?;
    let report = temp.join("user_environment_coverage_matrix.report.json");
    let log = temp.join("user_environment_coverage_matrix.log.jsonl");
    let output = Command::new(root.join("scripts/check_user_environment_coverage_matrix.sh"))
        .env("USER_ENVIRONMENT_COVERAGE_MATRIX", matrix)
        .env("USER_ENVIRONMENT_COVERAGE_REPORT", &report)
        .env("USER_ENVIRONMENT_COVERAGE_LOG", &log)
        .output()?;
    Ok((report, log, output))
}

fn write_matrix_variant(
    original: &Value,
    prefix: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut value = original.clone();
    mutate(&mut value)?;
    let dir = unique_temp_dir(prefix)?;
    let path = dir.join("user_environment_coverage_matrix.v1.json");
    std::fs::write(&path, serde_json::to_string_pretty(&value)?)?;
    Ok(path)
}

fn set_row_field(
    value: &mut Value,
    row_index: usize,
    field: &str,
    replacement: Value,
) -> TestResult {
    let rows = value
        .get_mut("rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("rows should be mutable array"))?;
    let row = rows
        .get_mut(row_index)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error(format!("row {row_index} should be object")))?;
    row.insert(field.to_owned(), replacement);
    Ok(())
}

fn assert_gate_fails_with(
    matrix_path: &Path,
    prefix: &str,
    expected_signature: &str,
) -> TestResult {
    let (report_path, _log_path, output) = run_gate_with_matrix(matrix_path, prefix)?;
    assert!(
        !output.status.success(),
        "gate unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report_path)?;
    let signatures = array_field(&report, "failure_signatures")?;
    assert!(
        signatures
            .iter()
            .any(|signature| signature.as_str() == Some(expected_signature)),
        "expected failure signature {expected_signature}; report={report:#?}"
    );
    Ok(())
}

#[test]
fn matrix_schema_covers_required_dimensions() -> TestResult {
    let matrix = load_matrix()?;
    assert_eq!(string_field(&matrix, "schema_version")?, "v1");
    assert_eq!(string_field(&matrix, "bead")?, "bd-bp8fl.10.7");

    let required_log_fields = array_field(&matrix, "required_log_fields")?;
    for field in REQUIRED_LOG_FIELDS {
        assert!(
            required_log_fields
                .iter()
                .any(|value| value.as_str() == Some(*field)),
            "required_log_fields missing {field}"
        );
    }

    let rows = array_field(&matrix, "rows")?;
    let mut architectures = BTreeSet::new();
    let mut runtime_modes = BTreeSet::new();
    let mut replacement_levels = BTreeSet::new();
    let mut states = BTreeSet::new();
    let mut has_x86_64_l0_strict = false;
    let mut has_x86_64_l0_hardened = false;
    let mut has_aarch64_blocked = false;
    let mut has_resolver_online = false;
    let mut has_resolver_offline = false;
    let mut has_locale_variant = false;
    let mut has_filesystem_permission = false;
    let mut has_threaded_workload = false;
    let mut has_debug_profile = false;

    for row in rows {
        let architecture = string_field(row, "architecture")?;
        let runtime_mode = string_field(row, "runtime_mode")?;
        let replacement_level = string_field(row, "replacement_level")?;
        let state = string_field(row, "state")?;
        architectures.insert(architecture);
        runtime_modes.insert(runtime_mode);
        replacement_levels.insert(replacement_level);
        states.insert(state);

        has_x86_64_l0_strict |=
            architecture == "x86_64" && runtime_mode == "strict" && replacement_level == "L0";
        has_x86_64_l0_hardened |=
            architecture == "x86_64" && runtime_mode == "hardened" && replacement_level == "L0";
        has_aarch64_blocked |= architecture == "aarch64" && state == "blocked";
        has_resolver_online |= row.get("network_state").and_then(Value::as_str) == Some("online")
            && row.get("workload_id").and_then(Value::as_str) == Some("uwm-resolver-nss");
        has_resolver_offline |= row.get("network_state").and_then(Value::as_str) == Some("offline")
            && row.get("workload_id").and_then(Value::as_str) == Some("uwm-resolver-nss");
        has_locale_variant |= row
            .get("locale_env_variables")
            .and_then(Value::as_object)
            .is_some_and(|locale| {
                locale
                    .values()
                    .any(|value| value.as_str() == Some("C.UTF-8"))
            });
        has_filesystem_permission |= row
            .get("filesystem_permission_model")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("read_only"));
        has_threaded_workload |= row.get("thread_count").and_then(Value::as_u64).unwrap_or(0) > 1
            && row.get("workload_id").and_then(Value::as_str) == Some("uwm-threaded-service");
        has_debug_profile |= row.get("build_profile").and_then(Value::as_str) == Some("debug");

        assert_eq!(
            row.get("support_claim_allowed").and_then(Value::as_bool),
            Some(false),
            "{} must not claim support",
            string_field(row, "environment_id")?
        );
    }

    assert!(architectures.contains("x86_64"));
    assert!(architectures.contains("aarch64"));
    assert!(runtime_modes.contains("strict"));
    assert!(runtime_modes.contains("hardened"));
    assert!(replacement_levels.contains("L0"));
    assert!(replacement_levels.contains("L1"));
    assert!(states.contains("required"));
    assert!(states.contains("blocked"));
    assert!(states.contains("optional"));
    assert!(states.contains("skipped"));
    assert!(has_x86_64_l0_strict);
    assert!(has_x86_64_l0_hardened);
    assert!(has_aarch64_blocked);
    assert!(has_resolver_online);
    assert!(has_resolver_offline);
    assert!(has_locale_variant);
    assert!(has_filesystem_permission);
    assert!(has_threaded_workload);
    assert!(has_debug_profile);
    Ok(())
}

#[test]
fn rows_resolve_to_workload_replacement_and_reason_sources() -> TestResult {
    let root = workspace_root()?;
    let matrix = load_matrix()?;
    let inputs = matrix
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("inputs should be object"))?;
    for path in inputs.values().filter_map(Value::as_str) {
        assert!(root.join(path).is_file(), "input artifact missing: {path}");
    }

    let workload_path = inputs
        .get("workload_matrix")
        .and_then(Value::as_str)
        .ok_or_else(|| test_error("inputs.workload_matrix should be string"))?;
    let replacement_path = inputs
        .get("replacement_levels")
        .and_then(Value::as_str)
        .ok_or_else(|| test_error("inputs.replacement_levels should be string"))?;
    let workload_matrix = load_json(&root.join(workload_path))?;
    let replacement_levels = load_json(&root.join(replacement_path))?;
    let workload_ids: BTreeSet<_> = array_field(&workload_matrix, "workloads")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    let replacement_ids: BTreeSet<_> = array_field(&replacement_levels, "levels")?
        .iter()
        .filter_map(|row| row.get("level").and_then(Value::as_str))
        .collect();
    let reason_ids: BTreeSet<_> = array_field(&matrix, "reason_codes")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();

    for row in array_field(&matrix, "rows")? {
        assert!(workload_ids.contains(string_field(row, "workload_id")?));
        assert!(replacement_ids.contains(string_field(row, "replacement_level")?));
        assert!(reason_ids.contains(string_field(row, "reason_code")?));
    }
    Ok(())
}

#[test]
fn gate_script_emits_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let matrix_path = root.join("tests/conformance/user_environment_coverage_matrix.v1.json");
    let (report_path, log_path, output) =
        run_gate_with_matrix(&matrix_path, "environment-matrix-pass")?;
    assert!(
        output.status.success(),
        "gate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path)?;
    assert_eq!(report.get("status").and_then(Value::as_str), Some("pass"));
    let summary = report
        .get("summary")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("summary should be object"))?;
    assert_eq!(summary.get("row_count").and_then(Value::as_u64), Some(12));
    assert_eq!(
        summary
            .get("support_claim_allowed_count")
            .and_then(Value::as_u64),
        Some(0)
    );

    let log = std::fs::read_to_string(&log_path)?;
    let rows: Vec<Value> = log
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 12, "one log row per environment row");
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
    }
    Ok(())
}

#[test]
fn gate_rejects_missing_architecture_coverage() -> TestResult {
    let matrix = load_matrix()?;
    let path = write_matrix_variant(&matrix, "environment-missing-architecture", |value| {
        for row in value
            .get_mut("rows")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| test_error("rows should be array"))?
        {
            if row.get("architecture").and_then(Value::as_str) == Some("aarch64") {
                row["architecture"] = Value::String("x86_64".to_owned());
            }
        }
        Ok(())
    })?;
    assert_gate_fails_with(
        &path,
        "environment-missing-architecture-run",
        "environment_matrix_missing_architecture_coverage",
    )
}

#[test]
fn gate_rejects_invalid_reason_code() -> TestResult {
    let matrix = load_matrix()?;
    let path = write_matrix_variant(&matrix, "environment-invalid-reason", |value| {
        set_row_field(
            value,
            0,
            "reason_code",
            Value::String("unknown_reason".to_owned()),
        )
    })?;
    assert_gate_fails_with(
        &path,
        "environment-invalid-reason-run",
        "environment_matrix_invalid_reason_code",
    )
}

#[test]
fn gate_rejects_blocked_row_promoted_to_supported() -> TestResult {
    let matrix = load_matrix()?;
    let path = write_matrix_variant(&matrix, "environment-bad-support-merge", |value| {
        set_row_field(
            value,
            3,
            "support_status",
            Value::String("supported".to_owned()),
        )?;
        set_row_field(value, 3, "support_claim_allowed", Value::Bool(true))
    })?;
    assert_gate_fails_with(
        &path,
        "environment-bad-support-merge-run",
        "environment_matrix_bad_support_merge",
    )
}

#[test]
fn gate_rejects_stale_source_commit() -> TestResult {
    let matrix = load_matrix()?;
    let path = write_matrix_variant(&matrix, "environment-stale-source", |value| {
        let freshness = value
            .get_mut("freshness_policy")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| test_error("freshness_policy should be object"))?;
        freshness.insert(
            "source_commit".to_owned(),
            Value::String("deadbeef".to_owned()),
        );
        Ok(())
    })?;
    assert_gate_fails_with(
        &path,
        "environment-stale-source-run",
        "environment_matrix_stale_source_commit",
    )
}

#[test]
fn gate_rejects_missing_required_log_field() -> TestResult {
    let matrix = load_matrix()?;
    let path = write_matrix_variant(&matrix, "environment-missing-log-field", |value| {
        let fields = value
            .get_mut("required_log_fields")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| test_error("required_log_fields should be array"))?;
        fields.retain(|field| field.as_str() != Some("reason_code"));
        Ok(())
    })?;
    assert_gate_fails_with(
        &path,
        "environment-missing-log-field-run",
        "environment_matrix_log_contract_missing",
    )
}
