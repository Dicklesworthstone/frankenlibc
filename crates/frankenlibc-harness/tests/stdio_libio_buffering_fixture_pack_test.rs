//! Integration tests for stdio/libio buffering fixtures (bd-bp8fl.5.5).

use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "fixture_id",
    "operation",
    "buffering_mode",
    "orientation",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_SCENARIO_KINDS: &[&str] = &[
    "stream_open_close",
    "buffering_mode_control",
    "buffered_write",
    "buffered_read",
    "eof_state",
    "error_state",
    "seek_tell",
    "locking",
    "wide_io_orientation",
    "memory_stream",
    "cookie_stream",
    "internal_io_helper",
];

const REQUIRED_BUFFERING_MODES: &[&str] = &["not_applicable", "full", "line", "unbuffered"];
const REQUIRED_ORIENTATIONS: &[&str] = &["undecided", "byte", "wide"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/stdio_libio_buffering_fixture_pack.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_stdio_libio_buffering_fixture_pack.sh")
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
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
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
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

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<HashSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| test_error(format!("{context}.{key} entries must be strings")))
        })
        .collect()
}

fn mutable_rows(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("fixture_rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.fixture_rows must be mutable array"))
}

fn mutable_row_by_fixture_id<'a>(
    manifest: &'a mut Value,
    fixture_id: &str,
) -> TestResult<&'a mut Value> {
    mutable_rows(manifest)?
        .iter_mut()
        .find(|row| row.get("fixture_id").and_then(Value::as_str) == Some(fixture_id))
        .ok_or_else(|| test_error(format!("manifest row {fixture_id} must exist")))
}

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FLC_STDIO_LIBIO_FIXTURE_PACK_OUT_DIR", out_dir)
        .env(
            "FLC_STDIO_LIBIO_FIXTURE_PACK_REPORT",
            out_dir.join("stdio-libio.report.json"),
        )
        .env(
            "FLC_STDIO_LIBIO_FIXTURE_PACK_LOG",
            out_dir.join("stdio-libio.log.jsonl"),
        )
        .env("FLC_STDIO_LIBIO_FIXTURE_PACK_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_STDIO_LIBIO_FIXTURE_PACK_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run stdio/libio gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("stdio-libio.report.json");
    write_json(&manifest_fixture, manifest)?;
    let output = run_gate(root, Some(&manifest_fixture), &out_dir)?;
    if output.status.success() {
        return Err(test_error(format!(
            "{case_name}: gate should fail\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    load_json(&report_path)
}

fn expect_failure_signature(report: &Value, signature: &str) -> TestResult {
    let errors = array_field(report, "errors", "report")?;
    if errors.iter().any(|row| {
        row.get("failure_signature").and_then(Value::as_str) == Some(signature)
            || row
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains(signature))
    }) {
        Ok(())
    } else {
        Err(test_error(format!(
            "report should contain failure signature {signature}: {report:#?}"
        )))
    }
}

#[test]
fn manifest_defines_stdio_libio_schema_and_required_coverage() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.5.5"
    );
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "stdio-libio-buffering-fixture-pack-v1"
    );

    for key in [
        "stdio_file_ops_fixture",
        "stdio_phase_strategy",
        "stdio_invariants",
        "oracle_precedence_divergence",
        "hard_parts_failure_replay_gate",
        "hard_parts_e2e_catalog",
        "support_matrix",
        "stdio_abi_test",
        "stdio_locking_stress_test",
    ] {
        let rel = string_field(field(&manifest, "sources", "manifest")?, key, "sources")?;
        assert!(root.join(rel).exists(), "missing source {key}: {rel}");
    }

    let required_log_fields = array_field(&manifest, "required_log_fields", "manifest")?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(required_log_fields, REQUIRED_LOG_FIELDS);

    assert_eq!(
        string_set(&manifest, "required_scenario_kinds", "manifest")?,
        REQUIRED_SCENARIO_KINDS
            .iter()
            .map(|value| value.to_string())
            .collect()
    );
    assert_eq!(
        string_set(&manifest, "required_buffering_modes", "manifest")?,
        REQUIRED_BUFFERING_MODES
            .iter()
            .map(|value| value.to_string())
            .collect()
    );
    assert_eq!(
        string_set(&manifest, "required_orientations", "manifest")?,
        REQUIRED_ORIENTATIONS
            .iter()
            .map(|value| value.to_string())
            .collect()
    );

    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    assert!(rows.len() >= REQUIRED_SCENARIO_KINDS.len());
    let mut seen_scenarios = HashSet::new();
    for row in rows {
        for field in [
            "fixture_id",
            "scenario_kind",
            "operation",
            "symbols",
            "buffering_mode",
            "orientation",
            "file_kind",
            "runtime_mode",
            "replacement_level",
            "oracle_kind",
            "allowed_divergence",
        ] {
            assert!(row.get(field).is_some(), "fixture row missing {field}");
        }
        assert!(object_field(row, "expected", "fixture row")?.contains_key("errno"));
        assert!(object_field(row, "state_transition", "fixture row")?.contains_key("label"));
        assert!(object_field(row, "cleanup", "fixture row")?.contains_key("required"));
        assert_eq!(
            string_field(
                field(row, "direct_runner", "fixture row")?,
                "runner_kind",
                "direct"
            )?,
            "direct"
        );
        assert_eq!(
            string_field(
                field(row, "isolated_runner", "fixture row")?,
                "runner_kind",
                "isolated"
            )?,
            "isolated"
        );
        seen_scenarios.insert(string_field(row, "scenario_kind", "fixture row")?.to_string());
    }
    for scenario in REQUIRED_SCENARIO_KINDS {
        assert!(
            seen_scenarios.contains(*scenario),
            "missing scenario {scenario}"
        );
    }

    Ok(())
}

#[test]
fn gate_passes_and_emits_stdio_libio_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("stdio-libio-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("stdio-libio.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        field(&report, "summary", "report")?
            .get("required_scenario_kind_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_SCENARIO_KINDS.len() as u64)
    );
    assert_eq!(
        field(&report, "summary", "report")?
            .get("buffering_mode_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_BUFFERING_MODES.len() as u64)
    );

    let fixture_count = field(&report, "summary", "report")?
        .get("fixture_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| test_error("report.summary.fixture_count must be present"))?;
    let log_text = std::fs::read_to_string(out_dir.join("stdio-libio.log.jsonl"))?;
    let rows = log_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len() as u64, fixture_count);
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        assert_eq!(string_field(&row, "bead_id", "log")?, "bd-bp8fl.5.5");
        assert_eq!(string_field(&row, "failure_signature", "log")?, "ok");
    }

    Ok(())
}

#[test]
fn gate_fails_closed_for_stdio_libio_fixture_drift() -> TestResult {
    let root = workspace_root();
    let base = load_json(&manifest_path(&root))?;

    let mut stale = base.clone();
    stale
        .get_mut("freshness")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("freshness must be object"))?
        .insert(
            "required_source_commit".to_string(),
            Value::String("not-current-source-commit".to_string()),
        );
    let stale_report = run_negative_case(&root, "stdio-libio-stale", &stale)?;
    expect_failure_signature(&stale_report, "stale_artifact")?;

    let mut missing_source = base.clone();
    mutable_row_by_fixture_id(
        &mut missing_source,
        "stdio.buffered_write.fwrite_devnull.strict",
    )?
    .get_mut("source_case_refs")
    .and_then(Value::as_array_mut)
    .ok_or_else(|| test_error("source_case_refs must be array"))?
    .push(Value::String("missing_stdio_fixture_case".to_string()));
    let missing_report = run_negative_case(&root, "stdio-libio-missing-source", &missing_source)?;
    expect_failure_signature(&missing_report, "missing_source_artifact")?;

    let mut eof_state = base.clone();
    mutable_row_by_fixture_id(&mut eof_state, "stdio.eof_state.feof_after_devnull.strict")?
        .get_mut("expected")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("expected must be object"))?
        .insert("feof".to_string(), Value::Bool(false));
    let eof_report = run_negative_case(&root, "stdio-libio-eof-state", &eof_state)?;
    expect_failure_signature(&eof_report, "state_contract_mismatch")?;

    let mut wide_overclaim = base.clone();
    mutable_row_by_fixture_id(
        &mut wide_overclaim,
        "stdio.wide_io.orientation.blocked.strict",
    )?
    .get_mut("expected")
    .and_then(Value::as_object_mut)
    .ok_or_else(|| test_error("expected must be object"))?
    .insert("status".to_string(), Value::String("pass".to_string()));
    let wide_report = run_negative_case(&root, "stdio-libio-wide-overclaim", &wide_overclaim)?;
    expect_failure_signature(&wide_report, "unsupported_surface_overclaim")?;

    let mut cleanup = base.clone();
    mutable_row_by_fixture_id(&mut cleanup, "stdio.memory_stream.open_memstream.hardened")?
        .get_mut("cleanup")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("cleanup must be object"))?
        .insert("required".to_string(), Value::Bool(false));
    let cleanup_report = run_negative_case(&root, "stdio-libio-cleanup", &cleanup)?;
    expect_failure_signature(&cleanup_report, "cleanup_contract")?;

    let mut oracle = base;
    mutable_row_by_fixture_id(&mut oracle, "stdio.stream.open_close.devnull.strict")?
        .as_object_mut()
        .ok_or_else(|| test_error("fixture row must be object"))?
        .insert(
            "allowed_divergence".to_string(),
            Value::String("not_declared".to_string()),
        );
    let oracle_report = run_negative_case(&root, "stdio-libio-oracle", &oracle)?;
    expect_failure_signature(&oracle_report, "oracle_mismatch")?;

    Ok(())
}
