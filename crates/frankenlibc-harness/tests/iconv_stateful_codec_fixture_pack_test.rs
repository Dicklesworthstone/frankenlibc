//! Integration tests for iconv stateful codec fixtures (bd-bp8fl.5.3).

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
    "from_encoding",
    "to_encoding",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "consumed",
    "produced",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_SCENARIO_KINDS: &[&str] = &[
    "valid_conversion",
    "output_buffer_progress",
    "invalid_sequence",
    "incomplete_sequence",
    "state_reset",
    "stateful_codec",
    "transliteration_ignore",
    "unsupported_codec",
];

const REQUIRED_CODEC_CLASSIFICATIONS: &[&str] = &[
    "included_phase1",
    "excluded_stateful",
    "excluded_table_deferred",
    "unsupported_unknown",
    "unsupported_flag",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/iconv_stateful_codec_fixture_pack.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_iconv_stateful_codec_fixture_pack.sh")
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
        .env("FLC_ICONV_STATEFUL_FIXTURE_PACK_OUT_DIR", out_dir)
        .env(
            "FLC_ICONV_STATEFUL_FIXTURE_PACK_REPORT",
            out_dir.join("iconv-stateful.report.json"),
        )
        .env(
            "FLC_ICONV_STATEFUL_FIXTURE_PACK_LOG",
            out_dir.join("iconv-stateful.log.jsonl"),
        )
        .env("FLC_ICONV_STATEFUL_FIXTURE_PACK_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_ICONV_STATEFUL_FIXTURE_PACK_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run iconv fixture-pack gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("iconv-stateful.report.json");
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
fn manifest_defines_iconv_stateful_schema_and_required_coverage() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.5.3"
    );
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "iconv-stateful-codec-fixture-pack-v1"
    );

    for key in [
        "iconv_phase1_fixture",
        "iconv_codec_scope_ledger",
        "iconv_table_pack",
        "iconv_table_checksums",
        "oracle_precedence_divergence",
        "hard_parts_failure_replay_gate",
        "hard_parts_e2e_catalog",
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
        string_set(&manifest, "required_codec_classifications", "manifest")?,
        REQUIRED_CODEC_CLASSIFICATIONS
            .iter()
            .map(|value| value.to_string())
            .collect()
    );

    let errno_mappings: HashSet<_> = array_field(&manifest, "required_errno_mappings", "manifest")?
        .iter()
        .map(|row| {
            Ok((
                string_field(row, "errno", "errno mapping")?.to_string(),
                string_field(row, "name", "errno mapping")?.to_string(),
                string_field(row, "reason_code", "errno mapping")?.to_string(),
            ))
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        errno_mappings,
        HashSet::from([
            (
                "0".to_string(),
                "OK".to_string(),
                "conversion_complete".to_string(),
            ),
            (
                "7".to_string(),
                "E2BIG".to_string(),
                "output_buffer_too_small".to_string(),
            ),
            (
                "22".to_string(),
                "EINVAL".to_string(),
                "incomplete_or_unsupported".to_string(),
            ),
            (
                "84".to_string(),
                "EILSEQ".to_string(),
                "invalid_sequence".to_string(),
            ),
        ])
    );

    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    assert!(rows.len() >= REQUIRED_SCENARIO_KINDS.len());
    let mut seen_classifications = HashSet::new();
    for row in rows {
        for field in [
            "fixture_id",
            "scenario_kind",
            "from_encoding",
            "to_encoding",
            "input_bytes",
            "runtime_mode",
            "replacement_level",
            "oracle_kind",
            "allowed_divergence",
            "source_fixture_case",
        ] {
            assert!(row.get(field).is_some(), "fixture row missing {field}");
        }
        assert!(object_field(row, "chunking", "fixture row")?.contains_key("chunks"));
        assert!(object_field(row, "state_reset", "fixture row")?.contains_key("required"));
        assert!(array_field(row, "flags", "fixture row").is_ok());
        assert!(object_field(row, "expected", "fixture row")?.contains_key("errno"));
        assert!(
            object_field(row, "codec_classification", "fixture row")?
                .contains_key("classification")
        );
        assert!(object_field(row, "table_provenance", "fixture row")?.contains_key("required"));
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
        seen_classifications.insert(
            string_field(
                field(row, "codec_classification", "fixture row")?,
                "classification",
                "codec_classification",
            )?
            .to_string(),
        );
    }
    for classification in REQUIRED_CODEC_CLASSIFICATIONS {
        assert!(
            seen_classifications.contains(*classification),
            "missing classification {classification}"
        );
    }

    Ok(())
}

#[test]
fn gate_passes_and_emits_iconv_stateful_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("iconv-stateful-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("iconv-stateful.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        field(&report, "summary", "report")?
            .get("required_scenario_kind_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_SCENARIO_KINDS.len() as u64)
    );
    assert_eq!(
        field(&report, "summary", "report")?
            .get("runtime_mode_count")
            .and_then(Value::as_u64),
        Some(2)
    );

    let fixture_count = field(&report, "summary", "report")?
        .get("fixture_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| test_error("report.summary.fixture_count must be present"))?;
    let log_text = std::fs::read_to_string(out_dir.join("iconv-stateful.log.jsonl"))?;
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
        assert_eq!(string_field(&row, "bead_id", "log")?, "bd-bp8fl.5.3");
        assert_eq!(string_field(&row, "failure_signature", "log")?, "ok");
    }

    Ok(())
}

#[test]
fn gate_fails_closed_for_iconv_stateful_fixture_drift() -> TestResult {
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
    let stale_report = run_negative_case(&root, "iconv-stateful-stale", &stale)?;
    expect_failure_signature(&stale_report, "stale_artifact")?;

    let mut missing_fixture = base.clone();
    mutable_row_by_fixture_id(&mut missing_fixture, "iconv.valid.utf8_to_utf16le.strict")?
        .as_object_mut()
        .ok_or_else(|| test_error("fixture row must be object"))?
        .insert(
            "source_fixture_case".to_string(),
            Value::String("missing_iconv_fixture_case".to_string()),
        );
    let missing_report =
        run_negative_case(&root, "iconv-stateful-missing-fixture", &missing_fixture)?;
    expect_failure_signature(&missing_report, "missing_fixture_case")?;

    let mut invalid_sequence = base.clone();
    mutable_row_by_fixture_id(
        &mut invalid_sequence,
        "iconv.invalid_sequence.eilseq.strict",
    )?
    .get_mut("expected")
    .and_then(Value::as_object_mut)
    .ok_or_else(|| test_error("expected must be object"))?
    .insert("errno".to_string(), Value::String("22".to_string()));
    let invalid_report =
        run_negative_case(&root, "iconv-stateful-invalid-sequence", &invalid_sequence)?;
    expect_failure_signature(&invalid_report, "invalid_sequence_mapping")?;

    let mut reset_contract = base.clone();
    mutable_row_by_fixture_id(&mut reset_contract, "iconv.state_reset.utf32_bom.strict")?
        .get_mut("state_reset")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("state_reset must be object"))?
        .insert("required".to_string(), Value::Bool(false));
    let reset_report = run_negative_case(&root, "iconv-stateful-reset", &reset_contract)?;
    expect_failure_signature(&reset_report, "state_reset_contract")?;

    let mut unsupported_classification = base.clone();
    mutable_row_by_fixture_id(
        &mut unsupported_classification,
        "iconv.stateful_codec.iso2022jp.deferred.hardened",
    )?
    .get_mut("codec_classification")
    .and_then(Value::as_object_mut)
    .ok_or_else(|| test_error("codec_classification must be object"))?
    .insert(
        "classification".to_string(),
        Value::String("included_phase1".to_string()),
    );
    let unsupported_report = run_negative_case(
        &root,
        "iconv-stateful-unsupported-classification",
        &unsupported_classification,
    )?;
    expect_failure_signature(&unsupported_report, "unsupported_codec_classification")?;

    let mut table_provenance = base.clone();
    mutable_row_by_fixture_id(&mut table_provenance, "iconv.valid.utf8_to_utf16le.strict")?
        .get_mut("table_provenance")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("table_provenance must be object"))?
        .insert(
            "artifact_refs".to_string(),
            Value::Array(vec![Value::String(
                "tests/conformance/iconv_table_pack.v1.json".to_string(),
            )]),
        );
    let table_report = run_negative_case(&root, "iconv-stateful-table", &table_provenance)?;
    expect_failure_signature(&table_report, "table_provenance")?;

    let mut oracle = base;
    mutable_row_by_fixture_id(&mut oracle, "iconv.valid.utf8_to_utf16le.strict")?
        .as_object_mut()
        .ok_or_else(|| test_error("fixture row must be object"))?
        .insert(
            "allowed_divergence".to_string(),
            Value::String("not_declared".to_string()),
        );
    let oracle_report = run_negative_case(&root, "iconv-stateful-oracle", &oracle)?;
    expect_failure_signature(&oracle_report, "oracle_mismatch")?;

    Ok(())
}
