//! Integration tests for math/fenv/soft-fp exceptional-path fixtures (bd-bp8fl.5.7).

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
    "function",
    "input_class",
    "rounding_mode",
    "expected_class",
    "actual_class",
    "errno",
    "fenv_flags",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_SCENARIO_KINDS: &[&str] = &[
    "domain_error",
    "range_error",
    "divide_by_zero",
    "overflow",
    "underflow",
    "inexact",
    "rounding_mode_sensitivity",
    "nan_propagation",
    "infinity_behavior",
    "subnormal_behavior",
    "soft_fp_arch_sensitive",
];

const REQUIRED_EXCEPTION_FLAGS: &[&str] = &[
    "FE_INVALID",
    "FE_DIVBYZERO",
    "FE_OVERFLOW",
    "FE_UNDERFLOW",
    "FE_INEXACT",
];

const REQUIRED_VALUE_CLASSES: &[&str] = &[
    "quiet_nan",
    "negative_infinity",
    "positive_infinity",
    "positive_zero",
    "finite_rounded",
    "rounding_mode_set",
    "exception_flag_set",
    "positive_subnormal",
    "finite_arch_sensitive",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/math_fenv_softfp_fixture_pack.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_math_fenv_softfp_fixture_pack.sh")
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
        .env("FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_OUT_DIR", out_dir)
        .env(
            "FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_REPORT",
            out_dir.join("math-fenv-softfp.report.json"),
        )
        .env(
            "FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_LOG",
            out_dir.join("math-fenv-softfp.log.jsonl"),
        )
        .env("FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_MANIFEST", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run math/fenv gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("math-fenv-softfp.report.json");
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
fn manifest_defines_math_fenv_schema_and_required_coverage() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.5.7"
    );
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "math-fenv-softfp-fixture-pack-v1"
    );

    for key in [
        "math_ops_fixture",
        "oracle_precedence_divergence",
        "hard_parts_failure_replay_gate",
        "hard_parts_e2e_catalog",
        "support_matrix",
        "math_abi_test",
        "fenv_abi_test",
        "conformance_diff_math",
        "conformance_diff_fenv",
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
        string_set(&manifest, "required_exception_flags", "manifest")?,
        REQUIRED_EXCEPTION_FLAGS
            .iter()
            .map(|value| value.to_string())
            .collect()
    );
    assert_eq!(
        string_set(&manifest, "required_value_classes", "manifest")?,
        REQUIRED_VALUE_CLASSES
            .iter()
            .map(|value| value.to_string())
            .collect()
    );

    let rows = array_field(&manifest, "fixture_rows", "manifest")?;
    assert!(rows.len() >= REQUIRED_SCENARIO_KINDS.len());
    let mut seen_scenarios = HashSet::new();
    let mut seen_modes = HashSet::new();
    for row in rows {
        for field in [
            "fixture_id",
            "scenario_kind",
            "function",
            "symbols",
            "input_class",
            "inputs",
            "rounding_mode",
            "runtime_mode",
            "replacement_level",
            "oracle_kind",
            "allowed_divergence",
        ] {
            assert!(row.get(field).is_some(), "fixture row missing {field}");
        }
        assert!(object_field(row, "expected", "fixture row")?.contains_key("fenv_flags"));
        assert!(object_field(row, "tolerance", "fixture row")?.contains_key("kind"));
        assert!(
            object_field(row, "fenv_restoration", "fixture row")?.contains_key("requires_restore")
        );
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
        seen_modes.insert(string_field(row, "runtime_mode", "fixture row")?.to_string());
    }
    for scenario in REQUIRED_SCENARIO_KINDS {
        assert!(
            seen_scenarios.contains(*scenario),
            "missing scenario {scenario}"
        );
    }
    assert!(seen_modes.contains("strict"));
    assert!(seen_modes.contains("hardened"));

    Ok(())
}

#[test]
fn gate_passes_and_emits_math_fenv_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("math-fenv-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("math-fenv-softfp.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        field(&report, "summary", "report")?
            .get("required_scenario_kind_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_SCENARIO_KINDS.len() as u64)
    );
    assert_eq!(
        field(&report, "summary", "report")?
            .get("exception_flag_count")
            .and_then(Value::as_u64),
        Some(REQUIRED_EXCEPTION_FLAGS.len() as u64)
    );

    let fixture_count = field(&report, "summary", "report")?
        .get("fixture_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| test_error("report.summary.fixture_count must be present"))?;
    let log_text = std::fs::read_to_string(out_dir.join("math-fenv-softfp.log.jsonl"))?;
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
        assert_eq!(string_field(&row, "bead_id", "log")?, "bd-bp8fl.5.7");
        assert_eq!(string_field(&row, "failure_signature", "log")?, "ok");
    }

    Ok(())
}

#[test]
fn gate_fails_closed_for_math_fenv_fixture_drift() -> TestResult {
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
    let stale_report = run_negative_case(&root, "math-fenv-stale", &stale)?;
    expect_failure_signature(&stale_report, "stale_artifact")?;

    let mut missing_source = base.clone();
    mutable_row_by_fixture_id(&mut missing_source, "math.overflow.exp_large.strict")?
        .get_mut("source_case_refs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("source_case_refs must be array"))?
        .push(Value::String("test:missing_math_anchor".to_string()));
    let missing_report = run_negative_case(&root, "math-fenv-missing-source", &missing_source)?;
    expect_failure_signature(&missing_report, "missing_source_artifact")?;

    let mut overflow_flags = base.clone();
    mutable_row_by_fixture_id(&mut overflow_flags, "math.overflow.exp_large.strict")?
        .get_mut("expected")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("expected must be object"))?
        .insert(
            "fenv_flags".to_string(),
            Value::Array(vec![Value::String("FE_INEXACT".to_string())]),
        );
    let flag_report = run_negative_case(&root, "math-fenv-overflow-flags", &overflow_flags)?;
    expect_failure_signature(&flag_report, "fenv_flag_mismatch")?;

    let mut tolerance = base.clone();
    mutable_row_by_fixture_id(&mut tolerance, "math.inexact.rint_half_even.strict")?
        .get_mut("tolerance")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("tolerance must be object"))?
        .insert("kind".to_string(), Value::String("unbounded".to_string()));
    let tolerance_report = run_negative_case(&root, "math-fenv-tolerance", &tolerance)?;
    expect_failure_signature(&tolerance_report, "tolerance_policy_mismatch")?;

    let mut nan = base.clone();
    mutable_row_by_fixture_id(&mut nan, "math.nan.fmaximum_propagation.hardened")?
        .get_mut("expected")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("expected must be object"))?
        .insert(
            "value_class".to_string(),
            Value::String("finite_rounded".to_string()),
        );
    let nan_report = run_negative_case(&root, "math-fenv-nan", &nan)?;
    expect_failure_signature(&nan_report, "nan_classification_mismatch")?;

    let mut softfp = base.clone();
    mutable_row_by_fixture_id(&mut softfp, "math.softfp.sinl_arch_sensitive.deferred")?
        .get_mut("expected")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("expected must be object"))?
        .insert("status".to_string(), Value::String("pass".to_string()));
    let softfp_report = run_negative_case(&root, "math-fenv-softfp", &softfp)?;
    expect_failure_signature(&softfp_report, "soft_fp_overclaim")?;

    let mut oracle = base;
    mutable_row_by_fixture_id(&mut oracle, "math.domain.asin_out_of_range.strict")?
        .as_object_mut()
        .ok_or_else(|| test_error("fixture row must be object"))?
        .insert(
            "allowed_divergence".to_string(),
            Value::String("not_declared".to_string()),
        );
    let oracle_report = run_negative_case(&root, "math-fenv-oracle", &oracle)?;
    expect_failure_signature(&oracle_report, "oracle_mismatch")?;

    Ok(())
}
