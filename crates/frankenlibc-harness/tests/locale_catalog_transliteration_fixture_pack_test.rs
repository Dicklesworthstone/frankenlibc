//! Integration tests for the locale/catalog/transliteration fixture pack (bd-bp8fl.5.2).

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_CLASSES: &[&str] = &[
    "c_locale_collation",
    "utf8_locale_category_switch",
    "missing_locale_data",
    "collation_order",
    "catalog_lookup",
    "transliteration_boundary",
    "invalid_locale_name",
    "threaded_locale_read",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "fixture_id",
    "locale",
    "category",
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

const REQUIRED_DIAGNOSTIC_SIGNATURES: &[&str] = &[
    "stale_artifact",
    "missing_locale_data",
    "invalid_locale_name",
    "missing_catalog_fixture",
    "oracle_mismatch",
    "nondeterministic_output",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/locale_catalog_transliteration_fixture_pack.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_locale_catalog_transliteration_fixture_pack.sh")
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

fn mutable_scenarios(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("scenarios")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.scenarios must be mutable array"))
}

fn mutable_scenario(manifest: &mut Value, index: usize) -> TestResult<&mut Value> {
    mutable_scenarios(manifest)?
        .get_mut(index)
        .ok_or_else(|| test_error(format!("manifest.scenarios[{index}] must exist")))
}

fn object_field_mut<'a>(
    value: &'a mut Value,
    key: &str,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a mutable object")))
}

fn set_value(value: &mut Value, key: &str, replacement: Value, context: &str) -> TestResult {
    value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be a mutable object")))?
        .insert(key.to_string(), replacement);
    Ok(())
}

fn set_nested_value(
    value: &mut Value,
    object_key: &str,
    nested_key: &str,
    replacement: Value,
    context: &str,
) -> TestResult {
    object_field_mut(value, object_key, context)?.insert(nested_key.to_string(), replacement);
    Ok(())
}

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_LOCALE_FIXTURE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_LOCALE_FIXTURE_REPORT",
            out_dir.join("locale-fixture-pack.report.json"),
        )
        .env(
            "FRANKENLIBC_LOCALE_FIXTURE_LOG",
            out_dir.join("locale-fixture-pack.log.jsonl"),
        )
        .env("FRANKENLIBC_LOCALE_FIXTURE_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FRANKENLIBC_LOCALE_FIXTURE_PACK", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run locale fixture gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("locale-fixture-pack.report.json");
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
fn manifest_defines_locale_fixture_schema_and_required_classes() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.5.2"
    );
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "locale-catalog-transliteration-fixture-pack-v1"
    );

    let required_log_fields = array_field(&manifest, "required_log_fields", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(required_log_fields, REQUIRED_LOG_FIELDS);

    let fixture_classes = array_field(&manifest, "required_fixture_classes", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_fixture_classes entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(fixture_classes, REQUIRED_CLASSES);

    let scenarios = array_field(&manifest, "scenarios", "manifest")?;
    let mut covered_classes = scenarios
        .iter()
        .map(|scenario| string_field(scenario, "fixture_class", "scenario"))
        .collect::<TestResult<Vec<_>>>()?;
    covered_classes.sort_unstable();
    covered_classes.dedup();

    let mut required = REQUIRED_CLASSES.to_vec();
    required.sort_unstable();
    assert_eq!(covered_classes, required);

    for scenario in scenarios {
        assert!(!string_field(scenario, "locale", "scenario")?.is_empty());
        assert!(
            string_field(scenario, "category", "scenario")?.starts_with("LC_"),
            "category must be an LC_* category"
        );
        assert!(!array_field(scenario, "input_strings", "scenario")?.is_empty());
        assert!(object_field(scenario, "catalog_lookup", "scenario")?.contains_key("default_text"));
        assert!(object_field(scenario, "env_vars", "scenario")?.len() >= 2);
        assert!(
            array_field(scenario, "runtime_modes", "scenario")?
                .iter()
                .any(|mode| mode.as_str() == Some("strict"))
        );
        assert!(
            array_field(scenario, "runtime_modes", "scenario")?
                .iter()
                .any(|mode| mode.as_str() == Some("hardened"))
        );
        for expected_field in ["bytes", "text", "errno", "status", "decision_path"] {
            assert!(
                object_field(scenario, "expected", "scenario")?.contains_key(expected_field),
                "expected.{expected_field} should be present"
            );
        }
        assert!(object_field(scenario, "locale_data", "scenario")?.contains_key("path"));
        assert!(
            object_field(scenario, "determinism", "scenario")?
                .get("stability_iterations")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= 2
        );
        assert_eq!(
            string_field(
                field(scenario, "direct_runner", "scenario")?,
                "runner_kind",
                "direct_runner"
            )?,
            "direct"
        );
        assert!(
            string_field(
                field(scenario, "direct_runner", "scenario")?,
                "command",
                "direct_runner"
            )?
            .contains("rch exec -- cargo"),
            "direct runner must use rch exec -- cargo"
        );
        assert_eq!(
            string_field(
                field(scenario, "isolated_runner", "scenario")?,
                "runner_kind",
                "isolated_runner"
            )?,
            "isolated"
        );
    }

    let diagnostic_ids = array_field(&manifest, "diagnostic_signatures", "manifest")?
        .iter()
        .map(|row| string_field(row, "id", "diagnostic"))
        .collect::<TestResult<Vec<_>>>()?;
    for required_signature in REQUIRED_DIAGNOSTIC_SIGNATURES {
        assert!(
            diagnostic_ids.contains(required_signature),
            "missing diagnostic signature {required_signature}"
        );
    }

    Ok(())
}

#[test]
fn script_emits_pass_report_and_complete_jsonl_log() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("locale-fixture-pack-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    if !output.status.success() {
        return Err(test_error(format!(
            "locale fixture gate should pass\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let report = load_json(&out_dir.join("locale-fixture-pack.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    assert_eq!(
        array_field(&report, "covered_fixture_classes", "report")?.len(),
        REQUIRED_CLASSES.len()
    );

    let log_content = std::fs::read_to_string(out_dir.join("locale-fixture-pack.log.jsonl"))?;
    let log_rows = log_content
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        log_rows.len() >= REQUIRED_CLASSES.len() * 2,
        "strict+hardened logs should cover each class"
    );
    for row in &log_rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(
                row.get(field).is_some(),
                "log row missing {field}: {row:#?}"
            );
        }
        assert_eq!(string_field(row, "bead_id", "log")?, "bd-bp8fl.5.2");
        assert_eq!(string_field(row, "failure_signature", "log")?, "none");
    }

    Ok(())
}

#[test]
fn script_fails_closed_for_stale_missing_invalid_and_mismatched_inputs() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;

    let mut stale = manifest.clone();
    set_nested_value(
        &mut stale,
        "freshness",
        "required_source_commit",
        Value::String("not-current".to_string()),
        "manifest",
    )?;
    expect_failure_signature(
        &run_negative_case(&root, "locale-stale-artifact", &stale)?,
        "stale_artifact",
    )?;

    let mut missing_locale_data = manifest.clone();
    set_nested_value(
        mutable_scenario(&mut missing_locale_data, 0)?,
        "locale_data",
        "path",
        Value::String("tests/conformance/fixtures/missing-locale-data.json".to_string()),
        "scenario",
    )?;
    expect_failure_signature(
        &run_negative_case(&root, "locale-missing-data", &missing_locale_data)?,
        "missing_locale_data",
    )?;

    let mut invalid_locale = manifest.clone();
    set_value(
        mutable_scenario(&mut invalid_locale, 0)?,
        "locale",
        Value::String("bad locale with spaces".to_string()),
        "scenario",
    )?;
    expect_failure_signature(
        &run_negative_case(&root, "locale-invalid-name", &invalid_locale)?,
        "invalid_locale_name",
    )?;

    let mut missing_catalog = manifest.clone();
    set_nested_value(
        mutable_scenario(&mut missing_catalog, 4)?,
        "catalog_lookup",
        "default_text",
        Value::Null,
        "scenario",
    )?;
    expect_failure_signature(
        &run_negative_case(&root, "locale-missing-catalog", &missing_catalog)?,
        "missing_catalog_fixture",
    )?;

    let mut oracle_mismatch = manifest.clone();
    set_value(
        mutable_scenario(&mut oracle_mismatch, 0)?,
        "oracle_kind",
        Value::String("undocumented_oracle".to_string()),
        "scenario",
    )?;
    expect_failure_signature(
        &run_negative_case(&root, "locale-oracle-mismatch", &oracle_mismatch)?,
        "oracle_mismatch",
    )?;

    let mut nondeterministic = manifest.clone();
    set_nested_value(
        mutable_scenario(&mut nondeterministic, 0)?,
        "determinism",
        "stability_iterations",
        Value::from(1),
        "scenario",
    )?;
    expect_failure_signature(
        &run_negative_case(&root, "locale-nondeterministic", &nondeterministic)?,
        "nondeterministic_output",
    )?;

    let mut missing_field = manifest;
    set_value(
        mutable_scenario(&mut missing_field, 0)?,
        "category",
        Value::Null,
        "scenario",
    )?;
    expect_failure_signature(
        &run_negative_case(&root, "locale-missing-field", &missing_field)?,
        "missing_field",
    )?;

    Ok(())
}
