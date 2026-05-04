//! Integration tests for the hard-parts failure replay gate (bd-bp8fl.5.9).

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_FAMILIES: &[&str] = &[
    "resolver_nss",
    "locale_iconv",
    "loader_symbol",
    "stdio_error_state",
    "pthread_cancellation",
    "math_fenv",
    "signal_setjmp",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "failure_family",
    "scenario_id",
    "seed",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "status",
    "decision_path",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "cleanup_state",
    "failure_signature",
];

const REQUIRED_DIAGNOSTIC_SIGNATURES: &[&str] = &[
    "stale_artifact",
    "wrong_architecture",
    "missing_fixture",
    "nondeterministic_output",
    "oracle_mismatch",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/hard_parts_failure_replay_gate.v1.json")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_hard_parts_failure_replay_gate.sh")
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

fn run_gate(root: &Path, manifest: Option<&Path>, out_dir: &Path) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(script_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_HARD_PARTS_REPLAY_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_HARD_PARTS_REPLAY_REPORT",
            out_dir.join("hard-parts-replay.report.json"),
        )
        .env(
            "FRANKENLIBC_HARD_PARTS_REPLAY_LOG",
            out_dir.join("hard-parts-replay.log.jsonl"),
        )
        .env("FRANKENLIBC_HARD_PARTS_REPLAY_TARGET_DIR", out_dir);
    if let Some(manifest) = manifest {
        command.env("FRANKENLIBC_HARD_PARTS_REPLAY_GATE", manifest);
    }
    command
        .output()
        .map_err(|err| test_error(format!("failed to run hard-parts replay gate: {err}")))
}

fn run_negative_case(root: &Path, case_name: &str, manifest: &Value) -> TestResult<Value> {
    let out_dir = unique_temp_dir(case_name)?;
    let manifest_fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report_path = out_dir.join("hard-parts-replay.report.json");
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
fn manifest_defines_replay_schema_and_required_hard_parts_families() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version", "manifest")?, "v1");
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-bp8fl.5.9"
    );
    assert_eq!(
        string_field(&manifest, "gate_id", "manifest")?,
        "hard-parts-failure-replay-gate-v1"
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

    let family_list = array_field(&manifest, "required_failure_families", "manifest")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_failure_families entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(family_list, REQUIRED_FAMILIES);

    let scenarios = array_field(&manifest, "scenarios", "manifest")?;
    let mut covered_families = scenarios
        .iter()
        .map(|scenario| string_field(scenario, "failure_family", "scenario"))
        .collect::<TestResult<Vec<_>>>()?;
    covered_families.sort_unstable();
    covered_families.dedup();

    let mut required = REQUIRED_FAMILIES.to_vec();
    required.sort_unstable();
    assert_eq!(covered_families, required);

    for scenario in scenarios {
        assert!(object_field(scenario, "input_artifact", "scenario")?.contains_key("path"));
        assert!(object_field(scenario, "environment", "scenario")?.len() >= 2);
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
        assert!(object_field(scenario, "expected", "scenario")?.contains_key("decision_path"));
        assert!(object_field(scenario, "cleanup", "scenario")?.contains_key("state"));
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
        assert_eq!(
            string_field(
                field(scenario, "isolated_runner", "scenario")?,
                "runner_kind",
                "isolated_runner"
            )?,
            "isolated"
        );
    }

    Ok(())
}

#[test]
fn gate_passes_and_emits_direct_isolated_replay_logs() -> TestResult {
    let root = workspace_root();
    let out_dir = unique_temp_dir("hard-parts-replay-pass")?;
    let output = run_gate(&root, None, &out_dir)?;
    assert!(
        output.status.success(),
        "gate should pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("hard-parts-replay.report.json"))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    let summary = field(&report, "summary", "report")?;
    assert_eq!(
        summary.get("covered_family_count").and_then(Value::as_u64),
        Some(REQUIRED_FAMILIES.len() as u64)
    );
    assert_eq!(
        summary.get("direct_runner_count").and_then(Value::as_u64),
        Some(REQUIRED_FAMILIES.len() as u64)
    );
    assert_eq!(
        summary.get("isolated_runner_count").and_then(Value::as_u64),
        Some(REQUIRED_FAMILIES.len() as u64)
    );

    let diagnostics = array_field(&report, "diagnostic_signatures", "report")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("diagnostic signature entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    for signature in REQUIRED_DIAGNOSTIC_SIGNATURES {
        assert!(diagnostics.contains(signature), "missing {signature}");
    }

    let log_text = std::fs::read_to_string(out_dir.join("hard-parts-replay.log.jsonl"))?;
    let rows = log_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), REQUIRED_FAMILIES.len() * 2 * 2);
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "log row missing {field}");
        }
        assert_eq!(string_field(&row, "bead_id", "log")?, "bd-bp8fl.5.9");
        assert_eq!(string_field(&row, "failure_signature", "log")?, "ok");
        assert!(
            ["direct", "isolated"].contains(
                &row.get("actual")
                    .and_then(|actual| actual.get("runner_kind"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            )
        );
    }

    Ok(())
}

#[test]
fn gate_fails_closed_with_distinct_replay_diagnostics() -> TestResult {
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
    let stale_report = run_negative_case(&root, "hard-parts-replay-stale", &stale)?;
    expect_failure_signature(&stale_report, "stale_artifact")?;

    let mut wrong_arch = base.clone();
    wrong_arch
        .as_object_mut()
        .ok_or_else(|| test_error("manifest must be object"))?
        .insert(
            "supported_architectures".to_string(),
            Value::Array(vec![Value::String("not-the-current-arch".to_string())]),
        );
    let wrong_arch_report = run_negative_case(&root, "hard-parts-replay-wrong-arch", &wrong_arch)?;
    expect_failure_signature(&wrong_arch_report, "wrong_architecture")?;

    let mut missing_fixture = base.clone();
    mutable_scenario(&mut missing_fixture, 0)?
        .get_mut("input_artifact")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("input_artifact must be object"))?
        .insert(
            "path".to_string(),
            Value::String("tests/conformance/fixtures/does_not_exist.json".to_string()),
        );
    let missing_fixture_report =
        run_negative_case(&root, "hard-parts-replay-missing-fixture", &missing_fixture)?;
    expect_failure_signature(&missing_fixture_report, "missing_fixture")?;

    let mut nondeterministic = base.clone();
    mutable_scenario(&mut nondeterministic, 1)?
        .get_mut("determinism")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("determinism must be object"))?
        .insert("stability_iterations".to_string(), Value::from(1));
    let nondeterministic_report = run_negative_case(
        &root,
        "hard-parts-replay-nondeterministic",
        &nondeterministic,
    )?;
    expect_failure_signature(&nondeterministic_report, "nondeterministic_output")?;

    let mut oracle_mismatch = base.clone();
    mutable_scenario(&mut oracle_mismatch, 2)?
        .as_object_mut()
        .ok_or_else(|| test_error("scenario must be object"))?
        .insert(
            "oracle_kind".to_string(),
            Value::String("not_a_declared_oracle".to_string()),
        );
    let oracle_mismatch_report =
        run_negative_case(&root, "hard-parts-replay-oracle-mismatch", &oracle_mismatch)?;
    expect_failure_signature(&oracle_mismatch_report, "oracle_mismatch")?;

    let mut unsupported = base;
    mutable_scenario(&mut unsupported, 3)?
        .as_object_mut()
        .ok_or_else(|| test_error("scenario must be object"))?
        .insert(
            "failure_family".to_string(),
            Value::String("unsupported_family".to_string()),
        );
    let unsupported_report =
        run_negative_case(&root, "hard-parts-replay-unsupported", &unsupported)?;
    expect_failure_signature(&unsupported_report, "unsupported_scenario_class")?;

    Ok(())
}
