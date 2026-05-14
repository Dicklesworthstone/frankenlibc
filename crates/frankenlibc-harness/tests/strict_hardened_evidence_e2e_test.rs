//! Integration test: strict/hardened runtime evidence e2e scenarios (bd-b92jd.4.3)
//!
//! The gate freezes hermetic strict and hardened runtime-evidence scenarios for
//! string, malloc, stdio, pthread, and resolver paths. Missing family/mode
//! coverage, real network requirements, destructive operations, missing repair
//! evidence, and strict-mode repair attempts fail closed.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_FAMILIES: &[&str] = &["string", "malloc", "stdio", "pthread", "resolver"];
const REQUIRED_MODES: &[&str] = &["strict", "hardened"];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "validation_profile",
    "expected_decision",
    "actual_decision",
    "healing_action",
    "denied",
    "target_dir",
    "source_commit",
    "artifact_refs",
    "safety_signature",
    "failure_signature",
];
const REQUIRED_NEGATIVE_SIGNATURES: &[&str] = &[
    "strict_hardened_e2e_missing_family",
    "strict_hardened_e2e_missing_mode",
    "strict_hardened_e2e_real_network_required",
    "strict_hardened_e2e_destructive_operation",
    "strict_hardened_e2e_missing_healing_action",
    "strict_hardened_e2e_strict_repair_not_allowed",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn require_log_field(entry: &Value, field: &str, line_count: usize) -> TestResult {
    ensure(
        entry.get(field).is_some(),
        format!("structured log line {line_count} missing required field `{field}`"),
    )
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
    root.join("tests/conformance/strict_hardened_evidence_e2e.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/strict_hardened_evidence_e2e.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/strict_hardened_evidence_e2e.log.jsonl")
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

fn as_array<'a>(value: &'a Value, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn as_object<'a>(
    value: &'a Value,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| test_error(format!("{context} must be an object")))
}

fn set_object_field(value: &mut Value, key: &str, replacement: Value, context: &str) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    object.insert(key.to_owned(), replacement);
    Ok(())
}

fn set_nested_object_field(
    value: &mut Value,
    object_key: &str,
    field_key: &str,
    replacement: Value,
    context: &str,
) -> TestResult {
    let object = value
        .get_mut(object_key)
        .ok_or_else(|| test_error(format!("{context}.{object_key} is missing")))?;
    set_object_field(object, field_key, replacement, context)
}

fn safe_workspace_path(root: &Path, reference: &str) -> TestResult<PathBuf> {
    let trimmed = reference
        .split_once('#')
        .map_or(reference, |(path, _fragment)| path)
        .trim_end_matches('/');
    let rel_path = Path::new(trimmed);
    ensure(!rel_path.is_absolute(), "artifact path must be relative")?;
    for component in rel_path.components() {
        ensure(
            matches!(component, Component::Normal(_)),
            "artifact path contains unsafe components",
        )?;
    }
    Ok(root.join(rel_path)) // ubs:ignore - rel_path is rejected unless relative with only normal components.
}

fn run_gate(root: &Path) -> TestResult<std::process::Output> {
    Command::new(root.join("scripts/check_strict_hardened_evidence_e2e.sh"))
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run strict/hardened e2e gate: {err}")))
}

fn run_gate_with_fixture(root: &Path, case_name: &str, gate: &Value) -> TestResult<PathBuf> {
    let out_dir = root.join("target/conformance/strict_hardened_evidence_e2e_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", out_dir.display())))?;
    let gate_fixture = out_dir.join(format!("{case_name}.gate.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&gate_fixture, gate)?;

    let output = Command::new(root.join("scripts/check_strict_hardened_evidence_e2e.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_STRICT_HARDENED_E2E_GATE", &gate_fixture)
        .env("FRANKENLIBC_STRICT_HARDENED_E2E_REPORT", &report)
        .env("FRANKENLIBC_STRICT_HARDENED_E2E_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run negative gate case: {err}")))?;
    ensure(
        !output.status.success(),
        format!("{case_name}: negative gate case should fail"),
    )?;
    Ok(report)
}

fn expect_error_signature(report: &Path, signature: &str) -> TestResult {
    let report_json = load_json(report)?;
    ensure_eq(
        string_field(&report_json, "status", "report")?,
        "fail",
        format!("{} status", report.display()),
    )?;
    let errors = as_array(field(&report_json, "errors", "report")?, "report.errors")?;
    ensure(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(signature)),
        format!("report errors should include {signature}"),
    )
}

fn mutable_scenarios(gate: &mut Value) -> TestResult<&mut Vec<Value>> {
    gate.get_mut("scenarios")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("scenarios must be a mutable array"))
}

#[test]
fn e2e_artifact_covers_strict_hardened_runtime_evidence_contract() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path(&root))?;
    ensure_eq(
        string_field(&gate, "schema_version", "gate")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(string_field(&gate, "bead", "gate")?, "bd-b92jd.4.3", "bead")?;
    ensure(
        field(&gate, "runtime_evidence_enabled", "gate")?.as_bool() == Some(true),
        "runtime evidence must be enabled",
    )?;
    ensure(
        !string_field(&gate, "target_dir", "gate")?.is_empty(),
        "target_dir must be persisted",
    )?;
    ensure(
        !string_field(&gate, "source_commit", "gate")?.is_empty(),
        "source_commit must be persisted",
    )?;

    let network = as_object(field(&gate, "network_policy", "gate")?, "network_policy")?;
    ensure(
        network
            .get("real_network_required")
            .and_then(Value::as_bool)
            == Some(false),
        "resolver coverage must be hermetic",
    )?;
    let safety = as_object(
        field(&gate, "operation_safety", "gate")?,
        "operation_safety",
    )?;
    ensure(
        safety
            .get("destructive_system_operation")
            .and_then(Value::as_bool)
            == Some(false),
        "gate must not require destructive operations",
    )?;

    let inputs = as_object(field(&gate, "inputs", "gate")?, "inputs")?;
    for value in inputs.values() {
        let rel = value
            .as_str()
            .ok_or_else(|| test_error("input artifact path must be a string"))?;
        ensure(
            safe_workspace_path(&root, rel)?.exists(),
            "input artifact path points at missing file",
        )?;
    }

    let required_fields: Vec<&str> = as_array(
        field(&gate, "required_log_fields", "gate")?,
        "required_log_fields",
    )?
    .iter()
    .filter_map(Value::as_str)
    .collect();
    ensure_eq(
        required_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let scenarios = as_array(field(&gate, "scenarios", "gate")?, "scenarios")?;
    let mut family_modes = BTreeSet::new();
    let mut hardened_repairs = BTreeSet::new();
    for scenario in scenarios {
        let family = string_field(scenario, "api_family", "scenario")?;
        let mode = string_field(scenario, "runtime_mode", "scenario")?;
        family_modes.insert((family, mode));
        ensure_eq(
            string_field(scenario, "mode", "scenario")?,
            mode,
            "mode/runtime_mode parity",
        )?;
        ensure(
            field(scenario, "runtime_evidence_enabled", "scenario")?.as_bool() == Some(true),
            "scenario runtime evidence must be enabled",
        )?;
        let expected = string_field(scenario, "expected_decision", "scenario")?;
        ensure_eq(
            string_field(scenario, "actual_decision", "scenario")?,
            expected,
            "decision parity",
        )?;
        if mode == "strict" {
            ensure(
                expected != "Repair",
                "strict scenarios must not repair invalid inputs",
            )?;
            ensure(
                field(scenario, "expected_repair", "scenario")?.is_null(),
                "strict scenarios must not carry repair actions",
            )?;
        }
        if mode == "hardened" && expected == "Repair" {
            hardened_repairs.insert(family);
            ensure(
                string_field(scenario, "expected_repair", "scenario").is_ok(),
                "hardened repair scenario must carry expected_repair",
            )?;
        }
        ensure(
            !string_field(scenario, "target_dir", "scenario")?.is_empty(),
            "scenario target_dir must be persisted",
        )?;
        ensure(
            !string_field(scenario, "source_commit", "scenario")?.is_empty(),
            "scenario source_commit must be persisted",
        )?;
        let safety = as_object(
            field(scenario, "operation_safety", "scenario")?,
            "operation_safety",
        )?;
        ensure(
            safety.get("real_network_required").and_then(Value::as_bool) == Some(false),
            "scenario must not require real network",
        )?;
        ensure(
            safety
                .get("destructive_system_operation")
                .and_then(Value::as_bool)
                == Some(false),
            "scenario must not require destructive operations",
        )?;
        ensure(
            safe_workspace_path(
                &root,
                string_field(scenario, "fixture_case_ref", "scenario")?,
            )?
            .exists(),
            "fixture_case_ref points at missing file",
        )?;
        let refs = as_array(
            field(scenario, "artifact_refs", "scenario")?,
            "artifact_refs",
        )?;
        ensure(!refs.is_empty(), "artifact_refs must not be empty")?;
        for rel in refs {
            let path = rel
                .as_str()
                .ok_or_else(|| test_error("artifact_refs entries must be strings"))?;
            ensure(
                safe_workspace_path(&root, path)?.exists(),
                "artifact_refs entry points at missing file",
            )?;
        }
    }
    for family in REQUIRED_FAMILIES {
        for mode in REQUIRED_MODES {
            ensure(
                family_modes.contains(&(*family, *mode)),
                "missing required family/mode scenario coverage",
            )?;
        }
        ensure(
            hardened_repairs.contains(family),
            "hardened repair coverage missing for required family",
        )?;
    }

    let negative_cases = as_array(
        field(&gate, "negative_scenario_cases", "gate")?,
        "negative_scenario_cases",
    )?;
    let signatures = negative_cases
        .iter()
        .filter_map(|case| {
            case.get("expected_failure_signature")
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let expected_signatures = REQUIRED_NEGATIVE_SIGNATURES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    ensure_eq(
        signatures,
        expected_signatures,
        "negative signature coverage",
    )
}

#[test]
fn e2e_gate_script_passes_and_emits_report_and_jsonl_log() -> TestResult {
    let root = workspace_root();
    let output = run_gate(&root)?;
    ensure(
        output.status.success(),
        format!(
            "gate script failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&report_path(&root))?;
    ensure_eq(
        string_field(&report, "status", "report")?,
        "pass",
        "report status",
    )?;
    let summary = field(&report, "summary", "report")?;
    ensure_eq(
        field(summary, "scenario_count", "report.summary")?.as_u64(),
        Some(10),
        "report scenario_count",
    )?;
    ensure(
        !string_field(&report, "target_dir", "report")?.is_empty(),
        "report target_dir must be persisted",
    )?;
    ensure(
        !string_field(&report, "source_commit", "report")?.is_empty(),
        "report source_commit must be persisted",
    )?;

    let log = std::fs::read_to_string(log_path(&root))
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let mut line_count = 0usize;
    for line in log.lines() {
        line_count += 1;
        let entry: Value = serde_json::from_str(line)
            .map_err(|_| test_error("structured log entry should parse"))?;
        for field_name in REQUIRED_LOG_FIELDS {
            require_log_field(&entry, field_name, line_count)?;
        }
    }
    ensure_eq(line_count, 16usize, "structured log row count")
}

#[test]
fn e2e_gate_fails_closed_when_required_family_is_missing() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    mutable_scenarios(&mut gate)?
        .retain(|scenario| scenario.get("api_family").and_then(Value::as_str) != Some("resolver"));
    let report = run_gate_with_fixture(&root, "missing_family", &gate)?;
    expect_error_signature(&report, "strict_hardened_e2e_missing_family")
}

#[test]
fn e2e_gate_fails_closed_when_required_mode_is_missing() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    mutable_scenarios(&mut gate)?.retain(|scenario| {
        let family = scenario.get("api_family").and_then(Value::as_str);
        let mode = scenario.get("runtime_mode").and_then(Value::as_str);
        !(family == Some("string") && mode == Some("hardened"))
    });
    let report = run_gate_with_fixture(&root, "missing_mode", &gate)?;
    expect_error_signature(&report, "strict_hardened_e2e_missing_mode")
}

#[test]
fn e2e_gate_fails_closed_for_real_network_requirement() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    set_nested_object_field(
        &mut gate,
        "network_policy",
        "real_network_required",
        json!(true),
        "gate",
    )?;
    let report = run_gate_with_fixture(&root, "real_network_required", &gate)?;
    expect_error_signature(&report, "strict_hardened_e2e_real_network_required")
}

#[test]
fn e2e_gate_fails_closed_for_destructive_operation_requirement() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    set_nested_object_field(
        &mut gate,
        "operation_safety",
        "destructive_system_operation",
        json!(true),
        "gate",
    )?;
    let report = run_gate_with_fixture(&root, "destructive_operation", &gate)?;
    expect_error_signature(&report, "strict_hardened_e2e_destructive_operation")
}

#[test]
fn e2e_gate_fails_closed_for_missing_hardened_healing_action() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let scenario = mutable_scenarios(&mut gate)?
        .iter_mut()
        .find(|scenario| {
            scenario.get("scenario_id").and_then(Value::as_str)
                == Some("malloc-double-free-hardened")
        })
        .ok_or_else(|| test_error("missing malloc hardened scenario"))?;
    set_object_field(scenario, "expected_repair", Value::Null, "scenario")?;
    set_nested_object_field(
        scenario,
        "evidence_row",
        "healing_action",
        Value::Null,
        "scenario",
    )?;
    let report = run_gate_with_fixture(&root, "missing_healing_action", &gate)?;
    expect_error_signature(&report, "strict_hardened_e2e_missing_healing_action")
}

#[test]
fn e2e_gate_fails_closed_for_strict_mode_repair_attempt() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let scenario = mutable_scenarios(&mut gate)?
        .iter_mut()
        .find(|scenario| {
            scenario.get("scenario_id").and_then(Value::as_str)
                == Some("string-memcpy-overflow-strict")
        })
        .ok_or_else(|| test_error("missing string strict scenario"))?;
    set_object_field(scenario, "expected_decision", json!("Repair"), "scenario")?;
    set_object_field(scenario, "actual_decision", json!("Repair"), "scenario")?;
    set_object_field(scenario, "expected_repair", json!("ClampSize"), "scenario")?;
    set_object_field(
        scenario,
        "decision_path",
        json!(["mode", "string_bounds_probe", "repair"]),
        "scenario",
    )?;
    set_nested_object_field(
        scenario,
        "evidence_row",
        "decision_action",
        json!("Repair"),
        "scenario",
    )?;
    set_nested_object_field(
        scenario,
        "evidence_row",
        "healing_action",
        json!("ClampSize"),
        "scenario",
    )?;
    let report = run_gate_with_fixture(&root, "strict_repair", &gate)?;
    expect_error_signature(&report, "strict_hardened_e2e_strict_repair_not_allowed")
}
