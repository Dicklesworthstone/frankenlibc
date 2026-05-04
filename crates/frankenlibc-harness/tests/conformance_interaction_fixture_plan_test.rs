//! Integration test: conformance interaction fixture scheduler (bd-bp8fl.9.2)
//!
//! The gate keeps the fixture scheduler fail-closed: stale inventory, impossible
//! combinations, priority drift, and missing scheduler axes must block closure.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "plan_id",
    "interaction_tuple",
    "coverage_level",
    "selected",
    "reason",
    "artifact_refs",
    "source_commit",
    "failure_signature",
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

fn plan_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/conformance_interaction_fixture_plan.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/conformance_interaction_fixture_plan.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/conformance_interaction_fixture_plan.log.jsonl")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_conformance_interaction_fixture_plan.sh")
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

fn bool_field(value: &Value, key: &str, context: &str) -> TestResult<bool> {
    field(value, key, context)?
        .as_bool()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a bool")))
}

fn u64_field(value: &Value, key: &str, context: &str) -> TestResult<u64> {
    field(value, key, context)?
        .as_u64()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an unsigned integer")))
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

fn run_gate(root: &Path) -> TestResult<std::process::Output> {
    Command::new("bash")
        .arg(script_path(root))
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run interaction fixture gate: {err}")))
}

fn run_gate_with_fixture(root: &Path, case_name: &str, plan: &Value) -> TestResult<PathBuf> {
    let out_dir = root.join("target/conformance/conformance_interaction_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", out_dir.display())))?;
    let plan_fixture = out_dir.join(format!("{case_name}.plan.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&plan_fixture, plan)?;

    let output = Command::new("bash")
        .arg(script_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_CONFORMANCE_INTERACTION_PLAN", &plan_fixture)
        .env("FRANKENLIBC_CONFORMANCE_INTERACTION_REPORT", &report)
        .env("FRANKENLIBC_CONFORMANCE_INTERACTION_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run negative gate case: {err}")))?;
    ensure(
        !output.status.success(),
        format!("{case_name}: negative gate case should fail"),
    )?;
    Ok(report)
}

fn expect_failed_check(report: &Path, check: &str) -> TestResult {
    let report_json = load_json(report)?;
    ensure_eq(
        string_field(&report_json, "status", "report")?,
        "fail",
        format!("{} status", report.display()),
    )?;
    let checks = as_object(field(&report_json, "checks", "report")?, "report.checks")?;
    let check_status = checks
        .get(check)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("checks.{check} must be a string")))?;
    ensure_eq(check_status, "fail", format!("checks.{check}"))
}

fn mutable_candidates(plan: &mut Value) -> TestResult<&mut Vec<Value>> {
    plan.get_mut("candidates")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("candidates must be mutable array"))
}

fn mutable_scheduler_inputs(plan: &mut Value) -> TestResult<&mut serde_json::Map<String, Value>> {
    plan.get_mut("scheduler_inputs")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("scheduler_inputs must be mutable object"))
}

#[test]
fn plan_artifact_defines_scheduler_inputs_and_candidates() -> TestResult {
    let root = workspace_root();
    let plan = load_json(&plan_path(&root))?;
    ensure_eq(
        string_field(&plan, "schema_version", "plan")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(string_field(&plan, "bead", "plan")?, "bd-bp8fl.9.2", "bead")?;
    ensure_eq(
        string_field(&plan, "plan_id", "plan")?,
        "conformance-interaction-fixture-plan-v1",
        "plan_id",
    )?;

    let required_fields = as_array(
        field(&plan, "required_log_fields", "plan")?,
        "required_log_fields",
    )?;
    let required_fields: Vec<&str> = required_fields
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    ensure_eq(
        required_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let inputs = as_object(
        field(&plan, "scheduler_inputs", "plan")?,
        "scheduler_inputs",
    )?;
    for key in [
        "symbols",
        "modes",
        "locale_env_thread_state",
        "invalid_input_classes",
        "replacement_levels",
        "risk_weights",
        "fixture_inventory",
        "user_workload_exposure",
    ] {
        ensure(
            inputs.contains_key(key),
            "scheduler_inputs missing required key",
        )?;
    }
    let inventory = as_object(
        inputs
            .get("fixture_inventory")
            .ok_or_else(|| test_error("fixture_inventory missing"))?,
        "fixture_inventory",
    )?;
    let inventory_path = root.join(
        inventory
            .get("artifact")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("fixture_inventory.artifact must be a string"))?,
    );
    ensure(
        inventory_path.exists(),
        "fixture inventory artifact must exist",
    )?;
    ensure_eq(
        inventory
            .get("expected_campaign_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| test_error("expected_campaign_count must be unsigned integer"))?,
        18,
        "expected_campaign_count",
    )?;

    let candidates = as_array(field(&plan, "candidates", "plan")?, "candidates")?;
    ensure(
        candidates.len() >= 10,
        "candidate set must include selected and blocked rows",
    )?;
    let mut ids = BTreeSet::new();
    let mut feasible = 0;
    let mut blocked = 0;
    for row in candidates {
        let candidate_id = string_field(row, "candidate_id", "candidate")?;
        ensure(ids.insert(candidate_id), "candidate_id must be unique")?;
        let expected_score = u64_field(row, "risk_weight", candidate_id)? * 100
            + u64_field(row, "user_workload_exposure", candidate_id)? * 10
            + u64_field(row, "fixture_gap_weight", candidate_id)?
            + u64_field(row, "hard_parts_weight", candidate_id)?;
        ensure_eq(
            u64_field(row, "priority_score", candidate_id)?,
            expected_score,
            "candidate priority_score",
        )?;
        if bool_field(row, "feasible", candidate_id)? {
            feasible += 1;
        } else {
            blocked += 1;
            ensure(
                row.get("blocked_reason").and_then(Value::as_str).is_some(),
                "blocked candidates need blocked_reason",
            )?;
        }
    }
    ensure_eq(feasible, 8, "feasible candidate count")?;
    ensure_eq(blocked, 2, "blocked candidate count")?;
    Ok(())
}

#[test]
fn gate_generates_report_and_structured_logs() -> TestResult {
    let root = workspace_root();
    let output = run_gate(&root)?;
    ensure(
        output.status.success(),
        format!(
            "gate should pass\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&report_path(&root))?;
    ensure_eq(string_field(&report, "status", "report")?, "pass", "status")?;
    let metrics = field(&report, "metrics", "report")?;
    ensure_eq(
        u64_field(metrics, "pairwise_required", "metrics")?,
        u64_field(metrics, "pairwise_covered", "metrics")?,
        "pairwise coverage",
    )?;
    ensure_eq(
        u64_field(metrics, "twise_required", "metrics")?,
        u64_field(metrics, "twise_covered", "metrics")?,
        "t-wise coverage",
    )?;
    ensure_eq(
        u64_field(metrics, "selected_count", "metrics")?,
        8,
        "selected_count",
    )?;
    ensure_eq(
        u64_field(metrics, "blocked_count", "metrics")?,
        2,
        "blocked_count",
    )?;

    let log_content = std::fs::read_to_string(log_path(&root))
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    ensure(
        !log_content.trim().is_empty(),
        "structured log must be non-empty",
    )?;
    let mut saw_pairwise = false;
    let mut saw_twise = false;
    let mut saw_blocked = false;
    for line in log_content.lines() {
        let row: Value =
            serde_json::from_str(line).map_err(|_| test_error("log line should parse as JSON"))?;
        for field in REQUIRED_LOG_FIELDS {
            ensure(row.get(*field).is_some(), "log row missing required field")?;
        }
        match string_field(&row, "coverage_level", "log")? {
            "pairwise" => saw_pairwise = true,
            "t-wise" => saw_twise = true,
            "blocked" => saw_blocked = true,
            _ => {}
        }
    }
    ensure(saw_pairwise, "log must include pairwise rows")?;
    ensure(saw_twise, "log must include t-wise rows")?;
    ensure(saw_blocked, "log must include blocked diagnostics")?;
    Ok(())
}

#[test]
fn gate_rejects_stale_fixture_inventory() -> TestResult {
    let root = workspace_root();
    let mut plan = load_json(&plan_path(&root))?;
    let inputs = mutable_scheduler_inputs(&mut plan)?;
    let inventory = inputs
        .get_mut("fixture_inventory")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("fixture_inventory must be mutable object"))?;
    inventory.insert("expected_campaign_count".to_owned(), json!(999));
    let report = run_gate_with_fixture(&root, "stale_inventory", &plan)?;
    expect_failed_check(&report, "fixture_inventory_freshness")
}

#[test]
fn gate_rejects_impossible_selected_combinations() -> TestResult {
    let root = workspace_root();
    let mut plan = load_json(&plan_path(&root))?;
    let selected = plan
        .get_mut("selected_plan")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("selected_plan must be mutable array"))?;
    selected.pop();
    selected.push(json!("ca-009"));
    let report = run_gate_with_fixture(&root, "blocked_selected", &plan)?;
    expect_failed_check(&report, "blocked_combination_diagnostics")
}

#[test]
fn gate_rejects_priority_weighting_drift() -> TestResult {
    let root = workspace_root();
    let mut plan = load_json(&plan_path(&root))?;
    for row in mutable_candidates(&mut plan)? {
        if row.get("candidate_id").and_then(Value::as_str) == Some("ca-004") {
            *row.get_mut("priority_score")
                .ok_or_else(|| test_error("candidate priority_score must be mutable"))? = json!(1);
        }
    }
    let report = run_gate_with_fixture(&root, "priority_drift", &plan)?;
    expect_failed_check(&report, "candidate_contract")
}

#[test]
fn gate_rejects_missing_scheduler_axis() -> TestResult {
    let root = workspace_root();
    let mut plan = load_json(&plan_path(&root))?;
    mutable_scheduler_inputs(&mut plan)?.remove("invalid_input_classes");
    let report = run_gate_with_fixture(&root, "missing_scheduler_axis", &plan)?;
    expect_failed_check(&report, "scheduler_inputs")
}
