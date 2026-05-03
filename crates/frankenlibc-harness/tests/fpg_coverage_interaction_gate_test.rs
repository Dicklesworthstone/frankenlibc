//! Integration test: fpg coverage/interaction proof gate (bd-bp8fl.3.10)
//!
//! The gate binds ten FEATURE_PARITY proof/math rows to interaction matrices,
//! latency gates, and ABI/kernel equivalence witnesses. Missing anchors, stale
//! row bindings, or premature DONE claims must fail closed.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_GAP_IDS: &[&str] = &[
    "fp-proof-math-4577b75545e4",
    "fp-proof-math-638859dcb801",
    "fp-proof-math-77bcaf571ca9",
    "fp-proof-math-c76d1265a4b8",
    "fp-proof-math-0a9c8933d821",
    "fp-proof-math-a4fd102d5fd8",
    "fp-proof-math-25ac141c57f6",
    "fp-proof-math-0d50ca59b972",
    "fp-proof-math-d09a6233acb5",
    "fp-proof-math-080870cbbd8d",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "gap_id",
    "plan_id",
    "interaction_tuple",
    "coverage_level",
    "selected",
    "reason",
    "feature_parity_line",
    "evidence_artifact",
    "evidence_anchor",
    "evidence_verdict",
    "latency_gate",
    "equivalence_witness",
    "replacement_level",
    "claim_decision",
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

fn gate_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/fpg_coverage_interaction_gate.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/fpg_coverage_interaction_gate.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/fpg_coverage_interaction_gate.log.jsonl")
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

fn set_field(value: &mut Value, key: &str, replacement: Value, context: &str) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    object.insert(key.to_owned(), replacement);
    Ok(())
}

fn safe_workspace_path(root: &Path, rel: &str) -> TestResult<PathBuf> {
    let trimmed = rel.trim_end_matches('/');
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
    Command::new(root.join("scripts/check_fpg_coverage_interaction_gate.sh"))
        .current_dir(root)
        .output()
        .map_err(|err| {
            test_error(format!(
                "failed to run fpg coverage-interaction gate: {err}"
            ))
        })
}

fn run_gate_with_fixture(root: &Path, case_name: &str, gate: &Value) -> TestResult<PathBuf> {
    let out_dir = root.join("target/conformance/fpg_coverage_interaction_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", out_dir.display())))?;
    let gate_fixture = out_dir.join(format!("{case_name}.gate.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&gate_fixture, gate)?;

    let output = Command::new(root.join("scripts/check_fpg_coverage_interaction_gate.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_FPG_COVERAGE_INTERACTION_GATE", &gate_fixture)
        .env("FRANKENLIBC_FPG_COVERAGE_INTERACTION_REPORT", &report)
        .env("FRANKENLIBC_FPG_COVERAGE_INTERACTION_LOG", &log)
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

fn mutable_rows(gate: &mut Value) -> TestResult<&mut Vec<Value>> {
    gate.get_mut("rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("rows must be mutable array"))
}

#[test]
fn gate_artifact_covers_coverage_interaction_rows() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path(&root))?;
    ensure_eq(
        string_field(&gate, "schema_version", "gate")?,
        "v1",
        "schema",
    )?;
    ensure_eq(
        string_field(&gate, "bead", "gate")?,
        "bd-bp8fl.3.10",
        "bead",
    )?;
    ensure_eq(
        string_field(&gate, "owner_family_group", "gate")?,
        "fpg-proof-coverage-interaction",
        "owner_family_group",
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

    let mut required_fields = Vec::new();
    for value in as_array(
        field(&gate, "required_log_fields", "gate")?,
        "required_log_fields",
    )? {
        required_fields.push(
            value
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))?,
        );
    }
    ensure_eq(
        required_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let rows = as_array(field(&gate, "rows", "gate")?, "rows")?;
    ensure_eq(rows.len(), EXPECTED_GAP_IDS.len(), "row count")?;
    let mut actual_ids = BTreeSet::new();
    for row in rows {
        actual_ids.insert(string_field(row, "gap_id", "row")?);
        ensure_eq(
            string_field(row, "section", "row")?,
            "proof_math",
            "row section",
        )?;
        ensure(
            !as_array(field(row, "interaction_tuple", "row")?, "interaction_tuple")?.is_empty(),
            "interaction tuple must not be empty",
        )?;
        ensure(
            !string_field(row, "latency_gate", "row")?.is_empty()
                && !string_field(row, "equivalence_witness", "row")?.is_empty(),
            "latency and equivalence witnesses must be present",
        )?;
        ensure(
            !as_array(field(row, "evidence_anchors", "row")?, "evidence_anchors")?.is_empty(),
            "row anchors must not be empty",
        )?;
    }
    let expected_ids = EXPECTED_GAP_IDS.iter().copied().collect::<BTreeSet<_>>();
    ensure_eq(
        actual_ids,
        expected_ids,
        "coverage-interaction gap id coverage",
    )
}

#[test]
fn gate_script_passes_and_emits_structured_artifacts() -> TestResult {
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
    let expected_count = u64::try_from(EXPECTED_GAP_IDS.len())
        .map_err(|err| test_error(format!("expected gap count conversion failed: {err}")))?;
    let summary = field(&report, "summary", "report")?;
    ensure_eq(
        u64_field(summary, "row_count", "report.summary")?,
        expected_count,
        "report row_count",
    )?;

    let log = std::fs::read_to_string(log_path(&root))
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let mut line_count = 0usize;
    for line in log.lines() {
        line_count += 1;
        let entry: Value = serde_json::from_str(line)
            .map_err(|_| test_error("structured log entry should parse"))?;
        for field_name in REQUIRED_LOG_FIELDS {
            ensure(
                entry.get(*field_name).is_some(),
                "structured log entry is missing a required field",
            )?;
        }
    }
    ensure(
        line_count >= EXPECTED_GAP_IDS.len(),
        "log should include row evidence",
    )
}

#[test]
fn gate_rejects_missing_coverage_anchor() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_rows(&mut gate)?
        .get_mut(0)
        .ok_or_else(|| test_error("missing first gate row"))?;
    set_field(row, "evidence_anchors", Value::Array(Vec::new()), "row")?;
    let report = run_gate_with_fixture(&root, "missing_anchor", &gate)?;
    expect_failed_check(&report, "row_contract")
}

#[test]
fn gate_rejects_premature_done_claim() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_rows(&mut gate)?
        .get_mut(1)
        .ok_or_else(|| test_error("missing second gate row"))?;
    set_field(
        row,
        "claimed_status",
        Value::String("DONE".to_owned()),
        "row",
    )?;
    let report = run_gate_with_fixture(&root, "premature_done", &gate)?;
    expect_failed_check(&report, "claim_policy")
}

#[test]
fn gate_rejects_stale_feature_parity_binding() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_rows(&mut gate)?
        .get_mut(2)
        .ok_or_else(|| test_error("missing third gate row"))?;
    let provenance = row
        .get_mut("feature_parity_provenance")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("feature_parity_provenance must be an object"))?;
    provenance.insert("line".to_owned(), Value::from(244));
    let report = run_gate_with_fixture(&root, "stale_line", &gate)?;
    expect_failed_check(&report, "feature_parity_binding")
}

#[test]
fn gate_rejects_missing_equivalence_witness() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path(&root))?;
    let row = mutable_rows(&mut gate)?
        .get_mut(3)
        .ok_or_else(|| test_error("missing fourth gate row"))?;
    set_field(
        row,
        "equivalence_witness",
        Value::String(String::new()),
        "row",
    )?;
    let report = run_gate_with_fixture(&root, "missing_equivalence_witness", &gate)?;
    expect_failed_check(&report, "row_contract")
}
