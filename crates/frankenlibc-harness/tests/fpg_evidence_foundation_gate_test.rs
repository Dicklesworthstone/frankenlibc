//! Integration test: fpg evidence foundation gate (bd-bp8fl.3.12)
//!
//! The gate binds the seven FEATURE_PARITY gap-summary foundation rows to
//! current machine-readable evidence. Missing anchors, stale line bindings, or
//! premature DONE claims must fail closed.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_GAP_IDS: &[&str] = &[
    "fp-gap-summary-7b67c9268b67",
    "fp-gap-summary-d643858a62b5",
    "fp-gap-summary-7c8a46cdcb5e",
    "fp-gap-summary-b04531fdcdde",
    "fp-gap-summary-3675b24bb188",
    "fp-gap-summary-e0624b12f6a0",
    "fp-gap-summary-be0b24532a7e",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "gap_id",
    "section",
    "feature_parity_line",
    "foundation_surface",
    "expected",
    "actual",
    "evidence_artifact",
    "evidence_anchor",
    "evidence_verdict",
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

fn gate_path() -> PathBuf {
    workspace_root().join("tests/conformance/fpg_evidence_foundation_gate.v1.json")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/fpg_evidence_foundation_gate.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/fpg_evidence_foundation_gate.log.jsonl")
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
    Command::new(root.join("scripts/check_fpg_evidence_foundation_gate.sh"))
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run fpg evidence foundation gate: {err}")))
}

fn run_gate_with_fixture(root: &Path, case_name: &str, gate: &Value) -> TestResult<PathBuf> {
    let out_dir = root.join("target/conformance/fpg_evidence_foundation_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", out_dir.display())))?;
    let gate_fixture = out_dir.join(format!("{case_name}.gate.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&gate_fixture, gate)?;

    let output = Command::new(root.join("scripts/check_fpg_evidence_foundation_gate.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_FPG_EVIDENCE_FOUNDATION_GATE", &gate_fixture)
        .env("FRANKENLIBC_FPG_EVIDENCE_FOUNDATION_REPORT", &report)
        .env("FRANKENLIBC_FPG_EVIDENCE_FOUNDATION_LOG", &log)
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
        report_json["status"].as_str(),
        Some("fail"),
        format!("{} status", report.display()),
    )?;
    ensure_eq(
        report_json["checks"][check].as_str(),
        Some("fail"),
        format!("checks.{check}"),
    )
}

#[test]
fn gate_artifact_covers_foundation_rows() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path())?;
    ensure_eq(gate["schema_version"].as_str(), Some("v1"), "schema")?;
    ensure_eq(gate["bead"].as_str(), Some("bd-bp8fl.3.12"), "bead")?;
    ensure_eq(
        gate["owner_family_group"].as_str(),
        Some("fpg-gap-summary-evidence-foundation"),
        "owner_family_group",
    )?;

    let inputs = as_object(&gate["inputs"], "inputs")?;
    for key in [
        "feature_parity",
        "feature_parity_gap_ledger",
        "feature_parity_gap_groups",
        "feature_parity_gap_owner_family_groups",
        "fixture_dir",
        "perf_baseline_spec",
        "version_script",
        "proof_obligations_binder",
        "proof_traceability_check",
        "runtime_math_linkage",
        "risk_pareto_calibration",
        "risk_pareto_gate",
        "membrane_mode_split_fixture",
    ] {
        let rel = inputs
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| test_error(format!("inputs.{key} must be a string")))?;
        ensure(
            root.join(rel.trim_end_matches('/')).exists(),
            format!("inputs.{key} points at missing artifact {rel}"),
        )?;
    }

    let required_fields: Vec<&str> = as_array(&gate["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        required_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let rows = as_array(&gate["rows"], "rows")?;
    ensure_eq(rows.len(), EXPECTED_GAP_IDS.len(), "row count")?;
    let actual_ids = rows
        .iter()
        .filter_map(|row| row["gap_id"].as_str())
        .collect::<BTreeSet<_>>();
    let expected_ids = EXPECTED_GAP_IDS.iter().copied().collect::<BTreeSet<_>>();
    ensure_eq(actual_ids, expected_ids, "foundation gap id coverage")?;
    for row in rows {
        ensure_eq(row["section"].as_str(), Some("gap_summary"), "row section")?;
        ensure(
            !as_array(&row["evidence_anchors"], "evidence_anchors")?.is_empty(),
            format!("{} anchors must not be empty", row["gap_id"]),
        )?;
    }
    Ok(())
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
    ensure_eq(report["status"].as_str(), Some("pass"), "report status")?;
    ensure_eq(
        report["summary"]["row_count"].as_u64(),
        Some(EXPECTED_GAP_IDS.len() as u64),
        "report row_count",
    )?;

    let log = std::fs::read_to_string(log_path(&root))
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let lines = log.lines().collect::<Vec<_>>();
    ensure(
        lines.len() >= EXPECTED_GAP_IDS.len(),
        "log should include row evidence",
    )?;
    for (idx, line) in lines.iter().enumerate() {
        let entry: Value = serde_json::from_str(line)
            .map_err(|err| test_error(format!("log line {idx} should parse: {err}")))?;
        for field in REQUIRED_LOG_FIELDS {
            ensure(
                entry.get(*field).is_some(),
                format!("log line {idx} missing field {field}"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn gate_rejects_missing_foundation_anchor() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path())?;
    let rows = gate["rows"]
        .as_array_mut()
        .ok_or_else(|| test_error("rows must be mutable array"))?;
    rows[0]["evidence_anchors"] = Value::Array(Vec::new());
    let report = run_gate_with_fixture(&root, "missing_anchor", &gate)?;
    expect_failed_check(&report, "row_contract")
}

#[test]
fn gate_rejects_premature_done_claim() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path())?;
    let rows = gate["rows"]
        .as_array_mut()
        .ok_or_else(|| test_error("rows must be mutable array"))?;
    rows[1]["claimed_status"] = Value::String("DONE".to_owned());
    let report = run_gate_with_fixture(&root, "premature_done", &gate)?;
    expect_failed_check(&report, "claim_policy")
}

#[test]
fn gate_rejects_stale_feature_parity_binding() -> TestResult {
    let root = workspace_root();
    let mut gate = load_json(&gate_path())?;
    let rows = gate["rows"]
        .as_array_mut()
        .ok_or_else(|| test_error("rows must be mutable array"))?;
    rows[2]["feature_parity_provenance"]["line"] = Value::from(277);
    let report = run_gate_with_fixture(&root, "stale_line", &gate)?;
    expect_failed_check(&report, "feature_parity_binding")
}
