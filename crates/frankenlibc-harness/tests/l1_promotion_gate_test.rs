//! Integration test: L1 replacement-level promotion gate (bd-b92jd.1.3).
//!
//! Refuses to advance current_level past L0 unless every evidence
//! requirement in `tests/conformance/l1_promotion_gate.v1.json` is
//! currently met by its cited artifact. Each requirement is a
//! (artifact, field, expected_value | expected_kind) triple; the gate
//! resolves the field via dotted-path traversal (with one level of
//! `levels[level=L1]`-style filter for the replacement-levels artifact)
//! and asserts byte-for-byte equality.

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult = Result<(), Box<dyn Error>>;

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

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn as_str<'a>(value: &'a Value, context: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .ok_or_else(|| test_error(format!("{context} must be a string")))
}

fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn gate_path() -> PathBuf {
    workspace_root().join("tests/conformance/l1_promotion_gate.v1.json")
}

fn git_head(root: &Path) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("git rev-parse HEAD should run: {err}")))?;
    ensure(
        output.status.success(),
        format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    Ok(String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("git HEAD should be UTF-8: {err}")))?
        .trim()
        .to_owned())
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "promotion_run_id",
    "from_level",
    "to_level",
    "evidence_artifact",
    "evidence_status",
    "expected",
    "actual",
    "blocker_id",
    "decision",
    "rejection_reason",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "missing_artifact",
    "schema_drift",
    "source_commit_zero_or_blank",
    "stale_source_commit",
    "current_level_drifted_above_l0_without_gate_pass",
    "claim_reconciliation_status_not_pass",
];

const BLOCK_PROMOTION_KINDS: &[&str] = &[
    "missing_evidence_artifact",
    "stale_source_commit",
    "claim_reconciliation_errors",
    "smoke_summary_fails_or_skips_above_floor",
    "perf_waiver_broad_or_expired",
    "feature_parity_done_without_evidence",
    "readme_overclaim_relative_to_replacement_levels",
    "blocker_unresolved",
];

/// Resolve a dotted-path field expression with one supported filter form:
///
///   `levels[level=L1].blockers`  → find array element where .level == "L1"
///   `summary.errors`             → straight nested field access
fn select_field<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = root;
    for segment in path.split('.') {
        if let Some(idx) = segment.find('[') {
            let (key, filter) = segment.split_at(idx);
            let filter = filter.strip_prefix('[').and_then(|s| s.strip_suffix(']'))?;
            let (fkey, fvalue) = filter.split_once('=')?;
            let arr = cursor.get(key)?.as_array()?;
            cursor = arr
                .iter()
                .find(|el| el.get(fkey).and_then(|v| v.as_str()) == Some(fvalue))?;
        } else {
            cursor = cursor.get(segment)?;
        }
    }
    Some(cursor)
}

#[test]
fn gate_artifact_is_well_formed() -> TestResult {
    let gate = load_json(&gate_path())?;
    ensure_eq(
        gate["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(gate["bead"].as_str(), Some("bd-b92jd.1.3"), "bead")?;
    ensure(
        !gate["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;
    let freshness_policy = &gate["source_commit_freshness_policy"];
    ensure_eq(
        freshness_policy["recorded_source_commit_field"].as_str(),
        Some("source_commit"),
        "source_commit_freshness_policy.recorded_source_commit_field",
    )?;
    ensure_eq(
        freshness_policy["comparison_target"].as_str(),
        Some("current git HEAD"),
        "source_commit_freshness_policy.comparison_target",
    )?;
    ensure_eq(
        freshness_policy["stale_result"].as_str(),
        Some("block_l1_promotion"),
        "source_commit_freshness_policy.stale_result",
    )?;
    ensure_eq(
        freshness_policy["promotion_allowed_when_stale"].as_bool(),
        Some(false),
        "source_commit_freshness_policy.promotion_allowed_when_stale",
    )?;
    ensure_eq(
        freshness_policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "source_commit_freshness_policy.rejected_evidence_kind",
    )?;

    let inputs = gate["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for key in [
        "replacement_levels",
        "claim_reconciliation_report",
        "ld_preload_smoke_summary",
        "perf_regression_prevention",
        "perf_waiver_audit",
        "perf_budget_policy",
        "support_matrix",
        "fpg_claim_control_gate",
        "fpg_proof_core_safety_gate",
        "feature_parity",
        "readme",
    ] {
        let path = inputs
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| test_error(format!("inputs.{key} must be a string")))?;
        ensure(
            workspace_root().join(path).exists(),
            format!("inputs.{key} must reference an existing artifact: {path}"),
        )?;
    }

    let log_fields: Vec<&str> = as_array(&gate["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &gate["policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_l1_evidence_current"),
        "policy.default_decision",
    )?;
    ensure_eq(
        policy["current_level_at_audit_time"].as_str(),
        Some("L0"),
        "policy.current_level_at_audit_time",
    )?;
    ensure_eq(
        policy["max_promotion_target"].as_str(),
        Some("L1"),
        "policy.max_promotion_target",
    )?;
    let block: Vec<&str> = as_array(&policy["block_promotion_kinds"], "block_promotion_kinds")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    for kind in BLOCK_PROMOTION_KINDS {
        ensure(
            block.contains(kind),
            format!("block_promotion_kinds must include {kind}"),
        )?;
    }
    let rejected: Vec<&str> = as_array(
        &policy["rejected_evidence_kinds"],
        "rejected_evidence_kinds",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for kind in REJECTED_EVIDENCE_KINDS {
        ensure(
            rejected.contains(kind),
            format!("rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn stale_source_commit_policy_blocks_l1_promotion() -> TestResult {
    let root = workspace_root();
    let gate = load_json(&gate_path())?;
    let gate_commit = as_str(&gate["source_commit"], "source_commit")?;
    ensure(
        gate_commit.len() == 40 && gate_commit.chars().all(|ch| ch.is_ascii_hexdigit()),
        "source_commit must be a 40-character git SHA",
    )?;

    let current_head = git_head(&root)?;
    if gate_commit != current_head {
        let policy = &gate["source_commit_freshness_policy"];
        ensure_eq(
            policy["stale_result"].as_str(),
            Some("block_l1_promotion"),
            "stale promotion gate source_commit must block L1 promotion",
        )?;
        ensure_eq(
            policy["promotion_allowed_when_stale"].as_bool(),
            Some(false),
            "stale promotion gate source_commit must not allow promotion",
        )?;
        ensure_eq(
            policy["rejected_evidence_kind"].as_str(),
            Some("stale_source_commit"),
            "stale promotion gate source_commit must use stale_source_commit",
        )?;
    }

    Ok(())
}

#[test]
fn current_level_remains_l0_until_gate_passes() -> TestResult {
    let levels = load_json(&workspace_root().join("tests/conformance/replacement_levels.json"))?;
    let current = as_str(&levels["current_level"], "current_level")?;
    ensure_eq(
        current,
        "L0",
        "current_level must remain L0 until L1 promotion gate passes — drift detected",
    )
}

#[test]
fn every_evidence_requirement_resolves_against_its_cited_artifact() -> TestResult {
    let gate = load_json(&gate_path())?;
    let root = workspace_root();

    for req in as_array(
        &gate["evidence_requirements_for_l1"],
        "evidence_requirements_for_l1",
    )? {
        let req_id = as_str(&req["requirement_id"], "req.requirement_id")?;
        let artifact = as_str(&req["evidence_artifact"], "req.evidence_artifact")?;
        let field = as_str(&req["field"], "req.field")?;
        let abs_path = root.join(artifact);
        ensure(
            abs_path.exists(),
            format!("{req_id}: evidence_artifact missing on disk: {artifact}"),
        )?;
        let json = load_json(&abs_path)?;
        let actual = select_field(&json, field).ok_or_else(|| {
            test_error(format!(
                "{req_id}: field path {field} did not resolve in {artifact}"
            ))
        })?;

        if let Some(expected) = req.get("expected_value") {
            ensure_eq(
                actual,
                expected,
                format!("{req_id}: artifact {artifact} field {field} drift"),
            )?;
        } else if let Some(expected_kind) = req.get("expected_kind").and_then(|v| v.as_str()) {
            match expected_kind {
                "non_empty_array" => {
                    let arr = actual.as_array().ok_or_else(|| {
                        test_error(format!(
                            "{req_id}: field {field} must be an array (kind=non_empty_array)"
                        ))
                    })?;
                    ensure(
                        !arr.is_empty(),
                        format!("{req_id}: field {field} must be a non-empty array"),
                    )?;
                }
                other => {
                    return Err(test_error(format!(
                        "{req_id}: unknown expected_kind {other}"
                    )));
                }
            }
        } else {
            return Err(test_error(format!(
                "{req_id}: requirement must declare expected_value or expected_kind"
            )));
        }
    }
    Ok(())
}

#[test]
fn requirement_ids_are_unique() -> TestResult {
    let gate = load_json(&gate_path())?;
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for req in as_array(
        &gate["evidence_requirements_for_l1"],
        "evidence_requirements_for_l1",
    )? {
        let req_id = as_str(&req["requirement_id"], "req.requirement_id")?;
        ensure(
            seen.insert(req_id.to_string()),
            format!("duplicate requirement_id {req_id}"),
        )?;
    }
    ensure(
        seen.len() >= 5,
        format!(
            "gate must list at least 5 requirements; found {}",
            seen.len()
        ),
    )?;
    Ok(())
}

#[test]
fn consuming_gates_exist_on_disk() -> TestResult {
    let gate = load_json(&gate_path())?;
    let root = workspace_root();
    for path in as_array(&gate["consuming_gates"], "consuming_gates")? {
        let p = as_str(path, "consuming_gates[]")?;
        ensure(
            root.join(p).exists(),
            format!("consuming_gates entry not found: {p}"),
        )?;
    }
    Ok(())
}
