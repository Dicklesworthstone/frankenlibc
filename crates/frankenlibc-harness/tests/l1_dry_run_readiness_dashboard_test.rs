//! Integration test: L1 dry-run readiness dashboard (bd-i90i2).
//!
//! Joins the standalone-artifact / direct-link / smoke / dlfcn / perf /
//! claim-reconciliation / runtime-evidence inputs into a single
//! pass/blocker dashboard and verifies that:
//!
//!   * every row's cited evidence_artifact exists on disk;
//!   * every row's `field` resolves via dotted-path traversal in its
//!     cited artifact and matches `expected_value` exactly OR is
//!     bounded above by `expected_value_max`;
//!   * the dashboard never advertises auto-promotion
//!     (`auto_promotion_allowed: false`);
//!   * `current_level` in replacement_levels remains L0 until every
//!     row passes;
//!   * minimum row kinds are present (forge, smoke, direct_link,
//!     real_program, dlfcn, perf, claim_control, gate_meta,
//!     promotion_state);
//!   * required_log_fields, rejected_evidence_kinds, and
//!     consuming_gates are well-formed.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

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

fn dashboard_path() -> PathBuf {
    workspace_root().join("tests/conformance/l1_dry_run_readiness_dashboard.v1.json")
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "dashboard_run_id",
    "row_id",
    "row_kind",
    "evidence_artifact",
    "evidence_status",
    "blocker_id",
    "expected",
    "actual",
    "decision",
    "rejection_reason",
    "source_commit",
    "artifact_refs",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "missing_input_artifact",
    "stale_source_commit",
    "schema_drift",
    "dashboard_advances_current_level_implicitly",
    "blocker_count_unreported",
    "row_lacks_evidence_ref",
];

const REQUIRED_ROW_KINDS: &[&str] = &[
    "forge",
    "smoke",
    "direct_link",
    "real_program",
    "dlfcn",
    "perf",
    "claim_control",
    "gate_meta",
    "promotion_state",
];

const STATUS_SEMANTIC_ROW_KINDS: &[&str] = &["forge", "smoke", "direct_link", "real_program"];

fn select_field<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = root;
    for segment in path.split('.') {
        cursor = match cursor {
            Value::Object(map) => map.get(segment)?,
            _ => return None,
        };
    }
    Some(cursor)
}

#[test]
fn dashboard_artifact_is_well_formed() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    ensure_eq(
        dashboard["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(dashboard["bead"].as_str(), Some("bd-i90i2"), "bead")?;
    ensure(
        !dashboard["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;

    let inputs = dashboard["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for (key, val) in inputs {
        let path = val
            .as_str()
            .ok_or_else(|| test_error(format!("inputs.{key} must be a string")))?;
        ensure(
            workspace_root().join(path).exists(),
            format!("inputs.{key} must reference an existing artifact: {path}"),
        )?;
    }

    let log_fields: Vec<&str> = as_array(&dashboard["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &dashboard["policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("report_blockers_no_auto_promotion"),
        "policy.default_decision",
    )?;
    ensure_eq(
        policy["auto_promotion_allowed"].as_bool(),
        Some(false),
        "policy.auto_promotion_allowed must be false",
    )?;
    ensure_eq(
        policy["promotion_target"].as_str(),
        Some("L1"),
        "policy.promotion_target",
    )?;
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
fn every_row_resolves_evidence_field_and_matches_expected() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let root = workspace_root();
    let mut row_ids: BTreeSet<String> = BTreeSet::new();
    let mut kinds_seen: BTreeSet<String> = BTreeSet::new();

    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        ensure(
            row_ids.insert(row_id.to_string()),
            format!("duplicate row_id: {row_id}"),
        )?;
        let kind = as_str(&row["row_kind"], "row.row_kind")?;
        kinds_seen.insert(kind.to_string());
        let artifact = as_str(&row["evidence_artifact"], "row.evidence_artifact")?;
        let abs = root.join(artifact);
        ensure(
            abs.exists(),
            format!("row {row_id}: evidence_artifact {artifact} missing on disk"),
        )?;
        let json = load_json(&abs)?;
        let field = as_str(&row["field"], "row.field")?;
        let actual = select_field(&json, field).ok_or_else(|| {
            test_error(format!(
                "row {row_id}: field path {field} did not resolve in {artifact}"
            ))
        })?;

        if let Some(expected) = row.get("expected_value") {
            ensure_eq(
                actual,
                expected,
                format!("row {row_id}: artifact {artifact}#{field}"),
            )?;
        } else if let Some(max) = row.get("expected_value_max") {
            let max_n = max.as_i64().ok_or_else(|| {
                test_error(format!("row {row_id}: expected_value_max must be integer"))
            })?;
            let actual_n = actual
                .as_i64()
                .or_else(|| actual.as_u64().map(|n| n as i64))
                .ok_or_else(|| {
                    test_error(format!(
                        "row {row_id}: artifact {artifact}#{field} value must be numeric"
                    ))
                })?;
            ensure(
                actual_n <= max_n,
                format!(
                    "row {row_id}: artifact {artifact}#{field} = {actual_n} exceeds expected_value_max {max_n}"
                ),
            )?;
        } else {
            return Err(test_error(format!(
                "row {row_id}: must declare expected_value or expected_value_max"
            )));
        }
    }

    for kind in REQUIRED_ROW_KINDS {
        ensure(
            kinds_seen.contains(*kind),
            format!("required row_kind {kind} missing from dashboard"),
        )?;
    }
    Ok(())
}

#[test]
fn current_level_remains_l0_until_dashboard_passes_completely() -> TestResult {
    // Pin: replacement_levels.json#current_level must remain L0. The
    // dashboard MUST NEVER advance current_level on its own; only an
    // explicit human-driven release flow may flip it after every row
    // passes. This test catches a future edit that promotes silently.
    let levels = load_json(&workspace_root().join("tests/conformance/replacement_levels.json"))?;
    let current = as_str(&levels["current_level"], "current_level")?;
    ensure_eq(
        current,
        "L0",
        "current_level must remain L0 until L1 dry-run dashboard rows ALL pass and a human signs off",
    )
}

#[test]
fn minimum_row_kinds_each_have_at_least_one_row() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut kinds_seen: BTreeSet<String> = BTreeSet::new();
    for row in as_array(&dashboard["rows"], "rows")? {
        if let Some(kind) = row["row_kind"].as_str() {
            kinds_seen.insert(kind.to_string());
        }
    }
    let minimums = as_array(&dashboard["minimum_row_kinds"], "minimum_row_kinds")?;
    for required in minimums {
        let required = as_str(required, "minimum_row_kinds[]")?;
        ensure(
            kinds_seen.contains(required),
            format!("minimum_row_kinds requires at least one row of kind {required}; none present"),
        )?;
    }
    Ok(())
}

#[test]
fn critical_l1_evidence_rows_do_not_pass_on_schema_presence_only() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut semantic_counts = BTreeSet::new();
    for row in as_array(&dashboard["rows"], "rows")? {
        let kind = as_str(&row["row_kind"], "row.row_kind")?;
        if STATUS_SEMANTIC_ROW_KINDS.contains(&kind) {
            let field = as_str(&row["field"], "row.field")?;
            ensure(
                field != "schema_version",
                format!(
                    "row {}: critical L1 evidence row must assert a status/policy field, not schema_version",
                    as_str(&row["row_id"], "row.row_id")?
                ),
            )?;
            semantic_counts.insert(kind.to_string());
        }
    }
    for kind in STATUS_SEMANTIC_ROW_KINDS {
        ensure(
            semantic_counts.contains(*kind),
            format!(
                "critical L1 evidence row kind {kind} must have at least one semantic status/policy row"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn consuming_gates_exist_on_disk() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let root = workspace_root();
    for gate in as_array(&dashboard["consuming_gates"], "consuming_gates")? {
        let path = as_str(gate, "consuming_gates[]")?;
        ensure(
            root.join(path).exists(),
            format!("consuming_gates entry not found: {path}"),
        )?;
    }
    Ok(())
}

#[test]
fn dashboard_disclaims_auto_promotion_in_must_remain_unset() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let policy = &dashboard["policy"];
    let must_unset = as_array(
        &policy["must_remain_unset_until_all_rows_pass"],
        "must_remain_unset_until_all_rows_pass",
    )?;
    ensure(
        must_unset.len() >= 2,
        "must_remain_unset_until_all_rows_pass must list at least replacement_levels.current_level and release_tag_policy.current_release_level",
    )?;
    let entries: Vec<&str> = must_unset
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure(
        entries.iter().any(|e| e.contains("current_level")),
        "must_remain_unset_until_all_rows_pass must mention current_level",
    )?;
    ensure(
        entries.iter().any(|e| e.contains("release_tag_policy")),
        "must_remain_unset_until_all_rows_pass must mention release_tag_policy",
    )?;
    Ok(())
}
