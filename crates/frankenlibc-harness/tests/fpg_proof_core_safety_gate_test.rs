//! Integration test: fpg-proof-core-safety evidence gate (bd-bp8fl.3.8)
//!
//! Drives the seven `fpg-proof-core-safety` gaps from
//! `tests/conformance/feature_parity_gap_ledger.v1.json` through a fail-closed
//! evidence binder rooted at
//! `tests/conformance/fpg_proof_core_safety_gate.v1.json`.
//! Each row of the FEATURE_PARITY.md proof_math table cited by the gate must:
//!   * resolve at the cited line with the cited primary key,
//!   * remain in PLANNED or IN_PROGRESS — DONE without proof witnesses is blocked,
//!   * cite at least one machine-evidence anchor that resolves in
//!     proof_obligations_binder.v1.json, proof_binder_validation.v1.json,
//!     mode_contract_lock.v1.json, or the gap ledger itself.
//!
//! Negative coverage is enforced by the policy block lists: PROSE-only or
//! tracker-closure-only advancement is rejected, and any future hand-edit of
//! a gate-bound FEATURE_PARITY row to DONE is detected by the line scan.

use serde_json::Value;
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

fn read_text(path: &Path) -> Result<String, Box<dyn Error>> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
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
    workspace_root().join("tests/conformance/fpg_proof_core_safety_gate.v1.json")
}

fn ledger_path() -> PathBuf {
    workspace_root().join("tests/conformance/feature_parity_gap_ledger.v1.json")
}

fn owner_family_groups_path() -> PathBuf {
    workspace_root().join("tests/conformance/feature_parity_gap_owner_family_groups.v1.md")
}

fn feature_parity_path() -> PathBuf {
    workspace_root().join("FEATURE_PARITY.md")
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "gap_id",
    "section",
    "feature_parity_line",
    "claimed_status",
    "expected_status",
    "actual_status",
    "evidence_artifact",
    "evidence_anchor",
    "expected_value",
    "actual_value",
    "claim_decision",
    "replacement_level",
    "obligation_id",
    "obligation_status",
    "binder_valid",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const EXPECTED_GAP_IDS: &[&str] = &[
    "fp-proof-math-b821b415a5d6",
    "fp-proof-math-f3e03ea48a96",
    "fp-proof-math-0dbb786935af",
    "fp-proof-math-8c76410adba7",
    "fp-proof-math-2a49b40113a6",
    "fp-proof-math-f4c99678233a",
    "fp-proof-math-498e3ada4658",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "prose_only",
    "tracker_closure_only",
    "stale_obligation",
    "missing_obligation",
    "binder_invalid",
    "missing_mode_contract",
];

#[test]
fn gate_artifact_is_well_formed() -> TestResult {
    let gate = load_json(&gate_path())?;
    ensure_eq(
        gate["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(gate["bead"].as_str(), Some("bd-bp8fl.3.8"), "bead")?;
    ensure_eq(
        gate["owner_family_group"].as_str(),
        Some("fpg-proof-core-safety"),
        "owner_family_group",
    )?;
    ensure_eq(
        gate["evidence_owner"].as_str(),
        Some("membrane proof and conformance-binder owners"),
        "evidence_owner",
    )?;
    ensure(
        !gate["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;

    let inputs = gate["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    let required_inputs = [
        "feature_parity",
        "feature_parity_gap_ledger",
        "feature_parity_gap_owner_family_groups",
        "proof_obligations_binder",
        "proof_binder_validation",
        "mode_contract_lock",
    ];
    for key in required_inputs {
        let path = inputs
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| test_error(format!("inputs.{key} must be a string")))?;
        let resolved = workspace_root().join(path);
        ensure(
            resolved.exists(),
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

    let policy = &gate["claim_policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_proof_witness_current"),
        "claim_policy.default_decision",
    )?;
    let allow: Vec<&str> = as_array(&policy["allow_status"], "allow_status")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    for s in ["PLANNED", "IN_PROGRESS"] {
        ensure(
            allow.contains(&s),
            format!("claim_policy.allow_status must include {s}"),
        )?;
    }
    ensure(
        !allow.contains(&"DONE"),
        "claim_policy.allow_status must not include DONE",
    )?;
    let block_status: Vec<&str> = as_array(
        &policy["block_status_without_evidence"],
        "claim_policy.block_status_without_evidence",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    ensure(
        block_status.contains(&"DONE"),
        "claim_policy must block DONE without proof witness",
    )?;
    let block_levels: Vec<&str> = as_array(
        &policy["block_replacement_levels_without_evidence"],
        "claim_policy.block_replacement_levels_without_evidence",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for level in ["L1", "L2", "L3"] {
        ensure(
            block_levels.contains(&level),
            format!("claim_policy must block replacement level {level} without evidence"),
        )?;
    }
    let rejected: Vec<&str> = as_array(
        &policy["rejected_evidence_kinds"],
        "claim_policy.rejected_evidence_kinds",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for kind in REJECTED_EVIDENCE_KINDS {
        ensure(
            rejected.contains(kind),
            format!("claim_policy.rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn gate_rows_cover_all_seven_fpg_proof_core_safety_gaps() -> TestResult {
    let gate = load_json(&gate_path())?;
    let rows = as_array(&gate["rows"], "rows")?;
    ensure_eq(rows.len(), 7usize, "rows count")?;

    let mut row_ids: Vec<&str> = rows
        .iter()
        .map(|row| row["gap_id"].as_str().unwrap_or_default())
        .collect();
    row_ids.sort();
    let mut expected: Vec<&str> = EXPECTED_GAP_IDS.to_vec();
    expected.sort();
    ensure_eq(row_ids, expected, "row gap_ids")?;

    let ledger = load_json(&ledger_path())?;
    let ledger_gaps = as_array(&ledger["gaps"], "ledger.gaps")?;
    let ledger_index: std::collections::HashMap<&str, &Value> = ledger_gaps
        .iter()
        .filter_map(|gap| gap["gap_id"].as_str().map(|id| (id, gap)))
        .collect();

    for row in rows {
        let gap_id = as_str(&row["gap_id"], "row.gap_id")?;
        let ledger_gap = ledger_index
            .get(gap_id)
            .ok_or_else(|| test_error(format!("ledger missing gap_id {gap_id}")))?;
        let row_status = as_str(&row["claimed_status"], "row.claimed_status")?;
        let ledger_status = as_str(&ledger_gap["status"], "ledger.gap.status")?;
        ensure_eq(
            row_status,
            ledger_status,
            format!("row.{gap_id}.claimed_status must match ledger.status"),
        )?;
        let row_section = as_str(&row["section"], "row.section")?;
        ensure_eq(
            row_section,
            "proof_math",
            format!("row.{gap_id}.section must be proof_math"),
        )?;
        let ledger_section = ledger_gap["section"].as_str().unwrap_or("");
        ensure_eq(
            ledger_section,
            "proof_math",
            format!("ledger.{gap_id}.section must be proof_math"),
        )?;
    }
    Ok(())
}

#[test]
fn gate_rows_resolve_at_cited_feature_parity_lines() -> TestResult {
    let gate = load_json(&gate_path())?;
    let rows = as_array(&gate["rows"], "rows")?;
    let parity_text = read_text(&feature_parity_path())?;
    let parity_lines: Vec<&str> = parity_text.lines().collect();

    for row in rows {
        let gap_id = as_str(&row["gap_id"], "row.gap_id")?;
        let provenance = &row["feature_parity_provenance"];
        let path = as_str(&provenance["path"], "row.feature_parity_provenance.path")?;
        ensure_eq(
            path,
            "FEATURE_PARITY.md",
            format!("{gap_id} provenance.path"),
        )?;
        let line = provenance["line"]
            .as_u64()
            .ok_or_else(|| test_error(format!("{gap_id}.provenance.line must be a number")))?;
        let line_idx = (line as usize).checked_sub(1).ok_or_else(|| {
            test_error(format!("{gap_id}.provenance.line must be >= 1, got {line}"))
        })?;
        let line_text = parity_lines.get(line_idx).ok_or_else(|| {
            test_error(format!(
                "{gap_id}.provenance.line {line} out of range (FEATURE_PARITY.md has {} lines)",
                parity_lines.len()
            ))
        })?;

        let primary_key = as_str(&row["primary_key"], "row.primary_key")?;
        ensure(
            line_text.contains(primary_key),
            format!(
                "{gap_id}: FEATURE_PARITY.md:{line} should contain primary_key {primary_key:?}, found {line_text:?}"
            ),
        )?;

        let claimed = as_str(&row["claimed_status"], "row.claimed_status")?;
        ensure(
            line_text.contains(claimed),
            format!(
                "{gap_id}: FEATURE_PARITY.md:{line} should still report {claimed} (gate must be re-run with refreshed proof witness before promotion); found {line_text:?}"
            ),
        )?;
        ensure(
            !line_text.contains(" DONE "),
            format!(
                "{gap_id}: FEATURE_PARITY.md:{line} now claims DONE without a proof witness; the gate is fail-closed until proof_binder_validation.obligation.valid=true."
            ),
        )?;
    }
    Ok(())
}

fn select_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
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
fn gate_evidence_anchors_resolve_in_cited_artifacts() -> TestResult {
    let gate = load_json(&gate_path())?;
    let rows = as_array(&gate["rows"], "rows")?;

    let binder =
        load_json(&workspace_root().join("tests/conformance/proof_obligations_binder.v1.json"))?;
    let validation =
        load_json(&workspace_root().join("tests/conformance/proof_binder_validation.v1.json"))?;
    let mode_lock =
        load_json(&workspace_root().join("tests/conformance/mode_contract_lock.v1.json"))?;
    let ledger = load_json(&ledger_path())?;

    for row in rows {
        let gap_id = as_str(&row["gap_id"], "row.gap_id")?;
        let anchors = as_array(&row["evidence_anchors"], "row.evidence_anchors")?;
        ensure(
            !anchors.is_empty(),
            format!("{gap_id} must declare at least one evidence anchor"),
        )?;

        for anchor in anchors {
            let artifact = as_str(&anchor["artifact"], "anchor.artifact")?;
            let field = as_str(&anchor["field"], "anchor.field")?;
            let rationale = as_str(&anchor["rationale"], "anchor.rationale")?;
            ensure(
                !rationale.is_empty(),
                format!("{gap_id} anchor {artifact}/{field}: rationale must be non-empty"),
            )?;

            // proof_obligations_binder anchors: select the obligation by id.
            if artifact == "tests/conformance/proof_obligations_binder.v1.json"
                && field.starts_with("obligation.")
            {
                let obligation_id = as_str(&anchor["obligation_id"], "anchor.obligation_id")?;
                let obligation = as_array(&binder["obligations"], "binder.obligations")?
                    .iter()
                    .find(|o| o["id"].as_str() == Some(obligation_id))
                    .ok_or_else(|| {
                        test_error(format!(
                            "{gap_id}: obligation {obligation_id} not found in proof_obligations_binder"
                        ))
                    })?;
                let key = field.trim_start_matches("obligation.");
                let actual = &obligation[key];
                check_anchor_value(gap_id, artifact, field, anchor, actual)?;
                continue;
            }

            // proof_binder_validation anchors: per-obligation rows or top-level.
            if artifact == "tests/conformance/proof_binder_validation.v1.json"
                && field.starts_with("obligation.")
            {
                let obligation_id = as_str(&anchor["obligation_id"], "anchor.obligation_id")?;
                let obligation = as_array(&validation["obligations"], "validation.obligations")?
                    .iter()
                    .find(|o| o["obligation_id"].as_str() == Some(obligation_id))
                    .ok_or_else(|| {
                        test_error(format!(
                            "{gap_id}: obligation {obligation_id} not found in proof_binder_validation"
                        ))
                    })?;
                let key = field.trim_start_matches("obligation.");
                let actual = &obligation[key];
                check_anchor_value(gap_id, artifact, field, anchor, actual)?;
                continue;
            }
            if artifact == "tests/conformance/proof_binder_validation.v1.json" {
                let actual = select_value(&validation, field).ok_or_else(|| {
                    test_error(format!(
                        "{gap_id} anchor {artifact}/{field}: top-level field not found"
                    ))
                })?;
                check_anchor_value(gap_id, artifact, field, anchor, actual)?;
                continue;
            }

            // mode_contract_lock anchors.
            if artifact == "tests/conformance/mode_contract_lock.v1.json" {
                let actual = select_value(&mode_lock, field).ok_or_else(|| {
                    test_error(format!(
                        "{gap_id} anchor {artifact}/{field}: field not found"
                    ))
                })?;
                check_anchor_value(gap_id, artifact, field, anchor, actual)?;
                continue;
            }

            // Gap-ledger self/linked anchors.
            if artifact == "tests/conformance/feature_parity_gap_ledger.v1.json"
                && (field.starts_with("self.") || field.starts_with("linked."))
            {
                let target_gap_id: &str = if field.starts_with("self.") {
                    gap_id
                } else {
                    row["linked_gap_id"].as_str().ok_or_else(|| {
                        test_error(format!(
                            "{gap_id}: linked.* anchor requires row.linked_gap_id"
                        ))
                    })?
                };
                let gaps = as_array(&ledger["gaps"], "ledger.gaps")?;
                let gap = gaps
                    .iter()
                    .find(|g| g["gap_id"].as_str() == Some(target_gap_id))
                    .ok_or_else(|| {
                        test_error(format!(
                            "{gap_id}: target gap {target_gap_id} not found in ledger"
                        ))
                    })?;
                let key = field.split_once('.').map(|(_, k)| k).unwrap_or(field);
                let actual = &gap[key];
                check_anchor_value(gap_id, artifact, field, anchor, actual)?;
                continue;
            }

            return Err(test_error(format!(
                "{gap_id}: anchor artifact/field combo not handled by the gate test ({artifact}/{field})"
            )));
        }
    }
    Ok(())
}

fn check_anchor_value(
    gap_id: &str,
    artifact: &str,
    field: &str,
    anchor: &Value,
    actual: &Value,
) -> TestResult {
    if let Some(expected) = anchor.get("expected_value") {
        ensure_eq(
            actual,
            expected,
            format!("{gap_id} anchor {artifact}/{field} expected_value"),
        )?;
    }
    if let Some(min) = anchor.get("expected_value_min") {
        let min_n = min.as_i64().ok_or_else(|| {
            test_error(format!(
                "{gap_id} anchor expected_value_min must be integer"
            ))
        })?;
        let actual_n = actual
            .as_i64()
            .or_else(|| actual.as_u64().map(|n| n as i64))
            .ok_or_else(|| {
                test_error(format!(
                    "{gap_id} anchor {artifact}/{field}: value must be numeric"
                ))
            })?;
        ensure(
            actual_n >= min_n,
            format!("{gap_id} anchor {artifact}/{field}: expected >= {min_n}, got {actual_n}"),
        )?;
    }
    if let Some(needle) = anchor.get("expected_value_contains") {
        let needle = as_str(needle, "expected_value_contains")?;
        let haystack = actual.as_str().ok_or_else(|| {
            test_error(format!(
                "{gap_id} anchor {artifact}/{field}: value must be a string to substring-match"
            ))
        })?;
        ensure(
            haystack.contains(needle),
            format!(
                "{gap_id} anchor {artifact}/{field}: expected substring {needle:?} in {haystack:?}"
            ),
        )?;
    }
    if let Some(keys) = anchor.get("expected_keys_subset") {
        let array = actual.as_array().ok_or_else(|| {
            test_error(format!(
                "{gap_id} anchor {artifact}/{field}: value must be an array to check expected_keys_subset"
            ))
        })?;
        let actual_set: std::collections::HashSet<&str> =
            array.iter().filter_map(|v| v.as_str()).collect();
        for key in as_array(keys, "expected_keys_subset")? {
            let key = as_str(key, "expected_keys_subset[]")?;
            ensure(
                actual_set.contains(key),
                format!(
                    "{gap_id} anchor {artifact}/{field}: expected element {key} not present in {actual_set:?}"
                ),
            )?;
        }
    }
    Ok(())
}

#[test]
fn owner_family_groups_md_cites_this_gate() -> TestResult {
    let groups = read_text(&owner_family_groups_path())?;
    ensure(
        groups.contains("fpg-proof-core-safety"),
        "owner_family_groups md must mention fpg-proof-core-safety",
    )?;
    ensure(
        groups.contains("`bd-bp8fl.3.8`"),
        "owner_family_groups md must reference follow-up bead bd-bp8fl.3.8",
    )?;
    ensure(
        groups.contains("`proof_binder_and_mode_contract`"),
        "owner_family_groups md must reference the proof_binder_and_mode_contract gate kind",
    )?;
    Ok(())
}

#[test]
fn proof_binder_validation_remains_green_for_all_cited_obligations() -> TestResult {
    // The gate's central guarantee: every PO referenced by an evidence anchor
    // must currently report `valid: true` AND `total_violations: 0` globally.
    let gate = load_json(&gate_path())?;
    let validation =
        load_json(&workspace_root().join("tests/conformance/proof_binder_validation.v1.json"))?;

    ensure_eq(
        validation["binder_valid"].as_bool(),
        Some(true),
        "proof_binder_validation.binder_valid must be true",
    )?;
    let total_violations = validation["total_violations"].as_u64().unwrap_or(u64::MAX);
    ensure(
        total_violations == 0,
        format!("proof_binder_validation.total_violations must be 0; got {total_violations}"),
    )?;

    let validation_index: std::collections::HashMap<&str, &Value> =
        as_array(&validation["obligations"], "validation.obligations")?
            .iter()
            .filter_map(|o| o["obligation_id"].as_str().map(|id| (id, o)))
            .collect();

    let rows = as_array(&gate["rows"], "rows")?;
    let mut cited = std::collections::HashSet::new();
    for row in rows {
        let gap_id = as_str(&row["gap_id"], "row.gap_id")?;
        for anchor in as_array(&row["evidence_anchors"], "row.evidence_anchors")? {
            if let Some(po) = anchor["obligation_id"].as_str() {
                cited.insert(po);
                let val_row = validation_index.get(po).ok_or_else(|| {
                    test_error(format!(
                        "{gap_id}: obligation {po} cited in gate but absent from proof_binder_validation"
                    ))
                })?;
                ensure_eq(
                    val_row["valid"].as_bool(),
                    Some(true),
                    format!("{gap_id}: obligation {po} must be valid in proof_binder_validation"),
                )?;
            }
        }
    }

    // We only verify the cited subset; non-cited POs may exist for other
    // owner-family groups and are not in this gate's scope.
    ensure(
        !cited.is_empty(),
        "gate must cite at least one proof obligation",
    )?;
    Ok(())
}

#[test]
fn gate_blocks_done_status_without_proof_witness() -> TestResult {
    let gate = load_json(&gate_path())?;
    let policy = &gate["claim_policy"];
    let allow: Vec<&str> = as_array(&policy["allow_status"], "allow_status")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure(
        !allow.contains(&"DONE"),
        "policy must not list DONE in allow_status",
    )?;

    let rejected: Vec<&str> = as_array(
        &policy["rejected_evidence_kinds"],
        "rejected_evidence_kinds",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    ensure(
        rejected.contains(&"prose_only"),
        "rejected_evidence_kinds must include prose_only",
    )?;
    ensure(
        rejected.contains(&"tracker_closure_only"),
        "rejected_evidence_kinds must include tracker_closure_only",
    )?;
    ensure(
        rejected.contains(&"binder_invalid"),
        "rejected_evidence_kinds must include binder_invalid",
    )?;

    let parity_text = read_text(&feature_parity_path())?;
    let lines: Vec<&str> = parity_text.lines().collect();
    let rows = as_array(&gate["rows"], "rows")?;
    for row in rows {
        let line = row["feature_parity_provenance"]["line"]
            .as_u64()
            .unwrap_or(0) as usize;
        let line_text = lines.get(line.saturating_sub(1)).copied().unwrap_or("");
        ensure(
            !line_text.contains(" DONE "),
            format!(
                "gate row {} bound to FEATURE_PARITY.md:{} now claims DONE; gate must be re-run with refreshed proof witness before promotion",
                row["gap_id"], line
            ),
        )?;
    }
    Ok(())
}
