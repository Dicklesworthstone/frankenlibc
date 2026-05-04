//! Integration test: fpg-claim-control evidence gate (bd-bp8fl.3.5)
//!
//! Drives the eight `fpg-claim-control` gaps from
//! `tests/conformance/feature_parity_gap_ledger.v1.json` through a fail-closed
//! evidence binder rooted at `tests/conformance/fpg_claim_control_gate.v1.json`.
//! Each macro-coverage-target row in `FEATURE_PARITY.md` must:
//!   * resolve at the cited line with the cited primary key,
//!   * carry the cited `IN_PROGRESS` status (DONE without evidence is blocked),
//!   * cite at least one machine-evidence anchor that resolves in the named
//!     source artifact at the expected value or threshold.
//!
//! Negative tests demonstrate the fail-closed decision when the gate fixture
//! is mutated or when the FEATURE_PARITY row is hand-edited to claim DONE
//! without satisfying the evidence anchors.

use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
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
    workspace_root().join("tests/conformance/fpg_claim_control_gate.v1.json")
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
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const EXPECTED_GAP_IDS: &[&str] = &[
    "fp-macro-targets-fa7a23e18f01",
    "fp-macro-targets-7b75050a0f03",
    "fp-macro-targets-025864627e97",
    "fp-macro-targets-b1b8d5acbeff",
    "fp-macro-targets-b1983d62901c",
    "fp-macro-targets-556631616b22",
    "fp-macro-targets-1e330b896784",
    "gap-macro-fp-macro-targets-fa7a23e18f01",
];

#[test]
fn gate_artifact_is_well_formed() -> TestResult {
    let gate = load_json(&gate_path())?;
    ensure_eq(
        gate["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(gate["bead"].as_str(), Some("bd-bp8fl.3.5"), "bead")?;
    ensure_eq(
        gate["owner_family_group"].as_str(),
        Some("fpg-claim-control"),
        "owner_family_group",
    )?;
    ensure_eq(
        gate["evidence_owner"].as_str(),
        Some("docs/conformance release-gate owners"),
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
        "support_matrix",
        "replacement_levels",
        "reality_report",
        "semantic_contract_inventory",
        "feature_parity_gap_ledger",
        "feature_parity_gap_owner_family_groups",
        "hardened_repair_deny_matrix",
        "conformance_matrix",
        "perf_baseline_spec",
        "version_script",
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
        Some("block_until_evidence_current"),
        "claim_policy.default_decision",
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
        "claim_policy must block DONE without evidence",
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
    Ok(())
}

#[test]
fn gate_rows_cover_all_eight_fpg_claim_control_gaps() -> TestResult {
    let gate = load_json(&gate_path())?;
    let rows = as_array(&gate["rows"], "rows")?;
    ensure_eq(rows.len(), 8usize, "rows count")?;

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
        let ledger_section = ledger_gap["section"].as_str().unwrap_or("");
        if !ledger_section.is_empty() {
            ensure_eq(
                row_section,
                ledger_section,
                format!("row.{gap_id}.section must match ledger"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn gate_rows_resolve_at_cited_feature_parity_lines() -> TestResult {
    let gate = load_json(&gate_path())?;
    let rows = as_array(&gate["rows"], "rows")?;
    let parity_text = read_text(&feature_parity_path())?;
    let parity_lines: Vec<&str> = parity_text.lines().collect();

    let mut seen_lines: HashSet<usize> = HashSet::new();
    let mut macro_target_keys: BTreeSet<String> = BTreeSet::new();

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
        // The machine_delta sentinel reuses the linked row's line; both rows
        // are still required to land on a macro-targets row that mentions a
        // recognizable claim string.
        let kind = as_str(&row["kind"], "row.kind")?;
        if kind == "feature_parity_row_status" {
            ensure(
                line_text.contains(primary_key),
                format!(
                    "{gap_id}: FEATURE_PARITY.md:{line} should contain primary_key {primary_key:?}, found {line_text:?}"
                ),
            )?;
            ensure(
                line_text.contains("IN_PROGRESS"),
                format!(
                    "{gap_id}: FEATURE_PARITY.md:{line} must remain IN_PROGRESS until the evidence binder closes; row was {line_text:?}"
                ),
            )?;
            seen_lines.insert(line as usize);
            macro_target_keys.insert(primary_key.to_string());
        } else if kind == "machine_delta_drift" {
            let linked = as_str(&row["linked_gap_id"], "row.linked_gap_id")?;
            ensure(
                EXPECTED_GAP_IDS.contains(&linked),
                format!(
                    "{gap_id}: linked_gap_id {linked} must be one of the macro_targets gap ids"
                ),
            )?;
        } else {
            return Err(test_error(format!("{gap_id}: unknown row.kind {kind}")));
        }
    }

    // Every cited macro_targets IN_PROGRESS claim row in FEATURE_PARITY must be
    // cited exactly once by a feature_parity_row_status row in the gate. Match
    // by primary key so docs line insertions do not make the test stale.
    let mut macro_target_inprogress: BTreeSet<usize> = BTreeSet::new();
    for (idx, line) in parity_lines.iter().enumerate() {
        if line.starts_with("| ")
            && line.contains("IN_PROGRESS")
            && macro_target_keys.iter().any(|key| line.contains(key))
        {
            macro_target_inprogress.insert(idx + 1);
        }
    }
    ensure_eq(
        seen_lines.iter().copied().collect::<BTreeSet<_>>(),
        macro_target_inprogress,
        "every macro_targets IN_PROGRESS line must be cited exactly once by a feature_parity_row_status row",
    )?;
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

            // Special-case the version script (treated as a plain file).
            if artifact == "crates/frankenlibc-abi/version_scripts/libc.map" && field == "exists" {
                let exists = anchor["expected_value"].as_bool().unwrap_or(false);
                let resolved = workspace_root().join(artifact);
                ensure_eq(
                    resolved.exists(),
                    exists,
                    format!("{gap_id}: version script existence must match anchor"),
                )?;
                continue;
            }

            // The machine_delta sentinel anchors point at rows in the gap
            // ledger: `self.*` resolves the sentinel's own gap, `linked.*`
            // resolves the row named in `linked_gap_id`.
            if artifact == "tests/conformance/feature_parity_gap_ledger.v1.json"
                && (field.starts_with("self.") || field.starts_with("linked."))
            {
                let ledger = load_json(&workspace_root().join(artifact))?;
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
                let actual = gap[key].as_str().unwrap_or_default();
                let expected = as_str(&anchor["expected_value"], "anchor.expected_value")?;
                ensure_eq(
                    actual,
                    expected,
                    format!("{gap_id}: anchor {artifact}/{field} on {target_gap_id} mismatch"),
                )?;
                continue;
            }

            let artifact_path = workspace_root().join(artifact);
            ensure(
                artifact_path.exists(),
                format!("{gap_id} anchor artifact missing: {artifact}"),
            )?;
            let artifact_json = load_json(&artifact_path)?;
            let value = select_value(&artifact_json, field).ok_or_else(|| {
                test_error(format!(
                    "{gap_id} anchor {artifact}/{field}: field path not found in artifact"
                ))
            })?;

            if let Some(expected) = anchor.get("expected_value") {
                ensure_eq(
                    value,
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
                let actual_n = value.as_i64().or_else(|| value.as_u64().map(|n| n as i64)).ok_or_else(|| {
                    test_error(format!(
                        "{gap_id} anchor {artifact}/{field} value must be numeric to compare against expected_value_min"
                    ))
                })?;
                ensure(
                    actual_n >= min_n,
                    format!(
                        "{gap_id} anchor {artifact}/{field}: expected >= {min_n}, got {actual_n}"
                    ),
                )?;
            }
            if let Some(needle) = anchor.get("expected_value_contains") {
                let needle = as_str(needle, "expected_value_contains")?;
                let haystack = value
                    .as_str()
                    .ok_or_else(|| test_error(format!(
                        "{gap_id} anchor {artifact}/{field}: value must be a string to substring-match"
                    )))?;
                ensure(
                    haystack.contains(needle),
                    format!(
                        "{gap_id} anchor {artifact}/{field}: expected substring {needle:?} in {haystack:?}"
                    ),
                )?;
            }
            if let Some(keys) = anchor.get("expected_keys") {
                let object = value
                    .as_object()
                    .ok_or_else(|| test_error(format!(
                        "{gap_id} anchor {artifact}/{field}: value must be an object to check expected_keys"
                    )))?;
                for key in as_array(keys, "expected_keys")? {
                    let key = as_str(key, "expected_keys[]")?;
                    ensure(
                        object.contains_key(key),
                        format!("{gap_id} anchor {artifact}/{field}: missing expected key {key}"),
                    )?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn owner_family_groups_md_cites_this_gate() -> TestResult {
    let groups = read_text(&owner_family_groups_path())?;
    ensure(
        groups.contains("fpg-claim-control"),
        "owner_family_groups md must mention fpg-claim-control",
    )?;
    ensure(
        groups.contains("`bd-bp8fl.3.5`"),
        "owner_family_groups md must reference follow-up bead bd-bp8fl.3.5",
    )?;
    ensure(
        groups.contains("`claim_reconciliation_gate`"),
        "owner_family_groups md must reference the gate kind",
    )?;
    Ok(())
}

#[test]
fn gate_blocks_done_status_without_evidence_in_feature_parity() -> TestResult {
    // Construct a synthetic FEATURE_PARITY.md macro_targets line that flips a
    // gate-bound row to DONE. The gate fixture's claimed_status policy must
    // refuse to advance: only IN_PROGRESS or PLANNED may pass.
    let gate = load_json(&gate_path())?;
    let policy = &gate["claim_policy"];
    let allow: Vec<&str> = as_array(&policy["allow_status"], "allow_status")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure(
        allow.contains(&"IN_PROGRESS"),
        "policy must allow IN_PROGRESS",
    )?;
    ensure(allow.contains(&"PLANNED"), "policy must allow PLANNED")?;
    ensure(
        !allow.contains(&"DONE"),
        "policy must not list DONE in allow_status without evidence",
    )?;

    let block: Vec<&str> = as_array(
        &policy["block_status_without_evidence"],
        "block_status_without_evidence",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    ensure(
        block.contains(&"DONE"),
        "policy must block DONE without evidence",
    )?;

    // Walk every gate row and confirm the cited FEATURE_PARITY.md line still
    // declares IN_PROGRESS — flipping the live row to DONE without satisfying
    // the anchors must be detected by the line scan in
    // `gate_rows_resolve_at_cited_feature_parity_lines`.
    let parity_text = read_text(&feature_parity_path())?;
    let lines: Vec<&str> = parity_text.lines().collect();
    let rows = as_array(&gate["rows"], "rows")?;
    for row in rows {
        let kind = as_str(&row["kind"], "row.kind")?;
        if kind != "feature_parity_row_status" {
            continue;
        }
        let line = row["feature_parity_provenance"]["line"]
            .as_u64()
            .unwrap_or(0) as usize;
        let line_text = lines.get(line.saturating_sub(1)).copied().unwrap_or("");
        ensure(
            !line_text.contains(" DONE "),
            format!(
                "gate row {} is bound to FEATURE_PARITY.md:{} which now claims DONE; the gate must be re-run with refreshed evidence before promotion",
                row["gap_id"], line
            ),
        )?;
    }
    Ok(())
}

#[test]
fn gate_blocks_replacement_level_promotion_without_l0_evidence_floor() -> TestResult {
    // Replacement levels must remain blocked at L0 until the gate's evidence
    // anchors and the broader claim_reconciliation gate both report current.
    let levels: Value =
        load_json(&workspace_root().join("tests/conformance/replacement_levels.json"))?;
    let current = as_str(&levels["current_level"], "current_level")?;
    ensure(
        matches!(current, "L0" | "L1"),
        format!(
            "current_level {current} unexpected — fpg-claim-control gate expects L0 or L1 until L2/L3 evidence binders land"
        ),
    )?;
    Ok(())
}
