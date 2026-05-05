//! Integration test: locale/iconv breadth scope ledger (bd-b92jd.5.4).
//!
//! Loads `tests/conformance/locale_iconv_breadth_scope_ledger.v1.json`
//! and asserts the contract that future docs/support_matrix/release
//! advancement cannot bypass:
//!
//!   * each row carries a unique row_id, canonical name (or locale id),
//!     and either a satisfied-by reference to an existing artifact or
//!     an explicit fixture_obligation/skip_reason — silence is rejected
//!     (no DONE-by-omission);
//!   * implemented_bootstrap_codecs cross-references the canonical
//!     phase-1 ledger so phase-2 cannot regress phase-1 status;
//!   * unsupported_breadth_codecs mirrors phase-1 excluded families
//!     exactly — the breadth ledger is not allowed to silently relax
//!     a previously-excluded codec without a planned_breadth row;
//!   * minimum row counts hold for each category;
//!   * the cited inputs all exist on disk;
//!   * claim_policy blocks DONE / L1+ without evidence and enumerates
//!     the rejected_evidence_kinds.

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

fn ledger_path() -> PathBuf {
    workspace_root().join("tests/conformance/locale_iconv_breadth_scope_ledger.v1.json")
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "ledger_row_id",
    "row_kind",
    "canonical_name",
    "alias",
    "phase",
    "support_status",
    "fixture_obligation",
    "skip_reason",
    "expected_iconv_open_decision",
    "evidence_artifact",
    "claim_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "duplicate_canonical_name",
    "duplicate_alias",
    "missing_fixture_obligation",
    "missing_skip_reason",
    "stale_table_checksum",
    "phase1_phase2_collision",
    "ledger_drift",
];

#[test]
fn ledger_artifact_is_well_formed() -> TestResult {
    let ledger = load_json(&ledger_path())?;
    ensure_eq(
        ledger["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(ledger["bead"].as_str(), Some("bd-b92jd.5.4"), "bead")?;
    ensure_eq(
        ledger["phase"].as_str(),
        Some("phase2-breadth-survey"),
        "phase",
    )?;
    ensure(
        !ledger["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;

    let inputs = ledger["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for key in [
        "iconv_codec_scope_ledger",
        "iconv_table_pack",
        "iconv_table_checksums",
        "iconv_stateful_codec_fixture_pack",
        "locale_catalog_transliteration_fixture_pack",
        "feature_parity",
        "support_matrix",
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

    let log_fields: Vec<&str> = as_array(&ledger["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &ledger["claim_policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_breadth_evidence_current"),
        "claim_policy.default_decision",
    )?;
    let block_status: Vec<&str> = as_array(
        &policy["block_status_without_evidence"],
        "block_status_without_evidence",
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
        "block_replacement_levels_without_evidence",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for level in ["L1", "L2", "L3"] {
        ensure(
            block_levels.contains(&level),
            format!("claim_policy must block replacement level {level}"),
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
fn rows_have_unique_ids_and_canonical_names_with_no_phase_collision() -> TestResult {
    let ledger = load_json(&ledger_path())?;
    let buckets = [
        "implemented_bootstrap_codecs",
        "planned_breadth_codecs",
        "unsupported_breadth_codecs",
        "locale_breadth_rows",
    ];
    let mut all_row_ids: BTreeSet<String> = BTreeSet::new();
    let mut all_canonical: BTreeSet<String> = BTreeSet::new();

    for bucket in buckets {
        for row in as_array(&ledger[bucket], bucket)? {
            let row_id = as_str(&row["row_id"], "row.row_id")?;
            ensure(
                all_row_ids.insert(row_id.to_string()),
                format!("duplicate row_id across buckets: {row_id}"),
            )?;
            // canonical for codecs, locale for locale rows.
            let key = row
                .get("canonical")
                .or_else(|| row.get("locale"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    test_error(format!("{row_id}: row must carry canonical or locale"))
                })?;
            // Implemented + unsupported MUST be unique-canonical across both
            // buckets so phase-1 status cannot silently flip to phase-2 plan.
            // Planned and locale buckets may legitimately share a canonical
            // family with phase-1 rows when the phase-1 status is the same,
            // so we only enforce uniqueness across implemented + unsupported.
            if matches!(
                bucket,
                "implemented_bootstrap_codecs" | "unsupported_breadth_codecs"
            ) {
                ensure(
                    all_canonical.insert(key.to_string()),
                    format!(
                        "phase1_phase2_collision: canonical {key} already used by another implemented/unsupported row (row {row_id})"
                    ),
                )?;
            }
        }
    }

    Ok(())
}

#[test]
fn every_row_carries_either_fixture_obligation_or_skip_reason() -> TestResult {
    let ledger = load_json(&ledger_path())?;
    for bucket in [
        "implemented_bootstrap_codecs",
        "planned_breadth_codecs",
        "unsupported_breadth_codecs",
        "locale_breadth_rows",
    ] {
        for row in as_array(&ledger[bucket], bucket)? {
            let row_id = as_str(&row["row_id"], "row.row_id")?;
            let support = as_str(&row["support_status"], "row.support_status")?;
            let satisfied_by = row
                .get("fixture_obligation_satisfied_by")
                .and_then(|v| v.as_str());
            let obligation = row.get("fixture_obligation").and_then(|v| v.as_str());
            let skip_reason = row.get("skip_reason").and_then(|v| v.as_str());
            match support {
                "implemented" => {
                    let satisfied = satisfied_by.map(|s| !s.is_empty()).unwrap_or(false);
                    ensure(
                        satisfied,
                        format!(
                            "row {row_id} (implemented): must cite fixture_obligation_satisfied_by"
                        ),
                    )?;
                }
                "planned" => {
                    let has = obligation.map(|s| !s.is_empty()).unwrap_or(false);
                    ensure(
                        has,
                        format!("row {row_id} (planned): must declare fixture_obligation"),
                    )?;
                }
                "unsupported" => {
                    let has = skip_reason.map(|s| !s.is_empty()).unwrap_or(false);
                    ensure(
                        has,
                        format!("row {row_id} (unsupported): must declare skip_reason"),
                    )?;
                }
                other => {
                    return Err(test_error(format!(
                        "row {row_id}: unknown support_status {other}"
                    )));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn implemented_bootstrap_cross_references_canonical_phase1_ledger() -> TestResult {
    let ledger = load_json(&ledger_path())?;
    let canonical =
        load_json(&workspace_root().join("tests/conformance/iconv_codec_scope_ledger.v1.json"))?;
    let mut phase1_canonical: BTreeSet<String> = BTreeSet::new();
    for row in as_array(&canonical["included_codecs"], "canonical.included_codecs")? {
        if let Some(name) = row["canonical"].as_str() {
            phase1_canonical.insert(name.to_string());
        }
    }
    for row in as_array(
        &ledger["implemented_bootstrap_codecs"],
        "implemented_bootstrap_codecs",
    )? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        let name = as_str(&row["canonical"], "row.canonical")?;
        ensure(
            phase1_canonical.contains(name),
            format!(
                "ledger_drift: implemented_bootstrap row {row_id} cites canonical {name} which is not in iconv_codec_scope_ledger.v1.json#included_codecs"
            ),
        )?;
        let satisfied_by = as_str(
            &row["fixture_obligation_satisfied_by"],
            "row.fixture_obligation_satisfied_by",
        )?;
        ensure(
            satisfied_by.starts_with("tests/conformance/iconv_codec_scope_ledger.v1.json"),
            format!(
                "row {row_id}: implemented bootstrap must cite the canonical phase-1 ledger as evidence"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn unsupported_breadth_mirrors_canonical_excluded_families_exactly() -> TestResult {
    let ledger = load_json(&ledger_path())?;
    let canonical =
        load_json(&workspace_root().join("tests/conformance/iconv_codec_scope_ledger.v1.json"))?;
    let mut canonical_excluded: BTreeSet<String> = BTreeSet::new();
    for row in as_array(
        &canonical["excluded_codec_families"],
        "canonical.excluded_codec_families",
    )? {
        if let Some(name) = row["canonical"].as_str() {
            canonical_excluded.insert(name.to_string());
        }
    }
    let mut breadth_unsupported: BTreeSet<String> = BTreeSet::new();
    for row in as_array(
        &ledger["unsupported_breadth_codecs"],
        "unsupported_breadth_codecs",
    )? {
        let name = as_str(&row["canonical"], "row.canonical")?;
        breadth_unsupported.insert(name.to_string());
    }
    ensure_eq(
        breadth_unsupported,
        canonical_excluded,
        "unsupported_breadth_codecs canonical set must equal canonical phase-1 excluded_codec_families set (no silent relaxation, no missing rows)",
    )
}

#[test]
fn minimum_row_counts_hold() -> TestResult {
    let ledger = load_json(&ledger_path())?;
    let minimums = ledger["minimum_row_counts"]
        .as_object()
        .ok_or_else(|| test_error("minimum_row_counts must be an object"))?;
    for (bucket, expected_min) in minimums {
        let expected = expected_min
            .as_u64()
            .ok_or_else(|| test_error(format!("minimum_row_counts.{bucket} must be integer")))?
            as usize;
        let actual = as_array(&ledger[bucket.as_str()], bucket)?.len();
        ensure(
            actual >= expected,
            format!("{bucket}: ledger has {actual} rows, minimum is {expected}"),
        )?;
    }
    Ok(())
}

#[test]
fn planned_codecs_have_distinct_canonical_names_within_bucket() -> TestResult {
    let ledger = load_json(&ledger_path())?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for row in as_array(&ledger["planned_breadth_codecs"], "planned_breadth_codecs")? {
        let name = as_str(&row["canonical"], "row.canonical")?.to_string();
        ensure(
            seen.insert(name.clone()),
            format!("duplicate_canonical_name: planned_breadth_codecs has duplicate {name}"),
        )?;
    }
    Ok(())
}
