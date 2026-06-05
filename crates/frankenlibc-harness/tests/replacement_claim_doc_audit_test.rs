//! Integration test: replacement-claim doc audit (bd-5unc9).
//!
//! Refuses overclaim phrasing in user-visible docs (README.md,
//! FEATURE_PARITY.md) unless the L1 dry-run dashboard cites
//! pass-state on every row AND replacement_levels.current_level has
//! been explicitly promoted to L1. The audit catches:
//!
//!   * `forbidden_phrases_unless_l1_promoted` appearing in any doc
//!     while current_level is still L0 or the L1 dry-run dashboard
//!     forbids auto-promotion;
//!   * the release script
//!     `scripts/release/check_replacement_claim_evidence.sh`
//!     missing required structural markers (`FRANKENLIBC_RELEASE_TAG`,
//!     release-claim-evidence gate identifier, L0/L1 mention);
//!   * cited doc paths missing on disk;
//!   * `allowed_anchor_phrases` whose `expected_doc_path` is missing
//!     the cited anchor (skipped only when `optional_until_phase` is
//!     declared).

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

fn audit_path() -> PathBuf {
    workspace_root().join("tests/conformance/replacement_claim_doc_audit.v1.json")
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
    "audit_run_id",
    "doc_path",
    "phrase",
    "phrase_kind",
    "claim_state_required",
    "claim_state_actual",
    "decision",
    "rejection_reason",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "overclaim_in_doc_while_dashboard_blocks",
    "overclaim_in_doc_while_current_level_l0",
    "release_script_missing",
    "missing_release_script_marker",
    "doc_path_missing",
    "stale_source_commit",
];

#[test]
fn audit_artifact_is_well_formed() -> TestResult {
    let audit = load_json(&audit_path())?;
    ensure_eq(
        audit["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(audit["bead"].as_str(), Some("bd-5unc9"), "bead")?;
    ensure(
        !audit["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;
    let freshness_policy = &audit["source_commit_freshness_policy"];
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
        Some("block_replacement_claim_text"),
        "source_commit_freshness_policy.stale_result",
    )?;
    ensure_eq(
        freshness_policy["claim_text_allowed_when_stale"].as_bool(),
        Some(false),
        "source_commit_freshness_policy.claim_text_allowed_when_stale",
    )?;
    ensure_eq(
        freshness_policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "source_commit_freshness_policy.rejected_evidence_kind",
    )?;

    let inputs = audit["inputs"]
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

    let log_fields: Vec<&str> = as_array(&audit["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &audit["policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_l1_dashboard_and_promotion_aligned"),
        "policy.default_decision",
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
fn stale_source_commit_policy_blocks_replacement_claim_text() -> TestResult {
    let root = workspace_root();
    let audit = load_json(&audit_path())?;
    let audit_commit = as_str(&audit["source_commit"], "source_commit")?;
    ensure(
        audit_commit.len() == 40 && audit_commit.chars().all(|ch| ch.is_ascii_hexdigit()),
        "source_commit must be a 40-character git SHA",
    )?;

    let current_head = git_head(&root)?;
    if audit_commit != current_head {
        let policy = &audit["source_commit_freshness_policy"];
        ensure_eq(
            policy["stale_result"].as_str(),
            Some("block_replacement_claim_text"),
            "stale replacement doc audit source_commit must block replacement claim text",
        )?;
        ensure_eq(
            policy["claim_text_allowed_when_stale"].as_bool(),
            Some(false),
            "stale replacement doc audit source_commit must not allow claim text",
        )?;
        ensure_eq(
            policy["rejected_evidence_kind"].as_str(),
            Some("stale_source_commit"),
            "stale replacement doc audit source_commit must use stale_source_commit",
        )?;
    }

    Ok(())
}

fn l1_promotion_evidence_is_complete(levels: &Value) -> TestResult {
    ensure_eq(
        levels["release_tag_policy"]["current_release_level"].as_str(),
        Some("L1"),
        "release_tag_policy.current_release_level",
    )?;
    let l1 = as_array(&levels["levels"], "levels")?
        .iter()
        .find(|entry| entry["level"].as_str() == Some("L1"))
        .ok_or_else(|| test_error("replacement_levels.json must include L1 entry"))?;
    ensure_eq(l1["status"].as_str(), Some("achieved"), "levels.L1.status")?;
    ensure_eq(
        l1["host_glibc_required"].as_bool(),
        Some(true),
        "levels.L1.host_glibc_required",
    )?;
    ensure(
        as_str(&l1["description"], "levels.L1.description")?
            .contains("not a standalone replacement claim"),
        "levels.L1.description must preserve non-standalone claim boundary",
    )?;
    ensure(
        as_array(&l1["blockers"], "levels.L1.blockers")?.is_empty(),
        "levels.L1.blockers must be empty before L1 doc phrases are allowed",
    )?;
    let objective_gate = &l1["objective_gate"];
    ensure_eq(
        objective_gate["status"].as_str(),
        Some("pass"),
        "levels.L1.objective_gate.status",
    )?;
    let obligation_ids: Vec<&str> = as_array(
        &objective_gate["obligations"],
        "levels.L1.objective_gate.obligations",
    )?
    .iter()
    .map(|obligation| obligation["id"].as_str().unwrap_or_default())
    .collect();
    for required in [
        "stub_free_taxonomy",
        "callthrough_pct_within_l1_bound",
        "implemented_pct_meets_l1_floor",
        "hardened_smoke_battery",
        "claim_reconciliation_clean",
        "perf_budget_alignment",
        "promotion_claim_control",
        "crt_startup_tls_proof_matrix",
    ] {
        ensure(
            obligation_ids.contains(&required),
            format!("levels.L1.objective_gate.obligations missing {required}"),
        )?;
    }
    for obligation in as_array(
        &objective_gate["obligations"],
        "levels.L1.objective_gate.obligations",
    )? {
        ensure_eq(
            obligation["outcome"].as_str(),
            Some("pass"),
            format!(
                "levels.L1.objective_gate.obligation.{}",
                obligation["id"].as_str().unwrap_or("<unknown>")
            ),
        )?;
    }
    Ok(())
}

#[test]
fn replacement_claim_phrases_match_current_level_policy() -> TestResult {
    let audit = load_json(&audit_path())?;
    let levels = load_json(&workspace_root().join("tests/conformance/replacement_levels.json"))?;
    let current_level = as_str(&levels["current_level"], "current_level")?;

    let doc_paths: Vec<String> = as_array(&audit["subject"]["doc_paths"], "subject.doc_paths")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    let mut doc_contents: Vec<(String, String)> = Vec::new();
    for path in &doc_paths {
        let abs = workspace_root().join(path);
        ensure(abs.exists(), format!("doc_path_missing: {path}"))?;
        let lower = read_text(&abs)?.to_lowercase();
        doc_contents.push((path.clone(), lower));
    }

    if current_level == "L1" {
        l1_promotion_evidence_is_complete(&levels)?;
        for entry in as_array(
            &audit["forbidden_phrases_unless_l1_promoted"],
            "forbidden_phrases_unless_l1_promoted",
        )? {
            let phrase_id = as_str(&entry["phrase_id"], "entry.phrase_id")?;
            match as_str(&entry["phrase_kind"], "entry.phrase_kind")? {
                "case_insensitive_substring" | "case_insensitive_substring_unless_disclaimed" => {}
                other => {
                    return Err(test_error(format!(
                        "phrase {phrase_id}: unsupported phrase_kind {other}"
                    )));
                }
            }
        }
        return Ok(());
    }

    if current_level != "L0" {
        return Err(test_error(format!(
            "current_level={current_level}; update replacement_claim_doc_audit_test.rs before relaxing L2/L3 claim semantics"
        )));
    }

    for entry in as_array(
        &audit["forbidden_phrases_unless_l1_promoted"],
        "forbidden_phrases_unless_l1_promoted",
    )? {
        let phrase_id = as_str(&entry["phrase_id"], "entry.phrase_id")?;
        let phrase = as_str(&entry["phrase"], "entry.phrase")?;
        let kind = as_str(&entry["phrase_kind"], "entry.phrase_kind")?;
        let disclaimer_anchors: Vec<String> = entry
            .get("disclaimer_anchors")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let needle = phrase.to_lowercase();
        for (path, content) in &doc_contents {
            // For each occurrence, examine the surrounding ±200-char window
            // for one of the disclaimer anchors. If `kind` allows
            // disclaimer-suppression, occurrences inside a window with any
            // anchor pass; bare occurrences fail.
            let mut idx = 0usize;
            while let Some(pos) = content[idx..].find(&needle) {
                let abs_pos = idx + pos;
                let window_start = abs_pos.saturating_sub(200);
                let window_end = (abs_pos + needle.len() + 200).min(content.len());
                let window = &content[window_start..window_end];
                let allowed = match kind {
                    "case_insensitive_substring" => false,
                    "case_insensitive_substring_unless_disclaimed" => {
                        disclaimer_anchors.iter().any(|a| window.contains(a))
                    }
                    other => {
                        return Err(test_error(format!(
                            "phrase {phrase_id}: unsupported phrase_kind {other}"
                        )));
                    }
                };
                ensure(
                    allowed,
                    format!(
                        "overclaim_in_doc_while_current_level_l0: phrase {phrase_id} ({phrase:?}) at {path}:offset {abs_pos} has no disclaimer anchor in ±200 chars; current_level=L0 forbids it"
                    ),
                )?;
                idx = abs_pos + needle.len();
            }
        }
    }
    Ok(())
}

#[test]
fn release_script_carries_required_structural_markers() -> TestResult {
    let audit = load_json(&audit_path())?;
    let release_path = audit["subject"]["release_script"]
        .as_str()
        .ok_or_else(|| test_error("subject.release_script must be a string"))?;
    let abs = workspace_root().join(release_path);
    ensure(
        abs.exists(),
        format!("release_script_missing: {release_path}"),
    )?;
    let content = read_text(&abs)?;
    for marker in as_array(
        &audit["release_script_required_markers"],
        "release_script_required_markers",
    )? {
        let marker = as_str(marker, "release_script_required_markers[]")?;
        ensure(
            content.contains(marker),
            format!("missing_release_script_marker: {release_path} does not mention {marker}"),
        )?;
    }
    Ok(())
}

#[test]
fn audit_pins_l1_dry_run_dashboard_as_consuming_gate() -> TestResult {
    let audit = load_json(&audit_path())?;
    let consuming: Vec<&str> = as_array(&audit["consuming_gates"], "consuming_gates")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure(
        consuming.contains(&"tests/conformance/l1_dry_run_readiness_dashboard.v1.json"),
        "consuming_gates must include the L1 dry-run readiness dashboard",
    )?;
    ensure(
        consuming.contains(&"tests/conformance/replacement_levels.json"),
        "consuming_gates must include replacement_levels.json",
    )?;
    let root = workspace_root();
    for path in consuming {
        ensure(
            root.join(path).exists(),
            format!("consuming_gates entry not found: {path}"),
        )?;
    }
    Ok(())
}

#[test]
fn allowed_anchor_phrases_resolve_in_their_expected_doc_or_are_phase_deferred() -> TestResult {
    let audit = load_json(&audit_path())?;
    for entry in as_array(&audit["allowed_anchor_phrases"], "allowed_anchor_phrases")? {
        let phrase_id = as_str(&entry["phrase_id"], "entry.phrase_id")?;
        let phrase = as_str(&entry["phrase"], "entry.phrase")?;
        let expected_doc = as_str(&entry["expected_doc_path"], "entry.expected_doc_path")?;
        let optional = entry
            .get("optional_until_phase")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let abs = workspace_root().join(expected_doc);
        ensure(
            abs.exists(),
            format!("anchor {phrase_id}: expected_doc_path missing: {expected_doc}"),
        )?;
        let content = read_text(&abs)?.to_lowercase();
        let needle = phrase.to_lowercase();
        if !content.contains(&needle) {
            if optional {
                // Phase-deferred anchor; record but do not fail.
                continue;
            }
            return Err(test_error(format!(
                "anchor {phrase_id}: phrase {phrase:?} missing in {expected_doc} and not flagged optional_until_phase"
            )));
        }
    }
    Ok(())
}

#[test]
fn audit_subject_includes_both_readme_and_feature_parity() -> TestResult {
    let audit = load_json(&audit_path())?;
    let docs: Vec<&str> = as_array(&audit["subject"]["doc_paths"], "subject.doc_paths")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure(
        docs.contains(&"README.md"),
        "subject.doc_paths must include README.md",
    )?;
    ensure(
        docs.contains(&"FEATURE_PARITY.md"),
        "subject.doc_paths must include FEATURE_PARITY.md",
    )?;
    Ok(())
}
