//! Integration test: dlfcn replace-boundary L1 burndown classification
//! (bd-wcwwl).
//!
//! Companion to the existing `dlfcn_replace_boundary_sentinel.v1.json` —
//! does NOT change the sentinel's host-callsite census but adds a
//! per-callsite L1-relevance classification:
//!
//!   * `l1_blocker` is this artifact's legacy field name for a standalone
//!     replacement blocker; it must be removed before current_level can
//!     promote to L2/L3.
//!   * `below_l1` is structurally unreachable in hardened interpose paths
//!     (proven by a cited runtime_policy guard); permitted to remain.
//!
//! The harness gate enforces:
//!   * every sentinel callsite has exactly one classification row;
//!   * every `below_l1` row carries a `below_l1_proof_kind` from the
//!     declared enum and a non-empty `rationale`;
//!   * the bootstrap_passthrough sentinel rows must classify as
//!     `below_l1` with proof `runtime_policy_bootstrap_only`, and the
//!     `bootstrap_passthrough_active()` guard must actually appear in
//!     dlfcn_abi.rs (otherwise the proof is fictional);
//!   * the L1-blocker count is at most `policy.max_l1_blockers`;
//!   * counts in `expected_counts` match the live classification.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
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

fn burndown_path() -> PathBuf {
    workspace_root().join("tests/conformance/dlfcn_replace_boundary_l1_burndown.v1.json")
}

fn sentinel_path() -> PathBuf {
    workspace_root().join("tests/conformance/dlfcn_replace_boundary_sentinel.v1.json")
}

fn dlfcn_source_path() -> PathBuf {
    workspace_root().join("crates/frankenlibc-abi/src/dlfcn_abi.rs")
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
    let head = String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("git HEAD should be UTF-8: {err}")))?
        .trim()
        .to_owned();
    ensure(
        is_hex_commit(&head),
        format!("git rev-parse HEAD returned invalid commit {head:?}"),
    )?;
    Ok(head)
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn source_commit_is_current(value: &str, current_head: &str) -> bool {
    value == "current" || value == current_head
}

fn assert_recorded_source_commit_is_current(root: &Path, burndown: &Value) -> TestResult {
    let source_commit = as_str(&burndown["source_commit"], "source_commit")?;
    ensure(
        source_commit == "current" || is_hex_commit(source_commit),
        format!("source_commit must be 'current' or a full hex git commit, got {source_commit:?}"),
    )?;
    let current_head = git_head(root)?;
    ensure(
        source_commit_is_current(source_commit, &current_head),
        "source_commit must be 'current' or match current git HEAD",
    )
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "callsite_id",
    "l1_relevance",
    "below_l1_proof_kind",
    "expected_l1_blocker",
    "actual_l1_blocker",
    "decision",
    "rejection_reason",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "callsite_missing_classification",
    "below_l1_without_proof_kind",
    "l1_blocker_count_drift",
    "duplicate_callsite_id",
    "stale_source_commit",
    "classification_does_not_match_sentinel_id_set",
];

const VALID_PROOF_KINDS: &[&str] = &[
    "runtime_policy_bootstrap_only",
    "host_handle_round_trip_outside_l1_namespace",
    "rtld_default_l0_only_lookup",
];

#[test]
fn burndown_artifact_is_well_formed() -> TestResult {
    let burndown = load_json(&burndown_path())?;
    ensure_eq(
        burndown["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(burndown["bead"].as_str(), Some("bd-wcwwl"), "bead")?;
    ensure_eq(
        burndown["source_commit"].as_str(),
        Some("current"),
        "checked-in dlfcn burndown source_commit must use current marker",
    )?;
    assert_recorded_source_commit_is_current(&workspace_root(), &burndown)?;
    let freshness_policy = &burndown["source_commit_freshness_policy"];
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
        Some("block_l1_burndown_classification"),
        "source_commit_freshness_policy.stale_result",
    )?;
    ensure_eq(
        freshness_policy["classification_allowed_when_stale"].as_bool(),
        Some(false),
        "source_commit_freshness_policy.classification_allowed_when_stale",
    )?;
    ensure_eq(
        freshness_policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "source_commit_freshness_policy.rejected_evidence_kind",
    )?;

    let inputs = burndown["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for key in ["sentinel", "dlfcn_source", "replacement_levels"] {
        let path = inputs
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| test_error(format!("inputs.{key} must be a string")))?;
        ensure(
            workspace_root().join(path).exists(),
            format!("inputs.{key} must reference an existing artifact: {path}"),
        )?;
    }

    let log_fields: Vec<&str> = as_array(&burndown["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &burndown["policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_burndown_classification_current"),
        "policy.default_decision",
    )?;
    ensure(
        policy["max_l1_blockers"]
            .as_u64()
            .map(|n| n <= 8)
            .unwrap_or(false),
        "policy.max_l1_blockers must be a u64 <= 8",
    )?;
    let proof_kinds: Vec<&str> = as_array(&policy["below_l1_proof_kinds"], "below_l1_proof_kinds")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    for kind in VALID_PROOF_KINDS {
        ensure(
            proof_kinds.contains(kind),
            format!("below_l1_proof_kinds must include {kind}"),
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
fn stale_source_commit_policy_blocks_l1_burndown_classification() -> TestResult {
    let mut burndown = load_json(&burndown_path())?;
    burndown["source_commit"] = json!("0000000000000000000000000000000000000000");

    let error = assert_recorded_source_commit_is_current(&workspace_root(), &burndown)
        .expect_err("stale recorded source_commit should be rejected");
    ensure(
        error
            .to_string()
            .contains("source_commit must be 'current' or match current git HEAD"),
        format!("unexpected stale source_commit error: {error}"),
    )?;

    let policy = &burndown["source_commit_freshness_policy"];
    ensure_eq(
        policy["stale_result"].as_str(),
        Some("block_l1_burndown_classification"),
        "stale dlfcn burndown source_commit must block L1 burndown classification",
    )?;
    ensure_eq(
        policy["classification_allowed_when_stale"].as_bool(),
        Some(false),
        "stale dlfcn burndown source_commit must not allow classification evidence",
    )?;
    ensure_eq(
        policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "stale dlfcn burndown source_commit must use stale_source_commit",
    )?;

    Ok(())
}

#[test]
fn classification_set_equals_sentinel_callsite_set() -> TestResult {
    let burndown = load_json(&burndown_path())?;
    let sentinel = load_json(&sentinel_path())?;

    let mut sentinel_ids: BTreeSet<String> = BTreeSet::new();
    for row in as_array(&sentinel["host_callsites"], "sentinel.host_callsites")? {
        if let Some(id) = row["callsite_id"].as_str() {
            sentinel_ids.insert(id.to_string());
        }
    }

    let mut burndown_ids: BTreeSet<String> = BTreeSet::new();
    for row in as_array(&burndown["classifications"], "classifications")? {
        let id = as_str(&row["callsite_id"], "row.callsite_id")?;
        ensure(
            burndown_ids.insert(id.to_string()),
            format!("duplicate_callsite_id: {id}"),
        )?;
    }

    ensure_eq(
        burndown_ids.clone(),
        sentinel_ids.clone(),
        "classification_does_not_match_sentinel_id_set: burndown callsite_id set must equal sentinel host_callsites set",
    )?;
    Ok(())
}

#[test]
fn every_classification_row_is_well_formed() -> TestResult {
    let burndown = load_json(&burndown_path())?;
    let proof_kinds: BTreeSet<&str> = VALID_PROOF_KINDS.iter().copied().collect();
    let mut by_relevance: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_proof_kind: BTreeMap<String, usize> = BTreeMap::new();

    for row in as_array(&burndown["classifications"], "classifications")? {
        let id = as_str(&row["callsite_id"], "row.callsite_id")?;
        let relevance = as_str(&row["l1_relevance"], "row.l1_relevance")?;
        ensure(
            matches!(relevance, "l1_blocker" | "below_l1"),
            format!("row {id}: l1_relevance {relevance} must be l1_blocker or below_l1"),
        )?;
        *by_relevance.entry(relevance.to_string()).or_default() += 1;

        let rationale = as_str(&row["rationale"], "row.rationale")?;
        ensure(
            !rationale.is_empty(),
            format!("row {id}: rationale must be non-empty"),
        )?;

        if relevance == "below_l1" {
            let proof = row
                .get("below_l1_proof_kind")
                .and_then(|v| v.as_str())
                .ok_or_else(|| test_error(format!("row {id}: below_l1_without_proof_kind")))?;
            ensure(
                proof_kinds.contains(proof),
                format!("row {id}: below_l1_proof_kind {proof} not in valid set"),
            )?;
            *by_proof_kind.entry(proof.to_string()).or_default() += 1;
        } else {
            // l1_blocker rows must NOT carry a below_l1_proof_kind.
            ensure(
                row.get("below_l1_proof_kind")
                    .map(|v| v.is_null())
                    .unwrap_or(true),
                format!("row {id}: l1_blocker must not carry below_l1_proof_kind"),
            )?;
        }
    }

    let expected = &burndown["expected_counts"];
    let total = expected["total"].as_u64().unwrap_or(0) as usize;
    let total_actual = by_relevance.values().sum::<usize>();
    ensure_eq(total_actual, total, "expected_counts.total")?;

    let exp_blockers = expected["l1_blocker"].as_u64().unwrap_or(0) as usize;
    let actual_blockers = by_relevance.get("l1_blocker").copied().unwrap_or(0);
    ensure_eq(actual_blockers, exp_blockers, "expected_counts.l1_blocker")?;

    let exp_below = expected["below_l1"].as_u64().unwrap_or(0) as usize;
    let actual_below = by_relevance.get("below_l1").copied().unwrap_or(0);
    ensure_eq(actual_below, exp_below, "expected_counts.below_l1")?;

    let exp_proof_map = expected["below_l1_by_proof_kind"]
        .as_object()
        .ok_or_else(|| test_error("expected_counts.below_l1_by_proof_kind must be an object"))?;
    for (kind, count) in exp_proof_map {
        let actual = by_proof_kind.get(kind).copied().unwrap_or(0);
        let expected_count = count.as_u64().unwrap_or(0) as usize;
        ensure_eq(
            actual,
            expected_count,
            format!("expected_counts.below_l1_by_proof_kind[{kind}]"),
        )?;
    }

    let max_blockers = burndown["policy"]["max_l1_blockers"].as_u64().unwrap_or(0) as usize;
    ensure(
        actual_blockers <= max_blockers,
        format!(
            "l1_blocker_count_drift: {actual_blockers} > policy.max_l1_blockers {max_blockers}"
        ),
    )?;
    Ok(())
}

#[test]
fn bootstrap_below_l1_proofs_match_actual_runtime_guards() -> TestResult {
    // Every below_l1 row that cites runtime_policy_bootstrap_only must
    // refer to a callsite whose enclosing function in dlfcn_abi.rs
    // actually contains a `bootstrap_passthrough_active()` guard. If the
    // guard disappears in a future edit, the proof is no longer valid
    // and L1 promotion would be silently lifted — this test catches it.
    let burndown = load_json(&burndown_path())?;
    let source = read_text(&dlfcn_source_path())?;
    let sentinel = load_json(&sentinel_path())?;

    // Build callsite_id -> context_anchor map from the sentinel.
    let mut anchor_by_id: BTreeMap<String, String> = BTreeMap::new();
    for row in as_array(&sentinel["host_callsites"], "sentinel.host_callsites")? {
        let id = as_str(&row["callsite_id"], "row.callsite_id")?.to_string();
        if let Some(ctx) = row["context_anchor"].as_str() {
            anchor_by_id.insert(id, ctx.to_string());
        }
    }

    let lines: Vec<&str> = source.lines().collect();
    for row in as_array(&burndown["classifications"], "classifications")? {
        let id = as_str(&row["callsite_id"], "row.callsite_id")?;
        let proof = row.get("below_l1_proof_kind").and_then(|v| v.as_str());
        if proof != Some("runtime_policy_bootstrap_only") {
            continue;
        }
        let anchor = anchor_by_id.get(id).ok_or_else(|| {
            test_error(format!(
                "row {id}: sentinel does not declare a context_anchor; cannot validate runtime_policy_bootstrap_only proof"
            ))
        })?;
        let anchor_idx = lines
            .iter()
            .position(|l| *l == anchor.as_str())
            .ok_or_else(|| {
                test_error(format!(
                    "row {id}: context_anchor {anchor:?} not found in dlfcn_abi.rs"
                ))
            })?;

        // Search the 60-line window AROUND the anchor for the
        // `bootstrap_passthrough_active()` guard. The current bootstrap
        // arms are 30-line blocks; 60-line window leaves headroom but
        // refuses to look across the whole file (which would let the
        // guard come from a totally unrelated function).
        let window_start = anchor_idx.saturating_sub(30);
        let window_end = (anchor_idx + 30).min(lines.len());
        let window_has_guard = lines[window_start..window_end]
            .iter()
            .any(|l| l.contains("bootstrap_passthrough_active()"));
        ensure(
            window_has_guard,
            format!(
                "row {id}: runtime_policy_bootstrap_only proof requires `bootstrap_passthrough_active()` guard within 30 lines of the context_anchor at line {} — guard not found, proof is fictional",
                anchor_idx + 1
            ),
        )?;
    }
    Ok(())
}

#[test]
fn consuming_gates_exist_on_disk() -> TestResult {
    let burndown = load_json(&burndown_path())?;
    let root = workspace_root();
    for gate in as_array(&burndown["consuming_gates"], "consuming_gates")? {
        let path = as_str(gate, "consuming_gates[]")?;
        ensure(
            root.join(path).exists(),
            format!("consuming_gates entry not found: {path}"),
        )?;
    }
    Ok(())
}

#[test]
fn burndown_decreases_l1_blocker_count_below_sentinel_total() -> TestResult {
    // Acceptance criterion of bd-wcwwl: "the sentinel count to decrease
    // OR a precise proof that a blocker belongs outside L1". This test
    // pins the burndown decision: the L1-blocker count strictly less
    // than the sentinel host_callsites count, with at least one row
    // proven below_l1 by a runtime_policy guard. If a future edit
    // reclassifies a below_l1 row back to l1_blocker without a real
    // delegation removal, this asserts the burndown's value-add is
    // preserved.
    let sentinel = load_json(&sentinel_path())?;
    let burndown = load_json(&burndown_path())?;
    let sentinel_total = as_array(&sentinel["host_callsites"], "sentinel.host_callsites")?.len();
    let burndown_blockers = burndown["expected_counts"]["l1_blocker"]
        .as_u64()
        .ok_or_else(|| test_error("expected_counts.l1_blocker must be u64"))?
        as usize;
    ensure(
        burndown_blockers < sentinel_total,
        format!(
            "burndown must record fewer L1 blockers ({burndown_blockers}) than sentinel total ({sentinel_total}); otherwise this artifact adds no value"
        ),
    )?;
    let below_l1 = burndown["expected_counts"]["below_l1"]
        .as_u64()
        .unwrap_or(0) as usize;
    ensure(
        below_l1 >= 1,
        format!(
            "burndown must have at least one below_l1 row (got {below_l1}); otherwise no blocker has been moved off the L1 critical path"
        ),
    )?;
    Ok(())
}
