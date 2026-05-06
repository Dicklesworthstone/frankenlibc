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

fn current_git_head(root: &Path) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("git rev-parse HEAD should run: {err}")))?;
    ensure(
        output.status.success(),
        format!("git rev-parse HEAD failed with status {}", output.status),
    )?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("git rev-parse HEAD should emit UTF-8: {err}")))?;
    let head = stdout.trim().to_string();
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

fn assert_recorded_source_commit_is_current(root: &Path, dashboard: &Value) -> TestResult {
    let source_commit = as_str(&dashboard["source_commit"], "source_commit")?;
    ensure(
        source_commit == "current" || is_hex_commit(source_commit),
        format!("source_commit must be 'current' or a full hex git commit, got {source_commit:?}"),
    )?;
    let current_head = current_git_head(root)?;
    ensure(
        source_commit_is_current(source_commit, &current_head),
        "source_commit must be 'current' or match current git HEAD",
    )
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

fn expected_source_commit_freshness_policy() -> Value {
    json!({
        "recorded_source_commit_field": "source_commit",
        "current_head_check": "git rev-parse HEAD",
        "fresh_result": "eligible_for_row_evaluation_only",
        "stale_result": "report_blockers_no_auto_promotion",
        "promotion_allowed_when_stale": false,
        "rejected_evidence_kind": "stale_source_commit",
    })
}

fn select_field<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = root;
    for segment in path.split('.') {
        cursor = match cursor {
            Value::Object(map) => map.get(segment)?,
            Value::Array(values) => values.get(segment.parse::<usize>().ok()?)?,
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
    let source_commit = as_str(&dashboard["source_commit"], "source_commit")?;
    ensure(
        source_commit == "current",
        "checked-in dashboard source_commit must use current marker",
    )?;
    assert_recorded_source_commit_is_current(&workspace_root(), &dashboard)?;
    let freshness_policy = &dashboard["source_commit_freshness_policy"];
    ensure_eq(
        freshness_policy,
        &expected_source_commit_freshness_policy(),
        "source_commit_freshness_policy",
    )?;
    ensure_eq(
        freshness_policy["recorded_source_commit_field"].as_str(),
        Some("source_commit"),
        "source_commit_freshness_policy.recorded_source_commit_field",
    )?;
    ensure_eq(
        freshness_policy["current_head_check"].as_str(),
        Some("git rev-parse HEAD"),
        "source_commit_freshness_policy.current_head_check",
    )?;
    ensure_eq(
        freshness_policy["fresh_result"].as_str(),
        Some("eligible_for_row_evaluation_only"),
        "source_commit_freshness_policy.fresh_result",
    )?;
    ensure_eq(
        freshness_policy["stale_result"].as_str(),
        Some("report_blockers_no_auto_promotion"),
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
    let current_head = current_git_head(&workspace_root())?;
    if !source_commit_is_current(source_commit, &current_head) {
        ensure_eq(
            freshness_policy["stale_result"].as_str(),
            Some("report_blockers_no_auto_promotion"),
            "stale dashboard source_commit must remain report-only",
        )?;
        ensure_eq(
            freshness_policy["promotion_allowed_when_stale"].as_bool(),
            Some(false),
            "stale dashboard source_commit must not allow promotion",
        )?;
    }

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
fn stale_recorded_source_commit_is_rejected_without_promotion() -> TestResult {
    let mut dashboard = load_json(&dashboard_path())?;
    dashboard["source_commit"] = json!("0000000000000000000000000000000000000000");

    let error = assert_recorded_source_commit_is_current(&workspace_root(), &dashboard)
        .expect_err("stale recorded source_commit should be rejected");
    ensure(
        error
            .to_string()
            .contains("source_commit must be 'current' or match current git HEAD"),
        format!("unexpected stale source_commit error: {error}"),
    )?;

    let freshness_policy = &dashboard["source_commit_freshness_policy"];
    ensure_eq(
        freshness_policy["stale_result"].as_str(),
        Some("report_blockers_no_auto_promotion"),
        "stale dashboard source_commit must remain report-only",
    )?;
    ensure_eq(
        freshness_policy["promotion_allowed_when_stale"].as_bool(),
        Some(false),
        "stale dashboard source_commit must not allow promotion",
    )
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
fn replacement_level_claim_control_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "replacement-level-release-tag-still-l0",
            ("release_tag_policy.current_release_level", json!("L0")),
        ),
        (
            "replacement-level-release-tag-example",
            (
                "release_tag_policy.current_release_tag_example",
                json!("v0.1.0-L0"),
            ),
        ),
        (
            "replacement-level-current-stub-count",
            ("current_assessment.stub", json!(0)),
        ),
        (
            "replacement-level-current-callthrough-pct",
            ("current_assessment.callthrough_pct", json!(0)),
        ),
        (
            "replacement-level-l1-status",
            ("levels.1.status", json!("in_progress")),
        ),
        (
            "replacement-level-l1-objective-gate-status",
            ("levels.1.objective_gate.status", json!("blocked")),
        ),
        (
            "replacement-level-l1-promotion-outcome",
            ("levels.1.objective_gate.obligations.6.outcome", json!("blocked")),
        ),
        (
            "replacement-level-l1-promotion-actual-current-level",
            (
                "levels.1.objective_gate.obligations.6.actual.current_level",
                json!("L0"),
            ),
        ),
        (
            "replacement-level-l1-crt-tls-outcome",
            ("levels.1.objective_gate.obligations.7.outcome", json!("blocked")),
        ),
        (
            "replacement-level-l1-crt-tls-blocked-row-count",
            (
                "levels.1.objective_gate.obligations.7.actual.blocked_row_count",
                json!(6),
            ),
        ),
        (
            "replacement-level-l1-first-blocker",
            (
                "levels.1.blockers.0",
                json!(
                    "L1 claim promotion remains blocked until current_level and release_tag_policy.current_release_level move from L0 to L1 together under the bd-gtf.4 objective gate."
                ),
            ),
        ),
        (
            "replacement-level-l0-to-l1-crt-requirement",
            (
                "transition_requirements.L0_to_L1.3",
                json!(
                    "Complete the L1 CRT/startup/TLS proof matrix for startup, TLS, init/fini, destructors, errno isolation, secure mode, and diagnostics"
                ),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("replacement-level-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected replacement level dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "promotion_state",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/replacement_levels.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing replacement level claim-control dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
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
fn standalone_artifact_report_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let expected_rows: BTreeSet<(&str, &str)> = [
        (
            "standalone-artifact-report-needed-libraries-diagnostic",
            "artifact_state.dependency_breakdown.needed_libraries",
        ),
        (
            "standalone-artifact-report-ldd-libraries-diagnostic",
            "artifact_state.dependency_breakdown.ldd_libraries",
        ),
        (
            "standalone-artifact-report-host-needed-libraries-diagnostic",
            "artifact_state.dependency_breakdown.host_needed_libraries",
        ),
        (
            "standalone-artifact-report-host-direct-needed-libraries-diagnostic",
            "artifact_state.dependency_breakdown.host_direct_needed_libraries",
        ),
        (
            "standalone-artifact-report-host-resolved-libraries-diagnostic",
            "artifact_state.dependency_breakdown.host_resolved_libraries",
        ),
        (
            "standalone-artifact-report-sampled-symbols-present-diagnostic",
            "artifact_state.sampled_symbols_present",
        ),
        (
            "standalone-artifact-report-symbol-samples-diagnostic",
            "artifact_state.symbol_samples",
        ),
        (
            "standalone-artifact-report-claim-status-diagnostic",
            "claim_status",
        ),
        (
            "standalone-artifact-report-source-commit-diagnostic",
            "source_commit",
        ),
        (
            "standalone-artifact-report-status-diagnostic",
            "artifact_state.status",
        ),
        (
            "standalone-artifact-report-failure-signature-diagnostic",
            "artifact_state.failure_signature",
        ),
        (
            "standalone-artifact-report-host-glibc-dependency-diagnostic",
            "artifact_state.host_glibc_dependency",
        ),
        (
            "standalone-artifact-report-path-diagnostic",
            "artifact_state.path",
        ),
        (
            "standalone-artifact-report-sha256-diagnostic",
            "artifact_state.sha256",
        ),
        (
            "standalone-artifact-report-mtime-diagnostic",
            "artifact_state.mtime",
        ),
        (
            "standalone-artifact-report-rustc-version-diagnostic",
            "build_provenance.rustc_version",
        ),
        (
            "standalone-artifact-report-cargo-profile-diagnostic",
            "build_provenance.cargo_profile",
        ),
        (
            "standalone-artifact-report-target-triple-diagnostic",
            "build_provenance.target_triple",
        ),
        (
            "standalone-artifact-report-cargo-target-dir-diagnostic",
            "build_provenance.cargo_target_dir",
        ),
        (
            "standalone-artifact-report-build-command-diagnostic",
            "build_provenance.build_command",
        ),
        (
            "standalone-artifact-report-sanitized-env-diagnostic",
            "build_provenance.sanitized_env",
        ),
        (
            "standalone-artifact-report-linker-path-diagnostic",
            "build_provenance.linker.path",
        ),
        (
            "standalone-artifact-report-linker-version-diagnostic",
            "build_provenance.linker.version",
        ),
        (
            "standalone-artifact-report-blocker-delta-baseline-source-diagnostic",
            "blocker_delta.baseline_source",
        ),
        (
            "standalone-artifact-report-blocker-delta-classification-diagnostic",
            "blocker_delta.delta_classification",
        ),
        (
            "standalone-artifact-report-blocker-delta-added-host-libraries-diagnostic",
            "blocker_delta.added_host_needed_libraries",
        ),
        (
            "standalone-artifact-report-blocker-delta-added-undefined-symbols-diagnostic",
            "blocker_delta.added_undefined_symbols",
        ),
        (
            "standalone-artifact-report-blocker-delta-added-version-requirements-diagnostic",
            "blocker_delta.added_version_requirements",
        ),
        (
            "standalone-artifact-report-blocker-delta-removed-host-libraries-diagnostic",
            "blocker_delta.removed_host_needed_libraries",
        ),
        (
            "standalone-artifact-report-blocker-delta-removed-undefined-symbols-diagnostic",
            "blocker_delta.removed_undefined_symbols",
        ),
        (
            "standalone-artifact-report-blocker-delta-removed-version-requirements-diagnostic",
            "blocker_delta.removed_version_requirements",
        ),
        (
            "standalone-artifact-report-blocker-delta-refresh-required-diagnostic",
            "blocker_delta.refresh_required",
        ),
        (
            "standalone-artifact-report-blocker-delta-refresh-note-diagnostic",
            "blocker_delta.refresh_note_present",
        ),
        (
            "standalone-artifact-report-undefined-symbols-diagnostic",
            "artifact_state.dependency_breakdown.undefined_symbols",
        ),
        (
            "standalone-artifact-report-unwind-symbols-diagnostic",
            "artifact_state.dependency_breakdown.undefined_unwind_symbols",
        ),
        (
            "standalone-artifact-report-glibc-symbols-diagnostic",
            "artifact_state.dependency_breakdown.undefined_glibc_symbols",
        ),
        (
            "standalone-artifact-report-tls-symbols-diagnostic",
            "artifact_state.dependency_breakdown.undefined_tls_symbols",
        ),
        (
            "standalone-artifact-report-version-needs-diagnostic",
            "artifact_state.dependency_breakdown.version_needs",
        ),
        (
            "standalone-artifact-report-host-version-requirements-diagnostic",
            "artifact_state.dependency_breakdown.host_version_requirements",
        ),
        (
            "standalone-artifact-report-loader-needed-diagnostic",
            "artifact_state.dependency_breakdown.loader_needed",
        ),
        (
            "standalone-artifact-report-blocking-reasons-diagnostic",
            "artifact_state.dependency_breakdown.blocking_reasons",
        ),
        (
            "standalone-artifact-report-top-level-blocking-reasons-diagnostic",
            "blocking_reasons",
        ),
        (
            "standalone-artifact-report-blocker-catalog-diagnostic",
            "artifact_state.dependency_breakdown.blocker_catalog",
        ),
        (
            "standalone-artifact-report-tool-exit-code-diagnostic",
            "tool_evidence.*.exit_code",
        ),
        (
            "standalone-artifact-report-tool-timeout-flag-diagnostic",
            "tool_evidence.*.timed_out",
        ),
        (
            "standalone-artifact-report-tool-timeout-budget-diagnostic",
            "tool_evidence.*.timeout_secs",
        ),
        (
            "standalone-artifact-report-tool-path-diagnostic",
            "tool_evidence.*.path",
        ),
    ]
    .into_iter()
    .collect();
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-artifact-report-") {
            continue;
        }
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_replacement_artifact.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        let expected_value = as_str(&row["expected_value"], "row.expected_value")?;
        seen.insert((row_id, expected_value));
    }
    ensure_eq(
        seen,
        expected_rows,
        "standalone artifact report dashboard rows",
    )
}

#[test]
fn standalone_artifact_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-artifact-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-artifact-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-artifact-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_standalone_replacement_artifact_evidence"),
            ),
        ),
        (
            "standalone-artifact-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.standalone_artifact_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-artifact-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-artifact-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected standalone artifact freshness row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_replacement_artifact.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing standalone artifact freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_owned_tls_surface_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-owned-tls-surface-manifest-id",
            ("manifest_id", json!("standalone-owned-tls-startup-surface")),
        ),
        (
            "standalone-owned-tls-surface-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-owned-tls-surface-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-owned-tls-surface-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_owned_tls_startup_surface"),
            ),
        ),
        (
            "standalone-owned-tls-surface-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.owned_tls_surface_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-owned-tls-surface-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_owned_tls_startup_surface"),
            ),
        ),
        (
            "standalone-owned-tls-surface-no-promotion",
            ("report_policy.promotion_allowed", json!(false)),
        ),
        (
            "standalone-owned-tls-surface-symbol-count",
            ("summary.current_tls_symbol_count", json!(1)),
        ),
        (
            "standalone-owned-tls-surface-provider-version-count",
            ("summary.provider_version_requirement_count", json!(1)),
        ),
        (
            "standalone-owned-tls-surface-ready-false",
            ("summary.owned_surface_ready", json!(false)),
        ),
        (
            "standalone-owned-tls-surface-claim-blocked",
            (
                "summary.claim_status_until_symbol_exit",
                json!("claim_blocked"),
            ),
        ),
        (
            "standalone-owned-tls-surface-hotspot-count",
            ("summary.source_surface_hotspot_count", json!(5)),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-owned-tls-surface-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected owned TLS surface dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_owned_tls_startup_surface.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing owned TLS surface dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_owned_tls_symbol_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-owned-tls-symbol-name",
            ("symbol_rows.0.symbol", json!("__tls_get_addr@GLIBC_2.3")),
        ),
        (
            "standalone-owned-tls-symbol-bare-name",
            ("symbol_rows.0.bare_symbol", json!("__tls_get_addr")),
        ),
        (
            "standalone-owned-tls-symbol-provider-library",
            (
                "symbol_rows.0.provider_library",
                json!("ld-linux-x86-64.so.2"),
            ),
        ),
        (
            "standalone-owned-tls-symbol-version-node",
            ("symbol_rows.0.version_node", json!("GLIBC_2.3")),
        ),
        (
            "standalone-owned-tls-symbol-requirement-id",
            (
                "symbol_rows.0.requirement_id",
                json!("ld-linux-x86-64.so.2:GLIBC_2.3"),
            ),
        ),
        (
            "standalone-owned-tls-symbol-blocking-reason",
            (
                "symbol_rows.0.blocking_reason",
                json!("undefined_tls_symbols"),
            ),
        ),
        (
            "standalone-owned-tls-symbol-provider-blocking-reason",
            (
                "symbol_rows.0.provider_blocking_reason",
                json!("host_version_requirements"),
            ),
        ),
        (
            "standalone-owned-tls-symbol-owner-surface",
            ("symbol_rows.0.owner_surface", json!("tls_startup")),
        ),
        (
            "standalone-owned-tls-symbol-provider-owner-surface",
            (
                "symbol_rows.0.provider_owner_surface",
                json!("loader_tls_runtime"),
            ),
        ),
        (
            "standalone-owned-tls-symbol-owned-surface-status",
            ("symbol_rows.0.owned_surface_status", json!("unresolved")),
        ),
        (
            "standalone-owned-tls-symbol-status-until-exit",
            ("symbol_rows.0.status_until_exit", json!("claim_blocked")),
        ),
        (
            "standalone-owned-tls-symbol-first-source-hotspot",
            (
                "symbol_rows.0.source_surface_hotspots.0",
                json!("crates/frankenlibc-abi/src/startup_abi.rs"),
            ),
        ),
        (
            "standalone-owned-tls-symbol-first-exit-criterion",
            (
                "symbol_rows.0.exit_criteria.0",
                json!("artifact_state.dependency_breakdown.undefined_tls_symbols is empty"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-owned-tls-symbol-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected owned TLS symbol dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_owned_tls_startup_surface.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing owned TLS symbol dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_owned_unwinder_surface_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-owned-unwinder-surface-manifest-id",
            (
                "manifest_id",
                json!("standalone-owned-unwinder-symbol-surface"),
            ),
        ),
        (
            "standalone-owned-unwinder-surface-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-owned-unwinder-surface-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-owned-unwinder-surface-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_owned_unwinder_symbol_surface"),
            ),
        ),
        (
            "standalone-owned-unwinder-surface-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.owned_unwinder_surface_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-owned-unwinder-surface-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_owned_unwinder_symbol_surface"),
            ),
        ),
        (
            "standalone-owned-unwinder-surface-no-promotion",
            ("report_policy.promotion_allowed", json!(false)),
        ),
        (
            "standalone-owned-unwinder-surface-symbol-count",
            ("summary.current_unwind_symbol_count", json!(12)),
        ),
        (
            "standalone-owned-unwinder-surface-provider-library-count",
            ("summary.provider_library_count", json!(1)),
        ),
        (
            "standalone-owned-unwinder-surface-provider-version-count",
            ("summary.provider_version_requirement_count", json!(3)),
        ),
        (
            "standalone-owned-unwinder-surface-unresolved-symbol-count",
            ("summary.unresolved_symbol_count", json!(12)),
        ),
        (
            "standalone-owned-unwinder-surface-ready-false",
            ("summary.owned_surface_ready", json!(false)),
        ),
        (
            "standalone-owned-unwinder-surface-claim-blocked",
            (
                "summary.claim_status_until_all_symbols_exit",
                json!("claim_blocked"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-owned-unwinder-surface-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected owned unwinder surface dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing owned unwinder surface dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_owned_unwinder_symbol_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-owned-unwinder-symbol-name",
            ("symbol_rows.0.symbol", json!("_Unwind_Backtrace@GCC_3.3")),
        ),
        (
            "standalone-owned-unwinder-symbol-bare-name",
            ("symbol_rows.0.bare_symbol", json!("_Unwind_Backtrace")),
        ),
        (
            "standalone-owned-unwinder-symbol-provider-library",
            ("symbol_rows.0.provider_library", json!("libgcc_s.so.1")),
        ),
        (
            "standalone-owned-unwinder-symbol-version-node",
            ("symbol_rows.0.version_node", json!("GCC_3.3")),
        ),
        (
            "standalone-owned-unwinder-symbol-requirement-id",
            ("symbol_rows.0.requirement_id", json!("libgcc_s.so.1:GCC_3.3")),
        ),
        (
            "standalone-owned-unwinder-symbol-blocking-reason",
            (
                "symbol_rows.0.blocking_reason",
                json!("undefined_unwind_symbols"),
            ),
        ),
        (
            "standalone-owned-unwinder-symbol-owner-surface",
            ("symbol_rows.0.owner_surface", json!("unwind_runtime")),
        ),
        (
            "standalone-owned-unwinder-symbol-source-diagnostic",
            (
                "symbol_rows.0.source_diagnostic",
                json!(
                    "standalone_compiler_runtime_blocker_diagnostics.current_forge_evidence.evidence_command_results.nm_dynamic.observed_undefined_unwind_symbols"
                ),
            ),
        ),
        (
            "standalone-owned-unwinder-symbol-source-version-matrix",
            (
                "symbol_rows.0.source_version_matrix",
                json!("standalone_host_version_requirement_burndown.version_requirement_matrix"),
            ),
        ),
        (
            "standalone-owned-unwinder-symbol-semantic-contract",
            (
                "symbol_rows.0.semantic_contract_class",
                json!("stack-trace frame enumeration"),
            ),
        ),
        (
            "standalone-owned-unwinder-symbol-owned-surface-status",
            ("symbol_rows.0.owned_surface_status", json!("unresolved")),
        ),
        (
            "standalone-owned-unwinder-symbol-status-until-exit",
            ("symbol_rows.0.status_until_exit", json!("claim_blocked")),
        ),
        (
            "standalone-owned-unwinder-symbol-first-evidence-command",
            (
                "symbol_rows.0.evidence_commands.0",
                json!("nm -D libfrankenlibc_replace.so | rg \"_Unwind_Backtrace\""),
            ),
        ),
        (
            "standalone-owned-unwinder-symbol-first-exit-criterion",
            (
                "symbol_rows.0.exit_criteria.0",
                json!("nm -D reports no undefined _Unwind_Backtrace symbol"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-owned-unwinder-symbol-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected owned unwinder symbol dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing owned unwinder symbol dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_compiler_runtime_experiment_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-compiler-runtime-experiment-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_compiler_runtime_experiment_refresh"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-source-commit-no-stale-evidence",
            (
                "source_commit_freshness_policy.experiment_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_compiler_runtime_experiment"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-report-only",
            ("report_policy.report_only", json!(true)),
        ),
        (
            "standalone-compiler-runtime-experiment-no-promotion",
            ("report_policy.promotion_allowed", json!(false)),
        ),
        (
            "standalone-compiler-runtime-experiment-no-replacement-level-change",
            (
                "report_policy.replacement_level_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-no-default-profile-change",
            (
                "report_policy.default_build_profile_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-explicit-mode-required",
            (
                "report_policy.non_baseline_lanes_require_explicit_mode",
                json!(true),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-required-mode",
            (
                "report_policy.required_mode",
                json!("--compiler-runtime-experiment"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-lane-count",
            ("summary.lane_count", json!(2)),
        ),
        (
            "standalone-compiler-runtime-experiment-baseline-lane",
            (
                "summary.baseline_lane",
                json!("baseline-release-standalone"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-experiment-lane",
            (
                "summary.experiment_lane",
                json!("panic-abort-compiler-runtime-minimized"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-baseline-claim-status",
            (
                "experiment_lanes.0.expected_claim_status",
                json!("claim_blocked"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-baseline-panic-strategy",
            (
                "experiment_lanes.0.panic_strategy",
                json!("implicit-unwind"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-abort-claim-status",
            (
                "experiment_lanes.1.expected_claim_status",
                json!("report_only"),
            ),
        ),
        (
            "standalone-compiler-runtime-experiment-abort-panic-strategy",
            ("experiment_lanes.1.panic_strategy", json!("abort")),
        ),
        (
            "standalone-compiler-runtime-experiment-abort-env",
            (
                "experiment_lanes.1.env.CARGO_PROFILE_RELEASE_PANIC",
                json!("abort"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-compiler-runtime-experiment-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected compiler runtime experiment dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_compiler_runtime_experiment.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing compiler runtime experiment dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_compiler_runtime_delta_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-compiler-runtime-delta-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_compiler_runtime_experiment_delta"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-source-commit-no-stale-evidence",
            (
                "source_commit_freshness_policy.delta_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_compiler_runtime_experiment_delta"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-report-only",
            ("report_policy.report_only", json!(true)),
        ),
        (
            "standalone-compiler-runtime-delta-no-promotion",
            ("report_policy.promotion_allowed", json!(false)),
        ),
        (
            "standalone-compiler-runtime-delta-no-replacement-level-change",
            (
                "report_policy.replacement_level_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-claim-status",
            ("summary.claim_status", json!("report_only")),
        ),
        (
            "standalone-compiler-runtime-delta-standalone-claim-status",
            ("summary.standalone_claim_status", json!("claim_blocked")),
        ),
        (
            "standalone-compiler-runtime-delta-classification",
            ("summary.delta_classification", json!("improvement")),
        ),
        (
            "standalone-compiler-runtime-delta-removed-unwind-symbol-count",
            ("summary.removed_unwind_symbol_count", json!(2)),
        ),
        (
            "standalone-compiler-runtime-delta-remaining-unwind-symbol-count",
            ("summary.remaining_unwind_symbol_count", json!(10)),
        ),
        (
            "standalone-compiler-runtime-delta-remaining-needed-library-count",
            ("summary.remaining_needed_library_count", json!(2)),
        ),
        (
            "standalone-compiler-runtime-delta-remaining-version-requirement-count",
            ("summary.remaining_version_requirement_count", json!(4)),
        ),
        (
            "standalone-compiler-runtime-delta-experiment-lane",
            (
                "observation.experiment_lane",
                json!("panic-abort-compiler-runtime-minimized"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-panic-strategy",
            (
                "observation.experiment_env.CARGO_PROFILE_RELEASE_PANIC",
                json!("abort"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-first-removed-unwind-symbol",
            (
                "observation.removed_undefined_unwind_symbols.0",
                json!("_Unwind_DeleteException@GCC_3.0"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-second-removed-unwind-symbol",
            (
                "observation.removed_undefined_unwind_symbols.1",
                json!("_Unwind_RaiseException@GCC_3.0"),
            ),
        ),
        (
            "standalone-compiler-runtime-delta-first-remaining-blocker",
            (
                "observation.remaining_blocking_reasons.0",
                json!("host_needed_libraries_present"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-compiler-runtime-delta-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected compiler runtime delta dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_compiler_runtime_experiment_delta.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing compiler runtime delta dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_tls_model_startup_experiment_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-tls-model-startup-experiment-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_standalone_tls_model_startup_experiment"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-source-commit-no-stale-evidence",
            (
                "source_commit_freshness_policy.experiment_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_standalone_tls_model_startup_experiment"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-report-only",
            ("report_policy.report_only", json!(true)),
        ),
        (
            "standalone-tls-model-startup-experiment-no-promotion",
            ("report_policy.promotion_allowed", json!(false)),
        ),
        (
            "standalone-tls-model-startup-experiment-no-replacement-level-change",
            (
                "report_policy.replacement_level_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-no-default-tls-model-change",
            (
                "report_policy.default_tls_model_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-local-exec-failure-policy",
            (
                "report_policy.local_exec_build_failure_result",
                json!("not_viable_for_cdylib_lane"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-claim-status",
            ("summary.claim_status", json!("report_only")),
        ),
        (
            "standalone-tls-model-startup-experiment-standalone-claim-status",
            ("summary.standalone_claim_status", json!("claim_blocked")),
        ),
        (
            "standalone-tls-model-startup-experiment-lane-count",
            ("summary.lane_count", json!(3)),
        ),
        (
            "standalone-tls-model-startup-experiment-build-pass-count",
            ("summary.build_pass_count", json!(1)),
        ),
        (
            "standalone-tls-model-startup-experiment-build-fail-count",
            ("summary.build_fail_count", json!(1)),
        ),
        (
            "standalone-tls-model-startup-experiment-initial-exec-delta",
            (
                "summary.initial_exec_delta_classification",
                json!("unchanged"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-initial-exec-symbol-count",
            ("summary.initial_exec_tls_symbol_count", json!(1)),
        ),
        (
            "standalone-tls-model-startup-experiment-baseline-lane-status",
            ("experiment_lanes.0.claim_status", json!("claim_blocked")),
        ),
        (
            "standalone-tls-model-startup-experiment-initial-exec-lane-status",
            ("experiment_lanes.1.claim_status", json!("report_only")),
        ),
        (
            "standalone-tls-model-startup-experiment-initial-exec-tls-model",
            ("experiment_lanes.1.tls_model", json!("initial-exec")),
        ),
        (
            "standalone-tls-model-startup-experiment-initial-exec-symbol",
            (
                "experiment_lanes.1.undefined_tls_symbols.0",
                json!("__tls_get_addr@GLIBC_2.3"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-local-exec-build-status",
            ("experiment_lanes.2.build_status", json!("fail")),
        ),
        (
            "standalone-tls-model-startup-experiment-local-exec-failure-signature",
            (
                "experiment_lanes.2.failure_signature",
                json!("non_pic_tls_relocation_in_shared_dependency"),
            ),
        ),
        (
            "standalone-tls-model-startup-experiment-local-exec-blocker",
            (
                "experiment_lanes.2.blocking_reasons.0",
                json!("tls_model_not_viable_for_cdylib_workspace"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-tls-model-startup-experiment-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected TLS model startup experiment dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_tls_model_startup_experiment.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing TLS model startup experiment dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_compiler_runtime_blocker_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-compiler-runtime-blocker-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_compiler_runtime_blocker_diagnostics_refresh"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-source-commit-no-diagnostic-evidence",
            (
                "source_commit_freshness_policy.diagnostic_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_compiler_runtime_blocker_diagnostics"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-compiler-runtime-blocker-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected compiler runtime blocker source freshness dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing compiler runtime blocker source freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_compiler_runtime_blocker_diagnostics_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-compiler-runtime-blocker-diagnostics-report-only",
            ("summary.report_only", json!(true)),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-no-promotion",
            ("report_policy.promotion_allowed", json!(false)),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-no-replacement-level-change",
            (
                "report_policy.replacement_level_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-no-default-build-profile-change",
            (
                "report_policy.default_build_profile_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-no-panic-strategy-change",
            ("report_policy.panic_strategy_change_allowed", json!(false)),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-blocker-mapping-count",
            ("summary.blocker_mapping_count", json!(2)),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-libgcc-needed-count",
            ("summary.libgcc_needed_library_count", json!(1)),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-unwind-symbol-count",
            ("summary.undefined_unwind_symbol_count", json!(12)),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-libgcc-version-need-count",
            ("summary.libgcc_version_need_count", json!(3)),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-current-claim-status",
            (
                "current_forge_evidence.latest_probe_claim_status",
                json!("claim_blocked"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-current-artifact-status",
            (
                "current_forge_evidence.latest_probe_artifact_status",
                json!("current"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-current-failure-signature",
            (
                "current_forge_evidence.latest_probe_failure_signature",
                json!("host_glibc_dependency"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-needed-libgcc",
            (
                "current_forge_evidence.evidence_command_results.readelf_dynamic.observed_needed_libraries.0",
                json!("libgcc_s.so.1"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-ldd-libgcc",
            (
                "current_forge_evidence.evidence_command_results.ldd.observed_host_resolved_libraries.2",
                json!("libgcc_s.so.1"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-first-unwind-symbol",
            (
                "current_forge_evidence.evidence_command_results.nm_dynamic.observed_undefined_unwind_symbols.0",
                json!("_Unwind_Backtrace@GCC_3.3"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-first-libgcc-version-requirement",
            (
                "blocker_mappings.0.observed_values.host_version_requirements.0",
                json!("libgcc_s.so.1:GCC_3.0"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-libgcc-blocker-id",
            ("blocker_mappings.0.blocker_id", json!("libgcc-runtime-dependency")),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-libgcc-owner-surface",
            ("blocker_mappings.0.owner_surface", json!("compiler_runtime")),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-libgcc-first-profile-knob",
            ("blocker_mappings.0.profile_knobs.0", json!("panic strategy")),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-unwind-blocker-id",
            ("blocker_mappings.1.blocker_id", json!("undefined-unwind-symbols")),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-unwind-owner-surface",
            ("blocker_mappings.1.owner_surface", json!("unwind_runtime")),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-current-panic-strategy",
            (
                "toolchain_profile.panic_strategy.current",
                json!("implicit-unwind"),
            ),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-baseline-lane-status",
            ("experiment_matrix.0.status", json!("observed_baseline")),
        ),
        (
            "standalone-compiler-runtime-blocker-diagnostics-panic-abort-lane-status",
            ("experiment_matrix.1.status", json!("implemented_report_only")),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-compiler-runtime-blocker-diagnostics-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected compiler runtime blocker diagnostics dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing compiler runtime blocker diagnostics dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_tls_blocker_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-tls-blocker-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-tls-blocker-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-tls-blocker-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_standalone_tls_blocker_diagnostics_refresh"),
            ),
        ),
        (
            "standalone-tls-blocker-source-commit-no-diagnostic-evidence",
            (
                "source_commit_freshness_policy.diagnostic_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-tls-blocker-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_standalone_tls_blocker_diagnostics"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-tls-blocker-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected TLS blocker source freshness dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_tls_blocker_diagnostics.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing TLS blocker source freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_tls_blocker_diagnostics_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-tls-blocker-diagnostics-report-only",
            ("summary.report_only", json!(true)),
        ),
        (
            "standalone-tls-blocker-diagnostics-no-promotion",
            ("report_policy.promotion_allowed", json!(false)),
        ),
        (
            "standalone-tls-blocker-diagnostics-no-replacement-level-change",
            (
                "report_policy.replacement_level_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-no-default-tls-model-change",
            (
                "report_policy.default_tls_model_change_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-symbol-count",
            ("summary.undefined_tls_symbol_count", json!(1)),
        ),
        (
            "standalone-tls-blocker-diagnostics-thread-local-count",
            ("summary.thread_local_macro_count", json!(90)),
        ),
        (
            "standalone-tls-blocker-diagnostics-thread-local-file-count",
            ("summary.thread_local_source_file_count", json!(29)),
        ),
        (
            "standalone-tls-blocker-diagnostics-abi-thread-local-count",
            ("summary.abi_thread_local_macro_count", json!(82)),
        ),
        (
            "standalone-tls-blocker-diagnostics-current-claim-status",
            (
                "current_forge_evidence.latest_probe_claim_status",
                json!("claim_blocked"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-current-artifact-status",
            (
                "current_forge_evidence.latest_probe_artifact_status",
                json!("current"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-current-failure-signature",
            (
                "current_forge_evidence.latest_probe_failure_signature",
                json!("host_glibc_dependency"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-observed-symbol",
            (
                "current_forge_evidence.observed_artifact_symbols.undefined_tls_symbols.0",
                json!("__tls_get_addr@GLIBC_2.3"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-nm-observed-symbol",
            (
                "current_forge_evidence.evidence_command_results.nm_dynamic.observed_undefined_tls_symbols.0",
                json!("__tls_get_addr@GLIBC_2.3"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-readelf-observed-symbol",
            (
                "current_forge_evidence.evidence_command_results.readelf_symbols.observed_undefined_tls_symbols.0",
                json!("__tls_get_addr@GLIBC_2.3"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-version-need",
            (
                "current_forge_evidence.observed_artifact_symbols.host_version_requirements.0",
                json!("ld-linux-x86-64.so.2:GLIBC_2.3"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-scan-total",
            ("source_surface_scan.total_thread_local_macro_count", json!(90)),
        ),
        (
            "standalone-tls-blocker-diagnostics-first-hot-file",
            (
                "source_surface_scan.thread_local_inventory.0.path",
                json!("crates/frankenlibc-abi/src/unistd_abi.rs"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-first-hot-file-count",
            (
                "source_surface_scan.thread_local_inventory.0.thread_local_macro_count",
                json!(25),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-primary-owner-group",
            ("source_owner_groups.0.group_id", json!("primary_errno_tls")),
        ),
        (
            "standalone-tls-blocker-diagnostics-primary-owner-classification",
            (
                "source_owner_groups.0.classification",
                json!("direct_tls_symbol_pressure"),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-negative-control-nm",
            (
                "negative_control_gate.artifact_nm_command",
                json!("nm -D libfrankenlibc_replace.so | rg \"__tls_get_addr(@GLIBC_2.3)?\""),
            ),
        ),
        (
            "standalone-tls-blocker-diagnostics-negative-control-pass-condition",
            (
                "negative_control_gate.future_pass_conditions.1",
                json!("nm -D reports no undefined __tls_get_addr symbol"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-tls-blocker-diagnostics-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected TLS blocker diagnostics dashboard row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_tls_blocker_diagnostics.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing TLS blocker diagnostics dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_smoke_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-smoke-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-smoke-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-smoke-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_standalone_link_run_smoke_evidence"),
            ),
        ),
        (
            "standalone-smoke-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.standalone_smoke_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-smoke-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-smoke-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected standalone smoke row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "smoke",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_link_run_smoke.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing standalone smoke freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn standalone_host_probe_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-host-probe-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "standalone-host-probe-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "standalone-host-probe-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_standalone_host_dependency_probe_evidence"),
            ),
        ),
        (
            "standalone-host-probe-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.host_dependency_probe_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "standalone-host-probe-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-host-probe-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected host probe freshness row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing standalone host probe freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn host_probe_projection_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-host-probe-projection-decision-diagnostic",
            "current_forge_blocker_projection.decision",
            json!("projection_only_claims_remain_blocked"),
        ),
        (
            "standalone-host-probe-projection-field-count-diagnostic",
            "summary.forge_projection_field_count",
            json!(19),
        ),
        (
            "standalone-host-probe-projection-blocking-reason-count-diagnostic",
            "summary.forge_projection_blocking_reason_count",
            json!(10),
        ),
        (
            "standalone-host-probe-projection-blocker-catalog-count-diagnostic",
            "summary.forge_projection_blocker_catalog_row_count",
            json!(10),
        ),
        (
            "standalone-host-probe-projection-failure-signature-count-diagnostic",
            "summary.forge_projection_failure_signature_count",
            json!(6),
        ),
    ]
    .into_iter()
    .map(|(row_id, field, expected_value)| (row_id, (field, expected_value)))
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-host-probe-projection-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected host probe projection row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing standalone host probe projection dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn host_probe_snapshot_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "standalone-host-probe-snapshot-decision-diagnostic",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.decision",
                json!("snapshot_only_claims_remain_blocked"),
            ),
        ),
        (
            "standalone-host-probe-snapshot-no-promotion",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.snapshot_policy.promotion_allowed",
                json!(false),
            ),
        ),
        (
            "standalone-host-probe-snapshot-refresh-required",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.snapshot_policy.refresh_required_on_blocker_delta",
                json!(true),
            ),
        ),
        (
            "standalone-host-probe-snapshot-stale-result",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.snapshot_policy.stale_result",
                json!("block_standalone_host_dependency_probe_evidence"),
            ),
        ),
        (
            "standalone-host-probe-snapshot-rejection-kind",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.snapshot_policy.rejected_evidence_kind",
                json!("stale_forge_blocker_snapshot"),
            ),
        ),
        (
            "standalone-host-probe-snapshot-blocking-reason-count",
            ("summary.forge_blocker_snapshot_blocking_reason_count", json!(10)),
        ),
        (
            "standalone-host-probe-snapshot-needed-library-count",
            ("summary.forge_blocker_snapshot_needed_library_count", json!(2)),
        ),
        (
            "standalone-host-probe-snapshot-needed-library-values",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.needed_libraries",
                json!(["ld-linux-x86-64.so.2", "libgcc_s.so.1"]),
            ),
        ),
        (
            "standalone-host-probe-snapshot-host-resolved-library-count",
            (
                "summary.forge_blocker_snapshot_host_resolved_library_count",
                json!(3),
            ),
        ),
        (
            "standalone-host-probe-snapshot-host-resolved-library-values",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.host_resolved_libraries",
                json!(["/lib64/ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"]),
            ),
        ),
        (
            "standalone-host-probe-snapshot-undefined-unwind-symbol-values",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.undefined_unwind_symbols",
                json!([
                    "_Unwind_Backtrace@GCC_3.3",
                    "_Unwind_DeleteException@GCC_3.0",
                    "_Unwind_GetDataRelBase@GCC_3.0",
                    "_Unwind_GetIP@GCC_3.0",
                    "_Unwind_GetIPInfo@GCC_4.2.0",
                    "_Unwind_GetLanguageSpecificData@GCC_3.0",
                    "_Unwind_GetRegionStart@GCC_3.0",
                    "_Unwind_GetTextRelBase@GCC_3.0",
                    "_Unwind_RaiseException@GCC_3.0",
                    "_Unwind_Resume@GCC_3.0",
                    "_Unwind_SetGR@GCC_3.0",
                    "_Unwind_SetIP@GCC_3.0",
                ]),
            ),
        ),
        (
            "standalone-host-probe-snapshot-undefined-glibc-symbol-values",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.undefined_glibc_symbols",
                json!(["__tls_get_addr@GLIBC_2.3"]),
            ),
        ),
        (
            "standalone-host-probe-snapshot-undefined-tls-symbol-values",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.undefined_tls_symbols",
                json!(["__tls_get_addr@GLIBC_2.3"]),
            ),
        ),
        (
            "standalone-host-probe-snapshot-undefined-symbol-count",
            ("summary.forge_blocker_snapshot_undefined_symbol_count", json!(14)),
        ),
        (
            "standalone-host-probe-snapshot-host-version-requirement-count",
            (
                "summary.forge_blocker_snapshot_host_version_requirement_count",
                json!(4),
            ),
        ),
        (
            "standalone-host-probe-snapshot-host-version-requirement-values",
            (
                "current_forge_blocker_projection.current_forge_blocker_value_snapshot.host_version_requirements",
                json!([
                    "ld-linux-x86-64.so.2:GLIBC_2.3",
                    "libgcc_s.so.1:GCC_3.0",
                    "libgcc_s.so.1:GCC_3.3",
                    "libgcc_s.so.1:GCC_4.2.0",
                ]),
            ),
        ),
        (
            "standalone-host-probe-snapshot-version-need-provider-count",
            (
                "summary.forge_blocker_snapshot_version_need_provider_count",
                json!(2),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("standalone-host-probe-snapshot-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected host probe snapshot row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "forge",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing standalone host probe snapshot dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn crt_tls_atexit_direct_link_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "crt-tls-atexit-direct-link-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "crt-tls-atexit-direct-link-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "crt-tls-atexit-direct-link-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_crt_tls_atexit_direct_link_proof_evidence"),
            ),
        ),
        (
            "crt-tls-atexit-direct-link-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.direct_link_proof_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "crt-tls-atexit-direct-link-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("crt-tls-atexit-direct-link-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected CRT/TLS/atexit direct-link freshness row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "direct_link",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/crt_tls_atexit_direct_link_run_proof_fixtures.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing CRT/TLS/atexit direct-link freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn real_program_smoke_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "real-program-smoke-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "real-program-smoke-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "real-program-smoke-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_real_program_smoke_evidence"),
            ),
        ),
        (
            "real-program-smoke-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.real_program_smoke_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "real-program-smoke-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("real-program-smoke-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected real-program smoke row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "real_program",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/real_program_smoke_suite.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing real-program smoke freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn dlfcn_sentinel_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "dlfcn-sentinel-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "dlfcn-sentinel-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "dlfcn-sentinel-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_dlfcn_replace_boundary_sentinel"),
            ),
        ),
        (
            "dlfcn-sentinel-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.sentinel_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "dlfcn-sentinel-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("dlfcn-sentinel-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected dlfcn sentinel row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "dlfcn",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/dlfcn_replace_boundary_sentinel.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing dlfcn sentinel freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn dlfcn_l1_burndown_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "dlfcn-l1-burndown-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "dlfcn-l1-burndown-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "dlfcn-l1-burndown-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_l1_burndown_classification"),
            ),
        ),
        (
            "dlfcn-l1-burndown-source-commit-no-classification",
            (
                "source_commit_freshness_policy.classification_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "dlfcn-l1-burndown-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("dlfcn-l1-burndown-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected dlfcn burndown row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "dlfcn",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/dlfcn_replace_boundary_l1_burndown.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing dlfcn L1 burndown freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn perf_waiver_audit_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "perf-waiver-audit-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "perf-waiver-audit-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "perf-waiver-audit-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_perf_waiver_audit"),
            ),
        ),
        (
            "perf-waiver-audit-source-commit-no-waiver-audit",
            (
                "source_commit_freshness_policy.waiver_audit_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "perf-waiver-audit-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("perf-waiver-audit-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected perf waiver audit row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "perf",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/perf_waiver_audit.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing perf waiver audit freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn perf_regression_prevention_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "perf-regression-prevention-no-issues",
            ("summary.total_issues", json!(0)),
        ),
        (
            "perf-regression-prevention-total-warnings",
            ("summary.total_warnings", json!(0)),
        ),
        (
            "perf-regression-prevention-baseline-slot-fill",
            ("summary.baseline_slot_fill_pct", json!(100.0)),
        ),
        (
            "perf-regression-prevention-hotpath-coverage",
            ("summary.hotpath_symbol_coverage_pct", json!(59.9)),
        ),
        (
            "perf-regression-prevention-gate-exists",
            ("gate_wiring.exists", json!(true)),
        ),
        (
            "perf-regression-prevention-event-logging",
            ("gate_wiring.features.event_logging", json!(true)),
        ),
        (
            "perf-regression-prevention-injection-support",
            ("gate_wiring.features.injection_support", json!(true)),
        ),
        (
            "perf-regression-prevention-not-covered-count",
            ("hotpath_symbol_coverage.not_covered", json!(61)),
        ),
        (
            "perf-regression-prevention-first-uncovered-module",
            (
                "hotpath_symbol_coverage.uncovered_modules.0",
                json!("c11threads_abi"),
            ),
        ),
        (
            "perf-regression-prevention-regression-threshold",
            ("config_consistency.regression_max_pct", json!(15)),
        ),
        (
            "perf-regression-prevention-active-waivers",
            ("config_consistency.active_waivers", json!(1)),
        ),
        (
            "perf-regression-prevention-expired-waivers",
            ("config_consistency.expired_waivers", json!(0)),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("perf-regression-prevention-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!(
                "unexpected perf regression prevention row: {row_id}"
            ))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "perf",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/perf_regression_prevention.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing perf regression prevention dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn perf_baseline_spec_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "perf-baseline-spec-total-suites",
            ("summary.total_suites", json!(5)),
        ),
        (
            "perf-baseline-spec-total-benchmarks",
            ("summary.total_benchmarks", json!(25)),
        ),
        (
            "perf-baseline-spec-enforced-suites",
            ("summary.enforced_suites", json!(3)),
        ),
        (
            "perf-baseline-spec-primary-gate-metric",
            ("percentile_targets.primary_gate_metric", json!("p50")),
        ),
        (
            "perf-baseline-spec-baseline-file",
            ("baseline_format.file", json!("scripts/perf_baseline.json")),
        ),
        (
            "perf-baseline-spec-max-cv",
            ("regeneration.validation.max_cv_pct", json!(15)),
        ),
        (
            "perf-baseline-spec-regression-threshold",
            ("regression_detection.max_regression_pct", json!(15)),
        ),
        (
            "perf-baseline-spec-profile-required-files",
            ("summary.profile_required_files", json!(6)),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("perf-baseline-spec-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected perf baseline spec row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "perf",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/perf_baseline_spec.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing perf baseline spec dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn perf_budget_policy_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "perf-budget-policy-strict-hotpath-strict-ns",
            ("budgets.strict_hotpath.strict_mode_ns", json!(20)),
        ),
        (
            "perf-budget-policy-strict-hotpath-hardened-ns",
            ("budgets.strict_hotpath.hardened_mode_ns", json!(200)),
        ),
        (
            "perf-budget-policy-repeat-runs",
            ("variance_guardrails.min_repeat_runs", json!(3)),
        ),
        (
            "perf-budget-policy-max-cv",
            (
                "variance_guardrails.max_coefficient_of_variation_pct",
                json!(15),
            ),
        ),
        (
            "perf-budget-policy-regression-threshold",
            ("regression_policy.max_regression_pct", json!(15)),
        ),
        (
            "perf-budget-policy-current-proof-required",
            (
                "workload_budget_extension.performance_claims_require_current_behavior_proof",
                json!(true),
            ),
        ),
        (
            "perf-budget-policy-user-workload-decision",
            (
                "workload_performance_budgets.0.decision",
                json!("claim_blocked"),
            ),
        ),
        (
            "perf-budget-policy-membrane-failure-signature",
            (
                "workload_performance_budgets.1.failure_signature",
                json!("membrane_perf_missing_current_baseline"),
            ),
        ),
        (
            "perf-budget-policy-microbench-only-blocks-claim",
            (
                "performance_claim_blocking_tests.2.failure_signature",
                json!("perf_claim_microbench_only"),
            ),
        ),
        (
            "perf-budget-policy-active-waiver-expiry",
            ("active_waivers.0.expires_at", json!("2026-05-11")),
        ),
        (
            "perf-budget-policy-first-unbenched-module",
            (
                "current_assessment.benchmark_coverage.not_yet_benched.0",
                json!("ctype_abi"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("perf-budget-policy-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected perf budget policy row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "perf",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/perf_budget_policy.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing perf budget policy dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn runtime_replay_source_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "runtime-replay-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "runtime-replay-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "runtime-replay-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_runtime_evidence_replay_gate"),
            ),
        ),
        (
            "runtime-replay-source-commit-no-evidence",
            (
                "source_commit_freshness_policy.runtime_replay_evidence_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "runtime-replay-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("runtime-replay-source-commit-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected runtime replay row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "runtime_evidence",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/runtime_evidence_replay_gate.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing runtime replay freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn every_input_source_commit_freshness_policy_is_exposed() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let rows = as_array(&dashboard["rows"], "rows")?;
    let inputs = dashboard["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for (input_key, input_path_value) in inputs {
        let input_path = as_str(input_path_value, "inputs value")?;
        let artifact = load_json(&workspace_root().join(input_path))?;
        let Some(policy) = artifact.get("source_commit_freshness_policy") else {
            continue;
        };
        let policy_fields = policy
            .as_object()
            .ok_or_else(|| {
                test_error(format!(
                    "{input_key} source_commit_freshness_policy must be an object"
                ))
            })?
            .keys()
            .map(|key| format!("source_commit_freshness_policy.{key}"))
            .collect::<BTreeSet<_>>();
        ensure(
            !policy_fields.is_empty(),
            format!("{input_key} source_commit_freshness_policy must not be empty"),
        )?;
        let freshness_rows = rows
            .iter()
            .filter(|row| row["evidence_artifact"].as_str() == Some(input_path))
            .filter(|row| {
                row["field"]
                    .as_str()
                    .is_some_and(|field| field.starts_with("source_commit_freshness_policy."))
            })
            .collect::<Vec<_>>();
        ensure_eq(
            freshness_rows.len(),
            policy_fields.len(),
            format!("{input_key} dashboard source freshness row count"),
        )?;
        let exposed_fields = freshness_rows
            .iter()
            .map(|row| as_str(&row["field"], "row.field").map(str::to_owned))
            .collect::<Result<BTreeSet<_>, _>>()?;
        ensure_eq(
            exposed_fields,
            policy_fields,
            format!("{input_key} dashboard source freshness fields"),
        )?;
    }
    Ok(())
}

#[test]
fn every_declared_input_has_dashboard_rows() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let rows = as_array(&dashboard["rows"], "rows")?;
    let inputs = dashboard["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for (input_key, input_path_value) in inputs {
        let input_path = as_str(input_path_value, "inputs value")?;
        ensure(
            rows.iter()
                .any(|row| row["evidence_artifact"].as_str() == Some(input_path)),
            format!("{input_key} input {input_path} has no dashboard rows"),
        )?;
    }
    Ok(())
}

#[test]
fn source_commit_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "l1-dashboard-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "l1-dashboard-source-commit-current-head-check",
            (
                "source_commit_freshness_policy.current_head_check",
                json!("git rev-parse HEAD"),
            ),
        ),
        (
            "l1-dashboard-source-commit-fresh-result",
            (
                "source_commit_freshness_policy.fresh_result",
                json!("eligible_for_row_evaluation_only"),
            ),
        ),
        (
            "l1-dashboard-stale-source-commit-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("report_blockers_no_auto_promotion"),
            ),
        ),
        (
            "l1-dashboard-stale-source-commit-no-promotion",
            (
                "source_commit_freshness_policy.promotion_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "l1-dashboard-stale-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("l1-dashboard-source-commit-")
            && !row_id.starts_with("l1-dashboard-stale-source-commit-")
        {
            continue;
        }
        let (expected_field, expected_value) = expected_rows.remove(row_id).ok_or_else(|| {
            test_error(format!("unexpected source commit freshness row: {row_id}"))
        })?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "gate_meta",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/l1_dry_run_readiness_dashboard.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing source commit freshness dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
}

#[test]
fn l1_promotion_gate_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
        (
            "l1-promotion-gate-pinned",
            (
                "policy.default_decision",
                json!("block_until_l1_evidence_current"),
            ),
        ),
        (
            "l1-promotion-gate-source-commit-field",
            (
                "source_commit_freshness_policy.recorded_source_commit_field",
                json!("source_commit"),
            ),
        ),
        (
            "l1-promotion-gate-source-commit-comparison-target",
            (
                "source_commit_freshness_policy.comparison_target",
                json!("current git HEAD"),
            ),
        ),
        (
            "l1-promotion-gate-source-commit-stale-result",
            (
                "source_commit_freshness_policy.stale_result",
                json!("block_l1_promotion"),
            ),
        ),
        (
            "l1-promotion-gate-source-commit-no-promotion",
            (
                "source_commit_freshness_policy.promotion_allowed_when_stale",
                json!(false),
            ),
        ),
        (
            "l1-promotion-gate-source-commit-rejection-kind",
            (
                "source_commit_freshness_policy.rejected_evidence_kind",
                json!("stale_source_commit"),
            ),
        ),
    ]
    .into_iter()
    .collect();
    for row in as_array(&dashboard["rows"], "rows")? {
        let row_id = as_str(&row["row_id"], "row.row_id")?;
        if !row_id.starts_with("l1-promotion-gate-") {
            continue;
        }
        let (expected_field, expected_value) = expected_rows
            .remove(row_id)
            .ok_or_else(|| test_error(format!("unexpected L1 promotion gate row: {row_id}")))?;
        ensure_eq(
            as_str(&row["row_kind"], "row.row_kind")?,
            "gate_meta",
            format!("row {row_id}: row_kind"),
        )?;
        ensure_eq(
            as_str(&row["evidence_artifact"], "row.evidence_artifact")?,
            "tests/conformance/l1_promotion_gate.v1.json",
            format!("row {row_id}: evidence_artifact"),
        )?;
        ensure_eq(
            as_str(&row["field"], "row.field")?,
            expected_field,
            format!("row {row_id}: field"),
        )?;
        ensure_eq(
            &row["expected_value"],
            &expected_value,
            format!("row {row_id}: expected_value"),
        )?;
    }
    ensure(
        expected_rows.is_empty(),
        format!(
            "missing L1 promotion gate dashboard rows: {:?}",
            expected_rows.keys().collect::<Vec<_>>()
        ),
    )
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
