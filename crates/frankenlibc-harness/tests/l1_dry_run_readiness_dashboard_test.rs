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
        !head.is_empty(),
        "git rev-parse HEAD returned an empty commit",
    )?;
    Ok(head)
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
    ensure(!source_commit.is_empty(), "source_commit must be set")?;
    ensure(
        source_commit.len() == 40 && source_commit.chars().all(|ch| ch.is_ascii_hexdigit()),
        "source_commit must be a full hex git commit",
    )?;
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
    if source_commit != current_head {
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
fn source_commit_freshness_rows_are_explicit() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let mut expected_rows: BTreeMap<&str, (&str, Value)> = [
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
        if row_id != "l1-dashboard-source-commit-fresh-result"
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
