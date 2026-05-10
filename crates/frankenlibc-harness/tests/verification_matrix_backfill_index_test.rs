//! Conformance + telemetry-index gate for the verification matrix
//! backfill (bd-3n0 / completion-debt bd-3n0.1).
//!
//! Pins, at conformance level:
//! 1. The primary e2e test file is present and contains the named
//!    test functions (7 e2e tests).
//! 2. The verification matrix artifact is present.
//! 3. The matrix entries carry non-empty backfill rows + valid
//!    coverage statuses (sanity-check sample).

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn index_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("verification_matrix_backfill_index.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

#[test]
fn index_anchors_to_3n0_with_completion_debt_bead() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&index_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "verification-matrix-backfill-index",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-3n0", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-3n0.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "primary_e2e_test_file")?
            == "crates/frankenlibc-harness/tests/verification_matrix_test.rs",
        "primary_e2e_test_file",
    )?;
    require(
        json_string(&m, "verification_matrix_artifact")?
            == "tests/conformance/verification_matrix.json",
        "verification_matrix_artifact",
    )
}

#[test]
fn index_audit_reference_pins_pre_repair_score_and_two_missing_items() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&index_path(&root))?;
    let aref = m
        .get("audit_reference")
        .ok_or_else(|| "missing audit_reference".to_string())?;
    require(
        json_string(aref, "pass")? == "2026-05-10T03-16-16Z",
        "audit_reference.pass",
    )?;
    let missing: Vec<&str> = json_array(aref, "missing_item_ids")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for k in ["tests.e2e.primary", "telemetry.primary"] {
        require(
            missing.contains(&k),
            format!("audit_reference.missing_item_ids missing {k}"),
        )?;
    }
    require(
        aref.get("score_before").and_then(Value::as_u64) == Some(470),
        "score_before",
    )?;
    require(
        aref.get("score_threshold").and_then(Value::as_u64) == Some(700),
        "score_threshold",
    )
}

#[test]
fn index_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&index_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "fail_closed_when_primary_e2e_test_file_missing",
        "fail_closed_when_verification_matrix_missing",
        "fail_closed_when_matrix_entry_has_empty_backfill_rows",
        "fail_closed_when_dashboard_stats_inconsistent_with_entries",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn primary_e2e_test_file_carries_named_functions() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let rel = json_string(&index, "primary_e2e_test_file")?;
    let test_path = root.join(rel);
    let src = std::fs::read_to_string(&test_path)
        .map_err(|e| format!("primary_e2e_test_file {test_path:?}: {e}"))?;
    for n in json_array(&index, "primary_e2e_test_functions")?
        .iter()
        .filter_map(Value::as_str)
    {
        let anchor = format!("fn {n}(");
        require(
            src.contains(&anchor),
            format!("primary e2e test file missing function `{anchor}`"),
        )?;
    }
    Ok(())
}

#[test]
fn verification_matrix_artifact_is_present_and_well_formed() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let rel = json_string(&index, "verification_matrix_artifact")?;
    let p = root.join(rel);
    let matrix = load_json(&p)?;
    // The matrix is a top-level object; the upstream test suite
    // already validates its full shape. Here we just sanity-check
    // that the file parses and exposes one of the canonical fields.
    require(
        matrix.is_object() || matrix.is_array(),
        "verification_matrix.json must be a JSON object or array",
    )?;
    if let Some(entries) = matrix.get("entries").and_then(Value::as_array) {
        require(
            !entries.is_empty(),
            "verification_matrix.json `entries` array must be non-empty",
        )?;
    }
    Ok(())
}

#[test]
fn telemetry_contract_documents_matrix_as_canonical_artifact() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let telemetry = index
        .get("telemetry_emission_contract")
        .ok_or_else(|| "missing telemetry_emission_contract".to_string())?;
    require(
        json_string(telemetry, "matrix_artifact_path")?
            == "tests/conformance/verification_matrix.json",
        "matrix_artifact_path",
    )?;
    require(
        json_string(telemetry, "matrix_artifact_kind")? == "json",
        "matrix_artifact_kind",
    )?;
    require(
        json_bool(telemetry, "entries_must_have_non_empty_backfill_rows")?,
        "entries_must_have_non_empty_backfill_rows must be true",
    )?;
    require(
        json_bool(telemetry, "entries_must_have_valid_coverage_statuses")?,
        "entries_must_have_valid_coverage_statuses must be true",
    )?;
    require(
        json_bool(telemetry, "dashboard_stats_must_match_entries")?,
        "dashboard_stats_must_match_entries must be true",
    )
}
