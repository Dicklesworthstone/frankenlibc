//! Conformance migration ledger gate for the fixture expected_output
//! schema policy (bd-0agsk.5 / completion-debt bd-0agsk.5.1).
//!
//! Pins, at conformance level, that:
//! 1. The current policy manifest's `schema_version` matches the
//!    version pinned in the migration ledger. A drift (e.g. someone
//!    bumps the upstream manifest to v2 without adding a paired
//!    migration entry) fails this gate.
//! 2. The primary conformance test file referenced by the migration
//!    ledger exists and contains every named test function.
//! 3. The migration ledger's invariants for any future v2 ratchet are
//!    pinned (canonical_policy.id, primary_adapter_source, adapter
//!    function set, expectation_tag_precedence preservation).

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

fn migration_manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("fixture_expected_output_schema_policy_migration.v1.json")
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
fn migration_manifest_anchors_to_0agsk_5_with_completion_debt_bead() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&migration_manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "fixture-expected-output-schema-policy-migration",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-0agsk.5", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-0agsk.5.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "current_policy_manifest_path")?
            == "tests/conformance/fixture_expected_output_schema_policy.v1.json",
        "current_policy_manifest_path",
    )?;
    require(
        json_string(&m, "primary_conformance_test_file")?
            == "crates/frankenlibc-harness/tests/fixture_expected_output_schema_policy_test.rs",
        "primary_conformance_test_file",
    )
}

#[test]
fn migration_manifest_audit_reference_pins_pre_repair_score() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&migration_manifest_path(&root))?;
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
    for k in ["tests.conformance.primary", "migrations.primary"] {
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
fn migration_manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&migration_manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "fail_closed_when_upstream_schema_version_drifts",
        "fail_closed_when_primary_conformance_test_file_missing",
        "fail_closed_when_canonical_policy_id_changes_silently",
        "fail_closed_when_adapter_functions_shrink",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn current_pinned_version_matches_upstream_policy_manifest_schema_version() -> TestResult {
    let root = workspace_root()?;
    let migration = load_json(&migration_manifest_path(&root))?;
    let upstream_path = root
        .join("tests")
        .join("conformance")
        .join("fixture_expected_output_schema_policy.v1.json");
    let upstream = load_json(&upstream_path)?;
    let pinned = json_string(&migration, "current_schema_version")?;
    let actual = json_string(&upstream, "schema_version")?;
    require(
        pinned == actual,
        format!(
            "schema_version drift: migration ledger pins `{pinned}` but upstream manifest reports `{actual}` — bump the migration_history before changing the upstream version"
        ),
    )
}

#[test]
fn upstream_policy_manifest_preserves_v1_invariants() -> TestResult {
    let root = workspace_root()?;
    let upstream_path = root
        .join("tests")
        .join("conformance")
        .join("fixture_expected_output_schema_policy.v1.json");
    let upstream = load_json(&upstream_path)?;
    let policy = upstream
        .get("canonical_policy")
        .ok_or_else(|| "upstream missing canonical_policy".to_string())?;
    require(
        json_string(policy, "id")? == "adapter_normalized_tagged_values",
        "canonical_policy.id must remain adapter_normalized_tagged_values",
    )?;
    require(
        json_string(policy, "primary_adapter_source")?
            == "crates/frankenlibc-harness/src/fixtures.rs",
        "primary_adapter_source must remain crates/frankenlibc-harness/src/fixtures.rs",
    )?;
    let adapters: Vec<&str> = json_array(policy, "adapter_functions")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for required in [
        "expected_output_from_raw_case",
        "normalize_expected_output_value",
        "format_return_and_values",
    ] {
        require(
            adapters.contains(&required),
            format!("adapter_functions list shrunk: required `{required}` missing"),
        )?;
    }
    Ok(())
}

#[test]
fn primary_conformance_test_file_exists_and_carries_named_tests() -> TestResult {
    let root = workspace_root()?;
    let migration = load_json(&migration_manifest_path(&root))?;
    let rel = json_string(&migration, "primary_conformance_test_file")?;
    let test_path = root.join(rel);
    let src = std::fs::read_to_string(&test_path)
        .map_err(|e| format!("primary_conformance_test_file {test_path:?} not readable: {e}"))?;
    let names: Vec<&str> = json_array(&migration, "primary_conformance_test_functions")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for n in names {
        let anchor = format!("fn {n}(");
        require(
            src.contains(&anchor),
            format!("primary conformance test file missing function `{anchor}`"),
        )?;
    }
    Ok(())
}

#[test]
fn migration_history_ledger_has_v1_entry() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&migration_manifest_path(&root))?;
    let history = json_array(&m, "migration_history")?;
    require(
        !history.is_empty(),
        "migration_history must record at least the v1 introduction",
    )?;
    let v1 = history
        .iter()
        .find(|e| {
            e.get("version").and_then(Value::as_str)
                == Some("fixture_expected_output_schema_policy.v1")
        })
        .ok_or_else(|| "migration_history missing v1 entry".to_string())?;
    require(
        v1.get("introduced_at_commit")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "v1 migration_history.introduced_at_commit must be non-empty",
    )?;
    require(
        v1.get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "v1 migration_history.summary must be non-empty",
    )
}
