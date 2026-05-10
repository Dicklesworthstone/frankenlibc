//! Conformance + telemetry-index gate for the full fixture schema
//! validation gate (bd-0agsk.6 / completion-debt bd-0agsk.6.1).
//!
//! Pins, at conformance level:
//! 1. The upstream gate manifest still exists at the named path and
//!    carries the pinned schema_version.
//! 2. The primary conformance test file is present and contains all
//!    6 named test functions.
//! 3. The check script is present and executable.
//! 4. The telemetry report path the upstream gate emits to is
//!    pinned by the index manifest — drift fails this gate.

use std::os::unix::fs::PermissionsExt;
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

fn telemetry_index_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("fixture_schema_validation_telemetry_index.v1.json")
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
fn telemetry_index_anchors_to_0agsk_6_with_completion_debt_bead() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&telemetry_index_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "fixture-schema-validation-telemetry-index",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-0agsk.6", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-0agsk.6.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "upstream_gate_manifest")?
            == "tests/conformance/fixture_schema_validation.v1.json",
        "upstream_gate_manifest",
    )?;
    require(
        json_string(&m, "primary_conformance_test_file")?
            == "crates/frankenlibc-harness/tests/fixture_schema_validation_test.rs",
        "primary_conformance_test_file",
    )?;
    require(
        json_string(&m, "upstream_gate_check_script")?
            == "scripts/check_fixture_schema_validation.sh",
        "upstream_gate_check_script",
    )
}

#[test]
fn telemetry_index_audit_reference_pins_pre_repair_score() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&telemetry_index_path(&root))?;
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
    for k in ["tests.conformance.primary", "telemetry.primary"] {
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
fn telemetry_index_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&telemetry_index_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "fail_closed_when_upstream_gate_manifest_missing",
        "fail_closed_when_primary_conformance_test_file_missing",
        "fail_closed_when_check_script_missing",
        "fail_closed_when_check_script_not_executable",
        "fail_closed_when_telemetry_report_path_drifts",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn upstream_gate_manifest_exists_with_pinned_schema_version() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&telemetry_index_path(&root))?;
    let upstream_rel = json_string(&index, "upstream_gate_manifest")?;
    let upstream_path = root.join(upstream_rel);
    let upstream = load_json(&upstream_path)?;
    let pinned = json_string(&index, "upstream_gate_schema_version")?;
    let actual = json_string(&upstream, "schema_version")?;
    require(
        pinned == actual,
        format!(
            "upstream gate schema_version drift: index pins `{pinned}` but upstream reports `{actual}`"
        ),
    )?;
    require(
        json_string(&upstream, "canonical_command")?
            == json_string(&index, "upstream_gate_canonical_command")?,
        "canonical_command drift",
    )
}

#[test]
fn primary_conformance_test_file_exists_with_named_tests() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&telemetry_index_path(&root))?;
    let rel = json_string(&index, "primary_conformance_test_file")?;
    let test_path = root.join(rel);
    let src = std::fs::read_to_string(&test_path)
        .map_err(|e| format!("primary_conformance_test_file {test_path:?}: {e}"))?;
    let names: Vec<&str> = json_array(&index, "primary_conformance_test_functions")?
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
fn check_script_is_present_and_executable() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&telemetry_index_path(&root))?;
    let rel = json_string(&index, "upstream_gate_check_script")?;
    let script_path = root.join(rel);
    let metadata = std::fs::metadata(&script_path)
        .map_err(|e| format!("upstream_gate_check_script {script_path:?}: {e}"))?;
    let mode = metadata.permissions().mode();
    require(
        mode & 0o111 != 0,
        format!(
            "{script_path:?} is not executable (mode {mode:o}); the canonical_command would fail"
        ),
    )
}

#[test]
fn telemetry_report_path_matches_upstream_gate_canonical_command() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&telemetry_index_path(&root))?;
    let telemetry = index
        .get("telemetry_emission_contract")
        .ok_or_else(|| "missing telemetry_emission_contract".to_string())?;
    let report_path = json_string(telemetry, "report_artifact_path")?;
    require(
        report_path == "target/conformance/fixture_schema_validation.report.json",
        format!("telemetry_emission_contract.report_artifact_path drifted: {report_path}"),
    )?;
    require(
        json_string(telemetry, "report_artifact_kind")? == "json",
        "report_artifact_kind must be json",
    )?;
    require(
        json_string(telemetry, "report_emission_command")?
            == json_string(&index, "upstream_gate_canonical_command")?,
        "report_emission_command must equal upstream_gate_canonical_command",
    )
}
