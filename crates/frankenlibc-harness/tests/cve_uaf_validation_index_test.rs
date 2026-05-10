//! Conformance + telemetry-index gate for the CVE use-after-free
//! validation gate (bd-1m5.3 / completion-debt bd-1m5.3.1).
//!
//! Pins, at conformance level:
//! 1. Primary unit + e2e test file present with named test functions.
//! 2. Python generator script present + executable.
//! 3. Telemetry report path stable AND, when present on disk, carries
//!    the required schema fields including BOTH UAF patterns
//!    (use_after_free + double_free).

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

fn index_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("cve_uaf_validation_index.v1.json")
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
fn index_anchors_to_1m5_3_with_completion_debt_bead() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&index_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "cve-uaf-validation-index",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-1m5.3", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-1m5.3.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "primary_unit_test_file")?
            == "crates/frankenlibc-harness/tests/cve_uaf_validation_test.rs",
        "primary_unit_test_file",
    )?;
    require(
        json_string(&m, "primary_e2e_test_function")? == "uaf_report_generates_successfully",
        "primary_e2e_test_function",
    )?;
    require(
        json_string(&m, "e2e_evidence_generator_script")?
            == "scripts/generate_cve_uaf_validation.py",
        "e2e_evidence_generator_script",
    )
}

#[test]
fn index_audit_reference_pins_pre_repair_score_and_three_missing_items() -> TestResult {
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
    for k in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
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
        "fail_closed_when_primary_unit_test_file_missing",
        "fail_closed_when_primary_e2e_test_file_missing",
        "fail_closed_when_e2e_generator_script_missing",
        "fail_closed_when_telemetry_report_path_drifts",
        "fail_closed_when_required_summary_field_missing_from_emitted_report",
        "fail_closed_when_required_uaf_pattern_missing_from_emitted_report",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn primary_unit_test_file_exists_with_named_unit_tests() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let rel = json_string(&index, "primary_unit_test_file")?;
    let test_path = root.join(rel);
    let src = std::fs::read_to_string(&test_path)
        .map_err(|e| format!("primary_unit_test_file {test_path:?}: {e}"))?;
    let names: Vec<&str> = json_array(&index, "primary_unit_test_functions")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for n in names {
        let anchor = format!("fn {n}(");
        require(
            src.contains(&anchor),
            format!("primary unit test file missing function `{anchor}`"),
        )?;
    }
    Ok(())
}

#[test]
fn primary_e2e_test_function_exists_in_test_file() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let rel = json_string(&index, "primary_e2e_test_file")?;
    let src = std::fs::read_to_string(root.join(rel))
        .map_err(|e| format!("primary_e2e_test_file: {e}"))?;
    let name = json_string(&index, "primary_e2e_test_function")?;
    let anchor = format!("fn {name}(");
    require(
        src.contains(&anchor),
        format!("primary e2e test function missing: `{anchor}`"),
    )?;
    let script = json_string(&index, "e2e_evidence_generator_script")?;
    require(
        src.contains(script),
        format!("e2e test must reference generator script `{script}`"),
    )
}

#[test]
fn e2e_generator_script_is_present_and_executable() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let rel = json_string(&index, "e2e_evidence_generator_script")?;
    let script_path = root.join(rel);
    let metadata = std::fs::metadata(&script_path)
        .map_err(|e| format!("e2e_evidence_generator_script {script_path:?}: {e}"))?;
    let mode = metadata.permissions().mode();
    require(
        mode & 0o111 != 0,
        format!("{script_path:?} is not executable (mode {mode:o})"),
    )
}

#[test]
fn telemetry_report_path_pinned_to_canonical_location() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let telemetry = index
        .get("telemetry_emission_contract")
        .ok_or_else(|| "missing telemetry_emission_contract".to_string())?;
    require(
        json_string(telemetry, "report_artifact_path")?
            == "tests/cve_arena/results/uaf_validation.v1.json",
        "report_artifact_path drift",
    )?;
    require(
        json_string(telemetry, "report_artifact_kind")? == "json",
        "report_artifact_kind",
    )?;
    let summary_required: Vec<&str> = json_array(telemetry, "required_summary_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for f in [
        "total_uaf_tests",
        "manifests_valid",
        "unique_healing_actions",
        "uaf_patterns_covered",
    ] {
        require(
            summary_required.contains(&f),
            format!("telemetry_emission_contract.required_summary_fields missing `{f}`"),
        )?;
    }
    let patterns: Vec<&str> = json_array(telemetry, "required_uaf_patterns")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for p in ["use_after_free", "double_free"] {
        require(
            patterns.contains(&p),
            format!("required_uaf_patterns missing `{p}`"),
        )?;
    }
    Ok(())
}

#[test]
fn telemetry_report_carries_required_fields_and_uaf_patterns_when_present_on_disk() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let telemetry = index
        .get("telemetry_emission_contract")
        .ok_or_else(|| "missing telemetry_emission_contract".to_string())?;
    let report_rel = json_string(telemetry, "report_artifact_path")?;
    let report_path = root.join(report_rel);
    if !report_path.exists() {
        return Ok(());
    }
    let report = load_json(&report_path)?;
    let top_required: Vec<&str> = json_array(telemetry, "required_top_level_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for f in top_required {
        require(
            report.get(f).is_some(),
            format!("telemetry report missing required top-level field `{f}`"),
        )?;
    }
    let summary = report
        .get("summary")
        .ok_or_else(|| "telemetry report missing `summary` object".to_string())?;
    let summary_required: Vec<&str> = json_array(telemetry, "required_summary_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for f in summary_required {
        require(
            summary.get(f).is_some(),
            format!("telemetry report.summary missing required field `{f}`"),
        )?;
    }
    let covered: Vec<&str> = summary
        .get("uaf_patterns_covered")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let required_patterns: Vec<&str> = json_array(telemetry, "required_uaf_patterns")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for p in required_patterns {
        require(
            covered.contains(&p),
            format!("telemetry report.summary.uaf_patterns_covered missing `{p}`"),
        )?;
    }
    Ok(())
}
