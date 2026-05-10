//! Conformance + telemetry-index gate for the closure-gate evidence
//! enforcement (bd-4rl / completion-debt bd-4rl.1).
//!
//! Pins, at conformance level:
//! 1. The primary unit + e2e test file is present and contains the
//!    named test functions (6 unit tests + 1 e2e test).
//! 2. The check script exists and is executable.
//! 3. Both conformance artifacts (closure_evidence_schema.json,
//!    verification_matrix.json) are present.
//! 4. The telemetry contract (exit-code semantics + summary line)
//!    is documented in the index manifest.

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
        .join("closure_gate_index.v1.json")
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
fn index_anchors_to_4rl_with_completion_debt_bead() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&index_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "closure-gate-index",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-4rl", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-4rl.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "primary_e2e_script")? == "scripts/check_closure_gate.sh",
        "primary_e2e_script",
    )?;
    require(
        json_string(&m, "primary_e2e_test_function")? == "gate_script_exists_and_executable",
        "primary_e2e_test_function",
    )
}

#[test]
fn index_audit_reference_pins_pre_repair_score_and_four_missing_items() -> TestResult {
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
        "tests.conformance.primary",
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
        "fail_closed_when_e2e_script_missing",
        "fail_closed_when_e2e_script_not_executable",
        "fail_closed_when_evidence_schema_missing",
        "fail_closed_when_verification_matrix_missing",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn primary_test_file_carries_named_unit_and_e2e_functions() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let unit_rel = json_string(&index, "primary_unit_test_file")?;
    let unit_src = std::fs::read_to_string(root.join(unit_rel))
        .map_err(|e| format!("primary_unit_test_file: {e}"))?;
    for n in json_array(&index, "primary_unit_test_functions")?
        .iter()
        .filter_map(Value::as_str)
    {
        let anchor = format!("fn {n}(");
        require(
            unit_src.contains(&anchor),
            format!("primary unit test file missing function `{anchor}`"),
        )?;
    }
    let e2e_rel = json_string(&index, "primary_e2e_test_file")?;
    let e2e_src = std::fs::read_to_string(root.join(e2e_rel))
        .map_err(|e| format!("primary_e2e_test_file: {e}"))?;
    let name = json_string(&index, "primary_e2e_test_function")?;
    let anchor = format!("fn {name}(");
    require(
        e2e_src.contains(&anchor),
        format!("primary e2e test file missing function `{anchor}`"),
    )
}

#[test]
fn check_script_is_present_and_executable() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let rel = json_string(&index, "primary_e2e_script")?;
    let p = root.join(rel);
    let metadata = std::fs::metadata(&p).map_err(|e| format!("{p:?}: {e}"))?;
    let mode = metadata.permissions().mode();
    require(
        mode & 0o111 != 0,
        format!("{p:?} not executable (mode {mode:o})"),
    )
}

#[test]
fn primary_conformance_artifacts_are_present() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let arts: Vec<&str> = json_array(&index, "primary_conformance_artifacts")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for rel in arts {
        let p = root.join(rel);
        require(p.exists(), format!("conformance artifact {p:?} missing"))?;
    }
    Ok(())
}

#[test]
fn telemetry_emission_contract_documents_exit_code_semantics() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let telemetry = index
        .get("telemetry_emission_contract")
        .ok_or_else(|| "missing telemetry_emission_contract".to_string())?;
    require(
        json_string(telemetry, "report_emission_command")? == "scripts/check_closure_gate.sh",
        "report_emission_command",
    )?;
    require(
        json_string(telemetry, "exit_code_contract")?.contains("exit 0"),
        "exit_code_contract must document exit 0 semantics",
    )?;
    require(
        json_string(telemetry, "exit_code_contract")?.contains("exit 1"),
        "exit_code_contract must document exit 1 semantics",
    )
}
