//! Conformance + telemetry-index gate for the perf-budget CI gate
//! (bd-2r0 / completion-debt bd-2r0.1).
//!
//! Pins, at conformance level:
//! 1. The primary unit + e2e test file is present and contains the
//!    named test functions (10 unit tests + 2 e2e tests).
//! 2. The check script exists and is executable.
//! 3. The policy artifact exists.
//! 4. The telemetry report + log paths under target/conformance/
//!    are stable.

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
        .join("perf_budget_ci_index.v1.json")
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
fn index_anchors_to_2r0_with_completion_debt_bead() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&index_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "perf-budget-ci-index",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-2r0", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-2r0.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "primary_unit_test_file")?
            == "crates/frankenlibc-harness/tests/perf_budget_test.rs",
        "primary_unit_test_file",
    )?;
    require(
        json_string(&m, "primary_e2e_script")? == "scripts/check_perf_budget.sh",
        "primary_e2e_script",
    )?;
    require(
        json_string(&m, "policy_artifact")? == "tests/conformance/perf_budget_policy.json",
        "policy_artifact",
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
        "fail_closed_when_e2e_script_missing",
        "fail_closed_when_e2e_script_not_executable",
        "fail_closed_when_telemetry_paths_drift",
        "fail_closed_when_policy_artifact_missing",
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
    let e2e_rel = json_string(&index, "primary_e2e_test_file")?;
    let e2e_src = std::fs::read_to_string(root.join(e2e_rel))
        .map_err(|e| format!("primary_e2e_test_file: {e}"))?;
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
    for n in json_array(&index, "primary_e2e_test_functions")?
        .iter()
        .filter_map(Value::as_str)
    {
        let anchor = format!("fn {n}(");
        require(
            e2e_src.contains(&anchor),
            format!("primary e2e test file missing function `{anchor}`"),
        )?;
    }
    Ok(())
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
fn policy_artifact_is_present() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let rel = json_string(&index, "policy_artifact")?;
    let p = root.join(rel);
    require(p.exists(), format!("policy_artifact {p:?} not present"))
}

#[test]
fn telemetry_paths_pinned_to_canonical_locations() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let telemetry = index
        .get("telemetry_emission_contract")
        .ok_or_else(|| "missing telemetry_emission_contract".to_string())?;
    require(
        json_string(telemetry, "report_artifact_path")?
            == "target/conformance/perf_budget_policy.report.json",
        "report_artifact_path drift",
    )?;
    require(
        json_string(telemetry, "log_artifact_path")?
            == "target/conformance/perf_budget_policy.log.jsonl",
        "log_artifact_path drift",
    )?;
    require(
        json_string(telemetry, "report_artifact_kind")? == "json",
        "report_artifact_kind",
    )?;
    require(
        json_string(telemetry, "log_artifact_kind")? == "jsonl",
        "log_artifact_kind",
    )
}

#[test]
fn check_script_emits_canonical_telemetry_paths() -> TestResult {
    let root = workspace_root()?;
    let script_path = root.join("scripts").join("check_perf_budget.sh");
    let src =
        std::fs::read_to_string(&script_path).map_err(|e| format!("check_perf_budget.sh: {e}"))?;
    require(
        src.contains("OUT_DIR=\"${ROOT}/target/conformance\""),
        "check_perf_budget.sh OUT_DIR must point at target/conformance",
    )?;
    require(
        src.contains("REPORT=\"${OUT_DIR}/perf_budget_policy.report.json\""),
        "check_perf_budget.sh must emit REPORT at OUT_DIR/perf_budget_policy.report.json",
    )?;
    require(
        src.contains("LOG=\"${OUT_DIR}/perf_budget_policy.log.jsonl\""),
        "check_perf_budget.sh must emit LOG at OUT_DIR/perf_budget_policy.log.jsonl",
    )
}
