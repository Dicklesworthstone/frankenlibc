//! Conformance + telemetry-index gate for the LD_PRELOAD smoke
//! e2e harness (bd-2cr / completion-debt bd-2cr.1).
//!
//! Pins, at conformance level:
//! 1. The primary unit + e2e test file is present and contains the
//!    named test functions (6 unit tests + 3 e2e tests).
//! 2. Both e2e scripts (e2e_suite.sh, ld_preload_smoke.sh) exist
//!    and are executable.
//! 3. The telemetry per-run directory layout under
//!    target/ld_preload_smoke/<run-id>/ is pinned with named
//!    abi_compat_report.json + trace.jsonl filenames.

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
        .join("ld_preload_smoke_e2e_index.v1.json")
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
fn index_anchors_to_2cr_with_completion_debt_bead() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&index_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "ld-preload-smoke-e2e-index",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-2cr", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-2cr.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "primary_unit_test_file")?
            == "crates/frankenlibc-harness/tests/e2e_suite_test.rs",
        "primary_unit_test_file",
    )?;
    require(
        json_string(&m, "primary_e2e_test_file")?
            == "crates/frankenlibc-harness/tests/e2e_suite_test.rs",
        "primary_e2e_test_file",
    )?;
    Ok(())
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
        "fail_closed_when_telemetry_run_dir_root_drifts",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn primary_unit_and_e2e_test_file_carries_named_functions() -> TestResult {
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
fn primary_e2e_scripts_are_present_and_executable() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let scripts: Vec<&str> = json_array(&index, "primary_e2e_scripts")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for rel in scripts {
        let p = root.join(rel);
        let metadata = std::fs::metadata(&p).map_err(|e| format!("{p:?}: {e}"))?;
        let mode = metadata.permissions().mode();
        require(
            mode & 0o111 != 0,
            format!("{p:?} not executable (mode {mode:o})"),
        )?;
    }
    Ok(())
}

#[test]
fn telemetry_run_dir_root_pinned_to_canonical_location() -> TestResult {
    let root = workspace_root()?;
    let index = load_json(&index_path(&root))?;
    let telemetry = index
        .get("telemetry_emission_contract")
        .ok_or_else(|| "missing telemetry_emission_contract".to_string())?;
    require(
        json_string(telemetry, "ld_preload_smoke_run_dir_root")? == "target/ld_preload_smoke",
        "ld_preload_smoke_run_dir_root drift",
    )?;
    require(
        json_string(telemetry, "ld_preload_smoke_report_path_template")?
            == "target/ld_preload_smoke/<run-id>/abi_compat_report.json",
        "ld_preload_smoke_report_path_template drift",
    )?;
    require(
        json_string(telemetry, "ld_preload_smoke_trace_path_template")?
            == "target/ld_preload_smoke/<run-id>/trace.jsonl",
        "ld_preload_smoke_trace_path_template drift",
    )
}

#[test]
fn ld_preload_smoke_script_emits_canonical_run_dir_root() -> TestResult {
    let root = workspace_root()?;
    let script_path = root.join("scripts").join("ld_preload_smoke.sh");
    let src =
        std::fs::read_to_string(&script_path).map_err(|e| format!("ld_preload_smoke.sh: {e}"))?;
    require(
        src.contains("OUT_ROOT=\"${ROOT}/target/ld_preload_smoke\""),
        "ld_preload_smoke.sh OUT_ROOT must point at target/ld_preload_smoke (telemetry root)",
    )?;
    require(
        src.contains("REPORT_FILE=\"${RUN_DIR}/abi_compat_report.json\""),
        "ld_preload_smoke.sh must emit REPORT_FILE at <run_dir>/abi_compat_report.json",
    )?;
    require(
        src.contains("TRACE_FILE=\"${RUN_DIR}/trace.jsonl\""),
        "ld_preload_smoke.sh must emit TRACE_FILE at <run_dir>/trace.jsonl",
    )
}

#[test]
fn ld_preload_smoke_default_run_id_is_process_unique() -> TestResult {
    let root = workspace_root()?;
    let script_path = root.join("scripts").join("ld_preload_smoke.sh");
    let src =
        std::fs::read_to_string(&script_path).map_err(|e| format!("ld_preload_smoke.sh: {e}"))?;
    require(
        src.contains("RUN_ID=\"${FRANKENLIBC_SMOKE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}\""),
        "standalone ld_preload_smoke.sh default run id must include the process id",
    )?;
    require(
        src.contains("\"\"|*[!A-Za-z0-9._-]*)"),
        "ld_preload_smoke.sh must validate caller-supplied smoke run ids before using them as paths",
    )
}

#[test]
fn ld_preload_smoke_rch_build_is_remote_and_target_isolated() -> TestResult {
    let root = workspace_root()?;
    let script_path = root.join("scripts").join("ld_preload_smoke.sh");
    let src =
        std::fs::read_to_string(&script_path).map_err(|e| format!("ld_preload_smoke.sh: {e}"))?;
    require(
        src.contains(
            ": \"${CARGO_TARGET_DIR:=${TMPDIR:-/tmp}/rch_target_frankenlibc_ld_preload_smoke_${RUN_ID}}\"",
        ),
        "ld_preload_smoke.sh must default to a per-run isolated Cargo target dir",
    )?;
    require(
        src.contains("case \",${RCH_ENV_ALLOWLIST:-},\" in"),
        "ld_preload_smoke.sh must inspect RCH_ENV_ALLOWLIST as comma-delimited tokens",
    )?;
    require(
        src.contains("export RCH_ENV_ALLOWLIST=\"${RCH_ENV_ALLOWLIST},CARGO_TARGET_DIR\""),
        "ld_preload_smoke.sh must forward CARGO_TARGET_DIR through rch",
    )?;
    let remote_required = src
        .find("export RCH_REQUIRE_REMOTE=1")
        .ok_or_else(|| "ld_preload_smoke.sh must require remote rch execution".to_string())?;
    let rch_build = src
        .find("rch exec -- cargo build -p frankenlibc-abi --release")
        .ok_or_else(|| "ld_preload_smoke.sh must build frankenlibc-abi through rch".to_string())?;
    require(
        remote_required < rch_build,
        "ld_preload_smoke.sh must require remote rch before invoking cargo build",
    )
}
