//! Conformance gate for the Gentoo test execution telemetry contract
//! (bd-2icq.8 / completion-debt bd-2icq.8.1).
//!
//! Pins that `scripts/gentoo/test-runner.py` writes explicit telemetry
//! into each per-package result and the aggregate summary. The audit
//! pass that created this completion-debt bead missed `telemetry.primary`;
//! these tests make that evidence concrete and file-backed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("gentoo_test_execution_telemetry.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    load_json(&manifest_path(&root))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value.get(field).ok_or_else(|| format!("missing `{field}`"))
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

fn string_set(value: &Value, field: &str) -> TestResult<HashSet<String>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("`{field}` entry should be string"))
                .map(ToOwned::to_owned)
        })
        .collect::<Result<HashSet<_>, _>>()
}

fn require_fields(value: &Value, required: &HashSet<String>, context: &str) -> TestResult {
    for field in required {
        require(
            value.get(field).is_some(),
            format!("{context} missing required field `{field}`"),
        )?;
    }
    Ok(())
}

fn unique_output_dir(root: &Path) -> TestResult<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("system time should be after unix epoch: {err}"))?
        .as_nanos();
    Ok(root.join("target").join("conformance").join(format!(
        "gentoo-test-execution-telemetry-{}-{nanos}",
        std::process::id()
    )))
}

#[test]
fn manifest_anchors_to_2icq_8_with_completion_debt_bead() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "gentoo-test-execution-telemetry",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-2icq.8", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-2icq.8.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "runner_file")? == "scripts/gentoo/test-runner.py",
        "runner_file",
    )?;
    require(
        json_string(&m, "docs_file")? == "docs/gentoo/test-analysis.md",
        "docs_file",
    )
}

#[test]
fn manifest_policy_pins_telemetry_requirements() -> TestResult {
    let m = load_manifest()?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for field in [
        "fail_closed_when_result_telemetry_missing",
        "fail_closed_when_summary_telemetry_missing",
        "fail_closed_when_instrumented_frankenlibc_log_missing",
        "fail_closed_when_dry_run_probe_missing",
    ] {
        require(json_bool(policy, field)?, format!("{field} must be true"))?;
    }

    let rejected = m
        .get("rejected_evidence_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing rejected_evidence_kinds".to_string())?;
    let rejected: HashSet<_> = rejected.iter().filter_map(Value::as_str).collect();
    for kind in [
        "missing_result_telemetry",
        "missing_summary_telemetry",
        "missing_frankenlibc_log_binding",
        "missing_healing_breakdown",
        "missing_dry_run_probe",
    ] {
        require(
            rejected.contains(kind),
            format!("rejected_evidence_kinds missing {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn manifest_audit_reference_pins_pre_repair_score() -> TestResult {
    let m = load_manifest()?;
    let aref = m
        .get("audit_reference")
        .ok_or_else(|| "missing audit_reference".to_string())?;
    require(
        json_string(aref, "pass")? == "2026-05-10T03-16-16Z",
        "audit_reference.pass",
    )?;
    require(
        json_string(aref, "missing_item_id")? == "telemetry.primary",
        "audit_reference.missing_item_id",
    )?;
    require(
        aref.get("score_before").and_then(Value::as_u64) == Some(440),
        "score_before",
    )?;
    require(
        aref.get("score_threshold").and_then(Value::as_u64) == Some(700),
        "score_threshold",
    )
}

#[test]
fn runner_source_defines_result_and_summary_telemetry() -> TestResult {
    let root = workspace_root()?;
    let m = load_manifest()?;
    let runner = root.join(json_string(&m, "runner_file")?);
    let src = std::fs::read_to_string(&runner).map_err(|err| format!("read {runner:?}: {err}"))?;

    for needle in [
        "\"schema_version\": \"gentoo_test_execution_telemetry.v1\"",
        "\"frankenlibc_mode\": franken_mode",
        "\"baseline_log\": baseline.log_file",
        "\"instrumented_log\": instrumented.log_file",
        "\"frankenlibc_log\": instrumented.frankenlibc_log",
        "\"healing_actions\": instrumented.healing_actions",
        "\"healing_breakdown\": instrumented.healing_breakdown or {}",
        "\"telemetry\": telemetry",
        "\"schema_version\": \"gentoo_test_execution_summary_telemetry.v1\"",
    ] {
        require(
            src.contains(needle),
            format!("test-runner.py missing telemetry source binding `{needle}`"),
        )?;
    }
    Ok(())
}

#[test]
fn dry_run_runner_emits_required_telemetry_fields() -> TestResult {
    let root = workspace_root()?;
    let m = load_manifest()?;
    let contract = m
        .get("telemetry_contract")
        .ok_or_else(|| "missing telemetry_contract".to_string())?;
    let probe = m
        .get("dry_run_probe")
        .ok_or_else(|| "missing dry_run_probe".to_string())?;
    let output_dir = unique_output_dir(&root)?;
    let package = json_string(probe, "package")?;

    let output = Command::new("python3")
        .current_dir(&root)
        .arg("scripts/gentoo/test-runner.py")
        .arg("--dry-run")
        .arg("--package")
        .arg(package)
        .arg("--output")
        .arg(&output_dir)
        .output()
        .map_err(|err| format!("failed to run Gentoo test runner dry run: {err}"))?;
    require(
        output.status.success(),
        format!(
            "Gentoo test runner dry run failed stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let sanitized = json_string(probe, "sanitized_package")?;
    let result_path = output_dir.join(sanitized).join("result.json");
    let summary_path = output_dir.join("summary.json");
    let result = load_json(&result_path)?;
    let summary = load_json(&summary_path)?;
    let baseline = json_field(&result, "baseline")?;
    let instrumented = json_field(&result, "instrumented")?;
    let comparison = json_field(&result, "comparison")?;
    let telemetry = json_field(&result, "telemetry")?;
    let summary_telemetry = json_field(&summary, "telemetry")?;

    require_fields(
        &result,
        &string_set(contract, "required_result_fields")?,
        "per-package result",
    )?;
    require_fields(
        instrumented,
        &string_set(contract, "required_instrumented_fields")?,
        "instrumented result",
    )?;
    require_fields(
        comparison,
        &string_set(contract, "required_comparison_fields")?,
        "comparison result",
    )?;
    require_fields(
        telemetry,
        &string_set(contract, "required_telemetry_fields")?,
        "per-package telemetry",
    )?;
    require_fields(
        &summary,
        &string_set(contract, "required_summary_fields")?,
        "summary",
    )?;
    require_fields(
        summary_telemetry,
        &string_set(contract, "required_summary_telemetry_fields")?,
        "summary telemetry",
    )?;

    require(
        json_string(telemetry, "schema_version")? == "gentoo_test_execution_telemetry.v1",
        "per-package telemetry schema_version",
    )?;
    require(json_string(telemetry, "package")? == package, "package")?;
    require(
        json_string(telemetry, "frankenlibc_mode")?
            == json_string(probe, "expected_frankenlibc_mode")?,
        "frankenlibc_mode",
    )?;
    require(
        json_string(telemetry, "verdict")? == json_string(probe, "expected_verdict")?,
        "verdict",
    )?;
    require(
        baseline.get("total_tests").and_then(Value::as_u64)
            == probe
                .get("expected_baseline_total_tests")
                .and_then(Value::as_u64),
        "baseline total_tests",
    )?;
    require(
        instrumented.get("total_tests").and_then(Value::as_u64)
            == probe
                .get("expected_instrumented_total_tests")
                .and_then(Value::as_u64),
        "instrumented total_tests",
    )?;
    require(
        telemetry.get("healing_actions").and_then(Value::as_u64)
            == probe
                .get("expected_healing_actions")
                .and_then(Value::as_u64),
        "healing_actions",
    )?;
    require(
        json_string(telemetry, "frankenlibc_log")?.ends_with("frankenlibc.jsonl"),
        "frankenlibc_log should bind the instrumented log path",
    )?;

    let packages = summary_telemetry
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "summary telemetry packages should be an array".to_string())?;
    require(
        packages.len() == 1,
        "summary should include one package row",
    )?;
    let package_row = packages
        .first()
        .ok_or_else(|| "summary telemetry package row missing".to_string())?;
    require_fields(
        package_row,
        &string_set(contract, "required_summary_package_fields")?,
        "summary telemetry package row",
    )?;
    require(
        json_string(package_row, "package")? == package,
        "summary telemetry package",
    )?;
    Ok(())
}

#[test]
fn test_analysis_docs_explain_telemetry_artifacts() -> TestResult {
    let root = workspace_root()?;
    let m = load_manifest()?;
    let docs = root.join(json_string(&m, "docs_file")?);
    let content = std::fs::read_to_string(&docs).map_err(|err| format!("read {docs:?}: {err}"))?;
    for needle in [
        "## Telemetry Contract",
        "gentoo_test_execution_telemetry.v1",
        "gentoo_test_execution_summary_telemetry.v1",
        "frankenlibc_log",
        "healing_breakdown",
    ] {
        require(
            content.contains(needle),
            format!("test-analysis.md missing telemetry doc `{needle}`"),
        )?;
    }
    Ok(())
}
