//! Integration test: hermetic resolver/NSS lab execution gate
//! (bd-b92jd.5.5).
//!
//! The structural manifest gate is not enough for the hard-subsystem epic.
//! This test runs the lab driver, verifies the JSONL evidence contract, and
//! mutates fixture manifests to prove the runner fails closed for the known
//! bad evidence classes.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_SCENARIOS: &[&str] = &[
    "nss-numeric-hosts-bypass",
    "nss-hosts-files-only",
    "nss-dns-success-then-cache",
    "nss-dns-timeout",
    "nss-dns-poisoning-rejected",
    "nss-search-domain-walk",
    "nss-passwd-files-only",
    "nss-group-files-only",
];
const REQUIRED_MODES: &[&str] = &["strict", "hardened"];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "scenario_kind",
    "fake_root_id",
    "runtime_mode",
    "oracle_kind",
    "query_kind",
    "resolved_host",
    "resolved_addrs",
    "resolved_errno",
    "expected",
    "actual",
    "decision_path",
    "duration_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];
const REQUIRED_FAILURE_SIGNATURES: &[&str] = &[
    "nss_lab_real_network_required",
    "nss_lab_missing_fake_root_file",
    "nss_lab_stale_source_commit",
    "nss_lab_missing_oracle",
    "nss_lab_missing_runtime_mode",
    "nss_lab_missing_fixture_obligation",
];

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

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/hermetic_nss_resolver_lab.v1.json")
}

fn runner_path(root: &Path) -> PathBuf {
    root.join("scripts/run_hermetic_nss_resolver_lab.sh")
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/conformance/nss_lab/hermetic_nss_resolver_lab.report.json")
}

fn log_path(root: &Path) -> PathBuf {
    root.join("target/conformance/nss_lab/hermetic_nss_resolver_lab.log.jsonl")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| test_error(format!("{} mkdir failed: {err}", parent.display())))?;
    }
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn as_array<'a>(value: &'a Value, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn as_object<'a>(
    value: &'a Value,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| test_error(format!("{context} must be an object")))
}

fn safe_workspace_path(root: &Path, reference: &str) -> TestResult<PathBuf> {
    let trimmed = reference
        .split_once('#')
        .map_or(reference, |(path, _fragment)| path)
        .trim_end_matches('/');
    let rel_path = Path::new(trimmed);
    ensure(!rel_path.is_absolute(), "artifact path must be relative")?;
    for component in rel_path.components() {
        ensure(
            matches!(component, Component::Normal(_)),
            "artifact path contains unsafe components",
        )?;
    }
    Ok(root.join(rel_path)) // ubs:ignore - rel_path is rejected unless relative with only normal components.
}

fn set_object_field(value: &mut Value, key: &str, replacement: Value, context: &str) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))?;
    object.insert(key.to_owned(), replacement);
    Ok(())
}

fn set_nested_object_field(
    value: &mut Value,
    object_key: &str,
    field_key: &str,
    replacement: Value,
    context: &str,
) -> TestResult {
    let object = value
        .get_mut(object_key)
        .ok_or_else(|| test_error(format!("{context}.{object_key} is missing")))?;
    set_object_field(object, field_key, replacement, context)
}

fn mutable_scenarios(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("scenarios")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("scenarios must be a mutable array"))
}

fn required_scenario_label(value: &str) -> TestResult<&'static str> {
    REQUIRED_SCENARIOS
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .ok_or_else(|| test_error("unknown scenario id in evidence row"))
}

fn required_mode_label(value: &str) -> TestResult<&'static str> {
    REQUIRED_MODES
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .ok_or_else(|| test_error("unknown runtime mode in evidence row"))
}

fn run_lab(root: &Path) -> TestResult<std::process::Output> {
    Command::new("bash")
        .arg(runner_path(root))
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run NSS lab runner: {err}")))
}

fn run_lab_with_manifest(root: &Path, case_name: &str, manifest: &Value) -> TestResult<PathBuf> {
    let out_dir = root
        .join("target/conformance/nss_lab_negative")
        .join(case_name);
    let fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&fixture, manifest)?;

    let output = Command::new("bash")
        .arg(runner_path(root))
        .current_dir(root)
        .env("FLC_NSS_LAB_MANIFEST", &fixture)
        .env("FLC_NSS_LAB_OUT_DIR", &out_dir)
        .env("FLC_NSS_LAB_REPORT", &report)
        .env("FLC_NSS_LAB_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run negative NSS lab case: {err}")))?;
    ensure(
        !output.status.success(),
        format!(
            "{case_name}: negative lab case should fail\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    Ok(report)
}

fn expect_error_signature(report: &Path, signature: &str) -> TestResult {
    let report_json = load_json(report)?;
    ensure_eq(
        string_field(&report_json, "status", "report")?,
        "fail",
        format!("{} status", report.display()),
    )?;
    let errors = as_array(field(&report_json, "errors", "report")?, "report.errors")?;
    ensure(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(signature)),
        format!("report errors should include {signature}"),
    )
}

#[test]
fn manifest_points_to_runner_and_skip_contract() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    ensure_eq(
        string_field(&manifest, "execution_runner", "manifest")?,
        "scripts/run_hermetic_nss_resolver_lab.sh",
        "execution_runner",
    )?;
    ensure(
        runner_path(&root).exists(),
        "execution_runner should point at an on-disk runner",
    )?;

    let freshness = as_object(field(&manifest, "freshness", "manifest")?, "freshness")?;
    ensure_eq(
        freshness
            .get("required_source_commit")
            .and_then(Value::as_str),
        Some("current"),
        "freshness.required_source_commit",
    )?;

    let skips = as_array(
        field(&manifest, "optional_skip_conditions", "manifest")?,
        "optional_skip_conditions",
    )?;
    ensure(
        skips.iter().any(|skip| {
            skip.get("skip_id").and_then(Value::as_str)
                == Some("real-network-probe-disabled-by-default")
        }),
        "manifest should record the default real-network skip condition",
    )?;
    Ok(())
}

#[test]
fn runner_passes_and_emits_current_jsonl_evidence() -> TestResult {
    let root = workspace_root();
    let output = run_lab(&root)?;
    ensure(
        output.status.success(),
        format!(
            "NSS lab runner failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report = load_json(&report_path(&root))?;
    ensure_eq(
        string_field(&report, "status", "report")?,
        "pass",
        "report status",
    )?;
    ensure_eq(
        field(
            field(&report, "summary", "report")?,
            "scenario_count",
            "report.summary",
        )?
        .as_u64(),
        Some(8),
        "scenario count",
    )?;
    ensure_eq(
        field(
            field(&report, "summary", "report")?,
            "evidence_row_count",
            "report.summary",
        )?
        .as_u64(),
        Some(16),
        "evidence row count",
    )?;
    ensure(
        field(&report, "real_network_observed", "report")?.as_bool() == Some(false),
        "runner must report no real-network observation",
    )?;
    ensure(
        field(&report, "source_commit", "report")?
            .as_str()
            .is_some_and(|commit| commit.len() == 40),
        "report must carry current git source commit",
    )?;

    let skips = as_array(
        field(&report, "skip_conditions", "report")?,
        "report.skip_conditions",
    )?;
    ensure(
        skips.iter().any(|skip| {
            skip.get("skip_id").and_then(Value::as_str)
                == Some("real-network-probe-disabled-by-default")
                && skip.get("status").and_then(Value::as_str) == Some("skipped")
        }),
        "runner should record the real-network skip condition",
    )?;

    let artifacts = as_object(
        field(&report, "scenario_artifacts", "report")?,
        "scenario_artifacts",
    )?;
    for scenario_id in REQUIRED_SCENARIOS {
        let artifact = artifacts
            .get(*scenario_id)
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("missing scenario artifact"))?;
        ensure(
            safe_workspace_path(&root, artifact)?.exists(),
            "scenario artifact should exist",
        )?;
    }

    let log = std::fs::read_to_string(log_path(&root))
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let mut row_count = 0usize;
    let mut modes_by_scenario: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
    for line in log.lines() {
        row_count += 1;
        let entry: Value = serde_json::from_str(line)
            .map_err(|_err| test_error("structured log row should parse"))?;
        for field_name in REQUIRED_LOG_FIELDS {
            ensure(
                entry.get(*field_name).is_some(),
                "structured log row missing required field",
            )?;
        }
        let scenario = required_scenario_label(string_field(&entry, "scenario_id", "entry")?)?;
        let mode = required_mode_label(string_field(&entry, "runtime_mode", "entry")?)?;
        modes_by_scenario.entry(scenario).or_default().insert(mode);
        ensure(
            string_field(&entry, "bead_id", "entry")? == "bd-b92jd.5.5",
            "row bead_id should identify execution bead",
        )?;
        ensure(
            string_field(&entry, "source_commit", "entry")?
                == string_field(&report, "source_commit", "report")?,
            "row source_commit should match report",
        )?;
        ensure(
            field(&entry, "duration_ns", "entry")?.as_u64().is_some(),
            "duration_ns should be numeric",
        )?;
        let refs = as_array(
            field(&entry, "artifact_refs", "entry")?,
            "entry.artifact_refs",
        )?;
        ensure(!refs.is_empty(), "artifact_refs should be non-empty")?;
        for artifact in refs {
            let artifact = artifact
                .as_str()
                .ok_or_else(|| test_error("artifact_refs entries must be strings"))?;
            ensure(
                safe_workspace_path(&root, artifact)?.exists(),
                "artifact ref should exist",
            )?;
        }
    }
    ensure_eq(row_count, 16usize, "JSONL row count")?;
    for scenario_id in REQUIRED_SCENARIOS {
        let modes = modes_by_scenario
            .get(*scenario_id)
            .ok_or_else(|| test_error("missing rows for scenario"))?;
        for mode in REQUIRED_MODES {
            ensure(
                modes.contains(*mode),
                "scenario missing required runtime mode",
            )?;
        }
    }
    Ok(())
}

#[test]
fn runner_fails_closed_for_real_network_requirement() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    set_nested_object_field(
        &mut manifest,
        "execution_policy",
        "real_network_allowed",
        json!(true),
        "manifest",
    )?;
    let report = run_lab_with_manifest(&root, "real_network_required", &manifest)?;
    expect_error_signature(&report, "nss_lab_real_network_required")
}

#[test]
fn runner_fails_closed_for_missing_fake_root_file() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let files = manifest
        .get_mut("fake_root_layout")
        .and_then(|layout| layout.get_mut("files"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("fake_root_layout.files should be mutable"))?;
    files.retain(|entry| entry.get("relative_path").and_then(Value::as_str) != Some("etc/hosts"));
    let report = run_lab_with_manifest(&root, "missing_fake_root_file", &manifest)?;
    expect_error_signature(&report, "nss_lab_missing_fake_root_file")
}

#[test]
fn runner_fails_closed_for_stale_source_commit() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    set_nested_object_field(
        &mut manifest,
        "freshness",
        "required_source_commit",
        json!("0000000000000000000000000000000000000000"),
        "manifest",
    )?;
    let report = run_lab_with_manifest(&root, "stale_source_commit", &manifest)?;
    expect_error_signature(&report, "nss_lab_stale_source_commit")
}

#[test]
fn runner_fails_closed_for_missing_oracle() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    set_object_field(first, "oracle_kind", json!(""), "scenario")?;
    let report = run_lab_with_manifest(&root, "missing_oracle", &manifest)?;
    expect_error_signature(&report, "nss_lab_missing_oracle")
}

#[test]
fn runner_fails_closed_for_missing_runtime_mode() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    set_object_field(first, "runtime_modes", json!(["strict"]), "scenario")?;
    let report = run_lab_with_manifest(&root, "missing_runtime_mode", &manifest)?;
    expect_error_signature(&report, "nss_lab_missing_runtime_mode")
}

#[test]
fn runner_fails_closed_for_missing_fixture_obligation() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    set_object_field(first, "fixture_obligation", json!(""), "scenario")?;
    let report = run_lab_with_manifest(&root, "missing_fixture_obligation", &manifest)?;
    expect_error_signature(&report, "nss_lab_missing_fixture_obligation")
}

#[test]
fn runner_summary_declares_required_failure_signatures() -> TestResult {
    let root = workspace_root();
    let output = run_lab(&root)?;
    ensure(
        output.status.success(),
        "NSS lab runner should pass before summary inspection",
    )?;
    let report = load_json(&report_path(&root))?;
    let summary = field(&report, "summary", "report")?;
    let signatures = as_array(
        field(summary, "negative_failure_signatures", "report.summary")?,
        "report.summary.negative_failure_signatures",
    )?;
    let signature_set = signatures
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for signature in REQUIRED_FAILURE_SIGNATURES {
        ensure(
            signature_set.contains(signature),
            "negative failure signature missing from runner summary",
        )?;
    }
    Ok(())
}
