//! Integration test: pthread/malloc/stdio stress orchard execution gate
//! (bd-b92jd.5.6).
//!
//! Runs the stress orchard smoke-tier runner, verifies the structured evidence
//! contract, and mutates fixture manifests to prove the runner fails closed for
//! stale or incomplete stress evidence.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BOTH_MODE_SCENARIOS: &[&str] = &[
    "malloc-concurrent-alloc-free",
    "stdio-file-buffering-contention",
    "pthread-mutex-lifecycle",
    "pthread-condvar-broadcast-signal",
    "pthread-condvar-timeout-edge",
    "pthread-rwlock-writer-priority",
    "pthread-cancellation-adjacent-state",
];
const HARDENED_ONLY_SCENARIOS: &[&str] = &[
    "hardened-repair-malloc-overflow",
    "hardened-repair-stdio-format-truncation",
];
const REQUIRED_MODES: &[&str] = &["strict", "hardened"];
const REQUIRED_TIERS: &[&str] = &["smoke", "normal"];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "scenario_kind",
    "tier",
    "iterations",
    "thread_count",
    "seed",
    "runtime_mode",
    "oracle_kind",
    "stress_kernel_id",
    "expected",
    "actual",
    "counters",
    "errno",
    "decision_path",
    "healing_action",
    "failure_signatures",
    "duration_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];
const REQUIRED_FAILURE_SIGNATURES: &[&str] = &[
    "missing_scenario_seed",
    "missing_oracle_kind",
    "non_deterministic_input",
    "unbounded_iteration_count",
    "local_only_runner",
    "stale_source_commit",
    "missing_runtime_mode_coverage",
    "missing_normal_tier_kernel",
    "missing_counter_field",
];

struct OrchardRun {
    output: Output,
    report: PathBuf,
    log: PathBuf,
}

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
    root.join("tests/conformance/pthread_malloc_stdio_stress_orchard.v1.json")
}

fn runner_path(root: &Path) -> PathBuf {
    root.join("scripts/run_pthread_malloc_stdio_stress_orchard.sh")
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance/stress_orchard_execution_tests")
        .join(format!("{label}-{stamp}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", dir.display())))?;
    Ok(dir)
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
    BOTH_MODE_SCENARIOS
        .iter()
        .chain(HARDENED_ONLY_SCENARIOS.iter())
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

fn required_tier_label(value: &str) -> TestResult<&'static str> {
    REQUIRED_TIERS
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .ok_or_else(|| test_error("unknown tier in evidence row"))
}

fn run_orchard(root: &Path, label: &str) -> TestResult<OrchardRun> {
    let out_dir = unique_out_dir(root, label)?;
    let report = out_dir.join("pthread_malloc_stdio_stress_orchard.report.json");
    let log = out_dir.join("pthread_malloc_stdio_stress_orchard.log.jsonl");
    let output = Command::new("bash")
        .arg(runner_path(root))
        .current_dir(root)
        .env("FLC_STRESS_ORCHARD_OUT_DIR", &out_dir)
        .env("FLC_STRESS_ORCHARD_REPORT", &report)
        .env("FLC_STRESS_ORCHARD_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run stress orchard runner: {err}")))?;
    Ok(OrchardRun {
        output,
        report,
        log,
    })
}

fn run_orchard_with_manifest(
    root: &Path,
    case_name: &str,
    manifest: &Value,
) -> TestResult<PathBuf> {
    let out_dir = root
        .join("target/conformance/stress_orchard_negative")
        .join(case_name);
    let fixture = out_dir.join(format!("{case_name}.manifest.json"));
    let report = out_dir.join(format!("{case_name}.report.json"));
    let log = out_dir.join(format!("{case_name}.log.jsonl"));
    write_json(&fixture, manifest)?;

    let output = Command::new("bash")
        .arg(runner_path(root))
        .current_dir(root)
        .env("FLC_STRESS_ORCHARD_MANIFEST", &fixture)
        .env("FLC_STRESS_ORCHARD_OUT_DIR", &out_dir)
        .env("FLC_STRESS_ORCHARD_REPORT", &report)
        .env("FLC_STRESS_ORCHARD_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run negative stress orchard case: {err}")))?;
    ensure(
        !output.status.success(),
        format!(
            "{case_name}: negative orchard case should fail\nstdout:\n{}\nstderr:\n{}",
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
fn manifest_points_to_runner_freshness_and_skip_contract() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&manifest_path(&root))?;
    ensure_eq(
        string_field(&manifest, "execution_runner", "manifest")?,
        "scripts/run_pthread_malloc_stdio_stress_orchard.sh",
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
            skip.get("skip_id").and_then(Value::as_str) == Some("deep-tier-disabled-by-default")
        }),
        "manifest should record the default deep-tier skip condition",
    )?;
    Ok(())
}

#[test]
fn runner_passes_and_emits_current_smoke_and_normal_jsonl_evidence() -> TestResult {
    let root = workspace_root();
    let run = run_orchard(&root, "pass")?;
    ensure(
        run.output.status.success(),
        format!(
            "stress orchard runner failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&run.output.stdout),
            String::from_utf8_lossy(&run.output.stderr)
        ),
    )?;

    let report = load_json(&run.report)?;
    ensure_eq(
        string_field(&report, "status", "report")?,
        "pass",
        "report status",
    )?;
    ensure_eq(
        string_field(&report, "tier", "report")?,
        "smoke+normal",
        "default tiers",
    )?;
    let tiers = as_array(field(&report, "tiers", "report")?, "report.tiers")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("report.tiers entries must be strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    ensure_eq(tiers, vec!["smoke", "normal"], "selected tiers")?;
    let iterations = as_object(field(&report, "iterations", "report")?, "report.iterations")?;
    ensure_eq(
        iterations.get("smoke").and_then(Value::as_u64),
        Some(256),
        "smoke iterations",
    )?;
    ensure_eq(
        iterations.get("normal").and_then(Value::as_u64),
        Some(4096),
        "normal iterations",
    )?;
    let thread_counts = as_object(
        field(&report, "thread_count", "report")?,
        "report.thread_count",
    )?;
    ensure_eq(
        thread_counts.get("smoke").and_then(Value::as_u64),
        Some(4),
        "smoke thread_count",
    )?;
    ensure_eq(
        thread_counts.get("normal").and_then(Value::as_u64),
        Some(8),
        "normal thread_count",
    )?;
    let summary = field(&report, "summary", "report")?;
    ensure_eq(
        field(summary, "scenario_count", "report.summary")?.as_u64(),
        Some(9),
        "scenario count",
    )?;
    ensure_eq(
        field(summary, "evidence_row_count", "report.summary")?.as_u64(),
        Some(32),
        "evidence row count",
    )?;
    ensure_eq(
        field(summary, "normal_tier_kernel_count", "report.summary")?.as_u64(),
        Some(9),
        "normal tier kernel count",
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
            skip.get("skip_id").and_then(Value::as_str) == Some("deep-tier-disabled-by-default")
                && skip.get("status").and_then(Value::as_str) == Some("skipped")
        }),
        "runner should record the deep-tier skip condition",
    )?;

    let artifacts = as_object(
        field(&report, "scenario_artifacts", "report")?,
        "scenario_artifacts",
    )?;
    for scenario_id in BOTH_MODE_SCENARIOS
        .iter()
        .chain(HARDENED_ONLY_SCENARIOS.iter())
    {
        let artifact = artifacts
            .get(*scenario_id)
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("missing scenario artifact"))?;
        ensure(
            safe_workspace_path(&root, artifact)?.exists(),
            "scenario artifact should exist",
        )?;
    }

    let log = std::fs::read_to_string(&run.log)
        .map_err(|err| test_error(format!("log should be readable: {err}")))?;
    let mut row_count = 0usize;
    let mut modes_by_scenario: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
    let mut tiers_by_scenario: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
    for line in log.lines() {
        row_count += 1;
        let entry: Value = serde_json::from_str(line)
            .map_err(|_err| test_error("structured log row should parse"))?;
        for field_name in REQUIRED_LOG_FIELDS {
            field(&entry, field_name, "structured log row")?;
        }
        let scenario = required_scenario_label(string_field(&entry, "scenario_id", "entry")?)?;
        let mode = required_mode_label(string_field(&entry, "runtime_mode", "entry")?)?;
        let tier = required_tier_label(string_field(&entry, "tier", "entry")?)?;
        modes_by_scenario.entry(scenario).or_default().insert(mode);
        tiers_by_scenario.entry(scenario).or_default().insert(tier);
        ensure(
            string_field(&entry, "bead_id", "entry")? == "bd-b92jd.5.6",
            "row bead_id should identify execution bead",
        )?;
        let expected_iterations = if tier == "smoke" { 256 } else { 4096 };
        let expected_threads = if tier == "smoke" { 4 } else { 8 };
        ensure_eq(
            field(&entry, "iterations", "entry")?.as_u64(),
            Some(expected_iterations),
            "row iterations should match tier",
        )?;
        ensure_eq(
            field(&entry, "thread_count", "entry")?.as_u64(),
            Some(expected_threads),
            "row thread_count should match tier",
        )?;
        ensure(
            !string_field(&entry, "stress_kernel_id", "entry")?.is_empty(),
            "stress_kernel_id should be non-empty",
        )?;
        ensure(
            as_object(field(&entry, "counters", "entry")?, "entry.counters")?
                .values()
                .all(Value::is_number),
            "counters should contain numeric values",
        )?;
        ensure(
            as_array(
                field(&entry, "failure_signatures", "entry")?,
                "entry.failure_signatures",
            )?
            .is_empty(),
            "passing rows should not carry failure signatures",
        )?;
        ensure(
            string_field(&entry, "source_commit", "entry")?
                == string_field(&report, "source_commit", "report")?,
            "row source_commit should match report",
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
    ensure_eq(row_count, 32usize, "JSONL row count")?;
    for scenario_id in BOTH_MODE_SCENARIOS {
        let modes = modes_by_scenario
            .get(*scenario_id)
            .ok_or_else(|| test_error("missing rows for scenario"))?;
        for mode in REQUIRED_MODES {
            ensure(
                modes.contains(*mode),
                "scenario missing required runtime mode",
            )?;
        }
        let tiers = tiers_by_scenario
            .get(*scenario_id)
            .ok_or_else(|| test_error("missing tiers for scenario"))?;
        ensure(
            tiers.contains("smoke") && tiers.contains("normal"),
            "scenario missing smoke or normal tier",
        )?;
    }
    for scenario_id in HARDENED_ONLY_SCENARIOS {
        let modes = modes_by_scenario
            .get(*scenario_id)
            .ok_or_else(|| test_error("missing rows for hardened scenario"))?;
        ensure_eq(
            modes.iter().copied().collect::<Vec<_>>(),
            vec!["hardened"],
            "hardened-only scenario modes",
        )?;
        let tiers = tiers_by_scenario
            .get(*scenario_id)
            .ok_or_else(|| test_error("missing tiers for hardened scenario"))?;
        ensure(
            tiers.contains("smoke") && tiers.contains("normal"),
            "hardened scenario missing smoke or normal tier",
        )?;
    }
    Ok(())
}

#[test]
fn runner_fails_closed_for_missing_seed() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    set_object_field(first, "seed", json!(""), "scenario")?;
    let report = run_orchard_with_manifest(&root, "missing_seed", &manifest)?;
    expect_error_signature(&report, "missing_scenario_seed")
}

#[test]
fn runner_fails_closed_for_missing_oracle() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    set_object_field(first, "oracle_kind", json!(""), "scenario")?;
    let report = run_orchard_with_manifest(&root, "missing_oracle", &manifest)?;
    expect_error_signature(&report, "missing_oracle_kind")
}

#[test]
fn runner_fails_closed_for_non_deterministic_seed() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    set_object_field(first, "seed", json!("random-time-seed"), "scenario")?;
    let report = run_orchard_with_manifest(&root, "non_deterministic_seed", &manifest)?;
    expect_error_signature(&report, "non_deterministic_input")
}

#[test]
fn runner_fails_closed_for_unbounded_iterations() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let tiers = manifest
        .get_mut("iteration_tiers")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("iteration_tiers should be mutable"))?;
    let first = tiers
        .first_mut()
        .ok_or_else(|| test_error("manifest should have tiers"))?;
    set_object_field(first, "iterations", json!(1_000_001), "tier")?;
    let report = run_orchard_with_manifest(&root, "unbounded_iterations", &manifest)?;
    expect_error_signature(&report, "unbounded_iteration_count")
}

#[test]
fn runner_fails_closed_for_local_only_runner() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    set_nested_object_field(
        &mut manifest,
        "execution_policy",
        "default_runner",
        json!("local_only"),
        "manifest",
    )?;
    let report = run_orchard_with_manifest(&root, "local_only_runner", &manifest)?;
    expect_error_signature(&report, "local_only_runner")
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
    let report = run_orchard_with_manifest(&root, "stale_source_commit", &manifest)?;
    expect_error_signature(&report, "stale_source_commit")
}

#[test]
fn runner_fails_closed_for_missing_runtime_mode() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    set_object_field(first, "runtime_modes", json!(["strict"]), "scenario")?;
    let report = run_orchard_with_manifest(&root, "missing_runtime_mode", &manifest)?;
    expect_error_signature(&report, "missing_runtime_mode_coverage")
}

#[test]
fn runner_fails_closed_for_missing_normal_tier_kernel() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    let object = first
        .as_object_mut()
        .ok_or_else(|| test_error("scenario should be an object"))?;
    object.remove("normal_tier_kernel");
    let report = run_orchard_with_manifest(&root, "missing_normal_tier_kernel", &manifest)?;
    expect_error_signature(&report, "missing_normal_tier_kernel")
}

#[test]
fn runner_fails_closed_for_missing_counter_field() -> TestResult {
    let root = workspace_root();
    let mut manifest = load_json(&manifest_path(&root))?;
    let first = mutable_scenarios(&mut manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest should have scenarios"))?;
    let counter_fields = first
        .get_mut("normal_tier_kernel")
        .and_then(|kernel| kernel.get_mut("counter_fields"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("counter_fields should be mutable"))?;
    counter_fields.push(json!("counter_that_does_not_exist"));
    let report = run_orchard_with_manifest(&root, "missing_counter_field", &manifest)?;
    expect_error_signature(&report, "missing_counter_field")
}

#[test]
fn runner_summary_declares_required_failure_signatures() -> TestResult {
    let root = workspace_root();
    let run = run_orchard(&root, "summary")?;
    ensure(
        run.output.status.success(),
        "stress orchard runner should pass before summary inspection",
    )?;
    let report = load_json(&run.report)?;
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
