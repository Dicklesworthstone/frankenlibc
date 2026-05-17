//! Integration test: standalone blocker burn-down progress rollup (bd-zyck1.94).
//!
//! The committed rollup stays compact and reference-based. The checker report
//! must materialize current values, owners, and exit criteria from the blocker
//! snapshot, version matrix, and owner/action ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const ROLLUP_PATH: &str = "tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json";
const OWNER_LEDGER_PATH: &str =
    "tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json";
const HOST_PROBE_PLAN_PATH: &str =
    "tests/conformance/standalone_host_dependency_probe_plan.v1.json";
const VERSION_BURNDOWN_PATH: &str =
    "tests/conformance/standalone_host_version_requirement_burndown.v1.json";
const OWNED_UNWIND_EXPERIMENT_PATH: &str =
    "tests/conformance/standalone_owned_unwind_experiment.v1.json";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_standalone_blocker_burndown_progress_rollup.sh")
}

fn load_json(root: &Path, rel: &str) -> TestResult<Value> {
    let path = root.join(rel);
    let content =
        std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn load_json_path(path: &Path) -> TestResult<Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| format!("{field} must be present"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))
}

fn string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    json_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn run_checker(root: &Path, rollup: &Path, label: &str) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target/conformance").join(format!(
        "standalone_blocker_burndown_progress_rollup.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP", rollup)
        .env("FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP_REPORT", &report)
        .current_dir(root)
        .output()
        .map_err(|err| format!("failed to run rollup checker: {err}"))?;
    Ok((output, report))
}

fn format_output(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_checker_failure(rollup: &Path, label: &str, expected_error: &str) -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, rollup, label)?;
    require(
        !output.status.success(),
        format!("checker unexpectedly passed\n{}", format_output(&output)),
    )?;
    let report_json = load_json_path(&report)?;
    let errors = json_array(&report_json, "errors")?;
    require(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(expected_error)),
        format!("expected error {expected_error:?}; report={report_json:?}"),
    )
}

fn unique_label(prefix: &str) -> TestResult<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time before UNIX_EPOCH: {err}"))?
        .as_nanos();
    Ok(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn write_mutated_rollup(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut rollup = load_json(&root, ROLLUP_PATH)?;
    mutate(&mut rollup)?;
    let dir = root.join("target/conformance/mutated-rollups");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&rollup)
        .map_err(|err| format!("failed to serialize mutated rollup: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn progress_row_mut<'a>(rollup: &'a mut Value, category: &str) -> TestResult<&'a mut Value> {
    let rows = rollup
        .get_mut("progress_categories")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "progress_categories must be an array".to_string())?;
    rows.iter_mut()
        .find(|row| row.get("category_id").and_then(Value::as_str) == Some(category))
        .ok_or_else(|| format!("missing category {category}"))
}

fn provider_row_mut<'a>(rollup: &'a mut Value, provider: &str) -> TestResult<&'a mut Value> {
    let rows = rollup
        .get_mut("version_provider_rollup")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "version_provider_rollup must be an array".to_string())?;
    rows.iter_mut()
        .find(|row| row.get("provider_library").and_then(Value::as_str) == Some(provider))
        .ok_or_else(|| format!("missing provider {provider}"))
}

fn get_path<'a>(mut value: &'a Value, dotted: &str) -> TestResult<&'a Value> {
    for segment in dotted.split('.') {
        value = value
            .get(segment)
            .ok_or_else(|| format!("{dotted}: missing {segment}"))?;
    }
    Ok(value)
}

fn matrix_requirement_ids_by_provider(
    version_burndown: &Value,
) -> TestResult<BTreeMap<String, BTreeSet<String>>> {
    let mut by_provider: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in json_array(version_burndown, "version_requirement_matrix")? {
        let provider = json_string(row, "provider_library")?.to_owned();
        let id = json_string(row, "requirement_id")?.to_owned();
        by_provider.entry(provider).or_default().insert(id);
    }
    Ok(by_provider)
}

#[test]
fn rollup_manifest_covers_owner_ledger_and_version_matrix() -> TestResult {
    let root = workspace_root()?;
    let rollup = load_json(&root, ROLLUP_PATH)?;
    let owner_ledger = load_json(&root, OWNER_LEDGER_PATH)?;
    let plan = load_json(&root, HOST_PROBE_PLAN_PATH)?;
    let version_burndown = load_json(&root, VERSION_BURNDOWN_PATH)?;
    let owned_unwind = load_json(&root, OWNED_UNWIND_EXPERIMENT_PATH)?;
    require(
        json_string(&rollup, "manifest_id")? == "standalone_blocker_burndown_progress_rollup",
        "manifest id",
    )?;
    require(json_string(&rollup, "bead")? == "bd-zyck1.94", "bead")?;
    require(
        json_field(&rollup, "rollup_policy")?
            .get("duplicate_source_values_in_manifest")
            .and_then(Value::as_bool)
            == Some(false),
        "rollup manifest must not duplicate source values",
    )?;

    let current_reasons = string_set(
        get_path(
            &plan,
            "current_forge_blocker_projection.current_forge_blocker_value_snapshot",
        )?,
        "blocking_reasons",
    )?;
    let mut reasons_by_owner: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut value_count_by_owner: BTreeMap<String, usize> = BTreeMap::new();
    for row in json_array(&owner_ledger, "ledger_rows")? {
        let owner = json_string(row, "owner_surface")?.to_owned();
        let reason = json_string(row, "blocking_reason")?.to_owned();
        require(
            current_reasons.contains(&reason),
            format!("owner ledger reason {reason} must be current"),
        )?;
        reasons_by_owner
            .entry(owner.clone())
            .or_default()
            .insert(reason);
        *value_count_by_owner.entry(owner).or_default() +=
            json_array(row, "current_blocker_values")?.len();
    }

    let mut rollup_reasons = BTreeSet::new();
    for row in json_array(&rollup, "progress_categories")? {
        let category = json_string(row, "category_id")?;
        let reasons = string_set(row, "source_blocking_reasons")?;
        require(
            reasons_by_owner.get(category) == Some(&reasons),
            format!("{category}: source reasons must match owner ledger"),
        )?;
        rollup_reasons.extend(reasons);
        require(
            json_field(row, "current_reason_count")?.as_u64()
                == Some(
                    reasons_by_owner
                        .get(category)
                        .ok_or_else(|| format!("missing owner {category}"))?
                        .len() as u64,
                ),
            format!("{category}: reason count mismatch"),
        )?;
        require(
            json_field(row, "last_known_value_count")?.as_u64()
                == Some(*value_count_by_owner.get(category).unwrap_or(&0) as u64),
            format!("{category}: value count mismatch"),
        )?;
    }
    require(
        rollup_reasons == current_reasons,
        "rollup categories must cover every current blocker reason",
    )?;

    let provider_requirements = matrix_requirement_ids_by_provider(&version_burndown)?;
    for row in json_array(&rollup, "version_provider_rollup")? {
        let provider = json_string(row, "provider_library")?;
        let ids = string_set(row, "source_requirement_ids")?;
        require(
            provider_requirements.get(provider) == Some(&ids),
            format!("{provider}: provider rollup must match version matrix"),
        )?;
    }

    let experiments = json_array(&rollup, "partial_burndown_experiments")?;
    require(
        experiments.len() == 1,
        "rollup must expose one partial burndown experiment",
    )?;
    let experiment = &experiments[0];
    let owned_summary = json_field(&owned_unwind, "summary")?;
    require(
        json_string(&owned_unwind, "manifest_id")? == "standalone-owned-unwind-experiment",
        "owned unwind manifest id",
    )?;
    require(
        json_field(owned_summary, "report_only")?.as_bool() == Some(true),
        "owned unwind summary remains report-only",
    )?;
    require(
        json_field(owned_summary, "promotion_allowed")?.as_bool() == Some(false),
        "owned unwind summary forbids promotion",
    )?;
    require(
        json_field(owned_summary, "default_forge_path_unchanged")?.as_bool() == Some(true),
        "owned unwind summary leaves default forge unchanged",
    )?;
    require(
        json_string(experiment, "experiment_id")? == "owned-unwind-stub-experiment",
        "partial experiment id",
    )?;
    require(
        json_string(experiment, "category_id")? == "unwind_runtime",
        "partial experiment category",
    )?;
    require(
        json_string(experiment, "source_manifest")? == OWNED_UNWIND_EXPERIMENT_PATH,
        "partial experiment source manifest",
    )?;
    require(
        json_string(experiment, "baseline_lane")? == json_string(owned_summary, "baseline_lane")?,
        "partial experiment baseline lane",
    )?;
    require(
        json_string(experiment, "experiment_lane")?
            == json_string(owned_summary, "experiment_lane")?,
        "partial experiment lane",
    )?;
    let baseline = json_field(owned_summary, "blocker_symbol_count_baseline")?
        .as_u64()
        .ok_or_else(|| "owned summary baseline count must be u64".to_string())?;
    let owned_when_complete = json_field(
        owned_summary,
        "blocker_symbol_count_owned_unwind_when_complete",
    )?
    .as_u64()
    .ok_or_else(|| "owned summary completion count must be u64".to_string())?;
    require(
        json_field(experiment, "baseline_value_count")?.as_u64() == Some(baseline),
        "partial experiment baseline count",
    )?;
    require(
        json_field(experiment, "experiment_value_count")?.as_u64() == Some(owned_when_complete),
        "partial experiment completion count",
    )?;
    require(
        json_field(experiment, "reduced_value_count")?.as_u64()
            == Some(baseline - owned_when_complete),
        "partial experiment reduced count",
    )?;
    Ok(())
}

#[test]
fn checker_materializes_current_values_and_exit_criteria() -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, &root.join(ROLLUP_PATH), "canonical")?;
    require(
        output.status.success(),
        format!(
            "checker failed canonical rollup\n{}",
            format_output(&output)
        ),
    )?;
    let report_json = load_json_path(&report)?;
    require(
        json_string(&report_json, "status")? == "pass",
        "checker report status must pass",
    )?;
    let categories = json_array(&report_json, "progress_categories")?;
    require(
        categories.len() == 8,
        "report must materialize eight categories",
    )?;
    for row in categories {
        let category = json_string(row, "category_id")?;
        require(
            !json_array(row, "last_known_values")?.is_empty(),
            format!("{category}: values must be materialized in report"),
        )?;
        require(
            !json_array(row, "target_exit_criteria")?.is_empty(),
            format!("{category}: exit criteria must be materialized in report"),
        )?;
    }
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "last_known_value_count",
        )?
        .as_u64()
            == Some(34),
        "report summary last_known_value_count must be 34",
    )?;
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "partial_burndown_experiment_count",
        )?
        .as_u64()
            == Some(1),
        "report summary partial experiment count",
    )?;
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "report_only_reduced_value_count",
        )?
        .as_u64()
            == Some(12),
        "report summary report-only reduced value count",
    )?;
    let experiments = json_array(&report_json, "partial_burndown_experiments")?;
    require(
        experiments.len() == 1,
        "report must materialize one partial burndown experiment",
    )
}

#[test]
fn checker_rejects_missing_current_blocker_reason_from_category() -> TestResult {
    let mutated = write_mutated_rollup("rollup-missing-reason", |rollup| {
        let row = progress_row_mut(rollup, "runtime_linkage")?;
        row.get_mut("source_blocking_reasons")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "source_blocking_reasons must be array".to_string())?
            .retain(|reason| reason.as_str() != Some("host_resolved_libraries_present"));
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "rollup-missing-reason",
        "progress_categories[runtime_linkage].source_blocking_reasons must match owner ledger rows for runtime_linkage",
    )
}

#[test]
fn checker_rejects_stale_value_count() -> TestResult {
    let mutated = write_mutated_rollup("rollup-stale-count", |rollup| {
        let row = progress_row_mut(rollup, "unwind_runtime")?;
        row.as_object_mut()
            .ok_or_else(|| "row must be object".to_string())?
            .insert("last_known_value_count".to_string(), Value::from(11));
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "rollup-stale-count",
        "progress_categories[unwind_runtime].last_known_value_count mismatch",
    )
}

#[test]
fn checker_rejects_version_provider_drift() -> TestResult {
    let mutated = write_mutated_rollup("rollup-version-provider-drift", |rollup| {
        let row = provider_row_mut(rollup, "libgcc_s.so.1")?;
        row.get_mut("source_requirement_ids")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "source_requirement_ids must be array".to_string())?
            .pop();
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "rollup-version-provider-drift",
        "version_provider_rollup[libgcc_s.so.1].source_requirement_ids must match version matrix provider rows",
    )
}

#[test]
fn checker_rejects_partial_experiment_overclaim() -> TestResult {
    let mutated = write_mutated_rollup("rollup-partial-overclaim", |rollup| {
        let row = rollup
            .get_mut("partial_burndown_experiments")
            .and_then(Value::as_array_mut)
            .and_then(|rows| rows.first_mut())
            .ok_or_else(|| "partial_burndown_experiments[0] must exist".to_string())?;
        row.as_object_mut()
            .ok_or_else(|| "partial experiment row must be object".to_string())?
            .insert("promotion_allowed".to_string(), Value::Bool(true));
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "rollup-partial-overclaim",
        "partial_burndown_experiments[owned-unwind-stub-experiment].promotion_allowed must be false",
    )
}
