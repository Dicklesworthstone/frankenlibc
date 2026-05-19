//! Integration test: standalone blocker burn-down progress rollup (bd-zyck1.94).
//!
//! The committed rollup stays compact and reference-based. The checker report
//! must materialize current values and exit criteria from live blocker action
//! rows while keeping each progress category aligned with exactly one live
//! owner-action surface.

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
const TLS_REMOVAL_EXPERIMENT_PATH: &str =
    "tests/conformance/standalone_tls_removal_experiment.v1.json";
const BLOCKER_ACTION_VALUE_SOURCE: &str = "standalone_host_dependency_probe_plan.current_forge_blocker_projection.blocker_action_required_rows.current_blocker_values";
const BLOCKER_ACTION_EXIT_CRITERIA_SOURCE: &str = "standalone_host_dependency_probe_plan.current_forge_blocker_projection.blocker_action_required_rows.exit_criteria";

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

fn array_contains(value: &Value, field: &str, expected: &str) -> TestResult<bool> {
    Ok(json_array(value, field)?
        .iter()
        .filter_map(Value::as_str)
        .any(|entry| entry == expected))
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

fn run_checker_with_owned_unwind(
    root: &Path,
    rollup: &Path,
    owned_unwind: &Path,
    label: &str,
) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target/conformance").join(format!(
        "standalone_blocker_burndown_progress_rollup.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP", rollup)
        .env(
            "FRANKENLIBC_STANDALONE_OWNED_UNWIND_EXPERIMENT",
            owned_unwind,
        )
        .env("FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP_REPORT", &report)
        .current_dir(root)
        .output()
        .map_err(|err| format!("failed to run rollup checker: {err}"))?;
    Ok((output, report))
}

fn run_checker_with_plan(
    root: &Path,
    rollup: &Path,
    plan: &Path,
    label: &str,
) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target/conformance").join(format!(
        "standalone_blocker_burndown_progress_rollup.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP", rollup)
        .env("FRANKENLIBC_STANDALONE_HOST_DEP_PLAN", plan)
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

fn expect_checker_failure_with_owned_unwind(
    owned_unwind: &Path,
    label: &str,
    expected_error: &str,
) -> TestResult {
    let root = workspace_root()?;
    let (output, report) =
        run_checker_with_owned_unwind(&root, &root.join(ROLLUP_PATH), owned_unwind, label)?;
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

fn expect_checker_failure_with_plan(plan: &Path, label: &str, expected_error: &str) -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker_with_plan(&root, &root.join(ROLLUP_PATH), plan, label)?;
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

fn write_mutated_owned_unwind(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut owned_unwind = load_json(&root, OWNED_UNWIND_EXPERIMENT_PATH)?;
    mutate(&mut owned_unwind)?;
    let dir = root.join("target/conformance/mutated-rollup-sources");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&owned_unwind)
        .map_err(|err| format!("failed to serialize mutated owned unwind source: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn write_mutated_plan(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut plan = load_json(&root, HOST_PROBE_PLAN_PATH)?;
    mutate(&mut plan)?;
    let dir = root.join("target/conformance/mutated-rollup-sources");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&plan)
        .map_err(|err| format!("failed to serialize mutated host dependency plan: {err}"))?;
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

fn action_rows_mut(plan: &mut Value) -> TestResult<&mut serde_json::Map<String, Value>> {
    plan.get_mut("current_forge_blocker_projection")
        .and_then(|projection| projection.get_mut("blocker_action_required_rows"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "blocker_action_required_rows must be an object".to_string())
}

fn partial_experiment_row_mut<'a>(
    rollup: &'a mut Value,
    experiment_id: &str,
) -> TestResult<&'a mut Value> {
    let rows = rollup
        .get_mut("partial_burndown_experiments")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "partial_burndown_experiments must be an array".to_string())?;
    rows.iter_mut()
        .find(|row| row.get("experiment_id").and_then(Value::as_str) == Some(experiment_id))
        .ok_or_else(|| format!("missing partial experiment {experiment_id}"))
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
    let tls_removal = load_json(&root, TLS_REMOVAL_EXPERIMENT_PATH)?;
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
    let action_rows = get_path(
        &plan,
        "current_forge_blocker_projection.blocker_action_required_rows",
    )?
    .as_object()
    .ok_or_else(|| "blocker_action_required_rows must be an object".to_string())?;
    let mut reasons_by_owner: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut value_count_by_owner: BTreeMap<String, usize> = BTreeMap::new();
    for row in json_array(&owner_ledger, "ledger_rows")? {
        let owner = json_string(row, "owner_surface")?.to_owned();
        let reason = json_string(row, "blocking_reason")?.to_owned();
        reasons_by_owner
            .entry(owner.clone())
            .or_default()
            .insert(reason.clone());
        let action_row = action_rows
            .get(&reason)
            .ok_or_else(|| format!("missing live action row for {reason}"))?;
        require(
            json_string(action_row, "blocking_reason")? == reason,
            format!("{reason}: live action row reason mismatch"),
        )?;
        require(
            json_field(action_row, "promotion_allowed")?.as_bool() == Some(false),
            format!("{reason}: live action row must not permit promotion"),
        )?;
        *value_count_by_owner.entry(owner).or_default() +=
            json_array(action_row, "current_blocker_values")?.len();
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
        require(
            json_string(row, "value_source")? == BLOCKER_ACTION_VALUE_SOURCE,
            format!("{category}: value source must use live action rows"),
        )?;
        require(
            json_string(row, "exit_criteria_source")? == BLOCKER_ACTION_EXIT_CRITERIA_SOURCE,
            format!("{category}: exit criteria source must use live action rows"),
        )?;
    }
    require(
        current_reasons.is_empty(),
        "clean forge snapshot should expose no current blocker reasons",
    )?;
    require(
        rollup_reasons == action_rows.keys().cloned().collect::<BTreeSet<_>>(),
        "rollup categories must retain every known blocker action row",
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
        experiments.len() == 2,
        "rollup must expose two partial burndown experiments",
    )?;
    let experiment_by_id: BTreeMap<String, &Value> = experiments
        .iter()
        .map(|experiment| {
            json_string(experiment, "experiment_id").map(|id| (id.to_owned(), experiment))
        })
        .collect::<TestResult<_>>()?;
    let experiment = *experiment_by_id
        .get("owned-unwind-stub-experiment")
        .ok_or_else(|| "missing owned unwind partial experiment".to_string())?;
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
    let live_contract = json_field(&owned_unwind, "live_dependency_evidence_contract")?;
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
    require(
        json_string(experiment, "live_dependency_contract_source")?
            == "standalone_owned_unwind_experiment.live_dependency_evidence_contract",
        "owned unwind partial experiment must reference live dependency contract",
    )?;
    require(
        json_field(experiment, "live_dependency_contract_required")?.as_bool() == Some(true),
        "owned unwind partial experiment must require live dependency contract",
    )?;
    require(
        json_string(
            experiment,
            "live_dependency_contract_status_until_default_forge_consumes_evidence",
        )? == "claim_blocked",
        "owned unwind live contract remains claim-blocked until default forge consumes it",
    )?;
    require(
        json_string(live_contract, "lane_id")? == json_string(experiment, "experiment_lane")?,
        "owned unwind live dependency contract must target partial experiment lane",
    )?;
    require(
        json_field(live_contract, "expected_undefined_unwind_symbol_count")?.as_u64() == Some(0),
        "owned unwind live dependency contract must expect zero undefined unwind symbols",
    )?;
    require(
        array_contains(live_contract, "forbidden_needed_libraries", "libgcc_s.so.1")?,
        "owned unwind live dependency contract must forbid libgcc_s NEEDED",
    )?;
    require(
        array_contains(
            live_contract,
            "forbidden_version_providers",
            "libgcc_s.so.1",
        )?,
        "owned unwind live dependency contract must forbid libgcc_s version providers",
    )?;
    require(
        array_contains(
            live_contract,
            "forbidden_undefined_symbol_prefixes",
            "_Unwind_",
        )?,
        "owned unwind live dependency contract must forbid _Unwind_ undefined prefixes",
    )?;
    require(
        json_string(live_contract, "status_on_violation")? == "fail_closed",
        "owned unwind live dependency contract must fail closed",
    )?;
    require(
        json_field(live_contract, "promotion_allowed_on_pass")?.as_bool() == Some(false),
        "owned unwind live dependency contract must not permit promotion",
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
    let tls_experiment = *experiment_by_id
        .get("owned-tls-cache-source-surface-experiment")
        .ok_or_else(|| "missing TLS removal partial experiment".to_string())?;
    let tls_summary = json_field(&tls_removal, "summary")?;
    require(
        json_string(&tls_removal, "manifest_id")? == "standalone-tls-removal-experiment",
        "TLS removal manifest id",
    )?;
    require(
        json_field(tls_summary, "promotion_allowed")?.as_bool() == Some(false),
        "TLS removal summary forbids promotion",
    )?;
    require(
        json_field(tls_summary, "default_forge_path_unchanged")?.as_bool() == Some(true),
        "TLS removal summary leaves default forge unchanged",
    )?;
    require(
        json_string(tls_experiment, "category_id")? == "tls_startup",
        "TLS partial experiment category",
    )?;
    require(
        json_string(tls_experiment, "source_manifest")? == TLS_REMOVAL_EXPERIMENT_PATH,
        "TLS partial experiment source manifest",
    )?;
    require(
        json_string(tls_experiment, "baseline_lane")? == json_string(tls_summary, "baseline_lane")?,
        "TLS partial experiment baseline lane",
    )?;
    require(
        json_string(tls_experiment, "experiment_lane")?
            == json_string(tls_summary, "experiment_lane")?,
        "TLS partial experiment lane",
    )?;
    let tls_baseline = json_field(tls_summary, "tls_blocker_symbol_count_baseline")?
        .as_u64()
        .ok_or_else(|| "TLS summary baseline count must be u64".to_string())?;
    let tls_owned_when_complete = json_field(
        tls_summary,
        "tls_blocker_symbol_count_owned_tls_cache_when_complete",
    )?
    .as_u64()
    .ok_or_else(|| "TLS summary completion count must be u64".to_string())?;
    require(
        json_field(tls_experiment, "baseline_value_count")?.as_u64() == Some(tls_baseline),
        "TLS partial experiment baseline count",
    )?;
    require(
        json_field(tls_experiment, "experiment_value_count")?.as_u64()
            == Some(tls_owned_when_complete),
        "TLS partial experiment completion count",
    )?;
    require(
        json_field(tls_experiment, "reduced_value_count")?.as_u64()
            == Some(tls_baseline - tls_owned_when_complete),
        "TLS partial experiment reduced count",
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
        categories.len() == 10,
        "report must materialize ten owner-surface categories",
    )?;
    for row in categories {
        let category = json_string(row, "category_id")?;
        require(
            json_array(row, "last_known_values")?.is_empty(),
            format!("{category}: values must be empty after clean default forge"),
        )?;
        let action_rows = json_array(row, "blocker_action_rows")?;
        require(
            !action_rows.is_empty(),
            format!("{category}: per-reason blocker action rows must be materialized"),
        )?;
        require(
            action_rows.len() == json_array(row, "source_blocking_reasons")?.len(),
            format!("{category}: action rows must match source blocking reasons"),
        )?;
        require(
            !json_array(row, "target_exit_criteria")?.is_empty(),
            format!("{category}: exit criteria must be materialized in report"),
        )?;
    }
    let category_by_id: BTreeMap<String, &Value> = categories
        .iter()
        .map(|row| json_string(row, "category_id").map(|id| (id.to_owned(), row)))
        .collect::<TestResult<_>>()?;
    let runtime_linkage = *category_by_id
        .get("runtime_linkage")
        .ok_or_else(|| "missing runtime_linkage category".to_string())?;
    require(
        string_set(runtime_linkage, "source_blocking_reasons")?
            == BTreeSet::from(["host_needed_libraries_present".to_string()]),
        "runtime_linkage must only cover aggregate host-needed libraries",
    )?;
    let runtime_action_by_reason: BTreeMap<String, &Value> =
        json_array(runtime_linkage, "blocker_action_rows")?
            .iter()
            .map(|row| json_string(row, "blocking_reason").map(|reason| (reason.to_owned(), row)))
            .collect::<TestResult<_>>()?;
    let host_needed = *runtime_action_by_reason
        .get("host_needed_libraries_present")
        .ok_or_else(|| "missing host-needed row".to_string())?;
    require(
        json_string(host_needed, "owner_surface")? == "runtime_linkage",
        "host-needed row owner surface",
    )?;
    require(
        json_string(host_needed, "primary_probe_id")? == "readelf_dynamic_dependencies",
        "host-needed row primary probe",
    )?;
    let direct_category = *category_by_id
        .get("direct_dynamic_dependencies")
        .ok_or_else(|| "missing direct_dynamic_dependencies category".to_string())?;
    require(
        string_set(direct_category, "source_blocking_reasons")?
            == BTreeSet::from(["host_direct_needed_libraries_present".to_string()]),
        "direct_dynamic_dependencies must only cover direct DT_NEEDED blockers",
    )?;
    let direct_action_by_reason: BTreeMap<String, &Value> =
        json_array(direct_category, "blocker_action_rows")?
            .iter()
            .map(|row| json_string(row, "blocking_reason").map(|reason| (reason.to_owned(), row)))
            .collect::<TestResult<_>>()?;
    let direct_needed = *direct_action_by_reason
        .get("host_direct_needed_libraries_present")
        .ok_or_else(|| "missing direct NEEDED row".to_string())?;
    require(
        json_string(direct_needed, "owner_surface")? == "direct_dynamic_dependencies",
        "direct NEEDED row owner surface",
    )?;
    require(
        json_string(direct_needed, "primary_probe_id")? == "readelf_dynamic_dependencies",
        "direct NEEDED row primary probe",
    )?;
    require(
        json_array(direct_needed, "current_blocker_values")?.is_empty(),
        "direct NEEDED row must have no current blocker values",
    )?;
    require(
        !array_contains(direct_needed, "current_blocker_values", "libc.so.6")?,
        "direct NEEDED row must not inherit transitive libc value",
    )?;
    let resolved_category = *category_by_id
        .get("loader_resolution")
        .ok_or_else(|| "missing loader_resolution category".to_string())?;
    require(
        string_set(resolved_category, "source_blocking_reasons")?
            == BTreeSet::from(["host_resolved_libraries_present".to_string()]),
        "loader_resolution must only cover ldd-resolution blockers",
    )?;
    let resolved_action_by_reason: BTreeMap<String, &Value> =
        json_array(resolved_category, "blocker_action_rows")?
            .iter()
            .map(|row| json_string(row, "blocking_reason").map(|reason| (reason.to_owned(), row)))
            .collect::<TestResult<_>>()?;
    let resolved = *resolved_action_by_reason
        .get("host_resolved_libraries_present")
        .ok_or_else(|| "missing resolved library row".to_string())?;
    require(
        json_string(resolved, "owner_surface")? == "loader_resolution",
        "resolved library row owner surface",
    )?;
    require(
        json_string(resolved, "primary_probe_id")? == "ldd_runtime_resolution",
        "resolved library row primary probe",
    )?;
    require(
        json_array(resolved, "current_blocker_values")?.is_empty(),
        "resolved library row must have no current blocker values",
    )?;
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "last_known_value_count",
        )?
        .as_u64()
            == Some(0),
        "report summary last_known_value_count must be 0",
    )?;
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "current_blocking_reason_count",
        )?
        .as_u64()
            == Some(0),
        "report summary current blocker count must be 0",
    )?;
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "blocked_progress_category_count",
        )?
        .as_u64()
            == Some(0),
        "report summary blocked category count must be 0",
    )?;
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "partial_burndown_experiment_count",
        )?
        .as_u64()
            == Some(2),
        "report summary partial experiment count",
    )?;
    require(
        json_field(
            json_field(&report_json, "summary")?,
            "report_only_reduced_value_count",
        )?
        .as_u64()
            == Some(13),
        "report summary report-only reduced value count",
    )?;
    let experiments = json_array(&report_json, "partial_burndown_experiments")?;
    require(
        experiments.len() == 2,
        "report must materialize two partial burndown experiments",
    )?;
    let experiment_by_id: BTreeMap<String, &Value> = experiments
        .iter()
        .map(|experiment| {
            json_string(experiment, "experiment_id").map(|id| (id.to_owned(), experiment))
        })
        .collect::<TestResult<_>>()?;
    let owned_unwind = *experiment_by_id
        .get("owned-unwind-stub-experiment")
        .ok_or_else(|| "missing owned unwind report experiment".to_string())?;
    let live_contract = json_field(owned_unwind, "live_dependency_contract")?;
    require(
        json_string(live_contract, "contract_validation_status")? == "pass",
        "owned unwind live dependency contract must pass in report",
    )?;
    require(
        json_string(live_contract, "source")?
            == "standalone_owned_unwind_experiment.live_dependency_evidence_contract",
        "owned unwind live dependency contract report source",
    )?;
    require(
        array_contains(live_contract, "forbidden_needed_libraries", "libgcc_s.so.1")?,
        "owned unwind report must materialize forbidden libgcc needed library",
    )?;
    require(
        array_contains(
            live_contract,
            "forbidden_version_providers",
            "libgcc_s.so.1",
        )?,
        "owned unwind report must materialize forbidden libgcc version provider",
    )?;
    require(
        array_contains(
            live_contract,
            "forbidden_undefined_symbol_prefixes",
            "_Unwind_",
        )?,
        "owned unwind report must materialize forbidden unwind prefix",
    )?;
    require(
        json_string(
            live_contract,
            "status_until_default_forge_consumes_evidence",
        )? == "claim_blocked",
        "owned unwind live dependency evidence must stay claim-blocked",
    )
}

#[test]
fn checker_rejects_missing_current_blocker_reason_from_category() -> TestResult {
    let mutated = write_mutated_rollup("rollup-missing-reason", |rollup| {
        let row = progress_row_mut(rollup, "loader_resolution")?;
        row.get_mut("source_blocking_reasons")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "source_blocking_reasons must be array".to_string())?
            .retain(|reason| reason.as_str() != Some("host_resolved_libraries_present"));
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "rollup-missing-reason",
        "progress_categories[loader_resolution].source_blocking_reasons must match owner ledger rows for loader_resolution",
    )
}

#[test]
fn checker_rejects_live_action_owner_surface_drift() -> TestResult {
    let mutated = write_mutated_plan("plan-live-action-owner-drift", |plan| {
        let rows = action_rows_mut(plan)?;
        let row = rows
            .get_mut("host_resolved_libraries_present")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                "host_resolved_libraries_present action row must be object".to_string()
            })?;
        row.insert(
            "owner_surface".to_string(),
            Value::String("runtime_linkage".to_string()),
        );
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &mutated,
        "plan-live-action-owner-drift",
        "progress_categories[loader_resolution].host_resolved_libraries_present.owner_surface must match progress category loader_resolution",
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
fn checker_rejects_missing_live_action_row() -> TestResult {
    let mutated = write_mutated_plan("plan-missing-live-action-row", |plan| {
        action_rows_mut(plan)?.remove("undefined_tls_symbols");
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &mutated,
        "plan-missing-live-action-row",
        "progress_categories[tls_startup].undefined_tls_symbols.owner_surface must match progress category tls_startup",
    )
}

#[test]
fn checker_rejects_live_action_value_drift() -> TestResult {
    let mutated = write_mutated_plan("plan-live-action-value-drift", |plan| {
        let rows = action_rows_mut(plan)?;
        let row = rows
            .get_mut("host_version_requirements")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "host_version_requirements action row must be object".to_string())?;
        row.insert(
            "current_blocker_values".to_string(),
            Value::Array(vec![
                Value::String("stale-provider:STALE_1.0".to_string()),
                Value::String("libgcc_s.so.1:GCC_3.0".to_string()),
                Value::String("libgcc_s.so.1:GCC_3.3".to_string()),
                Value::String("libgcc_s.so.1:GCC_4.2.0".to_string()),
            ]),
        );
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &mutated,
        "plan-live-action-value-drift",
        "current_forge_blocker_projection.blocker_action_required_rows.host_version_requirements.current_blocker_values must match snapshot blocker values",
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
        let row = partial_experiment_row_mut(rollup, "owned-unwind-stub-experiment")?;
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

#[test]
fn checker_rejects_missing_owned_unwind_live_dependency_contract_source() -> TestResult {
    let mutated = write_mutated_owned_unwind("owned-unwind-missing-live-contract", |owned| {
        owned
            .as_object_mut()
            .ok_or_else(|| "owned unwind source must be object".to_string())?
            .remove("live_dependency_evidence_contract");
        Ok(())
    })?;
    expect_checker_failure_with_owned_unwind(
        &mutated,
        "owned-unwind-missing-live-contract",
        "owned_unwind.live_dependency_evidence_contract: must be an object",
    )
}

#[test]
fn checker_rejects_non_fail_closed_owned_unwind_live_dependency_contract() -> TestResult {
    let mutated = write_mutated_owned_unwind("owned-unwind-live-contract-open", |owned| {
        json_field(owned, "live_dependency_evidence_contract")?;
        owned
            .get_mut("live_dependency_evidence_contract")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "live dependency contract must be object".to_string())?
            .insert(
                "status_on_violation".to_string(),
                Value::String("warn_only".to_string()),
            );
        Ok(())
    })?;
    expect_checker_failure_with_owned_unwind(
        &mutated,
        "owned-unwind-live-contract-open",
        "owned_unwind.live_dependency_evidence_contract.status_on_violation must be fail_closed",
    )
}

#[test]
fn checker_rejects_tls_partial_experiment_count_drift() -> TestResult {
    let mutated = write_mutated_rollup("rollup-tls-partial-count-drift", |rollup| {
        let row = partial_experiment_row_mut(rollup, "owned-tls-cache-source-surface-experiment")?;
        row.as_object_mut()
            .ok_or_else(|| "partial experiment row must be object".to_string())?
            .insert("experiment_value_count".to_string(), Value::from(1));
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "rollup-tls-partial-count-drift",
        "partial_burndown_experiments[owned-tls-cache-source-surface-experiment].experiment_value_count must match TLS removal summary",
    )
}
