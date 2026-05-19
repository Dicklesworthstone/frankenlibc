//! Integration test: standalone owned TLS startup surface (bd-w1c58).
//!
//! The surface is report-only planning evidence. It must stay locked to the
//! current __tls_get_addr blocker, provider version row, owner ledger entry,
//! and TLS model experiment while keeping replacement claims blocked.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const SURFACE_PATH: &str = "tests/conformance/standalone_owned_tls_startup_surface.v1.json";
const TLS_DIAGNOSTIC_PATH: &str = "tests/conformance/standalone_tls_blocker_diagnostics.v1.json";
const TLS_REMOVAL_PATH: &str = "tests/conformance/standalone_tls_removal_experiment.v1.json";
const TLS_EXPERIMENT_PATH: &str =
    "tests/conformance/standalone_tls_model_startup_experiment.v1.json";
const PLAN_PATH: &str = "tests/conformance/standalone_host_dependency_probe_plan.v1.json";
const VERSION_BURNDOWN_PATH: &str =
    "tests/conformance/standalone_host_version_requirement_burndown.v1.json";
const OWNER_LEDGER_PATH: &str =
    "tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json";
const ROLLUP_PATH: &str = "tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json";
const TLS_SYMBOL: &str = "__tls_get_addr@GLIBC_2.3";
const TLS_REQUIREMENT: &str = "ld-linux-x86-64.so.2:GLIBC_2.3";
const SOURCE_ACTION_ROW: &str = "standalone_host_dependency_probe_plan.current_forge_blocker_projection.blocker_action_required_rows.undefined_tls_symbols";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_standalone_owned_tls_startup_surface.sh")
}

fn load_json(root: &Path, rel: &str) -> TestResult<Value> {
    let path = match rel {
        value if value == SURFACE_PATH => {
            root.join("tests/conformance/standalone_owned_tls_startup_surface.v1.json")
        }
        value if value == TLS_DIAGNOSTIC_PATH => {
            root.join("tests/conformance/standalone_tls_blocker_diagnostics.v1.json")
        }
        value if value == TLS_REMOVAL_PATH => {
            root.join("tests/conformance/standalone_tls_removal_experiment.v1.json")
        }
        value if value == TLS_EXPERIMENT_PATH => {
            root.join("tests/conformance/standalone_tls_model_startup_experiment.v1.json")
        }
        value if value == PLAN_PATH => {
            root.join("tests/conformance/standalone_host_dependency_probe_plan.v1.json")
        }
        value if value == VERSION_BURNDOWN_PATH => {
            root.join("tests/conformance/standalone_host_version_requirement_burndown.v1.json")
        }
        value if value == OWNER_LEDGER_PATH => {
            root.join("tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json")
        }
        value if value == ROLLUP_PATH => {
            root.join("tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json")
        }
        _ => return Err(format!("unknown repo-relative fixture path: {rel}")),
    };
    load_json_path(&path)
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

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn get_path<'a>(mut value: &'a Value, dotted: &str) -> TestResult<&'a Value> {
    let mut missing = false;
    for segment in dotted.split('.') {
        if let Some(next) = value.get(segment) {
            value = next;
        } else {
            missing = true;
            break;
        }
    }
    if missing {
        Err("JSON path segment missing".to_string())
    } else {
        Ok(value)
    }
}

fn string_values(value: &Value, field: &str) -> TestResult<Vec<String>> {
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

fn run_checker(root: &Path, surface: &Path, label: &str) -> TestResult<(Output, PathBuf)> {
    let plan = root.join(PLAN_PATH);
    run_checker_with_plan(root, surface, &plan, label)
}

fn run_checker_with_plan(
    root: &Path,
    surface: &Path,
    plan: &Path,
    label: &str,
) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target/conformance").join(format!(
        "standalone_owned_tls_startup_surface.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_OWNED_TLS_SURFACE", surface)
        .env("FRANKENLIBC_STANDALONE_HOST_DEPENDENCY_PROBE_PLAN", plan)
        .env("FRANKENLIBC_STANDALONE_OWNED_TLS_SURFACE_REPORT", &report)
        .current_dir(root)
        .output()
        .map_err(|err| format!("failed to run owned TLS checker: {err}"))?;
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

fn expect_checker_failure(surface: &Path, label: &str, expected_error: &str) -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, surface, label)?;
    expect_failure_output(output, report, expected_error)
}

fn expect_checker_failure_with_plan(
    surface: &Path,
    plan: &Path,
    label: &str,
    expected_error: &str,
) -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker_with_plan(&root, surface, plan, label)?;
    expect_failure_output(output, report, expected_error)
}

fn expect_failure_output(output: Output, report: PathBuf, expected_error: &str) -> TestResult {
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

fn write_mutated_surface(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut surface = load_json(&root, SURFACE_PATH)?;
    mutate(&mut surface)?;
    let dir = root.join("target/conformance/mutated-owned-tls-surfaces");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&surface)
        .map_err(|err| format!("failed to serialize mutated surface: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn write_mutated_plan(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut plan = load_json(&root, PLAN_PATH)?;
    mutate(&mut plan)?;
    let dir = root.join("target/conformance/mutated-owned-tls-plans");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&plan)
        .map_err(|err| format!("failed to serialize mutated plan: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn first_symbol_row_mut(surface: &mut Value) -> TestResult<&mut Value> {
    surface
        .get_mut("symbol_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .ok_or_else(|| "symbol_rows[0] must exist".to_string())
}

fn live_tls_action_row(plan: &Value) -> TestResult<&Value> {
    get_path(
        plan,
        "current_forge_blocker_projection.blocker_action_required_rows.undefined_tls_symbols",
    )
}

fn set_object_field(value: &mut Value, field: &str, replacement: Value) -> TestResult {
    value
        .as_object_mut()
        .ok_or_else(|| "value must be an object".to_string())?
        .insert(field.to_owned(), replacement);
    Ok(())
}

#[test]
fn surface_manifest_covers_current_tls_diagnostics() -> TestResult {
    let root = workspace_root()?;
    let surface = load_json(&root, SURFACE_PATH)?;
    let diagnostic = load_json(&root, TLS_DIAGNOSTIC_PATH)?;
    let tls_removal = load_json(&root, TLS_REMOVAL_PATH)?;
    let experiment = load_json(&root, TLS_EXPERIMENT_PATH)?;
    let plan = load_json(&root, PLAN_PATH)?;
    let burndown = load_json(&root, VERSION_BURNDOWN_PATH)?;
    let owner_ledger = load_json(&root, OWNER_LEDGER_PATH)?;
    let rollup = load_json(&root, ROLLUP_PATH)?;

    require(
        json_string(&surface, "manifest_id")? == "standalone-owned-tls-startup-surface",
        "manifest id",
    )?;
    require(json_string(&surface, "bead")? == "bd-w1c58", "bead")?;
    require(
        json_field(&surface, "report_policy")?
            .get("promotion_allowed")
            .and_then(Value::as_bool)
            == Some(false),
        "surface must not allow promotion",
    )?;
    require(
        json_string(&surface, "source_action_row")? == SOURCE_ACTION_ROW,
        "surface must point at the live TLS blocker action row",
    )?;

    let diagnostic_symbols = string_values(
        get_path(
            &diagnostic,
            "current_forge_evidence.observed_artifact_symbols",
        )?,
        "undefined_tls_symbols",
    )?;
    let expected_tls_symbol = vec![TLS_SYMBOL.to_owned()];
    require(
        diagnostic_symbols == expected_tls_symbol,
        "TLS diagnostic must expose the current TLS blocker",
    )?;

    let rows = json_array(&surface, "symbol_rows")?;
    require(rows.len() == 1, "exactly one TLS symbol row")?;
    let row = rows
        .first()
        .ok_or_else(|| "surface must have one symbol row".to_string())?;
    require(
        json_string(row, "symbol")? == TLS_SYMBOL,
        "surface symbol row",
    )?;
    require(
        json_string(row, "requirement_id")? == TLS_REQUIREMENT,
        "surface requirement id",
    )?;
    require(
        json_string(row, "owner_surface")? == "tls_startup",
        "surface owner",
    )?;
    require(
        json_string(row, "provider_owner_surface")? == "loader_tls_runtime",
        "provider owner",
    )?;
    let artifact_probe = get_path(&diagnostic, "owned_tls_cache_artifact_probe")?;
    let mut expected_hotspots = Vec::new();
    for bucket in json_array(artifact_probe, "tls_descriptor_buckets")? {
        expected_hotspots.extend(string_values(bucket, "observed_call_site_examples")?);
    }
    require(
        expected_hotspots.len() == 6,
        "diagnostic must expose six residual std TLS descriptor hotspots",
    )?;
    require(
        string_values(row, "source_surface_hotspots")? == expected_hotspots,
        "surface hotspots must track the live residual std TLS descriptor buckets",
    )?;
    let diagnostic_residual_symbols: BTreeSet<String> =
        json_array(artifact_probe, "residual_artifact_tls_emitters")?
            .iter()
            .map(|entry| json_string(entry, "symbol").map(str::to_owned))
            .collect::<TestResult<_>>()?;
    let removal_residual_count = json_array(&tls_removal, "residual_artifact_tls_emitters")?.len();
    require(
        diagnostic_residual_symbols.len() == 6 && removal_residual_count == 6,
        "diagnostic and TLS-removal residual std TLS inventories must both contain six rows",
    )?;

    let version_rows = json_array(&burndown, "version_requirement_matrix")?;
    let tls_version_row = version_rows
        .iter()
        .find(|candidate| {
            candidate.get("requirement_id").and_then(Value::as_str) == Some(TLS_REQUIREMENT)
        })
        .ok_or_else(|| "missing TLS version burndown row".to_string())?;
    require(
        string_values(tls_version_row, "observed_symbols")? == expected_tls_symbol,
        "version row observes TLS symbol",
    )?;

    let action_row = live_tls_action_row(&plan)?;
    require(
        json_string(action_row, "blocking_reason")? == "undefined_tls_symbols",
        "live action row blocking reason",
    )?;
    require(
        json_string(action_row, "owner_surface")? == "tls_startup",
        "live action row owner surface",
    )?;
    require(
        json_string(action_row, "primary_probe_id")? == "nm_dynamic_undefined_symbols",
        "live action row primary probe",
    )?;
    require(
        json_field(action_row, "promotion_allowed")?.as_bool() == Some(false),
        "live action row must not allow promotion",
    )?;
    require(
        string_values(action_row, "current_blocker_values")? == expected_tls_symbol,
        "live action row values must match TLS diagnostic",
    )?;
    require(
        json_array(action_row, "exit_criteria")?.len() >= 2,
        "live action row exit criteria",
    )?;

    let owner_row = json_array(&owner_ledger, "ledger_rows")?
        .iter()
        .find(|candidate| {
            candidate.get("blocking_reason").and_then(Value::as_str)
                == Some("undefined_tls_symbols")
        })
        .ok_or_else(|| "missing owner ledger TLS row".to_string())?;
    require(
        json_string(owner_row, "owner_surface")? == "tls_startup",
        "owner ledger must retain stable TLS startup context",
    )?;

    let rollup_row = json_array(&rollup, "progress_categories")?
        .iter()
        .find(|candidate| {
            candidate.get("category_id").and_then(Value::as_str) == Some("tls_startup")
        })
        .ok_or_else(|| "missing tls_startup rollup row".to_string())?;
    require(
        rollup_row
            .get("last_known_value_count")
            .and_then(Value::as_u64)
            == Some(1),
        "rollup TLS count",
    )?;

    require(
        get_path(&experiment, "comparison")?
            .get("initial_exec_delta_classification")
            .and_then(Value::as_str)
            == Some("unchanged"),
        "TLS experiment must keep initial-exec unchanged",
    )?;
    Ok(())
}

#[test]
fn checker_materializes_owned_tls_surface_report() -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, Path::new(SURFACE_PATH), "ok")?;
    require(
        output.status.success(),
        format!("checker failed\n{}", format_output(&output)),
    )?;
    let report_json = load_json_path(&report)?;
    require(
        json_string(&report_json, "status")? == "pass",
        "report status",
    )?;
    require(
        json_string(&report_json, "claim_status")? == "claim_blocked",
        "claim status",
    )?;
    require(
        json_array(&report_json, "symbol_rows")?.len() == 1,
        "report symbol rows",
    )
}

#[test]
fn checker_rejects_stale_source_commit() -> TestResult {
    let mutated = write_mutated_surface("stale-source", |surface| {
        set_object_field(
            surface,
            "source_commit",
            Value::String("0000000000000000000000000000000000000000".to_owned()),
        )
    })?;
    expect_checker_failure(&mutated, "stale-source", "source_commit")
}

#[test]
fn checker_rejects_missing_tls_row() -> TestResult {
    let mutated = write_mutated_surface("missing-row", |surface| {
        set_object_field(surface, "symbol_rows", Value::Array(vec![]))
    })?;
    expect_checker_failure(
        &mutated,
        "missing-row",
        "symbol_rows must contain exactly one TLS row",
    )
}

#[test]
fn checker_rejects_provider_version_drift() -> TestResult {
    let mutated = write_mutated_surface("provider-drift", |surface| {
        let row = first_symbol_row_mut(surface)?;
        set_object_field(
            row,
            "requirement_id",
            Value::String("ld-linux-x86-64.so.2:GLIBC_2.4".to_owned()),
        )
    })?;
    expect_checker_failure(&mutated, "provider-drift", "requirement_id")
}

#[test]
fn checker_rejects_stale_residual_std_tls_hotspot() -> TestResult {
    let mutated = write_mutated_surface("stale-residual-std-tls-hotspot", |surface| {
        let hotspots = first_symbol_row_mut(surface)?
            .get_mut("source_surface_hotspots")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "source_surface_hotspots must be an array".to_string())?;
        let first = hotspots
            .first_mut()
            .ok_or_else(|| "source_surface_hotspots must have a first entry".to_string())?;
        *first = Value::String("crates/frankenlibc-abi/src/startup_abi.rs".to_owned());
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "stale-residual-std-tls-hotspot",
        "source_surface_hotspots must match live residual std TLS descriptor buckets",
    )
}

#[test]
fn checker_rejects_ready_and_promotion_overclaims() -> TestResult {
    let mutated = write_mutated_surface("ready-overclaim", |surface| {
        {
            let row = first_symbol_row_mut(surface)?;
            set_object_field(
                row,
                "owned_surface_status",
                Value::String("ready".to_owned()),
            )?;
        }
        let summary = surface
            .get_mut("summary")
            .ok_or_else(|| "summary must exist".to_string())?;
        set_object_field(summary, "owned_surface_ready", Value::Bool(true))?;
        let policy = surface
            .get_mut("report_policy")
            .ok_or_else(|| "report_policy must exist".to_string())?;
        set_object_field(policy, "promotion_allowed", Value::Bool(true))
    })?;
    expect_checker_failure(&mutated, "ready-overclaim", "report_policy")
}

#[test]
fn checker_rejects_missing_live_tls_action_row() -> TestResult {
    let root = workspace_root()?;
    let surface = root.join(SURFACE_PATH);
    let mutated_plan = write_mutated_plan("missing-live-tls-action-row", |plan| {
        let action_rows = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(|projection| projection.get_mut("blocker_action_required_rows"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "blocker_action_required_rows must be an object".to_string())?;
        action_rows
            .remove("undefined_tls_symbols")
            .ok_or_else(|| "mutation must remove undefined_tls_symbols".to_string())?;
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &surface,
        &mutated_plan,
        "missing-live-tls-action-row",
        "undefined_tls_symbols: must be an object",
    )
}

#[test]
fn checker_rejects_drifted_live_tls_action_values() -> TestResult {
    let root = workspace_root()?;
    let surface = root.join(SURFACE_PATH);
    let mutated_plan = write_mutated_plan("drifted-live-tls-action-values", |plan| {
        let values = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(|projection| projection.get_mut("blocker_action_required_rows"))
            .and_then(|rows| rows.get_mut("undefined_tls_symbols"))
            .and_then(|row| row.get_mut("current_blocker_values"))
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "current_blocker_values must be an array".to_string())?;
        let first = values
            .first_mut()
            .ok_or_else(|| "mutation needs at least one current blocker value".to_string())?;
        *first = Value::String("__tls_get_addr@GLIBC_999.0".to_owned());
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &surface,
        &mutated_plan,
        "drifted-live-tls-action-values",
        "undefined_tls_symbols.current_blocker_values must match current TLS diagnostic",
    )
}
