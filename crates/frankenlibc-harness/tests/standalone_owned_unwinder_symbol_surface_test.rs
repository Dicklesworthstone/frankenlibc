//! Integration test: standalone owned unwinder symbol surface (bd-zyck1.95).
//!
//! The surface is report-only planning evidence. It must stay locked to the
//! current _Unwind_* blocker set, provider version rows, and unwind owner
//! ledger while keeping replacement claims blocked.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const SURFACE_PATH: &str = "tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json";
const DIAGNOSTICS_PATH: &str =
    "tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json";
const PLAN_PATH: &str = "tests/conformance/standalone_host_dependency_probe_plan.v1.json";
const VERSION_BURNDOWN_PATH: &str =
    "tests/conformance/standalone_host_version_requirement_burndown.v1.json";
const OWNER_LEDGER_PATH: &str =
    "tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json";
const ROLLUP_PATH: &str = "tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json";
const SOURCE_ACTION_ROW: &str = "standalone_host_dependency_probe_plan.current_forge_blocker_projection.blocker_action_required_rows.undefined_unwind_symbols";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_standalone_owned_unwinder_symbol_surface.sh")
}

fn load_json(root: &Path, rel: &str) -> TestResult<Value> {
    load_json_path(&root.join(rel))
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

fn get_path<'a>(mut value: &'a Value, dotted: &str) -> TestResult<&'a Value> {
    for segment in dotted.split('.') {
        value = value
            .get(segment)
            .ok_or_else(|| format!("{dotted}: missing {segment}"))?;
    }
    Ok(value)
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
        "standalone_owned_unwinder_symbol_surface.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_OWNED_UNWINDER_SURFACE", surface)
        .env("FRANKENLIBC_STANDALONE_HOST_DEPENDENCY_PROBE_PLAN", plan)
        .env(
            "FRANKENLIBC_STANDALONE_OWNED_UNWINDER_SURFACE_REPORT",
            &report,
        )
        .current_dir(root)
        .output()
        .map_err(|err| format!("failed to run owned-unwinder checker: {err}"))?;
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
    let dir = root.join("target/conformance/mutated-owned-unwinder-surfaces");
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
    let dir = root.join("target/conformance/mutated-owned-unwinder-plans");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&plan)
        .map_err(|err| format!("failed to serialize mutated plan: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn symbol_row_mut<'a>(surface: &'a mut Value, symbol: &str) -> TestResult<&'a mut Value> {
    let rows = surface
        .get_mut("symbol_rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "symbol_rows must be an array".to_string())?;
    rows.iter_mut()
        .find(|row| row.get("symbol").and_then(Value::as_str) == Some(symbol))
        .ok_or_else(|| format!("missing symbol row {symbol}"))
}

fn set_object_field(value: &mut Value, field: &str, replacement: Value) -> TestResult {
    value
        .as_object_mut()
        .ok_or_else(|| "value must be an object".to_string())?
        .insert(field.to_owned(), replacement);
    Ok(())
}

fn current_unwind_symbols(diagnostics: &Value) -> TestResult<BTreeSet<String>> {
    string_set(
        get_path(
            diagnostics,
            "current_forge_evidence.evidence_command_results.nm_dynamic",
        )?,
        "observed_undefined_unwind_symbols",
    )
}

fn live_unwind_action_row(plan: &Value) -> TestResult<&Value> {
    get_path(
        plan,
        "current_forge_blocker_projection.blocker_action_required_rows.undefined_unwind_symbols",
    )
}

fn version_symbols_by_requirement(
    burndown: &Value,
) -> TestResult<BTreeMap<String, BTreeSet<String>>> {
    let mut by_requirement = BTreeMap::new();
    for row in json_array(burndown, "version_requirement_matrix")? {
        if json_string(row, "provider_library")? != "libgcc_s.so.1" {
            continue;
        }
        let secondary = string_set(row, "secondary_blocking_reasons")?;
        if !secondary.contains("undefined_unwind_symbols") {
            continue;
        }
        by_requirement.insert(
            json_string(row, "requirement_id")?.to_owned(),
            string_set(row, "observed_symbols")?,
        );
    }
    Ok(by_requirement)
}

#[test]
fn surface_manifest_covers_current_unwind_diagnostics() -> TestResult {
    let root = workspace_root()?;
    let surface = load_json(&root, SURFACE_PATH)?;
    let diagnostics = load_json(&root, DIAGNOSTICS_PATH)?;
    let plan = load_json(&root, PLAN_PATH)?;
    let burndown = load_json(&root, VERSION_BURNDOWN_PATH)?;
    let owner_ledger = load_json(&root, OWNER_LEDGER_PATH)?;
    let rollup = load_json(&root, ROLLUP_PATH)?;

    require(
        json_string(&surface, "manifest_id")? == "standalone-owned-unwinder-symbol-surface",
        "manifest id",
    )?;
    require(json_string(&surface, "bead")? == "bd-zyck1.95", "bead")?;
    require(
        json_field(&surface, "report_policy")?
            .get("promotion_allowed")
            .and_then(Value::as_bool)
            == Some(false),
        "surface must not allow promotion",
    )?;
    require(
        json_string(&surface, "source_action_row")? == SOURCE_ACTION_ROW,
        "surface must point at the live unwind blocker action row",
    )?;

    let current_symbols = current_unwind_symbols(&diagnostics)?;
    require(
        current_symbols.len() == 12,
        "diagnostics must expose twelve current unwind blockers",
    )?;
    let rows = json_array(&surface, "symbol_rows")?;
    let row_symbols: BTreeSet<_> = rows
        .iter()
        .map(|row| json_string(row, "symbol").map(str::to_owned))
        .collect::<TestResult<_>>()?;
    require(
        row_symbols == current_symbols,
        "symbol rows must cover current diagnostics exactly",
    )?;

    let by_requirement = version_symbols_by_requirement(&burndown)?;
    require(
        by_requirement.len() == 3,
        "libgcc unwind version requirement count",
    )?;
    for row in rows {
        let symbol = json_string(row, "symbol")?;
        let requirement = json_string(row, "requirement_id")?;
        require(
            by_requirement
                .get(requirement)
                .is_some_and(|symbols| symbols.contains(symbol)),
            format!("{symbol}: requirement mapping must include symbol"),
        )?;
        require(
            json_string(row, "owner_surface")? == "unwind_runtime",
            format!("{symbol}: owner surface"),
        )?;
        require(
            json_string(row, "owned_surface_status")? == "unresolved",
            format!("{symbol}: status"),
        )?;
    }

    let action_row = live_unwind_action_row(&plan)?;
    require(
        json_string(action_row, "blocking_reason")? == "undefined_unwind_symbols",
        "live action row blocking reason",
    )?;
    require(
        json_string(action_row, "owner_surface")? == "unwind_runtime",
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
        string_set(action_row, "current_blocker_values")? == current_symbols,
        "live action row values must match diagnostics",
    )?;
    require(
        json_array(action_row, "exit_criteria")?.len() >= 2,
        "live action row exit criteria",
    )?;

    let owner_row = json_array(&owner_ledger, "ledger_rows")?
        .iter()
        .find(|row| json_string(row, "blocking_reason") == Ok("undefined_unwind_symbols"))
        .ok_or_else(|| "owner ledger missing undefined_unwind_symbols row".to_string())?;
    require(
        json_string(owner_row, "owner_surface")? == "unwind_runtime",
        "owner ledger must retain stable unwind owner context",
    )?;
    let rollup_row = json_array(&rollup, "progress_categories")?
        .iter()
        .find(|row| json_string(row, "category_id") == Ok("unwind_runtime"))
        .ok_or_else(|| "rollup missing unwind_runtime row".to_string())?;
    require(
        json_field(rollup_row, "last_known_value_count")?.as_u64() == Some(12),
        "rollup unwind value count",
    )?;
    require(
        json_field(&surface, "summary")?
            .get("unresolved_symbol_count")
            .and_then(Value::as_u64)
            == Some(12),
        "summary unresolved count",
    )
}

#[test]
fn checker_materializes_owned_unwinder_report() -> TestResult {
    let root = workspace_root()?;
    let surface = root.join(SURFACE_PATH);
    let (output, report) = run_checker(&root, &surface, "canonical")?;
    require(
        output.status.success(),
        format!("checker failed\n{}", format_output(&output)),
    )?;
    let report = load_json_path(&report)?;
    require(
        json_string(&report, "status")? == "pass",
        "report status must pass",
    )?;
    require(
        json_string(&report, "claim_status")? == "claim_blocked",
        "claim status must stay blocked",
    )?;
    require(
        json_array(&report, "symbol_rows")?.len() == 12,
        "report must materialize twelve symbol rows",
    )?;
    require(
        json_array(&report, "provider_version_requirement_ids")?.len() == 3,
        "report must materialize three provider version requirements",
    )?;
    require(
        json_field(json_field(&report, "summary")?, "owned_surface_ready")?.as_bool()
            == Some(false),
        "owned surface must not be ready",
    )
}

#[test]
fn checker_rejects_missing_current_unwind_symbol_row() -> TestResult {
    let mutated = write_mutated_surface("missing-unwind-symbol", |surface| {
        let rows = surface
            .get_mut("symbol_rows")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "symbol_rows must be an array".to_string())?;
        let before = rows.len();
        rows.retain(|row| {
            row.get("symbol").and_then(Value::as_str) != Some("_Unwind_Resume@GCC_3.0")
        });
        require(rows.len() + 1 == before, "mutation must remove one row")
    })?;
    expect_checker_failure(
        &mutated,
        "missing-unwind-symbol",
        "symbol_rows must cover every current undefined unwind symbol exactly",
    )
}

#[test]
fn checker_rejects_provider_version_drift() -> TestResult {
    let mutated = write_mutated_surface("provider-version-drift", |surface| {
        let row = symbol_row_mut(surface, "_Unwind_Backtrace@GCC_3.3")?;
        set_object_field(
            row,
            "requirement_id",
            Value::String("libgcc_s.so.1:GCC_3.0".to_owned()),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "provider-version-drift",
        ".requirement_id must match version requirement matrix",
    )
}

#[test]
fn checker_rejects_ready_status_while_symbol_is_current() -> TestResult {
    let mutated = write_mutated_surface("ready-while-current", |surface| {
        let summary = surface
            .get_mut("summary")
            .ok_or_else(|| "summary must be present".to_string())?;
        set_object_field(summary, "owned_surface_ready", Value::Bool(true))?;
        let row = symbol_row_mut(surface, "_Unwind_SetIP@GCC_3.0")?;
        set_object_field(
            row,
            "owned_surface_status",
            Value::String("ready".to_owned()),
        )
    })?;
    expect_checker_failure(
        &mutated,
        "ready-while-current",
        "summary.owned_surface_ready must remain false",
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
    expect_checker_failure(
        &mutated,
        "stale-source",
        "surface source_commit must be 'current' or match current git HEAD",
    )
}

#[test]
fn checker_rejects_missing_live_unwind_action_row() -> TestResult {
    let root = workspace_root()?;
    let surface = root.join(SURFACE_PATH);
    let mutated_plan = write_mutated_plan("missing-live-unwind-action-row", |plan| {
        let action_rows = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(|projection| projection.get_mut("blocker_action_required_rows"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "blocker_action_required_rows must be an object".to_string())?;
        action_rows
            .remove("undefined_unwind_symbols")
            .ok_or_else(|| "mutation must remove undefined_unwind_symbols".to_string())?;
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &surface,
        &mutated_plan,
        "missing-live-unwind-action-row",
        "undefined_unwind_symbols: must be an object",
    )
}

#[test]
fn checker_rejects_drifted_live_unwind_action_values() -> TestResult {
    let root = workspace_root()?;
    let surface = root.join(SURFACE_PATH);
    let mutated_plan = write_mutated_plan("drifted-live-unwind-action-values", |plan| {
        let values = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(|projection| projection.get_mut("blocker_action_required_rows"))
            .and_then(|rows| rows.get_mut("undefined_unwind_symbols"))
            .and_then(|row| row.get_mut("current_blocker_values"))
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "current_blocker_values must be an array".to_string())?;
        let first = values
            .first_mut()
            .ok_or_else(|| "mutation needs at least one current blocker value".to_string())?;
        *first = Value::String("_Unwind_Bogus@GCC_0.0".to_owned());
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &surface,
        &mutated_plan,
        "drifted-live-unwind-action-values",
        "undefined_unwind_symbols.current_blocker_values must match current diagnostics",
    )
}
