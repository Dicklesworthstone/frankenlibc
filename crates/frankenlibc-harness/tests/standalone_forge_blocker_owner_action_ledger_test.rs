//! Integration test: standalone forge blocker owner/action ledger (bd-zyck1.93).
//!
//! The ledger is planning evidence for parallel standalone blocker burn-down.
//! It must fail closed when a current blocking reason loses an owner,
//! validation path, negative control, or first safe action. Resolved blockers
//! remain as catalog history, but their current blocker values must be empty.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_OWNER_SURFACES: &[&str] = &[
    "runtime_linkage",
    "direct_dynamic_dependencies",
    "loader_resolution",
    "loader_startup",
    "libc_surface",
    "compiler_runtime",
    "unwind_runtime",
    "tls_startup",
    "glibc_symbol_surface",
    "symbol_versioning",
];

const REQUIRED_ROW_FIELDS: &[&str] = &[
    "blocking_reason",
    "owner_surface",
    "catalog_owner_surface",
    "primary_probe_id",
    "primary_evidence_command",
    "negative_control_test",
    "likely_code_config_files",
    "validation_path",
    "first_safe_action",
    "exit_criteria",
    "current_blocker_values",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn ledger_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json")
}

fn plan_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_host_dependency_probe_plan.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_standalone_forge_blocker_owner_action_ledger.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
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

fn string_set(value: &Value, field: &str) -> TestResult<HashSet<String>> {
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

fn run_checker_with_plan(
    root: &Path,
    ledger: &Path,
    plan: &Path,
    label: &str,
) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target/conformance").join(format!(
        "standalone_forge_blocker_owner_action_ledger.{label}.report.json"
    ));
    let output = Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_STANDALONE_BLOCKER_OWNER_LEDGER", ledger)
        .env("FRANKENLIBC_STANDALONE_HOST_DEP_PLAN", plan)
        .env(
            "FRANKENLIBC_STANDALONE_BLOCKER_OWNER_LEDGER_REPORT",
            &report,
        )
        .current_dir(root)
        .output()
        .map_err(|err| format!("failed to run owner-action checker: {err}"))?;
    Ok((output, report))
}

fn run_checker(root: &Path, ledger: &Path, label: &str) -> TestResult<(Output, PathBuf)> {
    run_checker_with_plan(root, ledger, &plan_path(root), label)
}

fn format_output(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_checker_failure(ledger: &Path, label: &str, expected_error: &str) -> TestResult {
    let root = workspace_root()?;
    expect_checker_failure_with_plan(ledger, &plan_path(&root), label, expected_error)
}

fn expect_checker_failure_with_plan(
    ledger: &Path,
    plan: &Path,
    label: &str,
    expected_error: &str,
) -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker_with_plan(&root, ledger, plan, label)?;
    require(
        !output.status.success(),
        format!("checker unexpectedly passed\n{}", format_output(&output)),
    )?;
    let report_json = load_json(&report)?;
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

fn write_mutated_ledger(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut ledger = load_json(&ledger_path(&root))?;
    mutate(&mut ledger)?;
    let dir = root.join("target/conformance/mutated-ledgers");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&ledger)
        .map_err(|err| format!("failed to serialize mutated ledger: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn write_mutated_plan(
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let root = workspace_root()?;
    let mut plan = load_json(&plan_path(&root))?;
    mutate(&mut plan)?;
    let dir = root.join("target/conformance/mutated-plans");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let path = dir.join(format!("{}.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&plan)
        .map_err(|err| format!("failed to serialize mutated plan: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn ledger_row_mut<'a>(ledger: &'a mut Value, reason: &str) -> TestResult<&'a mut Value> {
    let rows = ledger
        .get_mut("ledger_rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "ledger_rows must be an array".to_string())?;
    rows.iter_mut()
        .find(|row| row.get("blocking_reason").and_then(Value::as_str) == Some(reason))
        .ok_or_else(|| format!("missing row {reason}"))
}

fn repo_ref_exists(root: &Path, value: &str) -> TestResult {
    let path = Path::new(value);
    require(
        !path.is_absolute()
            && !path
                .components()
                .any(|component| component == Component::ParentDir),
        format!("{value}: repo reference must be relative and stay inside repo"),
    )?;
    require(
        root.join(path).exists(),
        format!("{value}: repo reference must exist"),
    )
}

#[test]
fn ledger_manifest_covers_current_forge_snapshot() -> TestResult {
    let root = workspace_root()?;
    let ledger = load_json(&ledger_path(&root))?;
    let plan = load_json(&plan_path(&root))?;
    require(
        json_string(&ledger, "schema_version")? == "v1",
        "ledger schema version must be v1",
    )?;
    require(
        json_string(&ledger, "bead")? == "bd-zyck1.93",
        "ledger bead must be bd-zyck1.93",
    )?;
    require(
        json_string(&ledger, "source_commit")? == "current",
        "ledger source_commit must remain current until a snapshot refresh records a commit",
    )?;

    let required_fields = string_set(&ledger, "required_row_fields")?;
    for field in REQUIRED_ROW_FIELDS {
        require(
            required_fields.contains(*field),
            format!("required_row_fields missing {field}"),
        )?;
    }
    let required_owners = string_set(&ledger, "required_owner_surfaces")?;
    for owner in REQUIRED_OWNER_SURFACES {
        require(
            required_owners.contains(*owner),
            format!("required_owner_surfaces missing {owner}"),
        )?;
    }

    let projection = json_field(&plan, "current_forge_blocker_projection")?;
    let snapshot = json_field(projection, "current_forge_blocker_value_snapshot")?;
    let current_reasons = string_set(snapshot, "blocking_reasons")?;
    require(
        current_reasons.is_empty(),
        "current forge blocker snapshot must be empty after standalone blocker burn-down",
    )?;
    let reason_to_probe = json_field(projection, "blocking_reason_to_probe_id")?
        .as_object()
        .ok_or_else(|| "blocking_reason_to_probe_id must be object".to_string())?;
    let catalog = json_field(projection, "blocker_catalog_required_rows")?
        .as_object()
        .ok_or_else(|| "blocker_catalog_required_rows must be object".to_string())?;
    let probe_commands: HashMap<_, _> = json_array(&plan, "probe_rows")?
        .iter()
        .map(|row| {
            Ok((
                json_string(row, "probe_id")?.to_owned(),
                json_array(row, "command_argv")?.clone(),
            ))
        })
        .collect::<TestResult<_>>()?;
    let negative_test_ids = string_set_from_rows(&plan, "negative_claim_tests", "id")?;
    let mut rows_by_reason = HashMap::new();
    let mut owner_surfaces = HashSet::new();
    for row in json_array(&ledger, "ledger_rows")? {
        for field in REQUIRED_ROW_FIELDS {
            require(
                row.get(*field).is_some(),
                format!("ledger row missing {field}"),
            )?;
        }
        let reason = json_string(row, "blocking_reason")?;
        require(
            catalog.contains_key(reason),
            format!("ledger row {reason} must map to current or historical blocker catalog"),
        )?;
        require(
            rows_by_reason.insert(reason.to_owned(), row).is_none(),
            format!("duplicate ledger row {reason}"),
        )?;
        let owner = json_string(row, "owner_surface")?;
        require(
            REQUIRED_OWNER_SURFACES.contains(&owner),
            format!("{reason}: owner_surface {owner} must be in required owner set"),
        )?;
        owner_surfaces.insert(owner.to_owned());
        let catalog_owner = catalog
            .get(reason)
            .and_then(|entry| entry.get("owner_surface"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{reason}: missing catalog owner"))?;
        require(
            json_string(row, "catalog_owner_surface")? == catalog_owner,
            format!("{reason}: catalog_owner_surface must match host dependency probe plan"),
        )?;
        require(
            owner == catalog_owner,
            format!("{reason}: owner_surface must match live action-row owner"),
        )?;
        let probe_id = json_string(row, "primary_probe_id")?;
        require(
            reason_to_probe.get(reason).and_then(Value::as_str) == Some(probe_id),
            format!("{reason}: primary_probe_id must match host dependency probe map"),
        )?;
        require(
            probe_commands.get(probe_id) == Some(json_array(row, "primary_evidence_command")?),
            format!("{reason}: primary_evidence_command must match probe command"),
        )?;
        let negative = json_string(row, "negative_control_test")?;
        require(
            negative_test_ids.contains(negative),
            format!("{reason}: negative_control_test must exist in probe plan"),
        )?;
        for path in json_array(row, "likely_code_config_files")? {
            repo_ref_exists(
                &root,
                path.as_str()
                    .ok_or_else(|| format!("{reason}: likely paths must be strings"))?,
            )?;
        }
        require(
            !json_string(row, "first_safe_action")?.is_empty(),
            format!("{reason}: first_safe_action must be non-empty"),
        )?;
        require(
            !json_array(row, "exit_criteria")?.is_empty(),
            format!("{reason}: exit_criteria must be non-empty"),
        )?;
        require(
            json_array(row, "current_blocker_values")?.is_empty(),
            format!("{reason}: current_blocker_values must be empty for resolved blockers"),
        )?;
    }
    require(
        rows_by_reason.len() == catalog.len(),
        "ledger must retain exactly one row per cataloged forge blocker reason",
    )?;
    for reason in &current_reasons {
        require(
            rows_by_reason.contains_key(reason),
            format!("ledger must have a row for current forge blocker reason {reason}"),
        )?;
    }
    for owner in REQUIRED_OWNER_SURFACES {
        require(
            owner_surfaces.contains(*owner),
            format!("owner surface {owner} must have at least one row"),
        )?;
    }
    Ok(())
}

fn string_set_from_rows(
    value: &Value,
    rows_field: &str,
    string_field: &str,
) -> TestResult<HashSet<String>> {
    json_array(value, rows_field)?
        .iter()
        .map(|row| json_string(row, string_field).map(str::to_owned))
        .collect()
}

#[test]
fn checker_accepts_canonical_ledger() -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, &ledger_path(&root), "canonical")?;
    require(
        output.status.success(),
        format!(
            "checker failed canonical ledger\n{}",
            format_output(&output)
        ),
    )?;
    let report_json = load_json(&report)?;
    require(
        json_string(&report_json, "status")? == "pass",
        "canonical report status must pass",
    )?;
    require(
        json_field(&report_json, "current_blocking_reason_count")?.as_u64() == Some(0),
        "current_blocking_reason_count must be 0",
    )?;
    require(
        json_field(&report_json, "ledger_row_count")?.as_u64() == Some(10),
        "ledger_row_count must be 10",
    )
}

#[test]
fn checker_rejects_missing_current_blocker_row() -> TestResult {
    let mutated = write_mutated_ledger("owner-ledger-missing-row", |ledger| {
        let rows = ledger
            .get_mut("ledger_rows")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "ledger_rows must be an array".to_string())?;
        rows.retain(|row| {
            row.get("blocking_reason").and_then(Value::as_str) != Some("undefined_tls_symbols")
        });
        Ok(())
    })?;
    let mutated_plan = write_mutated_plan("owner-plan-current-row", |plan| {
        let reasons = plan
            .pointer_mut(
                "/current_forge_blocker_projection/current_forge_blocker_value_snapshot/blocking_reasons",
            )
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "blocking_reasons must be an array".to_string())?;
        reasons.push(Value::String("undefined_tls_symbols".to_string()));
        Ok(())
    })?;
    expect_checker_failure_with_plan(
        &mutated,
        &mutated_plan,
        "owner-ledger-missing-row",
        "ledger_rows missing current forge blocker reason undefined_tls_symbols",
    )
}

#[test]
fn checker_rejects_stale_values_on_resolved_blocker() -> TestResult {
    let mutated = write_mutated_ledger("owner-ledger-stale-values", |ledger| {
        let row = ledger_row_mut(ledger, "host_libc_dependency")?;
        row.as_object_mut()
            .ok_or_else(|| "row must be object".to_string())?
            .insert(
                "current_blocker_values".to_string(),
                Value::Array(vec![Value::String("libc.so.6".to_string())]),
            );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "owner-ledger-stale-values",
        "ledger_rows[host_libc_dependency].current_blocker_values must be empty for resolved blockers",
    )
}

#[test]
fn checker_rejects_missing_first_safe_action() -> TestResult {
    let mutated = write_mutated_ledger("owner-ledger-missing-action", |ledger| {
        let row = ledger_row_mut(ledger, "host_libc_dependency")?;
        row.as_object_mut()
            .ok_or_else(|| "row must be object".to_string())?
            .insert(
                "first_safe_action".to_string(),
                Value::String(String::new()),
            );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "owner-ledger-missing-action",
        "ledger_rows[host_libc_dependency].first_safe_action must be a non-empty string",
    )
}

#[test]
fn checker_rejects_missing_required_owner_surface() -> TestResult {
    let mutated = write_mutated_ledger("owner-ledger-owner-drift", |ledger| {
        let row = ledger_row_mut(ledger, "host_version_requirements")?;
        row.as_object_mut()
            .ok_or_else(|| "row must be object".to_string())?
            .insert(
                "owner_surface".to_string(),
                Value::String("runtime_linkage".to_string()),
            );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "owner-ledger-owner-drift",
        "required owner surface has no ledger row: symbol_versioning",
    )
}

#[test]
fn checker_rejects_owner_surface_drift_from_live_action_row() -> TestResult {
    let mutated = write_mutated_ledger("owner-ledger-live-owner-drift", |ledger| {
        let row = ledger_row_mut(ledger, "host_direct_needed_libraries_present")?;
        row.as_object_mut()
            .ok_or_else(|| "row must be object".to_string())?
            .insert(
                "owner_surface".to_string(),
                Value::String("runtime_linkage".to_string()),
            );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "owner-ledger-live-owner-drift",
        "ledger_rows[host_direct_needed_libraries_present].owner_surface must match live action-row owner direct_dynamic_dependencies",
    )
}

#[test]
fn checker_rejects_probe_mapping_drift() -> TestResult {
    let mutated = write_mutated_ledger("owner-ledger-probe-drift", |ledger| {
        let row = ledger_row_mut(ledger, "undefined_glibc_symbols")?;
        row.as_object_mut()
            .ok_or_else(|| "row must be object".to_string())?
            .insert(
                "primary_probe_id".to_string(),
                Value::String("readelf_dynamic_dependencies".to_string()),
            );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "owner-ledger-probe-drift",
        "ledger_rows[undefined_glibc_symbols].primary_probe_id must map to nm_undefined_host_symbols",
    )
}
