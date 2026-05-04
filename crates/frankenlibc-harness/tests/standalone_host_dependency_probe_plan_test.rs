//! Integration test: standalone host-dependency probe plan (bd-b92jd.1.1).
//!
//! Verifies that the probe plan distinguishes L0/L1 interpose evidence from
//! L2/L3 replacement evidence and fails closed on missing or conflicting rows.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "probe_id",
    "probe_type",
    "replacement_level",
    "evidence_boundary",
    "tool",
    "command",
    "expected",
    "actual_decision",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "failure_signature",
];

const REQUIRED_PROBE_TYPES: &[&str] = &[
    "l0_interpose_reference",
    "replace_artifact_presence",
    "dynamic_dependency_readelf",
    "ldd_host_glibc_scan",
    "undefined_symbol_nm",
    "version_script_export_nodes",
    "support_matrix_status_join",
    "replacement_profile_allowlist_join",
    "crt_startup_contract",
    "tls_init_destructor_contract",
    "atexit_on_exit_contract",
    "errno_tls_isolation_contract",
    "artifact_freshness",
    "negative_claim_control",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn plan_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/standalone_host_dependency_probe_plan.v1.json")
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

fn json_array_mut<'a>(value: &'a mut Value, field: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .get_mut(field)
        .ok_or_else(|| format!("{field} must be present"))?
        .as_array_mut()
        .ok_or_else(|| format!("{field} must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))
}

fn json_item_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{field} must contain only strings"))
}

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    json_field(value, field)?
        .as_u64()
        .ok_or_else(|| format!("{field} must be an unsigned integer"))
}

fn set_json_field(value: &mut Value, field: &str, replacement: Value) -> TestResult {
    let object = value
        .as_object_mut()
        .ok_or_else(|| "probe row must be an object".to_string())?;
    object.insert(field.to_string(), replacement);
    Ok(())
}

fn string_set(value: &Value, field: &str) -> TestResult<HashSet<String>> {
    json_array(value, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} must contain only strings"))
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

fn assert_repo_relative_existing_path(root: &Path, rel: &str, context: &str) -> TestResult {
    let path = Path::new(rel);
    require(!rel.is_empty(), format!("{context}: ref must not be empty"))?;
    require(
        !path.is_absolute(),
        format!("{context}: ref must be repo-relative: {rel}"),
    )?;
    require(
        !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_))),
        format!("{context}: ref must not escape repo root: {rel}"),
    )?;
    let full_path = root.join(path); // ubs:ignore - path is rejected above if absolute or parent-dir escaping.
    require(
        full_path.exists(),
        format!("{context}: missing artifact {rel}"),
    )
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock error: {err}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    Ok(dir)
}

fn write_mutated_plan<F>(label: &str, mutate: F) -> TestResult<PathBuf>
where
    F: FnOnce(&mut Value) -> TestResult,
{
    let root = workspace_root()?;
    let mut plan = load_json(&plan_path(&root))?;
    mutate(&mut plan)?;
    let dir = unique_temp_dir(label)?;
    let path = dir.join("standalone_host_dependency_probe_plan.v1.json");
    let content =
        serde_json::to_string_pretty(&plan).map_err(|err| format!("serialize plan: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn run_checker_with_plan(plan: &Path, label: &str) -> TestResult<(Output, PathBuf, PathBuf)> {
    let root = workspace_root()?;
    let dir = unique_temp_dir(label)?;
    let report = dir.join("standalone_host_dependency_probe_plan.report.json");
    let log = dir.join("standalone_host_dependency_probe_plan.log.jsonl");
    let output = Command::new("bash")
        .arg("scripts/check_standalone_host_dependency_probe_plan.sh")
        .env("FRANKENLIBC_STANDALONE_HOST_DEP_PLAN", plan)
        .env("FRANKENLIBC_STANDALONE_HOST_DEP_REPORT", &report)
        .env("FRANKENLIBC_STANDALONE_HOST_DEP_LOG", &log)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("checker did not run: {err}"))?;
    Ok((output, report, log))
}

fn run_checker(label: &str) -> TestResult<(Value, PathBuf)> {
    let root = workspace_root()?;
    let (output, report, log) = run_checker_with_plan(&plan_path(&root), label)?;
    require(
        output.status.success(),
        format!(
            "checker failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    Ok((load_json(&report)?, log))
}

fn parse_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| format!("jsonl parse: {err}")))
        .collect()
}

fn expect_checker_failure(plan: &Path, label: &str, expected_error: &str) -> TestResult {
    let (output, report, _log) = run_checker_with_plan(plan, label)?;
    require(
        !output.status.success(),
        "checker unexpectedly passed bad probe plan",
    )?;
    let report_json = load_json(&report)?;
    let errors = json_array(&report_json, "errors")?;
    require(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(expected_error)),
        format!("expected error containing {expected_error}; report={report_json:?}"),
    )
}

#[test]
fn plan_has_required_shape_and_probe_coverage() -> TestResult {
    let root = workspace_root()?;
    let plan = load_json(&plan_path(&root))?;

    require(
        json_string(&plan, "schema_version")? == "v1",
        "schema_version",
    )?;
    require(json_string(&plan, "bead")? == "bd-b92jd.1.1", "bead")?;
    require(
        json_field(&plan, "inputs")?.is_object(),
        "inputs must be object",
    )?;
    require(
        json_field(&plan, "artifact_freshness_policy")?.is_object(),
        "artifact freshness policy must be present",
    )?;

    let log_fields: Vec<_> = json_array(&plan, "required_log_fields")?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| "required_log_fields must contain strings".to_string())
        })
        .collect::<TestResult<_>>()?;
    require(
        log_fields == REQUIRED_LOG_FIELDS,
        "required_log_fields mismatch",
    )?;

    let expected_types: HashSet<_> = REQUIRED_PROBE_TYPES
        .iter()
        .map(|value| value.to_string())
        .collect();
    require(
        string_set(&plan, "required_probe_types")? == expected_types,
        "required probe type set mismatch",
    )?;

    let row_types: HashSet<_> = json_array(&plan, "probe_rows")?
        .iter()
        .map(|row| json_string(row, "probe_type").map(str::to_owned))
        .collect::<TestResult<_>>()?;
    require(
        row_types == expected_types,
        "probe rows must cover every required probe type",
    )?;
    Ok(())
}

#[test]
fn probe_rows_have_materialized_refs_and_fail_closed_boundaries() -> TestResult {
    let root = workspace_root()?;
    let plan = load_json(&plan_path(&root))?;
    let mut seen_ids: HashSet<&str> = HashSet::new();
    let mut l2_l3_blockers = 0_u64;
    let mut interpose_reference_rows = 0_u64;

    for row in json_array(&plan, "probe_rows")? {
        let probe_id = json_string(row, "probe_id")?;
        require(seen_ids.insert(probe_id), "duplicate probe id")?;

        for artifact in json_array(row, "input_artifacts")? {
            assert_repo_relative_existing_path(
                &root,
                json_item_string(artifact, "input_artifacts")?,
                probe_id,
            )?;
        }
        for artifact in json_array(row, "artifact_refs")? {
            assert_repo_relative_existing_path(
                &root,
                json_item_string(artifact, "artifact_refs")?,
                probe_id,
            )?;
        }

        let level = json_string(row, "replacement_level")?;
        let has_replace_level = level
            .split(',')
            .any(|part| matches!(part.trim(), "L2" | "L3"));
        if has_replace_level {
            require(
                json_string(row, "actual_decision")? == "claim_blocked",
                "L2/L3 probes must be claim_blocked until artifact evidence exists",
            )?;
            require(
                !json_array(row, "blocks_promotion_to")?.is_empty(),
                "blocked replacement probe must list blocked levels",
            )?;
            l2_l3_blockers += 1;
        }
        if json_string(row, "probe_type")? == "l0_interpose_reference" {
            require(
                json_string(row, "actual_decision")? == "evidence_allowed",
                "L0/L1 interpose row should be evidence_allowed",
            )?;
            interpose_reference_rows += 1;
        }
    }

    require(
        interpose_reference_rows == 1,
        "expected one L0/L1 reference row",
    )?;
    require(
        l2_l3_blockers >= 10,
        "expected broad L2/L3 blocker coverage",
    )
}

#[test]
fn checker_emits_report_and_required_jsonl_rows() -> TestResult {
    let (report, log_path) = run_checker("standalone-host-probe-plan-pass")?;
    require(
        json_string(&report, "status")? == "pass",
        "checker report must pass",
    )?;
    let summary = json_field(&report, "summary")?;
    require(
        json_u64(summary, "probe_count")? == 14,
        "probe_count must be 14",
    )?;
    require(
        json_u64(summary, "l2_l3_blocker_count")? == 13,
        "l2_l3 blocker count must be 13",
    )?;
    require(
        json_string(&report, "source_commit")?.len() == 40,
        "report source_commit must be current git SHA",
    )?;

    let rows = parse_jsonl(&log_path)?;
    require(rows.len() == 14, "expected one JSONL row per probe")?;
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            require(row.get(*field).is_some(), "log row missing required field")?;
        }
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_probe_type_row() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-missing-type", |plan| {
        let rows = json_array_mut(plan, "probe_rows")?;
        let before = rows.len();
        rows.retain(|row| json_string(row, "probe_type").ok() != Some("ldd_host_glibc_scan"));
        require(rows.len() + 1 == before, "expected to remove one ldd row")
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-missing-type",
        "missing probe type rows",
    )
}

#[test]
fn checker_rejects_conflicting_replace_claim_row() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-conflict", |plan| {
        let rows = json_array_mut(plan, "probe_rows")?;
        let row = rows
            .iter_mut()
            .find(|row| json_string(row, "probe_id").ok() == Some("replace_artifact_presence"))
            .ok_or_else(|| "missing replace_artifact_presence row".to_string())?;
        set_json_field(
            row,
            "actual_decision",
            Value::String("evidence_allowed".to_string()),
        )?;
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-conflict",
        "expected_decision and actual_decision conflict",
    )
}

#[test]
fn checker_rejects_missing_materialized_artifact_ref() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-bad-ref", |plan| {
        let rows = json_array_mut(plan, "probe_rows")?;
        let row = rows
            .iter_mut()
            .find(|row| json_string(row, "probe_id").ok() == Some("negative_claim_control"))
            .ok_or_else(|| "missing negative_claim_control row".to_string())?;
        set_json_field(
            row,
            "artifact_refs",
            Value::Array(vec![Value::String(
                "tests/conformance/does_not_exist_for_probe_plan.v1.json".to_string(),
            )]),
        )?;
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-bad-ref",
        "artifact ref does not exist",
    )
}
