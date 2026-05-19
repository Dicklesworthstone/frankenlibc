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

const FORGE_PROJECTION_FIELDS: &[&str] = &[
    "claim_status",
    "source_commit",
    "artifact_state.status",
    "artifact_state.failure_signature",
    "artifact_state.host_glibc_dependency",
    "artifact_state.path",
    "artifact_state.sha256",
    "artifact_state.mtime",
    "artifact_state.dependency_breakdown.needed_libraries",
    "artifact_state.dependency_breakdown.host_direct_needed_libraries",
    "artifact_state.dependency_breakdown.host_resolved_libraries",
    "artifact_state.dependency_breakdown.undefined_unwind_symbols",
    "artifact_state.dependency_breakdown.undefined_glibc_symbols",
    "artifact_state.dependency_breakdown.undefined_tls_symbols",
    "artifact_state.dependency_breakdown.version_needs",
    "artifact_state.dependency_breakdown.host_version_requirements",
    "artifact_state.dependency_breakdown.blocking_reasons",
    "blocking_reasons",
    "artifact_state.dependency_breakdown.blocker_catalog",
    "artifact_state.dependency_breakdown.blocker_action_rows",
];

const FORGE_BLOCKING_REASON_MAPPINGS: &[(&str, &str)] = &[
    (
        "host_needed_libraries_present",
        "readelf_dynamic_dependencies",
    ),
    (
        "host_direct_needed_libraries_present",
        "readelf_dynamic_dependencies",
    ),
    ("host_resolved_libraries_present", "ldd_host_glibc_scan"),
    ("host_loader_dependency", "ldd_host_glibc_scan"),
    ("host_libc_dependency", "ldd_host_glibc_scan"),
    ("libgcc_runtime_dependency", "readelf_dynamic_dependencies"),
    ("undefined_unwind_symbols", "nm_undefined_host_symbols"),
    ("undefined_glibc_symbols", "nm_undefined_host_symbols"),
    ("undefined_tls_symbols", "nm_undefined_host_symbols"),
    ("host_version_requirements", "version_script_export_nodes"),
];

const FORGE_BLOCKER_ACTION_PROBE_IDS: &[(&str, &str)] = &[
    (
        "host_needed_libraries_present",
        "readelf_dynamic_dependencies",
    ),
    (
        "host_direct_needed_libraries_present",
        "readelf_dynamic_dependencies",
    ),
    ("host_resolved_libraries_present", "ldd_runtime_resolution"),
    ("host_loader_dependency", "ldd_runtime_resolution"),
    ("host_libc_dependency", "ldd_runtime_resolution"),
    ("libgcc_runtime_dependency", "readelf_dynamic_dependencies"),
    ("undefined_unwind_symbols", "nm_dynamic_undefined_symbols"),
    ("undefined_glibc_symbols", "nm_dynamic_undefined_symbols"),
    ("undefined_tls_symbols", "nm_dynamic_undefined_symbols"),
    ("host_version_requirements", "readelf_version_needs"),
];

const FORGE_FAILURE_SIGNATURE_MAPPINGS: &[(&str, &str)] = &[
    ("standalone_artifact_missing", "missing_replace_artifact"),
    ("standalone_artifact_stale", "stale_source_commit"),
    ("wrong_artifact_profile", "wrong_artifact_profile"),
    ("host_glibc_dependency", "residual_host_glibc_dependency"),
    (
        "artifact_dependency_inspection_failed",
        "dependency_inspection_failed",
    ),
    ("symbol_evidence_missing", "missing_symbol_evidence"),
];

const FORGE_BLOCKER_SNAPSHOT_BLOCKING_REASONS: &[&str] = &[];

const FORGE_BLOCKER_SNAPSHOT_NEEDED_LIBRARIES: &[&str] = &[];

const FORGE_BLOCKER_SNAPSHOT_HOST_RESOLVED_LIBRARIES: &[&str] = &[];

const FORGE_BLOCKER_SNAPSHOT_HOST_NEEDED_LIBRARIES: &[&str] = &[];

const FORGE_BLOCKER_SNAPSHOT_UNDEFINED_UNWIND_SYMBOLS: &[&str] = &[];

const FORGE_BLOCKER_SNAPSHOT_UNDEFINED_GLIBC_SYMBOLS: &[&str] = &[];
const FORGE_BLOCKER_SNAPSHOT_UNDEFINED_TLS_SYMBOLS: &[&str] = &[];

const FORGE_BLOCKER_SNAPSHOT_HOST_VERSION_REQUIREMENTS: &[&str] = &[];

const FORGE_BLOCKER_SNAPSHOT_VERSION_NEEDS: &[(&str, &[&str])] = &[];

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

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn source_commit_is_current(value: &str, current_head: &str) -> bool {
    value == "current" || value == current_head
}

fn git_head(root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .map_err(|err| format!("git rev-parse HEAD should run: {err}"))?;
    require(
        output.status.success(),
        format!("git rev-parse HEAD failed with status {}", output.status),
    )?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("git rev-parse HEAD emitted non-UTF8: {err}"))?;
    let head = stdout.trim().to_owned();
    require(
        is_hex_commit(&head),
        format!("git HEAD must be a 40-hex commit, got {head:?}"),
    )?;
    Ok(head)
}

fn source_commit_freshness_policy(plan: &Value) -> TestResult<&Value> {
    json_field(plan, "source_commit_freshness_policy")
}

fn assert_source_commit_freshness_policy(plan: &Value) -> TestResult {
    let policy = source_commit_freshness_policy(plan)?;
    require(
        json_string(policy, "recorded_source_commit_field")? == "source_commit",
        "source_commit_freshness_policy.recorded_source_commit_field",
    )?;
    require(
        json_string(policy, "comparison_target")? == "current git HEAD",
        "source_commit_freshness_policy.comparison_target",
    )?;
    require(
        json_string(policy, "stale_result")? == "block_standalone_host_dependency_probe_evidence",
        "source_commit_freshness_policy.stale_result",
    )?;
    require(
        json_field(policy, "host_dependency_probe_evidence_allowed_when_stale")?.as_bool()
            == Some(false),
        "source_commit_freshness_policy.host_dependency_probe_evidence_allowed_when_stale",
    )?;
    require(
        json_string(policy, "rejected_evidence_kind")? == "stale_source_commit",
        "source_commit_freshness_policy.rejected_evidence_kind",
    )
}

fn assert_recorded_source_commit_is_current(root: &Path, plan: &Value) -> TestResult {
    let source_commit = json_string(plan, "source_commit")?;
    require(
        source_commit == "current" || is_hex_commit(source_commit),
        format!("source_commit must be 'current' or a 40-hex commit, got {source_commit:?}"),
    )?;
    let current_head = git_head(root)?;
    require(
        source_commit_is_current(source_commit, &current_head),
        "source_commit must be 'current' or match current git HEAD",
    )
}

fn assert_string_array_eq(value: &Value, field: &str, expected: &[&str]) -> TestResult {
    let actual = json_array(value, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("{field} must contain only strings"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    require(
        actual.as_slice().eq(expected),
        format!("{field} must match current live forge blocker snapshot"),
    )
}

fn assert_forge_blocker_value_snapshot(
    root: &Path,
    projection: &Value,
    expected_reason_set: &HashSet<String>,
) -> TestResult {
    let snapshot = json_field(projection, "current_forge_blocker_value_snapshot")?;
    require(
        json_string(snapshot, "source_artifact")?
            == "target/conformance/standalone_replacement_artifact.report.json",
        "snapshot source_artifact",
    )?;
    require(
        json_string(snapshot, "source_mode")? == "forge",
        "snapshot source_mode",
    )?;
    let snapshot_source_commit = json_string(snapshot, "source_commit")?;
    let current_head = git_head(root)?;
    require(
        source_commit_is_current(snapshot_source_commit, &current_head),
        "current_forge_blocker_value_snapshot.source_commit must be 'current' or match current git HEAD",
    )?;
    require(
        json_string(snapshot, "decision")? == "snapshot_only_artifact_current_no_l2_promotion",
        "snapshot decision must not promote replacement level",
    )?;
    require(
        json_string(snapshot, "claim_status")? == "artifact_current",
        "snapshot claim_status",
    )?;
    require(
        json_string(snapshot, "artifact_status")? == "current",
        "snapshot artifact_status",
    )?;
    require(
        json_string(snapshot, "failure_signature")?.eq("none"),
        "snapshot failure_signature",
    )?;
    require(
        json_field(snapshot, "host_glibc_dependency")?.as_bool() == Some(false),
        "snapshot host_glibc_dependency",
    )?;
    require(
        json_field(snapshot, "sampled_symbols_present")?.as_bool() == Some(true),
        "snapshot sampled_symbols_present",
    )?;

    assert_string_array_eq(
        snapshot,
        "blocking_reasons",
        FORGE_BLOCKER_SNAPSHOT_BLOCKING_REASONS,
    )?;
    let unknown_reasons = string_set(snapshot, "blocking_reasons")?
        .difference(expected_reason_set)
        .cloned()
        .collect::<HashSet<_>>();
    require(
        unknown_reasons.is_empty(),
        format!(
            "snapshot blocking_reasons must be known projected forge reasons: {unknown_reasons:?}"
        ),
    )?;
    assert_string_array_eq(
        snapshot,
        "needed_libraries",
        FORGE_BLOCKER_SNAPSHOT_NEEDED_LIBRARIES,
    )?;
    assert_string_array_eq(
        snapshot,
        "host_direct_needed_libraries",
        FORGE_BLOCKER_SNAPSHOT_NEEDED_LIBRARIES,
    )?;
    assert_string_array_eq(
        snapshot,
        "host_resolved_libraries",
        FORGE_BLOCKER_SNAPSHOT_HOST_RESOLVED_LIBRARIES,
    )?;
    assert_string_array_eq(
        snapshot,
        "host_needed_libraries",
        FORGE_BLOCKER_SNAPSHOT_HOST_NEEDED_LIBRARIES,
    )?;
    assert_string_array_eq(
        snapshot,
        "undefined_unwind_symbols",
        FORGE_BLOCKER_SNAPSHOT_UNDEFINED_UNWIND_SYMBOLS,
    )?;
    assert_string_array_eq(
        snapshot,
        "undefined_glibc_symbols",
        FORGE_BLOCKER_SNAPSHOT_UNDEFINED_GLIBC_SYMBOLS,
    )?;
    assert_string_array_eq(
        snapshot,
        "undefined_tls_symbols",
        FORGE_BLOCKER_SNAPSHOT_UNDEFINED_TLS_SYMBOLS,
    )?;
    assert_string_array_eq(
        snapshot,
        "host_version_requirements",
        FORGE_BLOCKER_SNAPSHOT_HOST_VERSION_REQUIREMENTS,
    )?;

    let version_needs = json_field(snapshot, "version_needs")?
        .as_object()
        .ok_or("snapshot version_needs must be object")?;
    require(
        version_needs.len() == FORGE_BLOCKER_SNAPSHOT_VERSION_NEEDS.len(),
        "snapshot version_needs provider count",
    )?;
    for (provider, expected_versions) in FORGE_BLOCKER_SNAPSHOT_VERSION_NEEDS {
        let versions = version_needs
            .get(*provider)
            .ok_or("snapshot version_needs missing provider")?;
        let actual_versions = versions
            .as_array()
            .ok_or("snapshot version_needs provider must be an array")?
            .iter()
            .map(|item| json_item_string(item, "snapshot version_needs provider"))
            .collect::<TestResult<Vec<_>>>()?;
        require(
            actual_versions.as_slice().eq(*expected_versions),
            "snapshot version_needs provider mismatch",
        )?;
    }

    let policy = json_field(snapshot, "snapshot_policy")?;
    require(
        json_field(policy, "promotion_allowed")?.as_bool() == Some(false),
        "snapshot policy promotion_allowed",
    )?;
    require(
        json_field(policy, "refresh_required_on_blocker_delta")?.as_bool() == Some(true),
        "snapshot policy refresh_required_on_blocker_delta",
    )?;
    require(
        json_string(policy, "stale_result")? == "block_standalone_host_dependency_probe_evidence",
        "snapshot policy stale_result",
    )?;
    require(
        json_string(policy, "rejected_evidence_kind")? == "stale_forge_blocker_snapshot",
        "snapshot policy rejected_evidence_kind",
    )
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

fn require_projection_field(
    projected_fields: &HashSet<String>,
    standalone_report_fields: &HashSet<String>,
    field: &str,
) -> TestResult {
    require(
        projected_fields.contains(field),
        format!("projection missing field {field}"),
    )?;
    require(
        standalone_report_fields.contains(field),
        format!("projection field is not in standalone report contract: {field}"),
    )
}

fn require_blocking_reason_mapping(
    reason_map: &serde_json::Map<String, Value>,
    probe_ids: &HashSet<String>,
    reason: &str,
    probe_id: &str,
) -> TestResult {
    require(
        reason_map.get(reason).and_then(Value::as_str) == Some(probe_id),
        format!("blocking reason {reason} must map to {probe_id}"),
    )?;
    require(
        probe_ids.contains(probe_id),
        format!("mapped probe id missing: {probe_id}"),
    )
}

fn require_blocker_catalog_row(
    catalog_rows: &serde_json::Map<String, Value>,
    standalone_catalog_definitions: &serde_json::Map<String, Value>,
    reason: &str,
) -> TestResult {
    let row = catalog_rows
        .get(reason)
        .ok_or_else(|| format!("blocker catalog missing {reason}"))?;
    require(
        json_string(row, "severity")? == "claim_blocking",
        format!("blocker catalog row {reason} must be claim_blocking"),
    )?;
    require(
        !json_string(row, "owner_surface")?.is_empty(),
        format!("blocker catalog row {reason} must name owner_surface"),
    )?;
    require(
        !json_string(row, "next_action")?.is_empty(),
        format!("blocker catalog row {reason} must include next_action"),
    )?;
    require(
        !json_array(row, "evidence_fields")?.is_empty(),
        format!("blocker catalog row {reason} must cite evidence_fields"),
    )?;
    let expected_row = standalone_catalog_definitions
        .get(reason)
        .ok_or_else(|| format!("standalone manifest missing catalog row {reason}"))?;
    require(
        row == expected_row,
        format!("blocker catalog row {reason} must match standalone manifest contract"),
    )
}

fn expected_blocker_action_values(reason: &str) -> TestResult<HashSet<String>> {
    let values: &[&str] = match reason {
        "host_needed_libraries_present" => FORGE_BLOCKER_SNAPSHOT_HOST_NEEDED_LIBRARIES,
        "host_direct_needed_libraries_present" => FORGE_BLOCKER_SNAPSHOT_NEEDED_LIBRARIES,
        "host_resolved_libraries_present" => FORGE_BLOCKER_SNAPSHOT_HOST_RESOLVED_LIBRARIES,
        "host_loader_dependency" => &[],
        "host_libc_dependency" => &[],
        "libgcc_runtime_dependency" => &[],
        "undefined_unwind_symbols" => FORGE_BLOCKER_SNAPSHOT_UNDEFINED_UNWIND_SYMBOLS,
        "undefined_glibc_symbols" => &[],
        "undefined_tls_symbols" => &[],
        "host_version_requirements" => FORGE_BLOCKER_SNAPSHOT_HOST_VERSION_REQUIREMENTS,
        _ => return Err(format!("unexpected blocker action reason {reason}")),
    };
    Ok(values.iter().map(|value| (*value).to_string()).collect())
}

fn require_blocker_action_row(
    action_rows: &serde_json::Map<String, Value>,
    catalog_rows: &serde_json::Map<String, Value>,
    reason: &str,
    primary_probe_id: &str,
) -> TestResult {
    let row = action_rows
        .get(reason)
        .ok_or_else(|| format!("blocker action rows missing {reason}"))?;
    require(
        json_string(row, "blocking_reason")? == reason,
        format!("blocker action row key and blocking_reason mismatch for {reason}"),
    )?;
    require(
        json_string(row, "primary_probe_id")? == primary_probe_id,
        format!("blocker action row {reason} must use primary probe {primary_probe_id}"),
    )?;
    require(
        json_field(row, "promotion_allowed")?.as_bool() == Some(false),
        format!("blocker action row {reason} must not allow promotion"),
    )?;
    require(
        !json_array(row, "exit_criteria")?.is_empty(),
        format!("blocker action row {reason} must include exit criteria"),
    )?;
    let catalog_row = catalog_rows
        .get(reason)
        .ok_or_else(|| format!("catalog rows missing {reason}"))?;
    for field in ["owner_surface", "evidence_fields", "next_action"] {
        require(
            json_field(row, field)? == json_field(catalog_row, field)?,
            format!("blocker action row {reason}.{field} must match catalog row"),
        )?;
    }
    require(
        string_set(row, "current_blocker_values")? == expected_blocker_action_values(reason)?,
        format!("blocker action row {reason} values must match current forge snapshot"),
    )
}

fn require_failure_mapping(
    failure_map: &serde_json::Map<String, Value>,
    standalone_failure_signatures: &HashSet<String>,
    negative_test_ids: &HashSet<String>,
    failure: &str,
    test_id: &str,
) -> TestResult {
    let mapped_test_id = failure_map.get(failure).and_then(Value::as_str);
    require(
        mapped_test_id.is_some_and(|actual| actual.eq(test_id)),
        format!("failure entry {failure} must map to {test_id}"),
    )?;
    require(
        standalone_failure_signatures.contains(failure),
        format!("mapped failure entry missing from standalone manifest: {failure}"),
    )?;
    require(
        negative_test_ids.contains(test_id),
        format!("mapped negative test missing: {test_id}"),
    )
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
    let source_commit = json_string(&plan, "source_commit")?;
    require(
        source_commit == "current" || is_hex_commit(source_commit),
        format!("source_commit must be 'current' or a 40-hex commit, got {source_commit:?}"),
    )?;
    require(
        source_commit == "current",
        "source_commit must use current marker",
    )?;
    assert_recorded_source_commit_is_current(&root, &plan)?;
    assert_source_commit_freshness_policy(&plan)?;
    require(
        json_field(&plan, "inputs")?.is_object(),
        "inputs must be object",
    )?;
    let inputs = json_field(&plan, "inputs")?
        .as_object()
        .ok_or_else(|| "inputs must be object".to_string())?;
    let standalone_artifact_ref = inputs
        .get("standalone_replacement_artifact")
        .and_then(Value::as_str)
        .ok_or_else(|| "inputs.standalone_replacement_artifact must be string".to_string())?;
    assert_repo_relative_existing_path(
        &root,
        standalone_artifact_ref,
        "inputs.standalone_replacement_artifact",
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

    let standalone_manifest = load_json(&root.join(standalone_artifact_ref))?;
    let standalone_report_fields = string_set(&standalone_manifest, "required_report_fields")?;
    let standalone_failure_signatures: HashSet<_> =
        json_array(&standalone_manifest, "expected_failure_classifications")?
            .iter()
            .map(|entry| json_string(entry, "failure_signature").map(str::to_owned))
            .collect::<TestResult<_>>()?;
    let standalone_catalog_definitions = json_field(
        json_field(&standalone_manifest, "blocker_catalog_contract")?,
        "definitions",
    )?
    .as_object()
    .ok_or_else(|| "standalone blocker catalog definitions must be object".to_string())?;
    let probe_ids: HashSet<_> = json_array(&plan, "probe_rows")?
        .iter()
        .map(|row| json_string(row, "probe_id").map(str::to_owned))
        .collect::<TestResult<_>>()?;
    let negative_test_ids: HashSet<_> = json_array(&plan, "negative_claim_tests")?
        .iter()
        .map(|entry| json_string(entry, "id").map(str::to_owned))
        .collect::<TestResult<_>>()?;

    let projection = json_field(&plan, "current_forge_blocker_projection")?;
    require(
        json_string(projection, "source_artifact")? == standalone_artifact_ref,
        "projection source_artifact must match standalone input",
    )?;
    require(
        json_string(projection, "decision")? == "projection_only_claims_remain_blocked",
        "projection decision must not promote claims",
    )?;
    let projected_fields = string_set(projection, "projected_report_fields")?;
    for field in FORGE_PROJECTION_FIELDS {
        require_projection_field(&projected_fields, &standalone_report_fields, field)?;
    }

    let reason_map = json_field(projection, "blocking_reason_to_probe_id")?
        .as_object()
        .ok_or_else(|| "blocking_reason_to_probe_id must be object".to_string())?;
    for (reason, probe_id) in FORGE_BLOCKING_REASON_MAPPINGS {
        require_blocking_reason_mapping(reason_map, &probe_ids, reason, probe_id)?;
    }
    require(
        reason_map.len() == FORGE_BLOCKING_REASON_MAPPINGS.len(),
        "blocking reason map must not omit or add projected forge reasons",
    )?;

    let catalog_rows = json_field(projection, "blocker_catalog_required_rows")?
        .as_object()
        .ok_or_else(|| "blocker_catalog_required_rows must be object".to_string())?;
    require(
        catalog_rows.len() == FORGE_BLOCKING_REASON_MAPPINGS.len(),
        "blocker catalog must have one row per projected blocking reason",
    )?;
    for (reason, _) in FORGE_BLOCKING_REASON_MAPPINGS {
        require_blocker_catalog_row(catalog_rows, standalone_catalog_definitions, reason)?;
    }

    let action_rows = json_field(projection, "blocker_action_required_rows")?
        .as_object()
        .ok_or_else(|| "blocker_action_required_rows must be object".to_string())?;
    require(
        action_rows.len() == FORGE_BLOCKING_REASON_MAPPINGS.len(),
        "blocker action rows must have one row per projected blocking reason",
    )?;
    for (reason, primary_probe_id) in FORGE_BLOCKER_ACTION_PROBE_IDS {
        require_blocker_action_row(action_rows, catalog_rows, reason, primary_probe_id)?;
    }

    let failure_map = json_field(projection, "failure_signature_to_negative_test")?
        .as_object()
        .ok_or_else(|| "failure_signature_to_negative_test must be object".to_string())?;
    for (failure, test_id) in FORGE_FAILURE_SIGNATURE_MAPPINGS {
        require_failure_mapping(
            failure_map,
            &standalone_failure_signatures,
            &negative_test_ids,
            failure,
            test_id,
        )?;
    }
    let expected_snapshot_reason_set: HashSet<String> = FORGE_BLOCKING_REASON_MAPPINGS
        .iter()
        .map(|(reason, _)| (*reason).to_string())
        .collect();
    assert_forge_blocker_value_snapshot(&root, projection, &expected_snapshot_reason_set)?;
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
fn stale_source_commit_policy_blocks_host_dependency_probe_evidence() -> TestResult {
    let root = workspace_root()?;
    let plan = load_json(&plan_path(&root))?;
    let source_commit = json_string(&plan, "source_commit")?;
    require(
        source_commit == "current" || is_hex_commit(source_commit),
        format!("source_commit must be 'current' or a 40-hex commit, got {source_commit:?}"),
    )?;
    assert_source_commit_freshness_policy(&plan)?;

    let current_head = git_head(&root)?;
    if !source_commit_is_current(source_commit, &current_head) {
        let policy = source_commit_freshness_policy(&plan)?;
        require(
            json_string(policy, "stale_result")?
                == "block_standalone_host_dependency_probe_evidence",
            "stale standalone host dependency source_commit must block probe evidence",
        )?;
        require(
            json_field(policy, "host_dependency_probe_evidence_allowed_when_stale")?.as_bool()
                == Some(false),
            "stale standalone host dependency source_commit must not allow probe evidence",
        )?;
        require(
            json_string(policy, "rejected_evidence_kind")? == "stale_source_commit",
            "stale standalone host dependency source_commit must use stale_source_commit",
        )?;
    }
    Ok(())
}

#[test]
fn stale_recorded_source_commit_helper_rejects_host_dependency_probe_evidence() -> TestResult {
    let root = workspace_root()?;
    let mut plan = load_json(&plan_path(&root))?;
    set_json_field(
        &mut plan,
        "source_commit",
        Value::String("0000000000000000000000000000000000000000".to_string()),
    )?;
    let error = assert_recorded_source_commit_is_current(&root, &plan)
        .expect_err("stale recorded source_commit should be rejected");
    require(
        error.contains("source_commit must be 'current' or match current git HEAD"),
        format!("unexpected stale source_commit error: {error}"),
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
        json_u64(summary, "forge_projection_field_count")? == 20,
        "forge projection field count must be 20",
    )?;
    require(
        json_u64(summary, "forge_projection_blocking_reason_count")? == 10,
        "forge projection blocking reason count must be 10",
    )?;
    require(
        json_u64(summary, "forge_projection_blocker_catalog_row_count")? == 10,
        "forge projection blocker catalog count must be 10",
    )?;
    require(
        json_u64(summary, "forge_projection_blocker_action_row_count")? == 10,
        "forge projection blocker action count must be 10",
    )?;
    match json_u64(summary, "forge_projection_failure_signature_count")? {
        6 => {}
        actual => {
            return Err(format!(
                "forge projection failure signature count must be 6, found {actual}"
            ));
        }
    }
    require(
        json_u64(summary, "forge_blocker_snapshot_blocking_reason_count")? == 0,
        "forge blocker snapshot reason count must be 0",
    )?;
    require(
        json_u64(summary, "forge_blocker_snapshot_needed_library_count")? == 0,
        "forge blocker snapshot needed library count must be 0",
    )?;
    require(
        json_u64(
            summary,
            "forge_blocker_snapshot_host_resolved_library_count",
        )? == 0,
        "forge blocker snapshot host resolved library count must be 0",
    )?;
    require(
        json_u64(summary, "forge_blocker_snapshot_undefined_symbol_count")? == 0,
        "forge blocker snapshot undefined symbol count must be 0",
    )?;
    require(
        json_u64(
            summary,
            "forge_blocker_snapshot_host_version_requirement_count",
        )? == 0,
        "forge blocker snapshot host version requirement count must be 0",
    )?;
    require(
        json_u64(
            summary,
            "forge_blocker_snapshot_version_need_provider_count",
        )? == 0,
        "forge blocker snapshot version need provider count must be 0",
    )?;
    require(
        json_string(&report, "source_commit")?.len() == 40,
        "report source_commit must be current git SHA",
    )?;
    require(
        json_string(&report, "plan_source_commit")? == "current",
        "report plan_source_commit must be the current marker",
    )?;
    let freshness = json_field(&report, "source_commit_freshness")?;
    require(
        json_string(freshness, "status")? == "current",
        "report freshness status must be current",
    )?;
    require(
        json_string(freshness, "recorded_source_commit_freshness")? == "pass",
        "report recorded source_commit freshness must pass",
    )?;
    require(
        json_string(freshness, "stale_result")?
            == "block_standalone_host_dependency_probe_evidence",
        "report freshness policy must block stale probe evidence",
    )?;
    require(
        json_field(
            freshness,
            "host_dependency_probe_evidence_allowed_when_stale",
        )?
        .as_bool()
            == Some(false),
        "report freshness policy must not allow stale probe evidence",
    )?;
    require(
        json_string(freshness, "rejected_evidence_kind")? == "stale_source_commit",
        "report freshness policy must identify stale_source_commit",
    )?;

    let rows = parse_jsonl(&log_path)?;
    require(rows.len() == 14, "expected one JSONL row per probe")?;
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            json_field(&row, field)?;
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
fn checker_rejects_missing_source_commit_freshness_policy() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-missing-freshness", |plan| {
        plan.as_object_mut()
            .ok_or_else(|| "plan must be object".to_string())?
            .remove("source_commit_freshness_policy");
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-missing-freshness",
        "source_commit_freshness_policy must match",
    )
}

#[test]
fn checker_rejects_source_commit_policy_that_allows_stale_evidence() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-stale-allowed", |plan| {
        let policy = plan
            .get_mut("source_commit_freshness_policy")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing source_commit_freshness_policy".to_string())?;
        policy.insert(
            "host_dependency_probe_evidence_allowed_when_stale".to_string(),
            Value::Bool(true),
        );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-stale-allowed",
        "source_commit_freshness_policy must match",
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

#[test]
fn checker_rejects_missing_forge_projection_mapping() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-missing-projection", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        let reason_map = projection
            .get_mut("blocking_reason_to_probe_id")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing blocking_reason_to_probe_id".to_string())?;
        reason_map.remove("host_libc_dependency");
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-missing-projection",
        "blocking_reason_to_probe_id missing host_libc_dependency",
    )
}

#[test]
fn checker_rejects_stale_recorded_source_commit() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-stale-source", |plan| {
        set_json_field(
            plan,
            "source_commit",
            Value::String("0000000000000000000000000000000000000000".to_string()),
        )
    })?;
    let (output, report, _log) =
        run_checker_with_plan(&mutated, "standalone-host-probe-plan-stale-source")?;
    require(
        !output.status.success(),
        "checker unexpectedly passed stale recorded source_commit",
    )?;
    let report_json = load_json(&report)?;
    let freshness = json_field(&report_json, "source_commit_freshness")?;
    require(
        json_string(freshness, "status")? == "stale",
        "stale recorded source_commit should report stale freshness",
    )?;
    require(
        json_string(freshness, "recorded_source_commit_freshness")? == "fail",
        "stale recorded source_commit should fail recorded freshness",
    )?;
    let errors = json_array(&report_json, "errors")?;
    require(
        errors.iter().filter_map(Value::as_str).any(|error| {
            error.contains("plan source_commit must be 'current' or match current git HEAD")
        }),
        format!("expected stale source_commit error; report={report_json:?}"),
    )
}

#[test]
fn checker_rejects_missing_forge_failure_signature_mapping() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-missing-failure-map", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        let failure_map = projection
            .get_mut("failure_signature_to_negative_test")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing failure_signature_to_negative_test".to_string())?;
        failure_map.remove("symbol_evidence_missing");
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-missing-failure-map",
        "failure_signature_to_negative_test missing symbol_evidence_missing",
    )
}

#[test]
fn checker_rejects_missing_forge_blocker_catalog_row() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-missing-catalog-row", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        let catalog = projection
            .get_mut("blocker_catalog_required_rows")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing blocker_catalog_required_rows".to_string())?;
        catalog.remove("undefined_tls_symbols");
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-missing-catalog-row",
        "blocker_catalog_required_rows missing undefined_tls_symbols",
    )
}

#[test]
fn checker_rejects_forge_blocker_catalog_contract_drift() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-catalog-drift", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        let catalog = projection
            .get_mut("blocker_catalog_required_rows")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing blocker_catalog_required_rows".to_string())?;
        let row = catalog
            .get_mut("undefined_tls_symbols")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing undefined_tls_symbols catalog row".to_string())?;
        row.insert(
            "owner_surface".to_string(),
            Value::String("generic_tls".to_string()),
        );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-catalog-drift",
        "blocker_catalog_required_rows.undefined_tls_symbols does not match standalone manifest contract",
    )
}

#[test]
fn checker_rejects_missing_forge_blocker_action_row() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-missing-action-row", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        let action_rows = projection
            .get_mut("blocker_action_required_rows")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing blocker_action_required_rows".to_string())?;
        action_rows.remove("undefined_tls_symbols");
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-missing-action-row",
        "blocker_action_required_rows missing undefined_tls_symbols",
    )
}

#[test]
fn checker_rejects_forge_blocker_action_value_drift() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-action-drift", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        let action_rows = projection
            .get_mut("blocker_action_required_rows")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing blocker_action_required_rows".to_string())?;
        let row = action_rows
            .get_mut("host_version_requirements")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing host_version_requirements action row".to_string())?;
        row.insert(
            "current_blocker_values".to_string(),
            Value::Array(vec![Value::String("libgcc_s.so.1:GCC_3.0".to_string())]),
        );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-action-drift",
        "blocker_action_required_rows.host_version_requirements.current_blocker_values must match current live forge blockers",
    )
}

#[test]
fn checker_rejects_missing_forge_blocker_value_snapshot() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-missing-snapshot", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        projection.remove("current_forge_blocker_value_snapshot");
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-missing-snapshot",
        "current_forge_blocker_value_snapshot must be an object",
    )
}

#[test]
fn checker_rejects_forge_blocker_value_snapshot_drift() -> TestResult {
    let mutated = write_mutated_plan("standalone-host-probe-plan-snapshot-drift", |plan| {
        let projection = plan
            .get_mut("current_forge_blocker_projection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_projection".to_string())?;
        let snapshot = projection
            .get_mut("current_forge_blocker_value_snapshot")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "missing current_forge_blocker_value_snapshot".to_string())?;
        snapshot.insert(
            "undefined_tls_symbols".to_string(),
            Value::Array(vec![Value::String("__tls_get_addr@GLIBC_2.3".to_string())]),
        );
        Ok(())
    })?;
    expect_checker_failure(
        &mutated,
        "standalone-host-probe-plan-snapshot-drift",
        "current_forge_blocker_value_snapshot.undefined_tls_symbols must match current live forge blockers",
    )
}
