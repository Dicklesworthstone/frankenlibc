//! Integration test: standalone host version requirement burn-down (bd-zyck1.90).
//!
//! The matrix is a report-only planning artifact, but it must stay tied to the
//! current forge snapshot so provider/version rows cannot drift independently
//! from the readelf evidence that blocks standalone replacement claims.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const BURNDOWN_PATH: &str =
    "tests/conformance/standalone_host_version_requirement_burndown.v1.json";
const HOST_PROBE_PLAN_PATH: &str =
    "tests/conformance/standalone_host_dependency_probe_plan.v1.json";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_json(root: &Path, rel: &str) -> TestResult<Value> {
    let path = root.join(rel);
    let content =
        std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn get_path<'a>(mut value: &'a Value, dotted: &str) -> TestResult<&'a Value> {
    for segment in dotted.split('.') {
        value = value
            .get(segment)
            .ok_or_else(|| format!("{dotted}: missing segment {segment}"))?;
    }
    Ok(value)
}

fn as_str<'a>(value: &'a Value, ctx: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{ctx} must be a string"))
}

fn as_bool(value: &Value, ctx: &str) -> TestResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| format!("{ctx} must be a bool"))
}

fn as_array<'a>(value: &'a Value, ctx: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("{ctx} must be an array"))
}

fn as_object<'a>(value: &'a Value, ctx: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| format!("{ctx} must be an object"))
}

fn as_u64(value: &Value, ctx: &str) -> TestResult<u64> {
    value.as_u64().ok_or_else(|| format!("{ctx} must be a u64"))
}

fn string_vec(value: &Value, ctx: &str) -> TestResult<Vec<String>> {
    as_array(value, ctx)?
        .iter()
        .enumerate()
        .map(|(idx, item)| as_str(item, &format!("{ctx}[{idx}]")).map(str::to_owned))
        .collect()
}

fn string_set(value: &Value, ctx: &str) -> TestResult<BTreeSet<String>> {
    Ok(string_vec(value, ctx)?.into_iter().collect())
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn ensure_eq<T>(left: T, right: T, context: impl Into<String>) -> TestResult
where
    T: PartialEq + std::fmt::Debug,
{
    if left == right {
        Ok(())
    } else {
        Err(format!("{}: left={left:?} right={right:?}", context.into()))
    }
}

fn git_head(root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(root)
        .output()
        .map_err(|err| format!("git rev-parse HEAD failed to start: {err}"))?;
    ensure(
        output.status.success(),
        format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    let head = String::from_utf8(output.stdout)
        .map_err(|err| format!("git rev-parse HEAD was not UTF-8: {err}"))?
        .trim()
        .to_owned();
    ensure(
        is_hex_commit(&head),
        format!("git rev-parse HEAD returned invalid commit {head:?}"),
    )?;
    Ok(head)
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn assert_source_commit_current(root: &Path, burndown: &Value) -> TestResult {
    let source_commit = as_str(&burndown["source_commit"], "source_commit")?;
    ensure(
        source_commit == "current" || is_hex_commit(source_commit),
        format!("source_commit must be current or full hex commit, got {source_commit:?}"),
    )?;
    let head = git_head(root)?;
    ensure(
        source_commit == "current" || source_commit == head,
        "source_commit must be current or match current git HEAD",
    )
}

fn flatten_version_needs(value: &Value, ctx: &str) -> TestResult<BTreeSet<String>> {
    let mut flattened = BTreeSet::new();
    for (provider, versions) in as_object(value, ctx)? {
        for version in string_vec(versions, &format!("{ctx}.{provider}"))? {
            flattened.insert(format!("{provider}:{version}"));
        }
    }
    Ok(flattened)
}

fn matrix_requirement_ids(burndown: &Value) -> TestResult<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for row in as_array(
        &burndown["version_requirement_matrix"],
        "version_requirement_matrix",
    )? {
        let id = as_str(&row["requirement_id"], "matrix.requirement_id")?.to_owned();
        ensure(ids.insert(id.clone()), format!("duplicate matrix row {id}"))?;
        ensure_eq(
            id,
            format!(
                "{}:{}",
                as_str(&row["provider_library"], "matrix.provider_library")?,
                as_str(&row["version_node"], "matrix.version_node")?
            ),
            "requirement id must equal provider:version",
        )?;
    }
    Ok(ids)
}

fn assert_matrix_matches_snapshot(burndown: &Value, snapshot: &Value) -> TestResult {
    let snapshot_requirements = string_set(
        &snapshot["host_version_requirements"],
        "snapshot.host_version_requirements",
    )?;
    let snapshot_flattened =
        flatten_version_needs(&snapshot["version_needs"], "snapshot.version_needs")?;
    ensure_eq(
        &snapshot_flattened,
        &snapshot_requirements,
        "snapshot flattened version_needs",
    )?;

    let evidence_requirements = string_set(
        &burndown["current_forge_evidence"]["observed_host_version_requirements"],
        "burndown.observed_host_version_requirements",
    )?;
    let evidence_flattened = flatten_version_needs(
        &burndown["current_forge_evidence"]["observed_version_needs"],
        "burndown.observed_version_needs",
    )?;
    let readelf_flattened = flatten_version_needs(
        &burndown["current_forge_evidence"]["evidence_command_results"]["readelf_version"]["observed_version_needs"],
        "burndown.readelf_version.observed_version_needs",
    )?;
    let matrix_ids = matrix_requirement_ids(burndown)?;

    ensure_eq(
        evidence_requirements,
        snapshot_requirements.clone(),
        "burndown observed host version requirements",
    )?;
    ensure_eq(
        evidence_flattened,
        snapshot_requirements.clone(),
        "burndown observed version_needs",
    )?;
    ensure_eq(
        readelf_flattened,
        snapshot_requirements.clone(),
        "burndown readelf version_needs",
    )?;
    ensure_eq(
        matrix_ids,
        snapshot_requirements,
        "matrix rows must match snapshot host version requirements",
    )
}

#[test]
fn burndown_manifest_is_report_only_and_current() -> TestResult {
    let root = workspace_root()?;
    let burndown = load_json(&root, BURNDOWN_PATH)?;
    ensure_eq(
        as_str(&burndown["schema_version"], "schema_version")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(
        as_str(&burndown["manifest_id"], "manifest_id")?,
        "standalone-host-version-requirement-burndown",
        "manifest_id",
    )?;
    ensure_eq(as_str(&burndown["bead"], "bead")?, "bd-zyck1.90", "bead")?;
    assert_source_commit_current(&root, &burndown)?;

    let freshness = &burndown["source_commit_freshness_policy"];
    ensure_eq(
        as_str(&freshness["stale_result"], "freshness.stale_result")?,
        "block_standalone_host_version_requirement_burndown",
        "freshness stale_result",
    )?;
    ensure(
        !as_bool(
            &freshness["version_need_evidence_allowed_when_stale"],
            "version_need_evidence_allowed_when_stale",
        )?,
        "stale source commits must not allow version-need evidence",
    )?;

    let policy = &burndown["report_policy"];
    for field in [
        "promotion_allowed",
        "replacement_level_change_allowed",
        "host_version_requirement_claim_allowed",
        "default_build_profile_change_allowed",
    ] {
        ensure(
            !as_bool(&policy[field], field)?,
            format!("report policy {field} must be false"),
        )?;
    }
    ensure_eq(
        as_str(&policy["stale_result"], "policy.stale_result")?,
        "block_standalone_host_version_requirement_burndown",
        "policy stale_result",
    )
}

#[test]
fn matrix_matches_current_forge_snapshot() -> TestResult {
    let root = workspace_root()?;
    let burndown = load_json(&root, BURNDOWN_PATH)?;
    let plan = load_json(&root, HOST_PROBE_PLAN_PATH)?;
    let snapshot = get_path(
        &plan,
        "current_forge_blocker_projection.current_forge_blocker_value_snapshot",
    )?;

    ensure_eq(
        as_str(
            &burndown["current_forge_evidence"]["latest_probe_claim_status"],
            "latest_probe_claim_status",
        )?,
        as_str(&snapshot["claim_status"], "snapshot.claim_status")?,
        "claim status",
    )?;
    ensure_eq(
        as_str(
            &burndown["current_forge_evidence"]["latest_probe_failure_signature"],
            "latest_probe_failure_signature",
        )?,
        as_str(&snapshot["failure_signature"], "snapshot.failure_signature")?,
        "failure signature",
    )?;
    assert_matrix_matches_snapshot(&burndown, snapshot)?;
    ensure_eq(
        as_u64(
            &burndown["summary"]["host_version_requirement_count"],
            "summary.host_version_requirement_count",
        )?,
        4,
        "host version requirement count",
    )?;
    ensure_eq(
        as_u64(
            &burndown["summary"]["version_need_provider_count"],
            "summary.version_need_provider_count",
        )?,
        2,
        "provider count",
    )
}

#[test]
fn provider_burndown_covers_every_snapshot_provider() -> TestResult {
    let root = workspace_root()?;
    let burndown = load_json(&root, BURNDOWN_PATH)?;
    let providers_from_evidence = as_object(
        &burndown["current_forge_evidence"]["observed_version_needs"],
        "observed_version_needs",
    )?
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();

    let mut providers_from_rows = BTreeSet::new();
    for row in as_array(&burndown["provider_burndown"], "provider_burndown")? {
        let provider = as_str(&row["provider_library"], "provider.provider_library")?.to_owned();
        ensure(
            providers_from_rows.insert(provider.clone()),
            format!("duplicate provider burndown row {provider}"),
        )?;
        ensure(
            as_u64(&row["requirement_count"], "provider.requirement_count")? > 0,
            format!("{provider} must have at least one requirement"),
        )?;
        ensure(
            !string_vec(&row["blocking_reasons"], "provider.blocking_reasons")?.is_empty(),
            format!("{provider} must list blocking reasons"),
        )?;
        ensure(
            as_str(
                &row["owned_substitute_strategy"],
                "provider.owned_substitute_strategy",
            )?
            .contains("Remove"),
            format!("{provider} must have an owned substitute strategy"),
        )?;
    }
    ensure_eq(
        providers_from_rows,
        providers_from_evidence,
        "provider burndown rows must match observed version providers",
    )
}

#[test]
fn matrix_rows_have_evidence_and_exit_criteria() -> TestResult {
    let root = workspace_root()?;
    let burndown = load_json(&root, BURNDOWN_PATH)?;
    for row in as_array(
        &burndown["version_requirement_matrix"],
        "version_requirement_matrix",
    )? {
        let id = as_str(&row["requirement_id"], "matrix.requirement_id")?;
        ensure_eq(
            as_str(&row["blocker_reason"], "matrix.blocker_reason")?,
            "host_version_requirements",
            format!("{id} blocker_reason"),
        )?;
        ensure(
            as_str(&row["evidence_command"], "matrix.evidence_command")?
                .contains("readelf --version-info"),
            format!("{id} evidence command must use readelf --version-info"),
        )?;
        ensure(
            !string_vec(
                &row["corroborating_evidence_commands"],
                "matrix.corroborating_evidence_commands",
            )?
            .is_empty(),
            format!("{id} must have corroborating evidence commands"),
        )?;
        ensure(
            !string_vec(&row["exit_criteria"], "matrix.exit_criteria")?.is_empty(),
            format!("{id} must have exit criteria"),
        )?;
        ensure_eq(
            as_str(
                &row["claim_status_until_exit"],
                "matrix.claim_status_until_exit",
            )?,
            "claim_blocked",
            format!("{id} claim status until exit"),
        )?;
    }
    Ok(())
}

#[test]
fn stale_or_partial_version_need_refresh_blocks_claims() -> TestResult {
    let root = workspace_root()?;
    let burndown = load_json(&root, BURNDOWN_PATH)?;
    let plan = load_json(&root, HOST_PROBE_PLAN_PATH)?;
    let snapshot = get_path(
        &plan,
        "current_forge_blocker_projection.current_forge_blocker_value_snapshot",
    )?;
    assert_matrix_matches_snapshot(&burndown, snapshot)?;

    let mut missing_matrix_row = burndown.clone();
    missing_matrix_row["version_requirement_matrix"]
        .as_array_mut()
        .ok_or_else(|| "matrix must be array".to_string())?
        .pop();
    ensure(
        assert_matrix_matches_snapshot(&missing_matrix_row, snapshot).is_err(),
        "removing a matrix row must fail the snapshot comparison",
    )?;

    let mut stale_evidence = burndown.clone();
    stale_evidence["current_forge_evidence"]["observed_host_version_requirements"]
        .as_array_mut()
        .ok_or_else(|| "observed_host_version_requirements must be array".to_string())?
        .pop();
    ensure(
        assert_matrix_matches_snapshot(&stale_evidence, snapshot).is_err(),
        "partial evidence refresh must fail the snapshot comparison",
    )?;

    let mut stale_commit = burndown;
    stale_commit["source_commit"] =
        Value::String("0000000000000000000000000000000000000000".to_owned());
    ensure(
        assert_source_commit_current(&root, &stale_commit).is_err(),
        "stale source_commit must fail freshness validation",
    )
}
