//! Integration test: hermetic resolver/NSS lab manifest gate
//! (bd-b92jd.5.1).
//!
//! Loads `tests/conformance/hermetic_nss_resolver_lab.v1.json` and asserts
//! the structural invariants the per-scenario kernels will rely on:
//!
//!   * each scenario carries a unique scenario_id and harness_test_name;
//!   * each scenario declares strict + hardened runtime_modes (or an
//!     explicit reason this is reduced — none currently allowed);
//!   * each scenario references the fake-root files it actually needs,
//!     and every file kind is one of the supported kinds;
//!   * dns scenarios that require the fake UDP endpoint have
//!     `fake_dns_required: true` and the manifest declares the
//!     fake_dns_endpoint config;
//!   * execution_policy pins real_network_allowed=false with the
//!     opt-in env var documented;
//!   * minimum_scenario_counts hold per kind (catches a regression
//!     that drops a numeric / hosts / dns / passwd / group row);
//!   * claim_policy blocks DONE / L1+ without evidence and lists
//!     real_network_call_observed in rejected_evidence_kinds (so a
//!     future failing scenario that leaks UDP cannot be silently
//!     accepted).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

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

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn as_str<'a>(value: &'a Value, context: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .ok_or_else(|| test_error(format!("{context} must be a string")))
}

fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn manifest_path() -> PathBuf {
    workspace_root().join("tests/conformance/hermetic_nss_resolver_lab.v1.json")
}

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

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "real_network_call_observed",
    "missing_fake_root_file",
    "scenario_lacks_oracle",
    "scenario_lacks_runtime_mode_coverage",
    "duplicate_scenario_id",
    "stale_source_commit",
    "scenario_lacks_fixture_obligation",
];

const SUPPORTED_FILE_KINDS: &[&str] = &[
    "hosts_db",
    "services_db",
    "passwd_db",
    "group_db",
    "resolv_conf",
    "nsswitch_conf",
];

#[test]
fn manifest_is_well_formed() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    ensure_eq(
        manifest["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(manifest["bead"].as_str(), Some("bd-b92jd.5.1"), "bead")?;
    ensure(
        !manifest["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;

    let log_fields: Vec<&str> = as_array(&manifest["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;
    Ok(())
}

#[test]
fn execution_policy_forbids_real_network_by_default() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let policy = &manifest["execution_policy"];
    ensure_eq(
        policy["default_runner"].as_str(),
        Some("rch_only"),
        "execution_policy.default_runner",
    )?;
    ensure_eq(
        policy["real_network_allowed"].as_bool(),
        Some(false),
        "execution_policy.real_network_allowed must default to false",
    )?;
    let envvar = as_str(
        &policy["real_network_envvar_override"],
        "execution_policy.real_network_envvar_override",
    )?;
    ensure(
        envvar.starts_with("FRANKENLIBC_"),
        format!("real_network_envvar_override should be a FRANKENLIBC_* variable; got {envvar}"),
    )?;
    let template = as_str(
        &policy["cargo_invocation_template"],
        "execution_policy.cargo_invocation_template",
    )?;
    for marker in [
        "rch exec",
        "cargo test",
        "-p frankenlibc-harness",
        "<scenario_test_name>",
    ] {
        ensure(
            template.contains(marker),
            format!("cargo_invocation_template must contain {marker:?}; got {template:?}"),
        )?;
    }
    Ok(())
}

#[test]
fn fake_root_layout_is_well_formed() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let layout = &manifest["fake_root_layout"];
    let envvar = as_str(&layout["root_envvar"], "fake_root_layout.root_envvar")?;
    ensure(
        envvar.starts_with("FRANKENLIBC_"),
        format!("root_envvar should be a FRANKENLIBC_* variable; got {envvar}"),
    )?;
    let mut declared_paths: BTreeSet<String> = BTreeSet::new();
    for entry in as_array(&layout["files"], "fake_root_layout.files")? {
        let path = as_str(&entry["relative_path"], "file.relative_path")?;
        ensure(
            declared_paths.insert(path.to_string()),
            format!("fake_root_layout.files: duplicate relative_path {path}"),
        )?;
        let kind = as_str(&entry["kind"], "file.kind")?;
        ensure(
            SUPPORTED_FILE_KINDS.contains(&kind),
            format!("fake_root_layout.files: unsupported kind {kind} on {path}"),
        )?;
        ensure(
            !path.starts_with('/'),
            format!(
                "relative_path {path} must NOT be absolute; lab driver joins it under root_envvar"
            ),
        )?;
    }
    // Required minima — every mainline scenario relies on at least these.
    for must in [
        "etc/hosts",
        "etc/services",
        "etc/passwd",
        "etc/group",
        "etc/resolv.conf",
        "etc/nsswitch.conf",
    ] {
        ensure(
            declared_paths.contains(must),
            format!("fake_root_layout.files must declare {must}"),
        )?;
    }
    let dns = &layout["fake_dns_endpoint"];
    ensure_eq(
        dns["kind"].as_str(),
        Some("fake_udp_dns"),
        "fake_dns_endpoint.kind must be fake_udp_dns",
    )?;
    let dns_addr = as_str(&dns["default_address"], "fake_dns_endpoint.default_address")?;
    ensure(
        dns_addr.starts_with("127.")
            || dns_addr.starts_with("[::1]")
            || dns_addr.starts_with("::1")
            || dns_addr.starts_with("localhost"),
        format!("fake_dns_endpoint.default_address must be loopback; got {dns_addr}"),
    )?;
    Ok(())
}

#[test]
fn scenarios_are_unique_complete_and_meet_minimum_counts() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let layout_files: BTreeSet<String> = as_array(
        &manifest["fake_root_layout"]["files"],
        "fake_root_layout.files",
    )?
    .iter()
    .filter_map(|f| f["relative_path"].as_str().map(|s| s.to_string()))
    .collect();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let mut test_names: BTreeSet<String> = BTreeSet::new();
    let mut artifacts: BTreeSet<String> = BTreeSet::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();

    for row in as_array(&manifest["scenarios"], "scenarios")? {
        let id = as_str(&row["scenario_id"], "row.scenario_id")?;
        ensure(
            ids.insert(id.to_string()),
            format!("duplicate_scenario_id {id}"),
        )?;
        let test_name = as_str(&row["harness_test_name"], "row.harness_test_name")?;
        ensure(
            test_names.insert(test_name.to_string()),
            format!("duplicate harness_test_name {test_name}"),
        )?;
        let kind = as_str(&row["scenario_kind"], "row.scenario_kind")?;
        *by_kind.entry(kind.to_string()).or_default() += 1;

        let oracle = as_str(&row["oracle_kind"], "row.oracle_kind")?;
        ensure(
            !oracle.is_empty(),
            format!("scenario {id}: scenario_lacks_oracle"),
        )?;
        let modes: Vec<&str> = as_array(&row["runtime_modes"], "row.runtime_modes")?
            .iter()
            .map(|v| v.as_str().unwrap_or_default())
            .collect();
        ensure(
            modes.contains(&"strict") && modes.contains(&"hardened"),
            format!(
                "scenario {id}: scenario_lacks_runtime_mode_coverage — runtime_modes must include both strict and hardened"
            ),
        )?;
        let obligation = as_str(&row["fixture_obligation"], "row.fixture_obligation")?;
        ensure(
            !obligation.is_empty(),
            format!("scenario {id}: scenario_lacks_fixture_obligation"),
        )?;

        let evidence = as_str(&row["evidence_artifact"], "row.evidence_artifact")?;
        ensure(
            evidence.starts_with("target/conformance/nss_lab/") && evidence.ends_with(".jsonl"),
            format!(
                "scenario {id}: evidence_artifact {evidence} must live under target/conformance/nss_lab/ and end in .jsonl"
            ),
        )?;
        ensure(
            artifacts.insert(evidence.to_string()),
            format!("scenario {id}: duplicate evidence_artifact {evidence}"),
        )?;

        for needed in as_array(&row["fake_root_files_needed"], "row.fake_root_files_needed")? {
            let needed = as_str(needed, "row.fake_root_files_needed[]")?;
            ensure(
                layout_files.contains(needed),
                format!(
                    "scenario {id}: missing_fake_root_file references {needed} which fake_root_layout does not declare"
                ),
            )?;
        }

        if kind == "dns" {
            ensure_eq(
                row["fake_dns_required"].as_bool(),
                Some(true),
                format!("scenario {id} (dns): fake_dns_required must be true"),
            )?;
        }
    }

    let minimums = manifest["minimum_scenario_counts"]
        .as_object()
        .ok_or_else(|| test_error("minimum_scenario_counts must be an object"))?;
    for (kind, expected) in minimums {
        let expected = expected.as_u64().unwrap_or(0) as usize;
        let actual = by_kind.get(kind).copied().unwrap_or(0);
        ensure(
            actual >= expected,
            format!("scenario_kind {kind}: have {actual}, minimum is {expected}"),
        )?;
    }
    Ok(())
}

#[test]
fn claim_policy_blocks_done_levels_and_real_network_observation() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let policy = &manifest["claim_policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_lab_evidence_current"),
        "claim_policy.default_decision",
    )?;
    let block_status: Vec<&str> = as_array(
        &policy["block_status_without_evidence"],
        "block_status_without_evidence",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    ensure(
        block_status.contains(&"DONE"),
        "claim_policy must block DONE without evidence",
    )?;
    let block_levels: Vec<&str> = as_array(
        &policy["block_replacement_levels_without_evidence"],
        "block_replacement_levels_without_evidence",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for level in ["L1", "L2", "L3"] {
        ensure(
            block_levels.contains(&level),
            format!("claim_policy must block replacement level {level}"),
        )?;
    }
    let rejected: Vec<&str> = as_array(
        &policy["rejected_evidence_kinds"],
        "rejected_evidence_kinds",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for kind in REJECTED_EVIDENCE_KINDS {
        ensure(
            rejected.contains(kind),
            format!("rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn consuming_gates_exist_on_disk() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let root = workspace_root();
    for gate in as_array(&manifest["consuming_gates"], "consuming_gates")? {
        let path = as_str(gate, "consuming_gates[]")?;
        ensure(
            root.join(path).exists(),
            format!("consuming_gates entry not found on disk: {path}"),
        )?;
    }
    Ok(())
}
