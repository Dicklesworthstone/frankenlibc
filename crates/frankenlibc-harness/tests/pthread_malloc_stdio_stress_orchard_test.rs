//! Integration test: pthread/malloc/stdio stress orchard manifest gate
//! (bd-b92jd.5.3).
//!
//! The orchard manifest at
//! `tests/conformance/pthread_malloc_stdio_stress_orchard.v1.json` declares
//! every deterministic stress scenario that must remain replayable under
//! rch with a fixed PCG32 seed, bounded iteration tier, and explicit
//! oracle. This gate verifies the manifest's structural invariants — it
//! does NOT actually run the heavy stress kernels (those land in their
//! own per-scenario harness_test_name files referenced by each row).
//! The contract:
//!
//!   * scenario_id, harness_test_name, and seed are unique across rows;
//!   * each row carries a non-empty oracle_kind, runtime_modes list,
//!     and evidence_artifact path under target/conformance/stress_orchard/;
//!   * iteration tiers are monotone in iteration count and thread count;
//!   * minimum_scenario_counts hold per kind (catches drift that drops a
//!     malloc, stdio, pthread, or hardened_repair scenario);
//!   * execution_policy.default_runner == "rch_only" so heavy workloads
//!     never land on shared local CI;
//!   * claim_policy blocks DONE / L1+ without evidence and enumerates
//!     the rejected_evidence_kinds.

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
    workspace_root().join("tests/conformance/pthread_malloc_stdio_stress_orchard.v1.json")
}

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
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "duration_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "missing_scenario_seed",
    "missing_oracle_kind",
    "non_deterministic_input",
    "unbounded_iteration_count",
    "local_only_runner",
    "stale_source_commit",
    "missing_runtime_mode_coverage",
];

#[test]
fn manifest_is_well_formed() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    ensure_eq(
        manifest["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(manifest["bead"].as_str(), Some("bd-b92jd.5.3"), "bead")?;
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
fn execution_policy_pins_rch_only_default_runner() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let policy = &manifest["execution_policy"];
    ensure_eq(
        policy["default_runner"].as_str(),
        Some("rch_only"),
        "execution_policy.default_runner",
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
    ensure_eq(
        policy["iteration_tier_envvar"].as_str(),
        Some("FRANKENLIBC_STRESS_TIER"),
        "iteration_tier_envvar",
    )?;
    ensure_eq(
        policy["default_tier"].as_str(),
        Some("smoke"),
        "default_tier",
    )?;
    Ok(())
}

#[test]
fn iteration_tiers_are_monotone() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let tiers = as_array(&manifest["iteration_tiers"], "iteration_tiers")?;
    ensure(
        tiers.len() >= 2,
        "iteration_tiers must declare at least two levels",
    )?;
    let mut prev_iters: u64 = 0;
    let mut prev_threads: u64 = 0;
    for tier in tiers {
        let iters = tier["iterations"]
            .as_u64()
            .ok_or_else(|| test_error("iterations must be an integer"))?;
        let threads = tier["thread_count"]
            .as_u64()
            .ok_or_else(|| test_error("thread_count must be an integer"))?;
        ensure(
            iters > 0 && iters <= 1_000_000,
            format!("iteration count {iters} out of bounded range (0, 1_000_000]"),
        )?;
        ensure(
            threads > 0 && threads <= 64,
            format!("thread_count {threads} out of bounded range (0, 64]"),
        )?;
        ensure(
            iters > prev_iters,
            format!(
                "iteration_tiers must be monotone increasing in iterations (prev={prev_iters}, this={iters})"
            ),
        )?;
        ensure(
            threads >= prev_threads,
            format!(
                "iteration_tiers must be monotone non-decreasing in thread_count (prev={prev_threads}, this={threads})"
            ),
        )?;
        prev_iters = iters;
        prev_threads = threads;
    }
    Ok(())
}

#[test]
fn scenarios_carry_unique_ids_seeds_and_test_names() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let mut seeds: BTreeSet<String> = BTreeSet::new();
    let mut test_names: BTreeSet<String> = BTreeSet::new();
    let mut artifacts: BTreeSet<String> = BTreeSet::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();

    for row in as_array(&manifest["scenarios"], "scenarios")? {
        let id = as_str(&row["scenario_id"], "row.scenario_id")?;
        ensure(
            ids.insert(id.to_string()),
            format!("duplicate scenario_id {id}"),
        )?;
        let kind = as_str(&row["scenario_kind"], "row.scenario_kind")?;
        *by_kind.entry(kind.to_string()).or_default() += 1;
        let seed = as_str(&row["seed"], "row.seed")?;
        ensure(
            seed.starts_with("0x") && seed.len() >= 18,
            format!("scenario {id}: seed {seed} must be a 0x-prefixed 64-bit literal"),
        )?;
        ensure(
            seeds.insert(seed.to_string()),
            format!("duplicate seed across scenarios: {seed}"),
        )?;
        let test_name = as_str(&row["harness_test_name"], "row.harness_test_name")?;
        ensure(
            test_names.insert(test_name.to_string()),
            format!("duplicate harness_test_name {test_name}"),
        )?;
        let oracle = as_str(&row["oracle_kind"], "row.oracle_kind")?;
        ensure(
            !oracle.is_empty(),
            format!("scenario {id}: oracle_kind must be non-empty"),
        )?;
        let modes = as_array(&row["runtime_modes"], "row.runtime_modes")?;
        ensure(
            !modes.is_empty(),
            format!("scenario {id}: runtime_modes must be non-empty"),
        )?;
        for mode in modes {
            let m = as_str(mode, "row.runtime_modes[]")?;
            ensure(
                matches!(m, "strict" | "hardened"),
                format!("scenario {id}: runtime_mode {m:?} must be strict|hardened"),
            )?;
        }
        let evidence = as_str(&row["evidence_artifact"], "row.evidence_artifact")?;
        ensure(
            evidence.starts_with("target/conformance/stress_orchard/"),
            format!(
                "scenario {id}: evidence_artifact {evidence:?} must live under target/conformance/stress_orchard/"
            ),
        )?;
        ensure(
            evidence.ends_with(".jsonl"),
            format!("scenario {id}: evidence_artifact {evidence:?} must be .jsonl"),
        )?;
        ensure(
            artifacts.insert(evidence.to_string()),
            format!("duplicate evidence_artifact {evidence}"),
        )?;
    }

    let minimums = manifest["minimum_scenario_counts"]
        .as_object()
        .ok_or_else(|| test_error("minimum_scenario_counts must be an object"))?;
    for (kind, expected) in minimums {
        let expected = expected.as_u64().unwrap_or(0) as usize;
        let actual = by_kind.get(kind).copied().unwrap_or(0);
        ensure(
            actual >= expected,
            format!("scenario_kind {kind}: have {actual} rows, minimum is {expected}"),
        )?;
    }
    Ok(())
}

#[test]
fn claim_policy_blocks_done_and_replacement_levels_without_evidence() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let policy = &manifest["claim_policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_orchard_evidence_current"),
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
fn hardened_repair_scenarios_only_run_in_hardened_mode() -> TestResult {
    // hardened_repair oracles assert decisions that strict mode is documented
    // not to take. If a future edit lists strict in runtime_modes for these
    // rows it would silently weaken the assertion; this gate refuses that.
    let manifest = load_json(&manifest_path())?;
    for row in as_array(&manifest["scenarios"], "scenarios")? {
        let kind = as_str(&row["scenario_kind"], "row.scenario_kind")?;
        if kind != "hardened_repair" {
            continue;
        }
        let id = as_str(&row["scenario_id"], "row.scenario_id")?;
        let modes: Vec<&str> = as_array(&row["runtime_modes"], "row.runtime_modes")?
            .iter()
            .map(|v| v.as_str().unwrap_or_default())
            .collect();
        ensure_eq(
            modes,
            vec!["hardened"],
            format!("hardened_repair scenario {id} must declare runtime_modes=[hardened] only"),
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
