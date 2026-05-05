//! Integration test: pthread/malloc/stdio stress orchard manifest gate
//! (bd-b92jd.5.3).
//!
//! The orchard manifest at
//! `tests/conformance/pthread_malloc_stdio_stress_orchard.v1.json` declares
//! every deterministic stress scenario that must remain replayable under
//! rch with a fixed PCG32 seed, bounded iteration tier, and explicit
//! oracle. This gate verifies the manifest's structural invariants; the
//! execution contract is covered by the sibling `*_execution_test` gate.
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
use std::path::{Component, Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn test_error_args(message: std::fmt::Arguments<'_>) -> Box<dyn Error> {
    std::io::Error::other(message.to_string()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn ensure_args(condition: bool, message: std::fmt::Arguments<'_>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error_args(message))
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

fn ensure_eq_args<T>(actual: T, expected: T, context: std::fmt::Arguments<'_>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{context}: expected {:?}, got {:?}",
            expected, actual
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

fn field<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str, Box<dyn Error>> {
    as_str(field(value, key, context)?, &format!("{context}.{key}"))
}

fn array_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    as_array(field(value, key, context)?, &format!("{context}.{key}"))
}

fn u64_field(value: &Value, key: &str, context: &str) -> Result<u64, Box<dyn Error>> {
    field(value, key, context)?
        .as_u64()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an integer")))
}

fn safe_workspace_path(root: &Path, reference: &str) -> Result<PathBuf, Box<dyn Error>> {
    let rel_path = Path::new(reference);
    ensure(!rel_path.is_absolute(), "workspace path must be relative")?;
    for component in rel_path.components() {
        ensure(
            matches!(component, Component::Normal(_)),
            "workspace path contains unsafe components",
        )?;
    }
    Ok(root.join(rel_path)) // ubs:ignore - rel_path is rejected unless relative with only normal components.
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
    "stress_kernel_id",
    "expected",
    "actual",
    "counters",
    "errno",
    "decision_path",
    "healing_action",
    "failure_signatures",
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
    "missing_normal_tier_kernel",
    "missing_counter_field",
];

#[test]
fn manifest_is_well_formed() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let source_commit = string_field(&manifest, "source_commit", "manifest")?;
    ensure_eq(
        string_field(&manifest, "schema_version", "manifest")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(
        string_field(&manifest, "bead", "manifest")?,
        "bd-b92jd.5.3",
        "bead",
    )?;
    ensure(!source_commit.is_empty(), "source_commit must be set")?;

    let log_fields: Vec<&str> = array_field(&manifest, "required_log_fields", "manifest")?
        .iter()
        .map(|v| as_str(v, "required_log_fields[]"))
        .collect::<Result<_, _>>()?;
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
    let policy = field(&manifest, "execution_policy", "manifest")?;
    ensure_eq(
        string_field(policy, "default_runner", "execution_policy")?,
        "rch_only",
        "execution_policy.default_runner",
    )?;
    let template = string_field(policy, "cargo_invocation_template", "execution_policy")?;
    for marker in [
        "rch exec",
        "cargo test",
        "-p frankenlibc-harness",
        "<scenario_test_name>",
    ] {
        ensure_args(
            template.contains(marker),
            format_args!("cargo_invocation_template must contain {marker:?}; got {template:?}"),
        )?;
    }
    ensure_eq(
        string_field(policy, "iteration_tier_envvar", "execution_policy")?,
        "FRANKENLIBC_STRESS_TIER",
        "iteration_tier_envvar",
    )?;
    let default_tiers: Vec<&str> = array_field(policy, "default_tiers", "execution_policy")?
        .iter()
        .map(|v| as_str(v, "execution_policy.default_tiers[]"))
        .collect::<Result<_, _>>()?;
    ensure_eq(
        default_tiers,
        vec!["smoke", "normal"],
        "execution_policy.default_tiers",
    )?;
    ensure_eq(
        string_field(policy, "deep_tier_envvar", "execution_policy")?,
        "FRANKENLIBC_STRESS_INCLUDE_DEEP",
        "deep_tier_envvar",
    )?;
    ensure_eq(
        string_field(policy, "default_tier", "execution_policy")?,
        "smoke",
        "default_tier",
    )?;
    Ok(())
}

#[test]
fn iteration_tiers_are_monotone() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let tiers = array_field(&manifest, "iteration_tiers", "manifest")?;
    ensure(
        tiers.len() >= 2,
        "iteration_tiers must declare at least two levels",
    )?;
    let mut prev_iters: u64 = 0;
    let mut prev_threads: u64 = 0;
    for tier in tiers {
        let iters = u64_field(tier, "iterations", "iteration_tiers[]")?;
        let threads = u64_field(tier, "thread_count", "iteration_tiers[]")?;
        ensure_args(
            iters > 0 && iters <= 1_000_000,
            format_args!("iteration count {iters} out of bounded range (0, 1_000_000]"),
        )?;
        ensure_args(
            threads > 0 && threads <= 64,
            format_args!("thread_count {threads} out of bounded range (0, 64]"),
        )?;
        ensure_args(
            iters > prev_iters,
            format_args!(
                "iteration_tiers must be monotone increasing in iterations (prev={prev_iters}, this={iters})"
            ),
        )?;
        ensure_args(
            threads >= prev_threads,
            format_args!(
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
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    let mut seeds: BTreeSet<&str> = BTreeSet::new();
    let mut test_names: BTreeSet<&str> = BTreeSet::new();
    let mut artifacts: BTreeSet<&str> = BTreeSet::new();
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();

    for row in array_field(&manifest, "scenarios", "manifest")? {
        let id = string_field(row, "scenario_id", "row")?;
        ensure_args(ids.insert(id), format_args!("duplicate scenario_id {id}"))?;
        let kind = string_field(row, "scenario_kind", "row")?;
        *by_kind.entry(kind).or_default() += 1;
        let seed = string_field(row, "seed", "row")?;
        ensure_args(
            seed.starts_with("0x") && seed.len() >= 18,
            format_args!("scenario {id}: seed {seed} must be a 0x-prefixed 64-bit literal"),
        )?;
        ensure_args(
            seeds.insert(seed),
            format_args!("duplicate seed across scenarios: {seed}"),
        )?;
        let test_name = string_field(row, "harness_test_name", "row")?;
        ensure_args(
            test_names.insert(test_name),
            format_args!("duplicate harness_test_name {test_name}"),
        )?;
        let oracle = string_field(row, "oracle_kind", "row")?;
        ensure_args(
            !oracle.is_empty(),
            format_args!("scenario {id}: oracle_kind must be non-empty"),
        )?;
        let kernel = field(row, "normal_tier_kernel", "row")?
            .as_object()
            .ok_or_else(|| test_error("row.normal_tier_kernel must be an object"))?;
        let kernel_id = kernel
            .get("kernel_id")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("normal_tier_kernel.kernel_id must be a string"))?;
        ensure_args(
            !kernel_id.is_empty(),
            format_args!("scenario {id}: normal_tier_kernel.kernel_id must be non-empty"),
        )?;
        ensure_eq_args(
            kernel.get("minimum_tier").and_then(Value::as_str),
            Some("normal"),
            format_args!("scenario {id}: normal_tier_kernel.minimum_tier"),
        )?;
        let counter_fields = kernel
            .get("counter_fields")
            .and_then(Value::as_array)
            .ok_or_else(|| test_error("normal_tier_kernel.counter_fields must be an array"))?;
        ensure_args(
            !counter_fields.is_empty(),
            format_args!("scenario {id}: counter_fields must be non-empty"),
        )?;
        for counter in counter_fields {
            let counter = as_str(counter, "normal_tier_kernel.counter_fields[]")?;
            ensure_args(
                !counter.is_empty(),
                format_args!("scenario {id}: counter field cannot be empty"),
            )?;
        }
        let modes = array_field(row, "runtime_modes", "row")?;
        ensure_args(
            !modes.is_empty(),
            format_args!("scenario {id}: runtime_modes must be non-empty"),
        )?;
        for mode in modes {
            let m = as_str(mode, "row.runtime_modes[]")?;
            ensure_args(
                matches!(m, "strict" | "hardened"),
                format_args!("scenario {id}: runtime_mode {m:?} must be strict|hardened"),
            )?;
        }
        let evidence = string_field(row, "evidence_artifact", "row")?;
        ensure_args(
            evidence.starts_with("target/conformance/stress_orchard/"),
            format_args!(
                "scenario {id}: evidence_artifact {evidence:?} must live under target/conformance/stress_orchard/"
            ),
        )?;
        ensure_args(
            evidence.ends_with(".jsonl"),
            format_args!("scenario {id}: evidence_artifact {evidence:?} must be .jsonl"),
        )?;
        ensure_args(
            artifacts.insert(evidence),
            format_args!("duplicate evidence_artifact {evidence}"),
        )?;
    }

    let minimums = field(&manifest, "minimum_scenario_counts", "manifest")?
        .as_object()
        .ok_or_else(|| test_error("minimum_scenario_counts must be an object"))?;
    for (kind, expected) in minimums {
        let expected = expected.as_u64().ok_or_else(|| {
            test_error_args(format_args!(
                "minimum_scenario_counts.{kind} must be an integer"
            ))
        })?;
        let expected = usize::try_from(expected).map_err(|err| {
            test_error_args(format_args!(
                "minimum_scenario_counts.{kind} is too large: {err}"
            ))
        })?;
        let actual = by_kind.get(kind.as_str()).copied().unwrap_or(0);
        ensure_args(
            actual >= expected,
            format_args!("scenario_kind {kind}: have {actual} rows, minimum is {expected}"),
        )?;
    }
    Ok(())
}

#[test]
fn claim_policy_blocks_done_and_replacement_levels_without_evidence() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let policy = field(&manifest, "claim_policy", "manifest")?;
    ensure_eq(
        string_field(policy, "default_decision", "claim_policy")?,
        "block_until_orchard_evidence_current",
        "claim_policy.default_decision",
    )?;
    let block_status: Vec<&str> =
        array_field(policy, "block_status_without_evidence", "claim_policy")?
            .iter()
            .map(|v| as_str(v, "claim_policy.block_status_without_evidence[]"))
            .collect::<Result<_, _>>()?;
    ensure(
        block_status.contains(&"DONE"),
        "claim_policy must block DONE without evidence",
    )?;
    let block_levels: Vec<&str> = array_field(
        policy,
        "block_replacement_levels_without_evidence",
        "claim_policy",
    )?
    .iter()
    .map(|v| {
        as_str(
            v,
            "claim_policy.block_replacement_levels_without_evidence[]",
        )
    })
    .collect::<Result<_, _>>()?;
    for level in ["L1", "L2", "L3"] {
        ensure_args(
            block_levels.contains(&level),
            format_args!("claim_policy must block replacement level {level}"),
        )?;
    }
    let rejected: Vec<&str> = array_field(policy, "rejected_evidence_kinds", "claim_policy")?
        .iter()
        .map(|v| as_str(v, "claim_policy.rejected_evidence_kinds[]"))
        .collect::<Result<_, _>>()?;
    for kind in REJECTED_EVIDENCE_KINDS {
        ensure_args(
            rejected.contains(kind),
            format_args!("rejected_evidence_kinds must include {kind}"),
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
    for row in array_field(&manifest, "scenarios", "manifest")? {
        let kind = string_field(row, "scenario_kind", "row")?;
        if kind != "hardened_repair" {
            continue;
        }
        let id = string_field(row, "scenario_id", "row")?;
        let modes: Vec<&str> = array_field(row, "runtime_modes", "row")?
            .iter()
            .map(|v| as_str(v, "row.runtime_modes[]"))
            .collect::<Result<_, _>>()?;
        ensure_eq_args(
            modes,
            vec!["hardened"],
            format_args!(
                "hardened_repair scenario {id} must declare runtime_modes=[hardened] only"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn consuming_gates_exist_on_disk() -> TestResult {
    let manifest = load_json(&manifest_path())?;
    let root = workspace_root();
    for gate in array_field(&manifest, "consuming_gates", "manifest")? {
        let path = as_str(gate, "consuming_gates[]")?;
        ensure_args(
            safe_workspace_path(&root, path)?.exists(),
            format_args!("consuming_gates entry not found on disk: {path}"),
        )?;
    }
    Ok(())
}
