//! Conformance gate for `tests/conformance/standalone_blocker_burndown_dag.v1.json`
//! (bd-juvqm.14).
//!
//! The DAG manifest is the report-only output of the standalone blocker
//! burn-down planner: given the owner-action ledger, live host-dependency
//! blocker action rows, and burn-down progress rollup, it proposes the next set
//! of beads an agent should consider creating (deduped against any open
//! tracker rows). The planner explicitly does not create beads — agents
//! decide manually.
//!
//! This gate enforces:
//!
//!   * Schema sanity (top-level fields, policy block, regeneration_note).
//!   * Inputs reference real conformance manifests.
//!   * `nodes[*].blocking_reason` exactly covers the ledger's
//!     `ledger_rows[*].blocking_reason` set (no missing, no extra) —
//!     the DAG cannot drift from the ledger silently.
//!   * `nodes[*].blocking_reason` exactly covers the live
//!     `blocker_action_required_rows` set from the host dependency probe plan.
//!   * Dedupe keys are unique and follow the
//!     `burn-<owner_surface>-<blocking_reason>` format.
//!   * Every owner_surface lands on a `validation_lane` listed in the
//!     rch validation lane plan (bd-juvqm.9).
//!   * Every `depends_on` edge resolves to a node in the same DAG.
//!   * The DAG is acyclic (no cycle reachable via depends_on).
//!   * Each node carries a non-trivial `first_safe_action` and
//!     `exit_criteria` so a future agent can act without re-reading
//!     the entire ledger row.
//!
//! Failure mode is fail-closed: the DAG cannot promote into bead
//! creation while any of these invariants is violated.

use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn dag_path() -> PathBuf {
    workspace_root().join("tests/conformance/standalone_blocker_burndown_dag.v1.json")
}

fn ledger_path() -> PathBuf {
    workspace_root().join("tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json")
}

fn host_dependency_probe_plan_path() -> PathBuf {
    workspace_root().join("tests/conformance/standalone_host_dependency_probe_plan.v1.json")
}

fn rch_plan_path() -> PathBuf {
    workspace_root().join("tests/conformance/rch_validation_lane_plan.v1.json")
}

fn nodes(dag: &Value) -> Result<&Vec<Value>, Box<dyn Error>> {
    dag["nodes"]
        .as_array()
        .ok_or_else(|| test_error("dag.nodes must be an array"))
}

fn dag_blocking_reasons(dag: &Value) -> Result<BTreeSet<String>, Box<dyn Error>> {
    Ok(nodes(dag)?
        .iter()
        .filter_map(|n| n["blocking_reason"].as_str().map(|s| s.to_string()))
        .collect())
}

#[test]
fn dag_has_required_top_level_shape() -> TestResult {
    let dag = load_json(&dag_path())?;
    ensure(
        dag["schema_version"] == "v1",
        "schema_version must be \"v1\"",
    )?;
    ensure(dag["bead"] == "bd-juvqm.14", "bead must be bd-juvqm.14")?;
    ensure(
        dag["manifest_id"] == "standalone-blocker-burndown-dag",
        "manifest_id must be standalone-blocker-burndown-dag",
    )?;
    ensure(
        dag["source_commit"]
            .as_str()
            .map(|s| s == "current" || s.len() == 40)
            .unwrap_or(false),
        "source_commit must be \"current\" or a 40-char SHA",
    )?;
    let policy = dag["policy"]
        .as_object()
        .ok_or_else(|| test_error("dag.policy must be an object"))?;
    for required_policy in [
        "dedupe_key_format",
        "auto_create_beads",
        "ledger_coverage_required",
        "live_action_row_coverage_required",
        "ledger_extra_blocker_result",
        "ledger_missing_blocker_result",
        "live_action_row_extra_blocker_result",
        "live_action_row_missing_blocker_result",
        "stale_source_commit_result",
        "duplicate_dedupe_key_result",
        "missing_owner_surface_result",
        "missing_validation_lane_result",
        "validation_lane_must_match_rch_plan_surface_id",
    ] {
        ensure(
            policy.get(required_policy).is_some(),
            format!("policy.{required_policy} must be present"),
        )?;
    }
    ensure(
        policy["auto_create_beads"] == Value::Bool(false),
        "policy.auto_create_beads must be false (planner is report-only)",
    )?;
    ensure(
        policy["ledger_coverage_required"] == Value::Bool(true),
        "policy.ledger_coverage_required must be true",
    )?;
    ensure(
        policy["live_action_row_coverage_required"] == Value::Bool(true),
        "policy.live_action_row_coverage_required must be true",
    )?;
    ensure(
        policy["live_action_row_extra_blocker_result"] == "fail_closed",
        "policy.live_action_row_extra_blocker_result must be fail_closed",
    )?;
    ensure(
        policy["live_action_row_missing_blocker_result"] == "fail_closed",
        "policy.live_action_row_missing_blocker_result must be fail_closed",
    )?;
    ensure(
        dag["regeneration_note"]
            .as_str()
            .map(|s| s.len() > 60)
            .unwrap_or(false),
        "regeneration_note must be a non-trivial string",
    )?;
    Ok(())
}

#[test]
fn inputs_reference_real_manifests() -> TestResult {
    let dag = load_json(&dag_path())?;
    let inputs = dag["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for (key, value) in inputs {
        let path = value.as_str().unwrap_or("");
        let abs = workspace_root().join(path);
        ensure(
            abs.exists(),
            format!("input {key} -> {path} does not exist on disk"),
        )?;
    }
    Ok(())
}

#[test]
fn dag_blocking_reasons_match_ledger_exactly() -> TestResult {
    let dag = load_json(&dag_path())?;
    let ledger = load_json(&ledger_path())?;

    let dag_reasons = dag_blocking_reasons(&dag)?;

    let ledger_rows = ledger["ledger_rows"]
        .as_array()
        .ok_or_else(|| test_error("ledger.ledger_rows must be an array"))?;
    let ledger_reasons: BTreeSet<String> = ledger_rows
        .iter()
        .filter_map(|r| r["blocking_reason"].as_str().map(|s| s.to_string()))
        .collect();

    let missing: Vec<&String> = ledger_reasons.difference(&dag_reasons).collect();
    let extra: Vec<&String> = dag_reasons.difference(&ledger_reasons).collect();

    ensure(
        missing.is_empty(),
        format!(
            "DAG missing blocking_reasons present in ledger: {:?}",
            missing
        ),
    )?;
    ensure(
        extra.is_empty(),
        format!(
            "DAG has blocking_reasons not in ledger (stale planner output): {:?}",
            extra
        ),
    )?;
    Ok(())
}

#[test]
fn dag_blocking_reasons_match_live_action_rows_exactly() -> TestResult {
    let dag = load_json(&dag_path())?;
    let plan = load_json(&host_dependency_probe_plan_path())?;

    let dag_reasons = dag_blocking_reasons(&dag)?;
    let action_rows = plan["current_forge_blocker_projection"]["blocker_action_required_rows"]
        .as_object()
        .ok_or_else(|| test_error("blocker_action_required_rows must be an object"))?;
    let live_reasons: BTreeSet<String> = action_rows.keys().cloned().collect();

    for (reason, row) in action_rows {
        ensure(
            row["blocking_reason"].as_str() == Some(reason),
            format!("live action row key {reason} must match row.blocking_reason"),
        )?;
        ensure(
            row["promotion_allowed"] == Value::Bool(false),
            format!("live action row {reason} must not allow promotion"),
        )?;
        ensure(
            row["current_blocker_values"]
                .as_array()
                .map(|values| !values.is_empty())
                .unwrap_or(false),
            format!("live action row {reason} must carry current_blocker_values"),
        )?;
    }

    let missing: Vec<&String> = live_reasons.difference(&dag_reasons).collect();
    let extra: Vec<&String> = dag_reasons.difference(&live_reasons).collect();

    ensure(
        missing.is_empty(),
        format!("DAG missing blocking_reasons present in live action rows: {missing:?}"),
    )?;
    ensure(
        extra.is_empty(),
        format!("DAG has blocking_reasons not in live action rows: {extra:?}"),
    )?;
    Ok(())
}

#[test]
fn dedupe_keys_are_unique_and_well_formed() -> TestResult {
    let dag = load_json(&dag_path())?;
    let mut seen: HashSet<String> = HashSet::new();
    for node in nodes(&dag)? {
        let key = node["dedupe_key"]
            .as_str()
            .ok_or_else(|| test_error(format!("node missing dedupe_key: {node}")))?;
        ensure(
            key.starts_with("burn-"),
            format!("dedupe_key must start with `burn-`: {key}"),
        )?;
        let owner = node["owner_surface"].as_str().unwrap_or("");
        let reason = node["blocking_reason"].as_str().unwrap_or("");
        let expected = format!("burn-{owner}-{reason}");
        ensure(
            key == expected,
            format!("dedupe_key {key} must match burn-<owner>-<reason> = {expected}"),
        )?;
        ensure(
            seen.insert(key.to_string()),
            format!("duplicate dedupe_key: {key}"),
        )?;
    }
    Ok(())
}

#[test]
fn every_owner_surface_in_canonical_set() -> TestResult {
    let dag = load_json(&dag_path())?;
    let ledger = load_json(&ledger_path())?;
    let canonical: BTreeSet<String> = ledger["required_owner_surfaces"]
        .as_array()
        .ok_or_else(|| test_error("ledger.required_owner_surfaces must be an array"))?
        .iter()
        .filter_map(|s| s.as_str().map(|s| s.to_string()))
        .collect();
    for node in nodes(&dag)? {
        let owner = node["owner_surface"]
            .as_str()
            .ok_or_else(|| test_error(format!("node missing owner_surface: {node}")))?;
        ensure(
            canonical.contains(owner),
            format!(
                "node owner_surface {owner} not in ledger canonical set {:?}",
                canonical
            ),
        )?;
    }
    Ok(())
}

#[test]
fn every_validation_lane_appears_in_rch_plan() -> TestResult {
    let dag = load_json(&dag_path())?;
    let plan = load_json(&rch_plan_path())?;
    let surface_ids: BTreeSet<String> = plan["surfaces"]
        .as_array()
        .ok_or_else(|| test_error("rch plan surfaces must be an array"))?
        .iter()
        .filter_map(|s| s["surface_id"].as_str().map(|s| s.to_string()))
        .collect();
    for node in nodes(&dag)? {
        let lane = node["validation_lane"]
            .as_str()
            .ok_or_else(|| test_error(format!("node missing validation_lane: {node}")))?;
        ensure(
            surface_ids.contains(lane),
            format!(
                "node validation_lane {lane} is not a surface_id in the rch validation lane plan; available: {:?}",
                surface_ids
            ),
        )?;
    }
    Ok(())
}

#[test]
fn depends_on_edges_resolve_to_known_nodes() -> TestResult {
    let dag = load_json(&dag_path())?;
    let n = nodes(&dag)?;
    let known: HashSet<String> = n
        .iter()
        .filter_map(|node| node["dedupe_key"].as_str().map(|s| s.to_string()))
        .collect();
    for node in n {
        let key = node["dedupe_key"].as_str().unwrap_or("?");
        let deps = node["depends_on"]
            .as_array()
            .ok_or_else(|| test_error(format!("node {key} missing depends_on array")))?;
        for dep in deps {
            let dep_key = dep
                .as_str()
                .ok_or_else(|| test_error(format!("node {key} depends_on entry must be string")))?;
            ensure(
                known.contains(dep_key),
                format!("node {key} depends_on {dep_key} which is not a known node"),
            )?;
            ensure(
                dep_key != key,
                format!("node {key} depends_on itself (self-loop)"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn dag_is_acyclic() -> TestResult {
    let dag = load_json(&dag_path())?;
    let n = nodes(&dag)?;

    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    for node in n {
        let key = node["dedupe_key"].as_str().unwrap_or("").to_string();
        let deps: Vec<String> = node["depends_on"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        graph.insert(key, deps);
    }

    // Kahn's algorithm: count in-degrees (the inverse graph), peel
    // off zero-in-degree nodes, expect to drain the entire set.
    // Here `depends_on` means "this node has the listed deps as
    // prerequisites", so an edge dep->node exists. In-degree of
    // a node = number of deps it has.
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    for (k, v) in &graph {
        in_degree.insert(k.clone(), v.len());
    }
    let mut frontier: Vec<String> = in_degree
        .iter()
        .filter_map(|(k, &d)| if d == 0 { Some(k.clone()) } else { None })
        .collect();
    let total = graph.len();
    let mut emitted = 0usize;

    // Build inverse: dep -> nodes that depend on dep
    let mut consumers: HashMap<String, Vec<String>> = HashMap::new();
    for (k, deps) in &graph {
        for d in deps {
            consumers.entry(d.clone()).or_default().push(k.clone());
        }
    }

    while let Some(k) = frontier.pop() {
        emitted += 1;
        if let Some(cs) = consumers.get(&k) {
            for c in cs {
                if let Some(d) = in_degree.get_mut(c) {
                    *d = d.saturating_sub(1);
                    if *d == 0 {
                        frontier.push(c.clone());
                    }
                }
            }
        }
    }

    ensure(
        emitted == total,
        format!("DAG contains a cycle: drained {emitted} of {total} nodes via Kahn's algorithm"),
    )?;
    Ok(())
}

#[test]
fn every_node_has_actionable_first_safe_action_and_exit_criteria() -> TestResult {
    let dag = load_json(&dag_path())?;
    for node in nodes(&dag)? {
        let key = node["dedupe_key"].as_str().unwrap_or("?");
        let action = node["first_safe_action"].as_str().unwrap_or("");
        let exit = node["exit_criteria"].as_str().unwrap_or("");
        ensure(
            action.len() > 30,
            format!(
                "node {key} first_safe_action must be a non-trivial sentence (>30 chars); got: {action}"
            ),
        )?;
        ensure(
            exit.len() > 30,
            format!(
                "node {key} exit_criteria must be a non-trivial sentence (>30 chars); got: {exit}"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn owner_surface_to_validation_lane_map_covers_all_surfaces() -> TestResult {
    let dag = load_json(&dag_path())?;
    let map = dag["owner_surface_to_validation_lane"]
        .as_object()
        .ok_or_else(|| test_error("dag.owner_surface_to_validation_lane must be an object"))?;
    for node in nodes(&dag)? {
        let owner = node["owner_surface"].as_str().unwrap_or("");
        let lane = node["validation_lane"].as_str().unwrap_or("");
        let mapped = map.get(owner).and_then(|v| v.as_str()).unwrap_or("");
        ensure(
            mapped == lane,
            format!(
                "node owner_surface={owner} carries validation_lane={lane}, but owner_surface_to_validation_lane[{owner}]={mapped}"
            ),
        )?;
    }
    Ok(())
}
