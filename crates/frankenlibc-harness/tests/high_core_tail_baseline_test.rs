//! Conformance gate for `tests/conformance/high_core_tail_baseline.v1.json`
//! (bd-juvqm.1).
//!
//! Locks the baseline acceptance contract for the future 64+ core
//! tail-and-contention measurement run. This bead does NOT execute
//! the heavy benchmark — it pins the manifest a future bench wave
//! must satisfy: hot-path catalog, thread profiles, statistical
//! policy via tail_stats (bd-juvqm.11), required JSONL fields, and
//! environment fingerprint.

use serde_json::Value;
use std::collections::BTreeSet;
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

fn manifest_path() -> PathBuf {
    workspace_root().join("tests/conformance/high_core_tail_baseline.v1.json")
}

fn rch_plan_path() -> PathBuf {
    workspace_root().join("tests/conformance/rch_validation_lane_plan.v1.json")
}

fn perf_budget_path() -> PathBuf {
    workspace_root().join("tests/conformance/perf_budget_policy.json")
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

#[test]
fn manifest_has_required_top_level_shape() -> TestResult {
    let m = load_json(&manifest_path())?;
    ensure(m["schema_version"] == "v1", "schema_version must be v1")?;
    ensure(m["bead"] == "bd-juvqm.1", "bead must be bd-juvqm.1")?;
    ensure(
        m["manifest_id"] == "high-core-tail-baseline",
        "manifest_id mismatch",
    )?;
    ensure(
        m["source_commit"]
            .as_str()
            .map(|s| s.len() == 40)
            .unwrap_or(false),
        "source_commit must be a 40-char SHA",
    )?;
    let policy = m["policy"]
        .as_object()
        .ok_or_else(|| test_error("policy must be object"))?;
    for k in [
        "no_optimization_in_this_bead",
        "all_cargo_through_rch",
        "writes_deterministic_jsonl",
        "skip_when_overloaded_host_true",
        "fail_closed_when_missing_field",
        "fail_closed_when_thread_profile_unsupported",
        "fail_closed_when_perf_class_drifts_from_support_matrix",
    ] {
        ensure(
            policy.get(k).is_some(),
            format!("policy.{k} must be present"),
        )?;
    }
    ensure(
        policy["no_optimization_in_this_bead"] == Value::Bool(true),
        "policy.no_optimization_in_this_bead must be true",
    )?;
    ensure(
        policy["all_cargo_through_rch"] == Value::Bool(true),
        "policy.all_cargo_through_rch must be true",
    )?;
    Ok(())
}

#[test]
fn rch_validation_lane_resolves_in_lane_plan() -> TestResult {
    let m = load_json(&manifest_path())?;
    let lane = m["rch_validation_lane"].as_str().unwrap_or("");
    ensure(!lane.is_empty(), "rch_validation_lane must be non-empty")?;
    let plan = load_json(&rch_plan_path())?;
    let surface_ids: BTreeSet<String> = plan["surfaces"]
        .as_array()
        .ok_or_else(|| test_error("rch plan surfaces must be array"))?
        .iter()
        .filter_map(|s| s["surface_id"].as_str().map(|s| s.to_string()))
        .collect();
    ensure(
        surface_ids.contains(lane),
        format!(
            "rch_validation_lane {lane} must be a known surface_id in rch_validation_lane_plan.v1.json; available: {:?}",
            surface_ids
        ),
    )?;
    Ok(())
}

#[test]
fn tail_statistics_contract_aligns_with_perf_budget_policy() -> TestResult {
    let m = load_json(&manifest_path())?;
    let manifest_contract = m["tail_statistics_contract"]
        .as_object()
        .ok_or_else(|| test_error("tail_statistics_contract must be object"))?;

    let budget = load_json(&perf_budget_path())?;
    let budget_contract = budget["tail_statistics_contract"]
        .as_object()
        .ok_or_else(|| {
            test_error("perf_budget_policy.json missing tail_statistics_contract (bd-juvqm.11)")
        })?;

    for k in [
        "min_samples_for_p99",
        "min_samples_for_p999",
        "default_bootstrap_iters",
        "default_alpha",
        "overload_cv_threshold",
    ] {
        ensure(
            manifest_contract.get(k) == budget_contract.get(k),
            format!(
                "tail_statistics_contract.{k} drifted from perf_budget_policy: manifest={:?}, budget={:?}",
                manifest_contract.get(k),
                budget_contract.get(k)
            ),
        )?;
    }
    Ok(())
}

#[test]
fn thread_profiles_cover_required_concurrency_levels() -> TestResult {
    let m = load_json(&manifest_path())?;
    let profiles = m["thread_profiles"]
        .as_array()
        .ok_or_else(|| test_error("thread_profiles must be array"))?;
    let counts: BTreeSet<i64> = profiles
        .iter()
        .filter_map(|p| p["thread_count"].as_i64())
        .collect();
    // Bead acceptance: 1 / 8 / 32 / 64+ profiles must all be named.
    for required in [1, 8, 32, 64] {
        ensure(
            counts.contains(&required),
            format!(
                "thread_profiles missing required count {required}; got {:?}",
                counts
            ),
        )?;
    }
    // Each profile must carry a non-trivial rationale.
    for p in profiles {
        let id = p["profile_id"].as_str().unwrap_or("?");
        ensure(
            p["rationale"]
                .as_str()
                .map(|s| s.len() > 30)
                .unwrap_or(false),
            format!("thread_profile {id} rationale must be non-trivial"),
        )?;
    }
    Ok(())
}

#[test]
fn hot_path_catalog_covers_required_subsystems() -> TestResult {
    let m = load_json(&manifest_path())?;
    let catalog = m["hot_path_catalog"]
        .as_array()
        .ok_or_else(|| test_error("hot_path_catalog must be array"))?;
    let subsystems: BTreeSet<String> = catalog
        .iter()
        .filter_map(|e| e["owner_subsystem"].as_str().map(|s| s.to_string()))
        .collect();
    // Bead acceptance: allocator, pointer_validation, string/memory,
    // stdio, pthread.
    for required in [
        "allocator",
        "pointer_validation",
        "string_memory",
        "stdio",
        "pthread",
    ] {
        ensure(
            subsystems.contains(required),
            format!(
                "hot_path_catalog missing required owner_subsystem {required}; got {:?}",
                subsystems
            ),
        )?;
    }
    // Each catalog entry must carry a perf_class and an evidence_anchor.
    for entry in catalog {
        let path = entry["symbol_path"].as_str().unwrap_or("?");
        ensure(
            entry["perf_class"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            format!("hot_path_catalog {path} missing perf_class"),
        )?;
        ensure(
            entry["evidence_anchor"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            format!("hot_path_catalog {path} missing evidence_anchor"),
        )?;
    }
    Ok(())
}

#[test]
fn cost_decomposition_rows_are_complete() -> TestResult {
    let m = load_json(&manifest_path())?;
    let rows = m["cost_decomposition_rows"]
        .as_array()
        .ok_or_else(|| test_error("cost_decomposition_rows must be array"))?;
    let row_ids: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r["row_id"].as_str().map(|s| s.to_string()))
        .collect();
    // Bead acceptance: distinguish service_time, queueing/sync,
    // allocator/membrane, evidence emission.
    for required in [
        "service_time",
        "queueing_synchronization",
        "allocator_membrane_overhead",
        "evidence_emission",
    ] {
        ensure(
            row_ids.contains(required),
            format!(
                "cost_decomposition_rows missing required row_id {required}; got {:?}",
                row_ids
            ),
        )?;
    }
    for r in rows {
        let id = r["row_id"].as_str().unwrap_or("?");
        ensure(
            r["definition"]
                .as_str()
                .map(|s| s.len() > 30)
                .unwrap_or(false),
            format!("cost_decomposition_rows {id} definition must be non-trivial"),
        )?;
    }
    Ok(())
}

#[test]
fn required_jsonl_fields_include_tail_stats_contract_fields() -> TestResult {
    let m = load_json(&manifest_path())?;
    let fields: BTreeSet<String> = m["required_jsonl_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_jsonl_fields must be array"))?
        .iter()
        .filter_map(|f| f.as_str().map(|s| s.to_string()))
        .collect();

    // Anchor against the perf_budget_policy tail_statistics_contract:
    // every required_tail_stats_field must appear here.
    let budget = load_json(&perf_budget_path())?;
    let tail_required: Vec<String> = budget["tail_statistics_contract"]
        ["required_tail_stats_fields"]
        .as_array()
        .ok_or_else(|| {
            test_error("perf_budget_policy tail_statistics_contract.required_tail_stats_fields missing")
        })?
        .iter()
        .filter_map(|f| f.as_str().map(|s| s.to_string()))
        .collect();
    for f in &tail_required {
        ensure(
            fields.contains(f),
            format!("required_jsonl_fields missing tail_stats field {f}"),
        )?;
    }

    // Plus the bead-specific cost decomposition + evidence/contention.
    for f in [
        "service_time_ns",
        "queueing_synchronization_ns",
        "allocator_membrane_overhead_ns",
        "evidence_emission_ns",
        "evidence_loss_count",
        "contention_hint",
        "pressure_state",
        "thread_profile",
        "runtime_mode",
        "source_commit",
        "target_dir",
    ] {
        ensure(
            fields.contains(f),
            format!("required_jsonl_fields missing {f}"),
        )?;
    }
    Ok(())
}

#[test]
fn fail_closed_set_includes_critical_evidence_fields() -> TestResult {
    let m = load_json(&manifest_path())?;
    let fail_closed: BTreeSet<String> = m["policy"]["fail_closed_when_missing_field"]
        .as_array()
        .ok_or_else(|| test_error("policy.fail_closed_when_missing_field must be array"))?
        .iter()
        .filter_map(|f| f.as_str().map(|s| s.to_string()))
        .collect();
    for required in [
        "n",
        "p99",
        "p99_ci_low",
        "p99_ci_high",
        "sufficient_for_p99",
        "seed",
        "evidence_loss_count",
        "source_commit",
    ] {
        ensure(
            fail_closed.contains(required),
            format!("policy.fail_closed_when_missing_field missing {required}"),
        )?;
    }
    Ok(())
}

#[test]
fn baseline_command_template_routes_through_rch_with_target_dir() -> TestResult {
    let m = load_json(&manifest_path())?;
    let cmd = m["baseline_command_template"].as_str().unwrap_or("");
    ensure(
        cmd.contains("rch cargo "),
        format!("baseline_command_template must contain `rch cargo `: {cmd}"),
    )?;
    ensure(
        cmd.contains("CARGO_TARGET_DIR="),
        format!("baseline_command_template must contain CARGO_TARGET_DIR=: {cmd}"),
    )?;
    ensure(
        cmd.contains("<agent>"),
        format!("baseline_command_template must include <agent> placeholder: {cmd}"),
    )?;
    ensure(
        cmd.contains(" -p "),
        format!("baseline_command_template must include focused -p flag: {cmd}"),
    )?;
    Ok(())
}

#[test]
fn environment_fingerprint_required_fields_are_complete() -> TestResult {
    let m = load_json(&manifest_path())?;
    let env: BTreeSet<String> = m["environment_fingerprint_required_fields"]
        .as_array()
        .ok_or_else(|| test_error("environment_fingerprint_required_fields must be array"))?
        .iter()
        .filter_map(|f| f.as_str().map(|s| s.to_string()))
        .collect();
    for required in [
        "kernel",
        "cpu_model",
        "cpu_count",
        "load_average_1m",
        "rust_toolchain",
        "rch_worker_id",
    ] {
        ensure(
            env.contains(required),
            format!("environment_fingerprint missing {required}"),
        )?;
    }
    Ok(())
}

#[test]
fn downstream_consumers_each_name_a_real_bead() -> TestResult {
    let m = load_json(&manifest_path())?;
    let consumers = m["downstream_consumers"]
        .as_array()
        .ok_or_else(|| test_error("downstream_consumers must be array"))?;
    ensure(
        consumers.len() >= 3,
        format!(
            "downstream_consumers should name >=3 beads; got {}",
            consumers.len()
        ),
    )?;
    for c in consumers {
        let bead = c["bead"].as_str().unwrap_or("");
        ensure(
            bead.starts_with("bd-juvqm."),
            format!("downstream consumer bead must reference the bd-juvqm.* family: {bead}"),
        )?;
        ensure(
            c["consumes"]
                .as_str()
                .map(|s| s.len() > 40)
                .unwrap_or(false),
            format!("downstream consumer {bead} consumes description must be non-trivial"),
        )?;
    }
    Ok(())
}
