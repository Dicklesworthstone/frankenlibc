//! Conformance gate for `tests/conformance/strict_hardened_timing_side_channel_budget.v1.json`
//! (bd-juvqm.12).
//!
//! Locks the timing side-channel budget contract for representative
//! pointer / allocator / string / stdio / pthread paths across strict
//! and hardened modes. The gate validates the manifest itself plus
//! exercises the rejection logic against synthetic positive and
//! negative report fixtures, so the contract is testable today
//! without a live timing-measurement run.

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
    workspace_root().join("tests/conformance/strict_hardened_timing_side_channel_budget.v1.json")
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn manifest() -> Result<Value, Box<dyn Error>> {
    load_json(&manifest_path())
}

#[test]
fn manifest_has_required_top_level_shape() -> TestResult {
    let m = manifest()?;
    ensure(m["schema_version"] == "v1", "schema_version must be v1")?;
    ensure(m["bead"] == "bd-juvqm.12", "bead must be bd-juvqm.12")?;
    ensure(
        m["manifest_id"] == "strict-hardened-timing-side-channel-budget",
        "manifest_id mismatch",
    )?;
    ensure(
        m["source_commit"]
            .as_str()
            .map(|s| s.len() == 40)
            .unwrap_or(false),
        "source_commit must be 40-char SHA",
    )?;
    let policy = m["policy"]
        .as_object()
        .ok_or_else(|| test_error("policy must be object"))?;
    for k in [
        "default_decision",
        "fail_closed_when_missing_mode_pair",
        "fail_closed_when_artifact_refs_missing",
        "fail_closed_when_p99_delta_exceeds_budget",
        "fail_closed_when_p99_delta_amplifies_with_input_class",
        "fail_closed_when_source_commit_stale",
        "amplification_threshold_ratio",
        "rejected_evidence_kinds",
    ] {
        ensure(
            policy.get(k).is_some(),
            format!("policy.{k} must be present"),
        )?;
    }
    let amp = policy["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(0.0);
    ensure(
        (1.5..=10.0).contains(&amp),
        format!("amplification_threshold_ratio must be in [1.5, 10.0]; got {amp}"),
    )?;
    Ok(())
}

#[test]
fn paths_cover_required_subsystems_with_budgets() -> TestResult {
    let m = manifest()?;
    let paths = m["paths"]
        .as_array()
        .ok_or_else(|| test_error("paths must be array"))?;
    let owners: BTreeSet<String> = paths
        .iter()
        .filter_map(|p| p["owner_subsystem"].as_str().map(|s| s.to_string()))
        .collect();
    for required in ["membrane", "allocator", "string", "stdio", "pthread"] {
        ensure(
            owners.contains(required),
            format!("paths missing owner_subsystem {required}"),
        )?;
    }
    for p in paths {
        let id = p["path_id"].as_str().unwrap_or("?");
        let budget = p["allowed_p99_delta_budget_ns"].as_i64().unwrap_or(-1);
        ensure(
            budget >= 0,
            format!("path {id} allowed_p99_delta_budget_ns must be >=0"),
        )?;
        ensure(
            p["intentional_divergence"].is_boolean(),
            format!("path {id} intentional_divergence must be boolean"),
        )?;
        ensure(
            p["intentional_divergence_rationale"]
                .as_str()
                .map(|s| s.len() > 30)
                .unwrap_or(false),
            format!("path {id} intentional_divergence_rationale must be non-trivial"),
        )?;
    }
    Ok(())
}

#[test]
fn input_classes_include_typical_boundary_adversarial() -> TestResult {
    let m = manifest()?;
    let classes: BTreeSet<String> = m["input_classes"]
        .as_array()
        .ok_or_else(|| test_error("input_classes must be array"))?
        .iter()
        .filter_map(|c| c["input_class_id"].as_str().map(|s| s.to_string()))
        .collect();
    for required in ["typical", "boundary", "adversarial"] {
        ensure(
            classes.contains(required),
            format!("input_classes missing {required}"),
        )?;
    }
    Ok(())
}

#[test]
fn rejected_evidence_kinds_include_required_set() -> TestResult {
    let m = manifest()?;
    let kinds: BTreeSet<String> = m["policy"]["rejected_evidence_kinds"]
        .as_array()
        .ok_or_else(|| test_error("rejected_evidence_kinds must be array"))?
        .iter()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect();
    for required in [
        "missing_mode_pair",
        "missing_artifact_refs",
        "over_budget_p99_delta",
        "amplification_above_threshold",
        "stale_source_commit",
        "missing_required_field",
    ] {
        ensure(
            kinds.contains(required),
            format!("rejected_evidence_kinds missing {required}"),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Synthetic fixtures: rejection logic exercised without a live run.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Row {
    path_id: String,
    input_class: String,
    strict_p99_ns: f64,
    hardened_p99_ns: f64,
    allowed_budget_ns: i64,
    amplification_ratio: f64,
    artifact_refs: Vec<String>,
    source_commit: String,
}

fn judge_rows(
    rows: &[Row],
    manifest_source_commit: &str,
    required_paths: &BTreeSet<String>,
    amp_threshold: f64,
) -> Result<(), String> {
    // missing_mode_pair: every (path_id, input_class) row must
    // carry both strict and hardened p99 (encoded as two finite
    // numbers per row in this synthetic schema).
    if rows.is_empty() {
        return Err("EMPTY::EMPTY::missing_required_field".to_string());
    }
    let seen_paths: BTreeSet<String> = rows.iter().map(|r| r.path_id.clone()).collect();
    for required in required_paths {
        if !seen_paths.contains(required) {
            return Err(format!("{required}::ALL::missing_mode_pair"));
        }
    }
    for r in rows {
        if r.source_commit != manifest_source_commit {
            return Err(format!(
                "{}::{}::stale_source_commit",
                r.path_id, r.input_class
            ));
        }
        if r.artifact_refs.is_empty() {
            return Err(format!(
                "{}::{}::missing_artifact_refs",
                r.path_id, r.input_class
            ));
        }
        if !r.strict_p99_ns.is_finite() || !r.hardened_p99_ns.is_finite() {
            return Err(format!(
                "{}::{}::missing_required_field",
                r.path_id, r.input_class
            ));
        }
        let delta = r.hardened_p99_ns - r.strict_p99_ns;
        if delta > r.allowed_budget_ns as f64 {
            return Err(format!(
                "{}::{}::over_budget_p99_delta",
                r.path_id, r.input_class
            ));
        }
        if r.amplification_ratio > amp_threshold {
            return Err(format!(
                "{}::{}::amplification_above_threshold",
                r.path_id, r.input_class
            ));
        }
    }
    Ok(())
}

fn required_paths_set(m: &Value) -> BTreeSet<String> {
    m["paths"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p["path_id"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn well_formed_rows(commit: &str) -> Vec<Row> {
    vec![
        Row {
            path_id: "pointer.validate_region".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 18.0,
            hardened_p99_ns: 200.0,
            allowed_budget_ns: 200,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "allocator.malloc_fastpath".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 30.0,
            hardened_p99_ns: 170.0,
            allowed_budget_ns: 150,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "string.memcmp".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 12.0,
            hardened_p99_ns: 55.0,
            allowed_budget_ns: 50,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "stdio.fread_small".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 100.0,
            hardened_p99_ns: 350.0,
            allowed_budget_ns: 250,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "pthread.mutex_lock_uncontended".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 25.0,
            hardened_p99_ns: 125.0,
            allowed_budget_ns: 100,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
    ]
}

#[test]
fn positive_fixture_well_formed_rows_pass() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let rows = well_formed_rows(&commit);
    judge_rows(&rows, &commit, &paths, amp).map_err(test_error)?;
    Ok(())
}

#[test]
fn negative_fixture_missing_mode_pair_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    // Drop one path entirely.
    let mut rows = well_formed_rows(&commit);
    rows.retain(|r| r.path_id != "string.memcmp");
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "missing path row should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_mode_pair"),
        format!("rejection should be missing_mode_pair; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_missing_artifact_refs_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    rows[0].artifact_refs.clear();
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "empty artifact_refs should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_artifact_refs"),
        format!("rejection should be missing_artifact_refs; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_over_budget_delta_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    // Push pointer.validate_region delta over budget (200ns cap).
    rows[0].hardened_p99_ns = 500.0; // strict was 18.0, delta = 482 > 200
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "over-budget delta should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::over_budget_p99_delta"),
        format!("rejection should be over_budget_p99_delta; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_amplification_above_threshold_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    // Boost amplification on the first row past threshold (3.0).
    rows[0].amplification_ratio = 5.0;
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(
        err.is_err(),
        "amplification above threshold should be rejected",
    )?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::amplification_above_threshold"),
        format!("rejection should be amplification_above_threshold; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_stale_source_commit_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    rows[0].source_commit = "0000000000000000000000000000000000000000".to_string();
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "stale source_commit should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::stale_source_commit"),
        format!("rejection should be stale_source_commit; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_non_finite_quantile_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    rows[0].strict_p99_ns = f64::NAN;
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "NaN strict_p99 should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_required_field"),
        format!("rejection should be missing_required_field; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn anchored_baseline_manifest_exists_on_disk() -> TestResult {
    let m = manifest()?;
    let path = m["anchored_baseline_manifest"].as_str().unwrap_or("");
    ensure(!path.is_empty(), "anchored_baseline_manifest must be set")?;
    let abs = workspace_root().join(path);
    ensure(
        abs.exists(),
        format!("anchored_baseline_manifest {path} does not exist on disk"),
    )?;
    Ok(())
}
