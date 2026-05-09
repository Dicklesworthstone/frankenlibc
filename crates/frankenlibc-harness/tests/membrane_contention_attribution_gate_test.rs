//! Conformance gate for `tests/conformance/membrane_contention_attribution_gate.v1.json`
//! (bd-juvqm.2).
//!
//! Validates the *contract* a future contention-attribution report
//! must satisfy. Two layers of evidence:
//!
//!   1. Static checks on the checked-in manifest — schema, required
//!      pipeline stages, alignment with the high-core baseline
//!      manifest (bd-juvqm.1) and the perf_budget_policy
//!      tail_statistics_contract (bd-juvqm.11).
//!
//!   2. Synthetic positive + negative fixtures embedded in this test
//!      that exercise the rejection logic without a live benchmark
//!      run: a well-formed report passes; reports with missing
//!      stage rows, stale source_commit, non-monotone quantiles, or
//!      non-finite numbers all fail closed.
//!
//! Failure signatures follow the
//! `<stage_id>::<thread_profile>::<runtime_mode>::<rejected_evidence_kind>`
//! format so future optimization beads see exactly which surface
//! and which evidence kind tripped the gate.

use serde_json::{Value, json};
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
    workspace_root().join("tests/conformance/membrane_contention_attribution_gate.v1.json")
}

fn baseline_path() -> PathBuf {
    workspace_root().join("tests/conformance/high_core_tail_baseline.v1.json")
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

fn manifest() -> Result<Value, Box<dyn Error>> {
    load_json(&manifest_path())
}

#[test]
fn manifest_has_required_top_level_shape() -> TestResult {
    let m = manifest()?;
    ensure(m["schema_version"] == "v1", "schema_version must be v1")?;
    ensure(m["bead"] == "bd-juvqm.2", "bead must be bd-juvqm.2")?;
    ensure(
        m["manifest_id"] == "membrane-contention-attribution-gate",
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
        "fail_closed_when_missing_stage_row",
        "fail_closed_when_quantile_ordering_violated",
        "fail_closed_when_source_commit_stale",
        "fail_closed_when_required_attribution_field_missing",
        "fail_closed_when_sufficient_for_p99_false",
        "rejected_evidence_kinds",
    ] {
        ensure(
            policy.get(k).is_some(),
            format!("policy.{k} must be present"),
        )?;
    }
    let kinds: BTreeSet<String> = policy["rejected_evidence_kinds"]
        .as_array()
        .ok_or_else(|| test_error("rejected_evidence_kinds must be array"))?
        .iter()
        .filter_map(|s| s.as_str().map(|s| s.to_string()))
        .collect();
    for required in [
        "missing_stage_row",
        "missing_attribution_field",
        "non_monotone_quantile",
        "stale_source_commit",
        "insufficient_samples_for_p99",
    ] {
        ensure(
            kinds.contains(required),
            format!("rejected_evidence_kinds missing {required}"),
        )?;
    }
    Ok(())
}

#[test]
fn pipeline_covers_required_owner_subsystems() -> TestResult {
    let m = manifest()?;
    let stages = m["validation_pipeline_stages"]
        .as_array()
        .ok_or_else(|| test_error("validation_pipeline_stages must be array"))?;
    let stage_ids: BTreeSet<String> = stages
        .iter()
        .filter_map(|s| s["stage_id"].as_str().map(|s| s.to_string()))
        .collect();
    let owners: BTreeSet<String> = stages
        .iter()
        .filter_map(|s| s["owner_subsystem"].as_str().map(|s| s.to_string()))
        .collect();
    // The bead names: TLS cache, bloom, arena, fingerprint, canary,
    // bounds (membrane); shard + magazine (allocator); evidence
    // emission (runtime_math); pthread sync; stdio sync.
    for required in [
        "tls_cache",
        "bloom",
        "arena",
        "fingerprint",
        "canary",
        "bounds",
        "allocator_shard",
        "allocator_magazine",
        "evidence_emission",
        "pthread_sync",
        "stdio_sync",
    ] {
        ensure(
            stage_ids.contains(required),
            format!("validation_pipeline_stages missing {required}"),
        )?;
    }
    for required in ["membrane", "allocator", "runtime_math", "pthread", "stdio"] {
        ensure(
            owners.contains(required),
            format!("owner_subsystems missing {required}"),
        )?;
    }
    // Each stage must have a non-trivial rationale and an expected_signal.
    for s in stages {
        let id = s["stage_id"].as_str().unwrap_or("?");
        ensure(
            s["rationale"]
                .as_str()
                .map(|r| r.len() > 30)
                .unwrap_or(false),
            format!("stage {id} rationale must be non-trivial"),
        )?;
        ensure(
            s["expected_signal"]
                .as_str()
                .map(|r| !r.is_empty())
                .unwrap_or(false),
            format!("stage {id} expected_signal must be non-empty"),
        )?;
    }
    Ok(())
}

#[test]
fn required_attribution_fields_align_with_baseline_jsonl_fields() -> TestResult {
    let m = manifest()?;
    let attribution: BTreeSet<String> = m["required_attribution_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_attribution_fields must be array"))?
        .iter()
        .filter_map(|s| s.as_str().map(|s| s.to_string()))
        .collect();

    // Tail-stats core fields must come from perf_budget_policy
    // tail_statistics_contract (bd-juvqm.11).
    let budget = load_json(&perf_budget_path())?;
    let tail_required: Vec<String> = budget["tail_statistics_contract"]
        ["required_tail_stats_fields"]
        .as_array()
        .ok_or_else(|| {
            test_error("perf_budget_policy missing tail_statistics_contract.required_tail_stats_fields")
        })?
        .iter()
        .filter_map(|f| f.as_str().map(|s| s.to_string()))
        .collect();
    for f in [
        "n",
        "p50",
        "p95",
        "p99",
        "p999",
        "p99_ci_low",
        "p99_ci_high",
        "sufficient_for_p99",
        "seed",
        "bootstrap_iters",
    ] {
        ensure(
            tail_required.iter().any(|x| x == f),
            format!("perf_budget_policy tail_statistics_contract missing {f} (regenerate budget?)"),
        )?;
        ensure(
            attribution.contains(f),
            format!("required_attribution_fields missing tail_stats field {f}"),
        )?;
    }
    // Bead-specific attribution fields.
    for f in [
        "stage_id",
        "owner_subsystem",
        "expected_signal",
        "thread_profile",
        "runtime_mode",
        "contention_hint",
        "pressure_state",
        "evidence_loss_count",
        "failure_signature",
    ] {
        ensure(
            attribution.contains(f),
            format!("required_attribution_fields missing {f}"),
        )?;
    }
    // Baseline manifest's required_jsonl_fields should be a SUPERSET
    // (the baseline run is what feeds the attribution gate).
    let baseline = load_json(&baseline_path())?;
    let baseline_fields: BTreeSet<String> = baseline["required_jsonl_fields"]
        .as_array()
        .ok_or_else(|| test_error("baseline required_jsonl_fields missing"))?
        .iter()
        .filter_map(|s| s.as_str().map(|s| s.to_string()))
        .collect();
    for must in [
        "n",
        "p99",
        "p99_ci_low",
        "p99_ci_high",
        "sufficient_for_p99",
        "evidence_loss_count",
    ] {
        ensure(
            baseline_fields.contains(must),
            format!(
                "high_core_tail_baseline.v1.json required_jsonl_fields missing {must} — re-anchor bd-juvqm.1 manifest"
            ),
        )?;
    }
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

#[test]
fn failure_signature_format_is_pinned() -> TestResult {
    let m = manifest()?;
    let fmt = m["failure_signature_format"].as_str().unwrap_or("");
    ensure(
        fmt == "<stage_id>::<thread_profile>::<runtime_mode>::<rejected_evidence_kind>",
        format!("failure_signature_format drifted: {fmt}"),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------
// Synthetic fixtures: validate the gate's rejection logic without a
// live benchmark run. The "report" here is just a JSON Value that
// future tooling will assemble; the rejection check is the same set
// of invariants (so the gate's contract is testable today).
// ---------------------------------------------------------------------

/// Walk a synthetic report row and decide accept/reject + return the
/// failure_signature string when rejected. Used by the negative-fixture
/// tests below to prove the rejection logic is well-defined.
fn judge_row(
    row: &Value,
    manifest_source_commit: &str,
    required_stages: &BTreeSet<String>,
) -> Result<(), String> {
    // missing_attribution_field
    for f in [
        "stage_id",
        "thread_profile",
        "runtime_mode",
        "n",
        "p50",
        "p95",
        "p99",
        "p999",
        "p99_ci_low",
        "p99_ci_high",
        "sufficient_for_p99",
        "seed",
        "evidence_loss_count",
        "source_commit",
    ] {
        if row.get(f).is_none() {
            let sig = format!(
                "{}::{}::{}::missing_attribution_field",
                row["stage_id"].as_str().unwrap_or("UNKNOWN"),
                row["thread_profile"].as_str().unwrap_or("UNKNOWN"),
                row["runtime_mode"].as_str().unwrap_or("UNKNOWN"),
            );
            return Err(sig);
        }
    }
    let stage_id = row["stage_id"].as_str().unwrap_or("UNKNOWN").to_string();
    let thr = row["thread_profile"]
        .as_str()
        .unwrap_or("UNKNOWN")
        .to_string();
    let mode = row["runtime_mode"]
        .as_str()
        .unwrap_or("UNKNOWN")
        .to_string();
    let mksig = |kind: &str| format!("{stage_id}::{thr}::{mode}::{kind}");

    // missing_stage_row check is at the report level, but this
    // single-row judge ensures stage_id is in the canonical set —
    // a row referencing an unknown stage trips the same rejection.
    if !required_stages.contains(&stage_id) {
        return Err(mksig("missing_stage_row"));
    }

    // stale_source_commit
    let row_commit = row["source_commit"].as_str().unwrap_or("");
    if row_commit != manifest_source_commit {
        return Err(mksig("stale_source_commit"));
    }

    // sufficient_for_p99 must be true
    if row["sufficient_for_p99"] != Value::Bool(true) {
        return Err(mksig("insufficient_samples_for_p99"));
    }

    // non_monotone_quantile: p50 <= p95 <= p99 <= p999, ci brackets
    let p50 = row["p50"].as_f64().unwrap_or(f64::NAN);
    let p95 = row["p95"].as_f64().unwrap_or(f64::NAN);
    let p99 = row["p99"].as_f64().unwrap_or(f64::NAN);
    let p999 = row["p999"].as_f64().unwrap_or(f64::NAN);
    let lo = row["p99_ci_low"].as_f64().unwrap_or(f64::NAN);
    let hi = row["p99_ci_high"].as_f64().unwrap_or(f64::NAN);
    if !(p50.is_finite()
        && p95.is_finite()
        && p99.is_finite()
        && p999.is_finite()
        && lo.is_finite()
        && hi.is_finite())
    {
        return Err(mksig("negative_or_non_finite_quantile"));
    }
    if p50 < 0.0 || p95 < 0.0 || p99 < 0.0 || p999 < 0.0 {
        return Err(mksig("negative_or_non_finite_quantile"));
    }
    if !(p50 <= p95 && p95 <= p99 && p99 <= p999 && lo <= p99 && p99 <= hi) {
        return Err(mksig("non_monotone_quantile"));
    }
    Ok(())
}

fn well_formed_row(stage: &str, source_commit: &str) -> Value {
    json!({
        "stage_id": stage,
        "owner_subsystem": "membrane",
        "expected_signal": "bounds_check_ns",
        "thread_profile": "multi_64",
        "runtime_mode": "strict",
        "n": 5000,
        "p50": 12.0,
        "p95": 18.0,
        "p99": 22.0,
        "p999": 35.0,
        "p99_ci_low": 21.5,
        "p99_ci_high": 22.7,
        "sufficient_for_p99": true,
        "sufficient_for_p999": true,
        "seed": 42,
        "bootstrap_iters": 1000,
        "contention_hint": 0.12,
        "pressure_state": "low",
        "evidence_loss_count": 0,
        "source_commit": source_commit,
        "target_dir": "/data/projects/.cargo-target-frankenlibc-ubuntu_cc_1-juvqm2",
        "artifact_refs": ["target/conformance/high_core_tail_baseline.rows.jsonl"],
        "failure_signature": ""
    })
}

fn required_stage_set(m: &Value) -> BTreeSet<String> {
    m["validation_pipeline_stages"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["stage_id"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn positive_fixture_well_formed_row_is_accepted() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let stages = required_stage_set(&m);
    let row = well_formed_row("bounds", &commit);
    judge_row(&row, &commit, &stages).map_err(test_error)?;
    Ok(())
}

#[test]
fn negative_fixture_unknown_stage_is_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let stages = required_stage_set(&m);
    let row = well_formed_row("nonexistent_stage", &commit);
    let err = judge_row(&row, &commit, &stages);
    ensure(
        err.is_err(),
        "unknown stage_id should be rejected by the gate",
    )?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_stage_row"),
        format!("rejection signature should contain ::missing_stage_row; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_stale_source_commit_is_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let stages = required_stage_set(&m);
    let row = well_formed_row("bounds", "0000000000000000000000000000000000000000");
    let err = judge_row(&row, &commit, &stages);
    ensure(
        err.is_err(),
        "stale source_commit should be rejected by the gate",
    )?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::stale_source_commit"),
        format!("rejection signature should contain ::stale_source_commit; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_insufficient_samples_is_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let stages = required_stage_set(&m);
    let mut row = well_formed_row("arena", &commit);
    row["sufficient_for_p99"] = json!(false);
    let err = judge_row(&row, &commit, &stages);
    ensure(err.is_err(), "insufficient samples should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::insufficient_samples_for_p99"),
        format!("rejection signature should contain ::insufficient_samples_for_p99; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_non_monotone_quantile_is_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let stages = required_stage_set(&m);
    // p99 < p95: impossible ordering
    let mut row = well_formed_row("arena", &commit);
    row["p99"] = json!(10.0); // below p95=18.0
    let err = judge_row(&row, &commit, &stages);
    ensure(err.is_err(), "non-monotone quantile should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::non_monotone_quantile"),
        format!("rejection signature should contain ::non_monotone_quantile; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_non_finite_quantile_is_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let stages = required_stage_set(&m);
    let mut row = well_formed_row("arena", &commit);
    // serde_json cannot serialize NaN — use a negative number to
    // trip the "negative_or_non_finite_quantile" branch instead.
    row["p99"] = json!(-1.0);
    let err = judge_row(&row, &commit, &stages);
    ensure(
        err.is_err(),
        "negative quantile should be rejected (proxy for non-finite)",
    )?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::negative_or_non_finite_quantile"),
        format!("rejection signature should contain ::negative_or_non_finite_quantile; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_missing_required_field_is_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let stages = required_stage_set(&m);
    let mut row = well_formed_row("arena", &commit);
    let row_obj = row.as_object_mut().unwrap();
    row_obj.remove("p99_ci_low");
    let err = judge_row(&row, &commit, &stages);
    ensure(
        err.is_err(),
        "missing p99_ci_low should be rejected by the gate",
    )?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_attribution_field"),
        format!("rejection signature should contain ::missing_attribution_field; got: {sig}"),
    )?;
    Ok(())
}
