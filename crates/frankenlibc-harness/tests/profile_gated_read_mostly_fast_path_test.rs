//! Conformance gate for the profile-gated read-mostly fast-path
//! prototype (bd-juvqm.3).
//!
//! Validates the manifest schema + exercises the prototype's
//! isomorphism witness + measurement validator. The bead's live
//! before/after p99/p999/throughput run is environment-blocked at
//! this commit; this gate pins the contract that any future live
//! row MUST satisfy.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use frankenlibc_harness::read_mostly_fast_path_prototype::{
    LaneId, LiveMeasurementError, LiveMeasurementPair, LiveMeasurementRow, LivePairError,
    ProfileGatedReadMostly, isomorphism_witness, run_live_measurement, run_live_measurement_pair,
    validate_live_measurement, validate_live_measurement_pair,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("profile_gated_read_mostly_fast_path.v1.json")
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = manifest_path(&root);
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value.get(field).ok_or_else(|| format!("missing `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("`{field}` must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("`{field}` must be a string"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    json_field(value, field)?
        .as_bool()
        .ok_or_else(|| format!("`{field}` must be a bool"))
}

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    json_field(value, field)?
        .as_u64()
        .ok_or_else(|| format!("`{field}` must be a u64"))
}

#[test]
fn manifest_anchors_to_juvqm3_with_tls_cache_hotspot() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "profile-gated-read-mostly-fast-path",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-juvqm.3", "bead")?;
    let hotspot = json_field(&m, "selected_hotspot")?;
    require(
        json_string(hotspot, "stage_id")? == "tls_cache",
        "stage_id must be tls_cache (read-mostly per bd-juvqm.2)",
    )?;
    require(
        json_string(hotspot, "owner_subsystem")? == "membrane",
        "owner_subsystem must be membrane",
    )?;
    require(
        json_string(hotspot, "expected_signal")? == "tls_cache_miss_rate",
        "expected_signal anchored to bd-juvqm.2 attribution",
    )
}

#[test]
fn isomorphism_proof_covers_all_required_dimensions() -> TestResult {
    let m = load_manifest()?;
    let proof = json_field(&m, "isomorphism_proof")?;
    for f in [
        "ordering",
        "visibility",
        "safety_state_monotonicity",
        "errno_abi_behavior",
        "strict_hardened_divergence",
    ] {
        require(
            json_string(proof, f).is_ok(),
            format!("isomorphism_proof must include {f}"),
        )?;
    }
    Ok(())
}

#[test]
fn deterministic_fallback_contract_names_conservative_lane() -> TestResult {
    let m = load_manifest()?;
    let fb = json_field(&m, "deterministic_fallback_contract")?;
    require(
        json_string(fb, "fallback_lane")? == "Conservative",
        "fallback lane must be Conservative",
    )?;
    let inv = json_string(fb, "single_lever_invariant")?;
    require(
        inv.contains("ONLY") || inv.contains("only"),
        "single_lever_invariant must spell out the one-lever guarantee",
    )
}

#[test]
fn live_measurement_schema_pins_required_fields() -> TestResult {
    let m = load_manifest()?;
    let schema = json_field(&m, "live_measurement_schema")?;
    let required: BTreeSet<&str> = json_array(schema, "required_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "lane_id",
        "profile_id",
        "source_commit",
        "environment_fingerprint",
        "p99_ns",
        "p999_ns",
        "throughput_ops_per_sec",
        "n",
        "seed",
    ]
    .into_iter()
    .collect();
    require(
        required == expected,
        format!("required_fields: {required:?}"),
    )?;
    require(
        json_u64(schema, "minimum_samples_for_p999")? == 1000,
        "minimum_samples_for_p999",
    )?;
    require(
        json_bool(schema, "monotone_quantiles_required")?,
        "monotone_quantiles_required",
    )
}

#[test]
fn policy_fails_closed_on_required_kinds() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "policy")?;
    for f in [
        "fail_closed_when_lanes_disagree",
        "fail_closed_when_single_lever_invariant_violated",
        "fail_closed_when_live_measurement_missing_required_field",
        "fail_closed_when_source_commit_invalid",
        "fail_closed_when_environment_fingerprint_missing",
        "fail_closed_when_n_below_minimum_for_p999",
        "fail_closed_when_quantiles_non_monotone",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    let rejected: BTreeSet<&str> = json_array(policy, "rejected_evidence_kinds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for k in [
        "lanes_disagree_on_isomorphism_witness",
        "single_lever_invariant_violated",
        "missing_required_measurement_field",
        "invalid_source_commit",
        "missing_environment_fingerprint",
        "insufficient_samples_for_p999",
        "non_monotone_quantiles",
    ] {
        require(
            rejected.contains(k),
            format!("rejected_evidence_kinds must include {k}"),
        )?;
    }
    Ok(())
}

#[test]
fn live_isomorphism_witness_proves_lanes_agree_on_workload() -> TestResult {
    let writes: Vec<u32> = (1..=64).collect();
    let report = isomorphism_witness(0, &writes, 4);
    require(
        report.outcomes_identical,
        format!(
            "lanes must agree; conservative={:?}, seqlock={:?}",
            report.conservative_outcomes, report.seqlock_outcomes
        ),
    )?;
    require(
        report.conservative_outcomes.len() == 64 * 4,
        "isomorphism witness must produce N*reads_per_phase outcomes",
    )
}

#[test]
fn live_single_lever_flip_does_not_change_observable_outcome() -> TestResult {
    let mut p = ProfileGatedReadMostly::new(0, LaneId::Conservative);
    for v in [10, 20, 30, 40, 50] {
        p.write(v);
        let cons = p.read();
        p.set_profile_lane(LaneId::Seqlock);
        let seq = p.read();
        require(
            cons == seq && cons == v,
            format!("flip changed outcome at v={v}: cons={cons}, seq={seq}"),
        )?;
        p.set_profile_lane(LaneId::Conservative);
    }
    Ok(())
}

#[test]
fn live_validator_accepts_well_formed_measurement_row() -> TestResult {
    let row = LiveMeasurementRow {
        lane_id: "seqlock".into(),
        profile_id: "high-core-tail".into(),
        source_commit: "1".repeat(40),
        environment_fingerprint: "linux-x86_64-64core-2026-05".into(),
        p99_ns: 200,
        p999_ns: 400,
        throughput_ops_per_sec: 1_000_000,
        n: 1_000_000,
        seed: 0xc0ffee,
    };
    validate_live_measurement(&row).map_err(|e| format!("clean row must validate; got {e:?}"))
}

#[test]
fn live_validator_rejects_invalid_source_commit() -> TestResult {
    let row = LiveMeasurementRow {
        lane_id: "seqlock".into(),
        profile_id: "p".into(),
        source_commit: "stale".into(),
        environment_fingerprint: "x".into(),
        p99_ns: 1,
        p999_ns: 2,
        throughput_ops_per_sec: 1,
        n: 5_000,
        seed: 0,
    };
    match validate_live_measurement(&row) {
        Err(LiveMeasurementError::InvalidSourceCommit) => Ok(()),
        other => Err(format!("expected InvalidSourceCommit; got {other:?}")),
    }
}

#[test]
fn live_validator_rejects_n_below_minimum_for_p999() -> TestResult {
    let row = LiveMeasurementRow {
        lane_id: "seqlock".into(),
        profile_id: "p".into(),
        source_commit: "1".repeat(40),
        environment_fingerprint: "x".into(),
        p99_ns: 1,
        p999_ns: 2,
        throughput_ops_per_sec: 1,
        n: 100,
        seed: 0,
    };
    match validate_live_measurement(&row) {
        Err(LiveMeasurementError::InsufficientSamplesForP999) => Ok(()),
        other => Err(format!(
            "expected InsufficientSamplesForP999; got {other:?}"
        )),
    }
}

// ── Live runner tests (bd-8b70o) ─────────────────────────────────────

#[test]
fn manifest_live_runner_pins_pair_anchoring_fields() -> TestResult {
    let m = load_manifest()?;
    let runner = json_field(&m, "live_measurement_runner")?;
    require(
        json_string(runner, "tail_statistics_contract_owner")? == "bd-juvqm.11",
        "tail stats owner",
    )?;
    let labels = json_field(runner, "lane_id_label_contract")?;
    require(
        json_string(labels, "Conservative")? == "Conservative",
        "Conservative label",
    )?;
    require(
        json_string(labels, "Seqlock")? == "Seqlock",
        "Seqlock label",
    )?;
    let anchor: BTreeSet<&str> = json_array(runner, "lane_pair_required_anchoring_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "profile_id",
        "source_commit",
        "environment_fingerprint",
        "n",
        "seed",
    ]
    .into_iter()
    .collect();
    require(anchor == expected, format!("anchor: {anchor:?}"))?;
    require(
        json_bool(runner, "fail_closed_when_lane_id_label_wrong")?,
        "fail_closed_when_lane_id_label_wrong",
    )?;
    require(
        json_bool(
            runner,
            "fail_closed_when_anchoring_field_differs_between_lanes",
        )?,
        "fail_closed_when_anchoring_field_differs_between_lanes",
    )
}

#[test]
fn live_runner_produces_validatable_row_for_conservative_lane() -> TestResult {
    let commit = "1".repeat(40);
    let row = run_live_measurement(
        LaneId::Conservative,
        "test-profile",
        2_000,
        0xc0ffee,
        "linux-test",
        &commit,
    )
    .map_err(|e| format!("runner failed: {e:?}"))?;
    require(row.lane_id == "Conservative", "lane_id label")?;
    require(row.n == 2_000, "n")?;
    require(row.seed == 0xc0ffee, "seed")?;
    require(validate_live_measurement(&row).is_ok(), "row must validate")
}

#[test]
fn live_runner_pair_anchors_both_lanes_to_identical_inputs() -> TestResult {
    let commit = "a".repeat(40);
    let pair = run_live_measurement_pair("test-profile", 1_500, 0x1234_5678, "linux-test", &commit)
        .map_err(|e| format!("runner failed: {e:?}"))?;
    require(
        pair.conservative.lane_id == "Conservative",
        "conservative lane_id",
    )?;
    require(pair.seqlock.lane_id == "Seqlock", "seqlock lane_id")?;
    require(
        pair.conservative.source_commit == pair.seqlock.source_commit,
        "source_commit",
    )?;
    require(pair.conservative.n == pair.seqlock.n, "n")?;
    require(pair.conservative.seed == pair.seqlock.seed, "seed")?;
    require(
        pair.conservative.environment_fingerprint == pair.seqlock.environment_fingerprint,
        "environment_fingerprint",
    )?;
    require(
        validate_live_measurement_pair(&pair).is_ok(),
        format!("pair must validate: {pair:?}"),
    )
}

#[test]
fn live_runner_rejects_n_below_minimum_for_p999() -> TestResult {
    let commit = "b".repeat(40);
    match run_live_measurement(LaneId::Conservative, "p", 100, 0, "x", &commit) {
        Err(LiveMeasurementError::InsufficientSamplesForP999) => Ok(()),
        other => Err(format!(
            "expected InsufficientSamplesForP999; got {other:?}"
        )),
    }
}

#[test]
fn live_pair_validator_rejects_lane_id_mismatch() -> TestResult {
    let commit = "c".repeat(40);
    let pair = run_live_measurement_pair("p", 1_500, 0xabcd, "linux-test", &commit)
        .map_err(|e| format!("runner failed: {e:?}"))?;
    let mut bad = pair.clone();
    bad.conservative.lane_id = "WrongLabel".to_string();
    match validate_live_measurement_pair(&bad) {
        Err(LivePairError::ConservativeRowHasWrongLaneId) => Ok(()),
        other => Err(format!(
            "expected ConservativeRowHasWrongLaneId; got {other:?}"
        )),
    }
}

#[test]
fn live_pair_validator_rejects_source_commit_drift() -> TestResult {
    let commit = "d".repeat(40);
    let pair = run_live_measurement_pair("p", 1_500, 0xfeed, "linux-test", &commit)
        .map_err(|e| format!("runner failed: {e:?}"))?;
    let mut bad = pair.clone();
    bad.seqlock.source_commit = "f".repeat(40);
    match validate_live_measurement_pair(&bad) {
        Err(LivePairError::SourceCommitDiffers) => Ok(()),
        other => Err(format!("expected SourceCommitDiffers; got {other:?}")),
    }
}

#[test]
fn live_pair_validator_rejects_seed_drift() -> TestResult {
    let commit = "e".repeat(40);
    let pair = run_live_measurement_pair("p", 1_500, 0xface, "linux-test", &commit)
        .map_err(|e| format!("runner failed: {e:?}"))?;
    let mut bad = pair.clone();
    bad.seqlock.seed = bad.seqlock.seed.wrapping_add(1);
    match validate_live_measurement_pair(&bad) {
        Err(LivePairError::SeedDiffers) => Ok(()),
        other => Err(format!("expected SeedDiffers; got {other:?}")),
    }
}

#[test]
fn live_pair_validator_rejects_environment_fingerprint_drift() -> TestResult {
    let commit = "9".repeat(40);
    let pair = run_live_measurement_pair("p", 1_500, 0x4242, "linux-test", &commit)
        .map_err(|e| format!("runner failed: {e:?}"))?;
    let mut bad = pair.clone();
    bad.conservative.environment_fingerprint = "different".to_string();
    match validate_live_measurement_pair(&bad) {
        Err(LivePairError::EnvironmentFingerprintDiffers) => Ok(()),
        other => Err(format!(
            "expected EnvironmentFingerprintDiffers; got {other:?}"
        )),
    }
}

#[test]
fn _unused_imports_quiet() -> TestResult {
    // Touch every imported type to avoid unused-import warnings if a
    // refactor moves things around.
    let _: Option<LiveMeasurementRow> = None;
    let _: Option<LiveMeasurementPair> = None;
    let _: Option<ProfileGatedReadMostly> = None;
    let _ = isomorphism_witness;
    Ok(())
}

#[test]
fn summary_anchors_claim_status_to_report_only() -> TestResult {
    let m = load_manifest()?;
    let summary = json_field(&m, "summary")?;
    require(
        json_string(summary, "selected_hotspot_stage_id")? == "tls_cache",
        "summary stage_id",
    )?;
    require(json_u64(summary, "lanes_count")? == 2, "lanes count")?;
    require(
        json_bool(summary, "single_lever_change")?,
        "single_lever_change",
    )?;
    require(
        json_string(summary, "deterministic_fallback_lane")? == "Conservative",
        "fallback lane",
    )?;
    require(
        json_string(summary, "claim_status")? == "report_only_until_live_measurement",
        "claim_status",
    )
}
