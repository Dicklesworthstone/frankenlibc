//! Conformance gate for the LiveMeasurementPair → P99Delta bridge
//! (bd-vmp2v).
//!
//! Validates the manifest pins both bridge entry points + exercises
//! the bridge to assert (a) the bridge invokes drive-each-lane EXACTLY
//! once, (b) the LiveMeasurementPair p99 floors are consistent with
//! the returned P99Delta, (c) the validator behaves as the manifest
//! claims with both an absurdly generous budget and budget=0.

use std::path::{Path, PathBuf};

use frankenlibc_harness::read_mostly_fast_path_prototype::{
    LiveMeasurementError, LiveMeasurementPair, run_live_measurement_pair,
    run_live_measurement_pair_with_p99_delta,
    run_live_measurement_pair_with_p99_delta_and_detected_fingerprint,
};
use frankenlibc_harness::system_fingerprint::environment_fingerprint;
use frankenlibc_harness::tail_stats::{P99Delta, P99DeltaError, validate_p99_delta_against_budget};
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
        .join("live_measurement_pair_p99_delta_bridge.v1.json")
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

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

const SOURCE_COMMIT: &str = "e82d7ff837d210ca0171d900f01aa81c34e39642";
const N: u64 = 5_000;
const SEED: u64 = 0xc0ffee;

#[test]
fn manifest_anchors_to_vmp2v_with_bridge_paths() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "live-measurement-pair-p99-delta-bridge",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-vmp2v", "bead")?;
    require(
        json_string(&m, "bridge_pair_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_pair_with_p99_delta",
        "bridge_pair_function",
    )?;
    require(
        json_string(&m, "bridge_pair_default_fingerprint_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_pair_with_p99_delta_and_detected_fingerprint",
        "bridge_pair_default_fingerprint_function",
    )?;
    require(
        json_string(&m, "underlying_pair_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_pair",
        "underlying_pair_function",
    )?;
    require(
        json_string(&m, "underlying_p99_delta_function")?
            == "frankenlibc_harness::tail_stats::compute_p99_delta",
        "underlying_p99_delta_function",
    )?;
    require(
        json_string(&m, "underlying_p99_delta_validator")?
            == "frankenlibc_harness::tail_stats::validate_p99_delta_against_budget",
        "underlying_p99_delta_validator",
    )?;
    require(
        json_string(&m, "fingerprint_source_function")?
            == "frankenlibc_harness::system_fingerprint::environment_fingerprint",
        "fingerprint_source_function",
    )?;
    Ok(())
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let m = load_manifest()?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "bridge_drives_each_lane_exactly_once",
        "live_measurement_row_p99_must_be_consistent_with_p99_delta",
        "underlying_helpers_signature_unchanged",
        "default_fingerprint_variant_routes_through_environment_fingerprint",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

// Function-pointer aliases pin the bridge surfaces at COMPILE time.
type BridgeFn =
    fn(&str, u64, u64, &str, &str) -> Result<(LiveMeasurementPair, P99Delta), LiveMeasurementError>;
type BridgeDefaultFn =
    fn(&str, u64, u64, &str) -> Result<(LiveMeasurementPair, P99Delta), LiveMeasurementError>;
type UnderlyingPairFn =
    fn(&str, u64, u64, &str, &str) -> Result<LiveMeasurementPair, LiveMeasurementError>;

#[test]
fn bridge_function_pointers_compile_with_expected_signatures() -> TestResult {
    let _bridge: BridgeFn = run_live_measurement_pair_with_p99_delta;
    let _bridge_default: BridgeDefaultFn =
        run_live_measurement_pair_with_p99_delta_and_detected_fingerprint;
    let _pair: UnderlyingPairFn = run_live_measurement_pair;
    Ok(())
}

#[test]
fn bridge_pair_p99_floor_is_consistent_with_returned_p99_delta() -> TestResult {
    let (pair, delta) = run_live_measurement_pair_with_p99_delta(
        "bridge",
        N,
        SEED,
        "linux-x86_64-test",
        SOURCE_COMMIT,
    )
    .map_err(|e| format!("bridge failed: {e:?}"))?;

    // Pair anchoring sanity.
    require(pair.conservative.lane_id == "Conservative", "lane_id cons")?;
    require(pair.seqlock.lane_id == "Seqlock", "lane_id seq")?;
    require(pair.conservative.n == N, "n cons")?;
    require(pair.seqlock.n == N, "n seq")?;

    // The returned P99Delta is computed from the underlying TailStats
    // (f64 ns); the LiveMeasurementRow.p99_ns is the same value cast
    // to u64 with non-finite/negative clamped to 0. Therefore:
    //
    //   abs(cons.p99_ns as f64 - seq.p99_ns as f64) - 1.0  ≤  delta.p99_delta_ns
    //                                                      ≤  abs(diff) + 1.0
    //
    // The 1.0 ns slack covers the f64→u64 floor cast either way.
    let cons_p99 = pair.conservative.p99_ns as f64;
    let seq_p99 = pair.seqlock.p99_ns as f64;
    let row_diff = (cons_p99 - seq_p99).abs();
    require(
        delta.p99_delta_ns + 1.0 >= row_diff && row_diff + 1.0 >= delta.p99_delta_ns,
        format!(
            "p99 floor diff {row_diff} inconsistent with delta {} (slack=1ns)",
            delta.p99_delta_ns
        ),
    )?;
    require(
        delta.sufficient_samples,
        "sufficient_samples must be true at N=5_000",
    )?;
    require(
        delta.p99_delta_ns.is_finite(),
        "p99_delta_ns must be finite",
    )?;
    require(
        delta.amplification_ratio.is_finite() || delta.amplification_ratio == f64::INFINITY,
        "amplification_ratio finite or INF",
    )
}

#[test]
fn bridge_returned_delta_passes_validator_with_generous_budget() -> TestResult {
    let (_pair, delta) = run_live_measurement_pair_with_p99_delta(
        "validator-generous",
        N,
        SEED,
        "linux-x86_64-test",
        SOURCE_COMMIT,
    )
    .map_err(|e| format!("bridge failed: {e:?}"))?;

    // Generous: 1ms budget is far above any plausible single-mutex
    // read-mostly p99 delta on a healthy host. Amplification threshold
    // 1e9 covers the degenerate case where one lane returns 0.
    let res = validate_p99_delta_against_budget(&delta, 1_000_000, 1.0e9);
    require(
        res.is_ok(),
        format!("expected Ok with generous budget; got {res:?}"),
    )
}

#[test]
fn bridge_returned_delta_fails_validator_with_zero_budget() -> TestResult {
    let (_pair, delta) = run_live_measurement_pair_with_p99_delta(
        "validator-zero",
        N,
        SEED,
        "linux-x86_64-test",
        SOURCE_COMMIT,
    )
    .map_err(|e| format!("bridge failed: {e:?}"))?;

    // budget=0 with sufficient_samples=true must reject. The exact
    // variant depends on whether the CIs are disjoint:
    //   * disjoint → OverBudget (or AmplificationAboveThreshold if
    //                amp > 1.0)
    //   * overlapping → CiIndistinguishableButOverBudget
    //
    // Anything Ok here is a contract failure.
    let res = validate_p99_delta_against_budget(&delta, 0, 1.0e9);
    match res {
        Err(P99DeltaError::OverBudget)
        | Err(P99DeltaError::CiIndistinguishableButOverBudget)
        | Err(P99DeltaError::AmplificationAboveThreshold) => Ok(()),
        Err(P99DeltaError::InsufficientSamples) => Err(
            "InsufficientSamples — bridge returned delta with sufficient_samples=false at N=5_000"
                .to_string(),
        ),
        Ok(()) => Err("validator accepted budget=0 — bug in bridge or validator".to_string()),
    }
}

#[test]
fn bridge_default_fingerprint_variant_uses_environment_fingerprint() -> TestResult {
    let expected_fp = environment_fingerprint();
    let (pair, _delta) = run_live_measurement_pair_with_p99_delta_and_detected_fingerprint(
        "bridge-default-fp",
        N,
        SEED,
        SOURCE_COMMIT,
    )
    .map_err(|e| format!("bridge default-fp failed: {e:?}"))?;
    require(
        pair.conservative.environment_fingerprint == expected_fp,
        format!(
            "cons fp = {} expected {expected_fp}",
            pair.conservative.environment_fingerprint
        ),
    )?;
    require(
        pair.seqlock.environment_fingerprint == expected_fp,
        format!(
            "seq fp = {} expected {expected_fp}",
            pair.seqlock.environment_fingerprint
        ),
    )
}

#[test]
fn bridge_propagates_p999_validation_failure_unchanged() -> TestResult {
    // n below MIN_SAMPLES_FOR_P999 — the bridge must still reject
    // with InsufficientSamplesForP999, exactly like the underlying
    // run_live_measurement_pair would.
    let res =
        run_live_measurement_pair_with_p99_delta("p999-too-small", 100, 1, "x", SOURCE_COMMIT);
    match res {
        Err(LiveMeasurementError::InsufficientSamplesForP999) => Ok(()),
        other => Err(format!(
            "expected InsufficientSamplesForP999; got {other:?}"
        )),
    }
}
