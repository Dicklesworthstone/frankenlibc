//! Conformance gate for the default-fingerprint live measurement
//! convenience helpers (bd-gxgr5).
//!
//! Validates the manifest pins the helper paths + exercises the
//! pair/single helpers and asserts the resulting fingerprint equals
//! what `environment_fingerprint()` returns at call time. The crate
//! `forbid(unsafe_code)`s, and `std::env::set_var` is `unsafe` in
//! current Rust editions, so we deliberately do not mutate process
//! env from this test (which would also race with parallel tests).
//! Instead we observe the deterministic detector output.

use std::path::{Path, PathBuf};

use frankenlibc_harness::read_mostly_fast_path_prototype::{
    LaneId, LiveMeasurementError, LiveMeasurementPair, LiveMeasurementRow, run_live_measurement,
    run_live_measurement_pair, run_live_measurement_pair_with_detected_fingerprint,
    run_live_measurement_with_detected_fingerprint,
};
use frankenlibc_harness::system_fingerprint::environment_fingerprint;
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
        .join("live_measurement_pair_default_fingerprint.v1.json")
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

const SOURCE_COMMIT: &str = "cee26b198733e70d6b5a70b72ab257106ccbb1f8";

#[test]
fn manifest_anchors_to_gxgr5_with_helper_paths() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "live-measurement-pair-default-fingerprint",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-gxgr5", "bead")?;
    require(
        json_string(&m, "default_fingerprint_pair_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_pair_with_detected_fingerprint",
        "default_fingerprint_pair_function",
    )?;
    require(
        json_string(&m, "default_fingerprint_single_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_with_detected_fingerprint",
        "default_fingerprint_single_function",
    )?;
    require(
        json_string(&m, "underlying_pair_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement_pair",
        "underlying_pair_function",
    )?;
    require(
        json_string(&m, "underlying_single_function")?
            == "frankenlibc_harness::read_mostly_fast_path_prototype::run_live_measurement",
        "underlying_single_function",
    )?;
    require(
        json_string(&m, "fingerprint_source_function")?
            == "frankenlibc_harness::system_fingerprint::environment_fingerprint",
        "fingerprint_source_function",
    )?;
    Ok(())
}

#[test]
fn manifest_env_override_pins_var_name() -> TestResult {
    let m = load_manifest()?;
    let ov = m
        .get("env_override")
        .ok_or_else(|| "missing env_override".to_string())?;
    require(
        json_string(ov, "var_name")? == "FRANKENLIBC_ENV_FINGERPRINT",
        "var_name",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let m = load_manifest()?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "default_helpers_must_route_through_environment_fingerprint",
        "underlying_helpers_signature_unchanged",
        "fingerprint_must_propagate_to_both_lanes_in_pair",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

// Pin the wrapper + underlying signatures at COMPILE time (not just
// runtime). If the path renames or arity drifts, these aliases stop
// matching and the test file fails to compile.
type PairDefaultFn = fn(&str, u64, u64, &str) -> Result<LiveMeasurementPair, LiveMeasurementError>;
type SingleDefaultFn =
    fn(LaneId, &str, u64, u64, &str) -> Result<LiveMeasurementRow, LiveMeasurementError>;
type PairUnderlyingFn =
    fn(&str, u64, u64, &str, &str) -> Result<LiveMeasurementPair, LiveMeasurementError>;
type SingleUnderlyingFn =
    fn(LaneId, &str, u64, u64, &str, &str) -> Result<LiveMeasurementRow, LiveMeasurementError>;

#[test]
fn helper_function_pointers_compile_with_expected_signatures() -> TestResult {
    let _pair_default: PairDefaultFn = run_live_measurement_pair_with_detected_fingerprint;
    let _single_default: SingleDefaultFn = run_live_measurement_with_detected_fingerprint;
    let _pair_underlying: PairUnderlyingFn = run_live_measurement_pair;
    let _single_underlying: SingleUnderlyingFn = run_live_measurement;
    Ok(())
}

#[test]
fn pair_helper_routes_through_environment_fingerprint_for_both_lanes() -> TestResult {
    let n: u64 = 5_000;
    let seed: u64 = 0xc0ffee;
    // Snapshot the detector once. The convenience helper invokes the
    // SAME detector internally, so the resulting rows MUST carry an
    // identical fingerprint string. (`environment_fingerprint()` is
    // deterministic for a fixed env+fs state per bd-6epxt.)
    let expected = environment_fingerprint();
    let pair =
        run_live_measurement_pair_with_detected_fingerprint("default-fp", n, seed, SOURCE_COMMIT)
            .map_err(|e| format!("pair helper failed: {e:?}"))?;
    require(
        pair.conservative.environment_fingerprint == expected,
        format!(
            "conservative fingerprint = {} expected {expected}",
            pair.conservative.environment_fingerprint
        ),
    )?;
    require(
        pair.seqlock.environment_fingerprint == expected,
        format!(
            "seqlock fingerprint = {} expected {expected}",
            pair.seqlock.environment_fingerprint
        ),
    )?;
    require(pair.conservative.lane_id == "Conservative", "lane_id cons")?;
    require(pair.seqlock.lane_id == "Seqlock", "lane_id seq")?;
    require(pair.conservative.n == n, "n cons")?;
    require(pair.seqlock.n == n, "n seq")?;
    require(pair.conservative.seed == seed, "seed cons")?;
    require(pair.seqlock.seed == seed, "seed seq")
}

#[test]
fn single_helper_routes_through_environment_fingerprint() -> TestResult {
    let n: u64 = 5_000;
    let seed: u64 = 0xdeadbeef;
    let expected = environment_fingerprint();
    let row = run_live_measurement_with_detected_fingerprint(
        LaneId::Seqlock,
        "default-fp-single",
        n,
        seed,
        SOURCE_COMMIT,
    )
    .map_err(|e| format!("single helper failed: {e:?}"))?;
    require(
        row.environment_fingerprint == expected,
        format!(
            "fingerprint = {} expected {expected}",
            row.environment_fingerprint
        ),
    )?;
    require(row.lane_id == "Seqlock", "lane_id")?;
    require(row.n == n, "n")?;
    require(row.seed == seed, "seed")?;
    require(row.profile_id == "default-fp-single", "profile_id")?;
    require(row.source_commit == SOURCE_COMMIT, "source_commit")
}

#[test]
fn helpers_propagate_p999_validation_failure_unchanged() -> TestResult {
    // n below MIN_SAMPLES_FOR_P999 — the underlying helper must
    // still reject this exactly the same way through the wrapper.
    let n: u64 = 100;
    let seed: u64 = 1;
    match run_live_measurement_pair_with_detected_fingerprint(
        "p999-too-small",
        n,
        seed,
        SOURCE_COMMIT,
    ) {
        Err(LiveMeasurementError::InsufficientSamplesForP999) => {}
        other => {
            return Err(format!(
                "expected InsufficientSamplesForP999 from pair wrapper; got {other:?}"
            ));
        }
    }
    match run_live_measurement_with_detected_fingerprint(
        LaneId::Conservative,
        "p999-too-small-single",
        n,
        seed,
        SOURCE_COMMIT,
    ) {
        Err(LiveMeasurementError::InsufficientSamplesForP999) => Ok(()),
        other => Err(format!(
            "expected InsufficientSamplesForP999 from single wrapper; got {other:?}"
        )),
    }
}
