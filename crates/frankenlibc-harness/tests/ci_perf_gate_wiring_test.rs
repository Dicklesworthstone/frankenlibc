//! Integration test: CI benchmark gate wiring (bd-l93x.3)
//!
//! Validates that:
//! 1. `scripts/ci.sh` routes benchmark validation through `check_benchmark_gate.sh`
//!    when `rch` is available.
//! 2. The fallback path remains deterministic and validates both the perf baseline
//!    contract and symbol latency artifact before running `perf_gate.sh`.

use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let crate_dir = Path::new(manifest);
    let workspace = crate_dir
        .parent()
        .ok_or_else(|| test_error(format!("crate directory has no parent: {manifest}")))?;
    let repo = workspace
        .parent()
        .ok_or_else(|| test_error(format!("workspace directory has no parent: {manifest}")))?;
    Ok(repo.to_path_buf())
}

fn ci_script() -> TestResult<String> {
    let path = workspace_root()?.join("scripts/ci.sh");
    std::fs::read_to_string(&path)
        .map_err(|err| test_error(format!("scripts/ci.sh should exist: {err}")))
}

#[test]
fn benchmark_gate_prefers_rch_wrapper_when_available() -> TestResult {
    let script = ci_script()?;
    assert!(
        script.contains("scripts/check_benchmark_gate.sh"),
        "ci.sh should route the benchmark gate through scripts/check_benchmark_gate.sh"
    );
    Ok(())
}

#[test]
fn benchmark_gate_fallback_validates_local_contracts() -> TestResult {
    let script = ci_script()?;
    assert!(
        script.contains("scripts/check_perf_baseline.sh"),
        "ci.sh fallback should validate the perf baseline contract"
    );
    assert!(
        script.contains("scripts/check_symbol_latency_baseline.sh"),
        "ci.sh fallback should validate the symbol latency contract"
    );
    assert!(
        script.contains("scripts/perf_gate.sh"),
        "ci.sh fallback should still run scripts/perf_gate.sh locally"
    );
    assert!(
        script.contains("FRANKENLIBC_FORCE_LOCAL_BENCHMARK_GATE"),
        "ci.sh should expose a deterministic override for the local fallback path"
    );
    Ok(())
}

#[test]
fn ci_script_runs_elimination_backoff_gate() -> TestResult {
    let script = ci_script()?;
    assert!(
        script.contains("scripts/check_elimination_backoff.sh"),
        "ci.sh should run scripts/check_elimination_backoff.sh in the extended gate suite"
    );
    Ok(())
}

#[test]
fn ci_script_runs_metadata_read_benchmark_gate() -> TestResult {
    let script = ci_script()?;
    assert!(
        script.contains("scripts/check_metadata_read_benchmark.sh"),
        "ci.sh should run scripts/check_metadata_read_benchmark.sh in the extended gate suite"
    );
    Ok(())
}
