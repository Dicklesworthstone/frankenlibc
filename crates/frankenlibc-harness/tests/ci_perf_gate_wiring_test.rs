//! Integration test: CI benchmark gate wiring (bd-l93x.3)
//!
//! Validates that:
//! 1. `scripts/ci.sh` routes benchmark validation through `check_benchmark_gate.sh`
//!    when `rch` is available.
//! 2. The fallback path remains deterministic and validates both the perf baseline
//!    contract and symbol latency artifact before running `perf_gate.sh`.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn ci_script() -> String {
    let path = workspace_root().join("scripts/ci.sh");
    std::fs::read_to_string(&path).expect("scripts/ci.sh should exist")
}

#[test]
fn benchmark_gate_prefers_rch_wrapper_when_available() {
    let script = ci_script();
    assert!(
        script.contains("scripts/check_benchmark_gate.sh"),
        "ci.sh should route the benchmark gate through scripts/check_benchmark_gate.sh"
    );
}

#[test]
fn benchmark_gate_fallback_validates_local_contracts() {
    let script = ci_script();
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
}
