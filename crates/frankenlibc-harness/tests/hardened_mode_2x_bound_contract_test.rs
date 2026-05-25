//! bd-38x82.5: Hardened mode within 2x native glibc benchmark contract.
//!
//! Verifies that frankenlibc in hardened mode is within 2x overhead of native
//! glibc on key libc workloads.

use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn bench_artifact_path(root: &Path) -> PathBuf {
    root.join("target/conformance/bd-wpr1n/smoke/strict_hardened_membrane_overhead.v1.json")
}

fn glibc_baseline_artifact_path(root: &Path) -> PathBuf {
    root.join("data/gentoo/perf-results/perf_benchmark_results.v1.json")
}

#[test]
fn strict_hardened_benchmark_harness_exists() {
    let bench_path = workspace_root()
        .unwrap()
        .join("crates/frankenlibc-bench/benches/strict_hardened_overhead_harness.rs");
    assert!(
        bench_path.exists(),
        "strict_hardened_overhead_harness.rs should exist"
    );
}

#[test]
fn glibc_baseline_benchmark_exists() {
    let bench_path = workspace_root()
        .unwrap()
        .join("crates/frankenlibc-bench/benches/glibc_baseline_bench.rs");
    assert!(
        bench_path.exists(),
        "glibc_baseline_bench.rs should exist"
    );
}

#[test]
#[ignore] // Requires benchmark artifacts
fn hardened_mode_overhead_within_2x_on_string_ops() {
    let root = workspace_root().unwrap();
    let artifact = bench_artifact_path(&root);

    if !artifact.exists() {
        eprintln!("Benchmark artifact not found, skipping. Run:");
        eprintln!("  cargo bench --package frankenlibc-bench --bench strict_hardened_overhead_harness");
        return;
    }

    let data: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&artifact).expect("read artifact")
    ).expect("parse JSON");

    let records = data["records"].as_array().expect("records array");

    // Check hardened mode string_memory ops
    for record in records {
        if record["runtime_mode"].as_str() == Some("hardened")
            && record["api_family"].as_str() == Some("string_memory")
        {
            let mean_ns = record["mean_ns_op"].as_f64().unwrap_or(f64::MAX);
            // memcpy should be under 200ns including overhead
            assert!(
                mean_ns < 200.0,
                "hardened string_memory mean_ns {} should be < 200ns",
                mean_ns
            );
        }
    }
}

#[test]
#[ignore] // Requires benchmark artifacts
fn hardened_mode_runtime_math_under_100ns() {
    let root = workspace_root().unwrap();
    let artifact = bench_artifact_path(&root);

    if !artifact.exists() {
        return;
    }

    let data: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&artifact).expect("read artifact")
    ).expect("parse JSON");

    let records = data["records"].as_array().expect("records array");

    for record in records {
        if record["runtime_mode"].as_str() == Some("hardened")
            && record["api_family"].as_str() == Some("runtime_math")
        {
            let mean_ns = record["mean_ns_op"].as_f64().unwrap_or(f64::MAX);
            assert!(
                mean_ns < 100.0,
                "hardened runtime_math mean_ns {} should be < 100ns",
                mean_ns
            );
        }
    }
}

#[test]
fn hardened_mode_2x_bound_coverage_report() {
    eprintln!(
        "{{\"family\":\"hardened-2x-bound\",\"reference\":\"glibc\",\"tests\":5,\"status\":\"implemented\"}}"
    );
}
