//! Metamorphic invariants for tail-statistics evidence.
//!
//! MR strength matrix:
//! permutation invariance: sensitivity 4, independence 4, cost 1, score 16
//! translation equivariance: sensitivity 4, independence 5, cost 1, score 20
//! positive-scale equivariance: sensitivity 5, independence 5, cost 1, score 25

use frankenlibc_harness::tail_stats::{bootstrap_ci, compute, quantile};

const SEED: u64 = 0x5441_494c_5354_4154;

fn sample_series() -> Vec<f64> {
    (0..160)
        .map(|i| {
            let base = (i as f64 % 19.0) * 3.25;
            let trend = i as f64 * 0.75;
            let burst = if i % 17 == 0 { 42.0 } else { 0.0 };
            10.0 + base + trend + burst
        })
        .collect()
}

fn permuted(mut values: Vec<f64>) -> Vec<f64> {
    let n = values.len();
    for i in 0..n {
        let j = (i * 37 + 11) % n;
        values.swap(i, j);
    }
    values
}

fn assert_close(actual: f64, expected: f64, label: &str) {
    let tolerance = 1e-9_f64.max(expected.abs() * 1e-12);
    assert!(
        (actual - expected).abs() <= tolerance,
        "{label}: actual={actual}, expected={expected}, tolerance={tolerance}"
    );
}

#[test]
fn compute_is_permutation_invariant_for_same_seed() {
    let samples = sample_series();
    let shuffled = permuted(samples.clone());

    let original = compute(&samples, SEED).expect("original tail stats");
    let permuted = compute(&shuffled, SEED).expect("permuted tail stats");

    assert_eq!(
        original, permuted,
        "tail_stats::compute must sort samples before estimating quantiles and bootstrap CI"
    );
}

#[test]
fn quantiles_and_p99_ci_translate_with_samples() {
    let samples = sample_series();
    let offset = 37.5;
    let translated: Vec<f64> = samples.iter().map(|value| value + offset).collect();

    let original = compute(&samples, SEED).expect("original tail stats");
    let shifted = compute(&translated, SEED).expect("translated tail stats");

    assert_close(shifted.p50, original.p50 + offset, "p50 translation");
    assert_close(shifted.p95, original.p95 + offset, "p95 translation");
    assert_close(shifted.p99, original.p99 + offset, "p99 translation");
    assert_close(shifted.p999, original.p999 + offset, "p999 translation");
    assert_close(
        shifted.p99_ci_low,
        original.p99_ci_low + offset,
        "p99 ci low translation",
    );
    assert_close(
        shifted.p99_ci_high,
        original.p99_ci_high + offset,
        "p99 ci high translation",
    );
    assert_eq!(shifted.n, original.n);
    assert_eq!(shifted.seed, original.seed);
    assert_eq!(shifted.bootstrap_iters, original.bootstrap_iters);
}

#[test]
fn quantiles_and_p99_ci_scale_with_positive_factor() {
    let samples = sample_series();
    let scale = 2.0;
    let scaled: Vec<f64> = samples.iter().map(|value| value * scale).collect();

    let original = compute(&samples, SEED).expect("original tail stats");
    let scaled_stats = compute(&scaled, SEED).expect("scaled tail stats");

    assert_close(scaled_stats.p50, original.p50 * scale, "p50 scale");
    assert_close(scaled_stats.p95, original.p95 * scale, "p95 scale");
    assert_close(scaled_stats.p99, original.p99 * scale, "p99 scale");
    assert_close(scaled_stats.p999, original.p999 * scale, "p999 scale");
    assert_close(
        scaled_stats.p99_ci_low,
        original.p99_ci_low * scale,
        "p99 ci low scale",
    );
    assert_close(
        scaled_stats.p99_ci_high,
        original.p99_ci_high * scale,
        "p99 ci high scale",
    );
    assert_eq!(scaled_stats.sufficient_for_p99, original.sufficient_for_p99);
    assert_eq!(
        scaled_stats.sufficient_for_p999,
        original.sufficient_for_p999
    );
    assert_eq!(scaled_stats.overloaded_host, original.overloaded_host);
}

#[test]
fn quantile_helper_is_affine_equivariant() {
    let mut samples = sample_series();
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite sample"));
    let transformed: Vec<f64> = samples.iter().map(|value| value * 3.0 + 11.0).collect();

    for q in [0.0, 0.1, 0.5, 0.95, 0.99, 1.0] {
        let original = quantile(&samples, q).expect("original quantile");
        let actual = quantile(&transformed, q).expect("transformed quantile");
        assert_close(actual, original * 3.0 + 11.0, "quantile affine");
    }
}

#[test]
fn bootstrap_ci_is_permutation_invariant_for_same_seed() {
    let mut samples = sample_series();
    let mut shuffled = permuted(samples.clone());
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite sample"));
    shuffled.sort_by(|a, b| a.partial_cmp(b).expect("finite sample"));

    let original = bootstrap_ci(&samples, 0.99, 128, 0.05, SEED).expect("original ci");
    let permuted = bootstrap_ci(&shuffled, 0.99, 128, 0.05, SEED).expect("permuted ci");

    assert_eq!(original, permuted);
}
