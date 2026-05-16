//! Metamorphic invariants for tail-statistics evidence.
//!
//! MR strength matrix:
//! permutation invariance: sensitivity 4, independence 4, cost 1, score 16
//! translation equivariance: sensitivity 4, independence 5, cost 1, score 20
//! positive-scale equivariance: sensitivity 5, independence 5, cost 1, score 25

use std::fmt::Display;

use frankenlibc_harness::tail_stats::{bootstrap_ci, compute, quantile};

const SEED: u64 = 0x5441_494c_5354_4154;

type TestResult<T = ()> = Result<T, String>;

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

fn with_context<T, E: Display>(result: Result<T, E>, label: &str) -> TestResult<T> {
    result.map_err(|error| format!("{label}: {error}"))
}

fn sort_finite(values: &mut [f64], label: &str) -> TestResult {
    if let Some((index, value)) = values
        .iter()
        .enumerate()
        .find(|(_, value)| !value.is_finite())
    {
        return Err(format!(
            "{label}: non-finite sample at index {index}: {value}"
        ));
    }
    values.sort_by(|a, b| a.total_cmp(b));
    Ok(())
}

fn assert_close(actual: f64, expected: f64, label: &str) -> TestResult {
    let tolerance = 1e-9_f64.max(expected.abs() * 1e-12);
    if (actual - expected).abs() > tolerance {
        return Err(format!(
            "{label}: actual={actual}, expected={expected}, tolerance={tolerance}"
        ));
    }
    Ok(())
}

#[test]
fn compute_is_permutation_invariant_for_same_seed() -> TestResult {
    let samples = sample_series();
    let shuffled = permuted(samples.clone());

    let original = with_context(compute(&samples, SEED), "original tail stats")?;
    let permuted = with_context(compute(&shuffled, SEED), "permuted tail stats")?;

    assert_eq!(
        original, permuted,
        "tail_stats::compute must sort samples before estimating quantiles and bootstrap CI"
    );
    Ok(())
}

#[test]
fn quantiles_and_p99_ci_translate_with_samples() -> TestResult {
    let samples = sample_series();
    let offset = 37.5;
    let translated: Vec<f64> = samples.iter().map(|value| value + offset).collect();

    let original = with_context(compute(&samples, SEED), "original tail stats")?;
    let shifted = with_context(compute(&translated, SEED), "translated tail stats")?;

    assert_close(shifted.p50, original.p50 + offset, "p50 translation")?;
    assert_close(shifted.p95, original.p95 + offset, "p95 translation")?;
    assert_close(shifted.p99, original.p99 + offset, "p99 translation")?;
    assert_close(shifted.p999, original.p999 + offset, "p999 translation")?;
    assert_close(
        shifted.p99_ci_low,
        original.p99_ci_low + offset,
        "p99 ci low translation",
    )?;
    assert_close(
        shifted.p99_ci_high,
        original.p99_ci_high + offset,
        "p99 ci high translation",
    )?;
    assert_eq!(shifted.n, original.n);
    assert_eq!(shifted.seed, original.seed);
    assert_eq!(shifted.bootstrap_iters, original.bootstrap_iters);
    Ok(())
}

#[test]
fn quantiles_and_p99_ci_scale_with_positive_factor() -> TestResult {
    let samples = sample_series();
    let scale = 2.0;
    let scaled: Vec<f64> = samples.iter().map(|value| value * scale).collect();

    let original = with_context(compute(&samples, SEED), "original tail stats")?;
    let scaled_stats = with_context(compute(&scaled, SEED), "scaled tail stats")?;

    assert_close(scaled_stats.p50, original.p50 * scale, "p50 scale")?;
    assert_close(scaled_stats.p95, original.p95 * scale, "p95 scale")?;
    assert_close(scaled_stats.p99, original.p99 * scale, "p99 scale")?;
    assert_close(scaled_stats.p999, original.p999 * scale, "p999 scale")?;
    assert_close(
        scaled_stats.p99_ci_low,
        original.p99_ci_low * scale,
        "p99 ci low scale",
    )?;
    assert_close(
        scaled_stats.p99_ci_high,
        original.p99_ci_high * scale,
        "p99 ci high scale",
    )?;
    assert_eq!(scaled_stats.sufficient_for_p99, original.sufficient_for_p99);
    assert_eq!(
        scaled_stats.sufficient_for_p999,
        original.sufficient_for_p999
    );
    assert_eq!(scaled_stats.overloaded_host, original.overloaded_host);
    Ok(())
}

#[test]
fn quantile_helper_is_affine_equivariant() -> TestResult {
    let mut samples = sample_series();
    sort_finite(&mut samples, "affine samples")?;
    let transformed: Vec<f64> = samples.iter().map(|value| value * 3.0 + 11.0).collect();

    for q in [0.0, 0.1, 0.5, 0.95, 0.99, 1.0] {
        let original = with_context(quantile(&samples, q), &format!("original quantile q={q}"))?;
        let actual = with_context(
            quantile(&transformed, q),
            &format!("transformed quantile q={q}"),
        )?;
        assert_close(actual, original * 3.0 + 11.0, "quantile affine")?;
    }
    Ok(())
}

#[test]
fn bootstrap_ci_is_permutation_invariant_for_same_seed() -> TestResult {
    let mut samples = sample_series();
    let mut shuffled = permuted(samples.clone());
    sort_finite(&mut samples, "bootstrap samples")?;
    sort_finite(&mut shuffled, "bootstrap shuffled samples")?;

    let original = with_context(bootstrap_ci(&samples, 0.99, 128, 0.05, SEED), "original ci")?;
    let permuted = with_context(
        bootstrap_ci(&shuffled, 0.99, 128, 0.05, SEED),
        "permuted ci",
    )?;

    assert_eq!(original, permuted);
    Ok(())
}
