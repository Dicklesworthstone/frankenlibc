//! Bootstrap tail-statistics helpers for benchmark evidence (bd-juvqm.11).
//!
//! Produces deterministic p50/p95/p99/p999 quantiles, bootstrap confidence
//! intervals around p99, sample-count sufficiency flags, and an
//! overloaded-host warning derived from the coefficient of variation.
//! Designed for reuse across perf manifests; does not alter existing
//! benchmark semantics, but provides one source of truth for tail
//! statistics so future high-core baseline work
//! (bd-juvqm.1 / bd-juvqm.7 / bd-juvqm.12) does not re-invent it.
//!
//! Determinism: every randomized step is seeded via a built-in PCG32
//! generator. Calling [`compute`] twice with the same samples and seed
//! must produce bitwise-identical output, so report fixtures hash
//! reliably and downstream gates can fail closed when a regenerator
//! tries to re-seed silently.
//!
//! Failure modes (returned as [`TailStatsError`]):
//!   * [`TailStatsError::Empty`] — no samples provided.
//!   * [`TailStatsError::NonFiniteSample`] — any NaN/inf in input.
//!   * [`TailStatsError::InvalidQuantile`] — q outside `[0, 1]` or
//!     non-finite. The public [`compute`] call only ever passes
//!     valid quantiles, but the helper is exposed for callers that
//!     compute custom quantiles.
//!
//! Sufficiency policy (matches the perf_budget_policy contract):
//!   * p99 needs at least [`MIN_SAMPLES_FOR_P99`] samples.
//!   * p999 needs at least [`MIN_SAMPLES_FOR_P999`] samples.
//!   * Reports must surface both flags so a gate can refuse claims
//!     made on too-few samples.

/// Default bootstrap iterations for the p99 confidence interval.
pub const DEFAULT_BOOTSTRAP_ITERS: u32 = 1_000;

/// Default two-sided alpha for the p99 confidence interval (95% CI).
pub const DEFAULT_ALPHA: f64 = 0.05;

/// Minimum sample count required before a p99 claim is considered
/// statistically sufficient.
pub const MIN_SAMPLES_FOR_P99: usize = 100;

/// Minimum sample count required before a p999 claim is considered
/// statistically sufficient.
pub const MIN_SAMPLES_FOR_P999: usize = 1_000;

/// Coefficient of variation above which the host is treated as
/// overloaded for the purposes of tail evidence (cv > 1.0 means
/// the standard deviation exceeds the mean — variance dominates).
pub const OVERLOAD_CV_THRESHOLD: f64 = 1.0;

/// Failure shapes for tail-statistics computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailStatsError {
    /// No samples were supplied.
    Empty,
    /// At least one sample was NaN, +inf, or -inf.
    NonFiniteSample,
    /// A quantile argument was outside `[0, 1]` or non-finite.
    InvalidQuantile,
}

impl core::fmt::Display for TailStatsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TailStatsError::Empty => f.write_str("no samples"),
            TailStatsError::NonFiniteSample => f.write_str("non-finite sample"),
            TailStatsError::InvalidQuantile => f.write_str("invalid quantile"),
        }
    }
}

impl std::error::Error for TailStatsError {}

/// One reproducer-grade tail-statistics report. Every field is part
/// of the perf_budget_policy `tail_statistics_contract` and must be
/// emitted alongside any tail claim — gates fail closed when a tail
/// claim arrives without these fields populated.
#[derive(Debug, Clone, PartialEq)]
pub struct TailStats {
    /// Sample count actually consumed.
    pub n: usize,
    /// 50th percentile (median).
    pub p50: f64,
    /// 95th percentile.
    pub p95: f64,
    /// 99th percentile.
    pub p99: f64,
    /// 99.9th percentile.
    pub p999: f64,
    /// Lower bound of the bootstrap CI for p99.
    pub p99_ci_low: f64,
    /// Upper bound of the bootstrap CI for p99.
    pub p99_ci_high: f64,
    /// Whether `n` >= [`MIN_SAMPLES_FOR_P99`].
    pub sufficient_for_p99: bool,
    /// Whether `n` >= [`MIN_SAMPLES_FOR_P999`].
    pub sufficient_for_p999: bool,
    /// Whether the coefficient of variation exceeded
    /// [`OVERLOAD_CV_THRESHOLD`] (suggests an overloaded host).
    pub overloaded_host: bool,
    /// PCG32 seed used for the bootstrap. Surface this in reports so
    /// a regenerator must commit to the same seed or visibly perturb.
    pub seed: u64,
    /// Number of bootstrap iterations actually run.
    pub bootstrap_iters: u32,
}

/// Compute a single quantile from a *pre-sorted* ascending sample
/// slice using Type-7 (R/Excel) linear interpolation. `q` must be
/// finite and in `[0, 1]`.
pub fn quantile(sorted: &[f64], q: f64) -> Result<f64, TailStatsError> {
    if sorted.is_empty() {
        return Err(TailStatsError::Empty);
    }
    if !q.is_finite() || !(0.0..=1.0).contains(&q) {
        return Err(TailStatsError::InvalidQuantile);
    }
    if sorted.len() == 1 {
        return Ok(sorted[0]);
    }
    let h = (sorted.len() as f64 - 1.0) * q;
    let lo = h.floor() as usize;
    let hi = h.ceil() as usize;
    let frac = h - h.floor();
    Ok(sorted[lo] + frac * (sorted[hi] - sorted[lo]))
}

/// Bootstrap confidence interval for a quantile of `sorted` (must be
/// pre-sorted ascending). Returns `(lo, hi)` of the
/// `(alpha/2, 1 - alpha/2)` empirical interval over `iters`
/// resamples. Falls back to `(p, p)` when there are too few samples
/// or zero iterations.
pub fn bootstrap_ci(
    sorted: &[f64],
    q: f64,
    iters: u32,
    alpha: f64,
    seed: u64,
) -> Result<(f64, f64), TailStatsError> {
    if sorted.is_empty() {
        return Err(TailStatsError::Empty);
    }
    if !alpha.is_finite() || !(0.0..1.0).contains(&alpha) {
        return Err(TailStatsError::InvalidQuantile);
    }
    let p = quantile(sorted, q)?;
    if sorted.len() < 3 || iters == 0 {
        return Ok((p, p));
    }

    let mut rng = Pcg32::seeded(seed);
    let n = sorted.len();
    let mut estimates: Vec<f64> = Vec::with_capacity(iters as usize);
    let mut tmp: Vec<f64> = vec![0.0; n];
    for _ in 0..iters {
        for slot in tmp.iter_mut() {
            let idx = (rng.next_u32() as usize) % n;
            *slot = sorted[idx];
        }
        tmp.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        estimates.push(quantile(&tmp, q)?);
    }
    estimates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let m = estimates.len();
    let lo_idx = ((alpha / 2.0) * m as f64).floor() as usize;
    let hi_idx = (((1.0 - alpha / 2.0) * m as f64).ceil() as usize).saturating_sub(1);
    Ok((estimates[lo_idx.min(m - 1)], estimates[hi_idx.min(m - 1)]))
}

/// Compute a full [`TailStats`] reproducer for `samples`. The
/// returned struct is deterministic in `(samples, seed)` — calling
/// twice with the same inputs yields a `PartialEq`-equal result.
pub fn compute(samples: &[f64], seed: u64) -> Result<TailStats, TailStatsError> {
    if samples.is_empty() {
        return Err(TailStatsError::Empty);
    }
    if samples.iter().any(|x| !x.is_finite()) {
        return Err(TailStatsError::NonFiniteSample);
    }
    let mut sorted: Vec<f64> = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = sorted.len();
    let p50 = quantile(&sorted, 0.50)?;
    let p95 = quantile(&sorted, 0.95)?;
    let p99 = quantile(&sorted, 0.99)?;
    let p999 = quantile(&sorted, 0.999)?;
    let (p99_ci_low, p99_ci_high) =
        bootstrap_ci(&sorted, 0.99, DEFAULT_BOOTSTRAP_ITERS, DEFAULT_ALPHA, seed)?;

    let mean = sorted.iter().sum::<f64>() / n as f64;
    let var = if n > 0 {
        sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64
    } else {
        0.0
    };
    let std = var.sqrt();
    let cv = if mean.abs() > 0.0 {
        std / mean.abs()
    } else {
        0.0
    };

    Ok(TailStats {
        n,
        p50,
        p95,
        p99,
        p999,
        p99_ci_low,
        p99_ci_high,
        sufficient_for_p99: n >= MIN_SAMPLES_FOR_P99,
        sufficient_for_p999: n >= MIN_SAMPLES_FOR_P999,
        overloaded_host: cv > OVERLOAD_CV_THRESHOLD,
        seed,
        bootstrap_iters: DEFAULT_BOOTSTRAP_ITERS,
    })
}

/// Tiny PCG32 PRNG — duplicated locally so the harness has zero
/// runtime-RNG crate dependency. The constants match the reference
/// PCG-XSH-RR implementation.
struct Pcg32 {
    state: u64,
    inc: u64,
}

impl Pcg32 {
    fn seeded(seed: u64) -> Self {
        let mut p = Pcg32 {
            state: 0,
            inc: (seed << 1) | 1,
        };
        p.next_u32();
        p.state = p.state.wrapping_add(seed);
        p.next_u32();
        p
    }
    fn next_u32(&mut self) -> u32 {
        let oldstate = self.state;
        self.state = oldstate
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(self.inc);
        let xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) as u32;
        let rot = (oldstate >> 59) as u32;
        xorshifted.rotate_right(rot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() < eps
    }

    #[test]
    fn empty_input_is_rejected() {
        assert_eq!(compute(&[], 7), Err(TailStatsError::Empty));
        assert_eq!(quantile(&[], 0.5), Err(TailStatsError::Empty));
    }

    #[test]
    fn non_finite_samples_rejected() {
        assert_eq!(
            compute(&[1.0, f64::NAN, 3.0], 7),
            Err(TailStatsError::NonFiniteSample)
        );
        assert_eq!(
            compute(&[1.0, f64::INFINITY, 3.0], 7),
            Err(TailStatsError::NonFiniteSample)
        );
        assert_eq!(
            compute(&[1.0, f64::NEG_INFINITY], 7),
            Err(TailStatsError::NonFiniteSample)
        );
    }

    #[test]
    fn invalid_quantile_rejected() {
        let s = [1.0, 2.0, 3.0];
        assert_eq!(quantile(&s, -0.01), Err(TailStatsError::InvalidQuantile));
        assert_eq!(quantile(&s, 1.01), Err(TailStatsError::InvalidQuantile));
        assert_eq!(quantile(&s, f64::NAN), Err(TailStatsError::InvalidQuantile));
    }

    #[test]
    fn quantile_is_monotone() {
        // Random-looking but deterministic sample.
        let mut s: Vec<f64> = (1..=200).map(|i| i as f64).collect();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let qs = [0.0_f64, 0.1, 0.25, 0.5, 0.9, 0.95, 0.99, 0.999, 1.0];
        let mut prev = quantile(&s, qs[0]).unwrap();
        for &q in &qs[1..] {
            let v = quantile(&s, q).unwrap();
            assert!(v >= prev, "quantile non-monotone: q={q} v={v} prev={prev}");
            prev = v;
        }
    }

    #[test]
    fn quantile_uniform_1_to_1000() {
        let s: Vec<f64> = (1..=1000).map(|i| i as f64).collect();
        // Type-7 interpolation on 1..=1000:
        //   q*999 + 1 with linear interp between integer indices.
        let p50 = quantile(&s, 0.5).unwrap();
        let p95 = quantile(&s, 0.95).unwrap();
        let p99 = quantile(&s, 0.99).unwrap();
        let p999 = quantile(&s, 0.999).unwrap();
        assert!(approx_eq(p50, 500.5, 0.001), "p50={p50}");
        assert!(approx_eq(p95, 950.05, 0.05), "p95={p95}");
        assert!(approx_eq(p99, 990.01, 0.05), "p99={p99}");
        assert!(approx_eq(p999, 999.001, 0.05), "p999={p999}");
    }

    #[test]
    fn compute_reports_sufficiency_correctly() {
        let small: Vec<f64> = (1..=50).map(|i| i as f64).collect();
        let medium: Vec<f64> = (1..=500).map(|i| i as f64).collect();
        let large: Vec<f64> = (1..=2000).map(|i| i as f64).collect();

        let s50 = compute(&small, 1).unwrap();
        let s500 = compute(&medium, 1).unwrap();
        let s2000 = compute(&large, 1).unwrap();

        assert!(!s50.sufficient_for_p99);
        assert!(!s50.sufficient_for_p999);
        assert!(s500.sufficient_for_p99);
        assert!(!s500.sufficient_for_p999);
        assert!(s2000.sufficient_for_p99);
        assert!(s2000.sufficient_for_p999);
    }

    #[test]
    fn compute_quantiles_are_monotone() {
        let s: Vec<f64> = (1..=300).map(|i| i as f64).collect();
        let r = compute(&s, 1234).unwrap();
        assert!(r.p50 <= r.p95);
        assert!(r.p95 <= r.p99);
        assert!(r.p99 <= r.p999);
        assert!(r.p99_ci_low <= r.p99);
        assert!(r.p99 <= r.p99_ci_high);
    }

    #[test]
    fn deterministic_seed_yields_identical_output() {
        let s: Vec<f64> = (1..=300).map(|i| i as f64 * 1.7).collect();
        let a = compute(&s, 0xdead_beef).unwrap();
        let b = compute(&s, 0xdead_beef).unwrap();
        assert_eq!(a, b);
        // Different seed must perturb the CI (with overwhelming
        // probability — fail-closed if the seed silently goes
        // unused).
        let c = compute(&s, 0xface_b00c).unwrap();
        let same_ci = approx_eq(a.p99_ci_low, c.p99_ci_low, 1e-9)
            && approx_eq(a.p99_ci_high, c.p99_ci_high, 1e-9);
        assert!(
            !same_ci,
            "p99 CI did not vary with seed — bootstrap not seeded?"
        );
    }

    #[test]
    fn overloaded_host_warning_triggers_on_high_cv() {
        // Mean ≈ 50, std ≈ 50: cv ≈ 1.0; push past threshold.
        let s: Vec<f64> = (0..200)
            .map(|i| if i % 2 == 0 { 1.0 } else { 199.0 })
            .collect();
        let r = compute(&s, 1).unwrap();
        assert!(
            r.overloaded_host,
            "expected high-CV sample to trip overloaded_host; cv was below threshold (n={}, p50={}, p99={})",
            r.n, r.p50, r.p99
        );
    }

    #[test]
    fn overloaded_host_warning_quiet_on_steady_input() {
        let s: Vec<f64> = (0..200).map(|_| 100.0).collect();
        let r = compute(&s, 1).unwrap();
        assert!(!r.overloaded_host);
    }

    #[test]
    fn bootstrap_ci_handles_tiny_samples_gracefully() {
        let s = [10.0, 20.0];
        let (lo, hi) = bootstrap_ci(&s, 0.99, 1000, 0.05, 7).unwrap();
        let p = quantile(&s, 0.99).unwrap();
        assert_eq!(lo, p);
        assert_eq!(hi, p);
    }

    #[test]
    fn bootstrap_ci_rejects_invalid_alpha() {
        let s: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        assert!(bootstrap_ci(&s, 0.99, 100, -0.1, 1).is_err());
        assert!(bootstrap_ci(&s, 0.99, 100, 1.0, 1).is_err());
        assert!(bootstrap_ci(&s, 0.99, 100, f64::NAN, 1).is_err());
    }

    #[test]
    fn bootstrap_ci_brackets_point_estimate() {
        let s: Vec<f64> = (1..=500).map(|i| i as f64).collect();
        let p = quantile(&s, 0.99).unwrap();
        let (lo, hi) = bootstrap_ci(&s, 0.99, 1000, 0.05, 42).unwrap();
        assert!(lo <= p, "lo={lo} > p={p}");
        assert!(hi >= p, "hi={hi} < p={p}");
        assert!(hi >= lo);
    }
}
