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

/// Strict-vs-hardened p99 delta computed from two [`TailStats`]
/// instances (bd-hp41p).
///
/// Used by the bd-juvqm.12 timing side-channel budget gate to
/// classify whether an observed p99 delta is (a) within budget, (b)
/// over budget, (c) just noise (CI overlap), or (d) amplified
/// beyond the per-path threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct P99Delta {
    /// Absolute value of `(strict.p99 - hardened.p99)` in
    /// nanoseconds. Always non-negative — sign is irrelevant for
    /// budget gating.
    pub p99_delta_ns: f64,
    /// True iff the bootstrap p99 CIs of the two TailStats do NOT
    /// overlap. Disjoint CIs mean the delta is statistically
    /// distinguishable from noise.
    pub ci_disjoint: bool,
    /// `max(strict.p99, hardened.p99) / min(strict.p99, hardened.p99)`.
    /// If the smaller p99 is 0, the ratio is `f64::INFINITY`.
    pub amplification_ratio: f64,
    /// True iff both TailStats have at least
    /// [`MIN_SAMPLES_FOR_P99`] samples.
    pub sufficient_samples: bool,
}

/// Compute a [`P99Delta`] from two [`TailStats`] instances.
pub fn compute_p99_delta(strict: &TailStats, hardened: &TailStats) -> P99Delta {
    let p99_delta_ns = (strict.p99 - hardened.p99).abs();
    let ci_disjoint =
        strict.p99_ci_high < hardened.p99_ci_low || hardened.p99_ci_high < strict.p99_ci_low;
    let max = strict.p99.max(hardened.p99);
    let min = strict.p99.min(hardened.p99);
    let amplification_ratio = if min > 0.0 {
        max / min
    } else if max > 0.0 {
        f64::INFINITY
    } else {
        // Both p99 values are 0 — ratio is undefined; treat as 1 (no amplification).
        1.0
    };
    let sufficient_samples = strict.sufficient_for_p99 && hardened.sufficient_for_p99;
    P99Delta {
        p99_delta_ns,
        ci_disjoint,
        amplification_ratio,
        sufficient_samples,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P99DeltaError {
    OverBudget,
    AmplificationAboveThreshold,
    InsufficientSamples,
    /// CI intervals overlap (delta is noise) AND the apparent
    /// p99_delta_ns exceeds budget. The contract distinguishes this
    /// from a real over-budget event because it requires more
    /// samples to disambiguate.
    CiIndistinguishableButOverBudget,
}

impl core::fmt::Display for P99DeltaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            P99DeltaError::OverBudget => f.write_str("p99_delta_ns exceeds allowed_budget_ns"),
            P99DeltaError::AmplificationAboveThreshold => {
                f.write_str("amplification_ratio exceeds threshold")
            }
            P99DeltaError::InsufficientSamples => {
                f.write_str("insufficient samples for p99 (need >= 100)")
            }
            P99DeltaError::CiIndistinguishableButOverBudget => f.write_str(
                "p99 CIs overlap (delta is noise) but observed delta exceeds budget — collect more samples",
            ),
        }
    }
}

impl std::error::Error for P99DeltaError {}

/// Validate a [`P99Delta`] against a path's budget. Fails closed
/// when the delta is over budget, amplification is excessive,
/// samples are insufficient, or the apparent over-budget is just
/// noise (CI overlap).
pub fn validate_p99_delta_against_budget(
    delta: &P99Delta,
    allowed_budget_ns: u64,
    amplification_threshold: f64,
) -> Result<(), P99DeltaError> {
    if !delta.sufficient_samples {
        return Err(P99DeltaError::InsufficientSamples);
    }
    let over_budget = delta.p99_delta_ns > allowed_budget_ns as f64;
    if over_budget && !delta.ci_disjoint {
        return Err(P99DeltaError::CiIndistinguishableButOverBudget);
    }
    if delta.amplification_ratio > amplification_threshold {
        return Err(P99DeltaError::AmplificationAboveThreshold);
    }
    if over_budget {
        return Err(P99DeltaError::OverBudget);
    }
    Ok(())
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
    fn quantile_is_monotone() -> Result<(), TailStatsError> {
        // Random-looking but deterministic sample.
        let mut s: Vec<f64> = (1..=200).map(|i| i as f64).collect();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let qs = [0.0_f64, 0.1, 0.25, 0.5, 0.9, 0.95, 0.99, 0.999, 1.0];
        let mut prev = quantile(&s, qs[0])?;
        for &q in &qs[1..] {
            let v = quantile(&s, q)?;
            assert!(v >= prev, "quantile non-monotone: q={q} v={v} prev={prev}");
            prev = v;
        }
        Ok(())
    }

    #[test]
    fn quantile_uniform_1_to_1000() -> Result<(), TailStatsError> {
        let s: Vec<f64> = (1..=1000).map(|i| i as f64).collect();
        // Type-7 interpolation on 1..=1000:
        //   q*999 + 1 with linear interp between integer indices.
        let p50 = quantile(&s, 0.5)?;
        let p95 = quantile(&s, 0.95)?;
        let p99 = quantile(&s, 0.99)?;
        let p999 = quantile(&s, 0.999)?;
        assert!(approx_eq(p50, 500.5, 0.001), "p50={p50}");
        assert!(approx_eq(p95, 950.05, 0.05), "p95={p95}");
        assert!(approx_eq(p99, 990.01, 0.05), "p99={p99}");
        assert!(approx_eq(p999, 999.001, 0.05), "p999={p999}");
        Ok(())
    }

    #[test]
    fn compute_reports_sufficiency_correctly() -> Result<(), TailStatsError> {
        let small: Vec<f64> = (1..=50).map(|i| i as f64).collect();
        let medium: Vec<f64> = (1..=500).map(|i| i as f64).collect();
        let large: Vec<f64> = (1..=2000).map(|i| i as f64).collect();

        let s50 = compute(&small, 1)?;
        let s500 = compute(&medium, 1)?;
        let s2000 = compute(&large, 1)?;

        assert!(!s50.sufficient_for_p99);
        assert!(!s50.sufficient_for_p999);
        assert!(s500.sufficient_for_p99);
        assert!(!s500.sufficient_for_p999);
        assert!(s2000.sufficient_for_p99);
        assert!(s2000.sufficient_for_p999);
        Ok(())
    }

    #[test]
    fn compute_quantiles_are_monotone() -> Result<(), TailStatsError> {
        let s: Vec<f64> = (1..=300).map(|i| i as f64).collect();
        let r = compute(&s, 1234)?;
        assert!(r.p50 <= r.p95);
        assert!(r.p95 <= r.p99);
        assert!(r.p99 <= r.p999);
        assert!(r.p99_ci_low <= r.p99);
        assert!(r.p99 <= r.p99_ci_high);
        Ok(())
    }

    #[test]
    fn deterministic_seed_yields_identical_output() -> Result<(), TailStatsError> {
        let s: Vec<f64> = (1..=300).map(|i| i as f64 * 1.7).collect();
        let a = compute(&s, 0xdead_beef)?;
        let b = compute(&s, 0xdead_beef)?;
        assert_eq!(a, b);
        // Different seeds should perturb at least one deliberately
        // irregular bootstrap interval; checking a small seed panel
        // avoids relying on a single pair that can legitimately land
        // on identical empirical bounds.
        let irregular: Vec<f64> = (1..=37).map(|i| (i * i + 3 * i) as f64).collect();
        let baseline = bootstrap_ci(&irregular, 0.63, 25, 0.2, 0xdead_beef)?;
        let varied = (1_u64..=16).any(|seed| {
            let Ok(candidate) = bootstrap_ci(&irregular, 0.63, 25, 0.2, seed) else {
                return false;
            };
            !approx_eq(candidate.0, baseline.0, 1e-9) || !approx_eq(candidate.1, baseline.1, 1e-9)
        });
        assert!(varied, "bootstrap CI did not vary across seed panel");
        Ok(())
    }

    #[test]
    fn overloaded_host_warning_triggers_on_high_cv() -> Result<(), TailStatsError> {
        // Mostly steady samples plus one large outlier produce a
        // coefficient of variation far above the overload threshold.
        let mut s: Vec<f64> = vec![1.0; 199];
        s.push(10_000.0);
        let r = compute(&s, 1)?;
        assert!(
            r.overloaded_host,
            "expected high-CV sample to trip overloaded_host; cv was below threshold (n={}, p50={}, p99={})",
            r.n, r.p50, r.p99
        );
        Ok(())
    }

    #[test]
    fn overloaded_host_warning_quiet_on_steady_input() -> Result<(), TailStatsError> {
        let s: Vec<f64> = (0..200).map(|_| 100.0).collect();
        let r = compute(&s, 1)?;
        assert!(!r.overloaded_host);
        Ok(())
    }

    #[test]
    fn bootstrap_ci_handles_tiny_samples_gracefully() -> Result<(), TailStatsError> {
        let s = [10.0, 20.0];
        let (lo, hi) = bootstrap_ci(&s, 0.99, 1000, 0.05, 7)?;
        let p = quantile(&s, 0.99)?;
        assert_eq!(lo, p);
        assert_eq!(hi, p);
        Ok(())
    }

    #[test]
    fn bootstrap_ci_rejects_invalid_alpha() {
        let s: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        assert!(bootstrap_ci(&s, 0.99, 100, -0.1, 1).is_err());
        assert!(bootstrap_ci(&s, 0.99, 100, 1.0, 1).is_err());
        assert!(bootstrap_ci(&s, 0.99, 100, f64::NAN, 1).is_err());
    }

    #[test]
    fn bootstrap_ci_brackets_point_estimate() -> Result<(), TailStatsError> {
        let s: Vec<f64> = (1..=500).map(|i| i as f64).collect();
        let p = quantile(&s, 0.99)?;
        let (lo, hi) = bootstrap_ci(&s, 0.99, 1000, 0.05, 42)?;
        assert!(lo <= p, "lo={lo} > p={p}");
        assert!(hi >= p, "hi={hi} < p={p}");
        assert!(hi >= lo);
        Ok(())
    }

    // ── P99Delta tests (bd-hp41p) ────────────────────────────────────

    fn synth_stats(p99: f64, ci_low: f64, ci_high: f64, n: usize) -> TailStats {
        TailStats {
            n,
            p50: p99 * 0.5,
            p95: p99 * 0.9,
            p99,
            p999: p99 * 1.1,
            p99_ci_low: ci_low,
            p99_ci_high: ci_high,
            sufficient_for_p99: n >= MIN_SAMPLES_FOR_P99,
            sufficient_for_p999: n >= MIN_SAMPLES_FOR_P999,
            overloaded_host: false,
            seed: 0,
            bootstrap_iters: DEFAULT_BOOTSTRAP_ITERS,
        }
    }

    #[test]
    fn p99_delta_handles_strict_faster_than_hardened() {
        let strict = synth_stats(100.0, 95.0, 105.0, 1000);
        let hardened = synth_stats(250.0, 245.0, 255.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        assert_eq!(d.p99_delta_ns, 150.0);
        assert!(d.ci_disjoint, "CIs [95,105] and [245,255] must be disjoint");
        assert!(d.sufficient_samples);
        assert!((d.amplification_ratio - 2.5).abs() < 1e-9);
    }

    #[test]
    fn p99_delta_handles_hardened_faster_than_strict_by_taking_abs() {
        let strict = synth_stats(300.0, 290.0, 310.0, 1000);
        let hardened = synth_stats(100.0, 95.0, 105.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        assert_eq!(d.p99_delta_ns, 200.0, "abs delta");
    }

    #[test]
    fn p99_delta_ci_overlap_is_detected_as_indistinguishable() {
        let strict = synth_stats(100.0, 90.0, 110.0, 500);
        let hardened = synth_stats(150.0, 95.0, 200.0, 500);
        let d = compute_p99_delta(&strict, &hardened);
        // strict CI [90,110] overlaps hardened CI [95,200] at [95,110].
        assert!(!d.ci_disjoint);
    }

    #[test]
    fn p99_delta_amplification_ratio_handles_zero() {
        let strict = synth_stats(0.0, 0.0, 0.0, 1000);
        let hardened = synth_stats(100.0, 95.0, 105.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        assert!(d.amplification_ratio.is_infinite());
    }

    #[test]
    fn validate_within_budget_passes() {
        let strict = synth_stats(100.0, 95.0, 105.0, 1000);
        let hardened = synth_stats(250.0, 245.0, 255.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        // 150ns delta, 200ns budget → within budget. ratio=2.5 < 3.0.
        assert!(validate_p99_delta_against_budget(&d, 200, 3.0).is_ok());
    }

    #[test]
    fn validate_rejects_over_budget_with_disjoint_ci() {
        let strict = synth_stats(100.0, 95.0, 105.0, 1000);
        let hardened = synth_stats(400.0, 395.0, 405.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        // 300ns delta, 200ns budget → over budget. CIs disjoint.
        // ratio=4.0 > 3.0 → AmplificationAboveThreshold fires first.
        assert!(matches!(
            validate_p99_delta_against_budget(&d, 200, 3.0),
            Err(P99DeltaError::AmplificationAboveThreshold)
        ));
    }

    #[test]
    fn validate_rejects_over_budget_when_amplification_within_threshold() {
        let strict = synth_stats(100.0, 95.0, 105.0, 1000);
        let hardened = synth_stats(250.0, 245.0, 255.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        // 150ns delta, 100ns budget → over budget. ratio=2.5 < 3.0.
        assert!(matches!(
            validate_p99_delta_against_budget(&d, 100, 3.0),
            Err(P99DeltaError::OverBudget)
        ));
    }

    #[test]
    fn validate_rejects_amplification_above_threshold() {
        let strict = synth_stats(100.0, 95.0, 105.0, 1000);
        let hardened = synth_stats(500.0, 495.0, 505.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        // ratio=5.0 > 3.0.
        assert!(matches!(
            validate_p99_delta_against_budget(&d, 1_000_000, 3.0),
            Err(P99DeltaError::AmplificationAboveThreshold)
        ));
    }

    #[test]
    fn validate_rejects_insufficient_samples() {
        let strict = synth_stats(100.0, 95.0, 105.0, 50);
        let hardened = synth_stats(150.0, 145.0, 155.0, 50);
        let d = compute_p99_delta(&strict, &hardened);
        assert!(matches!(
            validate_p99_delta_against_budget(&d, 200, 3.0),
            Err(P99DeltaError::InsufficientSamples)
        ));
    }

    #[test]
    fn validate_rejects_ci_indistinguishable_but_over_budget() {
        let strict = synth_stats(100.0, 50.0, 200.0, 1000);
        let hardened = synth_stats(150.0, 80.0, 220.0, 1000);
        let d = compute_p99_delta(&strict, &hardened);
        // delta=50, budget=10 → over budget. CIs overlap heavily.
        assert!(!d.ci_disjoint);
        assert!(matches!(
            validate_p99_delta_against_budget(&d, 10, 3.0),
            Err(P99DeltaError::CiIndistinguishableButOverBudget)
        ));
    }
}
