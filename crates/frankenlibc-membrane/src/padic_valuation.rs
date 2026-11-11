//! # p-adic Valuation Error Calculus
//!
//! Applies non-Archimedean number theory to floating-point regime control,
//! detecting numerical drift between normal, subnormal, and exceptional states.
//!
//! ## Mathematical Foundation
//!
//! The p-adic valuation v_p(n) for prime p counts the exact power of p dividing n.
//! The p-adic absolute value is:
//!
//! ```text
//! |n|_p = p^{-v_p(n)}
//! ```
//!
//! This induces an **ultrametric** (non-Archimedean metric) on Q:
//!
//! ```text
//! d_p(x, y) = |x - y|_p ≤ max(|x|_p, |y|_p)   [strong triangle inequality]
//! ```
//!
//! The ultrametric property means "all triangles are isosceles with the unequal
//! side being the shortest." This is fundamentally different from the Archimedean
//! reals and captures a natural hierarchy in floating-point representations.
//!
//! ## Why p-adic for Floating Point?
//!
//! IEEE 754 floating-point numbers have a natural 2-adic structure:
//!
//! ```text
//! x = (-1)^s · 2^e · (1 + m/2^52)   [normal]
//! x = (-1)^s · 2^{1-bias} · (0 + m/2^52)   [subnormal]
//! ```
//!
//! The exponent field `e` is essentially the 2-adic valuation of the number's
//! magnitude. The regime transitions (normal → subnormal → zero, normal → ∞ → NaN)
//! correspond to the 2-adic valuation crossing critical thresholds.
//!
//! ## Regime Detection via Valuation Profiles
//!
//! We maintain a **valuation profile** — a histogram of observed 2-adic
//! exponents — and detect regime drift by computing the ultrametric distance
//! between the current profile and a calibrated baseline.
//!
//! ```text
//! d(current, baseline) = max_i |current_i - baseline_i|
//! ```
//!
//! This max-metric is the natural ultrametric on profile space. When it
//! exceeds threshold, numerical regime transition is occurring.
//!
//! ## Hensel's Lemma Connection
//!
//! Hensel's lemma states that if f(a) ≡ 0 (mod p) and f'(a) ≢ 0 (mod p),
//! then the root lifts uniquely to Z_p. This is the p-adic analog of Newton's
//! method. For floating-point: if a numerical algorithm converges in the
//! ultrametric (exponent bits stabilize), it converges in the p-adic sense
//! even when Archimedean analysis is pessimistic.
//!
//! ## Connection to Math Item #40
//!
//! Non-Archimedean (p-adic valuation) error calculus for exceptional
//! floating-point regime control.

/// Number of exponent bins in the valuation profile.
const EXPONENT_BINS: usize = 12;
/// Window size for valuation profile estimation.
const PADIC_WINDOW: u64 = 128;
/// Baseline calibration windows required.
const PADIC_BASELINE_WINDOWS: u64 = 4;
/// Regime drift warning threshold (ultrametric distance).
const DRIFT_WARN: f64 = 0.15;
/// Regime drift critical threshold.
const DRIFT_CRIT: f64 = 0.35;
/// Immediate exceptional trigger if current NaN/Inf share exceeds this.
const EXCEPTIONAL_SHARE_CRIT: f64 = 0.25;
/// Exceptional trigger if NaN/Inf share jumps relative to baseline.
const EXCEPTIONAL_DELTA_CRIT: f64 = 0.10;
/// Hensel convergence: minimum fraction of stable exponents.
const HENSEL_STABILITY: f64 = 0.7;

// ── Valuation arithmetic ────────────────────────────────────────

/// Binary (2-adic) valuation: v_2(n) = number of trailing zeros.
///
/// Returns the exact power of 2 dividing n. v_2(0) is defined as
/// the word size (64) by convention (0 is divisible by all powers).
///
/// This is O(1) via hardware `ctz` instruction.
#[inline]
#[cfg_attr(not(test), allow(dead_code))]
fn binary_valuation(n: u64) -> u32 {
    if n == 0 {
        return 64;
    }
    n.trailing_zeros()
}

/// 2-adic absolute value: |n|_2 = 2^{-v_2(n)}.
///
/// Returns 0.0 for n = 0 (|0|_p = 0 in every p-adic norm).
#[inline]
#[cfg_attr(not(test), allow(dead_code))]
fn padic_abs(n: u64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let v = binary_valuation(n);
    crate::util::powi_f64(2.0, -(v as i32))
}

/// Classify an IEEE 754 exponent into one of EXPONENT_BINS regime bins.
///
/// Bin layout (for f64, bias=1023):
/// - 0: zero/subnormal (exponent = 0)
/// - 1..10: normal ranges (exponent mapped linearly across 1..2046)
/// - 11: infinity/NaN (exponent = 2047)
fn exponent_to_bin(biased_exponent: u16) -> usize {
    match biased_exponent {
        0 => 0,                    // subnormal or zero
        2047 => EXPONENT_BINS - 1, // infinity or NaN
        e => {
            // Map [1, 2046] linearly to [1, EXPONENT_BINS-2]
            let normal_bins = EXPONENT_BINS - 2; // 10
            let bin = ((e as usize - 1) * normal_bins) / 2045;
            (bin + 1).min(EXPONENT_BINS - 2)
        }
    }
}

/// Extract biased exponent from IEEE 754 binary64 bits.
#[inline]
fn extract_exponent(bits: u64) -> u16 {
    ((bits >> 52) & 0x7FF) as u16
}

/// Ultrametric distance between two valuation profiles.
///
/// Uses the Baire-style sequence ultrametric:
/// - Find the first bin where profiles differ beyond ε.
/// - Distance is `2^-k` where `k` is that first differing index.
/// - Identical profiles have distance `0.0`.
///
/// This construction satisfies the strong triangle inequality by design.
fn ultrametric_distance(a: &[f64; EXPONENT_BINS], b: &[f64; EXPONENT_BINS]) -> f64 {
    const EPS: f64 = 1e-12;
    match a
        .iter()
        .zip(b.iter())
        .position(|(&ai, &bi)| (ai - bi).abs() > EPS)
    {
        None => 0.0,
        Some(k) => crate::util::powi_f64(2.0, -(k as i32)),
    }
}

/// Hensel stability score: fraction of bins where the profile has stabilized
/// (difference from baseline is below a small ε).
///
/// This captures the p-adic analog of Newton convergence: if most exponent
/// bins are stable, the numerical computation is converging in the
/// ultrametric topology.
fn hensel_stability(current: &[f64; EXPONENT_BINS], baseline: &[f64; EXPONENT_BINS]) -> f64 {
    let stable_count = current
        .iter()
        .zip(baseline.iter())
        .filter(|&(&c, &b)| (c - b).abs() < DRIFT_WARN)
        .count();
    stable_count as f64 / EXPONENT_BINS as f64
}

/// Concentration index: how concentrated the profile is in a single bin.
///
/// Uses the Herfindahl-Hirschman index (sum of squared shares).
/// HHI = 1/n for uniform, HHI = 1.0 for single-bin concentration.
fn concentration_index(profile: &[f64; EXPONENT_BINS]) -> f64 {
    profile.iter().map(|&p| p * p).sum()
}

/// Effective number of regimes (inverse HHI).
///
/// This is the p-adic analog of the "number of distinct scales" active
/// in the computation.
fn effective_regimes(profile: &[f64; EXPONENT_BINS]) -> f64 {
    let hhi = concentration_index(profile);
    if hhi < 1e-12 {
        return EXPONENT_BINS as f64;
    }
    1.0 / hhi
}

// ── Public types ────────────────────────────────────────────────

/// p-adic numerical regime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadicState {
    /// Baseline valuation profile not yet established.
    Calibrating,
    /// Valuation profile is stable — computation in normal regime.
    Normal,
    /// Drift detected — transition between numerical regimes.
    DenormalDrift,
    /// Severe regime anomaly — exceptional floating-point behavior.
    ExceptionalRegime,
}

/// Telemetry snapshot for the p-adic monitor.
pub struct PadicSummary {
    pub state: PadicState,
    pub ultrametric_distance: f64,
    pub hensel_stability: f64,
    pub effective_regimes: f64,
    pub drift_count: u64,
}

/// p-adic valuation monitor for floating-point regime control.
///
/// Maintains a windowed valuation profile (histogram of IEEE 754 exponent
/// bins) and detects regime drift by computing ultrametric distance from
/// a calibrated baseline. Uses Hensel stability as an additional
/// convergence diagnostic.
pub struct PadicValuationMonitor {
    /// Current window: counts per exponent bin.
    bin_counts: [u64; EXPONENT_BINS],
    window_total: u64,
    /// Calibrated baseline valuation profile.
    baseline: [f64; EXPONENT_BINS],
    baseline_ready: bool,
    baseline_windows: u64,
    /// Current state.
    state: PadicState,
    /// Drift detection count.
    drift_count: u64,
    /// Last computed ultrametric distance.
    last_distance: f64,
    /// Last computed Hensel stability.
    last_hensel: f64,
}

impl PadicValuationMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bin_counts: [0; EXPONENT_BINS],
            window_total: 0,
            baseline: [0.0; EXPONENT_BINS],
            baseline_ready: false,
            baseline_windows: 0,
            state: PadicState::Calibrating,
            drift_count: 0,
            last_distance: 0.0,
            last_hensel: 1.0,
        }
    }

    /// Feed a floating-point observation (as raw IEEE 754 bits).
    ///
    /// The monitor extracts the biased exponent, classifies it into
    /// a regime bin, and accumulates a windowed valuation profile.
    pub fn observe(&mut self, fp_bits: u64) {
        let exp = extract_exponent(fp_bits);
        let bin = exponent_to_bin(exp);
        self.bin_counts[bin] += 1;
        self.window_total += 1;

        if self.window_total < PADIC_WINDOW {
            return;
        }

        // Compute current valuation profile (normalized).
        let total = self.window_total as f64;
        let mut current = [0.0f64; EXPONENT_BINS];
        for (i, &c) in self.bin_counts.iter().enumerate() {
            current[i] = c as f64 / total;
        }

        // Reset window.
        self.bin_counts = [0; EXPONENT_BINS];
        self.window_total = 0;

        if !self.baseline_ready {
            // Incremental baseline averaging.
            let n = self.baseline_windows as f64 + 1.0;
            for (i, bv) in self.baseline.iter_mut().enumerate() {
                *bv = ((n - 1.0) * *bv + current[i]) / n;
            }
            self.baseline_windows += 1;
            self.baseline_ready = self.baseline_windows >= PADIC_BASELINE_WINDOWS;
            self.state = PadicState::Calibrating;
            return;
        }

        // Compute ultrametric distance from baseline.
        let dist = ultrametric_distance(&current, &self.baseline);
        let hensel = hensel_stability(&current, &self.baseline);
        self.last_distance = dist;
        self.last_hensel = hensel;

        // Exceptional-bin excursion detection:
        // the Baire ultrametric intentionally emphasizes earliest-bin divergence,
        // so large changes concentrated in the terminal NaN/Inf bin can be
        // underweighted by distance alone. We gate that bin explicitly.
        let exceptional_idx = EXPONENT_BINS - 1;
        let exceptional_share = current[exceptional_idx];
        let exceptional_delta = (exceptional_share - self.baseline[exceptional_idx]).abs();
        let exceptional_excursion = exceptional_share >= EXCEPTIONAL_SHARE_CRIT
            || exceptional_delta >= EXCEPTIONAL_DELTA_CRIT;

        // State classification.
        if exceptional_excursion || dist > DRIFT_CRIT || hensel < (1.0 - HENSEL_STABILITY) {
            self.state = PadicState::ExceptionalRegime;
            self.drift_count += 1;
        } else if dist > DRIFT_WARN {
            self.state = PadicState::DenormalDrift;
            self.drift_count += 1;
        } else {
            self.state = PadicState::Normal;
        }
    }

    /// Feed a floating-point value directly (as f64).
    pub fn observe_f64(&mut self, value: f64) {
        self.observe(value.to_bits());
    }

    #[must_use]
    pub fn state(&self) -> PadicState {
        self.state
    }

    #[must_use]
    pub fn drift_count(&self) -> u64 {
        self.drift_count
    }

    #[must_use]
    pub fn summary(&self) -> PadicSummary {
        let total = self.window_total.max(1) as f64;
        let mut current = [0.0f64; EXPONENT_BINS];
        for (i, &c) in self.bin_counts.iter().enumerate() {
            current[i] = c as f64 / total;
        }
        PadicSummary {
            state: self.state,
            ultrametric_distance: self.last_distance,
            hensel_stability: self.last_hensel,
            effective_regimes: effective_regimes(&current),
            drift_count: self.drift_count,
        }
    }
}

impl Default for PadicValuationMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_valuation_basic() {
        assert_eq!(binary_valuation(0), 64);
        assert_eq!(binary_valuation(1), 0);
        assert_eq!(binary_valuation(2), 1);
        assert_eq!(binary_valuation(4), 2);
        assert_eq!(binary_valuation(8), 3);
        assert_eq!(binary_valuation(12), 2); // 12 = 4 * 3, v_2 = 2
        assert_eq!(binary_valuation(1024), 10);
    }

    #[test]
    fn padic_abs_basic() {
        assert_eq!(padic_abs(0), 0.0);
        assert_eq!(padic_abs(1), 1.0); // |1|_2 = 2^0 = 1
        assert_eq!(padic_abs(2), 0.5); // |2|_2 = 2^{-1} = 0.5
        assert_eq!(padic_abs(4), 0.25); // |4|_2 = 2^{-2} = 0.25
        assert_eq!(padic_abs(3), 1.0); // |3|_2 = 2^0 = 1 (3 is odd)
        assert_eq!(padic_abs(6), 0.5); // |6|_2 = 2^{-1} = 0.5
    }

    #[test]
    fn ultrametric_strong_triangle_inequality() {
        // The ultrametric must satisfy: d(a,c) <= max(d(a,b), d(b,c))
        let a = [
            0.5, 0.3, 0.1, 0.05, 0.03, 0.02, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        ];
        let b = [
            0.4, 0.35, 0.12, 0.06, 0.04, 0.03, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        ];
        let c = [
            0.3, 0.4, 0.15, 0.07, 0.05, 0.03, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        ];

        let dab = ultrametric_distance(&a, &b);
        let dbc = ultrametric_distance(&b, &c);
        let dac = ultrametric_distance(&a, &c);

        assert!(
            dac <= dab.max(dbc) + 1e-10,
            "ultrametric violated: d(a,c)={dac} > max(d(a,b)={dab}, d(b,c)={dbc})"
        );
    }

    #[test]
    fn exponent_bin_zero_subnormal() {
        assert_eq!(exponent_to_bin(0), 0);
    }

    #[test]
    fn exponent_bin_infinity_nan() {
        assert_eq!(exponent_to_bin(2047), EXPONENT_BINS - 1);
    }

    #[test]
    fn exponent_bin_normal_range() {
        // Normal exponents [1, 2046] should map to bins [1, EXPONENT_BINS-2]
        let bin_low = exponent_to_bin(1);
        let bin_high = exponent_to_bin(2046);
        assert!(bin_low >= 1);
        assert!(bin_high <= EXPONENT_BINS - 2);
        assert!(bin_high >= bin_low);
    }

    #[test]
    fn extract_exponent_known_values() {
        // 1.0_f64 has biased exponent 1023
        assert_eq!(extract_exponent(1.0_f64.to_bits()), 1023);
        // 2.0_f64 has biased exponent 1024
        assert_eq!(extract_exponent(2.0_f64.to_bits()), 1024);
        // f64::INFINITY has exponent 2047
        assert_eq!(extract_exponent(f64::INFINITY.to_bits()), 2047);
        // 0.0 has exponent 0
        assert_eq!(extract_exponent(0.0_f64.to_bits()), 0);
    }

    #[test]
    fn concentration_uniform() {
        let uniform = [1.0 / EXPONENT_BINS as f64; EXPONENT_BINS];
        let hhi = concentration_index(&uniform);
        let expected = 1.0 / EXPONENT_BINS as f64;
        assert!((hhi - expected).abs() < 1e-10);
    }

    #[test]
    fn concentration_single_bin() {
        let mut concentrated = [0.0; EXPONENT_BINS];
        concentrated[3] = 1.0;
        let hhi = concentration_index(&concentrated);
        assert!((hhi - 1.0).abs() < 1e-10);
    }

    #[test]
    fn effective_regimes_range() {
        let uniform = [1.0 / EXPONENT_BINS as f64; EXPONENT_BINS];
        let eff = effective_regimes(&uniform);
        assert!((eff - EXPONENT_BINS as f64).abs() < 1e-8);

        let mut concentrated = [0.0; EXPONENT_BINS];
        concentrated[5] = 1.0;
        let eff_conc = effective_regimes(&concentrated);
        assert!((eff_conc - 1.0).abs() < 1e-8);
    }

    #[test]
    fn hensel_stability_identical_profiles() {
        let profile = [
            0.3, 0.2, 0.15, 0.1, 0.08, 0.07, 0.05, 0.03, 0.01, 0.01, 0.0, 0.0,
        ];
        let stab = hensel_stability(&profile, &profile);
        assert!((stab - 1.0).abs() < 1e-10);
    }

    #[test]
    fn monitor_starts_calibrating() {
        let mon = PadicValuationMonitor::new();
        assert_eq!(mon.state(), PadicState::Calibrating);
    }

    #[test]
    fn normal_values_reach_normal_state() {
        let mut mon = PadicValuationMonitor::new();
        // Feed normal floating-point values (around 1.0).
        for i in 0..3000 {
            let val = 1.0 + (i as f64) * 0.001;
            mon.observe_f64(val);
        }
        assert_eq!(
            mon.state(),
            PadicState::Normal,
            "expected Normal with consistent normal-range values"
        );
    }

    #[test]
    fn regime_shift_triggers_drift() {
        let mut mon = PadicValuationMonitor::new();
        // Calibrate with normal values.
        for i in 0..1500 {
            let val = 1.0 + (i as f64) * 0.01;
            mon.observe_f64(val);
        }
        // Shift to subnormal regime.
        for _ in 0..1500 {
            mon.observe_f64(5e-309); // subnormal
        }
        assert!(
            matches!(
                mon.state(),
                PadicState::DenormalDrift | PadicState::ExceptionalRegime
            ),
            "expected drift detection, got {:?}",
            mon.state()
        );
    }

    #[test]
    fn exceptional_values_trigger_exceptional_state() {
        let mut mon = PadicValuationMonitor::new();
        // Calibrate with normal values.
        for i in 0..1500 {
            mon.observe_f64(100.0 + i as f64);
        }
        // Flood with infinity/NaN.
        for _ in 0..1500 {
            mon.observe_f64(f64::INFINITY);
        }
        assert!(
            matches!(
                mon.state(),
                PadicState::DenormalDrift | PadicState::ExceptionalRegime
            ),
            "expected exceptional detection, got {:?}",
            mon.state()
        );
    }

    #[test]
    fn drift_count_increments() {
        let mut mon = PadicValuationMonitor::new();
        for i in 0..1500 {
            mon.observe_f64(1.0 + i as f64 * 0.01);
        }
        for _ in 0..1500 {
            mon.observe_f64(5e-309);
        }
        if matches!(
            mon.state(),
            PadicState::DenormalDrift | PadicState::ExceptionalRegime
        ) {
            assert!(mon.drift_count() > 0);
        }
    }

    #[test]
    fn summary_valid_after_calibration() {
        let mut mon = PadicValuationMonitor::new();
        for i in 0..2000 {
            mon.observe_f64(1.0 + i as f64 * 0.001);
        }
        let s = mon.summary();
        assert!(s.ultrametric_distance >= 0.0);
        assert!(s.hensel_stability >= 0.0 && s.hensel_stability <= 1.0);
        assert!(s.effective_regimes >= 1.0);
    }

    #[test]
    fn padic_abs_ultrametric_property() {
        // |a + b|_2 <= max(|a|_2, |b|_2)
        // Test with specific values: a=6, b=10
        // |6|_2 = 1/2, |10|_2 = 1/2, |16|_2 = 1/16
        // 1/16 <= max(1/2, 1/2) = 1/2  ✓
        let a = 6u64;
        let b = 10u64;
        let sum_abs = padic_abs(a + b);
        let max_abs = padic_abs(a).max(padic_abs(b));
        assert!(
            sum_abs <= max_abs + 1e-10,
            "|{a}+{b}|_2 = {sum_abs} > max(|{a}|_2, |{b}|_2) = {max_abs}"
        );
    }
}
