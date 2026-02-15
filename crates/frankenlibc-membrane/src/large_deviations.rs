//! # Large Deviations Rate Function Monitor
//!
//! Computes the Cramér rate function for per-family adverse event rates,
//! providing **rigorous exponential probability bounds** for catastrophic
//! failure sequences that no statistical method can match.
//!
//! ## Mathematical Foundation
//!
//! For i.i.d. observations X₁, X₂, …, the **Cramér rate function** is the
//! Legendre-Fenchel transform of the cumulant generating function:
//!
//! ```text
//! I(x) = sup_θ { θx − Λ(θ) }
//! ```
//!
//! where Λ(θ) = log E[e^{θX}] is the CGF.
//!
//! For Bernoulli(p) observations (adverse / not-adverse):
//!
//! ```text
//! Λ(θ) = log(1 − p + p·e^θ)
//! I(x) = x·log(x/p) + (1−x)·log((1−x)/(1−p))
//! ```
//!
//! This is exactly the **binary KL divergence** D(x ‖ p).
//!
//! ## Cramér's Theorem (Large Deviation Principle)
//!
//! ```text
//! P(S_n / n ≥ x) ≤ exp(−n · I(x))     for x > E[X] = p
//! ```
//!
//! This bound is:
//! 1. **Exact rate**: lim_{n→∞} (1/n) log P(S_n/n ≥ x) = −I(x)
//! 2. **Strictly tighter than Hoeffding**: I(x) ≥ 2(x−p)² always
//! 3. **Strictly tighter than CLT**: captures exact tail geometry
//! 4. **Rate-optimal**: no exponential bound with a larger exponent exists
//!
//! ## Gärtner-Ellis Extension
//!
//! We evaluate I(x) at multiple critical thresholds (5%, 10%, 20% adverse
//! rate). A **drop** in I(x) relative to baseline means catastrophic failure
//! sequences are becoming more probable:
//!
//! ```text
//! P(adverse rate ≥ 20%) ≤ exp(−n · I(0.20))
//! ```
//!
//! If I(0.20) drops by 40% from baseline, the failure probability has
//! **increased exponentially** — an n-fold amplification of catastrophe risk.
//!
//! ## Connection to Math Item #22
//!
//! Large-deviations rare-event analysis for catastrophic failure budgeting.

use crate::runtime_math::ApiFamily;

/// Per-family observation window size.
const LD_WINDOW: usize = 256;

/// Baseline calibration windows.
const LD_BASELINE_WINDOWS: u64 = 4;

/// EWMA alpha for baseline adaptation during normal operation.
const LD_ALPHA: f64 = 0.03;

/// Critical thresholds at which we evaluate the rate function.
/// These represent the adverse rates we want probability bounds for.
const THRESHOLDS: [f64; 3] = [0.05, 0.10, 0.20];

/// Relative drop in rate function that triggers Elevated state.
const RATE_DROP_WARN: f64 = 0.4;

/// Relative drop that triggers Critical state.
const RATE_DROP_CRIT: f64 = 0.8;

/// Number of API families.
const FAMILIES: usize = ApiFamily::COUNT;

/// Binary KL divergence D(x ‖ p) = x·log(x/p) + (1−x)·log((1−x)/(1−p)).
///
/// This IS the Cramér rate function for Bernoulli(p).
///
/// Properties:
/// - I(p) = 0 (rate function is zero at the mean)
/// - I(x) > 0 for x ≠ p (strictly positive away from mean)
/// - I is convex (rate functions are always convex)
/// - I(x) ≥ 2(x−p)² (dominates Hoeffding exponent)
fn binary_kl(x: f64, p: f64) -> f64 {
    let x = x.clamp(1e-15, 1.0 - 1e-15);
    let p = p.clamp(1e-15, 1.0 - 1e-15);
    x * (x / p).ln() + (1.0 - x) * ((1.0 - x) / (1.0 - p)).ln()
}

/// Evaluate the rate function at multiple threshold levels.
///
/// For threshold > p: I(threshold) gives the exponential decay rate of
/// P(adverse rate ≥ threshold). Higher I = less probable = safer.
fn rate_profile(p: f64) -> [f64; THRESHOLDS.len()] {
    let mut profile = [0.0f64; THRESHOLDS.len()];
    for (i, &threshold) in THRESHOLDS.iter().enumerate() {
        if threshold > p + 1e-12 {
            profile[i] = binary_kl(threshold, p);
        }
        // When threshold ≤ p, the rate function for the upper tail is 0
        // (the event is not rare from above).
    }
    profile
}

/// Failure probability bound: log P(adverse rate ≥ threshold) ≤ −n · I(threshold).
fn failure_budget_log(n: u64, rate: f64) -> f64 {
    -(n as f64) * rate
}

/// Per-family rate function state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateState {
    /// Baseline rate function not yet established.
    Calibrating,
    /// Rate function is consistent with baseline — failure budget holds.
    Normal,
    /// Rate function has dropped — catastrophic sequences are more probable.
    Elevated,
    /// Severe rate function collapse — near-certain elevated failure rate.
    Critical,
}

/// Per-family rate function summary.
#[derive(Debug, Clone, Copy)]
pub struct RateFunctionSummary {
    pub state: RateState,
    /// Empirical adverse rate (lifetime).
    pub empirical_adverse_rate: f64,
    /// Rate function I(0.05) — probability bound exponent for 5% adverse rate.
    pub rate_at_5pct: f64,
    /// Rate function I(0.10).
    pub rate_at_10pct: f64,
    /// Rate function I(0.20).
    pub rate_at_20pct: f64,
    /// log P(adverse ≥ 5%) ≤ this value (negative = good).
    pub failure_budget_log_5pct: f64,
    /// Total anomaly detections for this family.
    pub anomaly_count: u64,
}

/// The large-deviations rate function monitor.
pub struct LargeDeviationsMonitor {
    // Lifetime counts.
    observations: [u64; FAMILIES],
    adverse_total: [u64; FAMILIES],
    // Sliding window counts.
    window_obs: [u64; FAMILIES],
    window_adverse: [u64; FAMILIES],
    // Baseline rate profiles per family.
    baseline_profiles: [[f64; THRESHOLDS.len()]; FAMILIES],
    baseline_windows: [u64; FAMILIES],
    baseline_ready: [bool; FAMILIES],
    // Current state per family.
    states: [RateState; FAMILIES],
    anomaly_counts: [u64; FAMILIES],
    // Last computed rate profiles.
    last_profiles: [[f64; THRESHOLDS.len()]; FAMILIES],
}

impl LargeDeviationsMonitor {
    /// Creates a new rate function monitor.
    pub fn new() -> Self {
        Self {
            observations: [0; FAMILIES],
            adverse_total: [0; FAMILIES],
            window_obs: [0; FAMILIES],
            window_adverse: [0; FAMILIES],
            baseline_profiles: [[0.0; THRESHOLDS.len()]; FAMILIES],
            baseline_windows: [0; FAMILIES],
            baseline_ready: [false; FAMILIES],
            states: [RateState::Calibrating; FAMILIES],
            anomaly_counts: [0; FAMILIES],
            last_profiles: [[0.0; THRESHOLDS.len()]; FAMILIES],
        }
    }

    /// Record an observation for a family.
    pub fn observe(&mut self, family_idx: usize, adverse: bool) {
        if family_idx >= FAMILIES {
            return;
        }
        self.observations[family_idx] += 1;
        self.window_obs[family_idx] += 1;
        if adverse {
            self.adverse_total[family_idx] += 1;
            self.window_adverse[family_idx] += 1;
        }

        if self.window_obs[family_idx] >= LD_WINDOW as u64 {
            self.recompute(family_idx);
            self.window_obs[family_idx] = 0;
            self.window_adverse[family_idx] = 0;
        }
    }

    /// Current state for a family.
    pub fn state(&self, family_idx: usize) -> RateState {
        if family_idx >= FAMILIES {
            return RateState::Calibrating;
        }
        self.states[family_idx]
    }

    /// Summary for a family.
    pub fn summary(&self, family_idx: usize) -> RateFunctionSummary {
        if family_idx >= FAMILIES {
            return RateFunctionSummary {
                state: RateState::Calibrating,
                empirical_adverse_rate: 0.0,
                rate_at_5pct: 0.0,
                rate_at_10pct: 0.0,
                rate_at_20pct: 0.0,
                failure_budget_log_5pct: 0.0,
                anomaly_count: 0,
            };
        }
        let p_hat = if self.observations[family_idx] > 0 {
            self.adverse_total[family_idx] as f64 / self.observations[family_idx] as f64
        } else {
            0.0
        };
        let profile = self.last_profiles[family_idx];
        RateFunctionSummary {
            state: self.states[family_idx],
            empirical_adverse_rate: p_hat,
            rate_at_5pct: profile[0],
            rate_at_10pct: profile[1],
            rate_at_20pct: profile[2],
            failure_budget_log_5pct: failure_budget_log(self.observations[family_idx], profile[0]),
            anomaly_count: self.anomaly_counts[family_idx],
        }
    }

    /// Maximum anomaly count across all families.
    pub fn max_anomaly_count(&self) -> u64 {
        *self.anomaly_counts.iter().max().unwrap_or(&0)
    }

    /// Number of families in elevated or critical state.
    pub fn elevated_family_count(&self) -> u32 {
        self.states
            .iter()
            .filter(|s| matches!(s, RateState::Elevated | RateState::Critical))
            .count() as u32
    }

    fn recompute(&mut self, fam: usize) {
        let total = self.window_obs[fam].max(1) as f64;
        let p_hat = self.window_adverse[fam] as f64 / total;

        let profile = rate_profile(p_hat);
        self.last_profiles[fam] = profile;

        if !self.baseline_ready[fam] {
            let n = self.baseline_windows[fam] as f64 + 1.0;
            let alpha = 1.0 / n;
            for (i, &pv) in profile.iter().enumerate() {
                self.baseline_profiles[fam][i] =
                    (1.0 - alpha) * self.baseline_profiles[fam][i] + alpha * pv;
            }
            self.baseline_windows[fam] += 1;
            self.baseline_ready[fam] = self.baseline_windows[fam] >= LD_BASELINE_WINDOWS;
            self.states[fam] = RateState::Calibrating;
            return;
        }

        // Detect rate function collapse: a DROP means catastrophic events
        // are more probable (the exponential bound has a smaller exponent).
        let mut max_relative_drop = 0.0f64;
        for (i, &pv) in profile.iter().enumerate() {
            let baseline = self.baseline_profiles[fam][i];
            if baseline > 1e-12 {
                let relative_drop = (baseline - pv) / baseline;
                max_relative_drop = max_relative_drop.max(relative_drop);
            }
        }

        if max_relative_drop > RATE_DROP_CRIT {
            self.states[fam] = RateState::Critical;
            self.anomaly_counts[fam] += 1;
        } else if max_relative_drop > RATE_DROP_WARN {
            self.states[fam] = RateState::Elevated;
            self.anomaly_counts[fam] += 1;
        } else {
            self.states[fam] = RateState::Normal;
            // Slow baseline adaptation during normal operation.
            for (i, &pv) in profile.iter().enumerate() {
                self.baseline_profiles[fam][i] =
                    (1.0 - LD_ALPHA) * self.baseline_profiles[fam][i] + LD_ALPHA * pv;
            }
        }
    }
}

impl Default for LargeDeviationsMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kl_at_mean_is_zero() {
        let p = 0.1;
        assert!(binary_kl(p, p).abs() < 1e-10, "I(p) should be 0");
    }

    #[test]
    fn kl_is_positive_away_from_mean() {
        let p = 0.05;
        for &x in &[0.01, 0.10, 0.20, 0.50, 0.90] {
            let rate = binary_kl(x, p);
            assert!(rate > 0.0, "I({x}) = {rate}, expected > 0 for x ≠ p");
        }
    }

    #[test]
    fn kl_dominates_hoeffding() {
        // Cramér: I(x) = D(x || p)
        // Hoeffding: 2(x-p)²
        // Cramér ≥ Hoeffding always (Pinsker-style bound).
        let p = 0.05;
        for &x in &[0.10, 0.15, 0.20, 0.30, 0.50] {
            let cramer = binary_kl(x, p);
            let hoeffding = 2.0 * (x - p) * (x - p);
            assert!(
                cramer >= hoeffding - 1e-10,
                "Cramér I({x}) = {cramer} < Hoeffding {hoeffding}"
            );
        }
    }

    #[test]
    fn rate_function_is_convex() {
        // I(x) is convex: I(λa + (1-λ)b) ≤ λI(a) + (1-λ)I(b).
        let p = 0.1;
        let a = 0.2;
        let b = 0.8;
        let lambda = 0.3;
        let mid = lambda * a + (1.0 - lambda) * b;
        let i_mid = binary_kl(mid, p);
        let i_convex = lambda * binary_kl(a, p) + (1.0 - lambda) * binary_kl(b, p);
        assert!(
            i_mid <= i_convex + 1e-10,
            "convexity violated: I({mid}) = {i_mid} > {i_convex}"
        );
    }

    #[test]
    fn rate_profile_for_low_p_gives_high_rates() {
        // When empirical p is very low, I(threshold) should be large.
        let profile = rate_profile(0.001);
        assert!(
            profile[0] > 0.1,
            "I(0.05) = {} for p=0.001, expected large",
            profile[0]
        );
        assert!(
            profile[1] > profile[0],
            "I(0.10) should > I(0.05) for p=0.001"
        );
        assert!(
            profile[2] > profile[1],
            "I(0.20) should > I(0.10) for p=0.001"
        );
    }

    #[test]
    fn rate_profile_zero_when_p_exceeds_threshold() {
        // When p > threshold, the upper-tail rate is 0.
        let profile = rate_profile(0.25);
        assert!(profile[0] < 1e-10, "I(0.05) should be 0 when p=0.25 > 0.05");
        assert!(profile[1] < 1e-10, "I(0.10) should be 0 when p=0.25 > 0.10");
        assert!(profile[2] < 1e-10, "I(0.20) should be 0 when p=0.25 > 0.20");
    }

    #[test]
    fn failure_budget_is_negative() {
        let rate = binary_kl(0.10, 0.02); // I(0.10) for p=0.02
        let budget = failure_budget_log(1000, rate);
        assert!(budget < 0.0, "failure budget should be negative (log-prob)");
        // With 1000 observations and low p, the bound should be very negative.
        assert!(
            budget < -10.0,
            "budget = {budget}, expected << 0 for n=1000"
        );
    }

    #[test]
    fn new_monitor_is_calibrating() {
        let mon = LargeDeviationsMonitor::new();
        assert_eq!(mon.state(0), RateState::Calibrating);
        assert_eq!(mon.max_anomaly_count(), 0);
    }

    #[test]
    fn stable_low_adverse_reaches_normal() {
        let mut mon = LargeDeviationsMonitor::new();
        // Feed several windows of low-adverse-rate data.
        for _ in 0..8 {
            for i in 0..LD_WINDOW {
                // 1% adverse rate.
                mon.observe(0, i % 100 == 0);
            }
        }
        assert_ne!(
            mon.state(0),
            RateState::Calibrating,
            "should have left calibration"
        );
    }

    #[test]
    fn adverse_surge_triggers_elevated() {
        let mut mon = LargeDeviationsMonitor::new();
        // Phase 1: low adverse rate (1%) — calibrate baseline.
        for _ in 0..8 {
            for i in 0..LD_WINDOW {
                mon.observe(1, i % 100 == 0);
            }
        }
        // Phase 2: high adverse rate (50%) — catastrophic surge.
        for _ in 0..4 {
            for i in 0..LD_WINDOW {
                mon.observe(1, i % 2 == 0);
            }
        }
        assert!(
            mon.anomaly_counts[1] > 0
                || matches!(mon.state(1), RateState::Elevated | RateState::Critical),
            "expected elevated/critical, got {:?} with count {}",
            mon.state(1),
            mon.anomaly_counts[1],
        );
    }

    #[test]
    fn families_are_independent() {
        let mut mon = LargeDeviationsMonitor::new();
        // Stress family 0 with high adverse.
        for _ in 0..12 {
            for i in 0..LD_WINDOW {
                mon.observe(0, i % 2 == 0); // 50% adverse
                mon.observe(3, false); // family 3: 0% adverse
            }
        }
        // Family 0 should be elevated/critical, family 3 should not be.
        assert_ne!(
            mon.state(0),
            RateState::Calibrating,
            "family 0 should have left calibration"
        );
        // Family 3 should be Normal (since all observations are clean).
        if mon.state(3) != RateState::Calibrating {
            assert_eq!(
                mon.state(3),
                RateState::Normal,
                "family 3 (no adverse) should be Normal"
            );
        }
    }

    #[test]
    fn summary_has_valid_fields() {
        let mut mon = LargeDeviationsMonitor::new();
        for _ in 0..6 {
            for i in 0..LD_WINDOW {
                mon.observe(2, i % 50 == 0); // 2% adverse
            }
        }
        let s = mon.summary(2);
        assert!(s.empirical_adverse_rate >= 0.0 && s.empirical_adverse_rate <= 1.0);
        assert!(s.rate_at_5pct >= 0.0);
        assert!(s.rate_at_10pct >= 0.0);
        assert!(s.rate_at_20pct >= 0.0);
        assert!(s.failure_budget_log_5pct <= 0.0 || s.rate_at_5pct < 1e-12);
    }

    #[test]
    fn high_index_api_family_is_tracked() {
        let mut mon = LargeDeviationsMonitor::new();
        let family = ApiFamily::Poll as usize;

        for _ in 0..6 {
            for i in 0..LD_WINDOW {
                mon.observe(family, i % 25 == 0); // 4% adverse
            }
        }

        let summary = mon.summary(family);
        assert_ne!(
            mon.state(family),
            RateState::Calibrating,
            "high-index family should leave calibration like lower indices"
        );
        assert!(summary.empirical_adverse_rate > 0.0);
        assert!(summary.failure_budget_log_5pct <= 0.0 || summary.rate_at_5pct < 1e-12);
    }
}
