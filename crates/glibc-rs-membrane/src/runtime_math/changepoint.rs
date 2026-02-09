//! Bayesian online change-point detection for drift in performance and
//! repair-rate behavior (Adams & MacKay 2007).
//!
//! **Reverse-core anchor**: strict/hardened decision calibration — eliminate
//! threshold drift; detect sudden shifts in adverse rates or validation
//! performance.
//!
//! We maintain an online posterior over the "run length" `r_t` (time since last
//! change-point). At each step:
//!
//! 1. **Growth**: `P(r_t = r_{t-1}+1) ∝ P(x_t | r) · (1 - H(r)) · P(r_{t-1})`
//! 2. **Reset**: `P(r_t = 0) ∝ Σ_r P(x_t | r) · H(r) · P(r)`
//! 3. **Hazard**: `H(r) = 1/(r + λ)` — geometric prior on run lengths
//!
//! The predictive likelihood uses a conjugate Beta-Bernoulli model with
//! per-run-length sufficient statistics so that each run length carries its
//! own posterior rate estimate. A change-point concentrates posterior mass on
//! short run-lengths whose fresh rate estimate diverges from the long-running
//! one.

#![deny(unsafe_code)]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of observations required before leaving `Calibrating`.
const WARMUP_COUNT: u64 = 32;

/// Geometric prior mean run length (hazard = 1 / (r + λ)).
const HAZARD_LAMBDA: f64 = 200.0;

/// Run-lengths below this threshold are considered "short".
const SHORT_WINDOW: usize = 16;

/// Posterior mass on short run-lengths required for `Drift`.
const DRIFT_THRESHOLD: f64 = 0.30;

/// Posterior mass on short run-lengths required for `ChangePoint`.
const CHANGEPOINT_THRESHOLD: f64 = 0.60;

/// Truncation horizon — fixed array size for the run-length distribution.
const MAX_RUN_LENGTH: usize = 256;

/// EWMA smoothing factor for adverse-rate estimation.
const EWMA_ALPHA: f64 = 0.03;

/// Beta prior pseudo-count for the conjugate Bernoulli model.
/// Using Beta(alpha_0, beta_0) = Beta(1, 1) gives a uniform prior on [0,1].
const BETA_ALPHA0: f64 = 1.0;
const BETA_BETA0: f64 = 1.0;

// ---------------------------------------------------------------------------
// State enum
// ---------------------------------------------------------------------------

/// Qualitative state produced by the change-point detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangepointState {
    /// Fewer than `WARMUP_COUNT` observations received.
    Calibrating,
    /// Posterior mass on short run-lengths is below `DRIFT_THRESHOLD`.
    Stable,
    /// Posterior mass >= `DRIFT_THRESHOLD` but < `CHANGEPOINT_THRESHOLD`.
    Drift,
    /// Posterior mass >= `CHANGEPOINT_THRESHOLD`.
    ChangePoint,
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Point-in-time summary of the change-point detector.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChangepointSummary {
    pub state: ChangepointState,
    /// Sum of posterior for r < `SHORT_WINDOW`.
    pub posterior_short_mass: f64,
    /// Number of times `ChangePoint` state was entered.
    pub change_point_count: u64,
    /// Maximum MAP run length observed over the detector's lifetime.
    pub max_run_length: u64,
    /// Total observations fed to the detector.
    pub total_observations: u64,
    /// EWMA-smoothed adverse rate.
    pub ewma_adverse_rate: f64,
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// Bayesian online change-point controller.
///
/// Maintains the full (truncated) posterior over run lengths with per-run-length
/// Beta-Bernoulli sufficient statistics and produces a qualitative state
/// summary at each observation.
pub struct ChangepointController {
    /// Current posterior over run lengths (indices 0..MAX_RUN_LENGTH).
    run_length_probs: [f64; MAX_RUN_LENGTH],
    /// Per-run-length sufficient statistic: number of adverse events.
    suf_adverse: [f64; MAX_RUN_LENGTH],
    /// Per-run-length sufficient statistic: total observations in this run.
    suf_total: [f64; MAX_RUN_LENGTH],
    /// Current maximum active run length (index into `run_length_probs`).
    current_max_rl: usize,
    /// Lifetime adverse observation count.
    adverse_count: u64,
    /// Lifetime total observation count.
    total_observations: u64,
    /// Number of times `ChangePoint` state was entered.
    change_point_count: u64,
    /// Maximum MAP run length observed over the detector's lifetime.
    max_observed_rl: u64,
    /// EWMA-smoothed adverse rate.
    ewma_adverse_rate: f64,
    /// Current qualitative state.
    state: ChangepointState,
}

impl ChangepointController {
    /// Create a new controller with all posterior mass at r = 0.
    #[must_use]
    pub fn new() -> Self {
        let mut run_length_probs = [0.0_f64; MAX_RUN_LENGTH];
        run_length_probs[0] = 1.0;
        Self {
            run_length_probs,
            suf_adverse: [0.0_f64; MAX_RUN_LENGTH],
            suf_total: [0.0_f64; MAX_RUN_LENGTH],
            current_max_rl: 0,
            adverse_count: 0,
            total_observations: 0,
            change_point_count: 0,
            max_observed_rl: 0,
            ewma_adverse_rate: 0.0,
            state: ChangepointState::Calibrating,
        }
    }

    /// Feed one Bernoulli observation (`adverse = true` means adverse event).
    ///
    /// This is the core Bayesian update:
    /// 1. Compute predictive likelihood under Beta-Bernoulli for each run length.
    /// 2. Multiply by growth probability `(1 - hazard)`.
    /// 3. Accumulate reset mass = `Σ hazard · posterior`.
    /// 4. Shift run-length distribution (and sufficient statistics) forward by 1.
    /// 5. Set `r = 0` mass to the accumulated reset mass.
    /// 6. Renormalize.
    /// 7. Compute posterior short mass and update state.
    pub fn observe(&mut self, adverse: bool) {
        // Update global counters.
        self.total_observations += 1;
        if adverse {
            self.adverse_count += 1;
        }

        // EWMA adverse rate update (for summary reporting).
        let x = if adverse { 1.0 } else { 0.0 };
        self.ewma_adverse_rate = EWMA_ALPHA * x + (1.0 - EWMA_ALPHA) * self.ewma_adverse_rate;

        // --- Growth & reset accumulation ---
        let max_rl = self.current_max_rl;
        let mut reset_mass = 0.0_f64;

        // Temporary buffers for the shifted distribution.
        let mut new_probs = [0.0_f64; MAX_RUN_LENGTH];
        let mut new_adverse = [0.0_f64; MAX_RUN_LENGTH];
        let mut new_total = [0.0_f64; MAX_RUN_LENGTH];

        for r in (0..=max_rl).rev() {
            let prior = self.run_length_probs[r];
            if prior < 1e-300 {
                continue;
            }

            // Beta-Bernoulli predictive likelihood for this run length:
            // P(x=1 | data_r) = (alpha0 + k_r) / (alpha0 + beta0 + n_r)
            let alpha_post = BETA_ALPHA0 + self.suf_adverse[r];
            let beta_post = BETA_BETA0 + (self.suf_total[r] - self.suf_adverse[r]);
            let denom = alpha_post + beta_post;
            let pred_adverse = alpha_post / denom;
            let likelihood = if adverse {
                pred_adverse
            } else {
                1.0 - pred_adverse
            };

            let weighted = prior * likelihood;
            let hazard = 1.0 / (r as f64 + HAZARD_LAMBDA);

            // Reset contribution.
            reset_mass += weighted * hazard;

            // Growth: shift r -> r+1 (if within truncation window).
            let next_r = r + 1;
            if next_r < MAX_RUN_LENGTH {
                new_probs[next_r] = weighted * (1.0 - hazard);
                // Carry forward sufficient statistics, adding the new observation.
                new_adverse[next_r] = self.suf_adverse[r] + x;
                new_total[next_r] = self.suf_total[r] + 1.0;
            }
        }

        // Set r = 0: fresh run, with only the prior and no data yet observed
        // in this new segment (the current observation was already used in the
        // predictive likelihood above for reset mass; the r=0 slot starts fresh
        // with the observation folded in).
        new_probs[0] = reset_mass;
        new_adverse[0] = x;
        new_total[0] = 1.0;

        // Update current max run length.
        let new_max_rl = (max_rl + 1).min(MAX_RUN_LENGTH - 1);
        self.current_max_rl = new_max_rl;

        // Renormalize.
        let total: f64 = new_probs[..=new_max_rl].iter().sum();
        if total > 0.0 {
            let inv_total = 1.0 / total;
            for p in new_probs[..=new_max_rl].iter_mut() {
                *p *= inv_total;
            }
        } else {
            // Degenerate: reset to uniform on r = 0.
            new_probs[0] = 1.0;
        }

        self.run_length_probs = new_probs;
        self.suf_adverse = new_adverse;
        self.suf_total = new_total;

        // Track MAP run length.
        let mut map_rl = 0_usize;
        let mut map_prob = 0.0_f64;
        for r in 0..=new_max_rl {
            if self.run_length_probs[r] > map_prob {
                map_prob = self.run_length_probs[r];
                map_rl = r;
            }
        }
        if (map_rl as u64) > self.max_observed_rl {
            self.max_observed_rl = map_rl as u64;
        }

        // Compute posterior short mass.
        let short_limit = SHORT_WINDOW.min(new_max_rl + 1);
        let short_mass: f64 = self.run_length_probs[..short_limit].iter().sum();

        // State transition.
        let prev_state = self.state;
        if self.total_observations < WARMUP_COUNT {
            self.state = ChangepointState::Calibrating;
        } else if short_mass >= CHANGEPOINT_THRESHOLD {
            self.state = ChangepointState::ChangePoint;
        } else if short_mass >= DRIFT_THRESHOLD {
            self.state = ChangepointState::Drift;
        } else {
            self.state = ChangepointState::Stable;
        }

        // Increment change-point counter on *entry* to ChangePoint state.
        if self.state == ChangepointState::ChangePoint
            && prev_state != ChangepointState::ChangePoint
        {
            self.change_point_count += 1;
        }
    }

    /// Current qualitative state.
    #[must_use]
    pub fn state(&self) -> ChangepointState {
        self.state
    }

    /// Point-in-time summary.
    #[must_use]
    pub fn summary(&self) -> ChangepointSummary {
        let short_limit = SHORT_WINDOW.min(self.current_max_rl + 1);
        let posterior_short_mass: f64 = self.run_length_probs[..short_limit].iter().sum();

        ChangepointSummary {
            state: self.state,
            posterior_short_mass,
            change_point_count: self.change_point_count,
            max_run_length: self.max_observed_rl,
            total_observations: self.total_observations,
            ewma_adverse_rate: self.ewma_adverse_rate,
        }
    }
}

impl Default for ChangepointController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = ChangepointController::new();
        assert_eq!(ctrl.state(), ChangepointState::Calibrating);
        let s = ctrl.summary();
        assert_eq!(s.state, ChangepointState::Calibrating);
        assert_eq!(s.total_observations, 0);
    }

    #[test]
    fn stable_with_consistent_traffic() {
        let mut ctrl = ChangepointController::new();
        // Feed consistent low-adverse traffic (~2% adverse rate).
        for i in 0..500_u64 {
            ctrl.observe(i % 50 == 0);
        }
        assert_eq!(ctrl.state(), ChangepointState::Stable);
        let s = ctrl.summary();
        assert_eq!(s.state, ChangepointState::Stable);
        assert!(
            s.posterior_short_mass < DRIFT_THRESHOLD,
            "short mass {:.4} should be below drift threshold {:.4}",
            s.posterior_short_mass,
            DRIFT_THRESHOLD,
        );
    }

    #[test]
    fn drift_on_moderate_regime_shift() {
        let mut ctrl = ChangepointController::new();
        // Establish stable baseline: ~2% adverse rate.
        for i in 0..300_u64 {
            ctrl.observe(i % 50 == 0);
        }
        assert_eq!(ctrl.state(), ChangepointState::Stable);

        // Introduce moderate shift: ~20% adverse rate.
        let mut reached_drift = false;
        for i in 0..200_u64 {
            ctrl.observe(i % 5 == 0);
            if ctrl.state() == ChangepointState::Drift
                || ctrl.state() == ChangepointState::ChangePoint
            {
                reached_drift = true;
                break;
            }
        }
        assert!(
            reached_drift,
            "Expected Drift (or ChangePoint) after moderate regime shift"
        );
    }

    #[test]
    fn changepoint_on_sudden_regime_shift() {
        let mut ctrl = ChangepointController::new();
        // Establish a clean baseline: 0% adverse.
        for _ in 0..200 {
            ctrl.observe(false);
        }
        assert_eq!(ctrl.state(), ChangepointState::Stable);

        // Sudden flip to heavy adverse (100%).
        let mut reached_changepoint = false;
        for _ in 0..100 {
            ctrl.observe(true);
            if ctrl.state() == ChangepointState::ChangePoint {
                reached_changepoint = true;
                break;
            }
        }
        assert!(
            reached_changepoint,
            "Expected ChangePoint after sudden regime flip"
        );
    }

    #[test]
    fn recovery_after_changepoint() {
        let mut ctrl = ChangepointController::new();
        // Establish clean baseline.
        for _ in 0..200 {
            ctrl.observe(false);
        }
        // Force a change-point and ensure we observed a shifted state at least once.
        let mut saw_shift_state = false;
        for _ in 0..300 {
            ctrl.observe(true);
            if matches!(
                ctrl.state(),
                ChangepointState::ChangePoint | ChangepointState::Drift
            ) {
                saw_shift_state = true;
            }
        }
        assert!(
            saw_shift_state,
            "Expected to observe ChangePoint or Drift during shock phase",
        );

        // Recover: long clean traffic.
        for _ in 0..1000 {
            ctrl.observe(false);
        }
        assert_eq!(
            ctrl.state(),
            ChangepointState::Stable,
            "Expected Stable after long recovery period"
        );
    }

    #[test]
    fn change_point_count_increments() {
        let mut ctrl = ChangepointController::new();
        // First stable regime.
        for _ in 0..200 {
            ctrl.observe(false);
        }
        assert_eq!(ctrl.summary().change_point_count, 0);

        // First change-point.
        for _ in 0..100 {
            ctrl.observe(true);
        }
        let count_after_first = ctrl.summary().change_point_count;
        assert!(
            count_after_first >= 1,
            "Expected at least 1 change-point detection, got {}",
            count_after_first,
        );

        // Recover.
        for _ in 0..500 {
            ctrl.observe(false);
        }

        // Second change-point.
        for _ in 0..100 {
            ctrl.observe(true);
        }
        let count_after_second = ctrl.summary().change_point_count;
        assert!(
            count_after_second > count_after_first,
            "Expected change_point_count to increase: {} -> {}",
            count_after_first,
            count_after_second,
        );
    }

    #[test]
    fn summary_fields_bounded() {
        let mut ctrl = ChangepointController::new();
        for i in 0..500_u64 {
            ctrl.observe(i % 7 == 0);
        }
        let s = ctrl.summary();

        assert_eq!(s.total_observations, 500);
        assert!(
            (0.0..=1.0).contains(&s.posterior_short_mass),
            "posterior_short_mass {:.4} out of [0, 1]",
            s.posterior_short_mass,
        );
        assert!(
            (0.0..=1.0).contains(&s.ewma_adverse_rate),
            "ewma_adverse_rate {:.6} out of [0, 1]",
            s.ewma_adverse_rate,
        );
        assert!(s.max_run_length <= s.total_observations);
    }

    #[test]
    fn ewma_tracks_adverse_rate() {
        let mut ctrl = ChangepointController::new();
        // Feed 100% adverse traffic.
        for _ in 0..200 {
            ctrl.observe(true);
        }
        let s_high = ctrl.summary();
        assert!(
            s_high.ewma_adverse_rate > 0.8,
            "EWMA {:.4} should be high after all-adverse traffic",
            s_high.ewma_adverse_rate,
        );

        // Feed 100% clean traffic for a while.
        for _ in 0..1000 {
            ctrl.observe(false);
        }
        let s_low = ctrl.summary();
        assert!(
            s_low.ewma_adverse_rate < 0.10,
            "EWMA {:.4} should fall after extended clean traffic",
            s_low.ewma_adverse_rate,
        );
    }

    #[test]
    fn default_impl_matches_new() {
        let from_new = ChangepointController::new();
        let from_default = ChangepointController::default();
        assert_eq!(from_new.state(), from_default.state());
        assert_eq!(
            from_new.summary().total_observations,
            from_default.summary().total_observations,
        );
    }
}
