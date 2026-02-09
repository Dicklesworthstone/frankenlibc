//! Split conformal prediction risk controller for finite-sample decision guarantees.
//!
//! **Math item #27**: Conformal prediction / risk-control methods.
//!
//! Implements split conformal prediction (Vovk et al. 2005, Lei et al. 2018).
//! Given a calibration set of nonconformity scores {s_1, ..., s_n}, the conformal
//! p-value for a new score s is:
//!
//!   p(s) = (|{i : s_i >= s}| + 1) / (n + 1)
//!
//! This yields a prediction set C_alpha = {y : s(y) <= q_{1-alpha}} where q_{1-alpha}
//! is the ceil((1-alpha)(1+1/n))-th quantile of the calibration scores. The key
//! guarantee is:
//!
//!   P(Y_{n+1} in C_alpha) >= 1 - alpha
//!
//! This holds in finite samples with no distributional assumptions (exchangeability
//! suffices).
//!
//! At runtime, we maintain a sliding window of recent risk scores as the calibration
//! set, compute the conformal threshold as the empirical quantile, and monitor
//! whether the empirical coverage rate stays above the target.

#![deny(unsafe_code)]

/// Minimum observations before leaving `Calibrating` state.
const WARMUP_COUNT: u64 = 64;

/// Calibration window size (circular buffer capacity).
const WINDOW_SIZE: usize = 256;

/// Target miscoverage rate (95% coverage target).
const TARGET_ALPHA: f64 = 0.05;

/// Empirical coverage below this triggers `Undercoverage`.
const UNDERCOVERAGE_THRESHOLD: f64 = 0.90;

/// Empirical coverage below this triggers `CoverageFailure`.
const FAILURE_THRESHOLD: f64 = 0.85;

/// EWMA smoothing factor for coverage tracking.
const EWMA_ALPHA: f64 = 0.02;

/// Coverage state of the conformal risk controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformalState {
    /// Fewer than `WARMUP_COUNT` observations have been recorded.
    Calibrating,
    /// Empirical coverage >= `UNDERCOVERAGE_THRESHOLD`.
    Covered,
    /// Coverage in [`FAILURE_THRESHOLD`, `UNDERCOVERAGE_THRESHOLD`).
    Undercoverage,
    /// Coverage < `FAILURE_THRESHOLD`.
    CoverageFailure,
}

/// Point-in-time summary of the conformal risk controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConformalSummary {
    /// Current coverage state.
    pub state: ConformalState,
    /// EWMA-smoothed coverage rate (0..1).
    pub empirical_coverage: f64,
    /// Current (1-alpha) quantile of calibration scores.
    pub conformal_threshold: f64,
    /// Number of times an observation exceeded the conformal threshold.
    pub violation_count: u64,
    /// Total observations recorded.
    pub total_observations: u64,
}

/// Split conformal prediction risk controller.
///
/// Maintains a sliding window of recent nonconformity scores, computes a
/// distribution-free conformal threshold at the (1-alpha) quantile, and
/// tracks empirical coverage via EWMA to detect undercoverage regimes.
pub struct ConformalRiskController {
    /// Circular buffer of recent nonconformity scores.
    scores: [f64; WINDOW_SIZE],
    /// Current write position in the circular buffer.
    write_pos: usize,
    /// Number of filled entries (up to `WINDOW_SIZE`).
    fill: usize,
    /// EWMA-smoothed coverage rate.
    coverage_ewma: f64,
    /// Cached (1-alpha) quantile of the calibration window.
    conformal_threshold: f64,
    /// Number of observations that exceeded the conformal threshold.
    violation_count: u64,
    /// Total observations recorded.
    total_observations: u64,
    /// Current coverage state.
    state: ConformalState,
}

impl ConformalRiskController {
    /// Create a new controller with an empty calibration window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scores: [0.0; WINDOW_SIZE],
            write_pos: 0,
            fill: 0,
            coverage_ewma: 1.0,
            conformal_threshold: f64::INFINITY,
            violation_count: 0,
            total_observations: 0,
            state: ConformalState::Calibrating,
        }
    }

    /// Add a new nonconformity score and update coverage and threshold.
    ///
    /// The observe method:
    /// 1. Increments total_observations
    /// 2. Computes conformal p-value: p = (count of stored scores >= score + 1) / (fill + 1)
    /// 3. Determines if observation is "covered": p > TARGET_ALPHA
    /// 4. Updates coverage EWMA
    /// 5. Adds score to circular buffer
    /// 6. Recomputes conformal threshold from the updated window
    /// 7. Updates state based on coverage_ewma vs thresholds
    pub fn observe(&mut self, score: f64) {
        self.total_observations += 1;

        // Step 2: compute conformal p-value against current calibration window.
        let count_ge = if self.fill > 0 {
            let mut count = 0u64;
            for i in 0..self.fill {
                if self.scores[i] >= score {
                    count += 1;
                }
            }
            count
        } else {
            0
        };
        let p_value = (count_ge as f64 + 1.0) / (self.fill as f64 + 1.0);

        // Step 3: determine if observation is "covered" (within prediction set).
        let covered = p_value > TARGET_ALPHA;

        if !covered {
            self.violation_count += 1;
        }

        // Step 4: update coverage EWMA.
        let covered_f = if covered { 1.0 } else { 0.0 };
        self.coverage_ewma = EWMA_ALPHA * covered_f + (1.0 - EWMA_ALPHA) * self.coverage_ewma;

        // Step 5: add score to circular buffer.
        self.scores[self.write_pos] = score;
        self.write_pos = (self.write_pos + 1) % WINDOW_SIZE;
        if self.fill < WINDOW_SIZE {
            self.fill += 1;
        }

        // Step 6: recompute conformal threshold from updated window.
        self.conformal_threshold = self.compute_threshold();

        // Step 7: update state based on coverage_ewma vs thresholds.
        self.state = if self.total_observations < WARMUP_COUNT {
            ConformalState::Calibrating
        } else if self.coverage_ewma < FAILURE_THRESHOLD {
            ConformalState::CoverageFailure
        } else if self.coverage_ewma < UNDERCOVERAGE_THRESHOLD {
            ConformalState::Undercoverage
        } else {
            ConformalState::Covered
        };
    }

    /// Current coverage state.
    #[must_use]
    pub fn state(&self) -> ConformalState {
        self.state
    }

    /// Point-in-time summary.
    #[must_use]
    pub fn summary(&self) -> ConformalSummary {
        ConformalSummary {
            state: self.state,
            empirical_coverage: self.coverage_ewma,
            conformal_threshold: self.conformal_threshold,
            violation_count: self.violation_count,
            total_observations: self.total_observations,
        }
    }

    /// Compute the (1-alpha) quantile of the current calibration window.
    ///
    /// Uses a scratch copy sorted in-place. The quantile index is
    /// `ceil((1 - TARGET_ALPHA) * (fill + 1)) - 1`, clamped to valid range.
    fn compute_threshold(&self) -> f64 {
        if self.fill == 0 {
            return f64::INFINITY;
        }

        // Copy active entries into a scratch array and sort.
        let mut scratch = [0.0_f64; WINDOW_SIZE];
        scratch[..self.fill].copy_from_slice(&self.scores[..self.fill]);

        // When the buffer wraps, entries are stored in positions 0..fill
        // but with the logical ordering rotated. However, we are computing
        // a quantile (order statistic) so we only need a sorted copy.
        let active = &mut scratch[..self.fill];
        active.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));

        // Quantile index: ceil((1 - alpha) * (fill + 1)) - 1, clamped.
        let raw_rank = ((1.0 - TARGET_ALPHA) * (self.fill as f64 + 1.0)).ceil() as usize;
        let idx = raw_rank.saturating_sub(1).min(self.fill - 1);

        active[idx]
    }
}

impl Default for ConformalRiskController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = ConformalRiskController::new();
        assert_eq!(ctrl.state(), ConformalState::Calibrating);
        let s = ctrl.summary();
        assert_eq!(s.state, ConformalState::Calibrating);
        assert_eq!(s.total_observations, 0);
    }

    #[test]
    fn stable_scores_reach_covered() {
        let mut ctrl = ConformalRiskController::new();
        // Feed identical scores: every new score equals all stored scores,
        // so count_ge = fill, p = (fill + 1) / (fill + 1) = 1.0, always covered.
        for _ in 0..200 {
            ctrl.observe(1.0);
        }
        assert_eq!(ctrl.state(), ConformalState::Covered);
    }

    #[test]
    fn threshold_tracks_calibration_quantile() {
        let mut ctrl = ConformalRiskController::new();
        // Feed scores 1.0, 2.0, ..., 100.0
        for i in 1..=100 {
            ctrl.observe(i as f64);
        }
        // The (1-0.05) quantile of {1..100} should be around 95-96.
        let threshold = ctrl.summary().conformal_threshold;
        assert!(
            (90.0..=100.0).contains(&threshold),
            "threshold {threshold} should be near the 95th percentile"
        );
    }

    #[test]
    fn sudden_spike_triggers_undercoverage() {
        let mut ctrl = ConformalRiskController::new();
        // Build a stable calibration window with scores in [1, 256].
        for i in 0..256 {
            ctrl.observe((i % 100) as f64 + 1.0);
        }
        assert_eq!(ctrl.state(), ConformalState::Covered);

        // Now inject strictly increasing scores far above the calibration range.
        // Each new score is larger than all stored scores, so count_ge = 0,
        // p = 1/(fill+1) which is < 0.05 for fill >= 19.
        // This means each observation is NOT covered, dragging EWMA down.
        for i in 0..200 {
            ctrl.observe(1000.0 + (i as f64) * 10.0);
        }
        // Coverage EWMA should have dropped.
        let s = ctrl.summary();
        assert!(
            s.empirical_coverage < UNDERCOVERAGE_THRESHOLD,
            "coverage {} should be below undercoverage threshold {}",
            s.empirical_coverage,
            UNDERCOVERAGE_THRESHOLD
        );
        assert!(
            matches!(
                s.state,
                ConformalState::Undercoverage | ConformalState::CoverageFailure
            ),
            "state should be Undercoverage or CoverageFailure, got {:?}",
            s.state,
        );
    }

    #[test]
    fn sustained_high_scores_trigger_failure() {
        let mut ctrl = ConformalRiskController::new();
        // Build a stable calibration window.
        for i in 0..128 {
            ctrl.observe((i % 50) as f64 + 1.0);
        }
        // Sustained strictly increasing scores far above the calibration range.
        // Each score is larger than all stored scores, so p = 1/(fill+1) < 0.05,
        // meaning every observation is NOT covered.
        for i in 0..800 {
            ctrl.observe(1e6 + (i as f64) * 100.0);
        }
        let s = ctrl.summary();
        assert_eq!(
            s.state,
            ConformalState::CoverageFailure,
            "coverage {} should trigger CoverageFailure (< {})",
            s.empirical_coverage,
            FAILURE_THRESHOLD,
        );
    }

    #[test]
    fn recovery_after_scores_normalize() {
        let mut ctrl = ConformalRiskController::new();
        // Build up and then spike with strictly increasing scores.
        for i in 0..128 {
            ctrl.observe((i % 50) as f64 + 1.0);
        }
        for i in 0..500 {
            ctrl.observe(1e6 + (i as f64) * 100.0);
        }
        // Should be in a bad state.
        assert!(
            matches!(
                ctrl.state(),
                ConformalState::Undercoverage | ConformalState::CoverageFailure
            ),
            "expected degraded state before recovery, got {:?}",
            ctrl.state(),
        );

        // Return to constant scores — window fills with identical values,
        // every new observation has p = 1.0 (all stored >= new), so coverage
        // EWMA recovers back toward 1.0.
        for _ in 0..2000 {
            ctrl.observe(1.0);
        }
        assert_eq!(
            ctrl.state(),
            ConformalState::Covered,
            "state should recover to Covered after normalization"
        );
    }

    #[test]
    fn violation_count_increments() {
        let mut ctrl = ConformalRiskController::new();
        // Seed with enough calibration scores so that p = 1/(fill+1) < 0.05.
        // We need fill >= 20 so that p = 1/21 ≈ 0.048 < 0.05.
        for _ in 0..25 {
            ctrl.observe(1.0);
        }
        let before = ctrl.summary().violation_count;
        // Inject a score strictly larger than all stored scores.
        // count_ge = 0, p = 1/(25+1) ≈ 0.038 < 0.05, so it is NOT covered.
        ctrl.observe(1e9);
        let after = ctrl.summary().violation_count;
        assert!(
            after > before,
            "violation_count should increment on extreme outlier"
        );
    }

    #[test]
    fn summary_fields_bounded() {
        let mut ctrl = ConformalRiskController::new();
        for i in 0..300 {
            ctrl.observe((i as f64) * 0.5);
        }
        let s = ctrl.summary();
        assert!(
            s.empirical_coverage >= 0.0 && s.empirical_coverage <= 1.0,
            "empirical_coverage {} out of [0,1]",
            s.empirical_coverage,
        );
        assert!(
            s.conformal_threshold.is_finite(),
            "conformal_threshold should be finite after observations"
        );
        assert!(s.violation_count <= s.total_observations);
        assert_eq!(s.total_observations, 300);
    }

    #[test]
    fn coverage_ewma_smooths_noise() {
        let mut ctrl = ConformalRiskController::new();
        // Build a solid calibration window.
        for _ in 0..200 {
            ctrl.observe(1.0);
        }
        let coverage_before = ctrl.summary().empirical_coverage;

        // Inject a single extreme outlier.
        ctrl.observe(1e12);
        let coverage_after = ctrl.summary().empirical_coverage;

        // The EWMA should not drop drastically from a single outlier.
        let drop = coverage_before - coverage_after;
        assert!(
            drop < 0.05,
            "single outlier caused coverage drop of {drop:.4}, EWMA should smooth this"
        );
        // But it should move at least a little.
        assert!(
            drop > 0.0,
            "EWMA should register at least some movement from outlier"
        );
    }
}
