//! Probabilistic coupling + Azuma-Hoeffding concentration bounds for
//! strict/hardened divergence certification (math item #18).
//!
//! **Reverse-core anchor**: certify that the strict and hardened decision
//! streams remain coupled (statistically indistinguishable) under normal
//! operation, and detect when they drift apart beyond tolerance.
//!
//! ## Mathematical Foundation
//!
//! ### Optimal Coupling
//!
//! Given two discrete distributions P (strict) and Q (hardened) over
//! actions, the *optimal coupling* (gamma*) minimizes:
//!
//! ```text
//! d_TV(P, Q) = (1/2) sum_a |P(a) - Q(a)| = P(X != Y)
//! ```
//!
//! where (X, Y) ~ gamma*. We track the empirical total-variation proxy
//! online: `coupling_distance = disagreements / total_observations`.
//!
//! ### Azuma-Hoeffding Concentration Inequality
//!
//! For the empirical disagreement rate p_hat based on n i.i.d. observations,
//! the true coupling distance p satisfies:
//!
//! ```text
//! P(|p_hat - p| > eps) <= 2 * exp(-2 * n * eps^2)
//! ```
//!
//! Solving for eps at confidence level delta = 0.01 (99% confidence):
//!
//! ```text
//! eps = sqrt(ln(2 / delta) / (2 * n))
//! ```
//!
//! The upper confidence bound is `divergence_bound = p_hat + eps`, and the
//! certification margin is `tolerance - divergence_bound`. A positive margin
//! certifies that strict/hardened are coupled within tolerance.

#![deny(unsafe_code)]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of observations required before leaving `Calibrating`.
const WARMUP_COUNT: u64 = 48;

/// Confidence parameter for the Hoeffding bound (99% confidence).
const DELTA: f64 = 0.01;

/// Tolerance threshold: below this divergence_bound, streams are `Coupled`.
const COUPLED_THRESHOLD: f64 = 0.05;

/// Divergence bound in [COUPLED_THRESHOLD, DRIFTING_THRESHOLD) => `Drifting`.
const DRIFTING_THRESHOLD: f64 = 0.15;

/// Divergence bound in [DRIFTING_THRESHOLD, FAILURE_THRESHOLD) => `Diverged`.
const FAILURE_THRESHOLD: f64 = 0.30;

/// EWMA smoothing factor for adverse-conditioned disagreement rate.
const EWMA_ALPHA: f64 = 0.03;

/// Maximum number of distinct action pairs tracked for frequency counts.
/// Action indices are u8, so there are at most 256 * 256 pairs; we track
/// a compact 16x16 sub-grid sufficient for the runtime action space.
const ACTION_GRID: usize = 16;

// ---------------------------------------------------------------------------
// State enum
// ---------------------------------------------------------------------------

/// Qualitative state of the coupling controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CouplingState {
    /// Fewer than `WARMUP_COUNT` observations received.
    Calibrating,
    /// Divergence bound < `COUPLED_THRESHOLD` — streams are certified coupled.
    Coupled,
    /// Divergence bound in [`COUPLED_THRESHOLD`, `DRIFTING_THRESHOLD`).
    Drifting,
    /// Divergence bound in [`DRIFTING_THRESHOLD`, `FAILURE_THRESHOLD`).
    Diverged,
    /// Divergence bound >= `FAILURE_THRESHOLD` — certification invalid.
    CertificationFailure,
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Point-in-time summary of the coupling controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CouplingSummary {
    /// Current coupling state.
    pub state: CouplingState,
    /// Empirical disagreement rate (disagreements / total_observations).
    pub coupling_distance: f64,
    /// Upper confidence bound: coupling_distance + Hoeffding epsilon.
    pub divergence_bound: f64,
    /// Certification margin: COUPLED_THRESHOLD - divergence_bound.
    /// Positive means certified coupled within tolerance.
    pub certification_margin: f64,
    /// Total number of (strict_action, hardened_action) pairs observed.
    pub total_observations: u64,
    /// Number of observations where strict_action != hardened_action.
    pub divergence_count: u64,
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// Online optimal coupling controller for strict/hardened divergence
/// certification.
///
/// Tracks the empirical disagreement rate between strict and hardened
/// decision streams, computes Azuma-Hoeffding upper confidence bounds,
/// and produces a qualitative certification state.
pub struct CouplingController {
    /// Number of observations where strict_action == hardened_action.
    agreement_count: u64,
    /// Number of observations where strict_action != hardened_action.
    disagreement_count: u64,
    /// Total observations (agreement_count + disagreement_count).
    total_observations: u64,
    /// Per-action-pair frequency grid: freq[strict][hardened].
    pair_freq: [[u64; ACTION_GRID]; ACTION_GRID],
    /// EWMA-smoothed adverse-conditioned disagreement rate.
    ewma_adverse_disagreement: f64,
    /// Current qualitative state.
    state: CouplingState,
}

impl CouplingController {
    /// Create a new controller in `Calibrating` state with zeroed statistics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agreement_count: 0,
            disagreement_count: 0,
            total_observations: 0,
            pair_freq: [[0u64; ACTION_GRID]; ACTION_GRID],
            ewma_adverse_disagreement: 0.0,
            state: CouplingState::Calibrating,
        }
    }

    /// Feed one observation of a (strict_action, hardened_action) pair.
    ///
    /// The `adverse` flag indicates whether this observation occurred under
    /// adverse conditions (e.g., high risk, failure, attack). The EWMA
    /// adverse-conditioned disagreement rate is updated only when `adverse`
    /// is true, providing sensitivity to divergence under stress.
    pub fn observe(&mut self, strict_action: u8, hardened_action: u8, adverse: bool) {
        self.total_observations += 1;

        let disagree = strict_action != hardened_action;

        if disagree {
            self.disagreement_count += 1;
        } else {
            self.agreement_count += 1;
        }

        // Update per-action-pair frequency grid (clamped to grid size).
        let si = usize::from(strict_action).min(ACTION_GRID - 1);
        let hi = usize::from(hardened_action).min(ACTION_GRID - 1);
        self.pair_freq[si][hi] = self.pair_freq[si][hi].saturating_add(1);

        // EWMA update for adverse-conditioned disagreement rate.
        if adverse {
            let x = if disagree { 1.0 } else { 0.0 };
            self.ewma_adverse_disagreement =
                EWMA_ALPHA * x + (1.0 - EWMA_ALPHA) * self.ewma_adverse_disagreement;
        }

        // Compute coupling distance and Hoeffding bound.
        let n = self.total_observations;
        let coupling_distance = self.disagreement_count as f64 / n as f64;
        let divergence_bound = if n >= WARMUP_COUNT {
            coupling_distance + hoeffding_epsilon(n)
        } else {
            // During warmup, use a conservative bound.
            1.0
        };

        // State transition.
        self.state = if n < WARMUP_COUNT {
            CouplingState::Calibrating
        } else if divergence_bound >= FAILURE_THRESHOLD {
            CouplingState::CertificationFailure
        } else if divergence_bound >= DRIFTING_THRESHOLD {
            CouplingState::Diverged
        } else if divergence_bound >= COUPLED_THRESHOLD {
            CouplingState::Drifting
        } else {
            CouplingState::Coupled
        };
    }

    /// Current qualitative coupling state.
    #[must_use]
    pub fn state(&self) -> CouplingState {
        self.state
    }

    /// Point-in-time summary of the coupling controller.
    #[must_use]
    pub fn summary(&self) -> CouplingSummary {
        let n = self.total_observations;
        let coupling_distance = if n > 0 {
            self.disagreement_count as f64 / n as f64
        } else {
            0.0
        };
        let divergence_bound = if n >= WARMUP_COUNT {
            coupling_distance + hoeffding_epsilon(n)
        } else {
            1.0
        };
        let certification_margin = COUPLED_THRESHOLD - divergence_bound;

        CouplingSummary {
            state: self.state,
            coupling_distance,
            divergence_bound,
            certification_margin,
            total_observations: n,
            divergence_count: self.disagreement_count,
        }
    }

    /// Returns true if the certification is currently valid (state is
    /// `Coupled` and the certification margin is positive).
    #[must_use]
    pub fn certification_valid(&self) -> bool {
        self.state == CouplingState::Coupled && self.summary().certification_margin > 0.0
    }
}

impl Default for CouplingController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute the Hoeffding epsilon for `n` observations at confidence `DELTA`.
///
/// eps = sqrt(ln(2 / delta) / (2 * n))
#[inline]
fn hoeffding_epsilon(n: u64) -> f64 {
    if n == 0 {
        return f64::INFINITY;
    }
    let log_term = (2.0_f64 / DELTA).ln();
    (log_term / (2.0 * n as f64)).sqrt()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = CouplingController::new();
        assert_eq!(ctrl.state(), CouplingState::Calibrating);
        let s = ctrl.summary();
        assert_eq!(s.state, CouplingState::Calibrating);
        assert_eq!(s.total_observations, 0);
        assert_eq!(s.divergence_count, 0);
    }

    #[test]
    fn identical_streams_stay_coupled() {
        let mut ctrl = CouplingController::new();
        // Feed 1200 identical (strict, hardened) pairs — zero disagreement.
        // Hoeffding eps at n=1200 with delta=0.01 is ~0.047 < 0.05 threshold.
        for i in 0..1200_u64 {
            let action = (i % 4) as u8;
            ctrl.observe(action, action, i % 10 == 0);
        }
        assert_eq!(ctrl.state(), CouplingState::Coupled);
        let s = ctrl.summary();
        assert_eq!(s.coupling_distance, 0.0);
        assert!(
            s.divergence_bound < COUPLED_THRESHOLD,
            "divergence_bound {:.6} should be below coupled threshold {:.4}",
            s.divergence_bound,
            COUPLED_THRESHOLD,
        );
        assert!(
            s.certification_margin > 0.0,
            "certification_margin {:.6} should be positive when coupled",
            s.certification_margin,
        );
    }

    #[test]
    fn gradual_drift_detected() {
        let mut ctrl = CouplingController::new();
        // Establish a baseline with identical observations past warmup.
        for i in 0..60_u64 {
            let action = (i % 3) as u8;
            ctrl.observe(action, action, false);
        }

        // Introduce gradual drift: ~10% disagreement rate.
        // After enough observations the empirical rate + Hoeffding eps
        // will push divergence_bound above COUPLED_THRESHOLD (0.05).
        let mut reached_drift = false;
        for i in 0..2000_u64 {
            let strict = (i % 4) as u8;
            let hardened = if i % 10 == 0 {
                (strict + 1) % 4
            } else {
                strict
            };
            ctrl.observe(strict, hardened, false);
            if ctrl.state() == CouplingState::Drifting
                || ctrl.state() == CouplingState::Diverged
                || ctrl.state() == CouplingState::CertificationFailure
            {
                reached_drift = true;
                break;
            }
        }
        assert!(
            reached_drift,
            "Expected drift detection with ~10% disagreement rate"
        );
    }

    #[test]
    fn abrupt_divergence_triggers_failure() {
        let mut ctrl = CouplingController::new();
        // Establish baseline past warmup.
        for _ in 0..60 {
            ctrl.observe(0, 0, false);
        }

        // Abrupt total divergence: every pair disagrees.
        // After k disagreements with n = 60 + k total:
        //   coupling_distance = k / n,  bound = k/n + eps(n)
        // At k=50: n=110, cd=0.4545, eps=0.1553 -> bound=0.61 >= 0.30
        let mut reached_failure = false;
        for _ in 0..300_u64 {
            ctrl.observe(0, 1, true);
            if ctrl.state() == CouplingState::CertificationFailure {
                reached_failure = true;
                break;
            }
        }
        assert!(
            reached_failure,
            "Expected CertificationFailure after abrupt total divergence"
        );
    }

    #[test]
    fn certification_margin_positive_when_coupled() {
        let mut ctrl = CouplingController::new();
        // Feed 1200 identical observations to reach Coupled state.
        // Hoeffding eps at n=1200 is ~0.047, so bound = 0.047 < 0.05.
        for i in 0..1200_u64 {
            ctrl.observe(1, 1, i % 20 == 0);
        }
        assert_eq!(ctrl.state(), CouplingState::Coupled);
        let s = ctrl.summary();
        assert!(
            s.certification_margin > 0.0,
            "margin {:.6} should be positive in Coupled state",
            s.certification_margin,
        );
        assert!(ctrl.certification_valid());
    }

    #[test]
    fn certification_invalid_when_diverged() {
        let mut ctrl = CouplingController::new();
        // Drive the controller into a diverged or failure state.
        for _ in 0..48 {
            ctrl.observe(0, 0, false);
        }
        // Now inject heavy disagreement.
        for _ in 0..500 {
            ctrl.observe(0, 1, true);
        }
        assert!(
            matches!(
                ctrl.state(),
                CouplingState::Diverged | CouplingState::CertificationFailure
            ),
            "Expected Diverged or CertificationFailure, got {:?}",
            ctrl.state(),
        );
        assert!(
            !ctrl.certification_valid(),
            "certification_valid() should return false when diverged"
        );
    }

    #[test]
    fn bounded_divergence_metric() {
        let mut ctrl = CouplingController::new();
        // Feed a mix of agreements and disagreements.
        for i in 0..1000_u64 {
            let strict = (i % 5) as u8;
            let hardened = if i % 20 == 0 {
                (strict + 1) % 5
            } else {
                strict
            };
            ctrl.observe(strict, hardened, i % 7 == 0);
        }
        let s = ctrl.summary();

        // Coupling distance must be in [0, 1].
        assert!(
            (0.0..=1.0).contains(&s.coupling_distance),
            "coupling_distance {:.6} out of [0, 1]",
            s.coupling_distance,
        );
        // Divergence bound must be >= coupling_distance.
        assert!(
            s.divergence_bound >= s.coupling_distance,
            "divergence_bound {:.6} should be >= coupling_distance {:.6}",
            s.divergence_bound,
            s.coupling_distance,
        );
        // Total observations should match.
        assert_eq!(s.total_observations, 1000);
        // Disagreement rate should be approximately 5% (1/20).
        assert!(
            (0.03..=0.08).contains(&s.coupling_distance),
            "coupling_distance {:.6} should be near 5% for 1-in-20 disagreements",
            s.coupling_distance,
        );
    }

    #[test]
    fn default_impl_matches_new() {
        let from_new = CouplingController::new();
        let from_default = CouplingController::default();
        assert_eq!(from_new.state(), from_default.state());
        assert_eq!(
            from_new.summary().total_observations,
            from_default.summary().total_observations,
        );
    }
}
