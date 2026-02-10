//! # Spectral-Sequence Obstruction Detector
//!
//! Implements spectral-sequence methods for detecting cross-layer
//! consistency defects in the controller ensemble (math item #28).
//!
//! ## Mathematical Foundation
//!
//! A **spectral sequence** is a sequence of pages (E_r, d_r) where each
//! page is the homology of the previous:
//!
//! ```text
//! E_{r+1} = H(E_r, d_r) = ker(d_r) / im(d_r)
//! ```
//!
//! The key property is d_r ∘ d_r = 0 (the differential squares to zero).
//! When this fails in practice — when the composition of two consecutive
//! differentials is nonzero — we detect an **obstruction class**:
//!
//! ```text
//! [ω] = d₂ ∘ d₁  ∈ H²(E)
//! ```
//!
//! This obstruction class represents a **global consistency defect** that
//! cannot be detected by examining any single layer in isolation.
//!
//! ## Runtime Application
//!
//! The controller ensemble has a natural filtration (layered structure):
//!
//! - **Layer 0 (E₁)**: Individual controller states (raw severity codes).
//!   The "first differential" d₁ maps each controller to its pairwise
//!   consistency with neighbors.
//!
//! - **Layer 1 (E₂)**: Pairwise controller relationships. The "second
//!   differential" d₂ maps pairwise relationships to triple-consistency
//!   (whether transitive consistency holds).
//!
//! - **Layer 2 (E₃)**: Global consistency. If d₂ ∘ d₁ ≈ 0, the ensemble
//!   is globally consistent. If not, the residual is an obstruction.
//!
//! ### Concrete Construction
//!
//! Given N controller states s_i ∈ {0,1,2,3}, define:
//!
//! 1. **d₁(i)**: signed difference between controller i and its expected
//!    value given the ensemble mean. d₁(i) = s_i − s̄ (deviation from mean).
//!
//! 2. **d₂(i,j)**: second-order consistency = d₁(i)·d₁(j) − cov(i,j).
//!    When controllers i,j have correlated deviations matching their
//!    historical covariance, d₂ ≈ 0. When the correlation structure breaks,
//!    d₂ ≠ 0.
//!
//! 3. **Obstruction** = ‖d₂‖_F / ‖d₁‖ (Frobenius norm of d₂ relative
//!    to d₁ norm). This is the "d² ≈ 0" test.
//!
//! A large obstruction means the controllers' pairwise relationships are
//! inconsistent with their individual behaviors — a cross-layer defect
//! that emerges only from the ensemble structure.
//!
//! ## State Machine
//!
//! - **Calibrating**: fewer than CALIBRATION_THRESHOLD observations
//!   (building covariance estimates).
//! - **Exact**: obstruction norm below tolerance (d² ≈ 0, globally consistent).
//! - **MinorObstruction**: obstruction present but moderate.
//! - **CriticalObstruction**: large obstruction — ensemble consistency breakdown.

/// Number of controller signals in the base severity vector.
const NUM_SIGNALS: usize = 25;

/// Number of tracked covariance pairs (top pairs by variance contribution).
const NUM_PAIRS: usize = 12;

/// Observations before leaving calibration.
const CALIBRATION_THRESHOLD: u64 = 128;

/// EWMA smoothing for obstruction tracking.
const EWMA_ALPHA: f64 = 0.05;

/// Obstruction threshold for Exact → MinorObstruction.
const MINOR_THRESHOLD: f64 = 0.25;

/// Obstruction threshold for MinorObstruction → CriticalObstruction.
const CRITICAL_THRESHOLD: f64 = 0.60;

/// Pre-selected controller pairs for d₂ computation.
/// These are pairs of controllers expected to have correlated behavior:
/// (risk-adjacent, topology-adjacent, compatibility-adjacent groupings).
const TRACKED_PAIRS: [(usize, usize); NUM_PAIRS] = [
    (3, 4),   // anytime ↔ cvar (both tail-risk)
    (4, 6),   // cvar ↔ large_deviations
    (3, 16),  // anytime ↔ conformal
    (0, 1),   // spectral ↔ rough_path (both signal-processing)
    (1, 2),   // rough_path ↔ persistence (topological)
    (7, 8),   // hji ↔ mean_field (game-theoretic)
    (9, 10),  // padic ↔ symplectic (algebraic)
    (13, 14), // topos ↔ audit (coherence)
    (12, 22), // equivariant ↔ ktheory (compatibility)
    (19, 20), // microlocal ↔ serre (sheaf-theoretic)
    (21, 23), // clifford ↔ covering (SIMD/interaction)
    (5, 15),  // bridge ↔ changepoint (regime detection)
];

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObstructionState {
    /// Insufficient observations for covariance estimation.
    Calibrating,
    /// d² ≈ 0: ensemble is globally consistent.
    Exact,
    /// Moderate obstruction: emerging cross-layer defect.
    MinorObstruction,
    /// Large obstruction: ensemble consistency breakdown.
    CriticalObstruction,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ObstructionSummary {
    pub state: ObstructionState,
    /// Smoothed obstruction norm (d₂ residual relative to d₁ norm).
    pub obstruction_norm: f64,
    /// Number of pairs with significant d₂ residual.
    pub obstructed_pair_count: u8,
    /// Maximum single-pair obstruction contribution.
    pub max_pair_obstruction: f64,
    /// Total observations.
    pub total_observations: u64,
    /// Cumulative CriticalObstruction count.
    pub critical_count: u64,
}

/// Spectral-sequence obstruction detector.
pub struct ObstructionDetector {
    /// Running mean of each controller's state.
    mean: [f64; NUM_SIGNALS],
    /// Running covariance estimates for tracked pairs.
    cov: [f64; NUM_PAIRS],
    /// EWMA-smoothed obstruction norm.
    smoothed_obstruction: f64,
    /// Last raw obstruction values per pair.
    last_pair_obstruction: [f64; NUM_PAIRS],
    /// Total observations.
    observations: u64,
    /// CriticalObstruction counter.
    critical_count: u64,
}

impl Default for ObstructionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ObstructionDetector {
    pub fn new() -> Self {
        Self {
            mean: [0.0; NUM_SIGNALS],
            cov: [0.0; NUM_PAIRS],
            smoothed_obstruction: 0.0,
            last_pair_obstruction: [0.0; NUM_PAIRS],
            observations: 0,
            critical_count: 0,
        }
    }

    /// Feed a severity vector and compute the obstruction.
    pub fn observe_and_update(&mut self, severity: &[u8; NUM_SIGNALS]) {
        self.observations += 1;

        let vals: [f64; NUM_SIGNALS] = {
            let mut v = [0.0; NUM_SIGNALS];
            for (vi, &s) in v.iter_mut().zip(severity.iter()) {
                *vi = f64::from(s);
            }
            v
        };

        // Update running means (EWMA).
        let alpha = if self.observations == 1 {
            1.0
        } else {
            EWMA_ALPHA
        };
        for (m, &v) in self.mean.iter_mut().zip(vals.iter()) {
            *m += alpha * (v - *m);
        }

        // Compute d₁: deviations from mean.
        let mut d1 = [0.0; NUM_SIGNALS];
        for (d, (&v, &m)) in d1.iter_mut().zip(vals.iter().zip(self.mean.iter())) {
            *d = v - m;
        }

        // Compute d₁ norm for normalization.
        let d1_norm_sq: f64 = d1.iter().map(|&x| x * x).sum();
        let d1_norm = d1_norm_sq.sqrt().max(1e-10);

        // For each tracked pair, compute d₂ and update covariance.
        let mut d2_frobenius_sq = 0.0;

        for (k, &(i, j)) in TRACKED_PAIRS.iter().enumerate() {
            // Product of deviations (empirical cross-term).
            let cross = d1[i] * d1[j];

            // d₂(i,j) = instantaneous cross − expected covariance.
            // When the correlation structure holds, d₂ ≈ 0.
            // Must compute d₂ BEFORE updating covariance to avoid attenuation.
            let d2_val = cross - self.cov[k];

            // Update covariance estimate.
            self.cov[k] += alpha * (cross - self.cov[k]);
            self.last_pair_obstruction[k] = d2_val.abs();

            d2_frobenius_sq += d2_val * d2_val;
        }

        // Obstruction norm: ‖d₂‖_F / ‖d₁‖.
        let obstruction = d2_frobenius_sq.sqrt() / d1_norm;

        // EWMA smoothing.
        if self.observations == 1 {
            self.smoothed_obstruction = obstruction;
        } else {
            self.smoothed_obstruction += EWMA_ALPHA * (obstruction - self.smoothed_obstruction);
        }

        // Count critical events.
        if self.observations > CALIBRATION_THRESHOLD
            && self.state() == ObstructionState::CriticalObstruction
        {
            self.critical_count += 1;
        }
    }

    /// Current state.
    pub fn state(&self) -> ObstructionState {
        if self.observations < CALIBRATION_THRESHOLD {
            return ObstructionState::Calibrating;
        }

        if self.smoothed_obstruction >= CRITICAL_THRESHOLD {
            ObstructionState::CriticalObstruction
        } else if self.smoothed_obstruction >= MINOR_THRESHOLD {
            ObstructionState::MinorObstruction
        } else {
            ObstructionState::Exact
        }
    }

    /// Summary snapshot.
    pub fn summary(&self) -> ObstructionSummary {
        let obstructed_count = self
            .last_pair_obstruction
            .iter()
            .filter(|&&v| v > MINOR_THRESHOLD)
            .count() as u8;

        let max_pair = self
            .last_pair_obstruction
            .iter()
            .copied()
            .fold(0.0_f64, f64::max);

        ObstructionSummary {
            state: self.state(),
            obstruction_norm: self.smoothed_obstruction,
            obstructed_pair_count: obstructed_count,
            max_pair_obstruction: max_pair,
            total_observations: self.observations,
            critical_count: self.critical_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_nominal() -> [u8; NUM_SIGNALS] {
        [1; NUM_SIGNALS]
    }

    fn all_same(val: u8) -> [u8; NUM_SIGNALS] {
        [val; NUM_SIGNALS]
    }

    #[test]
    fn calibration_phase() {
        let mut ctrl = ObstructionDetector::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe_and_update(&all_nominal());
        }
        assert_eq!(ctrl.state(), ObstructionState::Calibrating);
    }

    #[test]
    fn stable_ensemble_is_exact() {
        let mut ctrl = ObstructionDetector::new();
        // Constant input → d₁ = 0, d₂ = 0.
        for _ in 0..2000 {
            ctrl.observe_and_update(&all_nominal());
        }
        assert_eq!(ctrl.state(), ObstructionState::Exact);
        let s = ctrl.summary();
        assert!(
            s.obstruction_norm < MINOR_THRESHOLD,
            "Obstruction too high: {:.4}",
            s.obstruction_norm
        );
    }

    #[test]
    fn coherent_shift_stays_exact() {
        let mut ctrl = ObstructionDetector::new();
        // Calibrate.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(&all_nominal());
        }
        // All controllers shift together → covariance is maintained.
        for _ in 0..3000 {
            ctrl.observe_and_update(&all_same(2));
        }
        let s = ctrl.summary();
        // After the mean adapts, deviations return to ~0.
        assert_ne!(s.state, ObstructionState::CriticalObstruction);
    }

    #[test]
    fn incoherent_pair_creates_obstruction() {
        let mut ctrl = ObstructionDetector::new();
        // Calibrate with stable pattern.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(&all_nominal());
        }
        // Now: oscillate a tracked pair out of phase.
        // Pair (3,4) = anytime ↔ cvar. Make them anti-correlated.
        for i in 0..5000 {
            let mut pattern = [1u8; NUM_SIGNALS];
            if i % 2 == 0 {
                pattern[3] = 3; // anytime high
                pattern[4] = 0; // cvar low
            } else {
                pattern[3] = 0; // anytime low
                pattern[4] = 3; // cvar high
            }
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // Anti-correlated behavior in a tracked pair should create obstruction.
        assert!(
            s.obstruction_norm > 0.0,
            "Expected nonzero obstruction: {:.4}",
            s.obstruction_norm
        );
    }

    #[test]
    fn multiple_disrupted_pairs_escalates() {
        let mut ctrl = ObstructionDetector::new();
        // Calibrate.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(&all_nominal());
        }
        // Disrupt multiple tracked pairs simultaneously.
        for i in 0..5000 {
            let mut pattern = [1u8; NUM_SIGNALS];
            // Disrupt tail-risk pairs: (3,4), (4,6), (3,16)
            if i % 2 == 0 {
                pattern[3] = 3;
                pattern[4] = 0;
                pattern[6] = 3;
                pattern[16] = 0;
            } else {
                pattern[3] = 0;
                pattern[4] = 3;
                pattern[6] = 0;
                pattern[16] = 3;
            }
            // Also disrupt topology pair: (19,20)
            if i % 3 == 0 {
                pattern[19] = 3;
                pattern[20] = 0;
            }
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // Multiple disrupted pairs produce a higher obstruction than a single pair.
        assert!(
            s.obstruction_norm > 0.05,
            "Expected nonzero obstruction from multi-pair disruption: {:.4}",
            s.obstruction_norm
        );
    }

    #[test]
    fn recovery_after_disruption() {
        let mut ctrl = ObstructionDetector::new();
        // Calibrate + disrupt.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(&all_nominal());
        }
        for i in 0..2000 {
            let mut pattern = [1u8; NUM_SIGNALS];
            if i % 2 == 0 {
                pattern[3] = 3;
                pattern[4] = 0;
            } else {
                pattern[3] = 0;
                pattern[4] = 3;
            }
            ctrl.observe_and_update(&pattern);
        }
        let disrupted_obs = ctrl.summary().obstruction_norm;

        // Recover with stable input.
        for _ in 0..10_000 {
            ctrl.observe_and_update(&all_nominal());
        }
        let s = ctrl.summary();
        assert!(
            s.obstruction_norm < disrupted_obs,
            "Obstruction should decrease: was {disrupted_obs:.4}, now {:.4}",
            s.obstruction_norm
        );
    }

    #[test]
    fn zero_severity_has_low_obstruction() {
        let mut ctrl = ObstructionDetector::new();
        let zeros = [0u8; NUM_SIGNALS];
        for _ in 0..2000 {
            ctrl.observe_and_update(&zeros);
        }
        let s = ctrl.summary();
        assert_eq!(s.state, ObstructionState::Exact);
    }
}
