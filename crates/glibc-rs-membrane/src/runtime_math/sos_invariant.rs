//! # Sum-of-Squares Polynomial Invariant Runtime Guard
//!
//! Implements SOS (Sum-of-Squares) certificate synthesis methods for
//! runtime verification of nonlinear cross-controller invariants
//! (math item #21).
//!
//! ## Mathematical Foundation
//!
//! A polynomial p(x) is a **sum of squares** (SOS) if there exist
//! polynomials q₁, ..., qₘ such that:
//!
//! ```text
//! p(x) = Σᵢ qᵢ(x)²  ≥ 0   for all x
//! ```
//!
//! SOS decomposition certificates nonnegativity of p. The SOS condition
//! is equivalent to the existence of a positive semidefinite matrix Q
//! (the **Gram matrix**) such that:
//!
//! ```text
//! p(x) = z(x)ᵀ Q z(x)
//! ```
//!
//! where z(x) is the vector of monomials up to degree d/2.
//!
//! Finding Q is a **semidefinite program** (SDP), solvable in polynomial
//! time. Once Q is found offline, runtime *verification* reduces to:
//!
//! ```text
//! v = z(x)ᵀ Q z(x)    (a single quadratic form evaluation)
//! ```
//!
//! If v < 0 at runtime, the invariant p(x) ≥ 0 is violated — the system
//! has entered a state that the SOS certificate proved impossible under
//! normal operation.
//!
//! ## Runtime Application
//!
//! The controller state vector x = (s₁, s₂, ..., sₙ) where sᵢ ∈ {0,1,2,3}
//! encodes the state of each runtime math controller. We define
//! **quadratic invariants** — SOS-certified constraints on pairwise
//! relationships between controller states.
//!
//! For example, the invariant:
//!
//! ```text
//! (s_risk - s_cvar)² + (s_risk - s_eprocess)² ≤ K
//! ```
//!
//! says that risk, CVaR, and e-process controllers shouldn't diverge too
//! far from each other — they all track related phenomena (tail risk).
//!
//! We evaluate a set of pre-computed quadratic forms. Each form has a
//! **Gram matrix** Q (stored as the upper triangle of a symmetric matrix)
//! and a threshold. The runtime cost is O(d²) per invariant, where d
//! is the number of variables in the invariant (typically 3-5).
//!
//! ## Invariant Sets
//!
//! We define three invariant groups tracking cross-controller correlations:
//!
//! 1. **Tail-risk coherence**: risk detectors (eprocess, cvar, conformal,
//!    large_deviations) should have correlated state levels.
//!
//! 2. **Structural integrity**: topology detectors (cohomology, topos,
//!    serre, microlocal) should move together.
//!
//! 3. **Compatibility bundle**: ABI detectors (ktheory, equivariant,
//!    clifford, covering_array) should be correlated.
//!
//! ## State Machine
//!
//! - **Calibrating**: fewer than CALIBRATION_THRESHOLD observations.
//! - **InvariantSatisfied**: all quadratic forms within thresholds.
//! - **InvariantStressed**: some invariants near their violation boundary.
//! - **InvariantViolated**: one or more invariants significantly exceeded.

/// Number of controller signals (state codes) in the input vector.
const NUM_SIGNALS: usize = 25;

/// Observations before leaving calibration.
const CALIBRATION_THRESHOLD: u64 = 128;

/// EWMA smoothing for invariant tracking.
const EWMA_ALPHA: f64 = 0.05;

/// Number of pre-computed quadratic invariants.
const NUM_INVARIANTS: usize = 3;

/// Threshold for InvariantSatisfied → InvariantStressed (fraction of
/// budget consumed, 0..1).
const STRESS_THRESHOLD: f64 = 0.70;

/// Threshold for InvariantStressed → InvariantViolated.
const VIOLATION_THRESHOLD: f64 = 1.0;

/// A pre-computed quadratic invariant.
///
/// Evaluates: Σ_{i,j} Q[i][j] * (x[indices[i]] - center[i]) * (x[indices[j]] - center[j])
///
/// The invariant is satisfied when the evaluated form is ≤ budget.
struct QuadraticInvariant {
    /// Indices into the severity vector for the variables in this invariant.
    indices: &'static [usize],
    /// Center point (expected state levels under normal operation).
    center: &'static [f64],
    /// Upper-triangular Gram matrix entries (row-major, packed).
    /// For a d×d matrix, stores d*(d+1)/2 entries.
    gram_upper: &'static [f64],
    /// Budget: maximum allowed quadratic form value.
    budget: f64,
}

impl QuadraticInvariant {
    /// Evaluate the quadratic form at the given state vector.
    fn evaluate(&self, severity: &[u8; NUM_SIGNALS]) -> f64 {
        let d = self.indices.len();
        let mut result = 0.0;
        let mut idx = 0;

        for i in 0..d {
            let xi = f64::from(severity[self.indices[i]]) - self.center[i];
            for j in i..d {
                let xj = f64::from(severity[self.indices[j]]) - self.center[j];
                let coeff = self.gram_upper[idx];
                if i == j {
                    result += coeff * xi * xj;
                } else {
                    // Off-diagonal: count twice (symmetric matrix).
                    result += 2.0 * coeff * xi * xj;
                }
                idx += 1;
            }
        }

        result
    }

    /// Fraction of budget consumed (0..∞).
    fn stress_fraction(&self, severity: &[u8; NUM_SIGNALS]) -> f64 {
        let val = self.evaluate(severity);
        if self.budget > 0.0 {
            val / self.budget
        } else {
            0.0
        }
    }
}

// Invariant 1: Tail-risk coherence.
// Variables: anytime_state[3], cvar_state[4], conformal_state[16], ld_state[6]
// Severity array indices (from mod.rs severity construction order):
//   3 = anytime, 4 = cvar, 6 = ld, 16 = conformal
// These should move together — large pairwise discrepancies signal incoherence.
static TAIL_RISK_INDICES: [usize; 4] = [3, 4, 6, 16];
static TAIL_RISK_CENTER: [f64; 4] = [1.5, 1.5, 1.5, 1.5];
// Gram matrix (4×4, upper triangle = 10 entries):
// Penalizes pairwise *divergence* between controllers via negative off-diagonal.
// For centered variables y_i = x_i - 1.5, the form
//   Σ_i y_i² - 0.4 Σ_{i≠j} y_i y_j
// is large when controllers diverge (mixed signs) and small when coherent.
static TAIL_RISK_GRAM: [f64; 10] = [
    1.0,  // (0,0)
    -0.4, // (0,1) coherent pairs reduce form
    -0.3, // (0,2)
    -0.4, // (0,3)
    1.0,  // (1,1)
    -0.4, // (1,2)
    -0.3, // (1,3)
    1.0,  // (2,2)
    -0.4, // (2,3)
    1.0,  // (3,3)
];

// Invariant 2: Structural integrity.
// Variables: topos[13], serre[20], microlocal[19]
// Severity indices: 13 = topos, 20 = serre, 19 = microlocal
static STRUCTURAL_INDICES: [usize; 3] = [13, 19, 20];
static STRUCTURAL_CENTER: [f64; 3] = [1.5, 1.5, 1.5];
// Gram matrix (3×3, upper triangle = 6 entries):
// Negative off-diagonal penalizes incoherent divergence.
static STRUCTURAL_GRAM: [f64; 6] = [
    1.0,  // (0,0) topos self
    -0.5, // (0,1) topos-microlocal cross
    -0.4, // (0,2) topos-serre cross
    1.0,  // (1,1) microlocal self
    -0.5, // (1,2) microlocal-serre cross
    1.0,  // (2,2) serre self
];

// Invariant 3: Compatibility bundle.
// Variables: equivariant[12], ktheory[22], clifford[21], covering[23]
// Severity indices: 12 = equivariant, 21 = clifford, 22 = ktheory, 23 = covering
static COMPAT_INDICES: [usize; 4] = [12, 21, 22, 23];
static COMPAT_CENTER: [f64; 4] = [1.5, 1.5, 1.5, 1.5];
// Gram matrix (4×4, upper triangle = 10 entries):
// Negative off-diagonal penalizes incoherent divergence.
static COMPAT_GRAM: [f64; 10] = [
    1.0,  // (0,0) equivariant self
    -0.4, // (0,1) equivariant-clifford cross
    -0.5, // (0,2) equivariant-ktheory cross
    -0.3, // (0,3) equivariant-covering cross
    1.0,  // (1,1) clifford self
    -0.4, // (1,2) clifford-ktheory cross
    -0.3, // (1,3) clifford-covering cross
    1.0,  // (2,2) ktheory self
    -0.3, // (2,3) ktheory-covering cross
    1.0,  // (3,3) covering self
];

static INVARIANTS: [QuadraticInvariant; NUM_INVARIANTS] = [
    QuadraticInvariant {
        indices: &TAIL_RISK_INDICES,
        center: &TAIL_RISK_CENTER,
        gram_upper: &TAIL_RISK_GRAM,
        budget: 10.0,
    },
    QuadraticInvariant {
        indices: &STRUCTURAL_INDICES,
        center: &STRUCTURAL_CENTER,
        gram_upper: &STRUCTURAL_GRAM,
        budget: 8.0,
    },
    QuadraticInvariant {
        indices: &COMPAT_INDICES,
        center: &COMPAT_CENTER,
        gram_upper: &COMPAT_GRAM,
        budget: 10.0,
    },
];

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SosState {
    /// Insufficient observations.
    Calibrating,
    /// All invariants within budget.
    InvariantSatisfied,
    /// Some invariants near violation boundary.
    InvariantStressed,
    /// One or more invariants violated.
    InvariantViolated,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SosSummary {
    pub state: SosState,
    /// Maximum stress fraction across all invariants (0..∞).
    pub max_stress_fraction: f64,
    /// Number of invariants currently stressed (fraction ≥ STRESS_THRESHOLD).
    pub stressed_count: u8,
    /// Number of invariants currently violated (fraction ≥ VIOLATION_THRESHOLD).
    pub violated_count: u8,
    /// Total observations.
    pub total_observations: u64,
    /// Cumulative violation count.
    pub violation_event_count: u64,
}

/// SOS polynomial invariant runtime guard.
pub struct SosInvariantController {
    /// EWMA-smoothed stress fractions per invariant.
    smoothed_stress: [f64; NUM_INVARIANTS],
    /// Total observations.
    observations: u64,
    /// Cumulative invariant violation events.
    violation_event_count: u64,
    /// Last raw stress fractions for snapshot.
    last_raw_stress: [f64; NUM_INVARIANTS],
}

impl Default for SosInvariantController {
    fn default() -> Self {
        Self::new()
    }
}

impl SosInvariantController {
    pub fn new() -> Self {
        Self {
            smoothed_stress: [0.0; NUM_INVARIANTS],
            observations: 0,
            violation_event_count: 0,
            last_raw_stress: [0.0; NUM_INVARIANTS],
        }
    }

    /// Feed a severity vector and evaluate all invariants.
    pub fn observe_and_update(&mut self, severity: &[u8; NUM_SIGNALS]) {
        self.observations += 1;

        for (i, inv) in INVARIANTS.iter().enumerate() {
            let stress = inv.stress_fraction(severity);
            self.last_raw_stress[i] = stress;

            if self.observations == 1 {
                self.smoothed_stress[i] = stress;
            } else {
                self.smoothed_stress[i] += EWMA_ALPHA * (stress - self.smoothed_stress[i]);
            }
        }

        // Count violation events.
        if self.observations > CALIBRATION_THRESHOLD {
            let violated = self
                .smoothed_stress
                .iter()
                .any(|&s| s >= VIOLATION_THRESHOLD);
            if violated {
                self.violation_event_count += 1;
            }
        }
    }

    /// Current state.
    pub fn state(&self) -> SosState {
        if self.observations < CALIBRATION_THRESHOLD {
            return SosState::Calibrating;
        }

        let violated = self
            .smoothed_stress
            .iter()
            .filter(|&&s| s >= VIOLATION_THRESHOLD)
            .count();
        if violated > 0 {
            return SosState::InvariantViolated;
        }

        let stressed = self
            .smoothed_stress
            .iter()
            .filter(|&&s| s >= STRESS_THRESHOLD)
            .count();
        if stressed > 0 {
            return SosState::InvariantStressed;
        }

        SosState::InvariantSatisfied
    }

    /// Summary snapshot.
    pub fn summary(&self) -> SosSummary {
        let max_stress = self.smoothed_stress.iter().copied().fold(0.0_f64, f64::max);
        let stressed_count = self
            .smoothed_stress
            .iter()
            .filter(|&&s| s >= STRESS_THRESHOLD)
            .count() as u8;
        let violated_count = self
            .smoothed_stress
            .iter()
            .filter(|&&s| s >= VIOLATION_THRESHOLD)
            .count() as u8;

        SosSummary {
            state: self.state(),
            max_stress_fraction: max_stress,
            stressed_count,
            violated_count,
            total_observations: self.observations,
            violation_event_count: self.violation_event_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_nominal() -> [u8; NUM_SIGNALS] {
        [1; NUM_SIGNALS] // all at state 1 (nominal fixed point)
    }

    #[test]
    fn calibration_phase() {
        let mut ctrl = SosInvariantController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe_and_update(&all_nominal());
        }
        assert_eq!(ctrl.state(), SosState::Calibrating);
    }

    #[test]
    fn nominal_state_satisfies_invariants() {
        let mut ctrl = SosInvariantController::new();
        // All controllers at state 1 (deviation from center 1.5 is -0.5).
        // Quadratic form ≈ 0.25 * d (for identity Gram) which is well
        // within budgets of 8-10.
        for _ in 0..500 {
            ctrl.observe_and_update(&all_nominal());
        }
        assert_eq!(ctrl.state(), SosState::InvariantSatisfied);
    }

    #[test]
    fn coherent_escalation_stays_satisfied() {
        let mut ctrl = SosInvariantController::new();
        // All controllers escalate together → coherent, invariants hold.
        let pattern = [2u8; NUM_SIGNALS];
        for _ in 0..500 {
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // When all move together, cross-terms are zero (since deviations
        // from center are equal). The quadratic form grows but stays coherent.
        assert_ne!(s.state, SosState::InvariantViolated);
    }

    #[test]
    fn incoherent_tail_risk_stresses() {
        let mut ctrl = SosInvariantController::new();
        // Tail-risk group: indices 3, 4, 6, 16.
        // Make anytime(3) and cvar(4) spike to 3 while conformal(16) stays 0.
        let mut pattern = [1u8; NUM_SIGNALS];
        pattern[3] = 3; // anytime: alarm
        pattern[4] = 3; // cvar: alarm
        pattern[6] = 0; // ld: calibrating
        pattern[16] = 0; // conformal: calibrating

        for _ in 0..2000 {
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // Large discrepancy within the tail-risk group → stress or violation.
        assert!(
            s.state == SosState::InvariantStressed || s.state == SosState::InvariantViolated,
            "Expected stress/violation, got {:?} (max_stress={:.3})",
            s.state,
            s.max_stress_fraction
        );
    }

    #[test]
    fn severe_structural_incoherence_violates() {
        let mut ctrl = SosInvariantController::new();
        // Structural group: indices 13 (topos), 19 (microlocal), 20 (serre).
        // Topos at 3, microlocal at 0, serre at 3 → large cross-term stress.
        let mut pattern = [1u8; NUM_SIGNALS];
        pattern[13] = 3; // topos: incoherent
        pattern[19] = 0; // microlocal: calibrating
        pattern[20] = 3; // serre: collapsed

        for _ in 0..2000 {
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        assert!(
            s.max_stress_fraction > STRESS_THRESHOLD,
            "Expected high stress: {:.3}",
            s.max_stress_fraction
        );
    }

    #[test]
    fn recovery_from_stress() {
        let mut ctrl = SosInvariantController::new();
        // Drive into stress.
        let mut stressed = [1u8; NUM_SIGNALS];
        stressed[3] = 3;
        stressed[4] = 3;
        stressed[16] = 0;
        for _ in 0..1000 {
            ctrl.observe_and_update(&stressed);
        }
        let stress_before = ctrl.summary().max_stress_fraction;

        // Recover with nominal.
        for _ in 0..10_000 {
            ctrl.observe_and_update(&all_nominal());
        }
        let s = ctrl.summary();
        assert!(
            s.max_stress_fraction < stress_before,
            "Stress should decrease"
        );
        assert_eq!(s.state, SosState::InvariantSatisfied);
    }

    #[test]
    fn quadratic_form_evaluation_correctness() {
        // Manual check: 2-variable invariant with identity Gram.
        let inv = QuadraticInvariant {
            indices: &[0, 1],
            center: &[0.0, 0.0],
            gram_upper: &[1.0, 0.0, 1.0], // I₂
            budget: 10.0,
        };

        let mut sev = [0u8; NUM_SIGNALS];
        sev[0] = 3;
        sev[1] = 2;
        // Expected: 3² + 2² = 9 + 4 = 13
        let val = inv.evaluate(&sev);
        assert!((val - 13.0).abs() < 1e-10, "Got {val}");
        assert!((inv.stress_fraction(&sev) - 1.3).abs() < 1e-10);
    }
}
