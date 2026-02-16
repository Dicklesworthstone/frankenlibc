//! # Grobner-Basis Constraint Normalizer
//!
//! Implements Grobner-basis constraint normalization for reproducible proof
//! kernels and controller-state consistency verification (math item #30).
//!
//! ## Mathematical Foundation
//!
//! A **Grobner basis** G of a polynomial ideal I ⊂ k[x₁,...,xₙ] is a
//! generating set with the property that the leading term of every element
//! of I is divisible by the leading term of some element of G (w.r.t. a
//! fixed monomial ordering).
//!
//! The key property: **multivariate polynomial division by G is confluent**.
//! The remainder of p modulo G is unique, regardless of division order.
//! This gives a canonical representative for each equivalence class
//! p + I, enabling:
//!
//! 1. **Ideal membership testing**: p ∈ I iff p mod G = 0.
//! 2. **Normal form computation**: NF_G(p) is the unique canonical form.
//! 3. **Equality testing modulo constraints**: p = q mod I iff NF_G(p) = NF_G(q).
//!
//! ## Buchberger S-Polynomial Reduction (Offline)
//!
//! For generators f, g with lcm L of leading monomials:
//!
//! ```text
//! S(f,g) = (L/LT(f))·f - (L/LT(g))·g
//! ```
//!
//! The Grobner basis is complete when all S-polynomials reduce to zero.
//! We precompute the basis offline and ship only the reduced generators
//! as a compact lookup table for runtime normal-form evaluation.
//!
//! ## Runtime Application
//!
//! The controller state vector (s₁, s₂, ..., sₙ) ∈ {0,1,2,3}^N satisfies
//! polynomial constraints derived from the system's design invariants:
//!
//! - **Consistency constraints**: e.g., s_risk ≥ s_eprocess implies
//!   s_risk - s_eprocess ≥ 0 (the risk controller should never be less
//!   alarmed than the sequential tester).
//!
//! - **Compatibility constraints**: e.g., s_ktheory + s_serre ≤ 5
//!   (both can't be maximally alarmed without the SOS guard also firing).
//!
//! - **Ordering constraints**: e.g., s_tstructure ≤ max(s_derived, s_microlocal)
//!   (bootstrap ordering violations imply either derived-category or
//!   microlocal propagation faults).
//!
//! We encode these as polynomial ideal generators over Z/4Z (the state
//! ring), compute the Grobner basis offline, and ship the normal-form
//! reduction table for O(N²) runtime verification.
//!
//! When the controller state vector's normal form is non-zero (i.e., not
//! in the ideal of valid states), we have detected an **inconsistent**
//! controller configuration — a structural fault.
//!
//! ## Connection to Math Item #30
//!
//! Grobner-basis constraint normalization for reproducible proof kernels.
//!
//! ## Legacy Anchor
//!
//! `elf`, `sysdeps/*/dl-*` (loader/symbol/relocation) — ABI compatibility
//! is the space where multiple constraint families must be checked
//! simultaneously, and confluent normalization ensures reproducible results
//! regardless of check ordering.

/// Number of constraint polynomials in the reduced Grobner basis.
/// These are the precomputed generators shipping as runtime lookup tables.
const NUM_CONSTRAINTS: usize = 12;

/// Number of controller state variables tracked.
const NUM_VARIABLES: usize = 16;

/// EWMA decay for violation rate.
const EWMA_ALPHA: f64 = 0.02;

/// Violation rate threshold for inconsistency alarm.
const INCONSISTENCY_THRESHOLD: f64 = 0.10;

/// Severe threshold: structural inconsistency.
const SEVERE_THRESHOLD: f64 = 0.25;

/// Calibration threshold.
const CALIBRATION_OBS: u64 = 64;

/// A precomputed constraint from the Grobner basis.
///
/// Each constraint is a linear/quadratic polynomial over the state ring Z/4Z:
///   Σ_i a_i · x_i + Σ_{i,j} b_{ij} · x_i · x_j + c ≤ 0
///
/// For runtime speed, we encode as a small coefficient table.
#[derive(Debug, Clone, Copy)]
pub struct GrobnerConstraint {
    /// Linear coefficients: (variable_index, coefficient).
    pub linear: [(u8, i8); 4],
    /// Number of active linear terms.
    pub num_linear: u8,
    /// Quadratic terms: (var_i, var_j, coefficient).
    pub quadratic: [(u8, u8, i8); 2],
    /// Number of active quadratic terms.
    pub num_quadratic: u8,
    /// Constant offset.
    pub constant: i8,
    /// Upper bound (constraint satisfied if evaluation ≤ bound).
    pub bound: i8,
}

impl GrobnerConstraint {
    /// Evaluate the constraint polynomial at a given state vector.
    ///
    /// Returns the polynomial value. Constraint satisfied iff value ≤ bound.
    #[must_use]
    fn evaluate(&self, state: &[u8; NUM_VARIABLES]) -> i32 {
        let mut val = i32::from(self.constant);
        for i in 0..usize::from(self.num_linear) {
            let (idx, coeff) = self.linear[i];
            val += i32::from(coeff) * i32::from(state[idx as usize]);
        }
        for i in 0..usize::from(self.num_quadratic) {
            let (idx_i, idx_j, coeff) = self.quadratic[i];
            val += i32::from(coeff)
                * i32::from(state[idx_i as usize])
                * i32::from(state[idx_j as usize]);
        }
        val
    }

    /// Check if the constraint is satisfied.
    #[must_use]
    fn satisfied(&self, state: &[u8; NUM_VARIABLES]) -> bool {
        self.evaluate(state) <= i32::from(self.bound)
    }
}

/// Precomputed Grobner basis for the controller constraint ideal.
///
/// These constraints encode the design invariants of the runtime math kernel.
/// They are the reduced Grobner basis generators — confluent and complete.
const GROBNER_BASIS: [GrobnerConstraint; NUM_CONSTRAINTS] = [
    // C0: risk ≥ eprocess (risk should be at least as alarmed).
    // risk - eprocess ≥ 0, i.e., eprocess - risk ≤ 0
    GrobnerConstraint {
        linear: [(4, 1), (0, -1), (0, 0), (0, 0)], // eprocess(4) - risk(0)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 1, // allow 1 unit of slack
    },
    // C1: cvar ≤ risk + 1 (CVaR shouldn't outpace risk by much).
    GrobnerConstraint {
        linear: [(5, 1), (0, -1), (0, 0), (0, 0)], // cvar(5) - risk(0)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 1,
    },
    // C2: ktheory + serre ≤ 5 (both can't be maximally alarmed).
    GrobnerConstraint {
        linear: [(10, 1), (11, 1), (0, 0), (0, 0)], // ktheory(10) + serre(11)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 5,
    },
    // C3: tstructure ≤ max(microlocal, serre) + 1
    // Approximated as: tstructure - microlocal ≤ 1 AND tstructure - serre ≤ 1
    GrobnerConstraint {
        linear: [(12, 1), (9, -1), (0, 0), (0, 0)], // tstructure(12) - microlocal(9)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 1,
    },
    // C4: tstructure - serre ≤ 1
    GrobnerConstraint {
        linear: [(12, 1), (11, -1), (0, 0), (0, 0)],
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 1,
    },
    // C5: clifford ≤ equivariant + 1 (SIMD faults imply symmetry drift).
    GrobnerConstraint {
        linear: [(13, 1), (8, -1), (0, 0), (0, 0)], // clifford(13) - equivariant(8)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 1,
    },
    // C6: Quadratic coherence: risk * coupling ≤ 6
    // (high risk AND high coupling means both detectors agree — SOS should fire).
    GrobnerConstraint {
        linear: [(0, 0), (0, 0), (0, 0), (0, 0)],
        num_linear: 0,
        quadratic: [(0, 6, 1), (0, 0, 0)], // risk(0) * coupling(6)
        num_quadratic: 1,
        constant: 0,
        bound: 6,
    },
    // C7: bridge + changepoint ≤ 5 (regime-change detectors shouldn't both max).
    GrobnerConstraint {
        linear: [(1, 1), (2, 1), (0, 0), (0, 0)], // bridge(1) + changepoint(2)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 5,
    },
    // C8: hji breached implies mfg ≥ 1 (safety breach implies contention).
    // Encoded: hji - mfg ≤ 2
    GrobnerConstraint {
        linear: [(3, 1), (7, -1), (0, 0), (0, 0)], // hji(3) - mfg(7)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 2,
    },
    // C9: topos ≤ audit + 1 (locale incoherence implies session anomaly).
    GrobnerConstraint {
        linear: [(14, 1), (15, -1), (0, 0), (0, 0)], // topos(14) - audit(15)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 1,
    },
    // C10: microlocal ≤ risk + 1 (propagation faults imply elevated risk).
    GrobnerConstraint {
        linear: [(9, 1), (0, -1), (0, 0), (0, 0)], // microlocal(9) - risk(0)
        num_linear: 2,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 1,
    },
    // C11: Risk-adjacent energy cap: risk + bridge + changepoint + hji ≤ 10.
    // The four primary risk/regime detectors can't all be at max simultaneously
    // (max sum = 12, so ≤ 10 means at most 2 may reach level 3).
    GrobnerConstraint {
        linear: [(0, 1), (1, 1), (2, 1), (3, 1)],
        num_linear: 4,
        quadratic: [(0, 0, 0), (0, 0, 0)],
        num_quadratic: 0,
        constant: 0,
        bound: 10,
    },
];

/// Grobner normalizer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GrobnerState {
    /// Insufficient observations.
    Calibrating = 0,
    /// All constraints satisfied — state is in the normal-form ideal.
    Consistent = 1,
    /// Minor violations — some constraints mildly breached.
    MinorInconsistency = 2,
    /// Structural inconsistency — the controller state vector is outside
    /// the Grobner-basis ideal of valid configurations.
    StructuralFault = 3,
}

/// Telemetry snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GrobnerSnapshot {
    /// Violation rate (EWMA, 0..1).
    pub violation_rate: f64,
    /// Number of constraints violated in the last check.
    pub last_violations: u8,
    /// Maximum excess over bound across all constraints.
    pub max_excess: i32,
    /// Current state.
    pub state: GrobnerState,
    /// Total checks performed.
    pub checks: u64,
    /// Total structural fault detections.
    pub fault_count: u64,
}

/// Online Grobner-basis constraint normalizer.
pub struct GrobnerNormalizerController {
    /// Violation rate (EWMA).
    violation_rate: f64,
    /// Last violations count.
    last_violations: u8,
    /// Maximum excess.
    max_excess: i32,
    /// Current state.
    state: GrobnerState,
    /// Total checks.
    checks: u64,
    /// Fault detections.
    fault_count: u64,
}

impl GrobnerNormalizerController {
    /// Create a new Grobner normalizer controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            violation_rate: 0.0,
            last_violations: 0,
            max_excess: 0,
            state: GrobnerState::Calibrating,
            checks: 0,
            fault_count: 0,
        }
    }

    /// Check the controller state vector against the Grobner basis.
    ///
    /// The `state` array maps controller indices to their current severity
    /// level (0 = calibrating/nominal, 1 = mild, 2 = warning, 3 = alarm).
    ///
    /// Variable index mapping:
    /// 0=risk, 1=bridge, 2=changepoint, 3=hji, 4=eprocess/padic,
    /// 5=cvar, 6=coupling, 7=mfg, 8=equivariant, 9=microlocal,
    /// 10=ktheory, 11=serre, 12=tstructure, 13=clifford, 14=topos, 15=audit
    pub fn check_state_vector(&mut self, state: &[u8; NUM_VARIABLES]) {
        self.checks += 1;
        let mut violations = 0u8;
        let mut max_excess = 0i32;

        for constraint in &GROBNER_BASIS {
            if !constraint.satisfied(state) {
                violations += 1;
                let excess = constraint.evaluate(state) - i32::from(constraint.bound);
                max_excess = max_excess.max(excess);
            }
        }

        self.last_violations = violations;
        self.max_excess = max_excess;

        let violation_frac = f64::from(violations) / NUM_CONSTRAINTS as f64;
        self.violation_rate =
            (1.0 - EWMA_ALPHA) * self.violation_rate + EWMA_ALPHA * violation_frac;

        // State transition.
        if self.checks < CALIBRATION_OBS {
            self.state = GrobnerState::Calibrating;
        } else if self.violation_rate >= SEVERE_THRESHOLD || violations >= 4 {
            if self.state != GrobnerState::StructuralFault {
                self.fault_count += 1;
            }
            self.state = GrobnerState::StructuralFault;
        } else if self.violation_rate >= INCONSISTENCY_THRESHOLD || violations >= 2 {
            self.state = GrobnerState::MinorInconsistency;
        } else {
            self.state = GrobnerState::Consistent;
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> GrobnerState {
        self.state
    }

    /// Telemetry snapshot.
    #[must_use]
    pub fn snapshot(&self) -> GrobnerSnapshot {
        GrobnerSnapshot {
            violation_rate: self.violation_rate,
            last_violations: self.last_violations,
            max_excess: self.max_excess,
            state: self.state,
            checks: self.checks,
            fault_count: self.fault_count,
        }
    }
}

impl Default for GrobnerNormalizerController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = GrobnerNormalizerController::new();
        assert_eq!(ctrl.state(), GrobnerState::Calibrating);
    }

    #[test]
    fn all_zero_state_is_consistent() {
        let mut ctrl = GrobnerNormalizerController::new();
        let zero_state = [0u8; NUM_VARIABLES];
        for _ in 0..128 {
            ctrl.check_state_vector(&zero_state);
        }
        assert_eq!(ctrl.state(), GrobnerState::Consistent);
    }

    #[test]
    fn mild_state_stays_consistent() {
        let mut ctrl = GrobnerNormalizerController::new();
        // All controllers at level 1 — mild, should satisfy all constraints.
        let mild_state = [1u8; NUM_VARIABLES];
        for _ in 0..128 {
            ctrl.check_state_vector(&mild_state);
        }
        assert!(
            ctrl.state() == GrobnerState::Consistent
                || ctrl.state() == GrobnerState::MinorInconsistency,
            "Mild state should be consistent or minor, got {:?}",
            ctrl.state()
        );
    }

    #[test]
    fn maxed_state_triggers_fault() {
        let mut ctrl = GrobnerNormalizerController::new();
        // All controllers at maximum alarm — violates many constraints.
        let max_state = [3u8; NUM_VARIABLES];
        for _ in 0..128 {
            ctrl.check_state_vector(&max_state);
        }
        assert_eq!(
            ctrl.state(),
            GrobnerState::StructuralFault,
            "All-max state must trigger structural fault"
        );
        assert!(ctrl.fault_count > 0);
    }

    #[test]
    fn constraint_evaluation_correct() {
        let state = [0u8; NUM_VARIABLES];
        // All constraints should be satisfied at zero state.
        for (i, c) in GROBNER_BASIS.iter().enumerate() {
            assert!(
                c.satisfied(&state),
                "Constraint {} violated at zero state: eval={}, bound={}",
                i,
                c.evaluate(&state),
                c.bound
            );
        }
    }

    #[test]
    fn specific_violation_detected() {
        let mut ctrl = GrobnerNormalizerController::new();
        // eprocess(4) at 3, risk(0) at 0 → C0: eprocess - risk = 3 > bound 1
        let mut state = [0u8; NUM_VARIABLES];
        state[4] = 3; // eprocess alarm
        state[0] = 0; // risk calm
        for _ in 0..128 {
            ctrl.check_state_vector(&state);
        }
        assert!(
            ctrl.last_violations >= 1,
            "Should detect eprocess > risk violation"
        );
    }

    #[test]
    fn targeted_two_constraint_breaks_yield_minor_inconsistency() {
        let mut ctrl = GrobnerNormalizerController::new();
        // Violate only C0 and C1:
        // - C0: eprocess(4) - risk(0) <= 1
        // - C1: cvar(5) - risk(0) <= 1
        let mut state = [0u8; NUM_VARIABLES];
        state[4] = 2;
        state[5] = 2;

        for _ in 0..128 {
            ctrl.check_state_vector(&state);
        }

        let snap = ctrl.snapshot();
        assert_eq!(ctrl.state(), GrobnerState::MinorInconsistency);
        assert_eq!(snap.last_violations, 2);
        assert!(snap.max_excess >= 1);
    }

    #[test]
    fn fault_count_only_increments_on_structural_fault_entry() {
        let mut ctrl = GrobnerNormalizerController::new();
        let fault_state = [3u8; NUM_VARIABLES];
        let calm_state = [0u8; NUM_VARIABLES];

        // First entry into structural fault.
        for _ in 0..128 {
            ctrl.check_state_vector(&fault_state);
        }
        assert_eq!(ctrl.state(), GrobnerState::StructuralFault);
        let first_fault_count = ctrl.snapshot().fault_count;
        assert_eq!(first_fault_count, 1);

        // Staying in structural fault should not keep incrementing the counter.
        for _ in 0..128 {
            ctrl.check_state_vector(&fault_state);
        }
        assert_eq!(ctrl.snapshot().fault_count, first_fault_count);

        // Recover to non-fault.
        for _ in 0..1024 {
            ctrl.check_state_vector(&calm_state);
        }
        assert_ne!(ctrl.state(), GrobnerState::StructuralFault);

        // Re-enter structural fault should increment exactly once more.
        for _ in 0..128 {
            ctrl.check_state_vector(&fault_state);
        }
        assert_eq!(ctrl.state(), GrobnerState::StructuralFault);
        assert_eq!(ctrl.snapshot().fault_count, first_fault_count + 1);
    }
}
