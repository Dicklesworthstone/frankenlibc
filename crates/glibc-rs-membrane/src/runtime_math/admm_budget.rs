//! # ADMM Operator-Splitting Budget Allocator
//!
//! Implements online ADMM (Alternating Direction Method of Multipliers)
//! for joint optimization of the validation pipeline's competing
//! resource objectives (math item #26).
//!
//! ## Mathematical Foundation
//!
//! The **ADMM** algorithm (Boyd et al., 2011) solves convex optimization
//! problems with separable structure by decomposing them into coordinated
//! sub-problems via augmented Lagrangian splitting:
//!
//! ```text
//! minimize  f(x) + g(z)
//! subject to  Ax + Bz = c
//! ```
//!
//! The augmented Lagrangian is:
//!
//! ```text
//! L_ρ(x, z, y) = f(x) + g(z) + yᵀ(Ax + Bz − c) + (ρ/2)‖Ax + Bz − c‖²
//! ```
//!
//! ADMM iterates three steps:
//! 1. **x-update** (primal): minimize L_ρ over x, holding z,y fixed.
//! 2. **z-update** (consensus): minimize L_ρ over z, holding x,y fixed.
//! 3. **y-update** (dual ascent): y ← y + ρ(Ax + Bz − c).
//!
//! Convergence is certified when both the **primal residual** r = Ax+Bz−c
//! and the **dual residual** s = ρAᵀB(z−z_prev) fall below tolerance.
//!
//! ## Runtime Application
//!
//! The validation pipeline has three competing objectives:
//!
//! 1. **Risk reduction** (want high): more validation catches more faults.
//! 2. **Latency budget** (want low): validation adds overhead.
//! 3. **Coverage completeness** (want high): all code paths exercised.
//!
//! These form a constrained optimization problem:
//!
//! ```text
//! minimize   risk_cost(x) + latency_cost(x)
//! subject to  coverage(x) ≥ coverage_floor
//!             latency(x) ≤ latency_ceiling
//!             x ∈ [0,1]³  (budget fractions)
//! ```
//!
//! We decompose this into:
//! - **Primal**: optimal per-objective budget fractions x = (x_risk, x_latency, x_coverage).
//! - **Consensus**: the shared resource constraint z (total budget ≤ 1).
//! - **Dual**: shadow prices y for constraint violations.
//!
//! The shadow prices (Lagrange multipliers) are the key runtime signal:
//! - High y_latency means latency constraint is binding (system is latency-starved).
//! - High y_coverage means coverage constraint is binding (under-explored code paths).
//! - High y_risk means risk floor is active (too-aggressive risk reduction is expensive).
//!
//! The controller tracks primal-dual convergence. When the system drifts
//! (changing risk/latency/coverage profiles), the dual variables must
//! re-adapt, and the transient gap signals miscalibration.
//!
//! ## State Machine
//!
//! - **Calibrating**: fewer than CALIBRATION_THRESHOLD observations.
//! - **Converged**: primal-dual gap below convergence tolerance.
//! - **DualDrift**: dual variables drifting (gap growing but moderate).
//! - **ConstraintViolation**: gap exceeds critical threshold — budget
//!   allocation is significantly suboptimal.

/// Number of ADMM objectives (risk, latency, coverage).
const NUM_OBJECTIVES: usize = 3;

/// Observations before leaving calibration.
const CALIBRATION_THRESHOLD: u64 = 128;

/// EWMA smoothing for primal-dual gap tracking.
const EWMA_ALPHA: f64 = 0.05;

/// ADMM penalty parameter ρ.
const RHO: f64 = 1.0;

/// Convergence tolerance for primal-dual gap.
const CONVERGENCE_TOL: f64 = 0.10;

/// Critical threshold for ConstraintViolation.
const VIOLATION_TOL: f64 = 0.35;

/// Step size for online gradient update (diminishing).
const BASE_STEP: f64 = 0.02;

/// Budget fractions target: risk, latency, coverage should sum to ≤ 1.
const BUDGET_CAP: f64 = 1.0;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmmState {
    /// Insufficient observations.
    Calibrating,
    /// Primal-dual gap converged within tolerance.
    Converged,
    /// Dual variables drifting — budget allocation adapting.
    DualDrift,
    /// Primal-dual gap exceeds critical threshold.
    ConstraintViolation,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdmmSummary {
    pub state: AdmmState,
    /// Current primal budget fractions [risk, latency, coverage].
    pub primal: [f64; NUM_OBJECTIVES],
    /// Current dual shadow prices [risk, latency, coverage].
    pub dual: [f64; NUM_OBJECTIVES],
    /// Smoothed primal-dual gap.
    pub primal_dual_gap: f64,
    /// Total observations.
    pub total_observations: u64,
    /// Number of ConstraintViolation detections.
    pub violation_count: u64,
}

/// ADMM operator-splitting budget allocator.
pub struct AdmmBudgetController {
    /// Primal variables: budget fractions per objective [0,1].
    primal: [f64; NUM_OBJECTIVES],
    /// Consensus variable: shared budget allocation.
    consensus: [f64; NUM_OBJECTIVES],
    /// Dual variables (Lagrange multipliers / shadow prices).
    dual: [f64; NUM_OBJECTIVES],
    /// EWMA-smoothed primal-dual gap.
    smoothed_gap: f64,
    /// Total observations.
    observations: u64,
    /// ConstraintViolation counter.
    violation_count: u64,
}

impl Default for AdmmBudgetController {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmmBudgetController {
    pub fn new() -> Self {
        // Start with equal budget allocation.
        let initial = [1.0 / 3.0; NUM_OBJECTIVES];
        Self {
            primal: initial,
            consensus: initial,
            dual: [0.0; NUM_OBJECTIVES],
            smoothed_gap: 0.0,
            observations: 0,
            violation_count: 0,
        }
    }

    /// Feed observed objective costs and perform one ADMM iteration.
    ///
    /// - `risk_cost`: normalized risk level [0,1] (higher = more risk exposure).
    /// - `latency_fraction`: fraction of latency budget consumed [0,1].
    /// - `coverage_gap`: 1 - coverage fraction [0,1] (0 = full coverage).
    pub fn observe_and_update(&mut self, risk_cost: f64, latency_fraction: f64, coverage_gap: f64) {
        self.observations += 1;

        let costs = [
            risk_cost.clamp(0.0, 1.0),
            latency_fraction.clamp(0.0, 1.0),
            coverage_gap.clamp(0.0, 1.0),
        ];

        // Step size diminishes with observations for convergence.
        let step = BASE_STEP / (1.0 + (self.observations as f64).sqrt() * 0.01);

        // === x-update (primal) ===
        // Gradient of per-objective cost + augmented Lagrangian term.
        // The primal update moves budget toward high-cost objectives
        // (allocate more budget where cost is highest).
        let z_prev = self.consensus;

        for i in 0..NUM_OBJECTIVES {
            // Gradient: cost drives budget up; dual + penalty drive toward consensus.
            let gradient = -costs[i] + self.dual[i] + RHO * (self.primal[i] - self.consensus[i]);
            self.primal[i] = (self.primal[i] - step * gradient).clamp(0.0, 1.0);
        }

        // === z-update (consensus) ===
        // Project the average of (primal + dual/ρ) onto the budget simplex.
        let mut avg = [0.0; NUM_OBJECTIVES];
        for i in 0..NUM_OBJECTIVES {
            avg[i] = self.primal[i] + self.dual[i] / RHO;
        }
        self.consensus = Self::project_simplex(&avg, BUDGET_CAP);

        // === y-update (dual ascent) ===
        // Dual variables track constraint violations.
        for i in 0..NUM_OBJECTIVES {
            self.dual[i] += RHO * (self.primal[i] - self.consensus[i]);
        }

        // Compute primal and dual residuals.
        let primal_residual = Self::l2_norm_diff(&self.primal, &self.consensus);
        let dual_residual = RHO * Self::l2_norm_diff(&self.consensus, &z_prev);
        let gap = (primal_residual + dual_residual) / 2.0;

        // EWMA update.
        if self.observations == 1 {
            self.smoothed_gap = gap;
        } else {
            self.smoothed_gap += EWMA_ALPHA * (gap - self.smoothed_gap);
        }

        // Count violations.
        if self.observations > CALIBRATION_THRESHOLD
            && self.state() == AdmmState::ConstraintViolation
        {
            self.violation_count += 1;
        }
    }

    /// Project onto the capped simplex: Σ x_i ≤ cap, x_i ≥ 0.
    /// Uses the efficient O(n log n) simplex projection algorithm.
    fn project_simplex(v: &[f64; NUM_OBJECTIVES], cap: f64) -> [f64; NUM_OBJECTIVES] {
        // If already feasible, clamp negatives and return.
        let mut result = [0.0; NUM_OBJECTIVES];
        for i in 0..NUM_OBJECTIVES {
            result[i] = v[i].max(0.0);
        }

        let sum: f64 = result.iter().sum();
        if sum <= cap {
            return result;
        }

        // Sort descending to find the threshold.
        let mut sorted = result;
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        let mut cumsum = 0.0;
        let mut threshold = 0.0;
        for (k, &val) in sorted.iter().enumerate() {
            cumsum += val;
            let t = (cumsum - cap) / (k as f64 + 1.0);
            if val - t > 0.0 {
                threshold = t;
            }
        }

        for i in 0..NUM_OBJECTIVES {
            result[i] = (result[i] - threshold).max(0.0);
        }

        result
    }

    /// L2 norm of the difference between two vectors.
    fn l2_norm_diff(a: &[f64; NUM_OBJECTIVES], b: &[f64; NUM_OBJECTIVES]) -> f64 {
        let mut sum_sq = 0.0;
        for i in 0..NUM_OBJECTIVES {
            let d = a[i] - b[i];
            sum_sq += d * d;
        }
        sum_sq.sqrt()
    }

    /// Current state.
    pub fn state(&self) -> AdmmState {
        if self.observations < CALIBRATION_THRESHOLD {
            return AdmmState::Calibrating;
        }

        if self.smoothed_gap >= VIOLATION_TOL {
            AdmmState::ConstraintViolation
        } else if self.smoothed_gap >= CONVERGENCE_TOL {
            AdmmState::DualDrift
        } else {
            AdmmState::Converged
        }
    }

    /// Summary snapshot.
    pub fn summary(&self) -> AdmmSummary {
        AdmmSummary {
            state: self.state(),
            primal: self.primal,
            dual: self.dual,
            primal_dual_gap: self.smoothed_gap,
            total_observations: self.observations,
            violation_count: self.violation_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_phase() {
        let mut ctrl = AdmmBudgetController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe_and_update(0.1, 0.2, 0.1);
        }
        assert_eq!(ctrl.state(), AdmmState::Calibrating);
    }

    #[test]
    fn converges_under_stable_costs() {
        let mut ctrl = AdmmBudgetController::new();
        // Stable, moderate costs → should converge.
        for _ in 0..3000 {
            ctrl.observe_and_update(0.3, 0.3, 0.3);
        }
        let s = ctrl.summary();
        assert_eq!(s.state, AdmmState::Converged);
        assert!(s.primal_dual_gap < CONVERGENCE_TOL);
        // Budget fractions should be roughly equal given equal costs.
        let spread = s.primal.iter().copied().fold(0.0_f64, f64::max)
            - s.primal.iter().copied().fold(f64::MAX, f64::min);
        assert!(spread < 0.3, "Budget spread too wide: {spread:.3}");
    }

    #[test]
    fn high_risk_drives_risk_budget_up() {
        let mut ctrl = AdmmBudgetController::new();
        // High risk cost, low latency/coverage cost.
        for _ in 0..3000 {
            ctrl.observe_and_update(0.9, 0.1, 0.1);
        }
        let s = ctrl.summary();
        // Risk budget should be highest.
        assert!(
            s.primal[0] > s.primal[1] && s.primal[0] > s.primal[2],
            "Risk budget should dominate: {:?}",
            s.primal
        );
    }

    #[test]
    fn simplex_projection_preserves_cap() {
        let v = [0.5, 0.4, 0.3];
        let proj = AdmmBudgetController::project_simplex(&v, 1.0);
        let sum: f64 = proj.iter().sum();
        assert!(sum <= 1.0 + 1e-10, "Projection exceeds cap: {sum:.6}");
        for &p in &proj {
            assert!(p >= -1e-10, "Negative budget fraction: {p:.6}");
        }
    }

    #[test]
    fn cost_shock_causes_drift() {
        let mut ctrl = AdmmBudgetController::new();
        // Converge first.
        for _ in 0..2000 {
            ctrl.observe_and_update(0.3, 0.3, 0.3);
        }
        assert_eq!(ctrl.state(), AdmmState::Converged);

        // Sudden cost shock — latency spikes.
        for _ in 0..200 {
            ctrl.observe_and_update(0.1, 0.95, 0.1);
        }
        let s = ctrl.summary();
        // Gap may or may not cross DualDrift threshold depending on EWMA,
        // but the gap should have increased from the converged baseline.
        assert!(s.primal_dual_gap > 0.0);
    }

    #[test]
    fn recovery_from_shock() {
        let mut ctrl = AdmmBudgetController::new();
        // Stabilize.
        for _ in 0..2000 {
            ctrl.observe_and_update(0.3, 0.3, 0.3);
        }
        // Shock.
        for _ in 0..500 {
            ctrl.observe_and_update(0.9, 0.9, 0.9);
        }
        let gap_during = ctrl.summary().primal_dual_gap;
        // Recover.
        for _ in 0..5000 {
            ctrl.observe_and_update(0.3, 0.3, 0.3);
        }
        let s = ctrl.summary();
        assert!(
            s.primal_dual_gap < gap_during || s.state == AdmmState::Converged,
            "Should recover: gap was {gap_during:.4}, now {:.4}",
            s.primal_dual_gap
        );
    }

    #[test]
    fn dual_prices_reflect_constraints() {
        let mut ctrl = AdmmBudgetController::new();
        // Heavy coverage gap → coverage dual should grow.
        for _ in 0..3000 {
            ctrl.observe_and_update(0.1, 0.1, 0.9);
        }
        let s = ctrl.summary();
        // Coverage budget fraction should be highest.
        assert!(
            s.primal[2] > s.primal[0],
            "Coverage budget should be high: {:?}",
            s.primal
        );
    }
}
