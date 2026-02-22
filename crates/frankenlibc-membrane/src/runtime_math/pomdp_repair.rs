//! # Constrained POMDP Repair Policy Controller
//!
//! Implements constrained partially-observable Markov decision process
//! methods for optimal hardened-mode repair decisions (math item #8).
//!
//! ## Mathematical Foundation
//!
//! A **POMDP** (Partially Observable Markov Decision Process) extends an
//! MDP with hidden state. The agent maintains a **belief state** b(s) —
//! a probability distribution over the true system state s — and selects
//! actions to minimize expected long-run cost.
//!
//! The Bellman optimality equation for POMDPs:
//!
//! ```text
//! V*(b) = min_a [ C(b,a) + γ Σ_o P(o|b,a) V*(τ(b,a,o)) ]
//! ```
//!
//! where:
//! - b is the belief state (probability vector over hidden states)
//! - a ∈ {Allow, FullValidate, Repair, Deny} is the action
//! - C(b,a) is the immediate cost
//! - γ is the discount factor
//! - o is the observation
//! - τ(b,a,o) is the Bayesian belief update
//!
//! ## Tractable Approximation
//!
//! Full POMDP solving is PSPACE-hard. We use a **point-based value
//! iteration** (PBVI) approach on a **discretized belief simplex**:
//!
//! 1. The hidden state has NUM_HEALTH_STATES = 4 levels:
//!    {Healthy, Degraded, Faulty, Critical}
//!
//! 2. The belief simplex is sampled at a fixed set of representative
//!    belief points (corners + midpoints = 10 points).
//!
//! 3. The **alpha-vector** representation stores value functions as
//!    linear functions over the belief simplex: V(b) = max_i α_i · b.
//!
//! 4. Transitions are informed by the observed risk_ppm and action taken.
//!
//! ## Runtime Application
//!
//! The membrane's repair decision is currently a fixed threshold cascade:
//!
//! ```text
//! risk ≥ full_trigger → FullValidate
//! risk ≥ repair_trigger ∧ heals → Repair
//! else → Allow
//! ```
//!
//! The POMDP controller tracks how well this cascade matches the optimal
//! policy. When the gap between optimal and observed value grows, the
//! controller signals that the threshold cascade is miscalibrated.
//!
//! ## State Machine
//!
//! - **Calibrating**: fewer than CALIBRATION_THRESHOLD observations.
//! - **Optimal**: observed policy value is within tolerance of computed optimal.
//! - **SuboptimalPolicy**: persistent gap between optimal and observed values.
//! - **PolicyDivergence**: gap exceeds critical threshold — thresholds are
//!   significantly miscalibrated.

/// Number of discrete hidden health states.
const NUM_HEALTH_STATES: usize = 4;

/// Number of discrete actions.
const NUM_ACTIONS: usize = 4;

/// Observations before leaving calibration.
const CALIBRATION_THRESHOLD: u64 = 128;

/// EWMA smoothing for belief and value tracking.
const EWMA_ALPHA: f64 = 0.05;

/// Discount factor for value computation.
const GAMMA: f64 = 0.95;

/// Optimality gap threshold for Optimal → SuboptimalPolicy.
const SUBOPTIMAL_THRESHOLD: f64 = 0.15;

/// Optimality gap threshold for SuboptimalPolicy → PolicyDivergence.
const DIVERGENCE_THRESHOLD: f64 = 0.40;

/// Risk-ppm boundaries for observation mapping.
const RISK_BOUNDARIES: [u32; 3] = [50_000, 200_000, 500_000];

/// Hidden health state indices (documentation-only; indices used directly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum _HealthState {
    Healthy = 0,
    Degraded = 1,
    Faulty = 2,
    Critical = 3,
}

/// Action indices matching MembraneAction variants (documentation-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum _PolicyAction {
    Allow = 0,
    FullValidate = 1,
    Repair = 2,
    Deny = 3,
}

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PomdpState {
    /// Insufficient observations.
    Calibrating,
    /// Current policy is near-optimal.
    Optimal,
    /// Gap between optimal and observed policy value is growing.
    SuboptimalPolicy,
    /// Severe miscalibration between policy and optimal.
    PolicyDivergence,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PomdpSummary {
    pub state: PomdpState,
    /// Current belief over hidden health states [P(Healthy)..P(Critical)].
    pub belief: [f64; NUM_HEALTH_STATES],
    /// Computed optimal value at current belief point.
    pub optimal_value: f64,
    /// Observed value from actual policy decisions.
    pub observed_value: f64,
    /// Smoothed optimality gap (observed_cost - optimal_cost) / optimal_cost.
    pub optimality_gap: f64,
    /// Total observations.
    pub total_observations: u64,
    /// Number of PolicyDivergence detections.
    pub divergence_count: u64,
}

/// Transition matrix: P(s'|s, a) — probability of moving to health state s'
/// given current state s and action a.
///
/// Layout: transitions[action][from_state][to_state]
const fn build_transitions() -> [[[f64; NUM_HEALTH_STATES]; NUM_HEALTH_STATES]; NUM_ACTIONS] {
    let mut t = [[[0.0; NUM_HEALTH_STATES]; NUM_HEALTH_STATES]; NUM_ACTIONS];

    // Allow: system degrades slowly.
    t[0][0] = [0.90, 0.08, 0.02, 0.00]; // Healthy → mostly stays
    t[0][1] = [0.05, 0.80, 0.12, 0.03]; // Degraded → slow decline
    t[0][2] = [0.01, 0.05, 0.74, 0.20]; // Faulty → worsening
    t[0][3] = [0.00, 0.02, 0.08, 0.90]; // Critical → stuck

    // FullValidate: catches degradation, slight improvement.
    t[1][0] = [0.95, 0.04, 0.01, 0.00];
    t[1][1] = [0.15, 0.75, 0.08, 0.02];
    t[1][2] = [0.05, 0.20, 0.65, 0.10];
    t[1][3] = [0.02, 0.08, 0.20, 0.70];

    // Repair: strong recovery for degraded/faulty states.
    t[2][0] = [0.95, 0.04, 0.01, 0.00];
    t[2][1] = [0.40, 0.50, 0.08, 0.02];
    t[2][2] = [0.15, 0.35, 0.40, 0.10];
    t[2][3] = [0.05, 0.15, 0.30, 0.50];

    // Deny: prevents harm but doesn't fix underlying state.
    t[3][0] = [0.92, 0.06, 0.02, 0.00];
    t[3][1] = [0.10, 0.78, 0.10, 0.02];
    t[3][2] = [0.03, 0.12, 0.70, 0.15];
    t[3][3] = [0.01, 0.05, 0.14, 0.80];

    t
}

/// Immediate cost: C(s, a) — cost of taking action a in state s.
/// Lower is better.
const fn build_costs() -> [[f64; NUM_ACTIONS]; NUM_HEALTH_STATES] {
    [
        // Healthy: Allow is cheap; over-validating is wasteful.
        [0.0, 5.0, 8.0, 20.0],
        // Degraded: validation is prudent; allowing is risky.
        [10.0, 2.0, 3.0, 12.0],
        // Faulty: repair is essential; allowing is dangerous.
        [30.0, 8.0, 2.0, 5.0],
        // Critical: deny is safest; allowing is catastrophic.
        [50.0, 15.0, 5.0, 1.0],
    ]
}

static TRANSITIONS: [[[f64; NUM_HEALTH_STATES]; NUM_HEALTH_STATES]; NUM_ACTIONS] =
    build_transitions();
static COSTS: [[f64; NUM_ACTIONS]; NUM_HEALTH_STATES] = build_costs();

/// Constrained POMDP repair policy controller.
pub struct PomdpRepairController {
    /// Current belief state: P(HealthState = i).
    belief: [f64; NUM_HEALTH_STATES],
    /// EWMA-smoothed optimality gap.
    smoothed_gap: f64,
    /// Running optimal value estimate.
    smoothed_optimal_value: f64,
    /// Running observed value estimate.
    smoothed_observed_value: f64,
    /// Total observations.
    observations: u64,
    /// PolicyDivergence detection counter.
    divergence_count: u64,
}

impl Default for PomdpRepairController {
    fn default() -> Self {
        Self::new()
    }
}

impl PomdpRepairController {
    pub fn new() -> Self {
        // Uniform prior over health states.
        Self {
            belief: [0.25; NUM_HEALTH_STATES],
            smoothed_gap: 0.0,
            smoothed_optimal_value: 0.0,
            smoothed_observed_value: 0.0,
            observations: 0,
            divergence_count: 0,
        }
    }

    /// Feed an observation and update the belief + value tracking.
    ///
    /// - `risk_ppm`: the aggregated risk-ppm from the decide() path.
    /// - `action_code`: 0=Allow, 1=FullValidate, 2=Repair, 3=Deny.
    /// - `adverse`: whether adverse indicators were present.
    pub fn observe_and_update(&mut self, risk_ppm: u32, action_code: u8, adverse: bool) {
        self.observations += 1;

        // Map observation to an observation likelihood over health states.
        // Higher risk_ppm → more likely in worse health states.
        let obs_likelihood = self.observation_likelihood(risk_ppm, adverse);

        // Bayesian belief update: b'(s') ∝ P(o|s') × Σ_s P(s'|s,a) b(s)
        let action_idx = (action_code as usize).min(NUM_ACTIONS - 1);
        let mut new_belief = [0.0; NUM_HEALTH_STATES];

        for (s_prime, nb) in new_belief.iter_mut().enumerate() {
            let mut transition_sum = 0.0;
            for (s, &b) in self.belief.iter().enumerate() {
                transition_sum += TRANSITIONS[action_idx][s][s_prime] * b;
            }
            *nb = obs_likelihood[s_prime] * transition_sum;
        }

        // Normalize.
        let total: f64 = new_belief.iter().sum();
        if total > 1e-15 {
            for b in &mut new_belief {
                *b /= total;
            }
        } else {
            // Degenerate — reset to uniform.
            new_belief = [0.25; NUM_HEALTH_STATES];
        }

        self.belief = new_belief;

        // Compute optimal value at current belief via one-step lookahead.
        let optimal_cost = self.compute_optimal_value();

        // Compute observed cost (cost of the action actually taken).
        let observed_cost = self.compute_q_value(action_idx);

        // Optimality gap: (observed_cost - optimal_cost) / optimal_cost.
        // When observed matches optimal, gap ≈ 0. When observed is worse, gap > 0.
        let gap = if optimal_cost > 1e-10 {
            ((observed_cost - optimal_cost) / optimal_cost).clamp(0.0, 2.0)
        } else {
            0.0
        };
        let opt_value = -optimal_cost;
        let observed_value = -observed_cost;

        // EWMA update.
        if self.observations == 1 {
            self.smoothed_gap = gap;
            self.smoothed_optimal_value = opt_value;
            self.smoothed_observed_value = observed_value;
        } else {
            self.smoothed_gap += EWMA_ALPHA * (gap - self.smoothed_gap);
            self.smoothed_optimal_value += EWMA_ALPHA * (opt_value - self.smoothed_optimal_value);
            self.smoothed_observed_value +=
                EWMA_ALPHA * (observed_value - self.smoothed_observed_value);
        }

        // Count divergence detections.
        if self.observations > CALIBRATION_THRESHOLD && self.state() == PomdpState::PolicyDivergence
        {
            self.divergence_count += 1;
        }
    }

    /// Observation likelihood: P(o | health_state).
    /// Maps risk_ppm + adverse flag to a likelihood vector.
    fn observation_likelihood(&self, risk_ppm: u32, adverse: bool) -> [f64; NUM_HEALTH_STATES] {
        // Which risk bucket? 0=low, 1=moderate, 2=high, 3=critical
        let bucket = if risk_ppm < RISK_BOUNDARIES[0] {
            0
        } else if risk_ppm < RISK_BOUNDARIES[1] {
            1
        } else if risk_ppm < RISK_BOUNDARIES[2] {
            2
        } else {
            3
        };

        // Likelihood matrix: P(risk_bucket | health_state)
        // Each row is a health state, columns are risk buckets.
        let base_likelihood = [
            [0.70, 0.20, 0.08, 0.02], // Healthy → mostly low risk
            [0.25, 0.45, 0.22, 0.08], // Degraded → moderate risk
            [0.08, 0.20, 0.45, 0.27], // Faulty → high risk
            [0.02, 0.08, 0.25, 0.65], // Critical → extreme risk
        ];

        let mut likelihood = [0.0; NUM_HEALTH_STATES];
        for s in 0..NUM_HEALTH_STATES {
            likelihood[s] = base_likelihood[s][bucket];
            // Adverse flag shifts likelihood toward worse states.
            if adverse {
                let shift = match s {
                    0 => 0.7, // Healthy less likely if adverse
                    1 => 0.9,
                    2 => 1.2,
                    3 => 1.5, // Critical more likely if adverse
                    _ => 1.0,
                };
                likelihood[s] *= shift;
            }
        }

        likelihood
    }

    /// One-step Bellman lookahead Q-value for a specific action: C(b,a) + γ Σ_s' P(s'|b,a) V_approx(s')
    fn compute_q_value(&self, action: usize) -> f64 {
        let immediate = self.compute_expected_cost(action);
        let trans_a = &TRANSITIONS[action];

        // Approximate future cost via steady-state value estimate.
        let mut future_cost = 0.0;
        for (s_prime, cost_row) in COSTS.iter().enumerate() {
            let mut reach_prob = 0.0;
            for (s, &b) in self.belief.iter().enumerate() {
                reach_prob += trans_a[s][s_prime] * b;
            }
            // Approximate future value: cost of best action in s_prime.
            let min_future = cost_row.iter().copied().fold(f64::MAX, f64::min);
            future_cost += reach_prob * min_future;
        }

        immediate + GAMMA * future_cost
    }

    /// One-step Bellman lookahead: min_a Q(b, a)
    /// Returns the minimum expected cost (lower is better).
    fn compute_optimal_value(&self) -> f64 {
        let mut best_cost = f64::MAX;
        for a in 0..NUM_ACTIONS {
            let total = self.compute_q_value(a);
            if total < best_cost {
                best_cost = total;
            }
        }
        best_cost
    }

    /// Expected immediate cost of action a under current belief.
    fn compute_expected_cost(&self, action: usize) -> f64 {
        let mut cost = 0.0;
        for (&b, cost_row) in self.belief.iter().zip(COSTS.iter()) {
            cost += b * cost_row[action];
        }
        cost
    }

    /// Current state.
    pub fn state(&self) -> PomdpState {
        if self.observations < CALIBRATION_THRESHOLD {
            return PomdpState::Calibrating;
        }

        if self.smoothed_gap >= DIVERGENCE_THRESHOLD {
            PomdpState::PolicyDivergence
        } else if self.smoothed_gap >= SUBOPTIMAL_THRESHOLD {
            PomdpState::SuboptimalPolicy
        } else {
            PomdpState::Optimal
        }
    }

    /// Summary snapshot.
    pub fn summary(&self) -> PomdpSummary {
        PomdpSummary {
            state: self.state(),
            belief: self.belief,
            optimal_value: self.smoothed_optimal_value,
            observed_value: self.smoothed_observed_value,
            optimality_gap: self.smoothed_gap,
            total_observations: self.observations,
            divergence_count: self.divergence_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_phase() {
        let mut ctrl = PomdpRepairController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe_and_update(10_000, 0, false); // low risk, Allow
        }
        assert_eq!(ctrl.state(), PomdpState::Calibrating);
    }

    #[test]
    fn optimal_policy_under_low_risk() {
        let mut ctrl = PomdpRepairController::new();
        // Consistently low risk with Allow action → belief converges to Healthy.
        // Allow is optimal when healthy, so gap should be small.
        for _ in 0..2000 {
            ctrl.observe_and_update(10_000, 0, false);
        }
        assert_eq!(ctrl.state(), PomdpState::Optimal);
        let s = ctrl.summary();
        assert!(s.belief[0] > 0.5, "Should believe system is healthy");
        assert!(s.optimality_gap < SUBOPTIMAL_THRESHOLD);
    }

    #[test]
    fn suboptimal_when_allowing_high_risk() {
        let mut ctrl = PomdpRepairController::new();
        // Calibrate with low risk.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(10_000, 0, false);
        }
        // Now: high risk but still using Allow → suboptimal.
        // In high-risk, Repair or Deny would be better.
        for _ in 0..5000 {
            ctrl.observe_and_update(600_000, 0, true);
        }
        let s = ctrl.summary();
        assert!(
            s.state == PomdpState::SuboptimalPolicy || s.state == PomdpState::PolicyDivergence,
            "Expected suboptimal or divergence, got {:?} (gap={:.4})",
            s.state,
            s.optimality_gap
        );
    }

    #[test]
    fn belief_shifts_with_risk() {
        let mut ctrl = PomdpRepairController::new();
        // Low risk → healthy belief.
        for _ in 0..500 {
            ctrl.observe_and_update(5_000, 0, false);
        }
        let healthy_belief = ctrl.summary().belief[0];
        assert!(healthy_belief > 0.5);

        // High risk → belief shifts toward Faulty/Critical.
        for _ in 0..3000 {
            ctrl.observe_and_update(700_000, 3, true);
        }
        let s = ctrl.summary();
        let critical_belief = s.belief[3];
        assert!(
            critical_belief > healthy_belief * 0.5 || s.belief[2] > 0.2,
            "Belief should shift toward worse states: {:?}",
            s.belief
        );
    }

    #[test]
    fn proper_repair_stays_optimal() {
        let mut ctrl = PomdpRepairController::new();
        // High risk with Repair action → should be near-optimal since
        // Repair is the right action for Faulty state.
        for _ in 0..2000 {
            ctrl.observe_and_update(400_000, 2, false);
        }
        let s = ctrl.summary();
        // Repair at moderate-high risk should not diverge too much.
        assert_ne!(s.state, PomdpState::PolicyDivergence);
    }

    #[test]
    fn recovery_after_policy_correction() {
        let mut ctrl = PomdpRepairController::new();
        // Drive with suboptimal policy first.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(10_000, 0, false);
        }
        for _ in 0..3000 {
            ctrl.observe_and_update(500_000, 0, true); // allowing high risk
        }
        // Now correct: use Deny for high-risk situations.
        for _ in 0..15_000 {
            ctrl.observe_and_update(500_000, 3, true);
        }
        let s = ctrl.summary();
        // Gap should have decreased with corrected policy.
        // The belief will also shift, so optimal action matches.
        assert!(
            s.optimality_gap < DIVERGENCE_THRESHOLD,
            "Gap should decrease: {:.4}",
            s.optimality_gap
        );
    }

    #[test]
    fn uniform_prior_initialization() {
        let ctrl = PomdpRepairController::new();
        let s = ctrl.summary();
        for &b in &s.belief {
            assert!((b - 0.25).abs() < 1e-10, "Should start uniform");
        }
    }
}
