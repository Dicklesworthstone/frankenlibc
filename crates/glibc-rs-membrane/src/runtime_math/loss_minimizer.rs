//! Decision-theoretic loss minimization for hardened repair policy selection.
//!
//! **Math item #4**: proper scoring rules / decision-theoretic loss minimization.
//!
//! Implements an online loss-minimization framework that learns the expected loss
//! of each membrane action (allow, full-validate, repair, deny) using proper
//! scoring rules and EWMA-smoothed empirical loss tracking.
//!
//! The loss function for each action computes regret as:
//!
//! ```text
//! loss(action, adverse, cost_ns) = cost_component + adverse_penalty - benefit
//! ```
//!
//! - **Allow** (action 0): near-zero cost if no adverse event, high penalty if
//!   adverse (uncaught bad operation).
//! - **Full-validate** (action 1): moderate cost always (validation overhead),
//!   low penalty if adverse (caught by validation).
//! - **Repair** (action 2): moderate cost (repair overhead), very low adverse
//!   penalty (repairs succeed and fix the issue).
//! - **Deny** (action 3): zero adverse risk, but high opportunity cost (blocks
//!   valid operations regardless).
//!
//! The controller tracks per-action EWMA-smoothed empirical loss and recommends
//! the action with the lowest current expected loss. A state machine monitors
//! whether the system is balanced across actions or exhibits systematic bias.

#![deny(unsafe_code)]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of observations required before leaving `Calibrating`.
const WARMUP_COUNT: u64 = 32;

/// EWMA smoothing factor for per-action loss tracking.
const EWMA_ALPHA: f64 = 0.05;

/// Cost normalization divisor: maps nanosecond costs to [0, ~1] range.
/// 1000 ns is a reasonable upper bound for typical validation overhead.
const COST_NORM_NS: f64 = 1000.0;

/// Adverse penalty for Allow action (uncaught adverse event).
const ALLOW_ADVERSE_PENALTY: f64 = 10.0;

/// Benefit for Allow action when no adverse event (zero overhead).
const ALLOW_BENEFIT: f64 = 0.8;

/// Fixed cost component for Full-Validate action (validation overhead).
const VALIDATE_FIXED_COST: f64 = 0.5;

/// Adverse penalty for Full-Validate action (caught by validation).
const VALIDATE_ADVERSE_PENALTY: f64 = 1.0;

/// Fixed cost component for Repair action (repair overhead).
const REPAIR_FIXED_COST: f64 = 0.6;

/// Adverse penalty for Repair action (repair succeeds).
const REPAIR_ADVERSE_PENALTY: f64 = 0.3;

/// Cost scaling factor for Repair action.
const REPAIR_COST_FACTOR: f64 = 0.35;

/// Fixed opportunity cost for Deny action (blocks valid operations).
const DENY_OPPORTUNITY_COST: f64 = 1.5;

/// Cost scaling factor for Deny under adverse conditions.
/// Lower than repair because deny avoids most processing overhead.
const DENY_ADVERSE_COST_FACTOR: f64 = 0.10;

/// Threshold ratio between highest and lowest loss EWMA for bias detection.
/// When one action's loss EWMA exceeds another by this factor, the system
/// is considered biased toward the low-loss action.
const BIAS_RATIO: f64 = 2.5;

/// Absolute loss threshold: when all action losses exceed this, the system
/// is in a cost explosion state.
const COST_EXPLOSION_THRESHOLD: f64 = 2.0;

/// Number of tracked actions: Allow=0, FullValidate=1, Repair=2, Deny=3.
const NUM_ACTIONS: usize = 4;

// ---------------------------------------------------------------------------
// State enum
// ---------------------------------------------------------------------------

/// Qualitative state of the loss minimization controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossState {
    /// Fewer than `WARMUP_COUNT` observations received.
    Calibrating,
    /// All action losses are within a reasonable ratio of each other.
    Balanced,
    /// Repair action has substantially lower loss than others (repair-biased).
    RepairBiased,
    /// Deny action has substantially lower loss than others (deny-biased).
    DenyBiased,
    /// All action losses exceed `COST_EXPLOSION_THRESHOLD` simultaneously.
    CostExplosion,
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Point-in-time summary of the loss minimization controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LossSummary {
    /// Current qualitative state.
    pub state: LossState,
    /// Currently recommended action (0=allow, 1=full-validate, 2=repair, 3=deny).
    pub recommended_action: u8,
    /// EWMA-smoothed loss for the Repair action.
    pub repair_loss_ewma: f64,
    /// EWMA-smoothed loss for the Deny action.
    pub deny_loss_ewma: f64,
    /// EWMA-smoothed loss for the Allow action.
    pub allow_loss_ewma: f64,
    /// Total observations fed to the controller.
    pub total_decisions: u64,
    /// Number of times `CostExplosion` state was entered.
    pub cost_explosion_count: u64,
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

/// Online loss minimization controller for hardened repair policy selection.
///
/// Maintains EWMA-smoothed empirical loss for each membrane action and
/// recommends the action with the lowest expected loss. Monitors for
/// systematic bias and cost explosion conditions.
pub struct LossMinimizationController {
    /// Per-action EWMA-smoothed loss: [allow, full_validate, repair, deny].
    loss_ewma: [f64; NUM_ACTIONS],
    /// Per-action observation count.
    action_counts: [u64; NUM_ACTIONS],
    /// Total observations received.
    total_decisions: u64,
    /// Number of times `CostExplosion` state was entered.
    cost_explosion_count: u64,
    /// Current qualitative state.
    state: LossState,
}

impl LossMinimizationController {
    /// Create a new controller in the `Calibrating` state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            loss_ewma: [0.0; NUM_ACTIONS],
            action_counts: [0; NUM_ACTIONS],
            total_decisions: 0,
            cost_explosion_count: 0,
            state: LossState::Calibrating,
        }
    }

    /// Feed one observation: the action taken, whether an adverse event
    /// occurred, and the estimated cost in nanoseconds.
    ///
    /// This method:
    /// 1. Computes the counterfactual loss for every action (not just the
    ///    one taken) so that the controller learns about all policies.
    /// 2. Updates EWMA for every action.
    /// 3. Recomputes state based on loss relationships.
    pub fn observe(&mut self, action_taken: u8, adverse: bool, estimated_cost_ns: u64) {
        self.total_decisions += 1;

        let action_idx = (action_taken as usize).min(NUM_ACTIONS - 1);
        self.action_counts[action_idx] += 1;

        let cost_norm = (estimated_cost_ns as f64) / COST_NORM_NS;

        // Compute counterfactual loss for each action under the observed outcome.
        let losses = compute_action_losses(adverse, cost_norm);

        // Update EWMA for all actions.
        for (i, loss) in losses.iter().enumerate().take(NUM_ACTIONS) {
            self.loss_ewma[i] = EWMA_ALPHA * *loss + (1.0 - EWMA_ALPHA) * self.loss_ewma[i];
        }

        // Determine state based on current loss landscape.
        let prev_state = self.state;
        self.state = self.classify_state();

        // Increment cost explosion counter on *entry* to CostExplosion state.
        if self.state == LossState::CostExplosion && prev_state != LossState::CostExplosion {
            self.cost_explosion_count += 1;
        }
    }

    /// Current qualitative state.
    #[must_use]
    pub fn state(&self) -> LossState {
        self.state
    }

    /// Point-in-time summary.
    #[must_use]
    pub fn summary(&self) -> LossSummary {
        LossSummary {
            state: self.state,
            recommended_action: self.recommended_action(),
            repair_loss_ewma: self.loss_ewma[2],
            deny_loss_ewma: self.loss_ewma[3],
            allow_loss_ewma: self.loss_ewma[0],
            total_decisions: self.total_decisions,
            cost_explosion_count: self.cost_explosion_count,
        }
    }

    /// Recommend the action with the lowest current expected loss.
    ///
    /// Returns: 0=allow, 1=full-validate, 2=repair, 3=deny.
    #[must_use]
    pub fn recommended_action(&self) -> u8 {
        if self.total_decisions < WARMUP_COUNT {
            // During calibration, default to full-validate (safest exploratory action).
            return 1;
        }

        let mut best_action = 0_u8;
        let mut best_loss = self.loss_ewma[0];
        for i in 1..NUM_ACTIONS {
            if self.loss_ewma[i] < best_loss {
                best_loss = self.loss_ewma[i];
                best_action = i as u8;
            }
        }
        best_action
    }

    /// Classify the current state based on the loss landscape.
    fn classify_state(&self) -> LossState {
        if self.total_decisions < WARMUP_COUNT {
            return LossState::Calibrating;
        }

        // Check for cost explosion: all losses above threshold.
        let all_above = self.loss_ewma.iter().all(|&l| l > COST_EXPLOSION_THRESHOLD);
        if all_above {
            return LossState::CostExplosion;
        }

        // Find min and max losses.
        let min_loss = self.loss_ewma.iter().copied().fold(f64::INFINITY, f64::min);
        let max_loss = self
            .loss_ewma
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);

        // Check for bias: is one action dramatically better than others?
        if min_loss > 0.0 && max_loss / min_loss > BIAS_RATIO {
            // Find which action has the lowest loss.
            let best_action = self
                .loss_ewma
                .iter()
                .enumerate()
                .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(core::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(0);

            return match best_action {
                2 => LossState::RepairBiased,
                3 => LossState::DenyBiased,
                _ => LossState::Balanced,
            };
        }

        LossState::Balanced
    }
}

impl Default for LossMinimizationController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute the counterfactual loss for each action given the observed outcome.
///
/// Returns `[allow_loss, validate_loss, repair_loss, deny_loss]`.
fn compute_action_losses(adverse: bool, cost_norm: f64) -> [f64; NUM_ACTIONS] {
    let cost_component = cost_norm.min(10.0); // cap to prevent unbounded growth

    let allow_loss = if adverse {
        cost_component + ALLOW_ADVERSE_PENALTY
    } else {
        (cost_component * 0.1).max(0.0) // minimal cost for allow, no adverse
    };
    // Subtract benefit for allowing a clean operation.
    let allow_loss = if adverse {
        allow_loss
    } else {
        (allow_loss - ALLOW_BENEFIT).max(0.0)
    };

    let validate_loss = VALIDATE_FIXED_COST
        + cost_component * 0.3
        + if adverse {
            VALIDATE_ADVERSE_PENALTY
        } else {
            0.0
        };

    let repair_loss = REPAIR_FIXED_COST
        + cost_component * REPAIR_COST_FACTOR
        + if adverse { REPAIR_ADVERSE_PENALTY } else { 0.0 };

    // Deny has a fixed opportunity cost plus a small cost-proportional
    // component under adverse conditions (investigation/retry overhead).
    // The cost factor is lower than repair because deny avoids most
    // processing overhead by blocking the operation entirely.
    let deny_loss = DENY_OPPORTUNITY_COST
        + if adverse {
            cost_component * DENY_ADVERSE_COST_FACTOR
        } else {
            0.0
        };

    [allow_loss, validate_loss, repair_loss, deny_loss]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = LossMinimizationController::new();
        assert_eq!(ctrl.state(), LossState::Calibrating);
        let s = ctrl.summary();
        assert_eq!(s.state, LossState::Calibrating);
        assert_eq!(s.total_decisions, 0);
        assert_eq!(s.cost_explosion_count, 0);
        // During calibration, recommended action defaults to full-validate.
        assert_eq!(s.recommended_action, 1);
    }

    #[test]
    fn balanced_under_uniform_outcomes() {
        let mut ctrl = LossMinimizationController::new();
        // Feed a mix of actions with low cost and no adverse events.
        // This should produce a balanced loss landscape.
        for i in 0..200_u64 {
            let action = (i % 4) as u8;
            ctrl.observe(action, false, 50);
        }
        assert_eq!(
            ctrl.state(),
            LossState::Balanced,
            "Expected Balanced with uniform clean traffic, got {:?}",
            ctrl.state(),
        );
    }

    #[test]
    fn repair_bias_detection() {
        let mut ctrl = LossMinimizationController::new();
        // Feed heavy adverse traffic: repair action has the lowest loss
        // because its adverse penalty is much lower than allow/validate.
        for _ in 0..500 {
            ctrl.observe(2, true, 500);
        }
        // Under heavy adverse conditions, repair should dominate.
        // The state should detect this as repair-biased.
        let s = ctrl.summary();
        assert!(
            s.repair_loss_ewma < s.allow_loss_ewma,
            "repair loss {:.4} should be below allow loss {:.4} under adverse traffic",
            s.repair_loss_ewma,
            s.allow_loss_ewma,
        );
        // Repair should be the recommended action.
        assert_eq!(
            s.recommended_action, 2,
            "recommended action should be repair (2) under heavy adverse, got {}",
            s.recommended_action,
        );
    }

    #[test]
    fn deny_bias_detection() {
        let mut ctrl = LossMinimizationController::new();
        // Feed a mix of mostly adverse traffic with moderate costs.
        // Under these conditions, deny has the lowest EWMA because its
        // cost factor is smaller than repair/validate, but the costs are
        // moderate enough that not all actions exceed the explosion threshold.
        for i in 0..500_u64 {
            let adverse = i % 5 != 0; // 80% adverse
            ctrl.observe(3, adverse, 3000);
        }
        let s = ctrl.summary();
        assert!(
            s.deny_loss_ewma < s.allow_loss_ewma,
            "deny loss {:.4} should be below allow loss {:.4} under moderate adverse costs",
            s.deny_loss_ewma,
            s.allow_loss_ewma,
        );
        assert_eq!(
            s.state,
            LossState::DenyBiased,
            "Expected DenyBiased under moderate-cost adverse traffic, got {:?}",
            s.state,
        );
    }

    #[test]
    fn cost_explosion_detection() {
        let mut ctrl = LossMinimizationController::new();
        // Feed a mix of all actions with extreme costs and adverse events.
        // This should push all EWMA values above the cost explosion threshold.
        for i in 0..1000_u64 {
            let action = (i % 4) as u8;
            ctrl.observe(action, true, 500_000);
        }
        let s = ctrl.summary();
        // All loss EWMAs should be elevated.
        assert!(
            s.repair_loss_ewma > COST_EXPLOSION_THRESHOLD,
            "repair_loss_ewma {:.4} should exceed explosion threshold {:.4}",
            s.repair_loss_ewma,
            COST_EXPLOSION_THRESHOLD,
        );
        assert!(
            s.deny_loss_ewma > COST_EXPLOSION_THRESHOLD,
            "deny_loss_ewma {:.4} should exceed explosion threshold {:.4}",
            s.deny_loss_ewma,
            COST_EXPLOSION_THRESHOLD,
        );
        assert_eq!(
            s.state,
            LossState::CostExplosion,
            "Expected CostExplosion state, got {:?}",
            s.state,
        );
        assert!(
            s.cost_explosion_count >= 1,
            "Expected at least 1 cost explosion entry, got {}",
            s.cost_explosion_count,
        );
    }

    #[test]
    fn recommendation_changes_with_conditions() {
        let mut ctrl = LossMinimizationController::new();

        // Phase 1: clean traffic, low cost — allow should dominate.
        for _ in 0..200 {
            ctrl.observe(0, false, 10);
        }
        let rec_clean = ctrl.recommended_action();

        // Phase 2: heavy adverse traffic — repair should become preferred.
        for _ in 0..500 {
            ctrl.observe(2, true, 300);
        }
        let rec_adverse = ctrl.recommended_action();

        // Recommendation should change between the two phases.
        // Allow (0) is best under clean; repair (2) is best under adverse.
        assert_ne!(
            rec_clean, rec_adverse,
            "recommendation should change between clean and adverse phases \
            (clean={}, adverse={})",
            rec_clean, rec_adverse,
        );
    }

    #[test]
    fn loss_values_bounded() {
        let mut ctrl = LossMinimizationController::new();
        for i in 0..500_u64 {
            let action = (i % 4) as u8;
            let adverse = i % 7 == 0;
            ctrl.observe(action, adverse, (i * 10) % 2000);
        }
        let s = ctrl.summary();

        // All loss EWMAs should be non-negative.
        assert!(
            s.allow_loss_ewma >= 0.0,
            "allow_loss_ewma should be non-negative: {}",
            s.allow_loss_ewma,
        );
        assert!(
            s.repair_loss_ewma >= 0.0,
            "repair_loss_ewma should be non-negative: {}",
            s.repair_loss_ewma,
        );
        assert!(
            s.deny_loss_ewma >= 0.0,
            "deny_loss_ewma should be non-negative: {}",
            s.deny_loss_ewma,
        );

        // Loss EWMAs should not be astronomical (bounded by loss function design).
        assert!(
            s.allow_loss_ewma < 50.0,
            "allow_loss_ewma {} seems unbounded",
            s.allow_loss_ewma,
        );
        assert!(
            s.repair_loss_ewma < 50.0,
            "repair_loss_ewma {} seems unbounded",
            s.repair_loss_ewma,
        );
        assert!(
            s.deny_loss_ewma < 50.0,
            "deny_loss_ewma {} seems unbounded",
            s.deny_loss_ewma,
        );

        assert_eq!(s.total_decisions, 500);
        assert!(s.recommended_action <= 3);
    }

    #[test]
    fn default_impl_matches_new() {
        let from_new = LossMinimizationController::new();
        let from_default = LossMinimizationController::default();
        assert_eq!(from_new.state(), from_default.state());
        assert_eq!(
            from_new.summary().total_decisions,
            from_default.summary().total_decisions,
        );
        assert_eq!(
            from_new.summary().recommended_action,
            from_default.summary().recommended_action,
        );
    }
}
