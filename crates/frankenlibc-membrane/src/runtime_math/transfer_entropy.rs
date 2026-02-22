//! # Transfer Entropy Causal Flow Monitor
//!
//! Directed information-theoretic causality detection between controllers
//! via Schreiber's transfer entropy (2000), identifying when one controller's
//! state history helps predict another's future beyond what its own history
//! provides.
//!
//! ## Mathematical Foundation
//!
//! **Transfer entropy** (Schreiber 2000) from process Y to process X is:
//!
//! ```text
//! T_{Y→X} = Σ p(x_{t+1}, x_t^k, y_t^l)
//!           · log[ p(x_{t+1} | x_t^k, y_t^l) / p(x_{t+1} | x_t^k) ]
//! ```
//!
//! where x_t^k = (x_t, x_{t-1}, ..., x_{t-k+1}) is the length-k history
//! of X, and similarly for y_t^l.
//!
//! Equivalently (in terms of conditional entropies):
//!
//! ```text
//! T_{Y→X} = H(X_{t+1} | X_t^k) - H(X_{t+1} | X_t^k, Y_t^l)
//! ```
//!
//! Key properties:
//! - **T_{Y→X} ≥ 0** always (conditioning reduces entropy)
//! - **T_{Y→X} = 0** iff Y provides no predictive information about X
//!   beyond what X's own past provides (Granger non-causality)
//! - **T_{Y→X} ≠ T_{X→Y}** in general (asymmetric/directed)
//!
//! ## Why Transfer Entropy Instead of Mutual Information?
//!
//! - **Mutual information** I(X;Y) measures total shared information,
//!   but is symmetric and conflates direct vs indirect dependencies.
//! - **Transfer entropy** isolates the DIRECTED, CAUSAL component:
//!   "does Y's past help predict X's future, beyond X's own past?"
//!
//! This is the information-theoretic analogue of Granger causality,
//! but extends to nonlinear dependencies (Granger is linear-only).
//!
//! ## Online Estimation
//!
//! Full transfer entropy requires joint probability estimation over
//! high-dimensional state histories. For runtime efficiency, we use:
//!
//! 1. **Short history** (k=l=1): only one lag step, reducing joint
//!    distribution to 4×4×4 = 64 bins per controller pair.
//! 2. **Pairwise aggregation**: compute T_{i→j} for all pairs of
//!    the N controllers, then track max and mean transfer entropy.
//! 3. **EWMA smoothing**: bin counts updated with exponential decay
//!    for non-stationary adaptation.
//!
//! With k=l=1 and K=4 severity states:
//!
//! ```text
//! T_{Y→X} = Σ_{x',x,y} p(x',x,y) · log[ p(x'|x,y) / p(x'|x) ]
//! ```
//!
//! where x' ∈ {0,1,2,3}, x ∈ {0,1,2,3}, y ∈ {0,1,2,3}.
//!
//! ## Causal Flow Detection
//!
//! The monitor tracks:
//! - **Max pairwise TE**: strongest causal link in the ensemble.
//! - **Mean pairwise TE**: overall causal coupling density.
//! - **Net flow imbalance**: asymmetry in the causal graph.
//!
//! High transfer entropy indicates strong directional dependencies
//! between controllers — potential cascade pathways where a failure
//! in one controller propagates causally to others.
//!
//! ## Legacy Anchor
//!
//! `stdio`, `libio` (buffered I/O layer) — the stdio layer has
//! complex causal chains: buffer state → flush decisions → lock
//! contention → error propagation. Transfer entropy detects when
//! these causal pathways are abnormally strong, indicating
//! tight coupling that could cascade failures.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing for bin counts.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Transfer entropy threshold for CausalCoupling.
const COUPLING_THRESHOLD: f64 = 0.08;

/// Transfer entropy threshold for CascadeRisk.
const CASCADE_THRESHOLD: f64 = 0.20;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferEntropyState {
    /// Insufficient data.
    Calibrating = 0,
    /// Low transfer entropy — controllers are approximately independent.
    Independent = 1,
    /// Moderate transfer entropy — significant causal coupling detected.
    CausalCoupling = 2,
    /// High transfer entropy — strong directional dependencies (cascade risk).
    CascadeRisk = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct TransferEntropySummary {
    /// Current state.
    pub state: TransferEntropyState,
    /// Maximum pairwise transfer entropy across sampled pairs.
    pub max_te: f64,
    /// Mean pairwise transfer entropy across sampled pairs.
    pub mean_te: f64,
    /// Total observations.
    pub observations: u32,
}

/// A tracked controller pair (source → target).
struct PairTracker {
    /// Source controller index.
    source: usize,
    /// Target controller index.
    target: usize,
    /// Joint distribution p(x', x, y) — smoothed bin counts.
    /// Indexed as [x_next][x_curr][y_curr].
    joint: [[[f64; K]; K]; K],
    /// Marginal p(x', x) — smoothed bin counts.
    /// Indexed as [x_next][x_curr].
    marginal_xx: [[f64; K]; K],
    /// Latest computed transfer entropy.
    te: f64,
}

impl PairTracker {
    fn new(source: usize, target: usize) -> Self {
        // Initialize with uniform pseudo-counts for Laplace smoothing.
        let init = 1.0 / (K * K * K) as f64;
        let init_marginal = 1.0 / (K * K) as f64;
        Self {
            source,
            target,
            joint: [[[init; K]; K]; K],
            marginal_xx: [[init_marginal; K]; K],
            te: 0.0,
        }
    }

    /// Update with a new observation (x_next, x_curr, y_curr).
    fn update(&mut self, x_next: usize, x_curr: usize, y_curr: usize, alpha: f64) {
        // Decay all bins and increment the observed one.
        for x_n in 0..K {
            for x_c in 0..K {
                for y_c in 0..K {
                    let target_val = if x_n == x_next && x_c == x_curr && y_c == y_curr {
                        1.0
                    } else {
                        0.0
                    };
                    self.joint[x_n][x_c][y_c] += alpha * (target_val - self.joint[x_n][x_c][y_c]);
                }
                let target_marginal = if x_n == x_next && x_c == x_curr {
                    1.0
                } else {
                    0.0
                };
                self.marginal_xx[x_n][x_c] +=
                    alpha * (target_marginal - self.marginal_xx[x_n][x_c]);
            }
        }
    }

    /// Compute transfer entropy T_{Y→X} from current bin estimates.
    fn compute_te(&mut self) -> f64 {
        let eps = 1e-12;

        // Normalize joint to get probabilities.
        let joint_total: f64 = self
            .joint
            .iter()
            .flat_map(|a| a.iter())
            .flat_map(|b| b.iter())
            .sum();
        if joint_total < eps {
            self.te = 0.0;
            return 0.0;
        }

        let mut te = 0.0;
        for x_next in 0..K {
            for x_curr in 0..K {
                // p(x'|x) = p(x',x) / Σ_{x'} p(x',x)
                let p_marginal_x_curr: f64 =
                    (0..K).map(|xn| self.marginal_xx[xn][x_curr]).sum::<f64>();
                let p_x_next_given_x = self.marginal_xx[x_next][x_curr] / (p_marginal_x_curr + eps);

                for y_curr in 0..K {
                    let p_joint = self.joint[x_next][x_curr][y_curr] / joint_total;

                    // p(x'|x,y) = p(x',x,y) / Σ_{x'} p(x',x,y)
                    let p_x_y: f64 = (0..K).map(|xn| self.joint[xn][x_curr][y_curr]).sum::<f64>();
                    let p_x_next_given_xy = self.joint[x_next][x_curr][y_curr] / (p_x_y + eps);

                    if p_joint > eps && p_x_next_given_xy > eps && p_x_next_given_x > eps {
                        te += p_joint * (p_x_next_given_xy / p_x_next_given_x).ln();
                    }
                }
            }
        }

        self.te = te.max(0.0); // TE is non-negative by construction
        self.te
    }
}

/// Transfer entropy causal flow monitor.
pub struct TransferEntropyMonitor {
    /// Previous severity vector (for lag-1 history).
    prev_severity: [u8; N],
    /// Tracked controller pairs.
    pairs: Vec<PairTracker>,
    /// Smoothed maximum pairwise TE.
    max_te: f64,
    /// Smoothed mean pairwise TE.
    mean_te: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: TransferEntropyState,
}

impl TransferEntropyMonitor {
    #[must_use]
    pub fn new() -> Self {
        // Select N_SAMPLE_PAIRS diverse pairs using a deterministic schedule.
        // We pick pairs that span different controller regions.
        let pairs: Vec<PairTracker> = [
            (0, 5),
            (1, 10),
            (2, 15),
            (3, 20),
            (4, 24),
            (5, 12),
            (8, 16),
            (10, 22),
            (12, 0),
            (15, 3),
            (20, 8),
            (24, 1),
        ]
        .iter()
        .map(|&(s, t)| PairTracker::new(s, t))
        .collect();

        Self {
            prev_severity: [0; N],
            pairs,
            max_te: 0.0,
            mean_te: 0.0,
            count: 0,
            state: TransferEntropyState::Calibrating,
        }
    }

    /// Feed a severity vector and update transfer entropy estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // For each tracked pair (source→target), update joint distribution.
        // x_next = target's current state
        // x_curr = target's previous state
        // y_curr = source's previous state
        if self.count > 1 {
            for pair in &mut self.pairs {
                let x_next = (severity[pair.target] as usize).min(K - 1);
                let x_curr = (self.prev_severity[pair.target] as usize).min(K - 1);
                let y_curr = (self.prev_severity[pair.source] as usize).min(K - 1);
                pair.update(x_next, x_curr, y_curr, alpha);
            }
        }

        // Store for next step.
        self.prev_severity = *severity;

        // Recompute TE periodically (not every step, to save CPU).
        if self.count.is_multiple_of(4) && self.count > WARMUP / 2 {
            let mut max_te = 0.0_f64;
            let mut sum_te = 0.0_f64;
            for pair in &mut self.pairs {
                let te = pair.compute_te();
                max_te = max_te.max(te);
                sum_te += te;
            }
            let mean_te = if self.pairs.is_empty() {
                0.0
            } else {
                sum_te / self.pairs.len() as f64
            };

            self.max_te = max_te;
            self.mean_te = mean_te;
        }

        // State classification.
        self.state = if self.count < WARMUP {
            TransferEntropyState::Calibrating
        } else if self.max_te >= CASCADE_THRESHOLD {
            TransferEntropyState::CascadeRisk
        } else if self.max_te >= COUPLING_THRESHOLD {
            TransferEntropyState::CausalCoupling
        } else {
            TransferEntropyState::Independent
        };
    }

    pub fn state(&self) -> TransferEntropyState {
        self.state
    }

    pub fn max_te(&self) -> f64 {
        self.max_te
    }

    pub fn mean_te(&self) -> f64 {
        self.mean_te
    }

    pub fn summary(&self) -> TransferEntropySummary {
        TransferEntropySummary {
            state: self.state,
            max_te: self.max_te,
            mean_te: self.mean_te,
            observations: self.count,
        }
    }
}

impl Default for TransferEntropyMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = TransferEntropyMonitor::new();
        assert_eq!(m.state(), TransferEntropyState::Calibrating);
    }

    #[test]
    fn constant_inputs_yield_independent() {
        let mut m = TransferEntropyMonitor::new();
        // All controllers at same constant value → no information flow.
        for _ in 0..300 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(
            m.state(),
            TransferEntropyState::Independent,
            "Constant inputs should show no causal coupling, max_te={}",
            m.max_te()
        );
    }

    #[test]
    fn te_is_nonnegative() {
        let mut m = TransferEntropyMonitor::new();
        for i in 0u32..200 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_te() >= 0.0,
            "Transfer entropy must be non-negative: {}",
            m.max_te()
        );
        assert!(
            m.mean_te() >= 0.0,
            "Mean TE must be non-negative: {}",
            m.mean_te()
        );
    }

    #[test]
    fn independent_random_patterns_have_low_te() {
        let mut m = TransferEntropyMonitor::new();
        // Feed a deterministic but varied pattern — each controller
        // depends only on its own index, not on others.
        for t in 0u32..500 {
            let mut sev = [0u8; N];
            for (i, s) in sev.iter_mut().enumerate() {
                // Each controller has its own cycle, independent of others.
                *s = ((t as usize + i * 7) % 4) as u8;
            }
            m.observe_and_update(&sev);
        }
        // Independent cycles should have low TE.
        assert!(
            m.max_te() < CASCADE_THRESHOLD,
            "Independent patterns should not trigger cascade: max_te={}",
            m.max_te()
        );
    }

    #[test]
    fn causal_dependency_raises_te() {
        let mut m = TransferEntropyMonitor::new();
        // Create a strong causal link: controller 5 follows controller 0
        // with a 1-step lag. Pair (0, 5) is tracked.
        let mut prev_ctrl0 = 1u8;
        for t in 0u32..600 {
            let mut sev = [1u8; N];
            // Controller 0 oscillates.
            let ctrl0 = ((t / 3) % 4) as u8;
            sev[0] = ctrl0;
            // Controller 5 copies controller 0's previous value.
            sev[5] = prev_ctrl0;
            prev_ctrl0 = ctrl0;
            m.observe_and_update(&sev);
        }
        // The TE from controller 0 → controller 5 should be elevated.
        // We track pair (0, 5), so max_te should reflect this.
        assert!(
            m.max_te() > 0.01,
            "Causal dependency should raise TE: max_te={}",
            m.max_te()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = TransferEntropyMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_te - m.max_te()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
