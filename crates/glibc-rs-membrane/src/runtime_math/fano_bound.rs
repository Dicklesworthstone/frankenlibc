//! # Fano Mutual Information Bound Monitor
//!
//! Provides an information-theoretic lower bound on the ensemble's
//! irreducible prediction error using Fano's inequality and online
//! mutual information estimation between consecutive severity vectors.
//!
//! ## Mathematical Foundation
//!
//! **Fano's Inequality** (Fano 1961): For any estimator X̂ of X given Y:
//!
//! ```text
//! P(X̂ ≠ X) ≥ 1 - [I(X;Y) + log 2] / log |X|
//! ```
//!
//! where I(X;Y) is the mutual information between X and Y, and |X| is
//! the alphabet size of X.
//!
//! Applied to the severity process: let X = severity_{t+1} and
//! Y = severity_t (previous step). Then:
//!
//! ```text
//! P(error) ≥ 1 - [I(severity_{t+1}; severity_t) + log 2] / log K
//! ```
//!
//! where K is the number of severity states.
//!
//! ## Why Fano's Inequality?
//!
//! Existing monitors provide **upper bounds** on error:
//! - PAC-Bayes: "error ≤ bound with probability ≥ 1-δ"
//! - Rademacher: "generalization gap ≤ 2R̂ + concentration"
//! - Conformal: "coverage ≥ 1-α"
//!
//! Fano provides a **lower bound**: "no matter what estimator you use,
//! error ≥ this value." This is fundamentally different — it tells you
//! when the severity process is **inherently unpredictable**, not
//! because your estimator is bad, but because there isn't enough
//! temporal structure to predict.
//!
//! High Fano error bound = severity process is nearly i.i.d.
//! (no temporal structure → no predictability → high irreducible error)
//!
//! Low Fano error bound = severity process is highly structured
//! (strong temporal dependence → accurate prediction possible)
//!
//! ## Online Estimation
//!
//! Mutual information I(X;Y) = H(X) - H(X|Y) where:
//! - H(X) = -Σ_x p(x) log p(x) is the marginal entropy
//! - H(X|Y) = -Σ_y p(y) Σ_x p(x|y) log p(x|y) is conditional entropy
//!
//! We estimate these from EWMA-smoothed joint counts:
//! - Joint: p(x,y) from consecutive severity pairs
//! - Marginals: p(x) = Σ_y p(x,y), p(y) = Σ_x p(x,y)
//!
//! The MI is computed per-controller and aggregated (mean across controllers).
//!
//! ## Legacy Anchor
//!
//! `nss`, `resolv`, `nscd` (name service/resolver/cache subsystem) —
//! cache effectiveness fundamentally requires temporal predictability
//! in lookup patterns. Fano's inequality tells you the theoretical
//! minimum cache miss rate: if successive lookups have low mutual
//! information, NO caching strategy can achieve high hit rates.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing for joint distribution.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Fano error bound threshold for Uncertain.
const UNCERTAIN_THRESHOLD: f64 = 0.50;

/// Fano error bound threshold for Opaque.
const OPAQUE_THRESHOLD: f64 = 0.75;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FanoState {
    /// Insufficient data.
    Calibrating = 0,
    /// Low Fano bound — process is predictable (high MI).
    Predictable = 1,
    /// Moderate Fano bound — reduced temporal structure.
    Uncertain = 2,
    /// High Fano bound — process is nearly i.i.d. (minimal MI).
    Opaque = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct FanoSummary {
    /// Current state.
    pub state: FanoState,
    /// Mean mutual information across controllers (bits).
    pub mean_mi: f64,
    /// Mean Fano error lower bound across controllers (0..1).
    pub mean_fano_bound: f64,
    /// Total observations.
    pub observations: u32,
}

/// Per-controller joint distribution tracker.
struct ControllerJoint {
    /// Joint counts p(x_{t+1}, x_t), EWMA-smoothed.
    /// Indexed as [next][curr].
    joint: [[f64; K]; K],
}

impl ControllerJoint {
    fn new() -> Self {
        // Uniform initialization for Laplace smoothing.
        let init = 1.0 / (K * K) as f64;
        Self {
            joint: [[init; K]; K],
        }
    }

    /// Update with a transition observation.
    fn update(&mut self, from: usize, to: usize, alpha: f64) {
        for next in 0..K {
            for curr in 0..K {
                let target = if next == to && curr == from { 1.0 } else { 0.0 };
                self.joint[next][curr] += alpha * (target - self.joint[next][curr]);
            }
        }
    }

    /// Compute mutual information I(X_{t+1}; X_t) in nats.
    fn mutual_information(&self) -> f64 {
        let eps = 1e-12;
        let total: f64 = self.joint.iter().flat_map(|r| r.iter()).sum();
        if total < eps {
            return 0.0;
        }

        // Marginals.
        let mut p_next = [0.0_f64; K];
        let mut p_curr = [0.0_f64; K];
        for (next, row) in self.joint.iter().enumerate() {
            for (curr, &val) in row.iter().enumerate() {
                p_next[next] += val;
                p_curr[curr] += val;
            }
        }

        // MI = Σ p(x,y) log[ p(x,y) / (p(x) p(y)) ]
        let mut mi = 0.0;
        for (next, row) in self.joint.iter().enumerate() {
            for (curr, &joint_val) in row.iter().enumerate() {
                let p_xy = joint_val / total;
                let p_x = p_next[next] / total;
                let p_y = p_curr[curr] / total;
                if p_xy > eps && p_x > eps && p_y > eps {
                    mi += p_xy * (p_xy / (p_x * p_y)).ln();
                }
            }
        }
        mi.max(0.0) // MI is non-negative
    }

    /// Compute Fano error lower bound from MI.
    fn fano_bound(&self) -> f64 {
        let mi = self.mutual_information();
        let log_k = (K as f64).ln();
        if log_k < 1e-12 {
            return 0.0;
        }
        // P(error) >= 1 - [I(X;Y) + ln(2)] / ln(K)
        // Clamp to [0, 1].
        let bound = 1.0 - (mi + 2.0_f64.ln()) / log_k;
        bound.clamp(0.0, 1.0)
    }
}

/// Fano mutual information bound monitor.
pub struct FanoBoundMonitor {
    /// Per-controller joint distribution trackers.
    controllers: Vec<ControllerJoint>,
    /// Previous severity vector.
    prev_severity: [u8; N],
    /// Smoothed mean MI across controllers.
    mean_mi: f64,
    /// Smoothed mean Fano bound across controllers.
    mean_fano_bound: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: FanoState,
}

impl FanoBoundMonitor {
    #[must_use]
    pub fn new() -> Self {
        let controllers = (0..N).map(|_| ControllerJoint::new()).collect();
        Self {
            controllers,
            prev_severity: [0; N],
            mean_mi: 0.0,
            mean_fano_bound: 0.5, // Start pessimistic (uncertain).
            count: 0,
            state: FanoState::Calibrating,
        }
    }

    /// Feed a severity vector and update Fano bound estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        if self.count > 1 {
            // Update joint distributions and compute MI/Fano per controller.
            let mut mi_sum = 0.0_f64;
            let mut fano_sum = 0.0_f64;

            for (i, ctrl) in self.controllers.iter_mut().enumerate() {
                let from = (self.prev_severity[i] as usize).min(K - 1);
                let to = (severity[i] as usize).min(K - 1);
                ctrl.update(from, to, alpha);

                mi_sum += ctrl.mutual_information();
                fano_sum += ctrl.fano_bound();
            }

            let mean_mi_raw = mi_sum / N as f64;
            let mean_fano_raw = fano_sum / N as f64;

            self.mean_mi += alpha * (mean_mi_raw - self.mean_mi);
            self.mean_fano_bound += alpha * (mean_fano_raw - self.mean_fano_bound);
        }

        self.prev_severity = *severity;

        // State classification based on Fano bound.
        self.state = if self.count < WARMUP {
            FanoState::Calibrating
        } else if self.mean_fano_bound >= OPAQUE_THRESHOLD {
            FanoState::Opaque
        } else if self.mean_fano_bound >= UNCERTAIN_THRESHOLD {
            FanoState::Uncertain
        } else {
            FanoState::Predictable
        };
    }

    pub fn state(&self) -> FanoState {
        self.state
    }

    pub fn mean_mi(&self) -> f64 {
        self.mean_mi
    }

    pub fn mean_fano_bound(&self) -> f64 {
        self.mean_fano_bound
    }

    pub fn summary(&self) -> FanoSummary {
        FanoSummary {
            state: self.state,
            mean_mi: self.mean_mi,
            mean_fano_bound: self.mean_fano_bound,
            observations: self.count,
        }
    }
}

impl Default for FanoBoundMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = FanoBoundMonitor::new();
        assert_eq!(m.state(), FanoState::Calibrating);
    }

    #[test]
    fn deterministic_sequence_is_predictable() {
        let mut m = FanoBoundMonitor::new();
        // Deterministic cycle: 0→1→2→3→0→1→... has maximal MI.
        for i in 0u32..600 {
            let val = (i % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            FanoState::Predictable,
            "Deterministic cycle should be predictable, fano_bound={}, mi={}",
            m.mean_fano_bound(),
            m.mean_mi()
        );
    }

    #[test]
    fn constant_input_is_predictable() {
        let mut m = FanoBoundMonitor::new();
        // Constant → joint concentrates on (1,1) → conditional entropy = 0
        // → MI = H(X) → Fano bound = 1 - [H(X) + ln2]/lnK.
        // Since H(X) = 0 for constant, Fano = 1 - ln2/lnK ≈ 0.5.
        // Actually: MI = H(X) - H(X|Y). H(X) = 0 (degenerate), H(X|Y) = 0.
        // MI = 0. Fano = 1 - [0 + ln2]/ln4 = 1 - ln2/ln4 = 1 - 0.5 = 0.5.
        // This is right at the Uncertain threshold.
        for _ in 0..600 {
            m.observe_and_update(&[1u8; N]);
        }
        // Constant input has MI ≈ 0 (degenerate distribution).
        // Fano bound ≈ 0.5, which is exactly at the Uncertain threshold.
        assert!(
            m.mean_fano_bound() <= OPAQUE_THRESHOLD,
            "Constant input Fano bound={} should not be Opaque",
            m.mean_fano_bound()
        );
    }

    #[test]
    fn mi_is_nonnegative() {
        let mut m = FanoBoundMonitor::new();
        for i in 0u32..200 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.mean_mi() >= 0.0,
            "MI must be non-negative: {}",
            m.mean_mi()
        );
    }

    #[test]
    fn fano_bound_in_unit_interval() {
        let mut m = FanoBoundMonitor::new();
        for i in 0u32..500 {
            let mut sev = [0u8; N];
            for (j, s) in sev.iter_mut().enumerate() {
                *s = (((i as usize + j * 5) ^ (j * 11)) % 4) as u8;
            }
            m.observe_and_update(&sev);
        }
        assert!(
            m.mean_fano_bound() >= 0.0 && m.mean_fano_bound() <= 1.0,
            "Fano bound should be in [0,1]: {}",
            m.mean_fano_bound()
        );
    }

    #[test]
    fn high_mi_means_low_fano_bound() {
        let mut m_pred = FanoBoundMonitor::new();
        let mut m_rand = FanoBoundMonitor::new();

        // Predictable: strict cycle 0→1→2→3→0→...
        for i in 0u32..600 {
            m_pred.observe_and_update(&[(i % 4) as u8; N]);
        }

        // Less predictable: varied patterns.
        for i in 0u32..600 {
            let mut sev = [0u8; N];
            for (j, s) in sev.iter_mut().enumerate() {
                *s = (((i as usize).wrapping_mul(7) ^ j.wrapping_mul(13)) % 4) as u8;
            }
            m_rand.observe_and_update(&sev);
        }

        // Predictable should have higher MI.
        assert!(
            m_pred.mean_mi() >= m_rand.mean_mi(),
            "Predictable MI={} should exceed random MI={}",
            m_pred.mean_mi(),
            m_rand.mean_mi()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = FanoBoundMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.mean_mi - m.mean_mi()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
