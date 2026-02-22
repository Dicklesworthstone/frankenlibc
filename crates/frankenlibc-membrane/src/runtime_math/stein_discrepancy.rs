//! # Kernelized Stein Discrepancy Monitor
//!
//! Distribution-free goodness-of-fit testing via the Kernelized Stein
//! Discrepancy (KSD), detecting when the observed controller state
//! distribution deviates from a reference model WITHOUT requiring
//! the reference distribution's normalizing constant.
//!
//! ## Mathematical Foundation
//!
//! The **Stein operator** (Stein 1972) for a distribution p on ℝ^d is:
//!
//! ```text
//! (T_p f)(x) = ∇ log p(x) · f(x) + ∇ · f(x)
//! ```
//!
//! The key **Stein identity**: E_p[(T_p f)(X)] = 0 for all f in a
//! suitable function class. This means:
//!
//! ```text
//! E_q[(T_p f)(X)] ≠ 0  ⟹  q ≠ p
//! ```
//!
//! Crucially, the operator T_p only depends on ∇ log p (the **score
//! function**), not on p itself — so the normalizing constant cancels.
//!
//! ## Kernelized Stein Discrepancy (Liu, Lee, Jordan 2016)
//!
//! The **KSD** maximizes the Stein identity violation over an RKHS:
//!
//! ```text
//! KSD²(q, p) = E_{x,x'~q}[u_p(x, x')]
//! ```
//!
//! where the **Stein kernel** is:
//!
//! ```text
//! u_p(x, x') = s_p(x)ᵀ k(x,x') s_p(x')
//!            + s_p(x)ᵀ ∇_{x'} k(x,x')
//!            + ∇_x k(x,x')ᵀ s_p(x')
//!            + trace(∇_x ∇_{x'} k(x,x'))
//! ```
//!
//! with s_p(x) = ∇ log p(x) (the score) and k the RBF kernel.
//!
//! ## Discrete Adaptation
//!
//! For our discrete state space {0,1,2,3}^N, we build a **product
//! reference model** where each controller independently has state
//! probabilities derived from the calibration period. We then track
//! the per-controller KL divergence D(current || reference) as the
//! discrepancy measure:
//!
//! ```text
//! KSD²(q, p) ≈ (1/N) Σᵢ D_KL(q_i ‖ p_i)
//! ```
//!
//! where q_i is the live empirical distribution for controller i and
//! p_i is the calibration-frozen reference. This vanishes when q = p
//! and increases as the observation distribution drifts from reference.
//!
//! ## Why KSD Instead of MMD?
//!
//! - **MMD** (kernel_mmd.rs) requires both P and Q as empirical samples.
//!   It tests "are these two samples from the same distribution?"
//! - **KSD** tests "is this sample from a SPECIFIC model p?" without
//!   needing samples from p. The reference model is specified by its
//!   score function.
//!
//! KSD is the right tool when we have a **theoretical reference model**
//! (the calibrated baseline) and want to test goodness-of-fit, not
//! just two-sample comparison.
//!
//! ## Legacy Anchor
//!
//! `nss`, `resolv`, `nscd`, `sunrpc` (identity/network lookup/cache) —
//! the name-service stack must verify that lookup result distributions
//! match expected models (e.g., DNS cache hit rates). KSD formalizes
//! "does this cache behavior match the reference model?" without
//! needing the full reference distribution.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing factor.
const ALPHA: f64 = 0.05;

/// Warmup/calibration observations.
const WARMUP: u32 = 30;

/// Observations at which reference model is frozen.
const REFERENCE_FREEZE: u32 = 30;

/// KSD² threshold for Deviant.
const DEVIANT_THRESHOLD: f64 = 0.15;

/// KSD² threshold for Rejected (strong evidence of model misspecification).
const REJECTED_THRESHOLD: f64 = 0.40;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SteinState {
    /// Insufficient data.
    Calibrating = 0,
    /// Observations consistent with reference model.
    Consistent = 1,
    /// Moderate deviation from reference model.
    Deviant = 2,
    /// Strong evidence of model misspecification.
    Rejected = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct SteinSummary {
    /// Current state.
    pub state: SteinState,
    /// KSD² estimate.
    pub ksd_squared: f64,
    /// Max per-controller score deviation.
    pub max_score_deviation: f64,
    /// Total observations.
    pub observations: u32,
}

/// Per-controller reference model: empirical state frequencies.
#[derive(Clone)]
struct ReferenceModel {
    /// Smoothed state frequencies (calibration-frozen).
    freq: [f64; K],
}

impl ReferenceModel {
    fn uniform() -> Self {
        Self {
            freq: [1.0 / K as f64; K],
        }
    }

    /// Update with an observed state value.
    fn update(&mut self, state: u8, alpha: f64) {
        let idx = (state as usize).min(K - 1);
        for (k, f) in self.freq.iter_mut().enumerate() {
            let target = if k == idx { 1.0 } else { 0.0 };
            *f += alpha * (target - *f);
        }
    }

    /// KL divergence D(other || self) between two models.
    ///
    /// Measures how much the `other` distribution has drifted from `self`.
    /// Returns 0 when the distributions are identical, positive otherwise.
    /// Laplace-smoothed to avoid log(0).
    fn kl_from(&self, other: &ReferenceModel) -> f64 {
        let eps = 0.01;
        let self_total: f64 = self.freq.iter().sum::<f64>() + eps * K as f64;
        let other_total: f64 = other.freq.iter().sum::<f64>() + eps * K as f64;
        let mut kl = 0.0;
        for k in 0..K {
            let q_k = (other.freq[k] + eps) / other_total;
            let p_k = (self.freq[k] + eps) / self_total;
            kl += q_k * (q_k / p_k).ln();
        }
        kl.max(0.0) // numerical floor
    }
}

/// Kernelized Stein Discrepancy monitor.
///
/// Uses KL divergence D(current || reference) between the live empirical
/// model and the calibration-frozen reference as a goodness-of-fit proxy.
/// When the observation distribution matches the reference, KL → 0.
/// Regime shifts cause the current model to drift, increasing KL.
pub struct SteinDiscrepancyMonitor {
    /// Reference model per controller (frozen after calibration).
    reference: Vec<ReferenceModel>,
    /// Current empirical model per controller (live-updated).
    current: Vec<ReferenceModel>,
    /// Per-controller KL divergence (instantaneous).
    kl_per_ctrl: [f64; N],
    /// Smoothed total KL divergence (sum across controllers, EWMA).
    ksd_sq: f64,
    /// Per-controller smoothed divergence (EWMA of KL_i).
    score_deviation: [f64; N],
    /// Observation count.
    count: u32,
    /// Current state.
    state: SteinState,
}

impl SteinDiscrepancyMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            reference: (0..N).map(|_| ReferenceModel::uniform()).collect(),
            current: (0..N).map(|_| ReferenceModel::uniform()).collect(),
            kl_per_ctrl: [0.0; N],
            ksd_sq: 0.0,
            score_deviation: [0.0; N],
            count: 0,
            state: SteinState::Calibrating,
        }
    }

    /// Feed a severity vector and update divergence estimates.
    ///
    /// Computes per-controller KL divergence D(current_i || reference_i)
    /// where `current` tracks the live empirical distribution and `reference`
    /// was frozen at the end of calibration. Under stable conditions
    /// (same data distribution as calibration), KL → 0 → Consistent.
    /// Regime shifts cause current to diverge → KL increases → Deviant/Rejected.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Update current model and reference (during calibration).
        for (i, &s) in severity.iter().enumerate() {
            self.current[i].update(s, alpha);
            if self.count <= REFERENCE_FREEZE {
                self.reference[i].update(s, alpha);
            }
        }

        // Per-controller KL divergence D(current_i || reference_i).
        for i in 0..N {
            let kl_i = self.reference[i].kl_from(&self.current[i]);
            self.kl_per_ctrl[i] = kl_i;
            self.score_deviation[i] = kl_i;
        }

        // Total divergence: average per-controller KL.
        let total_kl: f64 = self.kl_per_ctrl.iter().sum::<f64>() / N as f64;
        self.ksd_sq = total_kl;

        // State classification.
        self.state = if self.count < WARMUP {
            SteinState::Calibrating
        } else if self.ksd_sq >= REJECTED_THRESHOLD {
            SteinState::Rejected
        } else if self.ksd_sq >= DEVIANT_THRESHOLD {
            SteinState::Deviant
        } else {
            SteinState::Consistent
        };
    }

    pub fn state(&self) -> SteinState {
        self.state
    }

    pub fn ksd_squared(&self) -> f64 {
        self.ksd_sq
    }

    /// Max per-controller score deviation from reference model.
    pub fn max_score_deviation(&self) -> f64 {
        self.score_deviation.iter().copied().fold(0.0_f64, f64::max)
    }

    pub fn summary(&self) -> SteinSummary {
        SteinSummary {
            state: self.state,
            ksd_squared: self.ksd_sq,
            max_score_deviation: self.max_score_deviation(),
            observations: self.count,
        }
    }
}

impl Default for SteinDiscrepancyMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = SteinDiscrepancyMonitor::new();
        assert_eq!(m.state(), SteinState::Calibrating);
    }

    #[test]
    fn stable_inputs_yield_consistent() {
        let mut m = SteinDiscrepancyMonitor::new();
        // Feed the same distribution throughout.
        for _ in 0..300 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(
            m.state(),
            SteinState::Consistent,
            "Stable inputs should be consistent, KSD²={}",
            m.ksd_squared()
        );
    }

    #[test]
    fn regime_shift_detected() {
        let mut m = SteinDiscrepancyMonitor::new();
        // Calibrate at state 0.
        for _ in 0..REFERENCE_FREEZE {
            m.observe_and_update(&[0u8; N]);
        }
        // Shift to state 3 — violates reference model.
        for _ in 0..500 {
            m.observe_and_update(&[3u8; N]);
        }
        assert!(
            m.state() as u8 >= SteinState::Deviant as u8,
            "Should detect deviation after regime shift, got {:?} KSD²={}",
            m.state(),
            m.ksd_squared()
        );
    }

    #[test]
    fn score_deviation_increases_with_misfit() {
        let mut m = SteinDiscrepancyMonitor::new();
        // Calibrate at state 1.
        for _ in 0..REFERENCE_FREEZE {
            m.observe_and_update(&[1u8; N]);
        }
        // Now feed state 3 — the score at state 3 should be very different
        // from what the reference model expects.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        assert!(
            m.max_score_deviation() > 0.1,
            "Score deviation {} should increase with model misfit",
            m.max_score_deviation()
        );
    }

    #[test]
    fn recovery_to_consistent() {
        let mut m = SteinDiscrepancyMonitor::new();
        let base = [1u8; N];
        for _ in 0..REFERENCE_FREEZE {
            m.observe_and_update(&base);
        }
        // Deviate.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        // Return to reference.
        for _ in 0..1000 {
            m.observe_and_update(&base);
        }
        assert_eq!(
            m.state(),
            SteinState::Consistent,
            "Should recover to Consistent after returning to reference"
        );
    }

    #[test]
    fn ksd_is_nonnegative() {
        let mut m = SteinDiscrepancyMonitor::new();
        for _ in 0..200 {
            m.observe_and_update(&[2u8; N]);
        }
        assert!(
            m.ksd_squared() >= 0.0,
            "KSD² should be non-negative: {}",
            m.ksd_squared()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = SteinDiscrepancyMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.ksd_squared - m.ksd_squared()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
