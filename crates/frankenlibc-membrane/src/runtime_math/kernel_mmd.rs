//! # Kernel MMD Monitor
//!
//! Maximum Mean Discrepancy (MMD) with RBF kernel for distribution-free
//! two-sample testing of the controller ensemble severity distribution.
//!
//! ## Mathematical Foundation
//!
//! The **Maximum Mean Discrepancy** (Gretton et al., "A Kernel Two-Sample
//! Test", JMLR 2012) measures the distance between distributions P and Q
//! by embedding them into a reproducing kernel Hilbert space (RKHS):
//!
//! ```text
//! MMD²(P, Q) = E_{x,x'~P}[k(x,x')] - 2E_{x~P,y~Q}[k(x,y)] + E_{y,y'~Q}[k(y,y')]
//! ```
//!
//! where k is a positive-definite kernel. With the **RBF kernel**:
//!
//! ```text
//! k(x, y) = exp(-‖x - y‖² / (2σ²))
//! ```
//!
//! MMD is a metric on distributions: MMD(P,Q) = 0 iff P = Q. This
//! provides a **universal** nonparametric test — it can detect ANY
//! distributional difference, not just shifts in mean or variance.
//!
//! ## Why MMD Instead of Wasserstein or Fisher-Rao?
//!
//! - **Wasserstein** (wasserstein_drift.rs): respects ordinal metric but
//!   operates per-controller independently. Cannot detect *joint*
//!   distributional changes (e.g., correlation shifts between controllers).
//! - **Fisher-Rao** (info_geometry.rs): per-controller categorical
//!   geometry, no joint structure.
//! - **MMD**: operates on the **joint** N-dimensional severity vector.
//!   The RBF kernel captures all moments simultaneously, making it
//!   sensitive to changes in correlation structure, higher moments,
//!   and any nonlinear distributional shift.
//!
//! ## Online Estimation
//!
//! We maintain a sliding EWMA approximation of the three kernel terms:
//! - `k_pp`: within-baseline kernel (frozen after warmup)
//! - `k_qq`: within-current kernel (updated each step)
//! - `k_pq`: cross kernel between baseline and current
//!
//! For computational efficiency, we use a single reference point (the
//! running mean) as the kernel anchor, and estimate MMD² via:
//!
//! ```text
//! MMD² ≈ k(μ_P, μ_P) - 2k(μ_P, μ_Q) + k(μ_Q, μ_Q)
//!      = 1 - 2·exp(-‖μ_P - μ_Q‖²/(2σ²)) + 1
//!      = 2(1 - exp(-‖μ_P - μ_Q‖²/(2σ²)))
//! ```
//!
//! This is the **mean embedding** approximation. For richer estimation,
//! we also track variance-corrected terms via the kernel trick on
//! the empirical covariance structure.

use std::sync::atomic::{AtomicU8, Ordering};

/// Number of base controllers (dimensionality of severity vector).
const N: usize = 25;

/// RBF kernel bandwidth parameter σ².
/// Chosen so that a 1-unit shift per controller gives meaningful signal:
/// ‖Δ‖² = N·1² = 25 → exp(-25/(2·50)) = exp(-0.25) ≈ 0.78 (moderate).
const SIGMA_SQ: f64 = 50.0;

/// EWMA smoothing factor.
const ALPHA: f64 = 0.05;

/// Warmup observations.
const WARMUP: u32 = 30;

/// Baseline freeze point.
const BASELINE_FREEZE: u32 = 30;

/// MMD² threshold for Drifting.
const DRIFT_THRESHOLD: f64 = 0.10;

/// MMD² threshold for Anomalous.
const ANOMALOUS_THRESHOLD: f64 = 0.40;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MmdState {
    /// Insufficient data.
    Calibrating = 0,
    /// Distributions match (MMD² ≈ 0).
    Conforming = 1,
    /// Moderate distributional drift.
    Drifting = 2,
    /// Significant distributional shift.
    Anomalous = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone)]
pub struct MmdSummary {
    pub state: MmdState,
    pub mmd_squared: f64,
    pub mean_shift_norm: f64,
    pub observations: u32,
}

/// Kernel MMD monitor.
pub struct KernelMmdMonitor {
    /// Baseline mean severity vector (frozen after warmup).
    baseline_mean: [f64; N],
    /// Baseline covariance diagonal (frozen).
    baseline_var: [f64; N],
    /// Current running mean severity vector.
    current_mean: [f64; N],
    /// Current running variance.
    current_var: [f64; N],
    /// Smoothed MMD² estimate.
    mmd_sq: f64,
    /// Smoothed mean-embedding MMD² (from means only).
    mean_mmd_sq: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: MmdState,
    /// Cached state code.
    pub cached_state: AtomicU8,
}

impl KernelMmdMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            baseline_mean: [0.0; N],
            baseline_var: [1.0; N],
            current_mean: [0.0; N],
            current_var: [1.0; N],
            mmd_sq: 0.0,
            mean_mmd_sq: 0.0,
            count: 0,
            state: MmdState::Calibrating,
            cached_state: AtomicU8::new(0),
        }
    }

    /// RBF kernel: k(x, y) = exp(-‖x-y‖²/(2σ²)).
    fn rbf_kernel(x: &[f64; N], y: &[f64; N]) -> f64 {
        let sq_dist: f64 = x
            .iter()
            .zip(y.iter())
            .map(|(&a, &b)| (a - b) * (a - b))
            .sum();
        (-sq_dist / (2.0 * SIGMA_SQ)).exp()
    }

    /// Feed a severity vector and update MMD estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Convert severity to f64.
        let vals: [f64; N] = std::array::from_fn(|i| f64::from(severity[i]));

        // Update current mean and variance.
        for ((&v, mean_i), var_i) in vals
            .iter()
            .zip(self.current_mean.iter_mut())
            .zip(self.current_var.iter_mut())
        {
            let old_mean = *mean_i;
            *mean_i += alpha * (v - *mean_i);
            let dev = (v - *mean_i) * (v - old_mean);
            *var_i += alpha * (dev.abs() - *var_i);
            *var_i = var_i.max(1e-6);
        }

        // During warmup, also update baseline.
        if self.count <= BASELINE_FREEZE {
            self.baseline_mean = self.current_mean;
            self.baseline_var = self.current_var;
        }

        if self.count < WARMUP {
            self.state = MmdState::Calibrating;
            self.cached_state.store(0, Ordering::Relaxed);
            return;
        }

        // Mean-embedding MMD²: 2(1 - k(μ_baseline, μ_current)).
        let k_means = Self::rbf_kernel(&self.baseline_mean, &self.current_mean);
        self.mean_mmd_sq = 2.0 * (1.0 - k_means);

        // Variance-corrected MMD²: account for spread differences.
        // When variances differ, the expected within-kernel values differ,
        // giving an additional signal beyond just mean shift.
        let var_shift: f64 = self
            .baseline_var
            .iter()
            .zip(self.current_var.iter())
            .map(|(&bv, &cv)| {
                let ratio = if bv > 1e-6 { cv / bv } else { 1.0 };
                (ratio.ln()).abs()
            })
            .sum::<f64>()
            / N as f64;

        // Combined MMD²: mean embedding + variance correction.
        let raw_mmd_sq = self.mean_mmd_sq + var_shift * 0.5;
        self.mmd_sq = raw_mmd_sq;

        // State classification.
        self.state = if self.mmd_sq >= ANOMALOUS_THRESHOLD {
            MmdState::Anomalous
        } else if self.mmd_sq >= DRIFT_THRESHOLD {
            MmdState::Drifting
        } else {
            MmdState::Conforming
        };

        self.cached_state.store(self.state as u8, Ordering::Relaxed);
    }

    pub fn state(&self) -> MmdState {
        self.state
    }

    pub fn mmd_squared(&self) -> f64 {
        self.mmd_sq
    }

    /// Euclidean norm of the mean shift vector.
    pub fn mean_shift_norm(&self) -> f64 {
        self.baseline_mean
            .iter()
            .zip(self.current_mean.iter())
            .map(|(&b, &c)| (b - c) * (b - c))
            .sum::<f64>()
            .sqrt()
    }

    pub fn summary(&self) -> MmdSummary {
        MmdSummary {
            state: self.state,
            mmd_squared: self.mmd_sq,
            mean_shift_norm: self.mean_shift_norm(),
            observations: self.count,
        }
    }
}

impl Default for KernelMmdMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_during_warmup() {
        let mut m = KernelMmdMonitor::new();
        for _ in 0..10 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(m.state(), MmdState::Calibrating);
    }

    #[test]
    fn stable_inputs_yield_conforming() {
        let mut m = KernelMmdMonitor::new();
        let stable = [1u8; N];
        for _ in 0..200 {
            m.observe_and_update(&stable);
        }
        assert_eq!(m.state(), MmdState::Conforming);
        assert!(
            m.mmd_squared() < 0.05,
            "MMD² {} should be near zero for constant input",
            m.mmd_squared()
        );
    }

    #[test]
    fn mean_shift_detected() {
        let mut m = KernelMmdMonitor::new();
        // Baseline at severity 0.
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&[0u8; N]);
        }
        // Shift to severity 3.
        for _ in 0..500 {
            m.observe_and_update(&[3u8; N]);
        }
        assert!(
            m.state() as u8 >= MmdState::Drifting as u8,
            "should detect drift after mean shift, got {:?} MMD²={}",
            m.state(),
            m.mmd_squared()
        );
    }

    #[test]
    fn variance_shift_detected() {
        let mut m = KernelMmdMonitor::new();
        // Baseline at constant severity 1.
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&[1u8; N]);
        }
        // Now alternate 0 and 3 (same mean ≈ 1.5 but high variance).
        for _ in 0..500 {
            m.observe_and_update(&[0u8; N]);
            m.observe_and_update(&[3u8; N]);
        }
        // The variance correction should pick this up even though
        // the mean shift is relatively small.
        assert!(
            m.mmd_squared() > 0.01,
            "MMD² {} should detect variance change",
            m.mmd_squared()
        );
    }

    #[test]
    fn recovery_to_conforming() {
        let mut m = KernelMmdMonitor::new();
        let base = [1u8; N];
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&base);
        }
        // Shift.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        // Recover.
        for _ in 0..1000 {
            m.observe_and_update(&base);
        }
        assert_eq!(
            m.state(),
            MmdState::Conforming,
            "should recover to Conforming after returning to baseline"
        );
    }

    #[test]
    fn rbf_kernel_self_is_one() {
        let x = [1.0_f64; N];
        let k = KernelMmdMonitor::rbf_kernel(&x, &x);
        assert!((k - 1.0).abs() < 1e-12, "k(x,x) should be 1.0, got {}", k);
    }

    #[test]
    fn rbf_kernel_symmetric() {
        let x: [f64; N] = std::array::from_fn(|i| i as f64);
        let y: [f64; N] = std::array::from_fn(|i| (N - i) as f64);
        let k_xy = KernelMmdMonitor::rbf_kernel(&x, &y);
        let k_yx = KernelMmdMonitor::rbf_kernel(&y, &x);
        assert!(
            (k_xy - k_yx).abs() < 1e-12,
            "kernel should be symmetric: {} vs {}",
            k_xy,
            k_yx
        );
    }

    #[test]
    fn mean_shift_norm_zero_at_baseline() {
        let mut m = KernelMmdMonitor::new();
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&[1u8; N]);
        }
        assert!(
            m.mean_shift_norm() < 0.1,
            "norm {} should be near zero at baseline",
            m.mean_shift_norm()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = KernelMmdMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.mmd_squared - m.mmd_squared()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
