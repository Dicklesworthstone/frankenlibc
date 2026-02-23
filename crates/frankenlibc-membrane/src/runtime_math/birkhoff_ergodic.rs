//! # Birkhoff Ergodic Convergence Monitor
//!
//! Tracks whether the time-average of severity converges to the ensemble
//! average, detecting non-ergodic behavior where the system becomes
//! trapped in a subset of states.
//!
//! ## Mathematical Foundation
//!
//! **Birkhoff's Ergodic Theorem** (Birkhoff 1931): For a measure-preserving
//! transformation T on a probability space and integrable f:
//!
//! ```text
//! (1/n) Σ_{k=0}^{n-1} f(T^k x) → f*(x)  a.s.
//! ```
//!
//! where f* is T-invariant. For ergodic systems, f* = E[f] = const,
//! so the time average converges to the spatial (ensemble) average.
//!
//! **Key insight:** If the time average is NOT converging, the system
//! is non-ergodic — it's trapped in a proper subset of its state space.
//!
//! ## Convergence Rate
//!
//! For ergodic Markov chains with spectral gap δ:
//!
//! ```text
//! |(1/n) Σ f(X_k) - E[f]| = O(1/√(nδ))
//! ```
//!
//! We monitor the convergence rate by comparing the time average at
//! different time scales. If the difference between short-window and
//! long-window time averages doesn't shrink, convergence has stalled.
//!
//! ## Why Birkhoff Ergodic Convergence?
//!
//! - **Dobrushin**: measures mixing SPEED (contraction coefficient).
//! - **Spectral gap**: measures λ₂ (algebraic mixing rate).
//! - **Birkhoff**: measures whether convergence is ACTUALLY HAPPENING.
//!
//! You can have fast theoretical mixing (small Dobrushin coefficient)
//! but empirically observe non-convergence if the system is in a
//! transient regime that hasn't yet reached the mixing timescale.
//! Birkhoff convergence is the EMPIRICAL test: is the observed time
//! average stabilizing?
//!
//! ## Online Estimation
//!
//! Per controller i:
//! 1. Maintain short-window EWMA (fast, α_fast) and long-window EWMA
//!    (slow, α_slow).
//! 2. Convergence gap = |fast_mean - slow_mean|.
//! 3. If gap is shrinking, system is converging (ergodic).
//! 4. If gap is stable or growing, system is non-ergodic.
//!
//! Aggregate: maximum convergence gap across controllers.
//!
//! ## Legacy Anchor
//!
//! `pthread` scheduling — POSIX requires "fair" scheduling where each
//! thread eventually gets CPU time. This is an ergodicity requirement:
//! the time-average CPU fraction for each thread should converge to
//! the ensemble average (1/N for N equal-priority threads). If the
//! Birkhoff convergence stalls, some threads are being starved — the
//! scheduler is non-ergodic.

/// Number of base controllers.
const N: usize = 25;

/// Fast EWMA smoothing parameter (short window).
const ALPHA_FAST: f64 = 0.15;

/// Slow EWMA smoothing parameter (long window).
const ALPHA_SLOW: f64 = 0.01;

/// EWMA for smoothing the convergence gap.
const ALPHA_GAP: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 60;

/// Gap threshold for SlowConvergence state.
const SLOW_CONVERGENCE_THRESHOLD: f64 = 0.30;

/// Gap threshold for NonErgodic state.
const NON_ERGODIC_THRESHOLD: f64 = 0.80;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErgodicState {
    /// Insufficient data.
    Calibrating = 0,
    /// Time average converging to ensemble average — ergodic.
    Ergodic = 1,
    /// Convergence is slow — system near non-ergodic boundary.
    SlowConvergence = 2,
    /// Time average not converging — non-ergodic, trapped in states.
    NonErgodic = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct ErgodicSummary {
    /// Current state.
    pub state: ErgodicState,
    /// Maximum convergence gap across controllers (0..∞).
    pub max_convergence_gap: f64,
    /// Mean convergence gap across controllers.
    pub mean_convergence_gap: f64,
    /// Total observations.
    pub observations: u32,
}

/// Birkhoff ergodic convergence monitor.
pub struct BirkhoffErgodicMonitor {
    /// Per-controller fast EWMA (short window).
    fast_mean: [f64; N],
    /// Per-controller slow EWMA (long window).
    slow_mean: [f64; N],
    /// Observation count.
    count: u32,
    /// Smoothed max convergence gap.
    max_convergence_gap: f64,
    /// Smoothed mean convergence gap.
    mean_convergence_gap: f64,
    /// Current state.
    state: ErgodicState,
}

impl BirkhoffErgodicMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fast_mean: [0.0; N],
            slow_mean: [0.0; N],
            count: 0,
            max_convergence_gap: 0.0,
            mean_convergence_gap: 0.0,
            state: ErgodicState::Calibrating,
        }
    }

    /// Feed a severity vector and update ergodic convergence estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);

        let mut max_gap = 0.0_f64;
        let mut sum_gap = 0.0_f64;

        for (i, &sev) in severity.iter().enumerate() {
            let x = sev.min(3) as f64;

            if self.count == 1 {
                self.fast_mean[i] = x;
                self.slow_mean[i] = x;
            } else {
                // Update dual-timescale EWMAs.
                self.fast_mean[i] += ALPHA_FAST * (x - self.fast_mean[i]);
                self.slow_mean[i] += ALPHA_SLOW * (x - self.slow_mean[i]);
            }

            // Convergence gap: normalized by max possible range (3.0).
            let gap = (self.fast_mean[i] - self.slow_mean[i]).abs() / 3.0;
            max_gap = max_gap.max(gap);
            sum_gap += gap;
        }

        let mean_gap = sum_gap / N as f64;

        if self.count == 1 {
            self.max_convergence_gap = max_gap;
            self.mean_convergence_gap = mean_gap;
        } else {
            // EWMA smooth the convergence gap.
            self.max_convergence_gap += ALPHA_GAP * (max_gap - self.max_convergence_gap);
            self.mean_convergence_gap += ALPHA_GAP * (mean_gap - self.mean_convergence_gap);
        }

        // State classification.
        self.state = if self.count < WARMUP {
            ErgodicState::Calibrating
        } else if self.max_convergence_gap >= NON_ERGODIC_THRESHOLD {
            ErgodicState::NonErgodic
        } else if self.max_convergence_gap >= SLOW_CONVERGENCE_THRESHOLD {
            ErgodicState::SlowConvergence
        } else {
            ErgodicState::Ergodic
        };
    }

    pub fn state(&self) -> ErgodicState {
        self.state
    }

    pub fn max_convergence_gap(&self) -> f64 {
        self.max_convergence_gap
    }

    pub fn mean_convergence_gap(&self) -> f64 {
        self.mean_convergence_gap
    }

    pub fn summary(&self) -> ErgodicSummary {
        ErgodicSummary {
            state: self.state,
            max_convergence_gap: self.max_convergence_gap,
            mean_convergence_gap: self.mean_convergence_gap,
            observations: self.count,
        }
    }
}

impl Default for BirkhoffErgodicMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = BirkhoffErgodicMonitor::new();
        assert_eq!(m.state(), ErgodicState::Calibrating);
    }

    #[test]
    fn constant_input_is_ergodic() {
        let mut m = BirkhoffErgodicMonitor::new();
        // Constant severity — both EWMAs converge to same value.
        for _ in 0..500 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            m.state(),
            ErgodicState::Ergodic,
            "Constant input should be Ergodic, gap={}",
            m.max_convergence_gap()
        );
    }

    #[test]
    fn stable_random_is_ergodic() {
        let mut m = BirkhoffErgodicMonitor::new();
        let mut rng = 42u64;
        for _ in 0..1000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            ErgodicState::Ergodic,
            "Stable random should be Ergodic, gap={}",
            m.max_convergence_gap()
        );
    }

    #[test]
    fn sudden_shift_detected() {
        let mut m = BirkhoffErgodicMonitor::new();
        // Establish steady state at severity 0.
        for _ in 0..300 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(m.state(), ErgodicState::Ergodic);
        // Sudden shift to severity 3 — fast mean jumps, slow lags.
        for _ in 0..50 {
            m.observe_and_update(&[3u8; N]);
        }
        // The gap should have increased.
        assert!(
            m.max_convergence_gap() > 0.0,
            "Sudden shift should increase gap: {}",
            m.max_convergence_gap()
        );
    }

    #[test]
    fn recovery_to_ergodic() {
        let mut m = BirkhoffErgodicMonitor::new();
        // Start low.
        for _ in 0..200 {
            m.observe_and_update(&[0u8; N]);
        }
        // Shift high.
        for _ in 0..100 {
            m.observe_and_update(&[3u8; N]);
        }
        // Then stabilize at 3 for a long time — both EWMAs converge.
        for _ in 0..2000 {
            m.observe_and_update(&[3u8; N]);
        }
        assert_eq!(
            m.state(),
            ErgodicState::Ergodic,
            "Should recover to Ergodic, gap={}",
            m.max_convergence_gap()
        );
    }

    #[test]
    fn gap_nonnegative() {
        let mut m = BirkhoffErgodicMonitor::new();
        for i in 0u32..300 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_convergence_gap() >= 0.0,
            "Gap must be non-negative: {}",
            m.max_convergence_gap()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = BirkhoffErgodicMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_convergence_gap - m.max_convergence_gap()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
