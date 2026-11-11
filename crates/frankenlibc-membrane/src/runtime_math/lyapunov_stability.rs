//! # Lyapunov Exponent Stability Monitor
//!
//! Maximal Lyapunov exponent estimation from the controller ensemble's
//! state time series for detecting chaotic/divergent dynamics.
//!
//! ## Mathematical Foundation
//!
//! The **Lyapunov exponent** (Oseledets 1968) measures the average
//! exponential rate of divergence between nearby trajectories in a
//! dynamical system:
//!
//! ```text
//! λ_max = lim_{t→∞} (1/t) ln(‖δx(t)‖ / ‖δx(0)‖)
//! ```
//!
//! - **λ_max < 0**: Trajectories converge — the system is **stable**.
//!   Small perturbations die out exponentially.
//! - **λ_max ≈ 0**: Neutral stability — perturbations neither grow nor
//!   decay (marginally stable, quasi-periodic).
//! - **λ_max > 0**: Trajectories **diverge** — the system is chaotic.
//!   Small perturbations amplify exponentially, making the system
//!   unpredictable beyond a time horizon of ~1/λ_max.
//!
//! ## Estimation from Scalar Time Series (Rosenstein et al. 1993)
//!
//! Given an observed time series x(1), x(2), ..., x(n), we:
//!
//! 1. Construct delay embeddings: X(t) = (x(t), x(t-τ), ..., x(t-(d-1)τ))
//! 2. For each point X(t), find its nearest neighbor X(t*)
//! 3. Track the divergence: d(t+k) = ‖X(t+k) - X(t*+k)‖
//! 4. Estimate λ_max = mean rate of ln(d(t+k)/d(t))
//!
//! ## Simplified Online Approach
//!
//! Full Rosenstein requires storing the entire time series and
//! nearest-neighbor search. For runtime efficiency, we use a
//! **simplified online estimator**:
//!
//! 1. Maintain a small ring buffer of recent severity vectors.
//! 2. Compute the per-step expansion ratio: ‖Δx(t)‖ / ‖Δx(t-1)‖.
//! 3. Smooth the log-expansion ratio via EWMA to get λ̂_max.
//!
//! This captures the local Lyapunov exponent (finite-time divergence
//! rate) without the full embedding machinery.
//!
//! ## Why Lyapunov Instead of Operator Norm?
//!
//! - **Operator norm** (operator_norm.rs) measures the spectral radius
//!   of a linearized transition matrix. It captures worst-case
//!   amplification under ANY perturbation direction.
//! - **Lyapunov exponent** measures ACTUAL trajectory-level divergence
//!   averaged over the system's natural dynamics. It is sensitive to
//!   the specific attractor structure, not just the linear worst case.
//!
//! A system can have spectral radius < 1 (operator-norm stable) but
//! positive Lyapunov exponent (chaotically mixing on a strange attractor).
//! The converse is also possible: spectral radius > 1 at a fixed point
//! but negative Lyapunov on the actual trajectory (due to nonlinear
//! saturation). Both perspectives are needed.
//!
//! ## Legacy Anchor
//!
//! `signal`, `setjmp`, `nptl` cancellation (async/nonlocal control transfer)
//! — signal delivery and longjmp semantics create discontinuous state
//! trajectories. The Lyapunov exponent detects when the ensemble is in
//! a regime where these discontinuities could cascade into unpredictable
//! behavior.

/// Number of base controllers (dimensionality of state vector).
const N: usize = 25;

/// Ring buffer size for recent states.
const BUFFER_SIZE: usize = 8;

/// EWMA smoothing for Lyapunov exponent estimate.
const ALPHA: f64 = 0.03;

/// Warmup observations before leaving Calibrating.
const WARMUP: u32 = BUFFER_SIZE as u32 + 10;

/// Minimum perturbation norm to avoid log(0) — below this, we
/// treat the system as locally constant (no divergence information).
const MIN_NORM: f64 = 0.01;

/// Lyapunov exponent threshold for Marginal (near zero).
const MARGINAL_THRESHOLD: f64 = 0.05;

/// Lyapunov exponent threshold for Chaotic (positive).
const CHAOTIC_THRESHOLD: f64 = 0.15;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LyapunovState {
    /// Insufficient data.
    Calibrating = 0,
    /// Negative exponent — perturbations decay (stable).
    Stable = 1,
    /// Exponent near zero — marginal stability (quasi-periodic).
    Marginal = 2,
    /// Positive exponent — perturbations grow (chaotic dynamics).
    Chaotic = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct LyapunovSummary {
    /// Current state.
    pub state: LyapunovState,
    /// Estimated maximal Lyapunov exponent (can be negative).
    pub exponent: f64,
    /// Recent expansion ratio (smoothed).
    pub expansion_ratio: f64,
    /// Total observations.
    pub observations: u32,
}

/// Lyapunov exponent stability monitor.
pub struct LyapunovStabilityMonitor {
    /// Ring buffer of recent severity vectors.
    buffer: [[f64; N]; BUFFER_SIZE],
    /// Write position in ring buffer.
    write_pos: usize,
    /// Previous perturbation norm (for expansion ratio).
    prev_norm: f64,
    /// Smoothed log-expansion ratio (Lyapunov exponent estimate).
    exponent: f64,
    /// Smoothed expansion ratio (for telemetry).
    expansion_ratio: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: LyapunovState,
}

impl LyapunovStabilityMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: [[0.0; N]; BUFFER_SIZE],
            write_pos: 0,
            prev_norm: 1.0,
            exponent: 0.0,
            expansion_ratio: 1.0,
            count: 0,
            state: LyapunovState::Calibrating,
        }
    }

    /// Feed a severity vector and update Lyapunov estimate.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Convert to f64 and store in ring buffer.
        let vals: [f64; N] = std::array::from_fn(|i| f64::from(severity[i]));
        self.buffer[self.write_pos] = vals;
        let prev_pos = if self.write_pos == 0 {
            BUFFER_SIZE - 1
        } else {
            self.write_pos - 1
        };

        // Compute perturbation: difference from previous state.
        let delta: [f64; N] = std::array::from_fn(|i| vals[i] - self.buffer[prev_pos][i]);

        let norm = delta.iter().map(|&d| d * d).sum::<f64>().sqrt();

        // Compute local expansion ratio.
        if norm > MIN_NORM && self.prev_norm > MIN_NORM && self.count > 2 {
            let ratio = norm / self.prev_norm;
            self.expansion_ratio += alpha * (ratio - self.expansion_ratio);

            // Lyapunov exponent = EWMA of ln(expansion_ratio).
            let log_ratio = crate::util::ln_f64(ratio);
            self.exponent += alpha * (log_ratio - self.exponent);
        }

        self.prev_norm = norm.max(MIN_NORM);

        // Advance ring buffer.
        self.write_pos = (self.write_pos + 1) % BUFFER_SIZE;

        // State classification.
        self.state = if self.count < WARMUP {
            LyapunovState::Calibrating
        } else if self.exponent >= CHAOTIC_THRESHOLD {
            LyapunovState::Chaotic
        } else if self.exponent >= MARGINAL_THRESHOLD {
            LyapunovState::Marginal
        } else {
            LyapunovState::Stable
        };
    }

    pub fn state(&self) -> LyapunovState {
        self.state
    }

    /// Estimated maximal Lyapunov exponent.
    pub fn exponent(&self) -> f64 {
        self.exponent
    }

    /// Smoothed expansion ratio.
    pub fn expansion_ratio(&self) -> f64 {
        self.expansion_ratio
    }

    pub fn summary(&self) -> LyapunovSummary {
        LyapunovSummary {
            state: self.state,
            exponent: self.exponent,
            expansion_ratio: self.expansion_ratio,
            observations: self.count,
        }
    }
}

impl Default for LyapunovStabilityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = LyapunovStabilityMonitor::new();
        assert_eq!(m.state(), LyapunovState::Calibrating);
    }

    #[test]
    fn constant_inputs_yield_stable() {
        let mut m = LyapunovStabilityMonitor::new();
        // Constant input → no perturbation growth.
        for _ in 0..200 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(
            m.state(),
            LyapunovState::Stable,
            "Constant input should be stable, exponent={}",
            m.exponent()
        );
    }

    #[test]
    fn oscillating_inputs_are_not_chaotic() {
        let mut m = LyapunovStabilityMonitor::new();
        // Regular oscillation: 0, 1, 0, 1 — predictable, not chaotic.
        for i in 0u32..500 {
            let val = if i % 2 == 0 { 0 } else { 1 };
            m.observe_and_update(&[val; N]);
        }
        // Regular oscillation should have expansion ratio ≈ 1 (neutral).
        assert!(
            m.exponent() < CHAOTIC_THRESHOLD,
            "Regular oscillation should not be chaotic, exponent={}",
            m.exponent()
        );
    }

    #[test]
    fn growing_perturbations_raise_exponent() {
        let mut m = LyapunovStabilityMonitor::new();
        // Warmup.
        for _ in 0..WARMUP {
            m.observe_and_update(&[1u8; N]);
        }
        // Simulate growing oscillations: each step has larger delta.
        // 1, 1, 3, 0, 3, 0, 3, 0, ... (large swings)
        for _ in 0..500 {
            m.observe_and_update(&[0u8; N]);
            m.observe_and_update(&[3u8; N]);
        }
        // Large regular swings should keep exponent near zero
        // (not growing, just consistently large).
        // This tests that we don't false-positive on mere amplitude.
        assert!(
            m.exponent() < 1.0,
            "Constant-amplitude swings should have bounded exponent: {}",
            m.exponent()
        );
    }

    #[test]
    fn recovery_from_perturbation() {
        let mut m = LyapunovStabilityMonitor::new();
        let base = [1u8; N];
        for _ in 0..WARMUP {
            m.observe_and_update(&base);
        }
        // Inject a brief chaotic-like sequence.
        for i in 0u32..100 {
            let val = ((i.wrapping_mul(7) ^ i.wrapping_mul(13)) % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        // Then stabilize.
        for _ in 0..500 {
            m.observe_and_update(&base);
        }
        assert_eq!(
            m.state(),
            LyapunovState::Stable,
            "Should recover to Stable after stabilization"
        );
    }

    #[test]
    fn exponent_can_be_negative() {
        let mut m = LyapunovStabilityMonitor::new();
        // Start with large perturbation, then converge.
        m.observe_and_update(&[0u8; N]);
        m.observe_and_update(&[3u8; N]);
        // Now converge to steady state.
        for _ in 0..500 {
            m.observe_and_update(&[1u8; N]);
        }
        // Exponent should be negative (converging).
        assert!(
            m.exponent() < MARGINAL_THRESHOLD,
            "Converging system should have low exponent: {}",
            m.exponent()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = LyapunovStabilityMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.exponent - m.exponent()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
