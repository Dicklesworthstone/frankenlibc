//! # Doob Decomposition Martingale Monitor
//!
//! Detects systematic (non-random) drift in the controller severity process
//! via Doob's decomposition theorem, separating the observed sequence into
//! a martingale (pure noise) and a predictable (systematic drift) component.
//!
//! ## Mathematical Foundation
//!
//! **Doob's Decomposition Theorem** (Doob 1953): Every adapted integrable
//! process {X_n} on a filtered probability space admits a unique decomposition:
//!
//! ```text
//! X_n = M_n + A_n
//! ```
//!
//! where:
//! - **M_n** is a martingale: E[M_{n+1} | F_n] = M_n
//! - **A_n** is predictable: A_n is F_{n-1}-measurable, A_0 = 0
//!
//! The predictable component is:
//!
//! ```text
//! A_n = Σ_{k=0}^{n-1} E[X_{k+1} - X_k | F_k]
//! ```
//!
//! i.e., the cumulative sum of conditional expected increments.
//!
//! ## Why Doob Decomposition?
//!
//! Existing drift detectors (changepoint, Wasserstein, Stein) measure
//! **distributional** change — they detect when the distribution of severity
//! states has shifted. But a distribution can be stationary while the
//! **conditional expectation** drifts systematically:
//!
//! - Controller alternates: state 0 → state 3 → state 0 → state 3
//!   Distribution is {0: 50%, 3: 50%} = stationary.
//!   But E[X_{n+1} | X_n = 0] = 3, E[X_{n+1} | X_n = 3] = 0.
//!   The predictable component |A_n| stays bounded.
//!
//! - Controller drifts: state 0 → 0 → 1 → 1 → 2 → 2 → 3 → 3
//!   E[X_{n+1} | X_n] > X_n for most steps.
//!   The predictable component |A_n| grows monotonically.
//!
//! Doob decomposition detects the SECOND case: systematic, non-random
//! worsening of the severity process that other monitors miss.
//!
//! ## Online Estimation
//!
//! We estimate E[X_{n+1} | X_n = s] from the empirical transition matrix:
//!
//! ```text
//! T[s][s'] ≈ P(X_{n+1} = s' | X_n = s)
//! E[X_{n+1} | X_n = s] = Σ_{s'} s' · T[s][s']
//! ```
//!
//! The transition matrix is updated with EWMA smoothing for adaptivity.
//! The predictable component is accumulated:
//!
//! ```text
//! A_n += E[X_{n+1} | X_n] - X_n
//! ```
//!
//! We track both the aggregate drift (sum across controllers) and the
//! per-controller maximum drift.
//!
//! ## Drift Detection
//!
//! - **|A_n| / n → 0**: martingale dominates, no systematic drift.
//! - **|A_n| / n → c > 0**: constant-rate drift (linear trend).
//! - **|A_n| / n → ∞**: accelerating drift (super-linear worsening).
//!
//! We track the drift rate: |ΔA_n| averaged over recent steps.
//!
//! ## Legacy Anchor
//!
//! `nptl`, `pthread`, cancellation (threading/concurrency subsystem) —
//! thread cancellation is the canonical optional stopping problem.
//! Doob's theorem guarantees that a fair process (martingale) cannot
//! be gamed by choosing when to stop. When the predictable component
//! is non-zero, the severity process is NOT fair — something is
//! systematically pushing it in one direction.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing for transition matrix.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Drift rate threshold for Drifting.
const DRIFT_THRESHOLD: f64 = 0.08;

/// Drift rate threshold for Runaway.
const RUNAWAY_THRESHOLD: f64 = 0.25;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DoobState {
    /// Insufficient data.
    Calibrating = 0,
    /// Predictable component is negligible — severity is a near-martingale.
    Stationary = 1,
    /// Moderate systematic drift detected.
    Drifting = 2,
    /// Strong systematic drift — severity is worsening non-randomly.
    Runaway = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct DoobSummary {
    /// Current state.
    pub state: DoobState,
    /// Smoothed drift rate (average |ΔA| per step across controllers).
    pub drift_rate: f64,
    /// Maximum per-controller cumulative drift magnitude.
    pub max_drift: f64,
    /// Total observations.
    pub observations: u32,
}

/// Doob decomposition martingale monitor.
pub struct DoobDecompositionMonitor {
    /// Per-controller empirical transition matrix T[ctrl][from][to].
    /// Smoothed counts (EWMA), not raw counts.
    transitions: [[[f64; K]; K]; N],
    /// Previous severity vector.
    prev_severity: [u8; N],
    /// Per-controller cumulative predictable component A_n.
    drift: [f64; N],
    /// Smoothed drift rate (EWMA of |ΔA| per step, aggregated).
    drift_rate: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: DoobState,
}

impl DoobDecompositionMonitor {
    #[must_use]
    pub fn new() -> Self {
        // Initialize transition matrices with uniform prior.
        let uniform = 1.0 / K as f64;
        Self {
            transitions: [[[uniform; K]; K]; N],
            prev_severity: [0; N],
            drift: [0.0; N],
            drift_rate: 0.0,
            count: 0,
            state: DoobState::Calibrating,
        }
    }

    /// Compute conditional expectation E[X_{n+1} | X_n = s] for controller i.
    fn conditional_expectation(&self, ctrl: usize, from_state: usize) -> f64 {
        let row = &self.transitions[ctrl][from_state];
        let total: f64 = row.iter().sum();
        if total < 1e-12 {
            return from_state as f64;
        }
        let mut expected = 0.0;
        for (s, &count) in row.iter().enumerate() {
            expected += s as f64 * count / total;
        }
        expected
    }

    /// Feed a severity vector and update Doob decomposition.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        if self.count > 1 {
            let mut step_drift_sum = 0.0_f64;

            for (i, (&prev_s, &cur_s)) in self.prev_severity.iter().zip(severity.iter()).enumerate()
            {
                let from = (prev_s as usize).min(K - 1);
                let to = (cur_s as usize).min(K - 1);

                // Compute predictable increment using prior transition matrix: E[X_n | X_{n-1}] - X_{n-1}.
                let expected = self.conditional_expectation(i, from);
                let increment = expected - from as f64;
                self.drift[i] += increment;
                step_drift_sum += increment.abs();

                // Update transition matrix for this controller.
                for s in 0..K {
                    let target = if s == to { 1.0 } else { 0.0 };
                    self.transitions[i][from][s] += alpha * (target - self.transitions[i][from][s]);
                }
            }

            // Smoothed drift rate: average |ΔA| per controller per step.
            let step_rate = step_drift_sum / N as f64;
            self.drift_rate += alpha * (step_rate - self.drift_rate);
        }

        self.prev_severity = *severity;

        // State classification.
        self.state = if self.count < WARMUP {
            DoobState::Calibrating
        } else if self.drift_rate >= RUNAWAY_THRESHOLD {
            DoobState::Runaway
        } else if self.drift_rate >= DRIFT_THRESHOLD {
            DoobState::Drifting
        } else {
            DoobState::Stationary
        };
    }

    pub fn state(&self) -> DoobState {
        self.state
    }

    pub fn drift_rate(&self) -> f64 {
        self.drift_rate
    }

    pub fn max_drift(&self) -> f64 {
        self.drift.iter().map(|d| d.abs()).fold(0.0_f64, f64::max)
    }

    pub fn summary(&self) -> DoobSummary {
        DoobSummary {
            state: self.state,
            drift_rate: self.drift_rate,
            max_drift: self.max_drift(),
            observations: self.count,
        }
    }
}

impl Default for DoobDecompositionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = DoobDecompositionMonitor::new();
        assert_eq!(m.state(), DoobState::Calibrating);
    }

    #[test]
    fn constant_inputs_are_stationary() {
        let mut m = DoobDecompositionMonitor::new();
        for _ in 0..300 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(
            m.state(),
            DoobState::Stationary,
            "Constant inputs are trivially martingale, drift_rate={}",
            m.drift_rate()
        );
        // Drift rate should be near zero.
        assert!(
            m.drift_rate() < DRIFT_THRESHOLD,
            "Drift rate should be low: {}",
            m.drift_rate()
        );
    }

    #[test]
    fn symmetric_oscillation_is_non_stationary() {
        let mut m = DoobDecompositionMonitor::new();
        // Symmetric oscillation: 0→3→0→3. The conditional expectation
        // E[X|X=0]=3, E[X|X=3]=0, so |increment| = 3 every step.
        // The predictable component is large (highly non-martingale)
        // even though increments alternate in sign.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 3u8 };
            m.observe_and_update(&[val; N]);
        }
        // Large |E[X|s] - s| → Doob detects non-trivial predictable component.
        assert_ne!(
            m.state(),
            DoobState::Stationary,
            "Oscillation has large predictable component, drift_rate={}",
            m.drift_rate()
        );
    }

    #[test]
    fn deterministic_cycle_detected() {
        let mut m = DoobDecompositionMonitor::new();
        // Rapid deterministic cycling 0→1→2→3→0→... has strong
        // conditional increments: E[X|k] = (k+1)%4, |increment| ≥ 1.
        for i in 0u32..500 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert_ne!(
            m.state(),
            DoobState::Stationary,
            "Deterministic cycle should be non-stationary, drift_rate={}",
            m.drift_rate()
        );
    }

    #[test]
    fn drift_rate_nonnegative() {
        let mut m = DoobDecompositionMonitor::new();
        for i in 0u32..200 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.drift_rate() >= 0.0,
            "Drift rate must be non-negative: {}",
            m.drift_rate()
        );
    }

    #[test]
    fn recovery_to_stationary() {
        let mut m = DoobDecompositionMonitor::new();
        // First, monotone drift.
        for i in 0u32..200 {
            let val = ((i / 10) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        // Then stabilize.
        for _ in 0..1000 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            m.state(),
            DoobState::Stationary,
            "Should recover after stabilization, drift_rate={}",
            m.drift_rate()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = DoobDecompositionMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.drift_rate - m.drift_rate()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
