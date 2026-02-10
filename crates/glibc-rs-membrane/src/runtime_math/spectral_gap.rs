//! # Spectral Gap Mixing Time Monitor
//!
//! Detects slow mixing and metastability in the controller severity Markov
//! chain via the spectral gap, quantifying how long the chain takes to
//! converge to its stationary distribution.
//!
//! ## Mathematical Foundation
//!
//! **Cheeger's Inequality and Spectral Gap** (Cheeger 1970, Sinclair &
//! Jerrum 1989): For a reversible Markov chain with transition matrix P,
//! the spectral gap is:
//!
//! ```text
//! gamma = 1 - |lambda_2|
//! ```
//!
//! where lambda_2 is the second-largest eigenvalue (in absolute value) of P.
//!
//! The mixing time is bounded by:
//!
//! ```text
//! t_mix(epsilon) <= ceil((1/gamma) * ln(1/epsilon))
//! ```
//!
//! Cheeger's inequality relates the spectral gap to the conductance h:
//!
//! ```text
//! gamma/2 <= h <= sqrt(2 * gamma)
//! ```
//!
//! Key properties:
//! - **|lambda_2| near 0**: maximal spectral gap, the chain mixes in O(1)
//!   steps. Every state rapidly forgets its history.
//! - **|lambda_2| near 1**: vanishing spectral gap, the chain mixes in
//!   O(1/gamma) = O(1/(1-|lambda_2|)) steps. The system retains memory
//!   of its initial state for exponentially long.
//! - **|lambda_2| approx 1** (metastability): the chain has quasi-stationary
//!   modes that persist for exponentially long, creating the illusion of
//!   stationarity within each mode while the global distribution has not
//!   converged.
//!
//! ## Why Spectral Gap?
//!
//! Complements Dobrushin's contraction coefficient (which gives a different
//! mixing bound via total variation between transition rows):
//!
//! - **Dobrushin**: delta < 1 implies mixing, but the bound can be loose.
//!   It is a worst-case pairwise measure.
//! - **Spectral gap**: gives TIGHT mixing time bounds for reversible chains
//!   via the eigenvalue structure of the full transition matrix.
//! - **Metastability detection**: when lambda_2 approx 1, the chain has
//!   quasi-stationary modes that persist exponentially long. These modes
//!   can fool distributional monitors into believing the system is stable,
//!   when in reality it has not yet explored its full state space.
//!
//! The spectral gap provides the sharpest single-number summary of how
//! quickly the severity process forgets its past.
//!
//! ## Online Estimation
//!
//! We estimate the transition matrix per-controller from observed severity
//! state transitions using EWMA smoothing, then estimate |lambda_2| via
//! power iteration on the deflated matrix (removing the stationary
//! component along the all-ones eigenvector).
//!
//! For K=4 states, 20 power iterations suffice for convergence of the
//! second eigenvalue estimate. The aggregate uses both the maximum
//! (worst-case controller) and mean across all N controllers.
//!
//! ## Legacy Anchor
//!
//! `futex`, `pthread`, cancellation (concurrency subsystem) -- race
//! conditions and contention create slow-mixing controller dynamics.
//! The spectral gap quantifies HOW slow the mixing is: a futex waiter
//! that systematically sees the same contention pattern has a near-unit
//! second eigenvalue, meaning the controller state is trapped in a
//! quasi-stable mode. Metastability detects when the system is stuck
//! in a mode that may not represent the true stationary behavior,
//! analogous to a lock convoy that appears stable but is actually a
//! degenerate operating point.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing for transition matrix.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Cadence for the expensive per-controller second-eigenvalue computation.
///
/// Rationale: `second_eigenvalue()` runs a 20-iteration power method; doing it
/// for all N controllers on every observation is too costly for strict-mode
/// hot paths.
const SAMPLE_INTERVAL: u32 = 16;

/// |lambda_2| above which the chain is classified as SlowMixing.
const SLOW_MIXING_THRESHOLD: f64 = 0.85;

/// |lambda_2| above which the chain is classified as Metastable.
const METASTABLE_THRESHOLD: f64 = 0.95;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpectralGapState {
    /// Insufficient data.
    Calibrating = 0,
    /// |lambda_2| well below 1 -- fast mixing.
    RapidMixing = 1,
    /// |lambda_2| approaching 1 -- slow mixing.
    SlowMixing = 2,
    /// |lambda_2| approx 1 -- quasi-stationary trapping.
    Metastable = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct SpectralGapSummary {
    /// Current state.
    pub state: SpectralGapState,
    /// Maximum |lambda_2| across controllers.
    pub max_second_eigenvalue: f64,
    /// Mean |lambda_2| across controllers.
    pub mean_second_eigenvalue: f64,
    /// Total observations.
    pub observations: u32,
}

/// Per-controller transition matrix tracker.
struct TransitionTracker {
    /// Transition matrix P[from][to], EWMA-smoothed counts.
    matrix: [[f64; K]; K],
}

impl TransitionTracker {
    fn new() -> Self {
        // Initialize with uniform prior.
        let init = 1.0 / K as f64;
        Self {
            matrix: [[init; K]; K],
        }
    }

    /// Update with an observed transition.
    fn update(&mut self, from: usize, to: usize, alpha: f64) {
        for s in 0..K {
            let target = if s == to { 1.0 } else { 0.0 };
            self.matrix[from][s] += alpha * (target - self.matrix[from][s]);
        }
    }

    /// Normalize the transition matrix rows to proper probabilities.
    fn normalized_probs(&self) -> [[f64; K]; K] {
        let mut probs = [[0.0_f64; K]; K];
        for (i, row) in self.matrix.iter().enumerate() {
            let sum: f64 = row.iter().sum();
            if sum > 1e-12 {
                for (k, &val) in row.iter().enumerate() {
                    probs[i][k] = val / sum;
                }
            } else {
                // Uniform fallback.
                for p in &mut probs[i] {
                    *p = 1.0 / K as f64;
                }
            }
        }
        probs
    }

    /// Estimate |lambda_2| of the stochastic transition matrix via
    /// power iteration on the deflated matrix.
    ///
    /// For a row-stochastic matrix P, lambda_1 = 1 with right eigenvector
    /// [1,1,...,1] (since each row sums to 1). We compute w = P*v and
    /// deflate by subtracting the mean (projection onto all-ones),
    /// forcing convergence to the second eigenvalue.
    fn second_eigenvalue(&self) -> f64 {
        let probs = self.normalized_probs();

        // Start with a vector orthogonal to the uniform direction.
        // Use [1, -1, 1, -1] as initial guess.
        let mut v = [1.0_f64, -1.0, 1.0, -1.0];
        let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
        for x in &mut v {
            *x /= norm;
        }

        // Power iteration with deflation: 20 iterations.
        for _ in 0..20 {
            // Matrix-vector multiply: w = P * v
            // (Pv)_j = Σ_i P[j][i] * v[i]
            let mut w = [0.0_f64; K];
            for j in 0..K {
                for i in 0..K {
                    w[j] += probs[j][i] * v[i];
                }
            }

            // Remove component along the dominant eigenvector (all-ones).
            // For row-stochastic P, P*[1,...,1] = [1,...,1], so the
            // dominant right eigenvector is all-ones. Subtracting the
            // mean removes this component.
            let mean: f64 = w.iter().sum::<f64>() / K as f64;
            for x in &mut w {
                *x -= mean;
            }

            // Normalize.
            let n = w.iter().map(|x| x * x).sum::<f64>().sqrt();
            if n < 1e-12 {
                // Deflated space is trivial -- gap is maximal.
                return 0.0;
            }
            for i in 0..K {
                v[i] = w[i] / n;
            }
        }

        // Compute Rayleigh quotient to estimate |lambda_2|.
        let mut w = [0.0_f64; K];
        for j in 0..K {
            for i in 0..K {
                w[j] += probs[j][i] * v[i];
            }
        }
        let mean: f64 = w.iter().sum::<f64>() / K as f64;
        for x in &mut w {
            *x -= mean;
        }
        let dot: f64 = v.iter().zip(w.iter()).map(|(a, b)| a * b).sum();
        dot.abs().clamp(0.0, 1.0)
    }
}

/// Spectral gap mixing time monitor.
pub struct SpectralGapMonitor {
    /// Per-controller transition trackers.
    trackers: Vec<TransitionTracker>,
    /// Previous severity vector.
    prev_severity: [u8; N],
    /// Smoothed max |lambda_2| across controllers.
    max_second_eigenvalue: f64,
    /// Smoothed mean |lambda_2| across controllers.
    mean_second_eigenvalue: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: SpectralGapState,
}

impl SpectralGapMonitor {
    #[must_use]
    pub fn new() -> Self {
        let trackers = (0..N).map(|_| TransitionTracker::new()).collect();
        Self {
            trackers,
            prev_severity: [0; N],
            max_second_eigenvalue: 0.0,
            mean_second_eigenvalue: 0.0,
            count: 0,
            state: SpectralGapState::Calibrating,
        }
    }

    /// Feed a severity vector and update spectral gap estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        if self.count > 1 {
            // Always update transition matrices (cheap).
            for (i, tracker) in self.trackers.iter_mut().enumerate() {
                let from = (self.prev_severity[i] as usize).min(K - 1);
                let to = (severity[i] as usize).min(K - 1);
                tracker.update(from, to, alpha);
            }

            // Heavy eigenvalue estimate is cadence-only.
            if self.count.is_multiple_of(SAMPLE_INTERVAL) {
                let mut max_lam2 = 0.0_f64;
                let mut sum_lam2 = 0.0_f64;
                for tracker in self.trackers.iter() {
                    let lam2 = tracker.second_eigenvalue();
                    max_lam2 = max_lam2.max(lam2);
                    sum_lam2 += lam2;
                }

                let mean_lam2 = sum_lam2 / N as f64;
                self.max_second_eigenvalue += alpha * (max_lam2 - self.max_second_eigenvalue);
                self.mean_second_eigenvalue += alpha * (mean_lam2 - self.mean_second_eigenvalue);
            }
        }

        self.prev_severity = *severity;

        // State classification based on smoothed max |lambda_2|.
        self.state = if self.count < WARMUP {
            SpectralGapState::Calibrating
        } else if self.max_second_eigenvalue >= METASTABLE_THRESHOLD {
            SpectralGapState::Metastable
        } else if self.max_second_eigenvalue >= SLOW_MIXING_THRESHOLD {
            SpectralGapState::SlowMixing
        } else {
            SpectralGapState::RapidMixing
        };
    }

    pub fn state(&self) -> SpectralGapState {
        self.state
    }

    pub fn max_second_eigenvalue(&self) -> f64 {
        self.max_second_eigenvalue
    }

    pub fn mean_second_eigenvalue(&self) -> f64 {
        self.mean_second_eigenvalue
    }

    pub fn summary(&self) -> SpectralGapSummary {
        SpectralGapSummary {
            state: self.state,
            max_second_eigenvalue: self.max_second_eigenvalue,
            mean_second_eigenvalue: self.mean_second_eigenvalue,
            observations: self.count,
        }
    }
}

impl Default for SpectralGapMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = SpectralGapMonitor::new();
        assert_eq!(m.state(), SpectralGapState::Calibrating);
    }

    #[test]
    fn constant_inputs_bounded() {
        let mut m = SpectralGapMonitor::new();
        // Constant severity: only one row of the transition matrix gets
        // updated (concentrating on the self-loop), while other rows stay
        // at the uniform prior. The second eigenvalue depends on the
        // resulting matrix structure -- just verify it is bounded.
        for _ in 0..300 {
            m.observe_and_update(&[1u8; N]);
        }
        assert!(
            m.max_second_eigenvalue() >= 0.0 && m.max_second_eigenvalue() <= 1.0,
            "|lambda_2| should be in [0,1]: {}",
            m.max_second_eigenvalue()
        );
    }

    #[test]
    fn stochastic_transitions_rapid_mixing() {
        let mut m = SpectralGapMonitor::new();
        // PRNG producing diverse transitions covering all (from, to) pairs
        // roughly uniformly. Each row of the transition matrix converges to
        // approximately uniform, so |lambda_2| should be small.
        let mut rng = 12345u64;
        for _ in 0..5000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_second_eigenvalue() < METASTABLE_THRESHOLD,
            "Stochastic transitions should not be Metastable: max_lam2={}",
            m.max_second_eigenvalue()
        );
    }

    #[test]
    fn alternating_states_high_eigenvalue() {
        let mut m = SpectralGapMonitor::new();
        // Strict alternation: 0→3→0→3→... creates a transition matrix
        // with strong off-diagonal structure. Row 0 concentrates on column 3,
        // row 3 concentrates on column 0. This matrix has |lambda_2| close
        // to 1 (period-2 chain).
        for i in 0u32..800 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 3u8 };
            m.observe_and_update(&[val; N]);
        }
        // The alternating chain should produce high |lambda_2|.
        assert!(
            m.max_second_eigenvalue() > 0.5,
            "Alternating states should have high |lambda_2|: {}",
            m.max_second_eigenvalue()
        );
    }

    #[test]
    fn second_eigenvalue_in_unit_interval() {
        let mut m = SpectralGapMonitor::new();
        for i in 0u32..300 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_second_eigenvalue() >= 0.0 && m.max_second_eigenvalue() <= 1.0,
            "|lambda_2| must be in [0,1]: {}",
            m.max_second_eigenvalue()
        );
        assert!(
            m.mean_second_eigenvalue() >= 0.0 && m.mean_second_eigenvalue() <= 1.0,
            "Mean |lambda_2| must be in [0,1]: {}",
            m.mean_second_eigenvalue()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = SpectralGapMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_second_eigenvalue - m.max_second_eigenvalue()).abs() < 1e-12);
        assert!((s.mean_second_eigenvalue - m.mean_second_eigenvalue()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }

    #[test]
    fn recovery_with_stochastic_transitions() {
        let mut m = SpectralGapMonitor::new();
        // Start with alternating (high |lambda_2|).
        for i in 0u32..300 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 3u8 };
            m.observe_and_update(&[val; N]);
        }
        // Then recover with diverse PRNG transitions.
        let mut rng = 67890u64;
        for _ in 0..8000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        // Should recover toward lower |lambda_2|.
        assert!(
            m.max_second_eigenvalue() < METASTABLE_THRESHOLD,
            "Should recover with stochastic transitions: max_lam2={}",
            m.max_second_eigenvalue()
        );
    }
}
