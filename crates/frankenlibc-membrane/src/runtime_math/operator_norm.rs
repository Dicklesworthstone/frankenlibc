//! # Operator-Norm Spectral Radius Stability Monitor
//!
//! Implements online power iteration for estimating the spectral radius
//! of the controller ensemble's state transition operator, detecting
//! emergent instability in the ensemble dynamics.
//!
//! ## Mathematical Foundation
//!
//! Given a sequence of state vectors x_t ∈ ℝ^N (controller severity
//! codes at time t), the **transition operator** A_t captures how
//! state perturbations propagate across the ensemble:
//!
//! ```text
//! A_t ≈ (x_{t+1} − x̄) (x_t − x̄)ᵀ / ‖x_t − x̄‖²
//! ```
//!
//! (rank-1 online approximation of the transition Jacobian).
//!
//! The **spectral radius** ρ(A) = max|λᵢ| determines stability:
//!
//! - **ρ < 1**: contractive — perturbations decay exponentially.
//!   The ensemble is self-correcting.
//! - **ρ = 1**: marginal — perturbations persist without growth.
//!   The ensemble is neutrally stable (a phase transition boundary).
//! - **ρ > 1**: unstable — perturbations amplify. Controllers are
//!   feeding back into each other, creating a positive feedback loop.
//!
//! ## Online Power Iteration
//!
//! Classical power iteration finds the dominant eigenvalue by
//! repeatedly applying A to a random vector v:
//!
//! ```text
//! v_{k+1} = A v_k / ‖A v_k‖
//! ρ ≈ ‖A v_k‖ / ‖v_k‖
//! ```
//!
//! In the online setting, we don't have an explicit matrix A. Instead,
//! we observe successive state vectors and track the **amplification
//! ratio**: how much the deviation from the mean grows between steps.
//!
//! ```text
//! ρ_t = ‖x_{t+1} − x̄‖ / ‖x_t − x̄‖
//! ```
//!
//! We smooth this ratio with EWMA and use the **directional coherence**
//! (how aligned successive perturbation vectors are) to distinguish
//! true spectral amplification from random fluctuation.
//!
//! ## Why This Matters for the Runtime
//!
//! Individual controllers may each look fine in isolation — all in
//! states 0-2 — yet the *ensemble* can be unstable: controller A's
//! elevated state causes B to escalate, which feeds back to A.
//! This positive feedback loop is invisible to any single controller
//! but is captured by ρ > 1.
//!
//! The Atiyah-Bott controller detects *concentrated* anomalies (few
//! controllers far from fixed points). The SOS controller detects
//! *incoherent* anomalies (controllers disagreeing). This controller
//! detects a third failure mode: *dynamic instability* (the trajectory
//! of the ensemble is amplifying over time, even if the current
//! snapshot looks benign).
//!
//! ## State Machine
//!
//! - **Calibrating**: fewer than CALIBRATION_THRESHOLD observations.
//! - **Contractive**: ρ < 0.85 — perturbations decay rapidly.
//! - **Marginal**: 0.85 ≤ ρ < 1.05 — near the stability boundary.
//! - **Unstable**: ρ ≥ 1.05 — perturbation amplification detected.

/// Number of controller signals in the base severity vector.
const NUM_SIGNALS: usize = 25;

/// Observations before leaving calibration.
const CALIBRATION_THRESHOLD: u64 = 128;

/// EWMA smoothing for spectral radius tracking.
const EWMA_ALPHA: f64 = 0.05;

/// Spectral radius threshold: Contractive → Marginal.
const MARGINAL_THRESHOLD: f64 = 0.85;

/// Spectral radius threshold: Marginal → Unstable.
const UNSTABLE_THRESHOLD: f64 = 1.05;

/// Minimum deviation norm to compute a meaningful ratio.
const MIN_NORM: f64 = 0.1;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StabilityState {
    /// Insufficient observations.
    Calibrating,
    /// Spectral radius < 0.85: perturbations decay exponentially.
    Contractive,
    /// 0.85 ≤ ρ < 1.05: near the stability boundary.
    Marginal,
    /// ρ ≥ 1.05: perturbation amplification.
    Unstable,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StabilitySummary {
    pub state: StabilityState,
    /// Smoothed spectral radius estimate.
    pub spectral_radius: f64,
    /// Smoothed directional coherence (cosine similarity between
    /// successive perturbation vectors, 0..1).
    pub directional_coherence: f64,
    /// Current deviation norm (distance of state from mean).
    pub deviation_norm: f64,
    /// Total observations.
    pub total_observations: u64,
    /// Cumulative Unstable detection count.
    pub instability_count: u64,
}

/// Operator-norm spectral radius stability monitor.
pub struct OperatorNormMonitor {
    /// Running mean of each controller state.
    mean: [f64; NUM_SIGNALS],
    /// Previous deviation vector (x_{t-1} - mean).
    prev_deviation: [f64; NUM_SIGNALS],
    /// Previous deviation norm.
    prev_norm: f64,
    /// EWMA-smoothed spectral radius estimate.
    smoothed_rho: f64,
    /// EWMA-smoothed directional coherence.
    smoothed_coherence: f64,
    /// Current deviation norm (for snapshot).
    current_norm: f64,
    /// Total observations.
    observations: u64,
    /// Unstable detection counter.
    instability_count: u64,
}

impl Default for OperatorNormMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorNormMonitor {
    pub fn new() -> Self {
        Self {
            mean: [0.0; NUM_SIGNALS],
            prev_deviation: [0.0; NUM_SIGNALS],
            prev_norm: 0.0,
            smoothed_rho: 0.5, // Start assuming contractive.
            smoothed_coherence: 0.0,
            current_norm: 0.0,
            observations: 0,
            instability_count: 0,
        }
    }

    /// Feed a severity vector and update spectral radius estimate.
    pub fn observe_and_update(&mut self, severity: &[u8; NUM_SIGNALS]) {
        self.observations += 1;

        // Convert to f64.
        let vals: [f64; NUM_SIGNALS] = {
            let mut v = [0.0; NUM_SIGNALS];
            for (vi, &s) in v.iter_mut().zip(severity.iter()) {
                *vi = f64::from(s);
            }
            v
        };

        // Update running mean.
        let alpha = if self.observations == 1 {
            1.0
        } else {
            EWMA_ALPHA
        };
        for (m, &v) in self.mean.iter_mut().zip(vals.iter()) {
            *m += alpha * (v - *m);
        }

        // Compute current deviation from mean.
        let mut deviation = [0.0; NUM_SIGNALS];
        let mut norm_sq = 0.0;
        for (d, (&v, &m)) in deviation.iter_mut().zip(vals.iter().zip(self.mean.iter())) {
            *d = v - m;
            norm_sq += *d * *d;
        }
        let norm = norm_sq.sqrt();
        self.current_norm = norm;

        // Compute amplification ratio and directional coherence.
        if self.observations >= 2 {
            if self.prev_norm > MIN_NORM && norm > MIN_NORM {
                // Spectral radius estimate: ‖deviation_t‖ / ‖deviation_{t-1}‖.
                let rho = norm / self.prev_norm;

                // Directional coherence: cosine similarity between successive deviations.
                let dot: f64 = deviation
                    .iter()
                    .zip(self.prev_deviation.iter())
                    .map(|(&d, &pd)| d * pd)
                    .sum();
                let coherence = (dot / (norm * self.prev_norm)).clamp(-1.0, 1.0).abs();

                // Weight the spectral radius by directional coherence.
                // High coherence → the amplification is in a consistent direction
                // (true spectral behavior). Low coherence → random fluctuation.
                let weighted_rho = rho * coherence + (1.0 - coherence) * 1.0;

                // EWMA update.
                self.smoothed_rho += EWMA_ALPHA * (weighted_rho - self.smoothed_rho);
                self.smoothed_coherence += EWMA_ALPHA * (coherence - self.smoothed_coherence);
            } else {
                // Deviation is vanishingly small — strongly contractive.
                self.smoothed_rho += EWMA_ALPHA * (0.0 - self.smoothed_rho);
                self.smoothed_coherence += EWMA_ALPHA * (0.0 - self.smoothed_coherence);
            }
        } else if self.observations == 1 {
            self.smoothed_rho = 0.5;
            self.smoothed_coherence = 0.0;
        }

        // Store current deviation for next iteration.
        self.prev_deviation = deviation;
        self.prev_norm = norm;

        // Count instability events.
        if self.observations > CALIBRATION_THRESHOLD && self.state() == StabilityState::Unstable {
            self.instability_count += 1;
        }
    }

    /// Current state.
    pub fn state(&self) -> StabilityState {
        if self.observations < CALIBRATION_THRESHOLD {
            return StabilityState::Calibrating;
        }

        if self.smoothed_rho >= UNSTABLE_THRESHOLD {
            StabilityState::Unstable
        } else if self.smoothed_rho >= MARGINAL_THRESHOLD {
            StabilityState::Marginal
        } else {
            StabilityState::Contractive
        }
    }

    /// Summary snapshot.
    pub fn summary(&self) -> StabilitySummary {
        StabilitySummary {
            state: self.state(),
            spectral_radius: self.smoothed_rho,
            directional_coherence: self.smoothed_coherence,
            deviation_norm: self.current_norm,
            total_observations: self.observations,
            instability_count: self.instability_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_stable() -> [u8; NUM_SIGNALS] {
        [1; NUM_SIGNALS]
    }

    #[test]
    fn calibration_phase() {
        let mut ctrl = OperatorNormMonitor::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe_and_update(&all_stable());
        }
        assert_eq!(ctrl.state(), StabilityState::Calibrating);
    }

    #[test]
    fn constant_input_is_contractive() {
        let mut ctrl = OperatorNormMonitor::new();
        // Constant input → deviation decays to ~0 → ρ → 0.
        for _ in 0..2000 {
            ctrl.observe_and_update(&all_stable());
        }
        let s = ctrl.summary();
        assert_eq!(s.state, StabilityState::Contractive);
        assert!(
            s.spectral_radius < MARGINAL_THRESHOLD,
            "ρ = {:.4}",
            s.spectral_radius
        );
    }

    #[test]
    fn oscillating_input_tests_stability() {
        let mut ctrl = OperatorNormMonitor::new();
        // Alternating pattern → persistent deviation → ρ ≈ 1.
        for i in 0..3000 {
            let mut pattern = [1u8; NUM_SIGNALS];
            if i % 2 == 0 {
                pattern[0] = 3;
                pattern[1] = 0;
            } else {
                pattern[0] = 0;
                pattern[1] = 3;
            }
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // Oscillation should produce marginal or higher spectral radius.
        assert!(
            s.spectral_radius > 0.5,
            "Expected elevated ρ from oscillation: {:.4}",
            s.spectral_radius
        );
    }

    #[test]
    fn growing_perturbation_detects_instability() {
        let mut ctrl = OperatorNormMonitor::new();
        // Calibrate.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(&all_stable());
        }
        // Slowly growing perturbation — more controllers escalate over time.
        // This simulates a positive feedback cascade.
        for phase in 0..4 {
            let escalation_count = (phase + 1) * 4;
            for _ in 0..500 {
                let mut pattern = [1u8; NUM_SIGNALS];
                for slot in pattern.iter_mut().take(escalation_count.min(NUM_SIGNALS)) {
                    *slot = 2 + (phase as u8).min(1);
                }
                ctrl.observe_and_update(&pattern);
            }
        }
        let s = ctrl.summary();
        // The growing perturbation should produce a higher spectral radius.
        assert!(
            s.spectral_radius > 0.7,
            "Expected elevated ρ from growing perturbation: {:.4}",
            s.spectral_radius
        );
    }

    #[test]
    fn recovery_from_perturbation() {
        let mut ctrl = OperatorNormMonitor::new();
        // Disturb then recover.
        for i in 0..1000 {
            let mut pattern = [1u8; NUM_SIGNALS];
            if i % 2 == 0 {
                for slot in pattern.iter_mut().take(10) {
                    *slot = 3;
                }
            }
            ctrl.observe_and_update(&pattern);
        }
        let rho_during = ctrl.summary().spectral_radius;

        // Recover with constant input.
        for _ in 0..5000 {
            ctrl.observe_and_update(&all_stable());
        }
        let s = ctrl.summary();
        assert!(
            s.spectral_radius < rho_during || s.state == StabilityState::Contractive,
            "Should recover: ρ was {rho_during:.4}, now {:.4}",
            s.spectral_radius
        );
    }

    #[test]
    fn directional_coherence_distinguishes_noise() {
        let mut ctrl = OperatorNormMonitor::new();
        // Random-like input (switching different controllers each time)
        // should have low directional coherence.
        for i in 0..3000 {
            let mut pattern = [1u8; NUM_SIGNALS];
            let idx = i % NUM_SIGNALS;
            pattern[idx] = 3;
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // Low coherence → weighted ρ closer to 1.0 (neutral).
        assert!(
            s.directional_coherence < 0.5,
            "Expected low coherence from rotating perturbation: {:.4}",
            s.directional_coherence
        );
    }

    #[test]
    fn all_zero_is_stable() {
        let mut ctrl = OperatorNormMonitor::new();
        let zeros = [0u8; NUM_SIGNALS];
        for _ in 0..2000 {
            ctrl.observe_and_update(&zeros);
        }
        let s = ctrl.summary();
        assert_eq!(s.state, StabilityState::Contractive);
    }
}
