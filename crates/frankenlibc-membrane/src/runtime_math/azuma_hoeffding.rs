//! # Azuma-Hoeffding Martingale Concentration Monitor
//!
//! Detects when the "noise" component of the severity process exceeds
//! its theoretical concentration bounds, indicating that severity
//! transitions violate the bounded-difference assumption.
//!
//! ## Mathematical Foundation
//!
//! **Azuma's Inequality** (Azuma 1967): For a supermartingale {M_n}
//! with bounded differences |M_k - M_{k-1}| ≤ c_k:
//!
//! ```text
//! P(M_n - M_0 ≥ t) ≤ exp(-t² / (2 Σ_{k=1}^{n} c_k²))
//! ```
//!
//! Combined with the symmetric bound (Hoeffding 1963):
//!
//! ```text
//! P(|S_n - nμ| ≥ t) ≤ 2 exp(-2t² / (n · c²))
//! ```
//!
//! For severity states in {0, ..., K-1}, the maximum single-step
//! change is c = K-1 = 3. After n steps:
//!
//! ```text
//! P(|S_n - nμ| ≥ t) ≤ 2 exp(-2t² / (n · (K-1)²))
//! ```
//!
//! where S_n = Σ X_k is the cumulative severity.
//!
//! ## Why Azuma-Hoeffding?
//!
//! Doob decomposition separates the severity process into drift (A_n)
//! and noise (M_n). Other controllers monitor the drift. Azuma-Hoeffding
//! bounds the NOISE:
//!
//! - When the cumulative deviation stays within Azuma bounds, fluctuations
//!   are "normal" — consistent with a bounded-difference process.
//! - When deviations exceed bounds, something structural has changed:
//!   the bounded-difference assumption is violated (severity jumps
//!   larger than expected), or the process is non-stationary.
//!
//! This is the severity process's **shock absorber diagnostic**: when
//! Azuma bounds are satisfied, random perturbations stay contained.
//! When violated, the system lacks the capacity to absorb shocks.
//!
//! ## Online Estimation
//!
//! Per controller i:
//! 1. EWMA mean μ̂_i of severity.
//! 2. Cumulative centered deviation: D_n = Σ_{k=1}^{n} (X_k - μ̂_i).
//! 3. Azuma threshold at confidence α: t_α = c · √(2n · ln(2/α)).
//! 4. Exceedance ratio: |D_n| / t_α.
//!
//! The aggregate exceedance is the maximum across all N controllers.
//!
//! ## Relationship to Other Monitors
//!
//! - **Doob**: separates drift from noise. Azuma bounds the noise.
//! - **Dobrushin**: detects mixing failure. Azuma detects concentration failure.
//! - **Lyapunov**: detects divergence. Azuma detects shock amplitude.
//!
//! ## Legacy Anchor
//!
//! `setjmp`/`longjmp`, signal handlers — non-local control flow can
//! cause unbounded severity transitions. When a signal handler fires
//! or longjmp unwinds the stack, the severity process may jump by more
//! than the bounded-difference assumption allows. Azuma-Hoeffding
//! detects exactly this: transitions that violate the "small steps"
//! guarantee.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing parameter.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Confidence level for Azuma bound (1 - α = 99%).
const CONFIDENCE_ALPHA: f64 = 0.01;

/// Exceedance ratio threshold for Diffuse state.
const DIFFUSE_THRESHOLD: f64 = 0.6;

/// Exceedance ratio threshold for Explosive state.
const EXPLOSIVE_THRESHOLD: f64 = 1.0;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AzumaState {
    /// Insufficient data.
    Calibrating = 0,
    /// Deviations within Azuma bounds — noise is well-contained.
    Concentrated = 1,
    /// Approaching Azuma bounds — noise amplifying.
    Diffuse = 2,
    /// Exceeding Azuma bounds — bounded-difference assumption violated.
    Explosive = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct AzumaSummary {
    /// Current state.
    pub state: AzumaState,
    /// Maximum exceedance ratio across controllers (0 = well within bounds).
    pub max_exceedance: f64,
    /// Mean exceedance ratio across controllers.
    pub mean_exceedance: f64,
    /// Total observations.
    pub observations: u32,
}

/// Azuma-Hoeffding concentration monitor.
pub struct AzumaHoeffdingMonitor {
    /// Per-controller EWMA mean of severity.
    mean: [f64; N],
    /// Per-controller cumulative centered deviation D_n.
    cumulative_dev: [f64; N],
    /// Observation count.
    count: u32,
    /// Smoothed max exceedance ratio.
    max_exceedance: f64,
    /// Smoothed mean exceedance ratio.
    mean_exceedance: f64,
    /// Current state.
    state: AzumaState,
}

impl AzumaHoeffdingMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mean: [0.0; N],
            cumulative_dev: [0.0; N],
            count: 0,
            max_exceedance: 0.0,
            mean_exceedance: 0.0,
            state: AzumaState::Calibrating,
        }
    }

    /// Compute the Azuma threshold at the current observation count.
    ///
    /// t_α = c · √(2n · ln(2/α)) where c = K-1 (max bounded difference).
    fn azuma_threshold(&self) -> f64 {
        let n = self.count as f64;
        let c = (K - 1) as f64;
        c * (2.0 * n * crate::util::ln_f64(2.0_f64 / CONFIDENCE_ALPHA)).sqrt()
    }

    /// Feed a severity vector and update concentration estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        let threshold = self.azuma_threshold().max(1e-12);
        let mut max_exc = 0.0_f64;
        let mut sum_exc = 0.0_f64;

        for (i, &sev) in severity.iter().enumerate() {
            let x = (sev as usize).min(K - 1) as f64;

            // Update EWMA mean.
            self.mean[i] += alpha * (x - self.mean[i]);

            // Accumulate centered deviation.
            self.cumulative_dev[i] += x - self.mean[i];

            // Exceedance ratio: |D_n| / t_α.
            let exc = self.cumulative_dev[i].abs() / threshold;
            max_exc = max_exc.max(exc);
            sum_exc += exc;
        }

        let mean_exc = sum_exc / N as f64;

        // EWMA smooth the exceedance ratios.
        self.max_exceedance += alpha * (max_exc - self.max_exceedance);
        self.mean_exceedance += alpha * (mean_exc - self.mean_exceedance);

        // State classification.
        self.state = if self.count < WARMUP {
            AzumaState::Calibrating
        } else if self.max_exceedance >= EXPLOSIVE_THRESHOLD {
            AzumaState::Explosive
        } else if self.max_exceedance >= DIFFUSE_THRESHOLD {
            AzumaState::Diffuse
        } else {
            AzumaState::Concentrated
        };
    }

    pub fn state(&self) -> AzumaState {
        self.state
    }

    pub fn max_exceedance(&self) -> f64 {
        self.max_exceedance
    }

    pub fn mean_exceedance(&self) -> f64 {
        self.mean_exceedance
    }

    pub fn summary(&self) -> AzumaSummary {
        AzumaSummary {
            state: self.state,
            max_exceedance: self.max_exceedance,
            mean_exceedance: self.mean_exceedance,
            observations: self.count,
        }
    }
}

impl Default for AzumaHoeffdingMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = AzumaHoeffdingMonitor::new();
        assert_eq!(m.state(), AzumaState::Calibrating);
    }

    #[test]
    fn constant_inputs_are_concentrated() {
        let mut m = AzumaHoeffdingMonitor::new();
        // Constant severity → deviations from mean are zero → well within bounds.
        for _ in 0..300 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            m.state(),
            AzumaState::Concentrated,
            "Constant inputs should be concentrated, max_exceedance={}",
            m.max_exceedance()
        );
    }

    #[test]
    fn small_fluctuations_are_concentrated() {
        let mut m = AzumaHoeffdingMonitor::new();
        // Small fluctuations between 1 and 2 — well within Azuma bounds.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 1u8 } else { 2u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            AzumaState::Concentrated,
            "Small fluctuations should be concentrated, max_exceedance={}",
            m.max_exceedance()
        );
    }

    #[test]
    fn exceedance_is_nonnegative() {
        let mut m = AzumaHoeffdingMonitor::new();
        for i in 0u32..200 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_exceedance() >= 0.0,
            "Exceedance must be non-negative: {}",
            m.max_exceedance()
        );
        assert!(
            m.mean_exceedance() >= 0.0,
            "Mean exceedance must be non-negative: {}",
            m.mean_exceedance()
        );
    }

    #[test]
    fn sustained_bias_raises_exceedance() {
        let mut m = AzumaHoeffdingMonitor::new();
        // Start with balanced data to establish mean ≈ 1.5.
        for i in 0u32..100 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        let early_exc = m.max_exceedance();
        // Then sustained bias to 3 — cumulative deviation grows.
        for _ in 0..500 {
            m.observe_and_update(&[3u8; N]);
        }
        assert!(
            m.max_exceedance() >= early_exc,
            "Sustained bias should increase exceedance: {} vs {}",
            m.max_exceedance(),
            early_exc
        );
    }

    #[test]
    fn recovery_after_bias() {
        let mut m = AzumaHoeffdingMonitor::new();
        // Sustained bias.
        for _ in 0..300 {
            m.observe_and_update(&[3u8; N]);
        }
        // Then return to balanced.
        for i in 0u32..2000 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        // Exceedance should be moderate (threshold grows as √n).
        assert!(
            m.max_exceedance() < EXPLOSIVE_THRESHOLD,
            "Should recover with balanced data: max_exceedance={}",
            m.max_exceedance()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = AzumaHoeffdingMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_exceedance - m.max_exceedance()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
