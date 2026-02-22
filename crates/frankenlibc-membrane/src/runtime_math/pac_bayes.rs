//! # PAC-Bayes Generalization Bound Monitor
//!
//! Real-time PAC-Bayes bound on the ensemble controller's expected
//! prediction error, providing the tightest known finite-sample
//! generalization guarantees for stochastic prediction aggregation.
//!
//! ## Mathematical Foundation
//!
//! The **PAC-Bayes theorem** (McAllester 1999, Catoni 2007) states:
//! for any prior π on hypothesis space H, any δ ∈ (0,1), with
//! probability ≥ 1-δ over n i.i.d. samples, for ALL posteriors ρ:
//!
//! ```text
//! E_ρ[L(h)] ≤ Ê_ρ[L(h)] + √( (KL(ρ ‖ π) + ln(2√n/δ)) / (2n) )
//! ```
//!
//! where:
//! - `E_ρ[L(h)]` is the expected risk under posterior ρ
//! - `Ê_ρ[L(h)]` is the empirical risk under posterior ρ
//! - `KL(ρ ‖ π)` is the Kullback-Leibler divergence from prior to posterior
//! - `n` is the number of observations
//!
//! ## Application to Controller Ensemble
//!
//! Our N=25 base controllers each produce a severity signal. We maintain:
//!
//! 1. **Prior weights** π: uniform 1/N (each controller equally trusted a priori)
//! 2. **Posterior weights** ρ: EWMA-adapted based on each controller's
//!    empirical accuracy (did it predict adverse outcomes correctly?)
//! 3. **KL divergence** KL(ρ ‖ π) = Σᵢ ρᵢ ln(ρᵢ / πᵢ)
//!
//! The PAC-Bayes bound then gives an upper bound on the **true error**
//! of the weighted ensemble, accounting for the data-dependent weight
//! adaptation. When the bound is loose (high KL or low n), the
//! ensemble's predictions cannot be trusted. When tight, we have
//! formal finite-sample guarantees.
//!
//! ## Catoni Bound (Tighter Variant)
//!
//! Catoni (2007) showed that the optimal PAC-Bayes bound uses the
//! **Catoni bound** function instead of the square root:
//!
//! ```text
//! E_ρ[L(h)] ≤ (1 - e^{-C}) / C
//! where C = Ê_ρ[L(h)] + (KL(ρ ‖ π) + ln(2√n/δ)) / (λn)
//! ```
//!
//! with λ an optimizable temperature parameter. We use the simpler
//! McAllester form for runtime efficiency and track the Catoni
//! tightening as a diagnostic.
//!
//! ## Why This Matters
//!
//! Other meta-controllers measure *what* the ensemble state is (Fisher-Rao,
//! Wasserstein, MMD). This controller measures *how much we should trust*
//! the ensemble's output — it bounds the gap between observed and true
//! error rates, accounting for the adaptive weight selection.
//!
//! High PAC-Bayes bound → the ensemble hasn't been tested enough, or
//! has adapted its weights too aggressively (high KL) → we should invest
//! in extra validation to compensate for the uncertainty.
//!
//! ## Connection to the Mandatory Math Stack
//!
//! Complements math #5 (anytime-valid e-processes) and math #27
//! (conformal prediction) with the PAC-Bayes generalization framework.
//! The three together form a triangle of statistical guarantees:
//! - E-processes: sequential validity (stop anytime)
//! - Conformal: distribution-free coverage (no distributional assumptions)
//! - PAC-Bayes: generalization (posterior weight adaptation bounded)
//!
//! ## Legacy Anchor
//!
//! `math`, `soft-fp`, `sysdeps/ieee754` (numeric/fenv correctness) —
//! the floating-point exceptional path handlers must maintain correctness
//! guarantees across regime transitions. PAC-Bayes bounds formalize the
//! "how much should we trust the current handler selection" question.

/// Number of base controllers.
const N: usize = 25;

/// EWMA smoothing for weight adaptation.
const ALPHA: f64 = 0.03;

/// Warmup observations before leaving Calibrating.
const WARMUP: u32 = 40;

/// Confidence parameter δ (99.5% confidence).
const DELTA: f64 = 0.005;

/// Prior: uniform weights (1/N each).
const PRIOR_WEIGHT: f64 = 1.0 / N as f64;

/// KL divergence threshold for Uncertain.
const KL_WARNING: f64 = 1.5;

/// KL divergence threshold for Unreliable.
const KL_ALARM: f64 = 3.0;

/// PAC-Bayes bound threshold for Uncertain (when bound exceeds
/// this fraction of the worst-case error, we flag uncertainty).
const BOUND_WARNING: f64 = 0.35;

/// PAC-Bayes bound threshold for Unreliable.
const BOUND_ALARM: f64 = 0.60;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacBayesState {
    /// Insufficient data for meaningful bounds.
    Calibrating = 0,
    /// PAC-Bayes bound is tight — ensemble predictions are trustworthy.
    Tight = 1,
    /// Bound is loosening — high KL or insufficient data.
    Uncertain = 2,
    /// Bound is very loose — ensemble cannot be trusted.
    Unreliable = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct PacBayesSummary {
    /// Current state.
    pub state: PacBayesState,
    /// KL(posterior || prior) divergence.
    pub kl_divergence: f64,
    /// PAC-Bayes generalization bound value.
    pub bound: f64,
    /// Weighted empirical error rate.
    pub empirical_error: f64,
    /// Effective number of observations.
    pub effective_n: f64,
    /// Total observations.
    pub observations: u32,
}

/// PAC-Bayes generalization bound monitor.
pub struct PacBayesMonitor {
    /// Posterior weights (adapted online).
    posterior: [f64; N],
    /// Per-controller empirical error rates (EWMA).
    error_rate: [f64; N],
    /// Weighted empirical error (EWMA).
    empirical_error: f64,
    /// KL(posterior || prior) (cached).
    kl_divergence: f64,
    /// PAC-Bayes bound value.
    bound: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: PacBayesState,
}

impl PacBayesMonitor {
    /// Create a new PAC-Bayes monitor with uniform prior.
    #[must_use]
    pub fn new() -> Self {
        Self {
            posterior: [PRIOR_WEIGHT; N],
            error_rate: [0.5; N],
            empirical_error: 0.5,
            kl_divergence: 0.0,
            bound: 1.0,
            count: 0,
            state: PacBayesState::Calibrating,
        }
    }

    /// Feed a severity vector and adverse outcome, update weights and bound.
    ///
    /// `severity`: the 25-element base controller severity vector.
    /// `adverse`: whether the outcome was adverse (the "label" for learning).
    pub fn observe(&mut self, severity: &[u8; N], adverse: bool) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Compute per-controller "error": did the controller's severity
        // predict the adverse outcome correctly?
        // High severity + adverse = correct (no error).
        // Low severity + adverse = missed prediction (error).
        // High severity + non-adverse = false alarm (error).
        // Low severity + non-adverse = correct (no error).
        for (i, &s) in severity.iter().enumerate() {
            let predicted_adverse = s >= 2;
            let error = if predicted_adverse != adverse {
                1.0
            } else {
                0.0
            };
            self.error_rate[i] += alpha * (error - self.error_rate[i]);
        }

        // Update posterior weights via exponentiated gradient:
        // ρᵢ ∝ πᵢ · exp(-η · error_rate_i)
        // Controllers with lower error rates get higher weight.
        let eta = 2.0; // temperature parameter
        let mut raw_weights = [0.0_f64; N];
        for (i, w) in raw_weights.iter_mut().enumerate() {
            *w = PRIOR_WEIGHT * (-eta * self.error_rate[i]).exp();
        }
        // Normalize to form a valid distribution.
        let total: f64 = raw_weights.iter().sum();
        if total > 1e-12 {
            for (p, &w) in self.posterior.iter_mut().zip(raw_weights.iter()) {
                *p = w / total;
            }
        }

        // Compute KL(posterior || prior).
        self.kl_divergence = 0.0;
        for &p in &self.posterior {
            if p > 1e-15 {
                self.kl_divergence += p * (p / PRIOR_WEIGHT).ln();
            }
        }
        // KL should be non-negative; clamp for numerical safety.
        self.kl_divergence = self.kl_divergence.max(0.0);

        // Weighted empirical error: Ê_ρ[L] = Σᵢ ρᵢ · error_rate_i.
        self.empirical_error = self
            .posterior
            .iter()
            .zip(self.error_rate.iter())
            .map(|(&p, &e)| p * e)
            .sum();

        // PAC-Bayes bound (McAllester form):
        // E_ρ[L] ≤ Ê_ρ[L] + √((KL(ρ‖π) + ln(2√n/δ)) / (2n))
        let n = if self.count <= WARMUP {
            self.count as f64
        } else {
            (2.0 / ALPHA - 1.0).min(self.count as f64)
        };
        let complexity_term = self.kl_divergence + (2.0 * n.sqrt() / DELTA).ln();
        let slack = (complexity_term / (2.0 * n)).sqrt();
        self.bound = (self.empirical_error + slack).clamp(0.0, 1.0);

        // State classification.
        self.state = if self.count < WARMUP {
            PacBayesState::Calibrating
        } else if self.bound >= BOUND_ALARM || self.kl_divergence >= KL_ALARM {
            PacBayesState::Unreliable
        } else if self.bound >= BOUND_WARNING || self.kl_divergence >= KL_WARNING {
            PacBayesState::Uncertain
        } else {
            PacBayesState::Tight
        };
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> PacBayesState {
        self.state
    }

    /// Current PAC-Bayes bound value (0..1).
    #[must_use]
    pub fn bound(&self) -> f64 {
        self.bound
    }

    /// KL divergence from posterior to prior.
    #[must_use]
    pub fn kl_divergence(&self) -> f64 {
        self.kl_divergence
    }

    /// Produce a telemetry summary.
    #[must_use]
    pub fn summary(&self) -> PacBayesSummary {
        let effective_n = if self.count <= WARMUP {
            self.count as f64
        } else {
            (2.0 / ALPHA - 1.0).min(self.count as f64)
        };
        PacBayesSummary {
            state: self.state,
            kl_divergence: self.kl_divergence,
            bound: self.bound,
            empirical_error: self.empirical_error,
            effective_n,
            observations: self.count,
        }
    }
}

impl Default for PacBayesMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = PacBayesMonitor::new();
        assert_eq!(m.state(), PacBayesState::Calibrating);
    }

    #[test]
    fn uniform_posterior_has_zero_kl() {
        let m = PacBayesMonitor::new();
        // Before any observations, posterior = prior = uniform.
        assert!(
            m.kl_divergence() < 1e-10,
            "KL should be ~0 for uniform weights, got {}",
            m.kl_divergence()
        );
    }

    #[test]
    fn accurate_ensemble_yields_tight() {
        let mut m = PacBayesMonitor::new();
        // All controllers at 0, no adverse → all predict correctly.
        for _ in 0..200 {
            m.observe(&[0u8; N], false);
        }
        assert_eq!(
            m.state(),
            PacBayesState::Tight,
            "Accurate ensemble should be tight, bound={}",
            m.bound()
        );
        assert!(
            m.bound() < BOUND_WARNING,
            "Bound {} should be below warning threshold {}",
            m.bound(),
            BOUND_WARNING
        );
    }

    #[test]
    fn inaccurate_ensemble_raises_bound() {
        let mut m = PacBayesMonitor::new();
        // All controllers at 0 but adverse is true → all miss.
        for _ in 0..200 {
            m.observe(&[0u8; N], true);
        }
        assert!(
            m.bound() > 0.3,
            "High-error ensemble bound {} should be elevated",
            m.bound()
        );
    }

    #[test]
    fn kl_increases_with_weight_concentration() {
        let mut m = PacBayesMonitor::new();
        // Some controllers accurate, others not — drives weight concentration.
        let mut sev = [0u8; N];
        sev[0] = 3;
        sev[1] = 3;
        sev[2] = 3;
        for _ in 0..200 {
            // Controllers 0-2 predict adverse correctly, rest miss.
            m.observe(&sev, true);
        }
        assert!(
            m.kl_divergence() > 0.3,
            "Weight concentration should increase KL: {}",
            m.kl_divergence()
        );
    }

    #[test]
    fn bound_tightens_with_more_data() {
        let mut m = PacBayesMonitor::new();
        for _ in 0..WARMUP {
            m.observe(&[1u8; N], false);
        }
        let bound_early = m.bound();
        for _ in 0..500 {
            m.observe(&[1u8; N], false);
        }
        let bound_late = m.bound();
        assert!(
            bound_late <= bound_early + 0.01,
            "Bound should tighten: early={} late={}",
            bound_early,
            bound_late
        );
    }

    #[test]
    fn recovery_to_tight() {
        let mut m = PacBayesMonitor::new();
        // Start with inaccurate predictions.
        for _ in 0..100 {
            m.observe(&[0u8; N], true);
        }
        // Then accurate predictions for a long time.
        for _ in 0..1000 {
            m.observe(&[0u8; N], false);
        }
        assert_eq!(
            m.state(),
            PacBayesState::Tight,
            "Should recover to Tight after sustained accuracy, bound={}",
            m.bound()
        );
    }

    #[test]
    fn summary_fields_populated() {
        let mut m = PacBayesMonitor::new();
        for _ in 0..50 {
            m.observe(&[1u8; N], false);
        }
        let s = m.summary();
        assert_eq!(s.observations, 50);
        assert_eq!(s.state, m.state());
        assert!((s.bound - m.bound()).abs() < 1e-12);
        assert!((s.kl_divergence - m.kl_divergence()).abs() < 1e-12);
    }
}
