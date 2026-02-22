//! # Bifurcation Proximity Detector
//!
//! Detects when the controller severity process is approaching a
//! qualitative regime change (bifurcation) via critical slowing down
//! — the universal early warning signal for bifurcations in dynamical
//! systems.
//!
//! ## Mathematical Foundation
//!
//! **Normal Form Bifurcation Theory** (Guckenheimer & Holmes 1983,
//! Kuznetsov 2004): A dynamical system x' = f(x, mu) undergoes a
//! bifurcation at parameter mu* when the qualitative behavior changes.
//! Key bifurcation types:
//!
//! 1. **Saddle-node** (fold): A stable and unstable fixed point collide
//!    and annihilate. Detected when det(Df) -> 0.
//! 2. **Hopf**: A fixed point loses stability as eigenvalues cross the
//!    imaginary axis. Detected when max(Re(lambda)) crosses zero.
//!
//! For a discrete-time system x_{n+1} = F(x_n), bifurcations occur
//! when eigenvalues of the Jacobian cross the unit circle:
//! - Saddle-node: lambda = 1 (fold)
//! - Period-doubling: lambda = -1 (flip)
//! - Neimark-Sacker: |lambda| = 1 (torus)
//!
//! ## Critical Slowing Down
//!
//! Near a bifurcation, the dominant eigenvalue lambda_1 of the
//! linearized system approaches the stability boundary. The recovery
//! time from perturbations diverges as:
//!
//! ```text
//! t_recovery ~ 1 / |1 - |lambda_1||
//! ```
//!
//! This manifests as increased **lag-1 autocorrelation** in the
//! observed time series — the system takes longer to "forget" its
//! previous state. Specifically:
//!
//! ```text
//! rho_1 = Corr(X_t, X_{t+1}) -> 1  as  lambda_1 -> 1
//! ```
//!
//! This is the universal early warning signal: it applies regardless
//! of the specific bifurcation type (Scheffer et al. 2009,
//! "Early-warning signals for critical transitions", Nature).
//!
//! ## Online Estimation
//!
//! We estimate the lag-1 autocorrelation directly via EWMA:
//!
//! ```text
//! mean_x     <- EWMA of severity
//! mean_xx    <- EWMA of severity^2
//! mean_xy    <- EWMA of severity_t * severity_{t-1}
//! var_x      = mean_xx - mean_x^2
//! autocorr   = (mean_xy - mean_x^2) / max(var_x, epsilon)
//! ```
//!
//! The per-controller autocorrelation rho_i directly measures the
//! critical slowing down indicator. When max(rho_i) approaches 1,
//! at least one controller is near a bifurcation.
//!
//! ## Why Bifurcation Detection?
//!
//! Other monitors detect THAT something changed (changepoint, drift,
//! phase transition). Bifurcation detection detects IMMINENT
//! qualitative change — before it happens. It is the "early warning
//! system" for regime transitions.
//!
//! - **Changepoint** (Adams & MacKay): detects that a change HAS
//!   occurred.
//! - **Wasserstein drift**: detects distributional shift after the
//!   fact.
//! - **Bifurcation proximity**: detects that a change is ABOUT TO
//!   occur, while there is still time to intervene.
//!
//! ## Legacy Anchor
//!
//! VM transitions (`mmap`, `mprotect`, `munmap`) — protection level
//! changes create genuine bifurcations in the safety state space.
//! A memory region going from PROT_READ|PROT_WRITE to PROT_READ
//! fundamentally changes what operations are valid. The bifurcation
//! detector warns when the system is approaching such a qualitative
//! shift.
//!
//! Also: strict/hardened calibration (#12) — threshold drift near
//! a bifurcation point means tiny parameter changes produce large
//! qualitative behavioral shifts. Detecting proximity to the
//! bifurcation allows proactive recalibration.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing for autocorrelation estimates.
const ALPHA: f64 = 0.03;

/// Warmup observations before leaving `Calibrating`.
const WARMUP: u32 = 40;

/// Autocorrelation threshold for `Approaching` (critical slowing down begins).
const APPROACHING_THRESHOLD: f64 = 0.80;

/// Autocorrelation threshold for `Critical` (bifurcation imminent/occurring).
const CRITICAL_THRESHOLD: f64 = 0.95;

/// Minimum variance below which autocorrelation is set to zero
/// (prevents division by near-zero).
const VAR_EPS: f64 = 1e-8;

/// Bifurcation proximity states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BifurcationState {
    /// Insufficient data to classify.
    Calibrating = 0,
    /// Sensitivity (autocorrelation) well below 1 — rapid recovery from
    /// perturbations, far from any bifurcation.
    Stable = 1,
    /// Autocorrelation approaching 1 — critical slowing down detected,
    /// bifurcation may be imminent.
    Approaching = 2,
    /// Autocorrelation near or above 1 — bifurcation imminent or occurring,
    /// qualitative regime change expected.
    Critical = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct BifurcationSummary {
    /// Current bifurcation proximity state.
    pub state: BifurcationState,
    /// Maximum lag-1 autocorrelation across controllers (0..1, clamped).
    pub max_sensitivity: f64,
    /// Mean lag-1 autocorrelation across controllers.
    pub mean_sensitivity: f64,
    /// Total observations processed.
    pub observations: u32,
}

/// Bifurcation proximity detector based on critical slowing down.
///
/// Tracks per-controller lag-1 autocorrelation of the severity process
/// via EWMA-smoothed second-order statistics. When autocorrelation
/// approaches 1, the system is near a bifurcation: recovery time from
/// perturbations diverges, indicating imminent qualitative change.
pub struct BifurcationDetector {
    /// Per-controller EWMA of severity (first moment).
    mean_x: [f64; N],
    /// Per-controller EWMA of severity squared (raw second moment).
    mean_xx: [f64; N],
    /// Per-controller EWMA of severity_t * severity_{t-1} (cross moment).
    mean_xy: [f64; N],
    /// Previous severity vector.
    prev_severity: [u8; N],
    /// Smoothed max autocorrelation across controllers.
    max_sensitivity: f64,
    /// Smoothed mean autocorrelation across controllers.
    mean_sensitivity: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: BifurcationState,
}

impl BifurcationDetector {
    /// Create a new bifurcation detector.
    #[must_use]
    pub fn new() -> Self {
        // Initialize mean_x to midpoint of state range for stability.
        let mid = (K - 1) as f64 / 2.0;
        Self {
            mean_x: [mid; N],
            mean_xx: [mid * mid; N],
            mean_xy: [mid * mid; N],
            prev_severity: [0; N],
            max_sensitivity: 0.0,
            mean_sensitivity: 0.0,
            count: 0,
            state: BifurcationState::Calibrating,
        }
    }

    /// Feed a severity vector and update bifurcation proximity estimates.
    ///
    /// Updates EWMA-smoothed lag-1 autocorrelation per controller and
    /// classifies the overall state based on the maximum and mean
    /// autocorrelation across the ensemble.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        if self.count > 1 {
            let mut max_rho = -1.0_f64;
            let mut sum_rho = 0.0_f64;

            for (i, (&cur_s, &prev_s)) in severity.iter().zip(self.prev_severity.iter()).enumerate()
            {
                let x = (cur_s as usize).min(K - 1) as f64;
                let x_prev = (prev_s as usize).min(K - 1) as f64;

                // Update EWMA moments.
                self.mean_x[i] += alpha * (x - self.mean_x[i]);
                self.mean_xx[i] += alpha * (x * x - self.mean_xx[i]);
                self.mean_xy[i] += alpha * (x * x_prev - self.mean_xy[i]);

                // Compute lag-1 autocorrelation.
                let var = self.mean_xx[i] - self.mean_x[i] * self.mean_x[i];
                let rho = if var > VAR_EPS {
                    let cov = self.mean_xy[i] - self.mean_x[i] * self.mean_x[i];
                    (cov / var).clamp(-1.0, 1.0)
                } else {
                    // Near-zero variance: constant or near-constant input.
                    // No meaningful autocorrelation signal.
                    0.0
                };

                max_rho = max_rho.max(rho);
                sum_rho += rho;
            }

            let mean_rho = sum_rho / N as f64;

            // Smooth the aggregate statistics.
            if self.count == 2 {
                self.max_sensitivity = max_rho;
                self.mean_sensitivity = mean_rho;
            } else {
                self.max_sensitivity += alpha * (max_rho - self.max_sensitivity);
                self.mean_sensitivity += alpha * (mean_rho - self.mean_sensitivity);
            }
        } else {
            // First observation: just initialize moments from the first sample.
            for (i, &s) in severity.iter().enumerate() {
                let x = (s as usize).min(K - 1) as f64;
                self.mean_x[i] = x;
                self.mean_xx[i] = x * x;
                self.mean_xy[i] = x * x;
            }
        }

        self.prev_severity = *severity;

        // State classification based on smoothed max autocorrelation.
        self.state = if self.count < WARMUP {
            BifurcationState::Calibrating
        } else if self.max_sensitivity >= CRITICAL_THRESHOLD {
            BifurcationState::Critical
        } else if self.max_sensitivity >= APPROACHING_THRESHOLD {
            BifurcationState::Approaching
        } else {
            BifurcationState::Stable
        };
    }

    /// Current bifurcation proximity state.
    pub fn state(&self) -> BifurcationState {
        self.state
    }

    /// Maximum lag-1 autocorrelation across controllers (smoothed).
    pub fn max_sensitivity(&self) -> f64 {
        self.max_sensitivity
    }

    /// Mean lag-1 autocorrelation across controllers (smoothed).
    pub fn mean_sensitivity(&self) -> f64 {
        self.mean_sensitivity
    }

    /// Summary for snapshot reporting.
    pub fn summary(&self) -> BifurcationSummary {
        BifurcationSummary {
            state: self.state,
            max_sensitivity: self.max_sensitivity,
            mean_sensitivity: self.mean_sensitivity,
            observations: self.count,
        }
    }
}

impl Default for BifurcationDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let d = BifurcationDetector::new();
        assert_eq!(d.state(), BifurcationState::Calibrating);
        assert_eq!(d.summary().observations, 0);
    }

    #[test]
    fn constant_inputs_stable() {
        // Constant input has zero variance, so autocorrelation is set to 0
        // (graceful handling of degenerate case).
        let mut d = BifurcationDetector::new();
        for _ in 0..300 {
            d.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            d.state(),
            BifurcationState::Stable,
            "Constant inputs should be Stable (rho=0 when var<eps), max_sensitivity={}",
            d.max_sensitivity()
        );
        // Sensitivity should be near zero.
        assert!(
            d.max_sensitivity().abs() < APPROACHING_THRESHOLD,
            "Constant inputs should have low sensitivity: {}",
            d.max_sensitivity()
        );
    }

    #[test]
    fn iid_transitions_stable() {
        // IID (independent) draws have zero lag-1 autocorrelation by
        // definition. The detector should classify this as Stable.
        let mut d = BifurcationDetector::new();
        let mut rng = 42u64;
        for _ in 0..5000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let mut sev = [0u8; N];
            for (j, s) in sev.iter_mut().enumerate() {
                // Each controller gets a pseudo-independent draw.
                let hash = rng.wrapping_mul(j as u64 + 1);
                *s = (hash % 4) as u8;
            }
            d.observe_and_update(&sev);
        }
        assert_eq!(
            d.state(),
            BifurcationState::Stable,
            "IID transitions should be Stable, max_sensitivity={}",
            d.max_sensitivity()
        );
        assert!(
            d.max_sensitivity() < APPROACHING_THRESHOLD,
            "IID autocorrelation should be well below 0.80: {}",
            d.max_sensitivity()
        );
    }

    #[test]
    fn highly_autocorrelated_approaching() {
        // Simulate slow monotone drift: severity increases very slowly,
        // staying at each level for many steps. This produces high
        // lag-1 autocorrelation (system is "sticky" — near a bifurcation).
        let mut d = BifurcationDetector::new();
        for epoch in 0..4u8 {
            let val = epoch.min(3);
            // Each level for many steps: high autocorrelation.
            for _ in 0..500 {
                d.observe_and_update(&[val; N]);
            }
        }
        // After long stretches at constant values with occasional jumps,
        // the autocorrelation should be high.
        let sensitivity = d.max_sensitivity();
        assert!(
            sensitivity >= APPROACHING_THRESHOLD || d.state() != BifurcationState::Stable,
            "Slow drift with long constant stretches should show high \
             autocorrelation or at least leave Stable: sensitivity={}, state={:?}",
            sensitivity,
            d.state()
        );
    }

    #[test]
    fn sensitivity_bounded() {
        // Sensitivity (autocorrelation) must always be in [-1, 1] due to clamping.
        let mut d = BifurcationDetector::new();
        let mut rng = 12345u64;
        for _ in 0..1000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            d.observe_and_update(&[val; N]);
        }
        assert!(
            d.max_sensitivity() >= -1.0 && d.max_sensitivity() <= 1.0,
            "Max sensitivity must be in [-1,1]: {}",
            d.max_sensitivity()
        );
        assert!(
            d.mean_sensitivity() >= -1.0 && d.mean_sensitivity() <= 1.0,
            "Mean sensitivity must be in [-1,1]: {}",
            d.mean_sensitivity()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut d = BifurcationDetector::new();
        for _ in 0..100 {
            d.observe_and_update(&[1u8; N]);
        }
        let s = d.summary();
        assert_eq!(s.state, d.state());
        assert!((s.max_sensitivity - d.max_sensitivity()).abs() < 1e-12);
        assert!((s.mean_sensitivity - d.mean_sensitivity()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }

    #[test]
    fn recovery_after_sticky_period() {
        let mut d = BifurcationDetector::new();
        // Start with a highly autocorrelated (sticky) regime.
        for _ in 0..300 {
            d.observe_and_update(&[3u8; N]);
        }
        // Then switch to IID noise — autocorrelation should decay.
        let mut rng = 99999u64;
        for _ in 0..5000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            d.observe_and_update(&[val; N]);
        }
        assert!(
            d.max_sensitivity() < CRITICAL_THRESHOLD,
            "Should recover from sticky period with IID noise: max_sensitivity={}",
            d.max_sensitivity()
        );
    }

    #[test]
    fn alternating_inputs_not_critical() {
        // Rapid alternation (0, 3, 0, 3, ...) has NEGATIVE autocorrelation
        // (anti-persistent), not positive. Should not be Critical.
        let mut d = BifurcationDetector::new();
        for i in 0u32..2000 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 3u8 };
            d.observe_and_update(&[val; N]);
        }
        assert_ne!(
            d.state(),
            BifurcationState::Critical,
            "Rapid alternation should not be Critical (negative autocorrelation), \
             max_sensitivity={}",
            d.max_sensitivity()
        );
    }
}
