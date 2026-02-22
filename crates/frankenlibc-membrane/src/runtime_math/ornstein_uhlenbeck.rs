//! # Ornstein-Uhlenbeck Mean Reversion Monitor
//!
//! Estimates the mean-reversion speed of the severity process, detecting
//! when the system has lost its tendency to return to equilibrium.
//!
//! ## Mathematical Foundation
//!
//! **Ornstein-Uhlenbeck Process** (Uhlenbeck & Ornstein 1930):
//!
//! ```text
//! dX_t = θ(μ - X_t)dt + σ dW_t
//! ```
//!
//! The discrete-time analogue (Euler-Maruyama):
//!
//! ```text
//! X_{n+1} = X_n + θ(μ - X_n) + ε_n
//!         = (1 - θ)X_n + θμ + ε_n
//! ```
//!
//! This is an AR(1) process X_{n+1} = φX_n + c + ε_n where:
//! - φ = 1 - θ (autoregressive coefficient)
//! - θ = 1 - φ (mean-reversion speed)
//! - μ = c / θ (long-run mean)
//!
//! **Key properties:**
//! - θ > 0: mean-reverting (stable equilibrium)
//! - θ = 0: random walk (unit root, no equilibrium)
//! - θ < 0: mean-diverging (explosive, unstable)
//!
//! ## Why Ornstein-Uhlenbeck?
//!
//! - **Dobrushin**: measures how fast the chain MIXES (forgets initial
//!   conditions). O-U measures how strongly it REVERTS to equilibrium.
//! - **Renewal**: measures WHEN recovery occurs. O-U measures HOW STRONG
//!   the restoring force is.
//! - **Lyapunov**: detects trajectory divergence (chaos). O-U detects
//!   loss of the mean-reverting property (unit root or explosive root).
//!
//! The mean-reversion speed θ is the "spring constant" of the severity
//! process: high θ means perturbations are quickly corrected; low θ
//! means the system drifts; negative θ means perturbations amplify.
//!
//! ## Online Estimation
//!
//! Per controller i, estimate φ via recursive least squares:
//!
//! ```text
//! φ̂_n = Σ X_{k-1} X_k / Σ X_{k-1}²   (centered)
//! ```
//!
//! Then θ̂ = 1 - φ̂. We use EWMA-weighted sums for online computation.
//!
//! ## Legacy Anchor
//!
//! `nice()` / `setpriority()` — process priority scheduling creates
//! mean-reverting dynamics: when a process gets too much CPU, the
//! scheduler pushes it back; too little, and it gets boosted. The
//! strength of this mean reversion (θ) determines scheduling fairness.
//! O-U detects when the "scheduling spring" has broken.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing parameter.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 50;

/// θ threshold below which we consider the process diffusing (near unit root).
const DIFFUSING_THRESHOLD: f64 = 0.02;

/// θ threshold below which we consider the process explosive (negative θ).
const EXPLOSIVE_THRESHOLD: f64 = -0.02;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OuState {
    /// Insufficient data.
    Calibrating = 0,
    /// θ > 0: mean-reverting, stable equilibrium.
    Stable = 1,
    /// θ ≈ 0: random walk, no restoring force.
    Diffusing = 2,
    /// θ < 0: mean-diverging, explosive.
    Explosive = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct OuSummary {
    /// Current state.
    pub state: OuState,
    /// Minimum θ across controllers (worst-case reversion).
    pub min_theta: f64,
    /// Mean θ across controllers.
    pub mean_theta: f64,
    /// Total observations.
    pub observations: u32,
}

/// Per-controller autoregression tracker.
struct ControllerAr {
    /// EWMA of X_{k-1} * X_k (cross product, centered).
    cross: f64,
    /// EWMA of X_{k-1}² (squared lag, centered).
    sq_lag: f64,
    /// Previous severity value (centered).
    prev: f64,
    /// EWMA mean of severity.
    mean: f64,
    /// Estimated φ.
    phi: f64,
    /// Whether we have a previous value.
    has_prev: bool,
}

impl ControllerAr {
    fn new() -> Self {
        Self {
            cross: 0.0,
            sq_lag: 0.0,
            prev: 0.0,
            mean: 0.0,
            phi: 0.0,
            has_prev: false,
        }
    }

    /// Estimated mean-reversion speed θ = 1 - φ.
    fn theta(&self) -> f64 {
        1.0 - self.phi
    }
}

/// Ornstein-Uhlenbeck mean reversion monitor.
pub struct OrnsteinUhlenbeckMonitor {
    /// Per-controller AR trackers.
    trackers: [ControllerAr; N],
    /// Observation count.
    count: u32,
    /// Smoothed minimum θ (worst-case reversion).
    min_theta: f64,
    /// Smoothed mean θ.
    mean_theta: f64,
    /// Current state.
    state: OuState,
}

impl OrnsteinUhlenbeckMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            trackers: core::array::from_fn(|_| ControllerAr::new()),
            count: 0,
            min_theta: 0.0,
            mean_theta: 0.0,
            state: OuState::Calibrating,
        }
    }

    /// Feed a severity vector and update mean-reversion estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        let mut min_theta = f64::MAX;
        let mut sum_theta = 0.0_f64;
        let mut valid_count = 0u32;

        for (i, &sev) in severity.iter().enumerate() {
            let x = (sev as usize).min(K - 1) as f64;
            let t = &mut self.trackers[i];

            // Update running mean.
            t.mean += alpha * (x - t.mean);

            // Center the observation.
            let centered = x - t.mean;

            if t.has_prev {
                // EWMA update of cross-product and squared lag.
                t.cross += alpha * (t.prev * centered - t.cross);
                t.sq_lag += alpha * (t.prev * t.prev - t.sq_lag);

                // Estimate φ = cross / sq_lag.
                if t.sq_lag.abs() > 1e-12 {
                    t.phi = (t.cross / t.sq_lag).clamp(-2.0, 2.0);
                }

                let theta = t.theta();
                min_theta = min_theta.min(theta);
                sum_theta += theta;
                valid_count += 1;
            }

            t.prev = centered;
            t.has_prev = true;
        }

        if valid_count > 0 {
            let raw_min = min_theta;
            let raw_mean = sum_theta / valid_count as f64;

            // Use aggregates directly (they are derived from EWMA-smoothed components).
            self.min_theta = raw_min;
            self.mean_theta = raw_mean;
        }

        // State classification based on minimum θ (worst-case controller).
        self.state = if self.count < WARMUP {
            OuState::Calibrating
        } else if self.min_theta < EXPLOSIVE_THRESHOLD {
            OuState::Explosive
        } else if self.min_theta < DIFFUSING_THRESHOLD {
            OuState::Diffusing
        } else {
            OuState::Stable
        };
    }

    pub fn state(&self) -> OuState {
        self.state
    }

    pub fn min_theta(&self) -> f64 {
        self.min_theta
    }

    pub fn mean_theta(&self) -> f64 {
        self.mean_theta
    }

    pub fn summary(&self) -> OuSummary {
        OuSummary {
            state: self.state,
            min_theta: self.min_theta,
            mean_theta: self.mean_theta,
            observations: self.count,
        }
    }
}

impl Default for OrnsteinUhlenbeckMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = OrnsteinUhlenbeckMonitor::new();
        assert_eq!(m.state(), OuState::Calibrating);
    }

    #[test]
    fn constant_input_has_positive_theta() {
        let mut m = OrnsteinUhlenbeckMonitor::new();
        // Constant severity → centered values all zero → φ undefined.
        // But with tiny EWMA noise, φ → 0, so θ → 1 (strongly reverting).
        for _ in 0..300 {
            m.observe_and_update(&[2u8; N]);
        }
        // θ should be positive (constant = maximally mean-reverting).
        assert!(
            m.min_theta() >= DIFFUSING_THRESHOLD,
            "Constant input should have positive θ: {}",
            m.min_theta()
        );
    }

    #[test]
    fn alternating_is_stable() {
        let mut m = OrnsteinUhlenbeckMonitor::new();
        // Alternating 1,2,1,2 → strong negative autocorrelation
        // → φ < 0 → θ > 1 (over-correcting mean reversion).
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 1u8 } else { 2u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            OuState::Stable,
            "Alternating should be Stable, min_θ={}",
            m.min_theta()
        );
    }

    #[test]
    fn random_walk_is_not_explosive() {
        let mut m = OrnsteinUhlenbeckMonitor::new();
        // Pseudo-random input — should have near-zero autocorrelation.
        let mut rng = 42u64;
        for _ in 0..1000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        // Random iid input has φ ≈ 0, θ ≈ 1 — should not be Explosive.
        assert_ne!(
            m.state(),
            OuState::Explosive,
            "Random input should not be Explosive, min_θ={}",
            m.min_theta()
        );
    }

    #[test]
    fn theta_bounded() {
        let mut m = OrnsteinUhlenbeckMonitor::new();
        let mut rng = 99u64;
        for _ in 0..500 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        // φ is clamped to [-2, 2] so θ = 1 - φ is in [-1, 3].
        assert!(
            m.min_theta() >= -1.5,
            "θ should be reasonably bounded: {}",
            m.min_theta()
        );
        assert!(
            m.mean_theta() <= 3.5,
            "θ should be reasonably bounded: {}",
            m.mean_theta()
        );
    }

    #[test]
    fn recovery_to_stable() {
        let mut m = OrnsteinUhlenbeckMonitor::new();
        // Start with stable alternating.
        for i in 0u32..200 {
            let val = if i.is_multiple_of(2) { 1u8 } else { 2u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(m.state(), OuState::Stable);
        // Add noise, then return to alternating.
        let mut rng = 77u64;
        for _ in 0..200 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        for i in 0u32..1000 {
            let val = if i.is_multiple_of(2) { 1u8 } else { 2u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            OuState::Stable,
            "Should recover to Stable, min_θ={}",
            m.min_theta()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = OrnsteinUhlenbeckMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.min_theta - m.min_theta()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
