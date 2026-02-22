//! # Information Geometry Monitor
//!
//! Fisher-Rao geodesic distance on the statistical manifold of
//! controller state distributions for structural regime shift detection.
//!
//! ## Mathematical Foundation
//!
//! The space of probability distributions forms a **Riemannian manifold**
//! (Amari 1985, Rao 1945). The natural metric on this manifold is the
//! **Fisher information metric**:
//!
//! ```text
//! g_ij(θ) = E[ (∂/∂θᵢ log p(x|θ)) (∂/∂θⱼ log p(x|θ)) ]
//! ```
//!
//! For categorical distributions (each controller has states {0,1,2,3}),
//! the Fisher-Rao geodesic distance between distributions p and q is:
//!
//! ```text
//! d_FR(p, q) = 2 arccos(Σₖ √(pₖ qₖ))
//! ```
//!
//! This is the **Bhattacharyya angle** — the arc-length on the unit
//! sphere after the square-root (Hellinger) embedding.
//!
//! ## Why Fisher-Rao Instead of Euclidean?
//!
//! Euclidean distance on probability vectors is dominated by large
//! components. Fisher-Rao is **intrinsic** — it respects the geometry
//! of the probability simplex:
//!
//! - Moving from (0.01, 0.99) to (0.02, 0.98) is a *large* change
//!   (the rare event doubled in probability).
//! - Moving from (0.50, 0.50) to (0.51, 0.49) is a *small* change
//!   (a minor perturbation near maximum entropy).
//!
//! This sensitivity to changes in the tails is exactly what we need
//! for safety monitoring, where rare states (severity 3) matter most.
//!
//! ## Per-Controller Divergence Profile
//!
//! We maintain a categorical distribution for each of the N=25 base
//! controllers, tracking the empirical frequency of states {0,1,2,3}.
//! For each controller i, we compute:
//!
//! ```text
//! dᵢ = d_FR(πᵢ_baseline, πᵢ_current)
//! ```
//!
//! The **aggregate geodesic distance** is:
//!
//! ```text
//! D = √(Σᵢ dᵢ²)
//! ```
//!
//! This L2 norm of per-controller Fisher-Rao distances gives the
//! overall "distance traveled" on the product manifold.
//!
//! ## Regime Detection
//!
//! A baseline distribution is established during calibration. When
//! the aggregate geodesic distance exceeds thresholds, the system
//! has undergone a structural regime shift — not just a magnitude
//! change, but a change in the *shape* of the state distribution.

use std::sync::atomic::{AtomicU8, Ordering};

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete states per controller (0, 1, 2, 3).
const K: usize = 4;

/// EWMA smoothing for distribution updates.
const ALPHA: f64 = 0.05;

/// Minimum observations before leaving Calibrating.
const WARMUP: u32 = 30;

/// Observations at which baseline is frozen.
const BASELINE_FREEZE: u32 = 30;

/// Laplace smoothing pseudocount to avoid zero probabilities.
const LAPLACE: f64 = 0.01;

/// Geodesic distance threshold for Drifting.
const DRIFT_THRESHOLD: f64 = 0.40;

/// Geodesic distance threshold for StructuralBreak.
const BREAK_THRESHOLD: f64 = 0.80;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GeometryState {
    /// Insufficient data.
    Calibrating = 0,
    /// Distribution is close to baseline.
    Stationary = 1,
    /// Distribution is drifting from baseline.
    Drifting = 2,
    /// Distribution has undergone a structural break.
    StructuralBreak = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone)]
pub struct InfoGeoSummary {
    pub state: GeometryState,
    pub geodesic_distance: f64,
    pub max_controller_distance: f64,
    pub max_controller_index: usize,
    pub observations: u32,
}

/// Per-controller categorical distribution.
#[derive(Clone)]
struct CategoricalDist {
    /// Unnormalized frequency counts (EWMA-smoothed).
    freq: [f64; K],
}

impl CategoricalDist {
    fn uniform() -> Self {
        Self {
            freq: [1.0 / K as f64; K],
        }
    }

    /// Update with an observed state value (0..K).
    fn update(&mut self, state: u8, alpha: f64) {
        let idx = (state as usize).min(K - 1);
        for (k, f) in self.freq.iter_mut().enumerate() {
            let target = if k == idx { 1.0 } else { 0.0 };
            *f += alpha * (target - *f);
        }
    }

    /// Normalized probabilities with Laplace smoothing.
    fn probs(&self) -> [f64; K] {
        let mut p = [0.0; K];
        let total: f64 = self.freq.iter().sum::<f64>() + LAPLACE * K as f64;
        for (k, &f) in self.freq.iter().enumerate() {
            p[k] = (f + LAPLACE) / total;
        }
        p
    }

    /// Fisher-Rao geodesic distance to another distribution.
    /// d_FR(p, q) = 2 arccos(Σₖ √(pₖ qₖ))
    fn fisher_rao_distance(&self, other: &CategoricalDist) -> f64 {
        let p = self.probs();
        let q = other.probs();
        let bc: f64 = p
            .iter()
            .zip(q.iter())
            .map(|(&pi, &qi)| (pi * qi).sqrt())
            .sum();
        // Bhattacharyya coefficient should be in [0, 1], clamp for
        // numerical safety.
        2.0 * bc.clamp(0.0, 1.0).acos()
    }
}

/// Information geometry monitor.
pub struct InfoGeometryMonitor {
    /// Baseline distributions (frozen after warmup).
    baseline: Vec<CategoricalDist>,
    /// Current running distributions.
    current: Vec<CategoricalDist>,
    /// Smoothed per-controller geodesic distances.
    distances: [f64; N],
    /// Smoothed aggregate geodesic distance.
    aggregate_distance: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: GeometryState,
    /// Cached state code for lock-free reads.
    pub cached_state: AtomicU8,
}

impl InfoGeometryMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            baseline: (0..N).map(|_| CategoricalDist::uniform()).collect(),
            current: (0..N).map(|_| CategoricalDist::uniform()).collect(),
            distances: [0.0; N],
            aggregate_distance: 0.0,
            count: 0,
            state: GeometryState::Calibrating,
            cached_state: AtomicU8::new(0),
        }
    }

    /// Feed a severity vector and update geometry estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Update current distributions.
        for (i, &s) in severity.iter().enumerate() {
            self.current[i].update(s, alpha);

            // During warmup, also update baseline.
            if self.count <= BASELINE_FREEZE {
                self.baseline[i].update(s, alpha);
            }
        }

        // Compute per-controller Fisher-Rao distances.
        let mut sum_sq = 0.0;
        for i in 0..N {
            let d = self.current[i].fisher_rao_distance(&self.baseline[i]);
            self.distances[i] = d;
            sum_sq += d * d;
        }

        // Aggregate geodesic distance on product manifold.
        self.aggregate_distance = sum_sq.sqrt();

        // State classification.
        self.state = if self.count < WARMUP {
            GeometryState::Calibrating
        } else if self.aggregate_distance >= BREAK_THRESHOLD {
            GeometryState::StructuralBreak
        } else if self.aggregate_distance >= DRIFT_THRESHOLD {
            GeometryState::Drifting
        } else {
            GeometryState::Stationary
        };

        self.cached_state.store(self.state as u8, Ordering::Relaxed);
    }

    pub fn state(&self) -> GeometryState {
        self.state
    }

    pub fn geodesic_distance(&self) -> f64 {
        self.aggregate_distance
    }

    /// Controller with the largest Fisher-Rao divergence from baseline.
    pub fn max_controller(&self) -> (usize, f64) {
        self.distances
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, &d)| (i, d))
            .unwrap_or((0, 0.0))
    }

    pub fn summary(&self) -> InfoGeoSummary {
        let (idx, dist) = self.max_controller();
        InfoGeoSummary {
            state: self.state,
            geodesic_distance: self.aggregate_distance,
            max_controller_distance: dist,
            max_controller_index: idx,
            observations: self.count,
        }
    }
}

impl Default for InfoGeometryMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_during_warmup() {
        let mut m = InfoGeometryMonitor::new();
        for _ in 0..10 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(m.state(), GeometryState::Calibrating);
    }

    #[test]
    fn stable_inputs_yield_stationary() {
        let mut m = InfoGeometryMonitor::new();
        let stable = [1u8; N];
        for _ in 0..200 {
            m.observe_and_update(&stable);
        }
        assert_eq!(m.state(), GeometryState::Stationary);
        assert!(
            m.geodesic_distance() < 0.1,
            "distance {} should be near zero for constant input",
            m.geodesic_distance()
        );
    }

    #[test]
    fn regime_shift_detected() {
        let mut m = InfoGeometryMonitor::new();
        // Establish baseline at state 0.
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&[0u8; N]);
        }
        // Now shift everything to state 3.
        for _ in 0..400 {
            m.observe_and_update(&[3u8; N]);
        }
        assert!(
            m.state() as u8 >= GeometryState::Drifting as u8,
            "should detect drift/break after regime shift, got {:?}",
            m.state()
        );
    }

    #[test]
    fn single_controller_shift_localized() {
        let mut m = InfoGeometryMonitor::new();
        // Baseline: all zeros.
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&[0u8; N]);
        }
        // Shift only controller 4 to state 3.
        let mut shifted = [0u8; N];
        shifted[4] = 3;
        for _ in 0..300 {
            m.observe_and_update(&shifted);
        }
        let (idx, dist) = m.max_controller();
        assert_eq!(idx, 4, "max divergence should be at controller 4");
        assert!(
            dist > 0.1,
            "divergence {} should be significant for shifted controller",
            dist
        );
    }

    #[test]
    fn recovery_to_stationary() {
        let mut m = InfoGeometryMonitor::new();
        // Baseline at state 1.
        let base = [1u8; N];
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&base);
        }
        // Shift to state 3.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        // Return to baseline.
        for _ in 0..1000 {
            m.observe_and_update(&base);
        }
        assert_eq!(
            m.state(),
            GeometryState::Stationary,
            "should recover to Stationary after returning to baseline"
        );
    }

    #[test]
    fn fisher_rao_distance_symmetric() {
        let mut a = CategoricalDist::uniform();
        let mut b = CategoricalDist::uniform();
        // Make them different.
        for _ in 0..50 {
            a.update(0, 0.1);
            b.update(3, 0.1);
        }
        let d_ab = a.fisher_rao_distance(&b);
        let d_ba = b.fisher_rao_distance(&a);
        assert!(
            (d_ab - d_ba).abs() < 1e-12,
            "Fisher-Rao distance should be symmetric: {} vs {}",
            d_ab,
            d_ba
        );
    }

    #[test]
    fn identical_distributions_zero_distance() {
        let a = CategoricalDist::uniform();
        let b = CategoricalDist::uniform();
        let d = a.fisher_rao_distance(&b);
        assert!(
            d < 1e-10,
            "distance between identical distributions should be ~0, got {}",
            d
        );
    }
}
