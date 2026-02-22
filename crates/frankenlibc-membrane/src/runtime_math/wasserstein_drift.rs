//! # Wasserstein Drift Monitor
//!
//! 1-Wasserstein (Earth Mover's) distance on severity histograms for
//! metric-aware distributional shift detection.
//!
//! ## Mathematical Foundation
//!
//! The **1-Wasserstein distance** (Kantorovich-Rubinstein, 1958) between
//! two probability distributions P and Q on a metric space is:
//!
//! ```text
//! W₁(P, Q) = inf_{γ ∈ Γ(P,Q)} E_{(x,y)~γ}[|x - y|]
//! ```
//!
//! For discrete distributions on {0, 1, 2, 3} with the standard metric
//! d(i,j) = |i - j|, the 1-Wasserstein distance has an elegant
//! **closed-form** via CDF differences:
//!
//! ```text
//! W₁(P, Q) = Σ_{k=0}^{K-2} |F_P(k) - F_Q(k)|
//! ```
//!
//! where F_P(k) = Σ_{j≤k} p_j is the cumulative distribution function.
//!
//! ## Why Wasserstein Instead of Fisher-Rao?
//!
//! Fisher-Rao (info_geometry.rs) treats severity levels as **unordered
//! categories**. It cannot distinguish a shift from state 0→1 (minor)
//! versus 0→3 (catastrophic) — both are just "different distributions."
//!
//! Wasserstein respects the **ordinal metric structure**: moving mass
//! from severity 0 to severity 3 costs 3× more than moving to severity 1.
//! This is exactly right for safety monitoring where severity magnitude
//! matters, not just distributional shape.
//!
//! The two metrics together give complete coverage:
//! - Fisher-Rao: detects shape changes in rare events (geometric)
//! - Wasserstein: detects magnitude shifts in severity (metric)
//!
//! ## Per-Controller Wasserstein Profile
//!
//! For each of the N=25 base controllers, we maintain an empirical
//! histogram over {0,1,2,3} and compute:
//!
//! ```text
//! wᵢ = W₁(hist_baseline_i, hist_current_i)
//! ```
//!
//! The **aggregate Wasserstein distance** is:
//!
//! ```text
//! W = (1/N) Σᵢ wᵢ
//! ```
//!
//! This mean gives uniform sensitivity across all controllers.
//!
//! ## Implementation
//!
//! Histograms use EWMA smoothing for adaptivity. Baseline is frozen
//! after warmup. The closed-form CDF computation makes each update O(NK)
//! with K=4 states — negligible overhead.

use std::sync::atomic::{AtomicU8, Ordering};

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing factor.
const ALPHA: f64 = 0.05;

/// Warmup observations.
const WARMUP: u32 = 30;

/// Observations at which baseline is frozen.
const BASELINE_FREEZE: u32 = 30;

/// Aggregate W₁ threshold for Transporting.
const TRANSPORT_THRESHOLD: f64 = 0.30;

/// Aggregate W₁ threshold for Displaced.
const DISPLACED_THRESHOLD: f64 = 0.80;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DriftState {
    /// Insufficient data.
    Calibrating = 0,
    /// Distribution close to baseline.
    Stable = 1,
    /// Distribution drifting (moderate W₁).
    Transporting = 2,
    /// Distribution displaced (large W₁).
    Displaced = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone)]
pub struct WassersteinSummary {
    pub state: DriftState,
    pub aggregate_distance: f64,
    pub max_controller_distance: f64,
    pub max_controller_index: usize,
    pub observations: u32,
}

/// Per-controller severity histogram.
#[derive(Clone)]
struct SeverityHistogram {
    /// EWMA-smoothed frequency for each state.
    freq: [f64; K],
}

impl SeverityHistogram {
    fn uniform() -> Self {
        Self {
            freq: [1.0 / K as f64; K],
        }
    }

    /// Update with an observed severity value.
    fn update(&mut self, state: u8, alpha: f64) {
        let idx = (state as usize).min(K - 1);
        for (k, f) in self.freq.iter_mut().enumerate() {
            let target = if k == idx { 1.0 } else { 0.0 };
            *f += alpha * (target - *f);
        }
    }

    /// Normalized probabilities.
    fn probs(&self) -> [f64; K] {
        let total: f64 = self.freq.iter().sum();
        if total < 1e-12 {
            return [1.0 / K as f64; K];
        }
        let mut p = [0.0; K];
        for (k, &f) in self.freq.iter().enumerate() {
            p[k] = f / total;
        }
        p
    }

    /// 1-Wasserstein distance to another histogram.
    /// W₁(P, Q) = Σ_{k=0}^{K-2} |F_P(k) - F_Q(k)|
    fn wasserstein_1(&self, other: &SeverityHistogram) -> f64 {
        let p = self.probs();
        let q = other.probs();
        let mut cdf_p = 0.0;
        let mut cdf_q = 0.0;
        let mut w1 = 0.0;
        // Sum over k = 0..K-2 (CDF at last point is always 1.0).
        for k in 0..(K - 1) {
            cdf_p += p[k];
            cdf_q += q[k];
            w1 += (cdf_p - cdf_q).abs();
        }
        w1
    }
}

/// Wasserstein drift monitor.
pub struct WassersteinDriftMonitor {
    /// Baseline histograms (frozen after warmup).
    baseline: Vec<SeverityHistogram>,
    /// Current running histograms.
    current: Vec<SeverityHistogram>,
    /// Smoothed per-controller Wasserstein distances.
    distances: [f64; N],
    /// Smoothed aggregate Wasserstein distance.
    aggregate_distance: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: DriftState,
    /// Cached state code for lock-free reads.
    pub cached_state: AtomicU8,
}

impl WassersteinDriftMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            baseline: (0..N).map(|_| SeverityHistogram::uniform()).collect(),
            current: (0..N).map(|_| SeverityHistogram::uniform()).collect(),
            distances: [0.0; N],
            aggregate_distance: 0.0,
            count: 0,
            state: DriftState::Calibrating,
            cached_state: AtomicU8::new(0),
        }
    }

    /// Feed a severity vector and update Wasserstein estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Update current histograms.
        for (i, &s) in severity.iter().enumerate() {
            self.current[i].update(s, alpha);

            // During warmup, also update baseline.
            if self.count <= BASELINE_FREEZE {
                self.baseline[i].update(s, alpha);
            }
        }

        // Compute per-controller Wasserstein distances.
        let mut sum = 0.0;
        for i in 0..N {
            let w = self.current[i].wasserstein_1(&self.baseline[i]);
            self.distances[i] = w;
            sum += w;
        }

        // Aggregate: mean Wasserstein distance.
        self.aggregate_distance = sum / N as f64;

        // State classification.
        self.state = if self.count < WARMUP {
            DriftState::Calibrating
        } else if self.aggregate_distance >= DISPLACED_THRESHOLD {
            DriftState::Displaced
        } else if self.aggregate_distance >= TRANSPORT_THRESHOLD {
            DriftState::Transporting
        } else {
            DriftState::Stable
        };

        self.cached_state.store(self.state as u8, Ordering::Relaxed);
    }

    pub fn state(&self) -> DriftState {
        self.state
    }

    pub fn aggregate_distance(&self) -> f64 {
        self.aggregate_distance
    }

    /// Controller with the largest Wasserstein distance from baseline.
    pub fn max_controller(&self) -> (usize, f64) {
        self.distances
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, &d)| (i, d))
            .unwrap_or((0, 0.0))
    }

    pub fn summary(&self) -> WassersteinSummary {
        let (idx, dist) = self.max_controller();
        WassersteinSummary {
            state: self.state,
            aggregate_distance: self.aggregate_distance,
            max_controller_distance: dist,
            max_controller_index: idx,
            observations: self.count,
        }
    }
}

impl Default for WassersteinDriftMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_during_warmup() {
        let mut m = WassersteinDriftMonitor::new();
        for _ in 0..10 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(m.state(), DriftState::Calibrating);
    }

    #[test]
    fn stable_inputs_yield_stable() {
        let mut m = WassersteinDriftMonitor::new();
        let stable = [1u8; N];
        for _ in 0..200 {
            m.observe_and_update(&stable);
        }
        assert_eq!(m.state(), DriftState::Stable);
        assert!(
            m.aggregate_distance() < 0.1,
            "distance {} should be near zero for constant input",
            m.aggregate_distance()
        );
    }

    #[test]
    fn severity_shift_detected() {
        let mut m = WassersteinDriftMonitor::new();
        // Baseline at severity 0.
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&[0u8; N]);
        }
        // Shift to severity 3 (maximum Wasserstein distance = 3.0).
        for _ in 0..500 {
            m.observe_and_update(&[3u8; N]);
        }
        assert!(
            m.state() as u8 >= DriftState::Transporting as u8,
            "should detect transport after severity shift, got {:?} dist={}",
            m.state(),
            m.aggregate_distance()
        );
    }

    #[test]
    fn single_controller_shift_localized() {
        let mut m = WassersteinDriftMonitor::new();
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&[0u8; N]);
        }
        let mut shifted = [0u8; N];
        shifted[7] = 3;
        for _ in 0..300 {
            m.observe_and_update(&shifted);
        }
        let (idx, dist) = m.max_controller();
        assert_eq!(idx, 7, "max drift should be at controller 7");
        assert!(
            dist > 0.1,
            "distance {} should be significant for shifted controller",
            dist
        );
    }

    #[test]
    fn recovery_to_stable() {
        let mut m = WassersteinDriftMonitor::new();
        let base = [1u8; N];
        for _ in 0..BASELINE_FREEZE {
            m.observe_and_update(&base);
        }
        // Shift.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        // Recover.
        for _ in 0..1000 {
            m.observe_and_update(&base);
        }
        assert_eq!(
            m.state(),
            DriftState::Stable,
            "should recover to Stable after returning to baseline"
        );
    }

    #[test]
    fn wasserstein_1_symmetric() {
        let mut a = SeverityHistogram::uniform();
        let mut b = SeverityHistogram::uniform();
        for _ in 0..50 {
            a.update(0, 0.1);
            b.update(3, 0.1);
        }
        let d_ab = a.wasserstein_1(&b);
        let d_ba = b.wasserstein_1(&a);
        assert!(
            (d_ab - d_ba).abs() < 1e-12,
            "W₁ should be symmetric: {} vs {}",
            d_ab,
            d_ba
        );
    }

    #[test]
    fn wasserstein_1_zero_for_identical() {
        let a = SeverityHistogram::uniform();
        let b = SeverityHistogram::uniform();
        let d = a.wasserstein_1(&b);
        assert!(
            d < 1e-12,
            "W₁ between identical distributions should be ~0, got {}",
            d
        );
    }

    #[test]
    fn wasserstein_1_max_distance() {
        // Dirac at 0 vs Dirac at 3 should give W₁ = 3.0.
        let mut a = SeverityHistogram { freq: [0.0; K] };
        a.freq[0] = 1.0;
        let mut b = SeverityHistogram { freq: [0.0; K] };
        b.freq[3] = 1.0;
        let d = a.wasserstein_1(&b);
        assert!(
            (d - 3.0).abs() < 1e-10,
            "W₁(δ₀, δ₃) should be 3.0, got {}",
            d
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = WassersteinDriftMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.aggregate_distance - m.aggregate_distance()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
