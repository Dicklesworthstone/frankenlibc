//! # Rough Path Signature Kernel
//!
//! Computes truncated path signatures of validation traces for
//! **universal noncommutative feature extraction**.
//!
//! ## Mathematical Foundation
//!
//! Given a discrete path X = (x₁, …, xₙ) in ℝ⁴, the **signature** is the
//! sequence of iterated integrals:
//!
//! ```text
//! S(X) = (1, S¹(X), S²(X), S³(X))
//! ```
//!
//! where:
//! - `S¹(X)ᵢ = Σₜ Δxᵢₜ`  (net displacement per dimension)
//! - `S²(X)ᵢⱼ = Σₛ<ₜ Δxᵢₛ · Δxⱼₜ`  (ordered cross-correlations)
//! - `S³(X)ᵢⱼₖ = Σᵣ<ₛ<ₜ Δxᵢᵣ · Δxⱼₛ · Δxₖₜ`  (three-point interactions)
//!
//! The truncated signature at depth k is a **universal feature**: it
//! characterizes the path up to tree-like equivalence (Chen's identity).
//!
//! **Universality theorem** (Hambly-Lyons 2010): Any continuous function of
//! the path can be approximated by a linear function of its signature. This
//! means the signature captures strictly more than spectral methods, which
//! only see second-order statistics (covariance).
//!
//! ## Incremental Computation via Chen's Identity
//!
//! Given signature S of path X up to time t, and increment dx at time t+1:
//!
//! ```text
//! S³ᵢⱼₖ += S²ᵢⱼ · dxₖ
//! S²ᵢⱼ  += S¹ᵢ · dxⱼ
//! S¹ᵢ   += dxᵢ
//! ```
//!
//! Update order is depth-descending (level-3 before level-2 before level-1)
//! to use the *old* values at each level.
//!
//! ## Connection to Math Items #24 and #29
//!
//! - #24: Rough-path signature embeddings for long-horizon trace dynamics.
//! - #29: The signature lives in the tensor algebra T(ℝ⁴) under the shuffle
//!   product — semigroup/group-action normalization on trace data.
//!
//! ## Runtime Use
//!
//! The monitor tracks a baseline signature and computes L2 signature distance.
//! Because signatures capture temporal ordering and all cross-moments, they
//! detect attack patterns and workload anomalies that are invisible to spectral
//! methods, Pareto controllers, and CUSUM detectors.

/// Observation dimension (matches spectral monitor).
const SIG_DIM: usize = 4;

/// Signature component counts per level:
/// level 1: d = 4
/// level 2: d² = 16
/// level 3: d³ = 64
/// Total truncated signature dimension: 84
const SIG_LEVEL_1: usize = SIG_DIM;
const SIG_LEVEL_2: usize = SIG_DIM * SIG_DIM;
const SIG_LEVEL_3: usize = SIG_DIM * SIG_DIM * SIG_DIM;

/// Sliding window size for path computation.
const SIG_WINDOW: usize = 32;

/// Number of windows to average before baseline is ready.
const BASELINE_WINDOWS: u64 = 4;

/// Anomaly threshold: signature distance / baseline norm above this triggers.
const ANOMALY_THRESHOLD: f64 = 2.0;

#[inline]
const fn l2_index(i: usize, j: usize) -> usize {
    i * SIG_DIM + j
}

#[inline]
const fn l3_index(i: usize, j: usize, k: usize) -> usize {
    l2_index(i, j) * SIG_DIM + k
}

/// The truncated path signature (depth 3, dimension 4).
///
/// Total storage: 4 + 16 + 64 = 84 f64s = 672 bytes.
#[derive(Debug, Clone)]
pub struct PathSignature {
    /// Level-1: net displacement per dimension. Σₜ Δxᵢₜ.
    pub level1: [f64; SIG_LEVEL_1],
    /// Level-2: ordered cross-correlations. Σₛ<ₜ Δxᵢₛ · Δxⱼₜ.
    pub level2: [f64; SIG_LEVEL_2],
    /// Level-3: three-point ordered interactions. Σᵣ<ₛ<ₜ Δxᵢᵣ · Δxⱼₛ · Δxₖₜ.
    pub level3: [f64; SIG_LEVEL_3],
}

impl PathSignature {
    const fn zero() -> Self {
        Self {
            level1: [0.0; SIG_LEVEL_1],
            level2: [0.0; SIG_LEVEL_2],
            level3: [0.0; SIG_LEVEL_3],
        }
    }

    /// Compute the truncated depth-3 signature of a discrete path via Chen's
    /// identity applied incrementally.
    ///
    /// Cost: O(d³ · n) = O(64 · 32) ≈ 2048 multiply-adds. Negligible.
    #[allow(clippy::needless_range_loop)]
    fn compute(path: &[[f64; SIG_DIM]]) -> Self {
        let mut sig = Self::zero();
        if path.len() < 2 {
            return sig;
        }

        for t in 1..path.len() {
            let mut dx = [0.0f64; SIG_DIM];
            for i in 0..SIG_DIM {
                dx[i] = path[t][i] - path[t - 1][i];
            }

            // Chen's identity: update from highest to lowest level.
            // Level-3: S³ᵢⱼₖ += S²ᵢⱼ · dxₖ (uses OLD S²)
            #[allow(clippy::needless_range_loop)]
            for i in 0..SIG_DIM {
                for j in 0..SIG_DIM {
                    let l2_val = sig.level2[l2_index(i, j)];
                    for k in 0..SIG_DIM {
                        sig.level3[l3_index(i, j, k)] += l2_val * dx[k];
                    }
                }
            }

            // Level-2: S²ᵢⱼ += S¹ᵢ · dxⱼ (uses OLD S¹)
            for i in 0..SIG_DIM {
                let l1_val = sig.level1[i];
                for (j, dxj) in dx.iter().copied().enumerate().take(SIG_DIM) {
                    sig.level2[l2_index(i, j)] += l1_val * dxj;
                }
            }

            // Level-1: S¹ᵢ += dxᵢ
            for (i, dxi) in dx.iter().copied().enumerate().take(SIG_DIM) {
                sig.level1[i] += dxi;
            }
        }

        sig
    }

    /// L2 norm of the full 84-dimensional signature vector.
    fn norm(&self) -> f64 {
        let mut sum = 0.0f64;
        for &v in &self.level1 {
            sum += v * v;
        }
        for &v in &self.level2 {
            sum += v * v;
        }
        for &v in &self.level3 {
            sum += v * v;
        }
        sum.sqrt()
    }

    /// L2 distance to another signature.
    fn distance(&self, other: &Self) -> f64 {
        let mut sum = 0.0f64;
        for i in 0..SIG_LEVEL_1 {
            let d = self.level1[i] - other.level1[i];
            sum += d * d;
        }
        for i in 0..SIG_LEVEL_2 {
            let d = self.level2[i] - other.level2[i];
            sum += d * d;
        }
        for i in 0..SIG_LEVEL_3 {
            let d = self.level3[i] - other.level3[i];
            sum += d * d;
        }
        sum.sqrt()
    }

    /// Blend toward another signature with given weight.
    fn blend(&mut self, other: &Self, alpha: f64) {
        let inv = 1.0 - alpha;
        for i in 0..SIG_LEVEL_1 {
            self.level1[i] = inv * self.level1[i] + alpha * other.level1[i];
        }
        for i in 0..SIG_LEVEL_2 {
            self.level2[i] = inv * self.level2[i] + alpha * other.level2[i];
        }
        for i in 0..SIG_LEVEL_3 {
            self.level3[i] = inv * self.level3[i] + alpha * other.level3[i];
        }
    }
}

/// Anomaly state from the signature kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    /// Baseline is still being established.
    Calibrating,
    /// Current trace signature is within normal range of baseline.
    Normal,
    /// Signature distance exceeds threshold — novel trace pattern detected.
    Anomalous,
}

/// Summary for telemetry export.
#[derive(Debug, Clone, Copy)]
pub struct SignatureSummary {
    pub state: SignatureState,
    pub signature_norm: f64,
    pub baseline_norm: f64,
    pub distance_to_baseline: f64,
    pub anomaly_score: f64,
    pub anomaly_count: u64,
}

/// The rough path signature monitor.
pub struct RoughPathMonitor {
    /// Circular buffer of 4D observations.
    window: [[f64; SIG_DIM]; SIG_WINDOW],
    /// Write position.
    write_pos: usize,
    /// Number of observations recorded (capped at SIG_WINDOW).
    count: usize,
    /// Baseline signature (EWMA of past window signatures).
    baseline: PathSignature,
    /// Baseline norm for relative thresholding.
    baseline_norm: f64,
    /// Number of window signatures averaged into baseline.
    baseline_windows: u64,
    /// Whether baseline is ready for anomaly detection.
    baseline_ready: bool,
    /// Current anomaly state.
    state: SignatureState,
    /// Last computed signature distance.
    last_distance: f64,
    /// Last computed signature norm.
    last_signature_norm: f64,
    /// Total anomaly detections.
    anomaly_count: u64,
}

impl RoughPathMonitor {
    /// Creates a new rough path monitor.
    pub fn new() -> Self {
        Self {
            window: [[0.0; SIG_DIM]; SIG_WINDOW],
            write_pos: 0,
            count: 0,
            baseline: PathSignature::zero(),
            baseline_norm: 0.0,
            baseline_windows: 0,
            baseline_ready: false,
            state: SignatureState::Calibrating,
            last_distance: 0.0,
            last_signature_norm: 0.0,
            anomaly_count: 0,
        }
    }

    /// Record a 4D observation vector.
    pub fn observe(&mut self, values: [f64; SIG_DIM]) {
        self.window[self.write_pos] = values;
        self.write_pos = (self.write_pos + 1) % SIG_WINDOW;
        if self.count < SIG_WINDOW {
            self.count += 1;
        }

        // Recompute signature when we've filled a complete window.
        if self.count >= SIG_WINDOW && self.write_pos == 0 {
            self.recompute();
        }
    }

    /// Current anomaly state.
    pub fn state(&self) -> SignatureState {
        self.state
    }

    /// Anomaly score: distance / baseline_norm. Values > ANOMALY_THRESHOLD
    /// indicate an anomalous trace pattern.
    pub fn anomaly_score(&self) -> f64 {
        if self.baseline_norm < 1e-12 {
            return 0.0;
        }
        self.last_distance / self.baseline_norm
    }

    /// Total anomaly detections over the monitor's lifetime.
    pub fn anomaly_count(&self) -> u64 {
        self.anomaly_count
    }

    /// Telemetry summary.
    pub fn summary(&self) -> SignatureSummary {
        SignatureSummary {
            state: self.state,
            signature_norm: self.last_signature_norm,
            baseline_norm: self.baseline_norm,
            distance_to_baseline: self.last_distance,
            anomaly_score: self.anomaly_score(),
            anomaly_count: self.anomaly_count,
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn recompute(&mut self) {
        // Extract path in chronological order from circular buffer.
        let mut path = [[0.0f64; SIG_DIM]; SIG_WINDOW];
        let start = self.write_pos; // write_pos is 0 after wrapping, but handle general case
        for (i, slot) in path.iter_mut().enumerate().take(self.count) {
            let idx = (start + i) % SIG_WINDOW;
            *slot = self.window[idx];
        }

        let sig = PathSignature::compute(&path[..self.count]);
        let sig_norm = sig.norm();
        self.last_signature_norm = sig_norm;

        if !self.baseline_ready {
            let alpha = 1.0 / (self.baseline_windows as f64 + 1.0);
            self.baseline.blend(&sig, alpha);
            self.baseline_norm = self.baseline.norm();
            self.baseline_windows += 1;
            self.baseline_ready = self.baseline_windows >= BASELINE_WINDOWS;
            self.state = SignatureState::Calibrating;
            return;
        }

        let distance = sig.distance(&self.baseline);
        self.last_distance = distance;
        let score = if self.baseline_norm > 1e-12 {
            distance / self.baseline_norm
        } else {
            0.0
        };

        if score > ANOMALY_THRESHOLD {
            self.state = SignatureState::Anomalous;
            self.anomaly_count += 1;
        } else {
            self.state = SignatureState::Normal;
            // Slow adaptation during normal operation.
            self.baseline.blend(&sig, 0.02);
            self.baseline_norm = self.baseline.norm();
        }
    }
}

impl Default for RoughPathMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_path_has_zero_signature() {
        let path = [[0.0; SIG_DIM]; 5];
        let sig = PathSignature::compute(&path);
        assert_eq!(sig.norm(), 0.0);
    }

    #[test]
    fn constant_path_has_zero_signature() {
        let path = [[1.0, 2.0, 3.0, 4.0]; 10];
        let sig = PathSignature::compute(&path);
        assert!(
            sig.norm() < 1e-10,
            "constant path signature norm = {}",
            sig.norm()
        );
    }

    #[test]
    fn single_dim_displacement() {
        // Path: (0,0,0,0) -> (1,0,0,0) -> (3,0,0,0)
        let path = [
            [0.0, 0.0, 0.0, 0.0],
            [1.0, 0.0, 0.0, 0.0],
            [3.0, 0.0, 0.0, 0.0],
        ];
        let sig = PathSignature::compute(&path);
        // Level-1[0] = total displacement in dim 0 = 3.0
        assert!((sig.level1[0] - 3.0).abs() < 1e-10);
        // Other level-1 components should be zero.
        assert!(sig.level1[1].abs() < 1e-10);
        assert!(sig.level1[2].abs() < 1e-10);
        assert!(sig.level1[3].abs() < 1e-10);
    }

    #[test]
    fn cross_term_level2() {
        // Path: (0,0,0,0) -> (1,0,0,0) -> (1,1,0,0)
        // dx₁ = (1,0,0,0), dx₂ = (0,1,0,0)
        // S²₀₁ = Σₛ<ₜ dx₀ₛ · dx₁ₜ = 1·1 = 1
        // S²₁₀ = Σₛ<ₜ dx₁ₛ · dx₀ₜ = 0·0 = 0 (dx₁ₛ=0 for s=1, dx₀ₜ=0 for t=2)
        let path = [
            [0.0, 0.0, 0.0, 0.0],
            [1.0, 0.0, 0.0, 0.0],
            [1.0, 1.0, 0.0, 0.0],
        ];
        let sig = PathSignature::compute(&path);
        // S²[0*4+1] = S²₀₁ = 1.0
        assert!(
            (sig.level2[1] - 1.0).abs() < 1e-10,
            "S²₀₁ = {}",
            sig.level2[1]
        );
        // S²[1*4+0] = S²₁₀ = 0.0
        assert!(
            sig.level2[SIG_DIM].abs() < 1e-10,
            "S²₁₀ = {}",
            sig.level2[SIG_DIM]
        );
    }

    #[test]
    fn signature_captures_temporal_ordering() {
        // Two paths with the SAME displacements but DIFFERENT ordering.
        // Forward: (0,0,0,0) -> (1,0,0,0) -> (1,1,0,0)
        let forward = [
            [0.0, 0.0, 0.0, 0.0],
            [1.0, 0.0, 0.0, 0.0],
            [1.0, 1.0, 0.0, 0.0],
        ];
        // Reversed: (0,0,0,0) -> (0,1,0,0) -> (1,1,0,0)
        let reversed = [
            [0.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [1.0, 1.0, 0.0, 0.0],
        ];
        let sig_f = PathSignature::compute(&forward);
        let sig_r = PathSignature::compute(&reversed);
        // Level-1 should be identical (same total displacement).
        for (i, (left, right)) in sig_f.level1.iter().zip(sig_r.level1.iter()).enumerate() {
            assert!((*left - *right).abs() < 1e-10, "level-1 differs at {i}");
        }
        // Level-2 should differ (temporal ordering matters).
        let dist = sig_f.distance(&sig_r);
        assert!(
            dist > 0.1,
            "temporal ordering not captured, distance = {dist}"
        );
    }

    #[test]
    fn norm_positive_for_nontrivial_path() {
        let path = [
            [0.0, 0.0, 0.0, 0.0],
            [1.0, 2.0, 3.0, 4.0],
            [2.0, 1.0, 4.0, 3.0],
        ];
        let sig = PathSignature::compute(&path);
        assert!(sig.norm() > 0.0);
    }

    #[test]
    fn distance_to_self_is_zero() {
        let path = [
            [0.0, 1.0, 2.0, 3.0],
            [1.0, 0.0, 3.0, 2.0],
            [2.0, 3.0, 0.0, 1.0],
        ];
        let sig = PathSignature::compute(&path);
        assert!(sig.distance(&sig) < 1e-10);
    }

    #[test]
    fn new_monitor_is_calibrating() {
        let monitor = RoughPathMonitor::new();
        assert_eq!(monitor.state(), SignatureState::Calibrating);
        assert_eq!(monitor.anomaly_count(), 0);
    }

    #[test]
    fn stable_data_reaches_normal() {
        let mut monitor = RoughPathMonitor::new();
        // Feed several windows of stable sinusoidal data.
        for epoch in 0..8 {
            for i in 0..SIG_WINDOW {
                let t = (epoch * SIG_WINDOW + i) as f64 * 0.1;
                monitor.observe([t.sin(), (t * 1.3).cos(), (t * 0.7).sin(), (t * 2.1).cos()]);
            }
        }
        assert_ne!(monitor.state(), SignatureState::Calibrating);
    }

    #[test]
    fn detects_trace_pattern_change() {
        let mut monitor = RoughPathMonitor::new();
        // Phase 1: smooth sinusoidal data for several windows.
        for epoch in 0..8 {
            for i in 0..SIG_WINDOW {
                let t = (epoch * SIG_WINDOW + i) as f64 * 0.1;
                monitor.observe([t.sin(), (t * 1.3).cos(), (t * 0.7).sin(), (t * 2.1).cos()]);
            }
        }
        // Phase 2: completely different pattern — step functions.
        for epoch in 0..4 {
            for i in 0..SIG_WINDOW {
                let v = if i < SIG_WINDOW / 2 { 100.0 } else { -100.0 };
                let flip = if epoch % 2 == 0 { 1.0 } else { -1.0 };
                monitor.observe([v * flip, -v * flip, v, -v]);
            }
        }
        // The step function pattern should be detected as anomalous
        // or the monitor should have detected at least one anomaly.
        assert!(
            monitor.anomaly_count() > 0 || monitor.state() == SignatureState::Anomalous,
            "expected anomaly detection, got {:?} with count {}",
            monitor.state(),
            monitor.anomaly_count(),
        );
    }

    #[test]
    fn level3_nonzero_for_multistep_path() {
        let path = [
            [0.0, 0.0, 0.0, 0.0],
            [1.0, 0.0, 0.0, 0.0],
            [1.0, 1.0, 0.0, 0.0],
            [1.0, 1.0, 1.0, 0.0],
        ];
        let sig = PathSignature::compute(&path);
        // S³₀₁₂ should be nonzero: dx₁=(1,0,0,0), dx₂=(0,1,0,0), dx₃=(0,0,1,0)
        // S³₀₁₂ = Σᵣ<ₛ<ₜ dx₀ᵣ · dx₁ₛ · dx₂ₜ = 1·1·1 = 1
        // S³₀₁₂ index: (0*d + 1)*d + 2 = d + 2
        let idx = l3_index(0, 1, 2);
        assert!(
            (sig.level3[idx] - 1.0).abs() < 1e-10,
            "S³₀₁₂ = {}, expected 1.0",
            sig.level3[idx]
        );
    }
}
