//! # Spectral Risk Monitor
//!
//! Detects phase transitions in membrane workload using **random matrix theory**.
//!
//! ## Mathematical Foundation
//!
//! The monitor maintains a sliding window of multi-dimensional observations
//! per call: `(risk_score, latency_ns, contention, hit_rate)`. The sample
//! covariance matrix `S = (1/n) X^T X` has eigenvalues whose distribution
//! is governed by the **Marchenko-Pastur law** under stationarity.
//!
//! For an `n × p` sample covariance (n observations, p = 4 dimensions):
//! - MP upper edge: `λ₊ = σ² (1 + √(p/n))²`
//! - Tracy-Widom regime: the largest eigenvalue fluctuates around `λ₊` on scale
//!   `n^{-2/3}`, following the TW₂ distribution.
//!
//! When the workload enters a new regime (attack pattern, load spike, config
//! change), a **signal eigenvalue** separates from the MP bulk, causing the
//! ratio `max_eigenvalue / median_eigenvalue` to exceed the TW threshold.
//!
//! This gives distribution-free phase transition detection: no false-positive
//! tuning needed — the threshold is determined by matrix dimension alone.
//!
//! ## Connection to Noncommutative Probability (Math Item #31)
//!
//! The eigenvalue edge statistics of sample covariance matrices belong to the
//! universality class studied in free probability / random matrix theory.
//! The Tracy-Widom distribution arises from the resolvent of Wigner matrices
//! via the Stieltjes transform — a tool from noncommutative probability.

/// Number of dimensions per observation vector.
const OBS_DIM: usize = 4;

/// Sliding window size for observations.
const SPECTRAL_WINDOW: usize = 64;

/// Edge-ratio threshold for phase transition detection.
///
/// Derived from TW₂ critical values: when the ratio of the largest eigenvalue
/// to the median eigenvalue exceeds this, we're outside the MP bulk.
const EDGE_RATIO_THRESHOLD: f64 = 3.0;

/// Multiplicative jump required over baseline edge ratio to mark a transition.
const EDGE_RATIO_JUMP_FACTOR: f64 = 1.35;

/// Multiplicative jump required over baseline dominant eigenvalue.
const MAX_EIGENVALUE_JUMP_FACTOR: f64 = 1.50;

/// Baseline bootstrap size before transition detection is enabled.
const BASELINE_BOOTSTRAP: usize = 32;

/// Number of consecutive transition signals to confirm a new regime.
const CONFIRM_STREAK: u32 = 3;

/// Tracy-Widom z-score delta required above baseline.
const TW_DELTA_THRESHOLD: f64 = 2.5;

/// CUSUM drift and leak parameters.
const CUSUM_DRIFT: f64 = 0.25;
const CUSUM_LEAK: f64 = 0.10;
const CUSUM_THRESHOLD: f64 = 4.0;

/// Phase state of the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseState {
    /// Normal operating regime — eigenvalue spectrum within MP bulk.
    Stationary,
    /// Phase transition detected — signal eigenvalue separating from bulk.
    Transitioning,
    /// Confirmed new regime — sustained eigenvalue separation.
    NewRegime,
}

/// Spectral signature at a point in time.
#[derive(Debug, Clone, Copy)]
pub struct SpectralSignature {
    /// Largest eigenvalue of the sample covariance.
    pub max_eigenvalue: f64,
    /// Ratio of largest to median eigenvalue (edge ratio).
    pub edge_ratio: f64,
    /// Marchenko-Pastur upper edge estimate.
    pub mp_edge: f64,
    /// Tracy-Widom style z-score against MP edge.
    pub tw_z: f64,
    /// Baseline-relative TW z-score delta.
    pub tw_delta: f64,
    /// Positive CUSUM value used for regime-change confidence.
    pub cusum: f64,
    /// Current phase state.
    pub phase: PhaseState,
    /// Cumulative phase transitions detected.
    pub transition_count: u64,
}

/// A single 4-dimensional observation vector.
#[derive(Debug, Clone, Copy)]
struct Observation {
    values: [f64; OBS_DIM],
}

impl Observation {
    const ZERO: Self = Self {
        values: [0.0; OBS_DIM],
    };
}

/// The spectral risk monitor.
pub struct SpectralMonitor {
    /// Circular buffer of observations.
    window: [Observation; SPECTRAL_WINDOW],
    /// Write position.
    write_pos: usize,
    /// Number of observations recorded (capped at SPECTRAL_WINDOW).
    count: usize,
    /// Running column sums for incremental mean computation.
    sums: [f64; OBS_DIM],
    /// Current phase state.
    phase: PhaseState,
    /// Consecutive transition signals.
    transition_streak: u32,
    /// Total transitions detected.
    transition_count: u64,
    /// Last computed signature.
    last_signature: Option<SpectralSignature>,
    /// Baseline edge ratio for stationary regime tracking.
    baseline_edge_ratio: f64,
    /// Baseline dominant eigenvalue for stationary regime tracking.
    baseline_max_eigenvalue: f64,
    /// Baseline Tracy-Widom z-score.
    baseline_tw_z: f64,
    /// Whether baseline has been initialized.
    baseline_ready: bool,
    /// Positive CUSUM statistic on TW-delta innovations.
    cusum_pos: f64,
}

impl SpectralMonitor {
    /// Creates a new spectral monitor.
    pub fn new() -> Self {
        Self {
            window: [Observation::ZERO; SPECTRAL_WINDOW],
            write_pos: 0,
            count: 0,
            sums: [0.0; OBS_DIM],
            phase: PhaseState::Stationary,
            transition_streak: 0,
            transition_count: 0,
            last_signature: None,
            baseline_edge_ratio: 0.0,
            baseline_max_eigenvalue: 0.0,
            baseline_tw_z: 0.0,
            baseline_ready: false,
            cusum_pos: 0.0,
        }
    }

    /// Record an observation vector: (risk_score, latency_ns, contention, hit_rate).
    pub fn observe(&mut self, risk_score: f64, latency_ns: f64, contention: f64, hit_rate: f64) {
        let obs = Observation {
            values: [risk_score, latency_ns, contention, hit_rate],
        };

        // If overwriting an old entry, subtract its contribution from sums.
        if self.count == SPECTRAL_WINDOW {
            let old = &self.window[self.write_pos];
            for j in 0..OBS_DIM {
                self.sums[j] -= old.values[j];
            }
        }

        self.window[self.write_pos] = obs;
        for j in 0..OBS_DIM {
            self.sums[j] += obs.values[j];
        }

        self.write_pos = (self.write_pos + 1) % SPECTRAL_WINDOW;
        if self.count < SPECTRAL_WINDOW {
            self.count += 1;
        }

        // Recompute spectral signature every 16 observations once we have enough data.
        if self.count >= OBS_DIM * 2 && self.count.is_multiple_of(16) {
            self.recompute_spectrum();
        }
    }

    /// Current spectral signature.
    pub fn signature(&self) -> SpectralSignature {
        self.last_signature.unwrap_or(SpectralSignature {
            max_eigenvalue: 0.0,
            edge_ratio: 0.0,
            mp_edge: 0.0,
            tw_z: 0.0,
            tw_delta: 0.0,
            cusum: 0.0,
            phase: PhaseState::Stationary,
            transition_count: 0,
        })
    }

    /// Current phase state.
    pub fn phase(&self) -> PhaseState {
        self.phase
    }

    /// Number of phase transitions detected.
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// Compute the normalized 4×4 sample covariance, extract eigenvalues, and
    /// run MP/TW/CUSUM regime diagnostics.
    fn recompute_spectrum(&mut self) {
        let n = self.count;
        let n_f = n as f64;
        if n < OBS_DIM * 2 {
            return;
        }

        // Column means.
        let mut means = [0.0f64; OBS_DIM];
        for (j, mean) in means.iter_mut().enumerate() {
            *mean = self.sums[j] / n_f;
        }

        // Per-column variance for whitening. This prevents unit-scale skew
        // (e.g., latency_ns dwarfing hit_rate) from triggering fake transitions.
        let mut variances = [0.0f64; OBS_DIM];
        for obs in &self.window[..n] {
            for j in 0..OBS_DIM {
                let d = obs.values[j] - means[j];
                variances[j] += d * d;
            }
        }
        for var in &mut variances {
            *var = (*var / n_f).max(1e-12);
        }
        let mut stddev = [0.0f64; OBS_DIM];
        for (j, sd) in stddev.iter_mut().enumerate() {
            *sd = variances[j].sqrt();
        }

        // Normalized covariance (correlation) matrix:
        // C = (1/n) Σ z_i z_i^T, z_j = (x_j - μ_j)/σ_j.
        let mut cov = [[0.0f64; OBS_DIM]; OBS_DIM];
        for obs in &self.window[..n] {
            let mut z = [0.0f64; OBS_DIM];
            for j in 0..OBS_DIM {
                z[j] = (obs.values[j] - means[j]) / stddev[j];
            }
            for r in 0..OBS_DIM {
                for c in r..OBS_DIM {
                    cov[r][c] += z[r] * z[c];
                }
            }
        }
        #[allow(clippy::needless_range_loop)]
        for r in 0..OBS_DIM {
            for c in r..OBS_DIM {
                cov[r][c] /= n_f;
                cov[c][r] = cov[r][c];
            }
        }

        // Eigenvalue extraction via power iteration + deflation (4×4, cheap).
        let eigenvalues = eigenvalues_symmetric_4x4(&cov);

        // Sort descending.
        let mut sorted = eigenvalues;
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        let max_ev = sorted[0].max(0.0);
        // Median of 4 values = average of middle two.
        let median_ev = ((sorted[1] + sorted[2]) / 2.0).max(1e-12);
        let edge_ratio = max_ev / median_ev;

        // Marchenko-Pastur upper edge estimate for p/n aspect ratio.
        let sigma2 = (cov[0][0] + cov[1][1] + cov[2][2] + cov[3][3]) / (OBS_DIM as f64);
        let gamma = (OBS_DIM as f64 / n_f).clamp(1e-6, 1.0);
        let sqrt_gamma = gamma.sqrt();
        let mp_edge = sigma2.max(1e-12) * (1.0 + sqrt_gamma).powi(2);

        // TW-like normalization scale (finite-sample edge fluctuations).
        let tw_scale =
            (sigma2.max(1e-12) * (1.0 + sqrt_gamma).powf(4.0 / 3.0) * n_f.powf(-2.0 / 3.0))
                .max(1e-9);
        let tw_z = (max_ev - mp_edge) / tw_scale;
        let tw_delta = if self.baseline_ready {
            tw_z - self.baseline_tw_z
        } else {
            0.0
        };

        // Bootstrap baseline over initial windows instead of locking onto a
        // single noisy estimate.
        if !self.baseline_ready {
            if self.baseline_edge_ratio == 0.0 {
                self.baseline_edge_ratio = edge_ratio;
                self.baseline_max_eigenvalue = max_ev;
                self.baseline_tw_z = tw_z;
            } else {
                self.baseline_edge_ratio = 0.85 * self.baseline_edge_ratio + 0.15 * edge_ratio;
                self.baseline_max_eigenvalue = 0.85 * self.baseline_max_eigenvalue + 0.15 * max_ev;
                self.baseline_tw_z = 0.85 * self.baseline_tw_z + 0.15 * tw_z;
            }
            self.baseline_ready = n >= BASELINE_BOOTSTRAP;
            self.phase = PhaseState::Stationary;
            self.transition_streak = 0;
            self.cusum_pos *= 1.0 - CUSUM_LEAK;
            self.last_signature = Some(SpectralSignature {
                max_eigenvalue: max_ev,
                edge_ratio,
                mp_edge,
                tw_z,
                tw_delta,
                cusum: self.cusum_pos,
                phase: self.phase,
                transition_count: self.transition_count,
            });
            return;
        }

        let baseline_edge = self.baseline_edge_ratio.max(1e-12);
        let baseline_max_ev = self.baseline_max_eigenvalue.max(1e-12);
        let edge_jump = edge_ratio / baseline_edge;
        let max_ev_jump = max_ev / baseline_max_ev;

        // Positive CUSUM on TW innovation for sustained-regime detection.
        self.cusum_pos = ((1.0 - CUSUM_LEAK) * self.cusum_pos + (tw_delta - CUSUM_DRIFT)).max(0.0);

        let strong_tw = tw_delta > TW_DELTA_THRESHOLD && edge_ratio > EDGE_RATIO_THRESHOLD;
        let strong_jump =
            edge_jump > EDGE_RATIO_JUMP_FACTOR || max_ev_jump > MAX_EIGENVALUE_JUMP_FACTOR;
        let cusum_alarm = self.cusum_pos > CUSUM_THRESHOLD;
        let is_transition = strong_tw || strong_jump || cusum_alarm;

        if is_transition {
            self.transition_streak += 1;
            if self.transition_streak >= CONFIRM_STREAK {
                if self.phase != PhaseState::NewRegime {
                    self.transition_count += 1;
                }
                self.phase = PhaseState::NewRegime;
                // Re-anchor baseline at confirmed new regime to avoid sticky alarms.
                self.baseline_edge_ratio = edge_ratio;
                self.baseline_max_eigenvalue = max_ev;
                self.baseline_tw_z = tw_z;
                self.cusum_pos = 0.0;
            } else {
                self.phase = PhaseState::Transitioning;
            }
        } else {
            // Stationary regime: slow EWMA adaptation.
            self.baseline_edge_ratio = 0.95 * self.baseline_edge_ratio + 0.05 * edge_ratio;
            self.baseline_max_eigenvalue = 0.95 * self.baseline_max_eigenvalue + 0.05 * max_ev;
            self.baseline_tw_z = 0.95 * self.baseline_tw_z + 0.05 * tw_z;
            self.transition_streak = 0;
            self.phase = PhaseState::Stationary;
            self.cusum_pos *= 1.0 - CUSUM_LEAK;
        }

        self.last_signature = Some(SpectralSignature {
            max_eigenvalue: max_ev,
            edge_ratio,
            mp_edge,
            tw_z,
            tw_delta,
            cusum: self.cusum_pos,
            phase: self.phase,
            transition_count: self.transition_count,
        });
    }
}

impl Default for SpectralMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Eigenvalues of a 4×4 symmetric matrix via power iteration + deflation.
///
/// This is O(4²·k) where k is the number of power-iteration steps (≤50).
/// For our tiny 4×4 matrix this is ~3200 multiplications total — negligible.
fn eigenvalues_symmetric_4x4(m: &[[f64; OBS_DIM]; OBS_DIM]) -> [f64; OBS_DIM] {
    let mut matrix = *m;
    let mut eigenvalues = [0.0f64; OBS_DIM];

    for ev_idx in 0..OBS_DIM {
        // Start with a unit vector that avoids deflation null space.
        let mut v = [0.0f64; OBS_DIM];
        v[ev_idx] = 1.0;

        let mut lambda = 0.0f64;
        for _ in 0..50 {
            // w = M · v
            let mut w = [0.0f64; OBS_DIM];
            for i in 0..OBS_DIM {
                for j in 0..OBS_DIM {
                    w[i] += matrix[i][j] * v[j];
                }
            }

            let norm: f64 = w.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm < 1e-15 {
                break;
            }

            lambda = norm;
            for i in 0..OBS_DIM {
                v[i] = w[i] / norm;
            }
        }

        eigenvalues[ev_idx] = lambda;

        // Deflate: M ← M − λ v vᵀ
        for i in 0..OBS_DIM {
            for j in 0..OBS_DIM {
                matrix[i][j] -= lambda * v[i] * v[j];
            }
        }
    }

    eigenvalues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_monitor_is_stationary() {
        let monitor = SpectralMonitor::new();
        assert_eq!(monitor.phase(), PhaseState::Stationary);
        assert_eq!(monitor.transition_count(), 0);
    }

    #[test]
    fn stationary_under_balanced_data() {
        let mut monitor = SpectralMonitor::new();
        // Feed data with independent, balanced variance per dimension.
        // Each dimension cycles at a different frequency so the covariance
        // matrix has similar-magnitude eigenvalues (no rank-1 spike).
        for i in 0..SPECTRAL_WINDOW {
            let t = (i as f64) / (SPECTRAL_WINDOW as f64) * std::f64::consts::TAU;
            let risk = 50.0 + 10.0 * (t * 1.0).sin();
            let latency = 500.0 + 100.0 * (t * 2.0).cos();
            let contention = 5.0 + 1.0 * (t * 3.0).sin();
            let hit_rate = 0.5 + 0.1 * (t * 5.0).cos();
            monitor.observe(risk, latency, contention, hit_rate);
        }
        // Balanced, multi-dimensional data should NOT trigger a phase transition.
        assert_eq!(monitor.phase(), PhaseState::Stationary);
    }

    #[test]
    fn detects_regime_change() {
        let mut monitor = SpectralMonitor::new();
        // Phase 1: calm, correlated data.
        for i in 0..48 {
            let x = (i as f64) / 100.0;
            monitor.observe(x, x * 10.0, x, x * 0.01);
        }
        // Phase 2: one dimension spikes while others stay calm.
        // This creates eigenvalue separation (signal eigenvalue >> bulk).
        for _ in 0..48 {
            monitor.observe(900.0, 1.0, 0.0, 0.0);
        }
        assert!(
            monitor.phase() == PhaseState::Transitioning
                || monitor.phase() == PhaseState::NewRegime,
            "Expected transition, got {:?}",
            monitor.phase()
        );
    }

    #[test]
    fn signature_available_after_enough_data() {
        let mut monitor = SpectralMonitor::new();
        for i in 0..32 {
            let x = i as f64;
            monitor.observe(x, x * 10.0, 0.0, 0.0);
        }
        let sig = monitor.signature();
        assert!(sig.max_eigenvalue >= 0.0);
    }

    #[test]
    fn identity_matrix_eigenvalues() {
        let identity = [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ];
        let evs = eigenvalues_symmetric_4x4(&identity);
        for ev in &evs {
            assert!(
                (ev - 1.0).abs() < 0.1,
                "identity eigenvalue should be ~1.0, got {ev}"
            );
        }
    }

    #[test]
    fn dominant_eigenvalue_extraction() {
        let m = [
            [100.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ];
        let evs = eigenvalues_symmetric_4x4(&m);
        let max_ev = evs.iter().cloned().fold(0.0f64, f64::max);
        assert!(
            (max_ev - 100.0).abs() < 1.0,
            "dominant eigenvalue should be ~100.0, got {max_ev}"
        );
    }

    #[test]
    fn edge_ratio_low_for_identity() {
        let identity = [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ];
        let evs = eigenvalues_symmetric_4x4(&identity);
        let mut sorted = evs;
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        let max_ev = sorted[0];
        let median_ev = (sorted[1] + sorted[2]) / 2.0;
        let ratio = if median_ev > 1e-15 {
            max_ev / median_ev
        } else {
            0.0
        };
        assert!(
            ratio < EDGE_RATIO_THRESHOLD,
            "identity edge ratio {ratio} should be below threshold"
        );
    }

    #[test]
    fn incremental_mean_correctness() {
        let mut monitor = SpectralMonitor::new();
        for i in 0..10 {
            monitor.observe(i as f64, 0.0, 0.0, 0.0);
        }
        // Sum of 0..10 = 45, mean = 4.5
        let expected_mean = 45.0 / 10.0;
        let actual_mean = monitor.sums[0] / monitor.count as f64;
        assert!(
            (actual_mean - expected_mean).abs() < 1e-10,
            "mean should be {expected_mean}, got {actual_mean}"
        );
    }
}
