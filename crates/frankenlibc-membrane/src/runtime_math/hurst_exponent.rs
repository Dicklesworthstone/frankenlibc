//! # Hurst Exponent / Rescaled Range (R/S) Monitor
//!
//! Estimates the Hurst exponent of the severity process to detect
//! long-range dependence, distinguishing between persistent trends,
//! anti-persistent oscillations, and independent increments.
//!
//! ## Mathematical Foundation
//!
//! **Hurst Exponent** (Hurst 1951, Mandelbrot & Wallis 1969):
//! For a time series {X_k}, partition into blocks of size n, and compute
//! the rescaled range for each block:
//!
//! ```text
//! R(n) = max_{1≤k≤n} W_k - min_{1≤k≤n} W_k
//! S(n) = √(Var(X_1,...,X_n))
//! ```
//!
//! where W_k = Σ_{i=1}^{k} (X_i - X̄) is the cumulative deviation.
//!
//! The Hurst exponent H satisfies:
//!
//! ```text
//! E[R(n)/S(n)] ~ c · n^H   as n → ∞
//! ```
//!
//! So H = log(R/S) / log(n) for large n.
//!
//! **Key regimes:**
//! - H = 0.5: independent increments (Brownian motion / random walk)
//! - H > 0.5: persistent (positive long-range autocorrelation) —
//!   upward trends continue upward, failures beget more failures
//! - H < 0.5: anti-persistent (negative long-range autocorrelation) —
//!   trends reverse more often than random, self-correcting
//!
//! ## Why Hurst Exponent?
//!
//! All existing temporal monitors use EWMA with fixed decay (short
//! memory). They cannot detect correlations that span hundreds of
//! observations. The Hurst exponent captures long-range dependence:
//!
//! - **Persistent (H > 0.5):** failures at time t predict failures at
//!   t+100. The system has "memory" that extends far beyond EWMA reach.
//!   This means current EWMA-based controllers are UNDERESTIMATING
//!   future risk because they don't account for long-range persistence.
//! - **Anti-persistent (H < 0.5):** the system over-corrects, creating
//!   oscillatory behavior. EWMA controllers may be OVERREACTING to
//!   transient fluctuations that would self-correct.
//! - **Independent (H ≈ 0.5):** EWMA assumptions are correct.
//!
//! ## Online Estimation
//!
//! Per controller, we maintain a sliding window of W observations and
//! compute the R/S statistic every SAMPLE_INTERVAL steps. The Hurst
//! exponent is estimated as H = ln(R/S) / ln(W).
//!
//! EWMA smoothing ensures stability across noisy estimates.
//!
//! ## Legacy Anchor
//!
//! `malloc`/`free` — memory allocation patterns exhibit the Hurst
//! effect: bursts of allocation cluster at multiple time scales (not
//! just short-term). A memory allocator tuned for short-range patterns
//! (EWMA) will be surprised by long-range allocation bursts. The Hurst
//! exponent detects this multi-scale clustering.

/// Number of base controllers.
const N: usize = 25;

/// Sliding window size for R/S computation.
const W: usize = 64;

/// Recompute R/S every SAMPLE_INTERVAL steps.
const SAMPLE_INTERVAL: u32 = 16;

/// EWMA smoothing for Hurst estimate.
const ALPHA: f64 = 0.05;

/// Warmup: need at least W observations.
const WARMUP: u32 = 64;

/// Hurst threshold for persistent regime.
const PERSISTENT_THRESHOLD: f64 = 0.60;

/// Hurst threshold for anti-persistent regime.
const ANTI_PERSISTENT_THRESHOLD: f64 = 0.40;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HurstState {
    /// Insufficient data.
    Calibrating = 0,
    /// H ≈ 0.5: independent increments, EWMA assumptions valid.
    Independent = 1,
    /// H > 0.5: persistent long-range dependence, failures cluster.
    Persistent = 2,
    /// H < 0.5: anti-persistent, self-correcting oscillations.
    AntiPersistent = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct HurstSummary {
    /// Current state.
    pub state: HurstState,
    /// Maximum Hurst exponent across controllers.
    pub max_hurst: f64,
    /// Mean Hurst exponent across controllers.
    pub mean_hurst: f64,
    /// Total observations.
    pub observations: u32,
}

/// Compute rescaled range R/S for a sequence.
///
/// Returns R/S where R = range of cumulative deviations, S = std dev.
fn rescaled_range(seq: &[f64], len: usize) -> f64 {
    if len < 2 {
        return 1.0;
    }

    // Mean.
    let mut sum = 0.0;
    for &x in &seq[..len] {
        sum += x;
    }
    let mean = sum / len as f64;

    // Cumulative deviation and variance.
    let mut cumdev = 0.0_f64;
    let mut max_cumdev = f64::NEG_INFINITY;
    let mut min_cumdev = f64::INFINITY;
    let mut var_sum = 0.0;

    for &x in &seq[..len] {
        let dev = x - mean;
        cumdev += dev;
        max_cumdev = max_cumdev.max(cumdev);
        min_cumdev = min_cumdev.min(cumdev);
        var_sum += dev * dev;
    }

    let range = max_cumdev - min_cumdev;
    let std_dev = (var_sum / len as f64).sqrt();

    if std_dev < 1e-12 {
        return 1.0; // Constant input: R/S = 1 by convention.
    }

    range / std_dev
}

/// Hurst exponent monitor.
pub struct HurstExponentMonitor {
    /// Ring buffer per controller: last W severity values.
    buffers: [[f64; W]; N],
    /// Write position in ring buffer.
    pos: usize,
    /// Number of values written (saturates at W).
    filled: usize,
    /// Observation count.
    count: u32,
    /// Smoothed max Hurst exponent.
    max_hurst: f64,
    /// Smoothed mean Hurst exponent.
    mean_hurst: f64,
    /// Current state.
    state: HurstState,
}

impl HurstExponentMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffers: [[0.0; W]; N],
            pos: 0,
            filled: 0,
            count: 0,
            max_hurst: 0.5,
            mean_hurst: 0.5,
            state: HurstState::Calibrating,
        }
    }

    /// Feed a severity vector and update Hurst exponent estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);

        // Write to ring buffers.
        for (i, &sev) in severity.iter().enumerate() {
            self.buffers[i][self.pos] = sev.min(3) as f64;
        }
        self.pos = (self.pos + 1) % W;
        if self.filled < W {
            self.filled += 1;
        }

        // Only compute R/S every SAMPLE_INTERVAL steps after buffer is full.
        if self.filled < W || !self.count.is_multiple_of(SAMPLE_INTERVAL) {
            return;
        }

        let alpha = if self.count <= WARMUP + SAMPLE_INTERVAL {
            0.5
        } else {
            ALPHA
        };

        let log_w = (W as f64).ln();
        let mut max_h = 0.0_f64;
        let mut sum_h = 0.0_f64;

        for buffer in &self.buffers {
            // Linearize the ring buffer.
            let mut linear = [0.0_f64; W];
            for (k, slot) in linear.iter_mut().enumerate() {
                *slot = buffer[(self.pos + k) % W];
            }

            let rs = rescaled_range(&linear, W);
            // H = ln(R/S) / ln(W).
            let h = if rs > 1e-12 {
                (rs.ln() / log_w).clamp(0.0, 1.0)
            } else {
                0.5
            };

            max_h = max_h.max(h);
            sum_h += h;
        }

        let mean_h = sum_h / N as f64;
        self.max_hurst += alpha * (max_h - self.max_hurst);
        self.mean_hurst += alpha * (mean_h - self.mean_hurst);

        // State classification based on mean Hurst exponent.
        self.state = if self.count < WARMUP {
            HurstState::Calibrating
        } else if self.mean_hurst > PERSISTENT_THRESHOLD {
            HurstState::Persistent
        } else if self.mean_hurst < ANTI_PERSISTENT_THRESHOLD {
            HurstState::AntiPersistent
        } else {
            HurstState::Independent
        };
    }

    pub fn state(&self) -> HurstState {
        self.state
    }

    pub fn max_hurst(&self) -> f64 {
        self.max_hurst
    }

    pub fn mean_hurst(&self) -> f64 {
        self.mean_hurst
    }

    pub fn summary(&self) -> HurstSummary {
        HurstSummary {
            state: self.state,
            max_hurst: self.max_hurst,
            mean_hurst: self.mean_hurst,
            observations: self.count,
        }
    }
}

impl Default for HurstExponentMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = HurstExponentMonitor::new();
        assert_eq!(m.state(), HurstState::Calibrating);
    }

    #[test]
    fn hurst_in_unit_interval() {
        let mut m = HurstExponentMonitor::new();
        let mut rng = 42u64;
        for _ in 0..500 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            (0.0..=1.0).contains(&m.mean_hurst()),
            "Mean Hurst should be in [0,1]: {}",
            m.mean_hurst()
        );
        assert!(
            (0.0..=1.0).contains(&m.max_hurst()),
            "Max Hurst should be in [0,1]: {}",
            m.max_hurst()
        );
    }

    #[test]
    fn constant_input_hurst_bounded() {
        let mut m = HurstExponentMonitor::new();
        // Constant input: R/S = 1, so H = 0.
        for _ in 0..500 {
            m.observe_and_update(&[2u8; N]);
        }
        // Constant input has degenerate R/S; H should be small or default.
        assert!(
            m.mean_hurst() < PERSISTENT_THRESHOLD,
            "Constant input should not be Persistent: {}",
            m.mean_hurst()
        );
    }

    #[test]
    fn alternating_is_not_persistent() {
        let mut m = HurstExponentMonitor::new();
        // Alternating 0,3,0,3 — strong anti-persistence.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 3u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_ne!(
            m.state(),
            HurstState::Persistent,
            "Alternating should not be Persistent, mean_hurst={}",
            m.mean_hurst()
        );
    }

    #[test]
    fn trending_input_has_higher_hurst() {
        let mut m = HurstExponentMonitor::new();
        // Trending: slow sawtooth ramp (0,0,0,...,1,1,1,...,2,2,...,3,3,...,0,...)
        // Each level held for 20 steps, creating persistent runs within
        // the 64-element window.
        for _cycle in 0u32..20 {
            for level in 0u8..=3 {
                for _ in 0..20 {
                    m.observe_and_update(&[level; N]);
                }
            }
        }
        // Persistent runs within windows create high R/S → H not anti-persistent.
        assert!(
            m.mean_hurst() > ANTI_PERSISTENT_THRESHOLD,
            "Trending input should have higher Hurst: {}",
            m.mean_hurst()
        );
    }

    #[test]
    fn pseudo_random_near_half() {
        let mut m = HurstExponentMonitor::new();
        let mut rng = 77u64;
        for _ in 0..1000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        // Pseudo-random should be near H = 0.5 (Independent).
        assert!(
            (0.3..=0.8).contains(&m.mean_hurst()),
            "Random input should be near 0.5: {}",
            m.mean_hurst()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = HurstExponentMonitor::new();
        for _ in 0..200 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_hurst - m.max_hurst()).abs() < 1e-12);
        assert_eq!(s.observations, 200);
    }
}
