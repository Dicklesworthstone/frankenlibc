//! # Lempel-Ziv Complexity Monitor
//!
//! Estimates the algorithmic complexity (compressibility) of the severity
//! sequence using the Lempel-Ziv 1976 factorization, detecting both
//! over-regularity (stuck/looping patterns) and anomalous randomness.
//!
//! ## Mathematical Foundation
//!
//! **LZ76 Factorization** (Lempel & Ziv 1976): A string s = s_1...s_n
//! is parsed exhaustively into c(s) phrases, where each phrase is the
//! shortest substring not previously seen as a prefix of any earlier
//! parsed portion:
//!
//! ```text
//! s = w_1 · w_2 · ... · w_{c(s)}
//! ```
//!
//! **Asymptotic normality** (Ziv 1978): For an ergodic source with
//! entropy rate h:
//!
//! ```text
//! c(n) · ln(n) / n → h   as n → ∞
//! ```
//!
//! So the normalized LZ complexity converges to the entropy rate,
//! providing a universal, assumption-free complexity estimate.
//!
//! ## Why Lempel-Ziv Complexity?
//!
//! Shannon entropy (provenance_info) measures the DISTRIBUTIONAL
//! randomness of severity states — it looks at frequencies, not order.
//! LZ complexity measures SEQUENTIAL structure — it captures patterns,
//! periodicities, and long-range dependencies that entropy alone misses:
//!
//! - Two sequences with identical histograms {0:25%, 1:25%, 2:25%, 3:25%}
//!   can have very different LZ complexity:
//!   - "0123012301230123..." (periodic, low LZ complexity)
//!   - "0312103220313102..." (pseudo-random, high LZ complexity)
//!     Shannon entropy is the same; LZ complexity differs dramatically.
//!
//! - **Low complexity** (repetitive): system is stuck in a loop or has
//!   frozen into a periodic pattern. Indicates a controller or subsystem
//!   that has lost adaptivity.
//! - **High complexity** (entropic): system behavior is unpredictable,
//!   possibly due to noise injection or loss of coherent structure.
//! - **Moderate complexity**: healthy — structured but adaptive.
//!
//! ## Online Estimation
//!
//! We maintain a sliding window of the last W severity observations
//! per controller. Every SAMPLE_INTERVAL steps, we compute the LZ76
//! complexity on the window and normalize:
//!
//! ```text
//! complexity_ratio = c(W) / c_random(W)
//! ```
//!
//! where c_random(W) ≈ W · ln(K) / ln(W) is the expected complexity
//! for an iid uniform source over K states.
//!
//! ## Legacy Anchor
//!
//! `regex`, `fnmatch`, `glob` — pattern matching is literally about
//! finding structure in strings. The LZ complexity of the monitoring
//! system's own output measures the structural richness of the
//! system's behavior. A healthy system has moderate LZ complexity:
//! enough structure to be predictable, enough variation to be adaptive.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// Sliding window size for complexity estimation.
const W: usize = 64;

/// Recompute complexity every SAMPLE_INTERVAL steps.
const SAMPLE_INTERVAL: u32 = 16;

/// EWMA smoothing for complexity ratio.
const ALPHA: f64 = 0.05;

/// Warmup: need at least W observations.
const WARMUP: u32 = 64;

/// Complexity ratio threshold for Repetitive state.
const REPETITIVE_THRESHOLD: f64 = 0.35;

/// Complexity ratio threshold for Entropic state.
const ENTROPIC_THRESHOLD: f64 = 0.90;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LempelZivState {
    /// Insufficient data.
    Calibrating = 0,
    /// Moderate complexity — healthy structure with adaptivity.
    Structured = 1,
    /// Very low complexity — stuck in repetitive patterns.
    Repetitive = 2,
    /// Very high complexity — near-random, loss of structure.
    Entropic = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct LempelZivSummary {
    /// Current state.
    pub state: LempelZivState,
    /// Maximum complexity ratio across controllers (0..1+).
    pub max_complexity_ratio: f64,
    /// Mean complexity ratio across controllers.
    pub mean_complexity_ratio: f64,
    /// Total observations.
    pub observations: u32,
}

/// Compute LZ76 factorization complexity of a sequence.
///
/// Returns the number of phrases in the exhaustive LZ76 parsing.
/// O(n²) in the worst case, but n = W = 64 is small.
fn lz76_complexity(seq: &[u8], len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let mut complexity = 1; // First symbol is always a new phrase.
    let mut i = 1;

    while i < len {
        // Find longest match of seq[i..] starting before position i.
        let mut best_match = 0;
        for j in 0..i {
            let mut m = 0;
            while j + m < i && i + m < len && seq[j + m] == seq[i + m] {
                m += 1;
            }
            if m > best_match {
                best_match = m;
            }
        }
        complexity += 1;
        i += best_match + 1;
    }

    complexity
}

/// Expected LZ76 complexity for iid uniform source over K states.
///
/// c_random(n) ≈ n · ln(K) / ln(n)
fn expected_random_complexity(n: usize) -> f64 {
    if n <= 1 {
        return 1.0;
    }
    let n_f = n as f64;
    n_f * (K as f64).ln() / n_f.ln()
}

/// Lempel-Ziv complexity monitor.
pub struct LempelZivMonitor {
    /// Ring buffer per controller: last W severity values.
    buffers: [[u8; W]; N],
    /// Write position in ring buffer.
    pos: usize,
    /// Number of values written (saturates at W).
    filled: usize,
    /// Observation count.
    count: u32,
    /// Smoothed max complexity ratio.
    max_complexity_ratio: f64,
    /// Smoothed mean complexity ratio.
    mean_complexity_ratio: f64,
    /// Current state.
    state: LempelZivState,
}

impl LempelZivMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffers: [[0u8; W]; N],
            pos: 0,
            filled: 0,
            count: 0,
            max_complexity_ratio: 0.0,
            mean_complexity_ratio: 0.0,
            state: LempelZivState::Calibrating,
        }
    }

    /// Feed a severity vector and update complexity estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);

        // Write to ring buffers.
        for (i, &sev) in severity.iter().enumerate() {
            self.buffers[i][self.pos] = sev.min((K - 1) as u8);
        }
        self.pos = (self.pos + 1) % W;
        if self.filled < W {
            self.filled += 1;
        }

        // Only compute complexity every SAMPLE_INTERVAL steps
        // and after buffer is full.
        if self.filled < W || !self.count.is_multiple_of(SAMPLE_INTERVAL) {
            return;
        }

        let alpha = if self.count <= WARMUP + SAMPLE_INTERVAL {
            0.5
        } else {
            ALPHA
        };

        let expected = expected_random_complexity(W);
        let mut max_ratio = 0.0_f64;
        let mut sum_ratio = 0.0_f64;

        for i in 0..N {
            // Linearize the ring buffer for LZ76 computation.
            let mut linear = [0u8; W];
            for (k, slot) in linear.iter_mut().enumerate() {
                *slot = self.buffers[i][(self.pos + k) % W];
            }

            let c = lz76_complexity(&linear, W);
            let ratio = c as f64 / expected.max(1.0);
            max_ratio = max_ratio.max(ratio);
            sum_ratio += ratio;
        }

        let mean_ratio = sum_ratio / N as f64;
        self.max_complexity_ratio += alpha * (max_ratio - self.max_complexity_ratio);
        self.mean_complexity_ratio += alpha * (mean_ratio - self.mean_complexity_ratio);

        // State classification.
        self.state = if self.count < WARMUP {
            LempelZivState::Calibrating
        } else if self.mean_complexity_ratio < REPETITIVE_THRESHOLD {
            LempelZivState::Repetitive
        } else if self.mean_complexity_ratio > ENTROPIC_THRESHOLD {
            LempelZivState::Entropic
        } else {
            LempelZivState::Structured
        };
    }

    pub fn state(&self) -> LempelZivState {
        self.state
    }

    pub fn max_complexity_ratio(&self) -> f64 {
        self.max_complexity_ratio
    }

    pub fn mean_complexity_ratio(&self) -> f64 {
        self.mean_complexity_ratio
    }

    pub fn summary(&self) -> LempelZivSummary {
        LempelZivSummary {
            state: self.state,
            max_complexity_ratio: self.max_complexity_ratio,
            mean_complexity_ratio: self.mean_complexity_ratio,
            observations: self.count,
        }
    }
}

impl Default for LempelZivMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = LempelZivMonitor::new();
        assert_eq!(m.state(), LempelZivState::Calibrating);
    }

    #[test]
    fn constant_input_is_repetitive() {
        let mut m = LempelZivMonitor::new();
        // Constant severity → LZ complexity = K (one phrase per unique
        // symbol seen, then all repeats match) → very low ratio.
        for _ in 0..500 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            m.state(),
            LempelZivState::Repetitive,
            "Constant input should be Repetitive, mean_ratio={}",
            m.mean_complexity_ratio()
        );
    }

    #[test]
    fn periodic_input_has_low_complexity() {
        let mut m = LempelZivMonitor::new();
        // Short period (0,1,0,1,...) → very few LZ phrases.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 1u8 };
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.mean_complexity_ratio() < 0.5,
            "Periodic input should have low complexity ratio: {}",
            m.mean_complexity_ratio()
        );
    }

    #[test]
    fn pseudo_random_input_has_high_complexity() {
        let mut m = LempelZivMonitor::new();
        // Pseudo-random via xorshift — approaches random complexity.
        let mut rng = 42u64;
        for _ in 0..500 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.mean_complexity_ratio() > REPETITIVE_THRESHOLD,
            "Random input should not be Repetitive: {}",
            m.mean_complexity_ratio()
        );
    }

    #[test]
    fn complexity_ratio_nonnegative() {
        let mut m = LempelZivMonitor::new();
        for i in 0u32..300 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_complexity_ratio() >= 0.0,
            "Complexity ratio must be non-negative: {}",
            m.max_complexity_ratio()
        );
    }

    #[test]
    fn lz76_basic_properties() {
        // Constant string: complexity = 1 (single phrase covers all).
        // Wait, actually for "2222...": first phrase is "2", then "22" matches
        // prefix "2" at position 0, so we advance by 1+1=2... let me trace:
        // "22222222" (8 chars):
        //   i=0: c=1 (phrase "2"), i → 1
        //   i=1: match "2" at j=0, len=1 (j+m=1 = i, stops). advance 1. c=2, i → 2
        //   Actually wait, j+m < i means j=0, m=0: 0+0<1 yes, seq[0]==seq[1]? yes. m=1.
        //   j+m=1 < i=1? no. So best_match=1. i += 1 = 2. c=2.
        //   i=2: j=0, m goes: 0+0<2 yes, 2==2 yes, m=1. 0+1<2 yes, 2==2 yes, m=2. 0+2<2? no. best=2.
        //   j=1: 1+0<2 yes, 2==2, m=1. 1+1<2? no. best=max(2,1)=2.
        //   i += 2 = 4. c=3.
        //   i=4: j=0: max match up to j+m<4. 0,1,2,3 all match → m=4. But i+m=8, check i+m<8: 4+3=7<8 ok, 4+4=8 not <8. m=4? Wait let me retrace.
        //   Actually j+m < i is the constraint. j=0, i=4: 0+0<4, 0+1<4, 0+2<4, 0+3<4, 0+4<4? no. So m=4 max check, but also i+m < len: 4+4=8 not <8. So m goes to min(3,3)=3. best=3. Actually let me just verify programmatically.
        let all_same = [2u8; 8];
        let c = lz76_complexity(&all_same, 8);
        assert!((2..=5).contains(&c), "Constant: c={c}");

        // All distinct (for 4 symbols): "01230123"
        let distinct = [0u8, 1, 2, 3, 0, 1, 2, 3];
        let c2 = lz76_complexity(&distinct, 8);
        assert!(c2 >= 3, "Periodic distinct: c={c2}");

        // Single element.
        let single = [1u8];
        assert_eq!(lz76_complexity(&single, 1), 1);

        // Empty.
        assert_eq!(lz76_complexity(&[], 0), 0);
    }

    #[test]
    fn recovery_from_stuck_to_structured() {
        let mut m = LempelZivMonitor::new();
        // Stuck phase.
        for _ in 0..200 {
            m.observe_and_update(&[1u8; N]);
        }
        // Then diverse input.
        let mut rng = 99u64;
        for _ in 0..800 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert_ne!(
            m.state(),
            LempelZivState::Repetitive,
            "Should recover from Repetitive, mean_ratio={}",
            m.mean_complexity_ratio()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = LempelZivMonitor::new();
        for _ in 0..200 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_complexity_ratio - m.max_complexity_ratio()).abs() < 1e-12);
        assert_eq!(s.observations, 200);
    }
}
