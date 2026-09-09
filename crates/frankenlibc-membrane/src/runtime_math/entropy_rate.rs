//! # Shannon Entropy Rate Complexity Monitor
//!
//! Measures the irreducible randomness per time step of the controller
//! severity process using Shannon's entropy rate for stationary Markov
//! chains, providing a normalized complexity metric for the ensemble.
//!
//! ## Mathematical Foundation
//!
//! **Shannon Entropy Rate** (Shannon 1948, Cover & Thomas 2006): For a
//! stationary stochastic process {X\_n}, the entropy rate is:
//!
//! ```text
//! H'(X) = lim_{n→∞} H(X_n | X_{n-1}, ..., X_1)
//! ```
//!
//! For a stationary Markov chain with transition matrix P and stationary
//! distribution π:
//!
//! ```text
//! H'(X) = -Σ_i π_i Σ_j P(j|i) · log₂ P(j|i)
//! ```
//!
//! This is the minimum number of bits needed to describe each new
//! observation given the entire past — the irreducible randomness per
//! time step.
//!
//! ## Properties
//!
//! - **0 ≤ H'(X) ≤ log₂(K)** where K is the alphabet size.
//! - **H'(X) = 0** ↔ the process is deterministic (given the past,
//!   the next state is certain).
//! - **H'(X) = log₂(K)** ↔ the process is IID uniform (the past
//!   provides no information about the future).
//! - **H'(X) ≤ H(X₁)** with equality iff the process is IID.
//!
//! The entropy rate RATIO r = H'(X) / log₂(K) gives a normalized
//! complexity measure in \[0, 1\].
//!
//! ## Why Entropy Rate?
//!
//! Complementary to Fano's inequality (which bounds prediction error
//! from mutual information):
//! - **Fano**: tells you the MINIMUM error any predictor must make.
//! - **Entropy rate**: tells you the MINIMUM description complexity
//!   of the process.
//!
//! High entropy rate = the severity process is intrinsically complex
//! and random. Low entropy rate = the process is simple, compressible,
//! and predictable.
//!
//! This directly measures whether the system's behavior has become
//! chaotic or remains structured.
//!
//! ## Online Estimation
//!
//! We estimate per-controller transition matrices with EWMA smoothing,
//! normalize rows to obtain conditional distributions P(·|i), then
//! compute the stationary distribution π by iterated matrix-vector
//! multiplication (power method, 30 iterations). The entropy rate is
//! then computed as H' = -Σ\_i π\_i Σ\_j P(j|i) log₂ P(j|i) and
//! averaged across all N controllers.
//!
//! ## Legacy Anchor
//!
//! `nss`, `resolv`, `nscd`, `sunrpc` (name service/resolver/cache
//! subsystem) — cache design fundamentally requires knowing the entropy
//! rate of the request sequence:
//! - **H' ≈ 0**: requests are highly repetitive, caching is maximally
//!   effective.
//! - **H' ≈ log₂(K)**: requests are maximally random, no caching
//!   strategy can help.
//! - The entropy rate is the EXACT answer to "how compressible is this
//!   access pattern?"

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing for transition matrix.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Cadence for the expensive stationary-distribution entropy-rate computation.
///
/// Rationale: `controller_entropy_rate()` runs a power method + log2 and is too
/// costly to execute on every observation in strict mode hot paths.
const SAMPLE_INTERVAL: u32 = 16;

/// Entropy rate ratio threshold for `ModerateComplexity`.
const MODERATE_THRESHOLD: f64 = 0.40;

/// Entropy rate ratio threshold for `HighComplexity`.
const HIGH_THRESHOLD: f64 = 0.70;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntropyRateState {
    /// Insufficient data.
    Calibrating = 0,
    /// H'/log₂K < 0.40 — highly structured, compressible process.
    LowComplexity = 1,
    /// 0.40 ≤ H'/log₂K < 0.70 — moderate randomness.
    ModerateComplexity = 2,
    /// H'/log₂K ≥ 0.70 — near-random, incompressible process.
    HighComplexity = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct EntropyRateSummary {
    /// Current state.
    pub state: EntropyRateState,
    /// Smoothed entropy rate H'(X) in bits.
    pub entropy_rate_bits: f64,
    /// Smoothed entropy rate ratio H'(X) / log₂(K), normalized to \[0, 1\].
    pub entropy_rate_ratio: f64,
    /// Total observations.
    pub observations: u32,
}

/// Estimate the stationary distribution π of a K×K row-stochastic
/// transition matrix via the power method (iterated matrix-vector
/// multiplication, 30 iterations starting from uniform).
fn estimate_stationary(probs: &[[f64; K]; K]) -> [f64; K] {
    let mut pi = [1.0 / K as f64; K];
    for _ in 0..30 {
        let mut next = [0.0_f64; K];
        for j in 0..K {
            for i in 0..K {
                next[j] += pi[i] * probs[i][j];
            }
        }
        let sum: f64 = next.iter().sum();
        if sum > 1e-12 {
            for x in &mut next {
                *x /= sum;
            }
        }
        pi = next;
    }
    pi
}

/// Shannon entropy rate complexity monitor.
///
/// Tracks per-controller Markov transition matrices via EWMA smoothing,
/// computes the entropy rate of the aggregate severity process, and
/// classifies process complexity into Low / Moderate / High regimes.
pub struct EntropyRateMonitor {
    /// Per-controller transition matrices T\[ctrl\]\[from\]\[to\], EWMA-smoothed.
    transitions: [[[f64; K]; K]; N],
    /// Previous severity vector.
    prev_severity: [u8; N],
    /// Smoothed entropy rate in bits.
    entropy_rate_bits: f64,
    /// Smoothed entropy rate ratio (H' / log₂K).
    entropy_rate_ratio: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: EntropyRateState,
}

impl EntropyRateMonitor {
    /// Create a new monitor with uniform-prior transition matrices.
    #[must_use]
    pub fn new() -> Self {
        let uniform = 1.0 / K as f64;
        Self {
            transitions: [[[uniform; K]; K]; N],
            prev_severity: [0; N],
            entropy_rate_bits: 0.0,
            entropy_rate_ratio: 0.0,
            count: 0,
            state: EntropyRateState::Calibrating,
        }
    }

    /// Normalize the transition matrix for a single controller,
    /// returning a proper row-stochastic matrix.
    fn normalized_matrix(&self, ctrl: usize) -> [[f64; K]; K] {
        let mut probs = [[0.0_f64; K]; K];
        for (i, row) in self.transitions[ctrl].iter().enumerate() {
            let sum: f64 = row.iter().sum();
            if sum > 1e-12 {
                for (k, &val) in row.iter().enumerate() {
                    probs[i][k] = val / sum;
                }
            } else {
                for p in &mut probs[i] {
                    *p = 1.0 / K as f64;
                }
            }
        }
        probs
    }

    /// Compute the entropy rate H'(X) in bits for a single controller.
    ///
    /// H' = -Σ_i π_i Σ_j P(j|i) log₂ P(j|i)
    fn controller_entropy_rate(&self, ctrl: usize) -> f64 {
        let probs = self.normalized_matrix(ctrl);
        let pi = estimate_stationary(&probs);
        let eps = 1e-15;

        let mut h_rate = 0.0_f64;
        for (i, &pi_i) in pi.iter().enumerate() {
            if pi_i < eps {
                continue;
            }
            for &p_ij in &probs[i] {
                if p_ij > eps {
                    h_rate -= pi_i * p_ij * p_ij.log2();
                }
            }
        }
        // Clamp to valid range: [0, log₂(K)]
        h_rate.clamp(0.0, (K as f64).log2())
    }

    /// Feed a severity vector and update entropy rate estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        if self.count > 1 {
            // Always update transition matrices (cheap).
            for (i, (&prev_s, &cur_s)) in self.prev_severity.iter().zip(severity.iter()).enumerate()
            {
                let from = (prev_s as usize).min(K - 1);
                let to = (cur_s as usize).min(K - 1);

                // EWMA update of the transition row.
                for (s, probability) in self.transitions[i][from].iter_mut().enumerate() {
                    let target = if s == to { 1.0 } else { 0.0 };
                    *probability += alpha * (target - *probability);
                }
            }

            // Heavy part is cadence-only.
            if self.count.is_multiple_of(SAMPLE_INTERVAL) {
                let mut h_sum = 0.0_f64;
                for i in 0..N {
                    h_sum += self.controller_entropy_rate(i);
                }
                let mean_h = h_sum / N as f64;
                let log2_k = (K as f64).log2();
                let ratio = if log2_k > 1e-12 {
                    (mean_h / log2_k).clamp(0.0, 1.0)
                } else {
                    0.0
                };

                // EWMA smooth the aggregate entropy rate.
                self.entropy_rate_bits += alpha * (mean_h - self.entropy_rate_bits);
                self.entropy_rate_ratio += alpha * (ratio - self.entropy_rate_ratio);
            }
        }

        self.prev_severity = *severity;

        // State classification.
        self.state = if self.count < WARMUP {
            EntropyRateState::Calibrating
        } else if self.entropy_rate_ratio >= HIGH_THRESHOLD {
            EntropyRateState::HighComplexity
        } else if self.entropy_rate_ratio >= MODERATE_THRESHOLD {
            EntropyRateState::ModerateComplexity
        } else {
            EntropyRateState::LowComplexity
        };
    }

    /// Current state classification.
    pub fn state(&self) -> EntropyRateState {
        self.state
    }

    /// Smoothed entropy rate in bits.
    pub fn entropy_rate_bits(&self) -> f64 {
        self.entropy_rate_bits
    }

    /// Smoothed entropy rate ratio (H' / log₂K), in \[0, 1\].
    pub fn entropy_rate_ratio(&self) -> f64 {
        self.entropy_rate_ratio
    }

    /// Snapshot summary.
    pub fn summary(&self) -> EntropyRateSummary {
        EntropyRateSummary {
            state: self.state,
            entropy_rate_bits: self.entropy_rate_bits,
            entropy_rate_ratio: self.entropy_rate_ratio,
            observations: self.count,
        }
    }
}

impl Default for EntropyRateMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = EntropyRateMonitor::new();
        assert_eq!(m.state(), EntropyRateState::Calibrating);
    }

    #[test]
    fn constant_inputs_low_complexity() {
        let mut m = EntropyRateMonitor::new();
        // Constant severity → transition matrix concentrates on a single
        // column per active row → H'(X) → 0 → LowComplexity.
        for _ in 0..600 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            m.state(),
            EntropyRateState::LowComplexity,
            "Constant input should be LowComplexity, ratio={}, bits={}",
            m.entropy_rate_ratio(),
            m.entropy_rate_bits()
        );
        assert!(
            m.entropy_rate_bits() < 0.5,
            "Entropy rate should be near zero for constant input: {}",
            m.entropy_rate_bits()
        );
    }

    #[test]
    fn deterministic_cycle_low_complexity() {
        let mut m = EntropyRateMonitor::new();
        // Deterministic cycle: 0→1→2→3→0→...
        // Each row of the transition matrix has a single 1.0 entry → H' = 0.
        for i in 0u32..600 {
            let val = (i % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            EntropyRateState::LowComplexity,
            "Deterministic cycle should be LowComplexity, ratio={}, bits={}",
            m.entropy_rate_ratio(),
            m.entropy_rate_bits()
        );
    }

    #[test]
    fn stochastic_transitions_higher_complexity() {
        let mut m = EntropyRateMonitor::new();
        // PRNG-driven transitions that cover all (from, to) pairs roughly
        // uniformly → each row of P converges to approximately uniform →
        // H' → log₂(K) → ratio → 1.0 → ModerateComplexity or HighComplexity.
        let mut rng = 98765u64;
        for _ in 0..5000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.entropy_rate_ratio() >= MODERATE_THRESHOLD,
            "Stochastic transitions should have moderate+ complexity, ratio={}",
            m.entropy_rate_ratio()
        );
        assert_ne!(
            m.state(),
            EntropyRateState::LowComplexity,
            "PRNG-driven input should not be LowComplexity"
        );
    }

    #[test]
    fn entropy_rate_bounded() {
        let mut m = EntropyRateMonitor::new();
        let log2_k = (K as f64).log2();
        for i in 0u32..500 {
            let mut sev = [0u8; N];
            for (j, s) in sev.iter_mut().enumerate() {
                *s = (((i as usize + j * 7) ^ (j * 13)) % 4) as u8;
            }
            m.observe_and_update(&sev);
        }
        assert!(
            m.entropy_rate_bits() >= 0.0,
            "Entropy rate must be non-negative: {}",
            m.entropy_rate_bits()
        );
        assert!(
            m.entropy_rate_bits() <= log2_k + 1e-9,
            "Entropy rate must be ≤ log₂(K)={}: {}",
            log2_k,
            m.entropy_rate_bits()
        );
    }

    #[test]
    fn ratio_in_unit_interval() {
        let mut m = EntropyRateMonitor::new();
        for i in 0u32..500 {
            let mut sev = [0u8; N];
            for (j, s) in sev.iter_mut().enumerate() {
                *s = (((i as usize).wrapping_mul(11) ^ j.wrapping_mul(5)) % 4) as u8;
            }
            m.observe_and_update(&sev);
        }
        assert!(
            m.entropy_rate_ratio() >= 0.0 && m.entropy_rate_ratio() <= 1.0,
            "Entropy rate ratio should be in [0,1]: {}",
            m.entropy_rate_ratio()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = EntropyRateMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.entropy_rate_bits - m.entropy_rate_bits()).abs() < 1e-12);
        assert!((s.entropy_rate_ratio - m.entropy_rate_ratio()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
