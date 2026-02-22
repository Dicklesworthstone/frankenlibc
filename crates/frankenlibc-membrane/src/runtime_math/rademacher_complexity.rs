//! # Rademacher Complexity Monitor
//!
//! Data-dependent generalization bound for the controller ensemble,
//! measuring the intrinsic capacity of the severity signal space to
//! correlate with random noise.
//!
//! ## Mathematical Foundation
//!
//! The **empirical Rademacher complexity** (Bartlett & Mendelson 2002)
//! for a function class F over n samples is:
//!
//! ```text
//! R̂_n(F) = (1/n) E_ε[ sup_{f∈F} |Σ_{t=1}^n ε_t · f(x_t)| ]
//! ```
//!
//! where ε_t ∈ {-1, +1} are i.i.d. Rademacher random variables.
//!
//! The **generalization bound** (Bartlett & Mendelson 2002, Theorem 8):
//!
//! ```text
//! sup_{f∈F} |E[f] - Ê_n[f]| ≤ 2·R̂_n(F) + √(ln(2/δ)/(2n))
//! ```
//!
//! with probability ≥ 1-δ.
//!
//! ## Why Rademacher Instead of PAC-Bayes?
//!
//! - **PAC-Bayes** (pac_bayes.rs) bounds how far the posterior weights
//!   have moved from the prior. If KL(ρ‖π) is large, the bound is loose.
//! - **Rademacher** bounds the capacity of the HYPOTHESIS CLASS ITSELF,
//!   independent of any particular weighting. Even with uniform weights,
//!   if the function class is too expressive for the sample size, Rademacher
//!   detects this.
//!
//! Concretely: PAC-Bayes answers "did we overfit the weights?"
//! Rademacher answers "CAN this ensemble overfit, regardless of weights?"
//!
//! ## Online Estimation
//!
//! Full Rademacher requires storing all n samples and re-computing with
//! fresh random signs. For runtime efficiency, we use M fixed random
//! sign vectors and maintain running signed sums per controller:
//!
//! ```text
//! S_{m,i} = Σ_t ε_{m,t} · severity_i(t)    (running signed sum)
//! R̂ ≈ (1/M) Σ_m max_i |S_{m,i}| / n        (Monte Carlo estimate)
//! ```
//!
//! where ε_{m,t} are generated from a deterministic PRNG seeded per m.
//!
//! ## Legacy Anchor
//!
//! `elf`, `dl-*` (loader/symbol resolution) — the dynamic linker's
//! IFUNC resolution cache can overfit to pathological symbol lookup
//! patterns. Rademacher complexity monitors whether the ensemble's
//! capacity to fit noise exceeds what the sample size justifies.

/// Number of base controllers.
const N: usize = 25;

/// Number of random sign vectors for Monte Carlo estimation.
const M: usize = 8;

/// EWMA smoothing factor.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Rademacher complexity threshold for Elevated (ensemble getting expressive).
const ELEVATED_THRESHOLD: f64 = 0.35;

/// Rademacher complexity threshold for Overfit (ensemble too expressive).
const OVERFIT_THRESHOLD: f64 = 0.60;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RademacherState {
    /// Insufficient data.
    Calibrating = 0,
    /// Low complexity — ensemble is well-regularized.
    Controlled = 1,
    /// Moderate complexity — approaching capacity limit.
    Elevated = 2,
    /// High complexity — ensemble can fit noise, predictions unreliable.
    Overfit = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct RademacherSummary {
    /// Current state.
    pub state: RademacherState,
    /// Empirical Rademacher complexity estimate (0..∞).
    pub complexity: f64,
    /// Generalization gap bound (2R̂ + concentration term).
    pub gen_gap_bound: f64,
    /// Total observations.
    pub observations: u32,
}

/// Deterministic PRNG for Rademacher sign generation.
/// Uses a simple xorshift64 seeded per sign-vector index.
struct SignGenerator {
    state: u64,
}

impl SignGenerator {
    /// Construct from a persisted PRNG state.
    /// xorshift64 is a bijection on non-zero u64, so a non-zero initial
    /// seed can never produce a zero state. Guard defensively anyway.
    fn from_state(state: u64) -> Self {
        Self {
            state: if state == 0 { 1 } else { state },
        }
    }

    /// Generate next Rademacher sign: +1.0 or -1.0.
    fn next_sign(&mut self) -> f64 {
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        if self.state & 1 == 0 { 1.0 } else { -1.0 }
    }
}

/// Rademacher complexity monitor.
pub struct RademacherComplexityMonitor {
    /// Per sign-vector, per-controller running signed sums.
    /// signed_sums[m][i] = Σ_t ε_{m,t} · severity_i(t)
    signed_sums: [[f64; N]; M],
    /// PRNG states for each sign vector (deterministic replay).
    generators: [u64; M],
    /// Smoothed Rademacher complexity estimate.
    complexity: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: RademacherState,
}

impl RademacherComplexityMonitor {
    #[must_use]
    pub fn new() -> Self {
        // Seed each generator with a distinct prime-based constant.
        let seeds: [u64; M] = [
            0x9E37_79B9_7F4A_7C15,
            0x6C62_272E_07BB_0142,
            0xBF58_476D_1CE4_E5B9,
            0x94D0_49BB_1331_11EB,
            0x517C_C1B7_2722_0A95,
            0x2545_F491_4F6C_DD1D,
            0x6906_9E3C_E547_F49C,
            0xDE0B_6B3A_7640_0000,
        ];
        Self {
            signed_sums: [[0.0; N]; M],
            generators: seeds,
            complexity: 0.0,
            count: 0,
            state: RademacherState::Calibrating,
        }
    }

    /// Feed a severity vector and update Rademacher complexity estimate.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        let n = self.count as f64;

        // For each sign vector, generate a sign and update signed sums.
        let mut max_abs_sums = [0.0_f64; M];
        for (m, gen_state) in self.generators.iter_mut().enumerate() {
            let mut rng = SignGenerator::from_state(*gen_state);
            let sign = rng.next_sign();
            *gen_state = rng.state; // persist PRNG state

            for (i, &s) in severity.iter().enumerate() {
                self.signed_sums[m][i] += sign * f64::from(s);
            }

            // max_i |S_{m,i}| / n
            let max_abs = self.signed_sums[m]
                .iter()
                .map(|&s| s.abs())
                .fold(0.0_f64, f64::max);
            max_abs_sums[m] = max_abs / n;
        }

        // R̂ ≈ (1/M) Σ_m max_i |S_{m,i}| / n
        let raw_complexity: f64 = max_abs_sums.iter().sum::<f64>() / M as f64;
        self.complexity += alpha * (raw_complexity - self.complexity);

        // State classification.
        self.state = if self.count < WARMUP {
            RademacherState::Calibrating
        } else if self.complexity >= OVERFIT_THRESHOLD {
            RademacherState::Overfit
        } else if self.complexity >= ELEVATED_THRESHOLD {
            RademacherState::Elevated
        } else {
            RademacherState::Controlled
        };
    }

    pub fn state(&self) -> RademacherState {
        self.state
    }

    pub fn complexity(&self) -> f64 {
        self.complexity
    }

    /// Generalization gap bound: 2R̂ + √(ln(2/δ)/(2n)) with δ=0.05.
    pub fn gen_gap_bound(&self) -> f64 {
        let n = if self.count <= WARMUP {
            (self.count as f64).max(1.0)
        } else {
            (2.0 / ALPHA - 1.0).min(self.count as f64)
        };
        let delta = 0.05;
        let concentration = ((2.0_f64 / delta).ln() / (2.0 * n)).sqrt();
        2.0 * self.complexity + concentration
    }

    pub fn summary(&self) -> RademacherSummary {
        RademacherSummary {
            state: self.state,
            complexity: self.complexity,
            gen_gap_bound: self.gen_gap_bound(),
            observations: self.count,
        }
    }
}

impl Default for RademacherComplexityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = RademacherComplexityMonitor::new();
        assert_eq!(m.state(), RademacherState::Calibrating);
    }

    #[test]
    fn constant_inputs_have_low_complexity() {
        let mut m = RademacherComplexityMonitor::new();
        // Constant severity → signed sums perform a random walk → R̂ ~ O(1/√n).
        for _ in 0..500 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(
            m.state(),
            RademacherState::Controlled,
            "Constant inputs should yield low complexity: {}",
            m.complexity()
        );
    }

    #[test]
    fn complexity_is_nonnegative() {
        let mut m = RademacherComplexityMonitor::new();
        for _ in 0..200 {
            m.observe_and_update(&[2u8; N]);
        }
        assert!(
            m.complexity() >= 0.0,
            "Rademacher complexity must be non-negative: {}",
            m.complexity()
        );
    }

    #[test]
    fn gen_gap_bound_decreases_with_data() {
        let mut m = RademacherComplexityMonitor::new();
        for _ in 0..WARMUP {
            m.observe_and_update(&[1u8; N]);
        }
        let early = m.gen_gap_bound();
        for _ in 0..500 {
            m.observe_and_update(&[1u8; N]);
        }
        let late = m.gen_gap_bound();
        assert!(
            late <= early + 0.01,
            "Gap bound should decrease: early={} late={}",
            early,
            late
        );
    }

    #[test]
    fn high_variance_inputs_raise_complexity() {
        let mut m = RademacherComplexityMonitor::new();
        // Rapidly switching between 0 and 3 → high variance in signed sums.
        for i in 0u32..500 {
            let val = if i % 2 == 0 { 0 } else { 3 };
            m.observe_and_update(&[val; N]);
        }
        // High variance inputs should have higher complexity than constant.
        let mut m2 = RademacherComplexityMonitor::new();
        for _ in 0u32..500 {
            m2.observe_and_update(&[1u8; N]);
        }
        assert!(
            m.complexity() >= m2.complexity(),
            "High-variance {} should exceed constant {}",
            m.complexity(),
            m2.complexity()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = RademacherComplexityMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.complexity - m.complexity()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
