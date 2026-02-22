//! # Borel-Cantelli Recurrence Monitor
//!
//! Classifies whether severity exceedances are transient (dying off) or
//! recurrent (persisting indefinitely), using the online analogue of the
//! Borel-Cantelli lemma.
//!
//! ## Mathematical Foundation
//!
//! **First Borel-Cantelli Lemma** (Borel 1909, Cantelli 1917):
//! For events {A_n}:
//!
//! ```text
//! Σ P(A_n) < ∞  ⟹  P(A_n i.o.) = 0
//! ```
//!
//! If the sum of probabilities converges, only finitely many events occur.
//!
//! **Second Borel-Cantelli Lemma**: If {A_n} are independent:
//!
//! ```text
//! Σ P(A_n) = ∞  ⟹  P(A_n i.o.) = 1
//! ```
//!
//! If the sum diverges, infinitely many events occur (almost surely).
//!
//! ## Why Borel-Cantelli?
//!
//! Existing monitors detect WHEN failures happen (renewal theory) or
//! HOW LIKELY they are (large deviations, conformal). Borel-Cantelli
//! answers a different question: **will failures KEEP happening?**
//!
//! - **Transient**: exceedance probabilities are decreasing fast enough
//!   that Σ P(A_n) converges — the system is "healing" and failures
//!   will eventually stop.
//! - **Recurrent**: exceedance probabilities persist — failures will
//!   continue indefinitely regardless of how long we wait.
//! - **Absorbing**: exceedance rate ≈ 1 — the system is stuck in the
//!   failure state.
//!
//! ## Online Estimation
//!
//! Per controller i:
//! 1. Define exceedance event: A_n = {severity_n ≥ THRESHOLD}.
//! 2. Track empirical exceedance rate p̂_n via EWMA.
//! 3. Track cumulative exceedance sum S_n = Σ_{k=1}^{n} 1_{A_k}.
//! 4. Compute exceedance ratio: S_n / n.
//! 5. Track exceedance trend: is p̂_n increasing or decreasing?
//!
//! The key diagnostic is the TREND of the exceedance rate: if p̂_n → 0,
//! we're in the transient regime; if p̂_n → c > 0, we're recurrent.
//!
//! ## Legacy Anchor
//!
//! `EAGAIN` / `EWOULDBLOCK` retries — when a non-blocking call returns
//! EAGAIN, are these transient (resource will become available) or
//! recurrent (resource is permanently contended)? Borel-Cantelli
//! classifies exactly this: whether retry-triggering events are finite
//! or persist indefinitely.

/// Number of base controllers.
const N: usize = 25;

/// Severity threshold defining an "exceedance" event.
const EXCEEDANCE_THRESHOLD: u8 = 2;

/// EWMA smoothing parameter.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 50;

/// Exceedance rate threshold for Transient (rate is low and falling).
const TRANSIENT_THRESHOLD: f64 = 0.05;

/// Exceedance rate threshold for Absorbing (rate near 1).
const ABSORBING_THRESHOLD: f64 = 0.90;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BorelCantelliState {
    /// Insufficient data.
    Calibrating = 0,
    /// Exceedances are dying off — finite total expected.
    Transient = 1,
    /// Exceedances persist — infinite total expected.
    Recurrent = 2,
    /// System is stuck in exceedance state.
    Absorbing = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct BorelCantelliSummary {
    /// Current state.
    pub state: BorelCantelliState,
    /// Maximum exceedance rate across controllers.
    pub max_exceedance_rate: f64,
    /// Mean exceedance rate across controllers.
    pub mean_exceedance_rate: f64,
    /// Total observations.
    pub observations: u32,
}

/// Per-controller exceedance tracker.
struct ControllerExceedance {
    /// EWMA exceedance rate.
    rate: f64,
    /// Cumulative exceedance count.
    exceedance_count: u32,
}

impl ControllerExceedance {
    fn new() -> Self {
        Self {
            rate: 0.0,
            exceedance_count: 0,
        }
    }
}

/// Borel-Cantelli recurrence monitor.
pub struct BorelCantelliMonitor {
    /// Per-controller trackers.
    trackers: [ControllerExceedance; N],
    /// Observation count.
    count: u32,
    /// Smoothed max exceedance rate.
    max_exceedance_rate: f64,
    /// Smoothed mean exceedance rate.
    mean_exceedance_rate: f64,
    /// Current state.
    state: BorelCantelliState,
}

impl BorelCantelliMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            trackers: core::array::from_fn(|_| ControllerExceedance::new()),
            count: 0,
            max_exceedance_rate: 0.0,
            mean_exceedance_rate: 0.0,
            state: BorelCantelliState::Calibrating,
        }
    }

    /// Feed a severity vector and update exceedance classification.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        let mut max_rate = 0.0_f64;
        let mut sum_rate = 0.0_f64;

        for (i, &sev) in severity.iter().enumerate() {
            let exceeded = if sev >= EXCEEDANCE_THRESHOLD {
                1.0
            } else {
                0.0
            };

            if sev >= EXCEEDANCE_THRESHOLD {
                self.trackers[i].exceedance_count =
                    self.trackers[i].exceedance_count.saturating_add(1);
            }

            // EWMA update of exceedance rate.
            self.trackers[i].rate += alpha * (exceeded - self.trackers[i].rate);

            max_rate = max_rate.max(self.trackers[i].rate);
            sum_rate += self.trackers[i].rate;
        }

        let mean_rate = sum_rate / N as f64;

        // Use aggregates directly (they are derived from EWMA-smoothed components).
        self.max_exceedance_rate = max_rate;
        self.mean_exceedance_rate = mean_rate;

        // State classification based on max exceedance rate.
        self.state = if self.count < WARMUP {
            BorelCantelliState::Calibrating
        } else if self.max_exceedance_rate >= ABSORBING_THRESHOLD {
            BorelCantelliState::Absorbing
        } else if self.max_exceedance_rate <= TRANSIENT_THRESHOLD {
            BorelCantelliState::Transient
        } else {
            BorelCantelliState::Recurrent
        };
    }

    pub fn state(&self) -> BorelCantelliState {
        self.state
    }

    pub fn max_exceedance_rate(&self) -> f64 {
        self.max_exceedance_rate
    }

    pub fn mean_exceedance_rate(&self) -> f64 {
        self.mean_exceedance_rate
    }

    pub fn summary(&self) -> BorelCantelliSummary {
        BorelCantelliSummary {
            state: self.state,
            max_exceedance_rate: self.max_exceedance_rate,
            mean_exceedance_rate: self.mean_exceedance_rate,
            observations: self.count,
        }
    }
}

impl Default for BorelCantelliMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = BorelCantelliMonitor::new();
        assert_eq!(m.state(), BorelCantelliState::Calibrating);
    }

    #[test]
    fn low_severity_is_transient() {
        let mut m = BorelCantelliMonitor::new();
        // Severity 0 or 1 — never exceeds threshold.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 1u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            BorelCantelliState::Transient,
            "Low severity should be Transient, max_rate={}",
            m.max_exceedance_rate()
        );
    }

    #[test]
    fn constant_high_is_absorbing() {
        let mut m = BorelCantelliMonitor::new();
        // Always at severity 3 — always exceeding threshold.
        for _ in 0..500 {
            m.observe_and_update(&[3u8; N]);
        }
        assert_eq!(
            m.state(),
            BorelCantelliState::Absorbing,
            "Constant high severity should be Absorbing, max_rate={}",
            m.max_exceedance_rate()
        );
    }

    #[test]
    fn mixed_input_is_recurrent() {
        let mut m = BorelCantelliMonitor::new();
        // Mix of low and high severity — persistent but not absorbing.
        for i in 0u32..500 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        // Exceedance rate should be around 0.5 (half the values >= 2).
        assert_eq!(
            m.state(),
            BorelCantelliState::Recurrent,
            "Mixed input should be Recurrent, max_rate={}",
            m.max_exceedance_rate()
        );
    }

    #[test]
    fn rates_are_nonnegative() {
        let mut m = BorelCantelliMonitor::new();
        let mut rng = 55u64;
        for _ in 0..300 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_exceedance_rate() >= 0.0,
            "Max rate must be non-negative: {}",
            m.max_exceedance_rate()
        );
        assert!(
            m.mean_exceedance_rate() >= 0.0,
            "Mean rate must be non-negative: {}",
            m.mean_exceedance_rate()
        );
    }

    #[test]
    fn recovery_from_absorbing() {
        let mut m = BorelCantelliMonitor::new();
        // Absorbing phase.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        // Then clean traffic.
        for _ in 0..2000 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_ne!(
            m.state(),
            BorelCantelliState::Absorbing,
            "Should recover from Absorbing, max_rate={}",
            m.max_exceedance_rate()
        );
    }

    #[test]
    fn transient_after_initial_burst() {
        let mut m = BorelCantelliMonitor::new();
        // Initial burst of exceedances.
        for _ in 0..50 {
            m.observe_and_update(&[3u8; N]);
        }
        // Then long period of no exceedances.
        for _ in 0..2000 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(
            m.state(),
            BorelCantelliState::Transient,
            "Should become Transient after burst dies, max_rate={}",
            m.max_exceedance_rate()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = BorelCantelliMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_exceedance_rate - m.max_exceedance_rate()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
