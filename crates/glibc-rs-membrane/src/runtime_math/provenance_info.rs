//! # Information-Theoretic Provenance Tag Controller
//!
//! Implements information-theoretic provenance tag design with quantified
//! collision/corruption bounds for the allocation fingerprint subsystem
//! (math item #11).
//!
//! ## Mathematical Foundation
//!
//! The allocation fingerprint system uses SipHash-2-4 to generate 128-bit
//! tags. The **information-theoretic security** of this scheme depends on:
//!
//! ### Shannon Entropy
//!
//! For a random variable X taking values in a finite set with probability
//! distribution p(x):
//!
//! ```text
//! H(X) = -Σ_x p(x) · log₂(p(x))
//! ```
//!
//! For uniformly random 128-bit tags, H(X) = 128 bits. Any deviation
//! from uniformity reduces H(X), weakening collision resistance.
//!
//! ### Rényi Entropy (Order 2)
//!
//! The collision probability is determined by the Rényi entropy of order 2:
//!
//! ```text
//! H₂(X) = -log₂(Σ_x p(x)²)
//! ```
//!
//! The collision probability for two independent draws is:
//!
//! ```text
//! P(collision) = 2^{-H₂(X)}
//! ```
//!
//! For ideal 128-bit tags, P(collision) = 2^{-128}. If H₂ drops, the
//! collision probability rises *exponentially*.
//!
//! ### Min-Entropy
//!
//! The worst-case collision bound uses min-entropy:
//!
//! ```text
//! H_∞(X) = -log₂(max_x p(x))
//! ```
//!
//! This gives the worst-case guessing probability: P(guess) = 2^{-H_∞(X)}.
//!
//! ## Runtime Application
//!
//! We monitor the empirical distribution of allocation fingerprint bytes
//! to detect entropy degradation that would weaken the allocation integrity
//! subsystem. Specifically:
//!
//! 1. **Byte frequency tracking**: Maintain a histogram of observed byte
//!    values across the low-order bits of fingerprint tags.
//!
//! 2. **Shannon entropy estimation**: H(X) should be near 8.0 bits/byte
//!    for uniformly random tags. Significant drop → key bias.
//!
//! 3. **Rényi H₂ estimation**: Directly measures collision probability.
//!    Drop below 7.0 bits/byte → collision risk exceeds design bounds.
//!
//! 4. **Birthday bound monitoring**: For N active allocations with H₂
//!    entropy per tag, the collision probability is:
//!
//!    ```text
//!    P(any collision) ≈ N² / 2^{H₂+1}
//!    ```
//!
//!    When N grows or H₂ drops, the birthday bound tightens.
//!
//! ## Connection to Math Item #11
//!
//! Information-theoretic provenance tag design with quantified
//! collision/corruption bounds.
//!
//! ## Legacy Anchor
//!
//! `malloc`, `nptl` (allocator/threading/temporal safety) — the
//! fingerprint subsystem is the allocation integrity foundation.

/// Histogram bins for byte value frequency tracking.
const BYTE_BINS: usize = 256;

/// Observation window for entropy estimation.
const ENTROPY_WINDOW: usize = 1024;

/// EWMA decay for entropy tracking.
const EWMA_ALPHA: f64 = 0.005;

/// Shannon entropy threshold for warning (bits/byte, ideal = 8.0).
const SHANNON_WARNING_THRESHOLD: f64 = 7.5;

/// Shannon entropy threshold for alarm.
const SHANNON_ALARM_THRESHOLD: f64 = 6.5;

/// Rényi H₂ threshold for collision risk warning (bits/byte).
const RENYI_WARNING_THRESHOLD: f64 = 7.0;

/// Rényi H₂ threshold for critical collision risk.
const RENYI_ALARM_THRESHOLD: f64 = 6.0;

/// Calibration observations needed.
const CALIBRATION_OBS: u64 = 256;

/// Provenance controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProvenanceState {
    /// Insufficient observations for entropy estimation.
    Calibrating = 0,
    /// Entropy within design bounds — collision resistance intact.
    Secure = 1,
    /// Entropy degrading — collision probability rising.
    EntropyDrift = 2,
    /// Collision risk exceeds design bounds — key rotation recommended.
    CollisionRisk = 3,
}

/// Telemetry snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProvenanceSnapshot {
    /// Shannon entropy estimate (bits/byte, 0..8).
    pub shannon_entropy: f64,
    /// Rényi H₂ entropy estimate (bits/byte, 0..8).
    pub renyi_h2: f64,
    /// Min-entropy estimate (bits/byte, 0..8).
    pub min_entropy: f64,
    /// Estimated collision probability (log₂ scale, more negative = safer).
    pub collision_log2: f64,
    /// Current state.
    pub state: ProvenanceState,
    /// Total bytes observed.
    pub observations: u64,
    /// Collision risk detection count.
    pub collision_risk_count: u64,
}

/// Online information-theoretic provenance tag monitor.
pub struct ProvenanceInfoController {
    /// Byte frequency histogram (running counts).
    histogram: [u64; BYTE_BINS],
    /// Total bytes observed.
    observations: u64,
    /// EWMA Shannon entropy estimate.
    shannon_ewma: f64,
    /// EWMA Rényi H₂ estimate.
    renyi_ewma: f64,
    /// Current state.
    state: ProvenanceState,
    /// Collision risk detection count.
    collision_risk_count: u64,
}

impl ProvenanceInfoController {
    /// Create a new provenance info controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            histogram: [0u64; BYTE_BINS],
            observations: 0,
            shannon_ewma: 8.0, // Start optimistic (ideal entropy).
            renyi_ewma: 8.0,
            state: ProvenanceState::Calibrating,
            collision_risk_count: 0,
        }
    }

    /// Observe a fingerprint byte sample.
    ///
    /// Feed the low-order bytes of allocation fingerprints here.
    /// The controller tracks the empirical distribution and estimates
    /// Shannon, Rényi, and min-entropy to detect degradation.
    pub fn observe_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.histogram[b as usize] += 1;
            self.observations += 1;
        }

        // Periodically re-estimate entropy.
        if self.observations.is_multiple_of(ENTROPY_WINDOW as u64) {
            self.update_entropy();
        }
    }

    /// Observe a single fingerprint tag (as u64 low bits).
    pub fn observe_tag(&mut self, tag: u64) {
        let bytes = tag.to_le_bytes();
        self.observe_bytes(&bytes);
    }

    /// Re-estimate entropy from the current histogram.
    fn update_entropy(&mut self) {
        if self.observations < CALIBRATION_OBS {
            self.state = ProvenanceState::Calibrating;
            return;
        }

        let n = self.observations as f64;
        let mut shannon = 0.0f64;
        let mut sum_p_sq = 0.0f64;

        for &count in &self.histogram {
            if count > 0 {
                let p = count as f64 / n;
                shannon -= p * p.log2();
                sum_p_sq += p * p;
            }
        }

        let renyi_h2 = if sum_p_sq > 0.0 {
            -sum_p_sq.log2()
        } else {
            8.0
        };

        // Update EWMA.
        self.shannon_ewma = (1.0 - EWMA_ALPHA) * self.shannon_ewma + EWMA_ALPHA * shannon;
        self.renyi_ewma = (1.0 - EWMA_ALPHA) * self.renyi_ewma + EWMA_ALPHA * renyi_h2;

        // State transition.
        if self.renyi_ewma < RENYI_ALARM_THRESHOLD || self.shannon_ewma < SHANNON_ALARM_THRESHOLD {
            if self.state != ProvenanceState::CollisionRisk {
                self.collision_risk_count += 1;
            }
            self.state = ProvenanceState::CollisionRisk;
        } else if self.renyi_ewma < RENYI_WARNING_THRESHOLD
            || self.shannon_ewma < SHANNON_WARNING_THRESHOLD
        {
            self.state = ProvenanceState::EntropyDrift;
        } else {
            self.state = ProvenanceState::Secure;
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> ProvenanceState {
        self.state
    }

    /// Shannon entropy estimate (bits/byte).
    #[must_use]
    pub fn shannon_entropy(&self) -> f64 {
        self.shannon_ewma
    }

    /// Rényi H₂ entropy estimate (bits/byte).
    #[must_use]
    pub fn renyi_h2(&self) -> f64 {
        self.renyi_ewma
    }

    /// Telemetry snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ProvenanceSnapshot {
        let n = self.observations as f64;
        let mut max_p = 0.0f64;
        if self.observations > 0 {
            for &count in &self.histogram {
                let p = count as f64 / n;
                max_p = max_p.max(p);
            }
        }
        let min_entropy = if max_p > 0.0 { -max_p.log2() } else { 8.0 };

        // Birthday bound collision probability (log₂).
        // P ≈ N²/2^{H₂+1} → log₂(P) ≈ 2·log₂(N) - H₂ - 1
        // Use H₂ scaled to 128-bit tag (H₂ * 16 bytes).
        let tag_h2 = self.renyi_ewma * 16.0; // Scale from per-byte to per-tag.
        let log2_n = if self.observations > 0 {
            (self.observations as f64).log2()
        } else {
            0.0
        };
        let collision_log2 = 2.0 * log2_n - tag_h2 - 1.0;

        ProvenanceSnapshot {
            shannon_entropy: self.shannon_ewma,
            renyi_h2: self.renyi_ewma,
            min_entropy,
            collision_log2,
            state: self.state,
            observations: self.observations,
            collision_risk_count: self.collision_risk_count,
        }
    }
}

impl Default for ProvenanceInfoController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = ProvenanceInfoController::new();
        assert_eq!(ctrl.state(), ProvenanceState::Calibrating);
    }

    #[test]
    fn uniform_bytes_stay_secure() {
        let mut ctrl = ProvenanceInfoController::new();
        // Feed uniformly distributed bytes.
        for round in 0..16u64 {
            let mut buf = [0u8; 256];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((i as u64 + round * 7) % 256) as u8;
            }
            ctrl.observe_bytes(&buf);
        }
        assert_eq!(
            ctrl.state(),
            ProvenanceState::Secure,
            "Uniform bytes should be Secure"
        );
        assert!(
            ctrl.shannon_entropy() > 7.0,
            "Shannon entropy should be high: {}",
            ctrl.shannon_entropy()
        );
    }

    #[test]
    fn biased_bytes_trigger_drift() {
        let mut ctrl = ProvenanceInfoController::new();
        // Feed heavily biased bytes (mostly 0x42).
        for _ in 0..64 {
            let buf = [0x42u8; 256];
            ctrl.observe_bytes(&buf);
        }
        assert!(
            ctrl.state() == ProvenanceState::EntropyDrift
                || ctrl.state() == ProvenanceState::CollisionRisk,
            "Biased bytes should trigger drift/collision, got {:?}",
            ctrl.state()
        );
    }

    #[test]
    fn tag_observation_works() {
        let mut ctrl = ProvenanceInfoController::new();
        for i in 0..2048u64 {
            ctrl.observe_tag(i.wrapping_mul(0x9e3779b97f4a7c15));
        }
        // Should have enough data and good entropy from the hash-like spread.
        assert_ne!(ctrl.state(), ProvenanceState::Calibrating);
    }

    #[test]
    fn snapshot_fields_populated() {
        let mut ctrl = ProvenanceInfoController::new();
        for i in 0..4096u64 {
            ctrl.observe_tag(i.wrapping_mul(0x517cc1b727220a95));
        }
        let snap = ctrl.snapshot();
        assert!(snap.observations >= 4096 * 8); // 8 bytes per tag
        assert!(snap.shannon_entropy > 0.0);
        assert!(snap.renyi_h2 > 0.0);
        assert!(snap.collision_log2 < 0.0, "Should have negative log₂(P)");
    }
}
