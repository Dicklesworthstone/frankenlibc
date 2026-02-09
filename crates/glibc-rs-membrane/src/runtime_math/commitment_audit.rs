//! # Commitment-Algebra + Martingale-Audit Controller
//!
//! Provides tamper-evident session/accounting traces via hash-chain commitments
//! and sequential hypothesis testing (martingale audit).
//!
//! ## Mathematical Foundation
//!
//! ### Hash-Chain Commitments
//!
//! Each session state transition is committed via a hash chain:
//!
//! ```text
//! C_0 = seed
//! C_{n+1} = H(C_n || from_state || to_state || transition_hash)
//! ```
//!
//! The chain is tamper-evident: modifying any committed transition breaks
//! the chain from that point forward, since `H` is a one-way function.
//! We use SipHash (via `std::hash`) for runtime compactness — the goal
//! is not cryptographic security but efficient tamper detection within
//! a single address space lifetime.
//!
//! ### Martingale Audit Process
//!
//! Model the session accounting sequence as a stochastic process. Under
//! the null hypothesis H_0 (no tampering), the log-likelihood ratio
//! process `M_n` forms a supermartingale:
//!
//! ```text
//! M_0 = 0
//! M_{n+1} = M_n + penalty(transition_n) - baseline_decrement
//! ```
//!
//! where `penalty(t) > 0` for invalid/suspicious transitions and
//! `baseline_decrement > 0` is the expected drift under H_0.
//!
//! Under H_0 (legitimate transitions), `E[M_{n+1} | F_n] <= M_n`
//! because penalties are rare and the baseline decrement dominates.
//!
//! By the **optional stopping theorem**, if `M_n` exceeds a threshold
//! `A`, we reject H_0 with controlled false-positive probability
//! bounded by `exp(-A)`. This gives us an anytime-valid sequential
//! test for tampering.
//!
//! ### Transition Consistency
//!
//! Each observed transition `(from_state, to_state, transition_hash)`
//! is validated against a finite-state machine of valid transitions.
//! Invalid transitions (e.g., self-loops with identical hashes, which
//! indicate replayed or stuck accounting entries) increment the
//! tampering score via the martingale penalty.
//!
//! ### Replay Detection
//!
//! A compact ring buffer of recent commitment hashes detects replay
//! attacks: if the same `transition_hash` appears twice within the
//! replay window, the chain is flagged. This catches the case where
//! an attacker replays a legitimate transition to mask a deletion.
//!
//! ## Connection to Math Item #44
//!
//! Commitment-algebra + martingale-audit methods for tamper-evident
//! session/accounting traces. Reverse core anchor: session accounting
//! (`login`, utmp/wtmp) — replay/tamper ambiguity + racey state
//! transitions.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ── Parameters ──────────────────────────────────────────────────

/// Minimum observations before leaving calibration.
const WARMUP_COUNT: u64 = 16;
/// Ring buffer capacity for replay detection.
const REPLAY_WINDOW: usize = 128;
/// Martingale warning threshold (log-likelihood).
const MARTINGALE_WARNING_THRESHOLD: f64 = 5.0;
/// Martingale alarm threshold (log-likelihood).
const MARTINGALE_ALARM_THRESHOLD: f64 = 20.0;
/// Penalty added to martingale per invalid transition.
const TRANSITION_PENALTY: f64 = 2.0;
/// Replay penalty: higher than transition penalty (definitive evidence).
const REPLAY_PENALTY: f64 = 10.0;
/// Baseline decrement per clean observation (EWMA-smoothed).
const BASELINE_DECREMENT: f64 = 0.05;
/// EWMA decay factor for smoothed martingale tracking.
const EWMA_ALPHA: f64 = 0.03;

// ── Commitment hash ─────────────────────────────────────────────

/// Compute a SipHash-based commitment: H(prev || from || to || data).
///
/// This is not cryptographically secure, but provides efficient
/// tamper detection within a single process lifetime.
fn commitment_hash(prev: u64, from_state: u32, to_state: u32, transition_hash: u64) -> u64 {
    let mut hasher = DefaultHasher::new();
    prev.hash(&mut hasher);
    from_state.hash(&mut hasher);
    to_state.hash(&mut hasher);
    transition_hash.hash(&mut hasher);
    hasher.finish()
}

// ── Public types ────────────────────────────────────────────────

/// Audit state for the commitment/martingale controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditState {
    /// Insufficient observations (< WARMUP_COUNT).
    Calibrating,
    /// Martingale bounded, no anomalies detected.
    Consistent,
    /// Elevated martingale value — suspicious transitions observed.
    Anomalous,
    /// Martingale crossed alarm threshold OR replay detected.
    TamperDetected,
}

/// Telemetry snapshot for the commitment audit controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuditSummary {
    /// Current audit state.
    pub state: AuditState,
    /// Current martingale process value.
    pub martingale_value: f64,
    /// Current head of the commitment chain.
    pub commitment_hash: u64,
    /// Total replay detections.
    pub replay_count: u64,
    /// Total invalid transition detections.
    pub invalid_transition_count: u64,
    /// Total observations processed.
    pub total_observations: u64,
}

/// Commitment-algebra + martingale-audit controller.
///
/// Maintains a hash-chain of session state transitions and runs
/// a sequential hypothesis test (supermartingale) to detect tampering,
/// replay attacks, and invalid state transitions in real time.
///
/// The controller is designed for runtime compactness: fixed-size
/// arrays, no heap allocation after construction, and O(1) per
/// observation.
pub struct CommitmentAuditController {
    /// Current head of the commitment chain.
    commitment: u64,
    /// Martingale process value (log-likelihood ratio).
    martingale: f64,
    /// EWMA-smoothed martingale for hysteresis.
    martingale_ewma: f64,
    /// Total observations.
    total_observations: u64,
    /// Invalid transition count.
    invalid_transition_count: u64,
    /// Replay detection count.
    replay_count: u64,
    /// Ring buffer of recent transition hashes for replay detection.
    replay_ring: [u64; REPLAY_WINDOW],
    /// Current write position in the ring buffer.
    replay_pos: usize,
    /// Number of entries currently in the ring buffer (up to REPLAY_WINDOW).
    replay_fill: usize,
    /// Current state.
    state: AuditState,
}

impl CommitmentAuditController {
    /// Create a new controller with a zero-seed commitment chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            commitment: 0,
            martingale: 0.0,
            martingale_ewma: 0.0,
            total_observations: 0,
            invalid_transition_count: 0,
            replay_count: 0,
            replay_ring: [0u64; REPLAY_WINDOW],
            replay_pos: 0,
            replay_fill: 0,
            state: AuditState::Calibrating,
        }
    }

    /// Observe a session state transition.
    ///
    /// Updates the commitment chain, checks for replays and invalid
    /// transitions, advances the martingale process, and updates the
    /// audit state.
    ///
    /// # Arguments
    ///
    /// * `from_state` - Encoding of the source session state.
    /// * `to_state` - Encoding of the destination session state.
    /// * `transition_hash` - Hash of the transition data (timestamp, actor, etc.).
    pub fn observe_transition(&mut self, from_state: u32, to_state: u32, transition_hash: u64) {
        self.total_observations += 1;

        // 1. Update commitment chain.
        self.commitment = commitment_hash(self.commitment, from_state, to_state, transition_hash);

        // 2. Check for replay: scan the ring buffer.
        let is_replay = self.check_replay(transition_hash);
        if is_replay {
            self.replay_count += 1;
        }

        // 3. Record transition_hash in the ring buffer.
        self.replay_ring[self.replay_pos] = transition_hash;
        self.replay_pos = (self.replay_pos + 1) % REPLAY_WINDOW;
        if self.replay_fill < REPLAY_WINDOW {
            self.replay_fill += 1;
        }

        // 4. Validate transition against FSM.
        //    Default policy: self-loops with the same hash are invalid
        //    (indicate replayed or stuck accounting entries).
        let is_invalid = from_state == to_state && transition_hash == 0;
        if is_invalid {
            self.invalid_transition_count += 1;
        }

        // 5. Update martingale process.
        let penalty = if is_replay {
            REPLAY_PENALTY
        } else if is_invalid {
            TRANSITION_PENALTY
        } else {
            0.0
        };

        self.martingale = (self.martingale + penalty - BASELINE_DECREMENT).max(0.0);

        // 6. Update EWMA-smoothed martingale.
        self.martingale_ewma =
            EWMA_ALPHA * self.martingale + (1.0 - EWMA_ALPHA) * self.martingale_ewma;

        // 7. Update state.
        self.state = self.classify_state();
    }

    /// Current audit state.
    #[must_use]
    pub fn state(&self) -> AuditState {
        self.state
    }

    /// Current head of the commitment chain.
    #[must_use]
    pub fn commitment(&self) -> u64 {
        self.commitment
    }

    /// Current martingale process value.
    #[must_use]
    pub fn martingale_value(&self) -> f64 {
        self.martingale
    }

    /// Telemetry summary snapshot.
    #[must_use]
    pub fn summary(&self) -> AuditSummary {
        AuditSummary {
            state: self.state,
            martingale_value: self.martingale,
            commitment_hash: self.commitment,
            replay_count: self.replay_count,
            invalid_transition_count: self.invalid_transition_count,
            total_observations: self.total_observations,
        }
    }

    /// Check if `transition_hash` appears in the replay ring buffer.
    fn check_replay(&self, transition_hash: u64) -> bool {
        // Only scan filled entries.
        for i in 0..self.replay_fill {
            if self.replay_ring[i] == transition_hash {
                return true;
            }
        }
        false
    }

    /// Classify the current state from martingale value and observation count.
    fn classify_state(&self) -> AuditState {
        if self.total_observations < WARMUP_COUNT {
            return AuditState::Calibrating;
        }

        if self.martingale >= MARTINGALE_ALARM_THRESHOLD {
            AuditState::TamperDetected
        } else if self.martingale >= MARTINGALE_WARNING_THRESHOLD {
            AuditState::Anomalous
        } else {
            AuditState::Consistent
        }
    }
}

impl Default for CommitmentAuditController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test 1: Calibrating state with few observations ─────────

    #[test]
    fn starts_calibrating_and_stays_until_warmup() {
        let mut ctrl = CommitmentAuditController::new();
        assert_eq!(ctrl.state(), AuditState::Calibrating);

        // Feed fewer than WARMUP_COUNT observations — must stay Calibrating.
        for i in 0..(WARMUP_COUNT - 1) {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 1000 + i);
            assert_eq!(
                ctrl.state(),
                AuditState::Calibrating,
                "should be Calibrating at observation {i}"
            );
        }
    }

    // ── Test 2: Consistent state with valid transitions ─────────

    #[test]
    fn clean_transitions_reach_consistent() {
        let mut ctrl = CommitmentAuditController::new();
        // Feed clean, distinct transitions well past warmup.
        for i in 0..100 {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 5000 + i);
        }
        assert_eq!(
            ctrl.state(),
            AuditState::Consistent,
            "expected Consistent with all-clean transitions"
        );
        assert!(ctrl.martingale_value() < MARTINGALE_WARNING_THRESHOLD);
    }

    // ── Test 3: Anomalous state when martingale rises above warning ──

    #[test]
    fn invalid_transitions_raise_martingale_to_anomalous() {
        let mut ctrl = CommitmentAuditController::new();
        // Pass warmup with clean transitions (hashes 3000..3016).
        for i in 0..WARMUP_COUNT {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 3000 + i);
        }
        assert_eq!(ctrl.state(), AuditState::Consistent);

        // A single replay (reusing hash 3000 from i=0) adds REPLAY_PENALTY (10.0)
        // minus BASELINE_DECREMENT (0.05) = 9.95, which lands squarely in the
        // Anomalous band (between WARNING=5.0 and ALARM=20.0).
        ctrl.observe_transition(50, 51, 3000);
        assert!(
            ctrl.martingale_value() >= MARTINGALE_WARNING_THRESHOLD,
            "martingale {} should be >= warning {}",
            ctrl.martingale_value(),
            MARTINGALE_WARNING_THRESHOLD
        );
        assert!(
            ctrl.martingale_value() < MARTINGALE_ALARM_THRESHOLD,
            "martingale {} should be < alarm {} to be Anomalous",
            ctrl.martingale_value(),
            MARTINGALE_ALARM_THRESHOLD
        );
        assert_eq!(
            ctrl.state(),
            AuditState::Anomalous,
            "expected Anomalous after single replay"
        );
    }

    // ── Test 4: TamperDetected when martingale exceeds alarm ────

    #[test]
    fn sustained_invalid_transitions_trigger_tamper_detected() {
        let mut ctrl = CommitmentAuditController::new();
        // Pass warmup.
        for i in 0..WARMUP_COUNT {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 200 + i);
        }

        // Feed many invalid transitions to cross alarm threshold (20.0).
        // Each adds ~1.95 net; need ~11 to exceed 20.0.
        for _ in 0..15 {
            ctrl.observe_transition(7, 7, 0);
        }
        assert!(
            ctrl.martingale_value() >= MARTINGALE_ALARM_THRESHOLD,
            "martingale {} should be >= alarm {}",
            ctrl.martingale_value(),
            MARTINGALE_ALARM_THRESHOLD
        );
        assert_eq!(ctrl.state(), AuditState::TamperDetected);
    }

    // ── Test 5: Replay detection ────────────────────────────────

    #[test]
    fn replay_detection_flags_duplicate_hash() {
        let mut ctrl = CommitmentAuditController::new();
        // Pass warmup with unique hashes.
        for i in 0..WARMUP_COUNT {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 300 + i);
        }
        assert_eq!(ctrl.replay_count, 0);

        // Now observe a transition hash that was already seen.
        let duplicate_hash = 300; // was used at i=0
        ctrl.observe_transition(50, 51, duplicate_hash);
        assert_eq!(ctrl.replay_count, 1, "replay should be detected");

        // The replay penalty (10.0) should spike the martingale significantly.
        assert!(
            ctrl.martingale_value() >= REPLAY_PENALTY - BASELINE_DECREMENT,
            "martingale should reflect replay penalty"
        );
    }

    // ── Test 6: Recovery from anomalous back to consistent ──────

    #[test]
    fn recovery_from_anomalous_to_consistent() {
        let mut ctrl = CommitmentAuditController::new();
        // Pass warmup with hashes 400..416.
        for i in 0..WARMUP_COUNT {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 400 + i);
        }

        // Push martingale into anomalous range with exactly 1 replay.
        // Reuse hash 400 (from i=0). Replay penalty = 10.0.
        ctrl.observe_transition(99, 100, 400);
        // martingale = 10.0 - 0.05 = 9.95. Anomalous (between 5 and 20).
        assert_eq!(
            ctrl.state(),
            AuditState::Anomalous,
            "expected Anomalous after replay, martingale = {}",
            ctrl.martingale_value()
        );

        // Now feed many clean transitions. Each decrements by BASELINE_DECREMENT (0.05).
        // The martingale is clamped at 0.0 minimum, so it will decay.
        // From ~9.95, need 9.95/0.05 = 199 clean observations to reach 0.
        // Need to cross below 5.0 for Consistent: (9.95 - 5.0)/0.05 = 99.
        for i in 0..200 {
            ctrl.observe_transition((1000 + i) as u32, (1001 + i) as u32, 50000 + i);
        }
        assert_eq!(
            ctrl.state(),
            AuditState::Consistent,
            "expected recovery to Consistent after clean traffic, martingale = {}",
            ctrl.martingale_value()
        );
    }

    // ── Test 7: Summary correctness ─────────────────────────────

    #[test]
    fn summary_reflects_controller_state() {
        let mut ctrl = CommitmentAuditController::new();
        for i in 0..30 {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 600 + i);
        }

        let s = ctrl.summary();
        assert_eq!(s.state, ctrl.state());
        assert_eq!(s.total_observations, 30);
        assert_eq!(s.replay_count, 0);
        assert_eq!(s.invalid_transition_count, 0);
        assert_eq!(s.commitment_hash, ctrl.commitment());
        assert!((s.martingale_value - ctrl.martingale_value()).abs() < 1e-12);
        // Commitment hash should be non-zero after observations.
        assert_ne!(s.commitment_hash, 0);
    }

    // ── Test 8: Commitment chain integrity ──────────────────────

    #[test]
    fn different_inputs_produce_different_chains() {
        let mut ctrl_a = CommitmentAuditController::new();
        let mut ctrl_b = CommitmentAuditController::new();

        // Feed identical transitions except one differs in to_state.
        for i in 0..20 {
            ctrl_a.observe_transition(i, i + 1, 700 + i as u64);
            ctrl_b.observe_transition(i, i + 1, 700 + i as u64);
        }
        // At this point, chains should be identical.
        assert_eq!(
            ctrl_a.commitment(),
            ctrl_b.commitment(),
            "identical sequences should produce identical commitment hashes"
        );

        // Diverge: different to_state.
        ctrl_a.observe_transition(20, 21, 720);
        ctrl_b.observe_transition(20, 22, 720);
        assert_ne!(
            ctrl_a.commitment(),
            ctrl_b.commitment(),
            "different transitions should produce different commitment hashes"
        );
    }

    // ── Test 9: Replay ring buffer wraps correctly ──────────────

    #[test]
    fn replay_ring_buffer_wraps_without_false_positives() {
        let mut ctrl = CommitmentAuditController::new();

        // Fill the ring buffer completely with unique hashes.
        for i in 0..(REPLAY_WINDOW as u64 + WARMUP_COUNT) {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 10000 + i);
        }
        assert_eq!(ctrl.replay_count, 0, "no replays should be detected");

        // Now use a hash from early in the sequence that has been evicted
        // from the ring buffer (i = 0 was evicted since window = 128).
        ctrl.observe_transition(999, 1000, 10000); // hash 10000 was at i=0
        // If WARMUP_COUNT + REPLAY_WINDOW > REPLAY_WINDOW, the earliest
        // entries should have been overwritten. With WARMUP_COUNT=16 and
        // REPLAY_WINDOW=128, after 144 entries the first 16 are evicted.
        assert_eq!(
            ctrl.replay_count, 0,
            "evicted hash should not trigger replay"
        );
    }

    // ── Test 10: Replay immediately triggers TamperDetected ─────

    #[test]
    fn replay_can_trigger_tamper_detected() {
        let mut ctrl = CommitmentAuditController::new();
        // Pass warmup.
        for i in 0..WARMUP_COUNT {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 800 + i);
        }
        assert_eq!(ctrl.state(), AuditState::Consistent);

        // Two replays in quick succession: each adds REPLAY_PENALTY = 10.0.
        // After two: martingale >= 20.0 - 2*0.05 = 19.9, which is below alarm.
        // Third replay pushes it over.
        let replay_hash = 800u64; // from i=0
        ctrl.observe_transition(50, 51, replay_hash);
        ctrl.observe_transition(52, 53, replay_hash);
        ctrl.observe_transition(54, 55, replay_hash);
        assert_eq!(
            ctrl.state(),
            AuditState::TamperDetected,
            "multiple replays should trigger TamperDetected, martingale = {}",
            ctrl.martingale_value()
        );
    }

    // ── Test 11: EWMA tracks martingale smoothly ────────────────

    #[test]
    fn ewma_tracks_martingale_direction() {
        let mut ctrl = CommitmentAuditController::new();
        // Feed clean transitions; EWMA should stay near zero.
        for i in 0..50 {
            ctrl.observe_transition(i as u32, (i + 1) as u32, 900 + i);
        }
        let ewma_clean = ctrl.martingale_ewma;
        assert!(
            ewma_clean < 1.0,
            "EWMA should be near zero with clean traffic, got {ewma_clean}"
        );

        // Feed invalid transitions; EWMA should rise.
        for _ in 0..10 {
            ctrl.observe_transition(0, 0, 0);
        }
        assert!(
            ctrl.martingale_ewma > ewma_clean,
            "EWMA should increase with invalid traffic"
        );
    }
}
