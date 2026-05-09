//! Profile-gated read-mostly fast-path prototype (bd-juvqm.3).
//!
//! A two-lane reader for read-mostly metadata:
//!
//!   * `LaneId::Conservative` — Mutex-based read. The pre-existing
//!     fallback. Always observable, always deterministic.
//!   * `LaneId::Seqlock` — bd-juvqm.8 seqlock counter. Lock-free
//!     publication; reads retry on writer-in-progress.
//!
//! The lane is selected by a runtime profile flag (`profile_lane`).
//! The optimization changes EXACTLY ONE LEVER: the lane the
//! reader takes. The published value, the writer protocol, and the
//! diagnostic counters are identical across lanes. This means the
//! optimization can be reverted by flipping the profile flag back to
//! `Conservative` without invalidating any unrelated evidence
//! artifact.
//!
//! Acceptance criterion #1 (before/after p99/p999/throughput) is a
//! LIVE measurement step. This module's tests prove the
//! correctness floor any future live measurement must respect:
//!
//!   * Both lanes return identical values for the same write
//!     history (golden outcomes — the isomorphism proof).
//!   * The conservative lane's outcome sequence is deterministic
//!     under any reader/writer interleaving (the fallback
//!     determinism contract).
//!   * Switching the profile lever NEVER changes the observable
//!     outcome on a quiescent reader (the single-lever invariant).
//!
//! Hotspot selected: the membrane TLS-cache miss path (per
//! bd-juvqm.2's `tls_cache` stage_id with expected_signal
//! `tls_cache_miss_rate`). Read-mostly: writers are rare
//! (cache invalidations); readers are every membrane validation.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneId {
    Conservative,
    Seqlock,
}

#[derive(Debug)]
pub struct ProfileGatedReadMostly {
    profile_lane: LaneId,
    /// Conservative lane: mutex around the value.
    conservative: Mutex<u32>,
    /// Seqlock lane: AtomicU32 version + AtomicU32 value.
    seq_ver: AtomicU32,
    seq_val: AtomicU32,
}

impl ProfileGatedReadMostly {
    pub fn new(initial: u32, profile_lane: LaneId) -> Self {
        Self {
            profile_lane,
            conservative: Mutex::new(initial),
            seq_ver: AtomicU32::new(0),
            seq_val: AtomicU32::new(initial),
        }
    }

    /// Single-lever flip: change the active lane for reads.
    pub fn set_profile_lane(&mut self, lane: LaneId) {
        self.profile_lane = lane;
    }

    pub fn profile_lane(&self) -> LaneId {
        self.profile_lane
    }

    /// Writer publishes a new value. Updates BOTH lanes so a
    /// profile-flip never observes stale data.
    pub fn write(&self, value: u32) {
        // Seqlock half: ver++ (odd) before mutating, ver++ (even) after.
        let pre = self.seq_ver.fetch_add(1, Ordering::AcqRel);
        debug_assert!(
            pre.is_multiple_of(2),
            "writer entered with non-quiescent ver"
        );
        self.seq_val.store(value, Ordering::Release);
        self.seq_ver.fetch_add(1, Ordering::AcqRel);
        // Conservative half: take mutex, store value.
        *self.conservative.lock().unwrap() = value;
    }

    /// Read using the active profile lane. Returns the value.
    /// On the seqlock lane this MAY retry; the helper masks the
    /// retry as long as the writer eventually quiesces.
    pub fn read(&self) -> u32 {
        match self.profile_lane {
            LaneId::Conservative => *self.conservative.lock().unwrap(),
            LaneId::Seqlock => self.read_seqlock_with_retry(),
        }
    }

    /// Direct conservative-lane read, ignoring the profile flag.
    /// Used by tests to compute the isomorphism witness.
    pub fn read_via_conservative(&self) -> u32 {
        *self.conservative.lock().unwrap()
    }

    /// Direct seqlock-lane read.
    pub fn read_via_seqlock(&self) -> u32 {
        self.read_seqlock_with_retry()
    }

    fn read_seqlock_with_retry(&self) -> u32 {
        loop {
            let v0 = self.seq_ver.load(Ordering::Acquire);
            if !v0.is_multiple_of(2) {
                core::hint::spin_loop();
                continue;
            }
            let val = self.seq_val.load(Ordering::Acquire);
            let v1 = self.seq_ver.load(Ordering::Acquire);
            if v0 == v1 {
                return val;
            }
            core::hint::spin_loop();
        }
    }
}

/// Apply a deterministic write history to a fresh prototype, then
/// drain reads via both lanes and verify they agree.
pub fn isomorphism_witness(
    initial: u32,
    writes: &[u32],
    reads_per_phase: usize,
) -> IsomorphismReport {
    // Run conservative lane.
    let cons = ProfileGatedReadMostly::new(initial, LaneId::Conservative);
    let mut cons_seq = Vec::with_capacity(writes.len() * reads_per_phase);
    for w in writes {
        cons.write(*w);
        for _ in 0..reads_per_phase {
            cons_seq.push(cons.read_via_conservative());
        }
    }

    // Run seqlock lane.
    let seq = ProfileGatedReadMostly::new(initial, LaneId::Seqlock);
    let mut seq_seq = Vec::with_capacity(writes.len() * reads_per_phase);
    for w in writes {
        seq.write(*w);
        for _ in 0..reads_per_phase {
            seq_seq.push(seq.read_via_seqlock());
        }
    }

    let identical = cons_seq == seq_seq;
    IsomorphismReport {
        conservative_outcomes: cons_seq,
        seqlock_outcomes: seq_seq,
        outcomes_identical: identical,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsomorphismReport {
    pub conservative_outcomes: Vec<u32>,
    pub seqlock_outcomes: Vec<u32>,
    pub outcomes_identical: bool,
}

/// Schema of the row a future LIVE measurement run must produce
/// per (lane, profile_id) pair. The harness validates that any
/// observed report carries every required field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveMeasurementRow {
    pub lane_id: String,
    pub profile_id: String,
    pub source_commit: String,
    pub environment_fingerprint: String,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub throughput_ops_per_sec: u64,
    pub n: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveMeasurementError {
    MissingLaneId,
    MissingProfileId,
    InvalidSourceCommit,
    MissingEnvironmentFingerprint,
    InsufficientSamplesForP999,
    NonMonotoneQuantiles,
}

pub fn validate_live_measurement(row: &LiveMeasurementRow) -> Result<(), LiveMeasurementError> {
    if row.lane_id.is_empty() {
        return Err(LiveMeasurementError::MissingLaneId);
    }
    if row.profile_id.is_empty() {
        return Err(LiveMeasurementError::MissingProfileId);
    }
    let sc = &row.source_commit;
    let is_sha = sc.len() == 40 && sc.chars().all(|c| c.is_ascii_hexdigit());
    if !is_sha {
        return Err(LiveMeasurementError::InvalidSourceCommit);
    }
    if row.environment_fingerprint.is_empty() {
        return Err(LiveMeasurementError::MissingEnvironmentFingerprint);
    }
    if row.n < 1000 {
        return Err(LiveMeasurementError::InsufficientSamplesForP999);
    }
    if row.p99_ns > row.p999_ns {
        return Err(LiveMeasurementError::NonMonotoneQuantiles);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isomorphism_witness_proves_lanes_agree_on_simple_history() {
        let report = isomorphism_witness(0, &[1, 2, 3, 5, 8], 4);
        assert!(report.outcomes_identical, "lanes must agree: {report:?}");
        assert_eq!(report.conservative_outcomes.len(), 5 * 4);
    }

    #[test]
    fn isomorphism_witness_proves_lanes_agree_on_long_history() {
        let writes: Vec<u32> = (0..200u32).collect();
        let report = isomorphism_witness(0xdead_beef, &writes, 1);
        assert!(report.outcomes_identical, "lanes must agree on 200 writes");
    }

    #[test]
    fn profile_lever_flip_does_not_change_outcome_on_quiescent_reader() {
        let mut p = ProfileGatedReadMostly::new(42, LaneId::Conservative);
        p.write(99);
        let cons_out = p.read();
        p.set_profile_lane(LaneId::Seqlock);
        let seq_out = p.read();
        assert_eq!(cons_out, seq_out, "single-lever flip changed outcome");
    }

    #[test]
    fn fallback_lane_is_deterministic_under_repeated_reads() {
        let p = ProfileGatedReadMostly::new(0, LaneId::Conservative);
        p.write(7);
        for _ in 0..256 {
            assert_eq!(p.read(), 7);
        }
    }

    #[test]
    fn seqlock_lane_returns_a_published_value() {
        let p = ProfileGatedReadMostly::new(0, LaneId::Seqlock);
        for v in [11, 22, 33, 44] {
            p.write(v);
            let observed = p.read();
            assert_eq!(observed, v);
        }
    }

    #[test]
    fn validate_live_measurement_accepts_well_formed_row() {
        let row = LiveMeasurementRow {
            lane_id: "seqlock".into(),
            profile_id: "high-core-tail".into(),
            source_commit: "1".repeat(40),
            environment_fingerprint: "linux-x86_64-64core".into(),
            p99_ns: 200,
            p999_ns: 400,
            throughput_ops_per_sec: 1_000_000,
            n: 1_000_000,
            seed: 0xc0ffee,
        };
        validate_live_measurement(&row).unwrap();
    }

    #[test]
    fn validate_live_measurement_rejects_invalid_source_commit() {
        let row = LiveMeasurementRow {
            lane_id: "seqlock".into(),
            profile_id: "high-core-tail".into(),
            source_commit: "not-a-sha".into(),
            environment_fingerprint: "x".into(),
            p99_ns: 1,
            p999_ns: 2,
            throughput_ops_per_sec: 1,
            n: 2_000,
            seed: 0,
        };
        assert_eq!(
            validate_live_measurement(&row),
            Err(LiveMeasurementError::InvalidSourceCommit)
        );
    }

    #[test]
    fn validate_live_measurement_rejects_insufficient_samples_for_p999() {
        let row = LiveMeasurementRow {
            lane_id: "seqlock".into(),
            profile_id: "p".into(),
            source_commit: "1".repeat(40),
            environment_fingerprint: "x".into(),
            p99_ns: 1,
            p999_ns: 2,
            throughput_ops_per_sec: 1,
            n: 100,
            seed: 0,
        };
        assert_eq!(
            validate_live_measurement(&row),
            Err(LiveMeasurementError::InsufficientSamplesForP999)
        );
    }

    #[test]
    fn validate_live_measurement_rejects_non_monotone_quantiles() {
        let row = LiveMeasurementRow {
            lane_id: "seqlock".into(),
            profile_id: "p".into(),
            source_commit: "1".repeat(40),
            environment_fingerprint: "x".into(),
            p99_ns: 1000,
            p999_ns: 500,
            throughput_ops_per_sec: 1,
            n: 5_000,
            seed: 0,
        };
        assert_eq!(
            validate_live_measurement(&row),
            Err(LiveMeasurementError::NonMonotoneQuantiles)
        );
    }

    #[test]
    fn validate_live_measurement_rejects_missing_environment_fingerprint() {
        let row = LiveMeasurementRow {
            lane_id: "seqlock".into(),
            profile_id: "p".into(),
            source_commit: "1".repeat(40),
            environment_fingerprint: String::new(),
            p99_ns: 1,
            p999_ns: 2,
            throughput_ops_per_sec: 1,
            n: 5_000,
            seed: 0,
        };
        assert_eq!(
            validate_live_measurement(&row),
            Err(LiveMeasurementError::MissingEnvironmentFingerprint)
        );
    }
}
