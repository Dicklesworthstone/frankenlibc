//! Reference model + stress driver for the evidence-ring backpressure
//! contract (bd-juvqm.7).
//!
//! `tests/conformance/evidence_ring_backpressure_stress_contract.v1.json`
//! pins the *shape* of the report a future stress run must produce.
//! This module provides:
//!
//!   1. A [`ModelRing`] — a bounded ring buffer with overwrite-oldest
//!      loss semantics, monotone sequence numbers, an `evidence_loss_count`
//!      that increments by exactly one per overwrite, an `epoch` that
//!      advances by one each time the ring fills a wrap, and a redaction
//!      cardinality cap.
//!
//!   2. [`StressDriver`] — drives a [`ModelRing`] to a configurable
//!      capacity-multiple with a deterministic seed and emits a
//!      [`StressReport`] in the format the manifest contract requires.
//!
//!   3. [`validate_stress_report`] — fails closed when the report
//!      does not match a documented loss_evidence_kind (the same
//!      enum the manifest declares).
//!
//! The model ring is intentionally NOT the production
//! `EvidenceRingBuffer` — production rings publish typed records
//! (`EvidenceSymbolRecord`, `DecisionCardV1`, etc.). The model
//! ring carries an opaque `u64` payload because the backpressure
//! contract is independent of payload shape.

use std::collections::BTreeMap;

/// Reference ring with the loss accounting fields the manifest
/// requires.
#[derive(Debug, Clone)]
pub struct ModelRing {
    capacity: usize,
    next_seqno: u64,
    /// `evidence_loss_count` per the manifest contract — number of
    /// records that were written into a slot whose previous occupant
    /// had not been read yet.
    loss_count: u64,
    /// `max_epoch` per the manifest contract — increments each time
    /// the writer wraps the ring.
    max_epoch: u64,
    /// Cardinality cap on the redaction set. Writers that would push
    /// the redaction set above this limit must drop the new tag — the
    /// drop is counted in `redacted_drop_count` (not in `loss_count`).
    redaction_cardinality_limit: usize,
    redaction_set: BTreeMap<String, u64>,
    redacted_drop_count: u64,
    slots: Vec<Option<RingRecord>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingRecord {
    pub seqno: u64,
    pub epoch: u64,
    pub payload: u64,
}

impl ModelRing {
    pub fn new(capacity: usize, redaction_cardinality_limit: usize) -> Self {
        assert!(capacity >= 2, "capacity must be at least 2");
        Self {
            capacity,
            next_seqno: 0,
            loss_count: 0,
            max_epoch: 0,
            redaction_cardinality_limit,
            redaction_set: BTreeMap::new(),
            redacted_drop_count: 0,
            slots: vec![None; capacity],
        }
    }

    /// Append one record to the ring. Returns the assigned seqno.
    pub fn push(&mut self, payload: u64) -> u64 {
        self.next_seqno += 1;
        let seqno = self.next_seqno;
        let idx = ((seqno - 1) as usize) % self.capacity;
        let epoch = (seqno - 1) / (self.capacity as u64);
        if epoch > self.max_epoch {
            self.max_epoch = epoch;
        }
        if self.slots[idx].is_some() {
            self.loss_count += 1;
        }
        self.slots[idx] = Some(RingRecord {
            seqno,
            epoch,
            payload,
        });
        seqno
    }

    /// Record a redaction tag. Returns true if the tag was kept,
    /// false if the cardinality cap dropped it.
    pub fn redact(&mut self, tag: &str) -> bool {
        if self.redaction_set.contains_key(tag) {
            *self.redaction_set.get_mut(tag).unwrap() += 1;
            return true;
        }
        if self.redaction_set.len() >= self.redaction_cardinality_limit {
            self.redacted_drop_count += 1;
            return false;
        }
        self.redaction_set.insert(tag.to_string(), 1);
        true
    }

    /// Snapshot of records currently visible. Sorted by seqno.
    pub fn snapshot_sorted(&self) -> Vec<RingRecord> {
        let mut out: Vec<RingRecord> = self.slots.iter().filter_map(|s| *s).collect();
        out.sort_by_key(|r| r.seqno);
        out
    }

    pub fn loss_count(&self) -> u64 {
        self.loss_count
    }

    pub fn max_epoch(&self) -> u64 {
        self.max_epoch
    }

    pub fn redaction_cardinality_limit(&self) -> usize {
        self.redaction_cardinality_limit
    }

    pub fn redaction_set_size(&self) -> usize {
        self.redaction_set.len()
    }

    pub fn redacted_drop_count(&self) -> u64 {
        self.redacted_drop_count
    }
}

/// Stress driver — drives a [`ModelRing`] past capacity with a
/// deterministic seed.
#[derive(Debug, Clone)]
pub struct StressDriver {
    seed: u64,
    drive_to_capacity_multiple: u64,
}

impl StressDriver {
    pub fn new(seed: u64, drive_to_capacity_multiple: u64) -> Self {
        assert!(
            drive_to_capacity_multiple >= 2,
            "drive_to_capacity_multiple must be >= 2 to exercise overwrite"
        );
        Self {
            seed,
            drive_to_capacity_multiple,
        }
    }

    pub fn run(&self, ring: &mut ModelRing) -> StressReport {
        let total = ring.capacity as u64 * self.drive_to_capacity_multiple;
        // Deterministic xorshift64 — payloads depend only on seed + i.
        let mut state = self.seed.wrapping_add(1);
        for i in 0..total {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let _ = ring.push(state.wrapping_add(i));
        }
        let snapshot = ring.snapshot_sorted();
        let snapshot_seqnos: Vec<u64> = snapshot.iter().map(|r| r.seqno).collect();
        let snapshot_first = snapshot_seqnos.first().copied().unwrap_or(0);
        let snapshot_last = snapshot_seqnos.last().copied().unwrap_or(0);
        let observed_gap = snapshot_first.saturating_sub(1);

        StressReport {
            ring_capacity: ring.capacity,
            stress_seed: self.seed,
            drive_to_capacity_multiple: self.drive_to_capacity_multiple,
            total_pushed: total,
            snapshot_size: snapshot.len(),
            snapshot_first_seqno: snapshot_first,
            snapshot_last_seqno: snapshot_last,
            observed_seqno_gap: observed_gap,
            evidence_loss_count: ring.loss_count(),
            max_epoch: ring.max_epoch(),
            redaction_set_size: ring.redaction_set_size(),
            redaction_cardinality_limit: ring.redaction_cardinality_limit(),
            redacted_drop_count: ring.redacted_drop_count(),
            snapshot_serialization: serialize_snapshot(&snapshot),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StressReport {
    pub ring_capacity: usize,
    pub stress_seed: u64,
    pub drive_to_capacity_multiple: u64,
    pub total_pushed: u64,
    pub snapshot_size: usize,
    pub snapshot_first_seqno: u64,
    pub snapshot_last_seqno: u64,
    pub observed_seqno_gap: u64,
    pub evidence_loss_count: u64,
    pub max_epoch: u64,
    pub redaction_set_size: usize,
    pub redaction_cardinality_limit: usize,
    pub redacted_drop_count: u64,
    pub snapshot_serialization: String,
}

/// Deterministic textual serialization of the snapshot — the
/// contract requires this be stable across runs with the same seed.
fn serialize_snapshot(records: &[RingRecord]) -> String {
    let mut out = String::new();
    for r in records {
        use std::fmt::Write as _;
        let _ = write!(
            &mut out,
            "seqno={},epoch={},payload={};",
            r.seqno, r.epoch, r.payload
        );
    }
    out
}

/// Validate a stress report against the manifest contract.
/// Returns the rejection codes (subset of `rejected_evidence_kinds`)
/// that fire on this report.
pub fn validate_stress_report(report: &StressReport) -> Vec<String> {
    let mut rej: Vec<String> = Vec::new();
    if report.snapshot_size > report.ring_capacity {
        rej.push("snapshot_exceeds_capacity".to_string());
    }
    if report.snapshot_last_seqno > report.total_pushed {
        rej.push("non_monotone_seqno".to_string());
    }
    if report.observed_seqno_gap != report.evidence_loss_count {
        rej.push("loss_count_underreports_gap".to_string());
    }
    if report.evidence_loss_count == 0 && report.drive_to_capacity_multiple > 1 {
        rej.push("missing_loss_count_field".to_string());
    }
    if report.max_epoch < 1 && report.drive_to_capacity_multiple >= 2 {
        rej.push("missing_max_epoch_field".to_string());
    }
    if report.redaction_cardinality_limit == 0 {
        rej.push("unbounded_redaction_cardinality".to_string());
    }
    rej
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_overwrites_on_full_and_increments_loss_count_by_one_per_overwrite() {
        let mut r = ModelRing::new(4, 8);
        for i in 0..10 {
            r.push(100 + i);
        }
        assert_eq!(r.loss_count(), 6, "10 pushes into cap=4 must overwrite 6");
        assert_eq!(r.snapshot_sorted().len(), 4);
    }

    #[test]
    fn seqno_is_monotone_under_repeated_pushes() {
        let mut r = ModelRing::new(8, 16);
        let mut last = 0u64;
        for _ in 0..200 {
            let s = r.push(0);
            assert!(s > last);
            last = s;
        }
    }

    #[test]
    fn max_epoch_advances_at_least_drive_minus_one_after_full_drives() {
        let mut r = ModelRing::new(8, 16);
        let driver = StressDriver::new(0xdead_beef, 4);
        let report = driver.run(&mut r);
        assert!(
            report.max_epoch >= 3,
            "drive=4 must produce max_epoch>=3, got {}",
            report.max_epoch
        );
    }

    #[test]
    fn snapshot_serialization_is_deterministic_across_runs_with_same_seed() {
        let mut a = ModelRing::new(16, 32);
        let mut b = ModelRing::new(16, 32);
        let driver = StressDriver::new(0xfeed_face, 4);
        let ra = driver.run(&mut a);
        let rb = driver.run(&mut b);
        assert_eq!(
            ra.snapshot_serialization, rb.snapshot_serialization,
            "deterministic_serialization_after_overwrite required"
        );
        assert_eq!(ra.evidence_loss_count, rb.evidence_loss_count);
        assert_eq!(ra.max_epoch, rb.max_epoch);
    }

    #[test]
    fn snapshot_serialization_differs_with_different_seed() {
        let mut a = ModelRing::new(16, 32);
        let mut b = ModelRing::new(16, 32);
        StressDriver::new(0x1, 4).run(&mut a);
        StressDriver::new(0x2, 4).run(&mut b);
        let sa = serialize_snapshot(&a.snapshot_sorted());
        let sb = serialize_snapshot(&b.snapshot_sorted());
        assert_ne!(sa, sb);
    }

    #[test]
    fn redaction_cardinality_limit_drops_extras_without_inflating_loss_count() {
        let mut r = ModelRing::new(8, 3);
        assert!(r.redact("a"));
        assert!(r.redact("b"));
        assert!(r.redact("c"));
        assert!(!r.redact("d"));
        assert!(!r.redact("e"));
        assert_eq!(r.redacted_drop_count(), 2);
        assert_eq!(r.redaction_set_size(), 3);
        assert_eq!(
            r.loss_count(),
            0,
            "redaction drops MUST NOT inflate loss_count"
        );
    }

    #[test]
    fn validate_stress_report_passes_clean_report() {
        let mut r = ModelRing::new(8, 16);
        let driver = StressDriver::new(7, 4);
        let report = driver.run(&mut r);
        let rej = validate_stress_report(&report);
        assert!(rej.is_empty(), "clean stress report must pass; got {rej:?}");
    }

    #[test]
    fn validate_stress_report_rejects_underreported_loss_count() {
        let mut r = ModelRing::new(8, 16);
        let driver = StressDriver::new(7, 4);
        let mut report = driver.run(&mut r);
        report.evidence_loss_count = 0;
        let rej = validate_stress_report(&report);
        assert!(rej.iter().any(|k| k == "missing_loss_count_field"));
    }

    #[test]
    fn validate_stress_report_rejects_unbounded_redaction_cardinality() {
        let mut r = ModelRing::new(8, 16);
        let driver = StressDriver::new(7, 4);
        let mut report = driver.run(&mut r);
        report.redaction_cardinality_limit = 0;
        let rej = validate_stress_report(&report);
        assert!(rej.iter().any(|k| k == "unbounded_redaction_cardinality"));
    }

    #[test]
    fn snapshot_first_seqno_equals_loss_count_plus_one_after_full_drive() {
        let mut r = ModelRing::new(8, 16);
        let driver = StressDriver::new(7, 4);
        let report = driver.run(&mut r);
        assert_eq!(
            report.snapshot_first_seqno,
            report.evidence_loss_count + 1,
            "in overwrite_oldest semantics the first surviving seqno is exactly loss_count + 1"
        );
    }

    #[test]
    fn observed_gap_equals_loss_count_under_overwrite_semantics() {
        let mut r = ModelRing::new(16, 32);
        let driver = StressDriver::new(0xa1b2c3, 4);
        let report = driver.run(&mut r);
        assert_eq!(report.observed_seqno_gap, report.evidence_loss_count);
    }
}
