//! Property-based tests for Alien CS concurrency primitives.
//!
//! Uses proptest to verify algebraic properties, monotonicity invariants,
//! and linearizability of RCU, SeqLock, EBR, and Flat Combining.

use frankenlibc_membrane::ebr::{EbrCollector, QuarantineEbr};
use frankenlibc_membrane::flat_combining::FlatCombiner;
use frankenlibc_membrane::rcu::{RcuCell, RcuReader};
use frankenlibc_membrane::seqlock::{SeqLock, SeqLockReader};
use proptest::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ──────────────── RCU properties ────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Every update is visible to the next read.
    #[test]
    fn rcu_update_visibility(values in prop::collection::vec(0u64..10000, 1..50)) {
        let cell = RcuCell::new(0u64);
        let mut reader = RcuReader::new(&cell);

        for &v in &values {
            cell.update(v);
            let observed = reader.read();
            prop_assert_eq!(*observed, v, "reader must see latest update");
        }
    }

    /// RCU epoch is monotonically non-decreasing after updates.
    #[test]
    fn rcu_epoch_monotonicity(updates in 1u64..200) {
        let cell = RcuCell::new(0u64);
        let mut prev_epoch = cell.epoch();

        for i in 0..updates {
            cell.update(i);
            let epoch = cell.epoch();
            prop_assert!(epoch >= prev_epoch, "epoch must not decrease: {} < {}", epoch, prev_epoch);
            prev_epoch = epoch;
        }
    }

    /// update_with applies the function exactly once.
    #[test]
    fn rcu_update_with_applies_once(base in 0u64..1000, delta in 1u64..100) {
        let cell = RcuCell::new(base);
        cell.update_with(|old| *old + delta);
        prop_assert_eq!(*cell.load(), base + delta);
    }

    /// load always returns a consistent snapshot (no torn reads).
    #[test]
    fn rcu_load_consistency(a in 0u64..10000, b in 0u64..10000) {
        let cell = RcuCell::new((a, b));
        let snap = cell.load();
        prop_assert_eq!(snap.0, a);
        prop_assert_eq!(snap.1, b);

        cell.update((b, a));
        let snap2 = cell.load();
        prop_assert_eq!(snap2.0, b);
        prop_assert_eq!(snap2.1, a);
    }
}

// ──────────────── SeqLock properties ────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Version increments exactly once per write_with call.
    #[test]
    fn seqlock_version_increments_per_write(writes in 1u64..200) {
        let sl = SeqLock::new(0u64);
        let initial = sl.version();

        for _ in 0..writes {
            sl.write_with(|d| *d += 1);
        }

        prop_assert_eq!(sl.version(), initial + writes);
    }

    /// Batched writes via write guard produce exactly one version bump.
    #[test]
    fn seqlock_batched_write_single_version_bump(mutations in 1usize..20) {
        let sl = SeqLock::new(0u64);
        let v_before = sl.version();

        {
            let mut guard = sl.write();
            for _ in 0..mutations {
                guard.mutate(|d| *d += 1);
            }
        }

        prop_assert_eq!(sl.version(), v_before + 1, "batched write must bump version exactly once");
        prop_assert_eq!(*sl.load(), mutations as u64, "all mutations must be applied");
    }

    /// read_if_changed returns None when version hasn't changed.
    #[test]
    fn seqlock_read_if_changed_none_when_stable(value in 0u64..10000, reads in 1usize..100) {
        let sl = SeqLock::new(value);
        let mut reader = SeqLockReader::new(&sl);

        // Prime the cache.
        let _ = reader.read();

        for _ in 0..reads {
            prop_assert!(reader.read_if_changed().is_none(), "no change should return None");
        }
    }

    /// has_changed_since correctly detects version changes.
    #[test]
    fn seqlock_has_changed_since(initial in 0u64..1000, writes in 1u64..50) {
        let sl = SeqLock::new(initial);
        let v0 = sl.version();
        prop_assert!(!sl.has_changed_since(v0));

        for _ in 0..writes {
            sl.write_with(|d| *d += 1);
        }

        prop_assert!(sl.has_changed_since(v0));
        prop_assert!(!sl.has_changed_since(sl.version()));
    }

    /// Snapshot consistency: field_a + field_b invariant preserved across writes.
    #[test]
    fn seqlock_snapshot_consistency_invariant(shifts in prop::collection::vec(0u64..1000, 1..50)) {
        let sl = SeqLock::new((500u64, 500u64));
        let mut reader = SeqLockReader::new(&sl);

        for &s in &shifts {
            sl.write_with(|d| {
                d.0 = s;
                d.1 = 1000 - s;
            });
            let snap = reader.read();
            prop_assert_eq!(snap.0 + snap.1, 1000, "invariant violated: {} + {} != 1000", snap.0, snap.1);
        }
    }

    /// Diagnostics writes counter matches actual writes.
    #[test]
    fn seqlock_diagnostics_write_count(writes in 0u64..100) {
        let sl = SeqLock::new(0u64);
        for _ in 0..writes {
            sl.write_with(|d| *d += 1);
        }
        let d = sl.diagnostics();
        prop_assert_eq!(d.writes, writes);
    }
}

// ──────────────── EBR properties ────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every retired item is eventually reclaimed after sufficient advances.
    #[test]
    fn ebr_all_retired_eventually_reclaimed(count in 1usize..100) {
        let collector = EbrCollector::new();
        let reclaimed = Arc::new(AtomicU64::new(0));

        for _ in 0..count {
            let r = Arc::clone(&reclaimed);
            collector.retire(move || {
                r.fetch_add(1, Ordering::Relaxed);
            });
        }

        // Enough advances to flush all buckets.
        for _ in 0..5 {
            collector.try_advance();
        }

        prop_assert_eq!(
            reclaimed.load(Ordering::Relaxed),
            count as u64,
            "all {} items must be reclaimed",
            count
        );
    }

    /// Epoch is monotonically non-decreasing.
    #[test]
    fn ebr_epoch_monotonicity(advances in 1u64..50) {
        let collector = EbrCollector::new();
        let mut prev = collector.epoch();

        for _ in 0..advances {
            collector.try_advance();
            let e = collector.epoch();
            prop_assert!(e >= prev, "epoch must not decrease");
            prev = e;
        }
    }

    /// total_retired in diagnostics matches actual retirements.
    #[test]
    fn ebr_diagnostics_retired_count(count in 0u64..200) {
        let collector = EbrCollector::new();
        for _ in 0..count {
            collector.retire(|| {});
        }
        let d = collector.diagnostics();
        prop_assert_eq!(d.total_retired, count);
    }

    /// total_reclaimed never exceeds total_retired.
    #[test]
    fn ebr_reclaimed_leq_retired(retire_count in 1u64..100, advance_count in 0u64..10) {
        let collector = EbrCollector::new();
        for _ in 0..retire_count {
            collector.retire(|| {});
        }
        for _ in 0..advance_count {
            collector.try_advance();
        }
        let d = collector.diagnostics();
        prop_assert!(
            d.total_reclaimed <= d.total_retired,
            "reclaimed ({}) must not exceed retired ({})",
            d.total_reclaimed, d.total_retired
        );
    }

    /// Quarantine delays reclamation by at least `depth` extra epochs.
    #[test]
    fn quarantine_delays_by_depth(depth in 1u64..5) {
        let q = QuarantineEbr::new(depth);
        let reclaimed = Arc::new(AtomicU64::new(0));

        let r = Arc::clone(&reclaimed);
        q.retire_quarantined(move || {
            r.fetch_add(1, Ordering::Relaxed);
        });

        // Advance `depth` times — item should still be in quarantine.
        for _ in 0..depth {
            q.try_advance();
        }
        prop_assert_eq!(
            reclaimed.load(Ordering::Relaxed), 0,
            "item should still be quarantined after {} advances (depth={})",
            depth, depth
        );

        // A few more advances should release it.
        for _ in 0..5 {
            q.try_advance();
        }
        prop_assert_eq!(
            reclaimed.load(Ordering::Relaxed), 1,
            "item must be reclaimed after sufficient advances"
        );
    }

    /// quarantine_len reflects pending items accurately.
    #[test]
    fn quarantine_len_accurate(count in 0usize..50) {
        let q = QuarantineEbr::new(2);
        for _ in 0..count {
            q.retire_quarantined(|| {});
        }
        prop_assert_eq!(q.quarantine_len(), count);
    }
}

// ──────────────── Flat Combining properties ────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Sequential increments produce exact sum.
    #[test]
    fn fc_sequential_increment_sum(increments in prop::collection::vec(1u64..100, 1..100)) {
        let fc = FlatCombiner::new(0u64, 8);
        let expected: u64 = increments.iter().sum();

        for &inc in &increments {
            fc.execute(inc, |state, op| {
                *state += op;
                *state
            });
        }

        let final_val = fc.execute(0u64, |state, _| *state);
        prop_assert_eq!(final_val, expected);
    }

    /// execute returns the correct result for each operation.
    #[test]
    fn fc_execute_returns_correct_result(ops in prop::collection::vec(1u64..50, 1..50)) {
        let fc = FlatCombiner::new(0u64, 8);
        let mut running_sum = 0u64;

        for &op in &ops {
            running_sum += op;
            let result = fc.execute(op, |state, o| {
                *state += o;
                *state
            });
            prop_assert_eq!(result, running_sum, "result must match running sum");
        }
    }

    /// total_ops in diagnostics matches actual operations.
    #[test]
    fn fc_diagnostics_total_ops(count in 0u64..200) {
        let fc = FlatCombiner::new(0u64, 8);
        for _ in 0..count {
            fc.execute(1u64, |state, op| {
                *state += op;
                *state
            });
        }
        let d = fc.diagnostics();
        prop_assert_eq!(d.total_ops, count);
    }

    /// with_state_ref provides consistent view of current state.
    #[test]
    fn fc_with_state_ref_consistency(values in prop::collection::vec(1u64..100, 1..50)) {
        let fc = FlatCombiner::new(Vec::<u64>::new(), 8);

        for &v in &values {
            fc.execute(v, |state, op| {
                state.push(op);
                state.len()
            });
        }

        fc.with_state_ref(|state| {
            prop_assert_eq!(state.len(), values.len());
            for (i, &v) in values.iter().enumerate() {
                prop_assert_eq!(state[i], v);
            }
            Ok(()) // proptest needs Result
        }).unwrap();
    }
}

// ──────────────── Cross-concept composition properties ────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// RCU + SeqLock: config version in state always refers to a valid config version.
    #[test]
    fn rcu_seqlock_version_coherence(updates in 1u64..50) {
        let config = SeqLock::new(0u64);
        let state = RcuCell::new(0u64);

        let mut cfg_reader = SeqLockReader::new(&config);
        let mut state_reader = RcuReader::new(&state);

        for i in 1..=updates {
            config.write_with(|c| *c = i);
            let version = config.version();
            state.update(version);

            let cfg_val = *cfg_reader.read();
            let state_val = *state_reader.read();

            // State should always hold a version <= current config version.
            prop_assert!(
                state_val <= config.version(),
                "state version {} exceeds config version {}",
                state_val, config.version()
            );
            prop_assert_eq!(cfg_val, i);
        }
    }

    /// FlatCombiner + EBR: accumulated counter equals expected after retirement.
    #[test]
    fn fc_ebr_accumulation_integrity(ops in prop::collection::vec(1u64..10, 1..100)) {
        let fc = FlatCombiner::new(0u64, 8);
        let collector = EbrCollector::new();
        let reclaimed = Arc::new(AtomicU64::new(0));
        let expected: u64 = ops.iter().sum();

        for (i, &op) in ops.iter().enumerate() {
            let val = fc.execute(op, |state, o| {
                *state += o;
                *state
            });

            if i.is_multiple_of(10) {
                let r = Arc::clone(&reclaimed);
                let snapshot = val;
                collector.retire(move || {
                    // Snapshot was valid at retirement time.
                    assert!(snapshot > 0);
                    r.fetch_add(1, Ordering::Relaxed);
                });
            }
        }

        for _ in 0..5 {
            collector.try_advance();
        }

        let final_val = fc.execute(0u64, |state, _| *state);
        prop_assert_eq!(final_val, expected);
    }

    /// SeqLock + EBR: old config snapshots are eventually reclaimed.
    #[test]
    fn seqlock_ebr_old_config_reclamation(configs in prop::collection::vec(0u64..10000, 1..30)) {
        let sl = SeqLock::new(0u64);
        let collector = EbrCollector::new();
        let reclaim_count = Arc::new(AtomicU64::new(0));

        for &c in &configs {
            let old_val = *sl.load();
            let cnt = Arc::clone(&reclaim_count);
            collector.retire(move || {
                std::hint::black_box(old_val);
                cnt.fetch_add(1, Ordering::Relaxed);
            });
            sl.write_with(|d| *d = c);
        }

        for _ in 0..5 {
            collector.try_advance();
        }

        prop_assert_eq!(
            reclaim_count.load(Ordering::Relaxed),
            configs.len() as u64,
            "all old configs must be reclaimed"
        );
    }
}
