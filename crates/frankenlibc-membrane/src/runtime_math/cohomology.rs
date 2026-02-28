//! Incremental overlap-consistency monitor (runtime sheaf proxy).

use std::sync::atomic::{AtomicU64, Ordering};

const SHARD_COUNT: usize = 64;

/// Lightweight consistency monitor for overlapping metadata shards.
///
/// The runtime approximation here is intentionally tiny: each shard stores a
/// section hash, and overlap witnesses are checked as cocycle-like constraints.
pub struct CohomologyMonitor {
    section_hashes: [AtomicU64; SHARD_COUNT],
    faults: AtomicU64,
}

impl CohomologyMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            section_hashes: std::array::from_fn(|_| AtomicU64::new(0)),
            faults: AtomicU64::new(0),
        }
    }

    /// Set the current section hash for a shard.
    pub fn set_section_hash(&self, shard: usize, hash: u64) {
        let idx = shard % SHARD_COUNT;
        self.section_hashes[idx].store(hash, Ordering::Relaxed);
    }

    /// Check overlap witness consistency between two shards.
    ///
    /// Returns true if consistent, false if a fault is detected.
    pub fn note_overlap(&self, left_shard: usize, right_shard: usize, witness_hash: u64) -> bool {
        let li = left_shard % SHARD_COUNT;
        let ri = right_shard % SHARD_COUNT;
        let left = self.section_hashes[li].load(Ordering::Relaxed);
        let right = self.section_hashes[ri].load(Ordering::Relaxed);
        let expected = left ^ right;

        if expected == witness_hash {
            true
        } else {
            self.faults.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Number of detected overlap/cocycle faults.
    #[must_use]
    pub fn fault_count(&self) -> u64 {
        self.faults.load(Ordering::Relaxed)
    }
}

impl Default for CohomologyMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn zero_initialized_sections_accept_zero_witness() {
        let monitor = CohomologyMonitor::new();
        assert!(monitor.note_overlap(0, 0, 0));
        assert!(monitor.note_overlap(7, 42, 0));
        assert_eq!(monitor.fault_count(), 0);
    }

    #[test]
    fn detects_inconsistent_overlap() {
        let monitor = CohomologyMonitor::new();
        monitor.set_section_hash(1, 0xAA);
        monitor.set_section_hash(2, 0x0F);
        assert!(monitor.note_overlap(1, 2, 0xA5));
        assert!(!monitor.note_overlap(1, 2, 0x00));
        assert_eq!(monitor.fault_count(), 1);
    }

    #[test]
    fn shard_wraparound_and_repeated_faults_are_counted() {
        let monitor = CohomologyMonitor::new();
        monitor.set_section_hash(1, 0xAA);
        monitor.set_section_hash(1 + SHARD_COUNT, 0xBB); // wraps and overrides shard 1
        monitor.set_section_hash(2, 0x11);

        // Wrapped shard index should participate in overlap checks.
        assert!(monitor.note_overlap(1 + SHARD_COUNT, 2, 0xAA)); // 0xBB ^ 0x11 = 0xAA

        // Same wrapped shard compared with itself is always xor=0.
        assert!(monitor.note_overlap(1, 1 + SHARD_COUNT, 0));

        // Fault counter should accumulate across repeated mismatches.
        assert!(!monitor.note_overlap(1, 2, 0x00));
        assert!(!monitor.note_overlap(1, 2, 0x01));
        assert_eq!(monitor.fault_count(), 2);
    }

    #[test]
    fn repeated_consistent_overlaps_never_increment_fault_counter() {
        let monitor = CohomologyMonitor::new();
        monitor.set_section_hash(5, 0x1234);
        monitor.set_section_hash(7, 0x00FF);
        let witness = 0x1234 ^ 0x00FF;

        for _ in 0..256 {
            assert!(monitor.note_overlap(5, 7, witness));
        }
        assert_eq!(monitor.fault_count(), 0);
    }

    #[test]
    fn concurrent_mismatches_are_counted_exactly_once_per_event() {
        let monitor = Arc::new(CohomologyMonitor::new());
        for i in 0..16usize {
            monitor.set_section_hash(i, (i as u64).saturating_add(0x10));
            monitor.set_section_hash(i + 16, (i as u64).saturating_add(0x40));
        }

        let mut handles = Vec::new();
        for i in 0..16usize {
            let monitor = Arc::clone(&monitor);
            handles.push(thread::spawn(move || {
                let left = i;
                let right = i + 16;
                let witness = (i as u64).saturating_add(0x10) ^ (i as u64).saturating_add(0x40);
                assert!(monitor.note_overlap(left, right, witness));
                assert!(!monitor.note_overlap(left, right, witness ^ 1));
            }));
        }

        for handle in handles {
            handle.join().expect("worker thread must not panic");
        }
        assert_eq!(monitor.fault_count(), 16);
    }
}
