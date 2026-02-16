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
}
