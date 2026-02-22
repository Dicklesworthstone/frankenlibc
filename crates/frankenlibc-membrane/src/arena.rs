//! Generational arena with quarantine queue for temporal safety.
//!
//! Every allocation gets a slot in the arena with a generation counter.
//! When freed, the slot enters a quarantine queue rather than being
//! immediately recycled. This ensures use-after-free is detected with
//! probability 1 (generation mismatch).
//!
//! Thread-safe via sharded `parking_lot::Mutex`.

#![allow(unsafe_code)]

use parking_lot::Mutex;
use std::collections::VecDeque;

use crate::fingerprint::{AllocationFingerprint, CANARY_SIZE, FINGERPRINT_SIZE};
use crate::lattice::SafetyState;
use crate::tls_cache::bump_tls_cache_epoch;

/// Maximum quarantine queue size in bytes.
const QUARANTINE_MAX_BYTES: usize = 64 * 1024 * 1024; // 64 MB

/// Maximum quarantine queue entry count.
const QUARANTINE_MAX_ENTRIES: usize = 65_536;

/// Number of shards for arena locks (power of 2).
const NUM_SHARDS: usize = 16;

/// Metadata for a single allocation slot.
#[derive(Debug, Clone, Copy)]
pub struct ArenaSlot {
    /// Base address of the full allocation (including fingerprint header).
    pub raw_base: usize,
    /// User-visible base address (after fingerprint header).
    pub user_base: usize,
    /// User-requested size.
    pub user_size: usize,
    /// Generation counter (monotonically increasing).
    pub generation: u32,
    /// Current safety state.
    pub state: SafetyState,
}

/// Entry in the quarantine queue.
#[derive(Debug, Clone, Copy)]
pub struct QuarantineEntry {
    pub(crate) user_base: usize,
    pub(crate) raw_base: usize,
    pub(crate) total_size: usize,
    pub(crate) align: usize,
}

/// A single shard of the arena.
struct ArenaShard {
    slots: Vec<ArenaSlot>,
    /// Map from user_base address to slot index.
    addr_to_slot: std::collections::HashMap<usize, usize>,
    /// Free slot indices for reuse.
    free_list: Vec<usize>,
    /// Quarantine queue for freed allocations.
    quarantine: VecDeque<QuarantineEntry>,
    /// Total bytes in quarantine.
    quarantine_bytes: usize,
}

impl ArenaShard {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            addr_to_slot: std::collections::HashMap::new(),
            free_list: Vec::new(),
            quarantine: VecDeque::new(),
            quarantine_bytes: 0,
        }
    }
}

/// Thread-safe generational allocation arena.
pub struct AllocationArena {
    shards: Box<[Mutex<ArenaShard>]>,
    /// Global generation counter.
    next_generation: std::sync::atomic::AtomicU32,
}

impl AllocationArena {
    /// Create a new empty arena.
    #[must_use]
    pub fn new() -> Self {
        let shards: Vec<Mutex<ArenaShard>> = (0..NUM_SHARDS)
            .map(|_| Mutex::new(ArenaShard::new()))
            .collect();
        Self {
            shards: shards.into_boxed_slice(),
            next_generation: std::sync::atomic::AtomicU32::new(1),
        }
    }

    /// Allocate memory with fingerprint header and canary.
    ///
    /// Returns the user-visible pointer (past the fingerprint header).
    /// Returns None if the system allocator fails.
    pub fn allocate(&self, user_size: usize) -> Option<*mut u8> {
        self.allocate_aligned(user_size, 16)
    }

    /// Allocate memory with fingerprint header, canary, and specific alignment.
    ///
    /// Alignment must be a power of 2.
    /// Returns the user-visible pointer (past the fingerprint header).
    pub fn allocate_aligned(&self, user_size: usize, align: usize) -> Option<*mut u8> {
        // Ensure alignment is at least 16 (for fingerprint) and power of 2
        let align = align.max(16);
        if !align.is_power_of_two() {
            return None;
        }

        // We need user_base to be aligned to `align`.
        // The fingerprint header sits at `user_base - FINGERPRINT_SIZE`.
        // The raw allocation starts at `raw_base`.
        // We need `user_base >= raw_base + FINGERPRINT_SIZE`.
        // We choose `offset = align` (since align >= 16 >= FINGERPRINT_SIZE).
        // So `user_base = raw_base + align`.
        // This ensures `user_base` is aligned (since raw_base is aligned)
        // and there is enough space for the header.
        // Unused gap: `[raw_base, raw_base + align - FINGERPRINT_SIZE)`.

        let offset = align;
        let total_size = offset.checked_add(user_size)?.checked_add(CANARY_SIZE)?;

        let generation = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Allocate raw memory via system allocator
        let layout = std::alloc::Layout::from_size_align(total_size, align).ok()?;
        // SAFETY: Layout is valid.
        let raw_ptr = unsafe { std::alloc::alloc(layout) };
        if raw_ptr.is_null() {
            return None;
        }

        let raw_base = raw_ptr as usize;
        let user_base = raw_base + offset;

        // Write fingerprint header at `user_base - FINGERPRINT_SIZE`
        let fp = AllocationFingerprint::compute(user_base, user_size as u32, generation);
        let fp_bytes = fp.to_bytes();
        // SAFETY: raw_ptr is valid for total_size. Header location is within [raw_base, raw_base + offset).
        unsafe {
            let header_ptr = (user_base - FINGERPRINT_SIZE) as *mut u8;
            std::ptr::copy_nonoverlapping(fp_bytes.as_ptr(), header_ptr, FINGERPRINT_SIZE);
        }

        // Write trailing canary
        let canary = fp.canary();
        let canary_bytes = canary.to_bytes();
        // SAFETY: canary sits at user_base + user_size. Valid since total_size = offset + user_size + CANARY_SIZE.
        unsafe {
            let canary_ptr = (user_base as *mut u8).add(user_size);
            std::ptr::copy_nonoverlapping(canary_bytes.as_ptr(), canary_ptr, CANARY_SIZE);
        }

        // Register in arena
        let slot = ArenaSlot {
            raw_base,
            user_base,
            user_size,
            generation,
            state: SafetyState::Valid,
        };

        let shard_idx = self.shard_for(user_base);
        let mut shard = self.shards[shard_idx].lock();

        let slot_idx = if let Some(free_idx) = shard.free_list.pop() {
            shard.slots[free_idx] = slot;
            free_idx
        } else {
            let idx = shard.slots.len();
            shard.slots.push(slot);
            idx
        };
        shard.addr_to_slot.insert(user_base, slot_idx);

        Some(user_base as *mut u8)
    }

    /// Free a membrane-managed allocation.
    ///
    /// Returns the action taken and any drained quarantine entries.
    ///
    /// @separation-pre: `Owns(slot(ptr)) * Owns(ArenaMeta)` where `ptr` is a candidate
    /// user pointer and non-arena memory is frame `F`.
    /// @separation-post: slot transitions to `Quarantined`/`Freed` variants with
    /// generation advanced; frame `F` is preserved.
    /// @separation-frame: `F` (memory outside arena slot/quarantine metadata).
    /// @separation-alias: `quarantine_enter`.
    pub fn free(&self, user_ptr: *mut u8) -> (FreeResult, Vec<QuarantineEntry>) {
        let user_base = user_ptr as usize;
        let shard_idx = self.shard_for(user_base);
        let mut shard = self.shards[shard_idx].lock();

        let Some(&slot_idx) = shard.addr_to_slot.get(&user_base) else {
            return (FreeResult::ForeignPointer, Vec::new());
        };

        // Pointer validity changes at free boundaries. Bump the global TLS-cache epoch so
        // any thread-local cached validations for this address (or other addresses)
        // cannot return stale CachedValid results after this point.
        bump_tls_cache_epoch();

        let slot = &mut shard.slots[slot_idx];

        match slot.state {
            SafetyState::Freed | SafetyState::Quarantined => {
                return (FreeResult::DoubleFree, Vec::new());
            }
            SafetyState::Invalid => {
                return (FreeResult::InvalidPointer, Vec::new());
            }
            _ => {}
        }

        // Verify canary before freeing
        let canary_ok = self.verify_canary_for_slot(slot);

        // Move to quarantine
        slot.state = SafetyState::Quarantined;
        slot.generation = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let raw_base = slot.raw_base;
        let offset = user_base - raw_base;
        let total_size = offset + slot.user_size + CANARY_SIZE;
        let align = offset;

        shard.quarantine.push_back(QuarantineEntry {
            user_base,
            raw_base,
            total_size,
            align,
        });
        shard.quarantine_bytes += total_size;

        // Drain quarantine if over limit
        let drained = self.drain_quarantine(&mut shard);

        if canary_ok {
            (FreeResult::Freed, drained)
        } else {
            (FreeResult::FreedWithCanaryCorruption, drained)
        }
    }

    /// Look up an allocation by user pointer address.
    ///
    /// @separation-pre: `Owns(ArenaIndex) * Readable(user_ptr)` with frame `F`.
    /// @separation-post: returns immutable slot snapshot (including generation/state)
    /// without mutating caller-visible memory; frame `F` is preserved.
    /// @separation-frame: `F` (all non-index memory).
    /// @separation-alias: `generation_check`.
    #[must_use]
    pub fn lookup(&self, user_ptr: usize) -> Option<ArenaSlot> {
        let exact_shard_idx = self.shard_for(user_ptr);

        {
            let shard = self.shards[exact_shard_idx].lock();
            // Try exact match first
            if let Some(&slot_idx) = shard.addr_to_slot.get(&user_ptr) {
                return Some(shard.slots[slot_idx]);
            }

            // Try containing lookup in this shard
            for slot in &shard.slots {
                if slot.state.is_live() || slot.state == SafetyState::Quarantined {
                    let end = slot.user_base.saturating_add(slot.user_size);
                    if user_ptr >= slot.user_base && user_ptr < end {
                        return Some(*slot);
                    }
                }
            }
        }

        // Try containing lookup in all other shards since an inner pointer
        // might cross a page boundary and thus hash to a different shard.
        for (idx, mutex) in self.shards.iter().enumerate() {
            if idx == exact_shard_idx {
                continue;
            }
            let shard = mutex.lock();
            for slot in &shard.slots {
                if slot.state.is_live() || slot.state == SafetyState::Quarantined {
                    let end = slot.user_base.saturating_add(slot.user_size);
                    if user_ptr >= slot.user_base && user_ptr < end {
                        return Some(*slot);
                    }
                }
            }
        }

        None
    }

    /// Look up and return remaining bytes from the given address.
    ///
    /// @separation-pre: `Owns(ArenaIndex) * Readable(addr)` with frame `F`.
    /// @separation-post: yields bounds witness `(slot, remaining)` when `addr` is in-range;
    /// frame `F` is preserved.
    /// @separation-frame: `F` (memory outside arena metadata and queried slot).
    /// @separation-alias: `check_bounds`.
    #[must_use]
    pub fn remaining_from(&self, addr: usize) -> Option<(ArenaSlot, usize)> {
        let slot = self.lookup(addr)?;
        let end = slot.user_base.saturating_add(slot.user_size);
        if addr >= slot.user_base && addr < end {
            Some((slot, end - addr))
        } else {
            None
        }
    }

    /// Check if an address belongs to any known allocation.
    #[must_use]
    pub fn contains(&self, addr: usize) -> bool {
        self.lookup(addr).is_some()
    }

    fn shard_for(&self, addr: usize) -> usize {
        // Use upper bits of address for shard selection to reduce contention
        (addr >> 12) % NUM_SHARDS
    }

    fn verify_canary_for_slot(&self, slot: &ArenaSlot) -> bool {
        let fp =
            AllocationFingerprint::compute(slot.user_base, slot.user_size as u32, slot.generation);
        let expected_canary = fp.canary();
        let canary_addr = slot.user_base + slot.user_size;

        let mut actual = [0u8; CANARY_SIZE];
        // SAFETY: canary_addr points to valid memory within the allocation's total size.
        unsafe {
            std::ptr::copy_nonoverlapping(
                canary_addr as *const u8,
                actual.as_mut_ptr(),
                CANARY_SIZE,
            );
        }
        expected_canary.verify(&actual)
    }

    fn drain_quarantine(&self, shard: &mut ArenaShard) -> Vec<QuarantineEntry> {
        let mut drained = Vec::new();

        while shard.quarantine_bytes > QUARANTINE_MAX_BYTES
            || shard.quarantine.len() > QUARANTINE_MAX_ENTRIES
        {
            let Some(entry) = shard.quarantine.pop_front() else {
                break;
            };

            // Mark slot as Freed (no longer quarantined)

            if let Some(&slot_idx) = shard.addr_to_slot.get(&entry.user_base) {
                shard.slots[slot_idx].state = SafetyState::Freed;

                shard.addr_to_slot.remove(&entry.user_base);

                shard.free_list.push(slot_idx);
            }

            // Actually release memory

            let layout = std::alloc::Layout::from_size_align(entry.total_size, entry.align)
                .expect("valid layout");

            // SAFETY: raw_base was allocated with this layout via std::alloc::alloc.

            unsafe {
                std::alloc::dealloc(entry.raw_base as *mut u8, layout);
            }

            shard.quarantine_bytes -= entry.total_size;

            drained.push(entry);
        }

        drained
    }
}

impl Default for AllocationArena {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a free operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeResult {
    /// Successfully freed and quarantined.
    Freed,
    /// Freed but trailing canary was corrupted (buffer overflow detected).
    FreedWithCanaryCorruption,
    /// Pointer was already freed (double free).
    DoubleFree,
    /// Pointer is not known to the arena (foreign pointer).
    ForeignPointer,
    /// Pointer is in an invalid state.
    InvalidPointer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_and_free_cycle() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(256).expect("allocation should succeed");
        assert!(!ptr.is_null());

        // Write to the allocation
        // SAFETY: ptr is valid for 256 bytes from allocate().
        unsafe {
            std::ptr::write_bytes(ptr, 0xAB, 256);
        }

        let (result, _) = arena.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn double_free_detected() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(64).expect("allocation should succeed");

        let (first, _) = arena.free(ptr);
        assert_eq!(first, FreeResult::Freed);

        let (second, _) = arena.free(ptr);
        assert_eq!(second, FreeResult::DoubleFree);
    }

    #[test]
    fn foreign_pointer_detected() {
        let arena = AllocationArena::new();
        let local = 42u64;
        let (result, _) = arena.free(std::ptr::addr_of!(local) as *mut u8);
        assert_eq!(result, FreeResult::ForeignPointer);
    }

    #[test]
    fn lookup_finds_allocation() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(128).expect("allocation should succeed");
        let addr = ptr as usize;

        let slot = arena.lookup(addr).expect("should find allocation");
        assert_eq!(slot.user_base, addr);
        assert_eq!(slot.user_size, 128);
        assert_eq!(slot.state, SafetyState::Valid);
    }

    #[test]
    fn lookup_into_middle_of_allocation() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(256).expect("allocation should succeed");
        let addr = ptr as usize;

        let (slot, remaining) = arena
            .remaining_from(addr + 64)
            .expect("should find containing allocation");
        assert_eq!(slot.user_base, addr);
        assert_eq!(remaining, 192);
    }

    #[test]
    fn canary_corruption_detected() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(32).expect("allocation should succeed");

        // Corrupt the canary by writing past the allocation
        // SAFETY: We intentionally write past bounds to test canary detection.
        unsafe {
            let canary_ptr = ptr.add(32);
            std::ptr::write_bytes(canary_ptr, 0xFF, CANARY_SIZE);
        }

        let (result, _) = arena.free(ptr);
        assert_eq!(result, FreeResult::FreedWithCanaryCorruption);
    }

    #[test]
    fn generation_increases() {
        let arena = AllocationArena::new();
        let p1 = arena.allocate(64).expect("alloc 1");
        let p2 = arena.allocate(64).expect("alloc 2");

        let s1 = arena.lookup(p1 as usize).unwrap();
        let s2 = arena.lookup(p2 as usize).unwrap();
        assert!(s2.generation > s1.generation);

        let _ = arena.free(p1);
        let _ = arena.free(p2);
    }

    #[test]
    fn free_promotes_slot_to_quarantined_with_new_generation() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(96).expect("allocation should succeed");

        let before = arena.lookup(ptr as usize).expect("live slot");
        assert_eq!(before.state, SafetyState::Valid);

        let (result, drained) = arena.free(ptr);
        assert_eq!(result, FreeResult::Freed);
        assert!(drained.is_empty(), "small free should not force drain");

        let after = arena
            .lookup(ptr as usize)
            .expect("freed slot should remain quarantined and discoverable");
        assert_eq!(after.state, SafetyState::Quarantined);
        assert!(
            after.generation > before.generation,
            "free should bump generation to invalidate stale pointers"
        );
    }

    #[test]
    fn quarantine_drain_evicts_oldest_when_entry_count_exceeded() {
        use std::alloc::{Layout, alloc, dealloc};

        let arena = AllocationArena::new();
        let align = 16_usize;
        let total_size = align + CANARY_SIZE;

        fn alloc_block(total_size: usize, align: usize) -> usize {
            let layout = Layout::from_size_align(total_size, align).expect("valid layout");
            // SAFETY: layout is valid; allocation failure is checked.
            unsafe {
                let ptr = alloc(layout);
                assert!(!ptr.is_null(), "alloc failed for total_size={total_size}");
                ptr as usize
            }
        }

        let mut shard = arena.shards[0].lock();

        let mut oldest_user = 0usize;
        for idx in 0..=QUARANTINE_MAX_ENTRIES {
            let raw = alloc_block(total_size, align);
            let user = raw + align;
            if idx == 0 {
                oldest_user = user;
            }
            shard.quarantine.push_back(QuarantineEntry {
                user_base: user,
                raw_base: raw,
                total_size,
                align,
            });
            shard.quarantine_bytes += total_size;
        }

        assert_eq!(
            shard.quarantine.len(),
            QUARANTINE_MAX_ENTRIES + 1,
            "test setup must exceed entry-count threshold by exactly one"
        );
        assert!(
            shard.quarantine_bytes < QUARANTINE_MAX_BYTES,
            "test setup should trigger count-based draining, not byte-based draining"
        );

        let drained = arena.drain_quarantine(&mut shard);

        assert_eq!(drained.len(), 1, "expected exactly one entry drained");
        assert_eq!(
            drained[0].user_base, oldest_user,
            "expected oldest entry to be drained first when count threshold is exceeded"
        );
        assert_eq!(
            shard.quarantine.len(),
            QUARANTINE_MAX_ENTRIES,
            "drain should stop once count is back at limit"
        );
        assert_eq!(
            shard.quarantine_bytes,
            QUARANTINE_MAX_ENTRIES * total_size,
            "exactly one entry worth of bytes should be removed"
        );

        // Cleanup: release remaining allocated blocks to avoid test-retained memory.
        while let Some(entry) = shard.quarantine.pop_front() {
            shard.quarantine_bytes = shard
                .quarantine_bytes
                .checked_sub(entry.total_size)
                .expect("quarantine bytes underflow");
            let layout =
                Layout::from_size_align(entry.total_size, entry.align).expect("valid layout");
            // SAFETY: entry.raw_base was allocated in alloc_block with the same layout.
            unsafe {
                dealloc(entry.raw_base as *mut u8, layout);
            }
        }
        assert_eq!(shard.quarantine_bytes, 0, "cleanup must fully drain bytes");
    }

    #[test]
    fn quarantine_drain_evicts_oldest_until_within_budget() {
        use std::alloc::{Layout, alloc, dealloc};

        let arena = AllocationArena::new();

        // Construct quarantine entries directly inside one shard to avoid dependence on
        // allocator address distribution across shards.
        let align = 16_usize;
        let total_size = (QUARANTINE_MAX_BYTES / 2) + 4096;
        let user_size = total_size
            .checked_sub(align + CANARY_SIZE)
            .expect("sizes underflow");

        fn alloc_block(total_size: usize, align: usize) -> usize {
            let layout = Layout::from_size_align(total_size, align).expect("valid layout");
            // SAFETY: layout is valid; we check for allocation failure.
            unsafe {
                let ptr = alloc(layout);
                assert!(!ptr.is_null(), "alloc failed for total_size={total_size}");
                ptr as usize
            }
        }

        let mut shard = arena.shards[0].lock();

        let raw1 = alloc_block(total_size, align);
        let user1 = raw1 + align;
        let slot1 = ArenaSlot {
            raw_base: raw1,
            user_base: user1,
            user_size,
            generation: 1,
            state: SafetyState::Quarantined,
        };
        shard.slots.push(slot1);
        let slot1_idx = shard.slots.len() - 1;
        shard.addr_to_slot.insert(user1, slot1_idx);
        shard.quarantine.push_back(QuarantineEntry {
            user_base: user1,
            raw_base: raw1,
            total_size,
            align,
        });
        shard.quarantine_bytes += total_size;

        let raw2 = alloc_block(total_size, align);
        let user2 = raw2 + align;
        let slot2 = ArenaSlot {
            raw_base: raw2,
            user_base: user2,
            user_size,
            generation: 2,
            state: SafetyState::Quarantined,
        };
        shard.slots.push(slot2);
        let slot2_idx = shard.slots.len() - 1;
        shard.addr_to_slot.insert(user2, slot2_idx);
        shard.quarantine.push_back(QuarantineEntry {
            user_base: user2,
            raw_base: raw2,
            total_size,
            align,
        });
        shard.quarantine_bytes += total_size;

        assert!(
            shard.quarantine_bytes > QUARANTINE_MAX_BYTES,
            "test setup must exceed drain threshold"
        );

        let drained = arena.drain_quarantine(&mut shard);

        assert_eq!(drained.len(), 1, "expected exactly one entry drained");
        assert_eq!(
            drained[0].user_base, user1,
            "expected oldest quarantine entry to be drained first"
        );
        assert!(
            shard.quarantine_bytes <= QUARANTINE_MAX_BYTES,
            "expected quarantine bytes within budget after drain"
        );
        assert!(
            !shard.addr_to_slot.contains_key(&user1),
            "expected drained entry to be removed from addr_to_slot"
        );
        assert_eq!(
            shard.slots[slot1_idx].state,
            SafetyState::Freed,
            "expected drained slot state to become Freed"
        );
        assert_eq!(
            shard.slots[slot2_idx].state,
            SafetyState::Quarantined,
            "expected most-recent slot to remain quarantined"
        );
        assert!(
            shard.free_list.contains(&slot1_idx),
            "expected drained slot index to be recycled in free_list"
        );

        // Cleanup: drain_quarantine intentionally left one entry quarantined; free it here so this
        // unit test doesn't retain ~32MB+ of memory across the test binary lifetime.
        let remaining = shard.quarantine.pop_front().expect("remaining entry");
        shard.quarantine_bytes = shard
            .quarantine_bytes
            .checked_sub(remaining.total_size)
            .expect("quarantine bytes underflow");
        if let Some(&slot_idx) = shard.addr_to_slot.get(&remaining.user_base) {
            shard.slots[slot_idx].state = SafetyState::Freed;
            shard.addr_to_slot.remove(&remaining.user_base);
            shard.free_list.push(slot_idx);
        }
        let layout =
            Layout::from_size_align(remaining.total_size, remaining.align).expect("valid layout");
        // SAFETY: remaining.raw_base was allocated by alloc_block with the same layout.
        unsafe {
            dealloc(remaining.raw_base as *mut u8, layout);
        }
    }
}
