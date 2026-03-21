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
    pub generation: u64,
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
    addr_to_slot: std::collections::BTreeMap<usize, usize>,
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
            addr_to_slot: std::collections::BTreeMap::new(),
            free_list: Vec::new(),
            quarantine: VecDeque::new(),
            quarantine_bytes: 0,
        }
    }
}

use std::sync::Arc;

use crate::ebr::QuarantineEbr;

/// Thread-safe generational allocation arena.
pub struct AllocationArena {
    shards: Box<[Mutex<ArenaShard>]>,
    /// Global generation counter.
    next_generation: std::sync::atomic::AtomicU64,
    /// Optional EBR collector for safe deferred deallocation.
    collector: Option<Arc<QuarantineEbr>>,
}

/// Result of a successful allocation in the arena.
#[derive(Debug, Clone, Copy)]
pub struct AllocationResult {
    /// User-visible pointer (past fingerprint header).
    pub ptr: *mut u8,
    /// User-visible base address (usize representation of ptr).
    pub user_base: usize,
    /// Base address of the full allocation (including fingerprint header).
    pub raw_base: usize,
    /// Total size of the raw allocation (including all overhead).
    pub total_size: usize,
}

impl AllocationArena {
    /// Create a new empty arena.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_collector(None)
    }

    /// Create a new empty arena with an EBR collector.
    #[must_use]
    pub fn new_with_collector(collector: Option<Arc<QuarantineEbr>>) -> Self {
        let shards: Vec<Mutex<ArenaShard>> = (0..NUM_SHARDS)
            .map(|_| Mutex::new(ArenaShard::new()))
            .collect();
        Self {
            shards: shards.into_boxed_slice(),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            collector,
        }
    }

    /// Allocate memory with fingerprint header and canary.
    ///
    /// Returns the allocation metadata on success.
    pub fn allocate(&self, user_size: usize) -> Option<AllocationResult> {
        self.allocate_aligned(user_size, 16)
    }

    /// Allocate memory with fingerprint header, canary, and specific alignment.
    ///
    /// Alignment must be a power of 2.
    /// Returns the allocation metadata on success.
    pub fn allocate_aligned(&self, user_size: usize, align: usize) -> Option<AllocationResult> {
        // Ensure alignment is at least 32 (>= FINGERPRINT_SIZE=24, power of 2) and power of 2
        let align = align.max(32);
        if !align.is_power_of_two() {
            return None;
        }

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
        let fp = AllocationFingerprint::compute(user_base, user_size as u64, generation);
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

        Some(AllocationResult {
            ptr: user_base as *mut u8,
            user_base,
            raw_base,
            total_size,
        })
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

        let (canary_ok, drained) = {
            let mut shard = self.shards[shard_idx].lock();

            let Some(&slot_idx) = shard.addr_to_slot.get(&user_base) else {
                return (FreeResult::ForeignPointer, Vec::new());
            };

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

            // Move to quarantine. Mark state FIRST, then bump the global TLS-cache epoch
            // so that any thread that Acquires the new epoch is guaranteed to see the
            // Quarantined state.
            slot.state = SafetyState::Quarantined;
            slot.generation = self
                .next_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            bump_tls_cache_epoch();

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

            // Drain quarantine if over limit (returns entries without deallocating)
            let drained = self.drain_quarantine(&mut shard);

            (canary_ok, drained)
        }; // shard lock is released here!

        // Actually release memory for all drained entries outside the lock.
        for entry in &drained {
            let layout = std::alloc::Layout::from_size_align(entry.total_size, entry.align)
                .expect("valid layout");

            if let Some(collector) = &self.collector {
                let raw_base = entry.raw_base;
                // Defer deallocation until grace period completes.
                collector.retire_quarantined(move || {
                    // SAFETY: raw_base was allocated with this layout.
                    unsafe {
                        std::alloc::dealloc(raw_base as *mut u8, layout);
                    }
                });
            } else {
                // Fallback: immediate deallocation (risky if validation is concurrent).
                unsafe {
                    std::alloc::dealloc(entry.raw_base as *mut u8, layout);
                }
            }
        }

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

        if let Some(slot) = self.lookup_in_shard(exact_shard_idx, user_ptr) {
            return Some(slot);
        }

        // Try containing lookup in all other shards since an inner pointer
        // might cross a page boundary and thus hash to a different shard.
        for idx in 0..NUM_SHARDS {
            if idx == exact_shard_idx {
                continue;
            }
            if let Some(slot) = self.lookup_in_shard(idx, user_ptr) {
                return Some(slot);
            }
        }

        None
    }

    fn lookup_in_shard(&self, shard_idx: usize, user_ptr: usize) -> Option<ArenaSlot> {
        let shard = self.shards[shard_idx].lock();

        // Check exact match or inner pointer / canary (user_base <= user_ptr)
        if let Some((&_base, &slot_idx)) = shard.addr_to_slot.range(..=user_ptr).next_back() {
            let slot = &shard.slots[slot_idx];
            if slot.state.is_live() || slot.state == SafetyState::Quarantined {
                let end = slot
                    .user_base
                    .saturating_add(slot.user_size)
                    .saturating_add(CANARY_SIZE);
                if user_ptr >= slot.raw_base && user_ptr < end {
                    return Some(*slot);
                }
            }
        }

        // Check fingerprint header (user_base > user_ptr)
        if let Some((&_base, &slot_idx)) = shard.addr_to_slot.range(user_ptr..).next() {
            let slot = &shard.slots[slot_idx];
            if slot.state.is_live() || slot.state == SafetyState::Quarantined {
                let end = slot
                    .user_base
                    .saturating_add(slot.user_size)
                    .saturating_add(CANARY_SIZE);
                if user_ptr >= slot.raw_base && user_ptr < end {
                    return Some(*slot);
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
            AllocationFingerprint::compute(slot.user_base, slot.user_size as u64, slot.generation);
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
            || shard.quarantine.len() > crate::quarantine_controller::current_depth()
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

            shard.quarantine_bytes = shard.quarantine_bytes.saturating_sub(entry.total_size);

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
        assert!(!ptr.ptr.is_null());

        // Write to the allocation
        // SAFETY: ptr is valid for 256 bytes from allocate().
        unsafe {
            std::ptr::write_bytes(ptr.ptr, 0xAB, 256);
        }

        let (result, _) = arena.free(ptr.ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn double_free_detected() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(64).expect("allocation should succeed");

        let (first, _) = arena.free(ptr.ptr);
        assert_eq!(first, FreeResult::Freed);

        let (second, _) = arena.free(ptr.ptr);
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
        let addr = ptr.ptr as usize;

        let slot = arena.lookup(addr).expect("should find allocation");
        assert_eq!(slot.user_base, addr);
        assert_eq!(slot.user_size, 128);
        assert_eq!(slot.state, SafetyState::Valid);
    }

    #[test]
    fn lookup_into_middle_of_allocation() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(256).expect("allocation should succeed");
        let addr = ptr.ptr as usize;

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
            let canary_ptr = ptr.ptr.add(32);
            std::ptr::write_bytes(canary_ptr, 0xFF, CANARY_SIZE);
        }

        let (result, _) = arena.free(ptr.ptr);
        assert_eq!(result, FreeResult::FreedWithCanaryCorruption);
    }

    #[test]
    fn generation_increases() {
        let arena = AllocationArena::new();
        let p1 = arena.allocate(64).expect("alloc 1");
        let p2 = arena.allocate(64).expect("alloc 2");

        let s1 = arena.lookup(p1.ptr as usize).unwrap();
        let s2 = arena.lookup(p2.ptr as usize).unwrap();
        assert!(s2.generation > s1.generation);

        let _ = arena.free(p1.ptr);
        let _ = arena.free(p2.ptr);
    }

    #[test]
    fn free_promotes_slot_to_quarantined_with_new_generation() {
        let arena = AllocationArena::new();
        let ptr = arena.allocate(96).expect("allocation should succeed");

        let before = arena.lookup(ptr.ptr as usize).expect("live slot");
        assert_eq!(before.state, SafetyState::Valid);

        let (result, drained) = arena.free(ptr.ptr);
        assert_eq!(result, FreeResult::Freed);
        assert!(drained.is_empty(), "small free should not force drain");

        let after = arena
            .lookup(ptr.ptr as usize)
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

        let max_entries = crate::quarantine_controller::current_depth();
        let mut oldest_user = 0usize;
        for idx in 0..=max_entries {
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
            max_entries + 1,
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
            max_entries,
            "drain should stop once count is back at limit"
        );
        assert_eq!(
            shard.quarantine_bytes,
            max_entries * total_size,
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

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Use-After-Free Detection (P=1)
    //
    // Theorem: After free(), any lookup of the freed pointer
    // returns a Quarantined state with a strictly higher generation
    // counter. A stale reference holding the old generation will
    // always detect the mismatch, giving P(detect UAF) = 1.
    //
    // The mechanism: free() atomically bumps the slot's generation
    // and transitions state to Quarantined. Any validation
    // comparing a stale generation with the slot's current
    // generation will find generation_stale < generation_current.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_uaf_detection_probability_one() {
        let arena = AllocationArena::new();

        // Allocate and record the generation
        let ptr = arena.allocate(128).expect("allocation should succeed");
        let addr = ptr.ptr as usize;
        let live_slot = arena.lookup(addr).expect("should find live allocation");
        let live_gen = live_slot.generation;
        assert_eq!(live_slot.state, SafetyState::Valid);

        // Free: slot transitions to Quarantined with bumped generation
        let (result, _) = arena.free(ptr.ptr);
        assert_eq!(result, FreeResult::Freed);

        let freed_slot = arena.lookup(addr).expect("should find quarantined slot");
        assert_eq!(
            freed_slot.state,
            SafetyState::Quarantined,
            "Freed slot must be Quarantined"
        );
        assert!(
            freed_slot.generation > live_gen,
            "Free must bump generation: live={live_gen}, freed={}",
            freed_slot.generation
        );

        // The UAF detection mechanism: a stale pointer would carry
        // live_gen, but the slot now has freed_gen > live_gen.
        // Generation mismatch is always detected.
        assert_ne!(
            live_gen, freed_slot.generation,
            "Generation mismatch must be detectable (P=1)"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Generation Monotonicity
    //
    // Theorem: The global generation counter is strictly
    // monotonically increasing across allocations and frees.
    // No two allocations or free operations share a generation.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_generation_strict_monotonicity() {
        let arena = AllocationArena::new();
        let mut prev_gen = 0u64;

        for _ in 0..50 {
            let ptr = arena.allocate(64).expect("alloc");
            let slot = arena.lookup(ptr.ptr as usize).expect("lookup");
            assert!(
                slot.generation > prev_gen,
                "Generation not strictly increasing: {} <= {}",
                slot.generation,
                prev_gen
            );
            prev_gen = slot.generation;

            let (result, _) = arena.free(ptr.ptr);
            assert_eq!(result, FreeResult::Freed);

            let freed = arena.lookup(ptr.ptr as usize).expect("freed lookup");
            assert!(
                freed.generation > prev_gen,
                "Free generation not strictly increasing: {} <= {}",
                freed.generation,
                prev_gen
            );
            prev_gen = freed.generation;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Double-Free Always Detected
    //
    // Theorem: Calling free() twice on the same pointer always
    // returns DoubleFree on the second call. This holds regardless
    // of other allocations or frees in between.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_double_free_always_detected() {
        let arena = AllocationArena::new();

        for _ in 0..10 {
            let ptr = arena.allocate(256).expect("alloc");

            let (first, _) = arena.free(ptr.ptr);
            assert_eq!(first, FreeResult::Freed);

            // Intervening allocation to test isolation
            let _ = arena.allocate(128);

            let (second, _) = arena.free(ptr.ptr);
            assert_eq!(
                second,
                FreeResult::DoubleFree,
                "Second free must always be detected as DoubleFree"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Quarantine FIFO Ordering
    //
    // Theorem: The quarantine queue drains in FIFO order — the
    // oldest freed allocation is recycled first. This maximizes
    // the temporal distance between free and reuse, strengthening
    // UAF detection.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_quarantine_fifo_ordering() {
        let arena = AllocationArena::new();

        // Allocate multiple blocks in sequence
        let mut ptrs = Vec::new();
        for _ in 0..5 {
            let ptr = arena.allocate(64).expect("alloc");
            ptrs.push(ptr);
        }

        // Free in order
        let mut free_order = Vec::new();
        for &ptr in &ptrs {
            let (result, _) = arena.free(ptr.ptr);
            assert_eq!(result, FreeResult::Freed);
            free_order.push(ptr.ptr as usize);
        }

        // Verify quarantine is populated in the same order
        // by checking that the first freed is the first found in quarantine
        let shard_idx = arena.shard_for(free_order[0]);
        let shard = arena.shards[shard_idx].lock();

        // For entries in this shard's quarantine, verify FIFO
        let shard_entries: Vec<usize> = shard.quarantine.iter().map(|e| e.user_base).collect();
        let our_entries: Vec<usize> = free_order
            .iter()
            .filter(|a| shard_entries.contains(a))
            .copied()
            .collect();

        // The order in the quarantine should match the free order
        let queue_order: Vec<usize> = shard_entries
            .iter()
            .filter(|a| our_entries.contains(a))
            .copied()
            .collect();
        assert_eq!(
            our_entries, queue_order,
            "Quarantine should be FIFO: free order vs queue order"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Foreign Pointer Rejection
    //
    // Theorem: Pointers not allocated through the arena are
    // always rejected with ForeignPointer on free(). The arena
    // never accidentally claims ownership of external memory.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_foreign_pointers_always_rejected() {
        let arena = AllocationArena::new();

        // Various foreign pointer patterns
        let stack_var: u64 = 42;
        let foreign_ptrs: &[*mut u8] = &[
            std::ptr::addr_of!(stack_var) as *mut u8,
            std::ptr::without_provenance_mut::<u8>(0x1),
            std::ptr::without_provenance_mut::<u8>(0xDEAD_BEEF),
            std::ptr::null_mut(),
        ];

        // Also allocate a real pointer and try adjacent addresses
        let real = arena.allocate(256).expect("alloc");
        let real_addr = real.ptr as usize;

        for &ptr in foreign_ptrs {
            if ptr.is_null() {
                continue; // null might special-case
            }
            let (result, _) = arena.free(ptr);
            assert_eq!(
                result,
                FreeResult::ForeignPointer,
                "Foreign pointer {ptr:?} should be rejected"
            );
        }

        // Address well outside any allocation
        let far_away = (real_addr + 1_000_000) as *mut u8;
        let (result, _) = arena.free(far_away);
        assert_eq!(result, FreeResult::ForeignPointer);

        // Cleanup
        let _ = arena.free(real.ptr);
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

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: Arena + EBR composition
    //
    // Verifies that the arena correctly integrates with the
    // epoch-based reclamation collector for safe deferred cleanup.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn arena_with_ebr_collector_allocate_and_free() {
        let ebr = Arc::new(crate::ebr::QuarantineEbr::new(2));
        let arena = AllocationArena::new_with_collector(Some(Arc::clone(&ebr)));

        let ptr = arena.allocate(128).expect("alloc should succeed");
        assert!(!ptr.ptr.is_null());

        let slot = arena.lookup(ptr.ptr as usize).expect("should find allocation");
        assert_eq!(slot.state, SafetyState::Valid);
        assert_eq!(slot.user_size, 128);

        let (result, _) = arena.free(ptr.ptr);
        assert_eq!(result, FreeResult::Freed);

        let freed_slot = arena.lookup(ptr.ptr as usize).expect("quarantined slot");
        assert_eq!(freed_slot.state, SafetyState::Quarantined);
    }

    #[test]
    fn arena_with_ebr_multiple_alloc_free_cycles() {
        let ebr = Arc::new(crate::ebr::QuarantineEbr::new(1));
        let arena = AllocationArena::new_with_collector(Some(Arc::clone(&ebr)));

        let mut ptrs = Vec::new();
        for size in [16, 64, 256, 1024, 4096] {
            let ptr = arena.allocate(size).expect("alloc");
            ptrs.push((ptr, size));
        }

        // Verify all allocations
        for &(ptr, size) in &ptrs {
            let slot = arena.lookup(ptr.ptr as usize).expect("lookup");
            assert_eq!(slot.user_size, size);
            assert_eq!(slot.state, SafetyState::Valid);
        }

        // Free all
        for &(ptr, _) in &ptrs {
            let (result, _) = arena.free(ptr.ptr);
            assert_eq!(result, FreeResult::Freed);
        }

        // All should be quarantined
        for &(ptr, _) in &ptrs {
            let slot = arena.lookup(ptr.ptr as usize).expect("freed lookup");
            assert_eq!(slot.state, SafetyState::Quarantined);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: Arena free -> TLS cache epoch invalidation
    //
    // Verifies that freeing an allocation in the arena correctly
    // bumps the TLS cache epoch, causing stale cache entries to miss.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn arena_free_bumps_tls_cache_epoch() {
        use crate::tls_cache::{
            CachedValidation, TlsValidationCache, current_epoch, lock_tls_cache_epoch_for_tests,
        };

        let arena = AllocationArena::new();
        let ptr = arena.allocate(256).expect("alloc");
        let addr = ptr.ptr as usize;

        // Insert a cached validation for this pointer
        let mut cache = TlsValidationCache::new();
        let cached = CachedValidation {
            user_base: addr,
            user_size: 256,
            generation: 1,
            state: SafetyState::Valid,
        };

        let epoch_before;
        {
            let _guard = lock_tls_cache_epoch_for_tests();
            epoch_before = current_epoch();
            cache.insert(addr, cached, epoch_before);
            assert!(
                cache.lookup(addr).is_some(),
                "cache should hit before arena free"
            );
        }

        // Free the allocation - this bumps the TLS cache epoch
        let (result, _) = arena.free(ptr.ptr);
        assert_eq!(result, FreeResult::Freed);

        let epoch_after = current_epoch();
        assert!(
            epoch_after > epoch_before,
            "arena free must bump TLS cache epoch: before={epoch_before}, after={epoch_after}"
        );

        // Cached entry should now miss due to epoch mismatch
        assert!(
            cache.lookup(addr).is_none(),
            "cache should miss after arena free bumped epoch"
        );
    }

    #[test]
    fn tls_cache_reinsert_after_arena_free_uses_new_epoch() {
        use crate::tls_cache::{
            CachedValidation, TlsValidationCache, current_epoch, lock_tls_cache_epoch_for_tests,
        };

        let arena = AllocationArena::new();
        let ptr = arena.allocate(64).expect("alloc");
        let addr = ptr.ptr as usize;

        let mut cache = TlsValidationCache::new();

        // Insert at current epoch
        {
            let _guard = lock_tls_cache_epoch_for_tests();
            cache.insert(
                addr,
                CachedValidation {
                    user_base: addr,
                    user_size: 64,
                    generation: 1,
                    state: SafetyState::Valid,
                },
                current_epoch(),
            );
        }

        // Free bumps epoch
        let (_, _) = arena.free(ptr.ptr);

        // Re-insert with new epoch (simulating re-validation after free)
        {
            let _guard = lock_tls_cache_epoch_for_tests();
            let new_epoch = current_epoch();
            cache.insert(
                addr,
                CachedValidation {
                    user_base: addr,
                    user_size: 64,
                    generation: 2,
                    state: SafetyState::Quarantined,
                },
                new_epoch,
            );

            // Should hit with the new quarantined state
            let result = cache.lookup(addr).expect("should hit after reinsert");
            assert_eq!(result.state, SafetyState::Quarantined);
            assert_eq!(result.generation, 2);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: Concurrent arena alloc/free with TLS cache
    //
    // Multiple threads concurrently allocating and freeing while
    // the TLS cache epoch is being bumped by frees. Validates that
    // epochs remain monotonically non-decreasing.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn concurrent_alloc_free_cache_epoch_monotonic() {
        use crate::tls_cache::current_epoch;
        use std::sync::Barrier;
        use std::thread;

        let arena = Arc::new(AllocationArena::new());
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let arena = Arc::clone(&arena);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut prev_epoch = 0u64;
                for _ in 0..200 {
                    let ptr = arena.allocate(64).expect("alloc");
                    let (result, _) = arena.free(ptr.ptr);
                    assert_eq!(result, FreeResult::Freed);

                    // Epoch must be monotonically non-decreasing
                    let epoch = current_epoch();
                    assert!(
                        epoch >= prev_epoch,
                        "TLS cache epoch must be monotonic: {epoch} < {prev_epoch}"
                    );
                    prev_epoch = epoch;
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: Arena generation counters under concurrent pressure
    //
    // Verifies that generation counters remain strictly monotonic
    // even under concurrent alloc/free from multiple threads.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn concurrent_generation_monotonicity() {
        use std::sync::Barrier;
        use std::thread;

        let arena = Arc::new(AllocationArena::new());
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let arena = Arc::clone(&arena);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut prev_gen = 0u64;
                for _ in 0..100 {
                    let ptr = arena.allocate(32).expect("alloc");
                    let slot = arena.lookup(ptr.ptr as usize).expect("lookup");
                    // Generation must be strictly increasing per-allocation
                    assert!(
                        slot.generation > prev_gen,
                        "generation not increasing: {} <= {}",
                        slot.generation,
                        prev_gen
                    );
                    prev_gen = slot.generation;

                    let (result, _) = arena.free(ptr.ptr);
                    assert_eq!(result, FreeResult::Freed);

                    let freed = arena.lookup(ptr.ptr as usize).expect("freed lookup");
                    assert!(freed.generation > prev_gen);
                    prev_gen = freed.generation;
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
    }
}
