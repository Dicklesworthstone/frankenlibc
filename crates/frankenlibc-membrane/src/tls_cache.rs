//! Thread-local validation cache.
//!
//! 1024-entry direct-mapped cache indexed by `ptr >> 4` (16-byte granularity).
//! Avoids global lock contention on the hot path by caching recent
//! validation results per-thread.
//!
//! ## Cross-thread invalidation: per-shard epochs
//!
//! Pointer validity can change without the owning thread's involvement (for
//! example, another thread frees an allocation). Cached entries must therefore
//! be tagged with an invalidation generation so that a stale `Valid` hit
//! cannot survive across a free.
//!
//! Earlier revisions used a single `GLOBAL_TLS_CACHE_EPOCH` atomic. That was
//! correct but coarse: any free of any allocation invalidated every cached
//! entry on every thread. Long-running threads paid a wave of cache misses
//! every time an unrelated allocation was freed.
//!
//! This revision shards invalidation across `NUM_TLS_CACHE_SHARDS` (16) atomic
//! counters, indexed by `tls_cache_shard_for(user_base)` to match
//! `arena::shard_for` exactly. A free only bumps the shard that owns the
//! freed slot, so on average a free invalidates ~1/16th of the address space
//! a thread cared about; caches in the other 15 shards stay warm. The
//! cross-shard isolation invariant is asserted by
//! `bump_of_unrelated_shard_does_not_invalidate_entry`.
//!
//! ## Race semantics
//!
//! The per-shard design preserves the same TOCTOU guarantee as the old global
//! epoch: a free that races with a concurrent validation cannot produce a
//! stale `Valid` cache hit. The pattern is unchanged at the call-site level;
//! callers snapshot epochs once at validation entry (now an array of 16 u64s
//! instead of one) and pass that snapshot through to `insert`. If a free
//! intervenes between snapshot and insert, the inserted entry's
//! `shard_epoch` lags the live `SHARD_EPOCHS[shard_idx]`, and the very next
//! lookup will mismatch and self-clean (same observable behaviour as the old
//! global-epoch design).
//!
//! `bump_tls_cache_epoch()` is retained as a "bump every shard" compatibility
//! wrapper for callers (and tests) that want to nuke the cache wholesale.
//! `current_epoch()` is retained as the max across all shards, for the rare
//! monotonicity-only consumer; it is no longer used as the cache-entry tag.

use crate::lattice::SafetyState;
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of entries in the TLS cache (must be power of 2).
const CACHE_SIZE: usize = 1024;
const CACHE_MASK: usize = CACHE_SIZE - 1;

/// Number of invalidation shards. Must match `arena::NUM_SHARDS`. The home
/// shard of any address is `tls_cache_shard_for(addr)` and the array
/// `SHARD_EPOCHS` is indexed by that shard id.
pub const NUM_TLS_CACHE_SHARDS: usize = 16;

// Drift between the arena's sharding and the TLS cache's would let a free in
// arena shard `s` bump the wrong `SHARD_EPOCHS` entry (or none at all),
// allowing stale `Valid` cache hits to survive across the free. Pin the
// invariant at compile time.
const _: () = assert!(
    NUM_TLS_CACHE_SHARDS == crate::arena::NUM_SHARDS,
    "NUM_TLS_CACHE_SHARDS must equal arena::NUM_SHARDS so per-shard \
     invalidation matches arena's shard placement",
);

// `CacheEntry::shard_idx` is `u8` to keep cache entries compact (the array
// has 1024 of them on every thread). Catch a future increase of the shard
// count past what u8 can index before it silently truncates.
const _: () = assert!(
    NUM_TLS_CACHE_SHARDS <= 256,
    "CacheEntry::shard_idx is u8; raise its type before pushing past 256 shards",
);

/// Per-shard invalidation stamps.
///
/// `arena::free` for a slot in shard `s` bumps `SHARD_EPOCHS[s]`. Cached
/// entries record `(shard_idx, shard_epoch)` at insert time; lookup compares
/// against the live shard epoch and misses on mismatch.
///
/// Each cell is initialised to 1 (not 0) so that the `EMPTY` cache entry's
/// `shard_epoch == 0` can never spuriously match a live shard's epoch even
/// if some code path reads a sentinel-zero entry.
///
/// The array is sized off `NUM_TLS_CACHE_SHARDS` and initialised via an inline
/// `const` block so changing the shard count requires only updating the
/// constant — no need to maintain a hand-listed array literal in lock-step.
#[repr(C)]
struct ShardEpochTable {
    epochs: [AtomicU64; NUM_TLS_CACHE_SHARDS],
    escalated_sources: std::sync::atomic::AtomicU32,
    pipeline_runtime_math_disabled: std::sync::atomic::AtomicBool,
}

impl core::ops::Deref for ShardEpochTable {
    type Target = [AtomicU64; NUM_TLS_CACHE_SHARDS];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.epochs
    }
}

static SHARD_EPOCHS: ShardEpochTable = ShardEpochTable {
    epochs: [const { AtomicU64::new(1) }; NUM_TLS_CACHE_SHARDS],
    escalated_sources: std::sync::atomic::AtomicU32::new(0),
    pipeline_runtime_math_disabled: std::sync::atomic::AtomicBool::new(false),
};

// Test-only synchronization to avoid flaky cache-hit expectations when other
// concurrently-running tests bump shard epochs (via allocator free paths).
//
// WARNING: Do not hold this lock while calling code paths that bump a shard
// epoch (e.g. arena free), or you'll deadlock.
#[cfg(test)]
static TLS_CACHE_EPOCH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Map an address to its TLS-cache invalidation shard.
///
/// Must match `arena::shard_for` exactly so that the shard a slot lives in
/// (and that the arena's free path bumps) matches the shard cached entries
/// for that slot record. Uses `(addr >> 12) % NUM_TLS_CACHE_SHARDS`.
#[inline]
#[must_use]
pub fn tls_cache_shard_for(addr: usize) -> usize {
    (addr >> 12) % NUM_TLS_CACHE_SHARDS
}

/// Current epoch of a specific shard. Used by lookup to detect invalidation.
#[inline(always)]
#[must_use]
pub fn current_shard_epoch(shard_idx: usize) -> u64 {
    let idx = shard_idx & (NUM_TLS_CACHE_SHARDS - 1);
    SHARD_EPOCHS[idx].load(Ordering::Acquire)
}

/// Snapshot every shard's current epoch in a single pass.
///
/// Callers performing a validation pipeline take this snapshot before the
/// arena lookup so the recorded shard epoch for the eventually-discovered
/// `user_base` shard is sampled *before* any racing free could bump it.
#[must_use]
pub fn snapshot_shard_epochs() -> [u64; NUM_TLS_CACHE_SHARDS] {
    let mut out = [0u64; NUM_TLS_CACHE_SHARDS];
    for (slot, atomic) in out.iter_mut().zip(SHARD_EPOCHS.iter()) {
        *slot = atomic.load(Ordering::Acquire);
    }
    out
}

/// Bump a single shard's epoch.
///
/// `arena::free` invokes this from within the shard's mutex critical section,
/// so the post-bump value is the one any later `current_shard_epoch` call
/// from another thread will observe with Acquire ordering.
pub fn bump_shard_epoch(shard_idx: usize) {
    #[cfg(test)]
    let _guard = TLS_CACHE_EPOCH_TEST_LOCK
        .lock()
        .expect("TLS cache epoch test lock poisoned");
    // Release ordering ensures all prior state changes (like marking a slot
    // Quarantined) are visible to any thread that performs an Acquire load
    // of the new epoch.
    let _ = SHARD_EPOCHS[shard_idx].fetch_add(1, Ordering::Release);
}

/// Compatibility wrapper: bump every shard's epoch.
///
/// Equivalent to "nuke every TLS cache across all threads". The per-shard
/// design exists specifically to avoid this on the common-case free path,
/// but callers that genuinely need a global invalidation (test fixtures,
/// process-wide teardown) can still ask for it explicitly.
pub fn bump_tls_cache_epoch() {
    #[cfg(test)]
    let _guard = TLS_CACHE_EPOCH_TEST_LOCK
        .lock()
        .expect("TLS cache epoch test lock poisoned");
    for atomic in SHARD_EPOCHS.iter() {
        let _ = atomic.fetch_add(1, Ordering::Release);
    }
}

/// Monotonic-ish epoch across all shards, retained for callers that want a
/// single u64 summary (legacy telemetry). Not used as a cache entry tag; see
/// `snapshot_shard_epochs` for the correct sampling primitive.
#[inline]
#[must_use]
pub fn current_epoch() -> u64 {
    let mut max = 0u64;
    for atomic in SHARD_EPOCHS.iter() {
        let v = atomic.load(Ordering::Acquire);
        if v > max {
            max = v;
        }
    }
    max
}

#[cfg(test)]
pub(crate) fn lock_tls_cache_epoch_for_tests() -> std::sync::MutexGuard<'static, ()> {
    TLS_CACHE_EPOCH_TEST_LOCK
        .lock()
        .expect("TLS cache epoch test lock poisoned")
}

/// A cached validation result for a pointer.
#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    /// The pointer address that was validated.
    addr: usize,
    /// The user-base address of the containing allocation.
    user_base: usize,
    /// The allocation size.
    user_size: usize,
    /// The generation at time of validation.
    generation: u64,
    /// Expected 64-bit `AllocationFingerprint::hash` at `user_base - 24`.
    expected_hash: u64,
    /// Expected 64-bit trailing `Canary` tag at `user_base + user_size`.
    expected_canary: u64,
    /// Shard epoch captured at validation start. A free of this slot will
    /// leave the live `SHARD_EPOCHS[shard_idx]` ahead of this value,
    /// turning the next lookup into a miss.
    shard_epoch: u64,
    /// Owning shard's `slots` vector index (`O(1)` lookup on warm-TLS verification).
    slot_idx: u32,
    /// The safety state at time of validation.
    state: SafetyState,
    /// Shard that owns this allocation, computed via `tls_cache_shard_for`
    /// on `user_base` at insert time. The arena's free path bumps
    /// `SHARD_EPOCHS[shard_idx]` when it disposes of this slot.
    shard_idx: u8,
    /// True when `expected_hash` and `expected_canary` bind a real arena block.
    has_integrity: bool,
    /// Whether this entry is populated.
    valid: bool,
}

const _: () = assert!(core::mem::size_of::<CacheEntry>() <= 64);

impl CacheEntry {
    const EMPTY: Self = Self {
        addr: 0,
        user_base: 0,
        user_size: 0,
        generation: 0,
        expected_hash: 0,
        expected_canary: 0,
        shard_epoch: 0,
        slot_idx: 0,
        state: SafetyState::Unknown,
        shard_idx: 0,
        has_integrity: false,
        valid: false,
    };
}

fn allocate_entries() -> Option<Box<[CacheEntry; CACHE_SIZE]>> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(CACHE_SIZE).ok()?;
    vec.resize(CACHE_SIZE, CacheEntry::EMPTY);
    vec.into_boxed_slice().try_into().ok()
}

const HIT_METRICS_FLUSH_BATCH: u64 = 4096;

/// Default cadence mask (`1-in-16` warm hits) for bounded warm-`TLS_CACHE` header/canary re-verification.
pub const DEFAULT_WARM_INTEGRITY_CADENCE_MASK: u32 = 15;
/// Escalated cadence mask (`1-in-1` = every warm hit) activated when `RuntimeMathKernel`
/// elevates `StringMemory`/`Allocator`/`PointerValidation` conformal risk.
pub const ESCALATED_WARM_INTEGRITY_CADENCE_MASK: u32 = 0;

/// Bitmask source: `ValidationPipeline::runtime_math` `PointerValidation` conformal risk escalation.
pub const INTEGRITY_SOURCE_PIPELINE_PTR_VALIDATOR: u32 = 1 << 0;
/// Bitmask source: ABI `RuntimeMathKernel` hot-family conformal risk escalation (`Allocator`/`StringMemory`/`Stdio`).
pub const INTEGRITY_SOURCE_ABI_HOT_FAMILIES: u32 = 1 << 1;
/// Bitmask source: explicit override via [`set_warm_integrity_cadence_mask`].
pub const INTEGRITY_SOURCE_TEST_OVERRIDE: u32 = 1 << 2;

/// Read the active warm-`TLS_CACHE` integrity verification cadence mask (`15` = 1-in-16, `0` = 1-in-1).
#[inline(always)]
#[must_use]
pub fn warm_integrity_cadence_mask() -> u32 {
    if SHARD_EPOCHS.escalated_sources.load(Ordering::Relaxed) != 0 {
        ESCALATED_WARM_INTEGRITY_CADENCE_MASK
    } else {
        DEFAULT_WARM_INTEGRITY_CADENCE_MASK
    }
}

/// Atomically set or clear an independent escalation source bit without racing sibling sources.
#[inline]
pub fn set_warm_integrity_source_escalated(source_bit: u32, escalated: bool) {
    if escalated {
        SHARD_EPOCHS
            .escalated_sources
            .fetch_or(source_bit, Ordering::Relaxed);
    } else {
        SHARD_EPOCHS
            .escalated_sources
            .fetch_and(!source_bit, Ordering::Relaxed);
    }
}

/// Update the explicit warm-`TLS_CACHE` integrity verification cadence override (`0` escalates, non-zero clears).
#[inline]
pub fn set_warm_integrity_cadence_mask(mask: u32) {
    set_warm_integrity_source_escalated(
        INTEGRITY_SOURCE_TEST_OVERRIDE,
        mask == ESCALATED_WARM_INTEGRITY_CADENCE_MASK,
    );
}

/// Read whether `FRANKENLIBC_RUNTIME_MATH=off` has disabled `ValidationPipeline::runtime_math`.
#[inline(always)]
#[must_use]
pub fn pipeline_runtime_math_disabled() -> bool {
    SHARD_EPOCHS
        .pipeline_runtime_math_disabled
        .load(Ordering::Relaxed)
}

/// Synchronize `FRANKENLIBC_RUNTIME_MATH=off` kill-switch into `ValidationPipeline`.
#[inline]
pub fn set_pipeline_runtime_math_disabled(disabled: bool) {
    SHARD_EPOCHS
        .pipeline_runtime_math_disabled
        .store(disabled, Ordering::Relaxed);
}

/// Near-tail write threshold in bytes: any hardened write whose destination has
/// `remaining <= WARM_WRITE_TAIL_THRESHOLD` (or `write_len >= remaining`) re-verifies
/// header and trailing canary immediately on warm `TLS_CACHE` hits.
#[cfg(any(test, not(feature = "owned-tls-cache")))]
pub(crate) const WARM_WRITE_TAIL_THRESHOLD: usize = 64;

/// Thread-local validation cache.
pub struct TlsValidationCache {
    entries: Option<Box<[CacheEntry; CACHE_SIZE]>>,
    /// The four allocations validated most recently, matched by RANGE: an
    /// interior pointer into one of them hits with exactly the guarantee an
    /// exact-address hit gives (the allocation was fully validated and has
    /// not been freed since; same shard-epoch check). The exact-address table
    /// alone missed every interior pointer, so code walking buffers (GNU
    /// sort comparing lines across its line buffer, merge buffer, and scratch
    /// allocations) paid the full pipeline on every string call
    /// (bd-rc0923-epic-eeuy4f.9, widened to 4-way in bd-rc0923-epic-eeuy4f.28).
    ranges: [CacheEntry; 4],
    hits: u64,
    misses: u64,
    unflushed_pipeline_hits: u64,
    unflushed_bloom_misses: u64,
    cadence_counter: u32,
    next_range: u8,
    unbacked: bool,
}

impl TlsValidationCache {
    /// Create a zero-initialized cache without allocating the backing table yet.
    ///
    /// Used for `const` TLS initialization so `TLS_CACHE` resides in `.tbss`
    /// and never runs `get_or_init_slow` (which previously moved a 232-byte
    /// `Option<RefCell<TlsValidationCache>>` via exported `memcpy` before the
    /// `RefCell` borrow guard was active, re-entering validation and
    /// overflowing 32 KiB thread stacks).
    #[cfg(not(feature = "owned-tls-cache"))]
    #[must_use]
    const fn const_new() -> Self {
        Self {
            entries: None,
            ranges: [CacheEntry::EMPTY; 4],
            hits: 0,
            misses: 0,
            unflushed_pipeline_hits: 0,
            unflushed_bloom_misses: 0,
            cadence_counter: 0,
            next_range: 0,
            unbacked: false,
        }
    }

    /// Ephemeral inline-only cache for re-entrant borrow or post-TLS-teardown
    /// fallback paths. Never allocates on the heap.
    #[must_use]
    const fn unbacked() -> Self {
        Self {
            entries: None,
            ranges: [CacheEntry::EMPTY; 4],
            hits: 0,
            misses: 0,
            unflushed_pipeline_hits: 0,
            unflushed_bloom_misses: 0,
            cadence_counter: 0,
            next_range: 0,
            unbacked: true,
        }
    }

    /// Create a new empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: allocate_entries(),
            ranges: [CacheEntry::EMPTY; 4],
            hits: 0,
            misses: 0,
            unflushed_pipeline_hits: 0,
            unflushed_bloom_misses: 0,
            cadence_counter: 0,
            next_range: 0,
            unbacked: false,
        }
    }

    #[cfg(test)]
    fn entry_valid(&self, idx: usize) -> bool {
        self.entries
            .as_ref()
            .is_some_and(|entries| entries[idx].valid)
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline(always)]
    fn remaining_for_state(state: SafetyState, remaining: usize) -> Option<usize> {
        match state {
            SafetyState::Valid | SafetyState::Readable | SafetyState::Writable => Some(remaining),
            SafetyState::Quarantined | SafetyState::Invalid => Some(0),
            _ => None,
        }
    }

    /// Batch pipeline hit accounting in TLS and flush to `GLOBAL_METRICS`
    /// every `HIT_METRICS_FLUSH_BATCH` hits (or on snapshot/drop).
    #[inline(always)]
    pub(crate) fn record_pipeline_hits(&mut self, count: u64) {
        if self.unbacked {
            let metrics = crate::metrics::global_metrics();
            crate::metrics::MembraneMetrics::add(&metrics.validations, count);
            crate::metrics::MembraneMetrics::add(&metrics.tls_cache_hits, count);
            return;
        }
        let next = self.unflushed_pipeline_hits + count;
        if next >= HIT_METRICS_FLUSH_BATCH {
            self.unflushed_pipeline_hits = 0;
            let metrics = crate::metrics::global_metrics();
            crate::metrics::MembraneMetrics::add(&metrics.validations, next);
            crate::metrics::MembraneMetrics::add(&metrics.tls_cache_hits, next);
        } else {
            self.unflushed_pipeline_hits = next;
        }
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline(always)]
    pub(crate) fn record_bloom_misses(&mut self, count: u64) {
        if self.unbacked {
            let metrics = crate::metrics::global_metrics();
            crate::metrics::MembraneMetrics::add(&metrics.validations, count);
            crate::metrics::MembraneMetrics::add(&metrics.bloom_misses, count);
            return;
        }
        let next = self.unflushed_bloom_misses + count;
        if next >= HIT_METRICS_FLUSH_BATCH {
            self.unflushed_bloom_misses = 0;
            let metrics = crate::metrics::global_metrics();
            crate::metrics::MembraneMetrics::add(&metrics.validations, next);
            crate::metrics::MembraneMetrics::add(&metrics.bloom_misses, next);
        } else {
            self.unflushed_bloom_misses = next;
        }
    }

    #[inline]
    pub(crate) fn flush_pipeline_hits(&mut self) {
        let pending_hits = self.unflushed_pipeline_hits;
        let pending_bloom_misses = self.unflushed_bloom_misses;
        if pending_hits != 0 || pending_bloom_misses != 0 {
            self.unflushed_pipeline_hits = 0;
            self.unflushed_bloom_misses = 0;
            let metrics = crate::metrics::global_metrics();
            crate::metrics::MembraneMetrics::add(
                &metrics.validations,
                pending_hits + pending_bloom_misses,
            );
            if pending_hits != 0 {
                crate::metrics::MembraneMetrics::add(&metrics.tls_cache_hits, pending_hits);
            }
            if pending_bloom_misses != 0 {
                crate::metrics::MembraneMetrics::add(&metrics.bloom_misses, pending_bloom_misses);
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn verify_entry_validation_slow(
        &mut self,
        entry: CacheEntry,
        arena: &crate::arena::AllocationArena,
    ) -> bool {
        match arena.verify_cached_slot_integrity(
            entry.user_base,
            entry.user_size,
            entry.generation,
            entry.slot_idx,
            entry.shard_idx,
            entry.shard_epoch,
            entry.expected_hash,
            entry.expected_canary,
        ) {
            crate::arena::CachedIntegrityVerdict::Intact => true,
            crate::arena::CachedIntegrityVerdict::EpochStale
            | crate::arena::CachedIntegrityVerdict::HeaderCorrupted
            | crate::arena::CachedIntegrityVerdict::CanaryCorrupted => {
                // Evict stale/corrupted entry so the caller falls through to the
                // authoritative validation stages (which record failure metrics
                // and emit structured transition logs once).
                self.invalidate(entry.user_base);
                false
            }
        }
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[cold]
    #[inline(never)]
    fn verify_entry_remaining_slow(
        &mut self,
        entry: CacheEntry,
        rem: usize,
        arena: &crate::arena::AllocationArena,
    ) -> CachedRemaining {
        match arena.verify_cached_slot_integrity(
            entry.user_base,
            entry.user_size,
            entry.generation,
            entry.slot_idx,
            entry.shard_idx,
            entry.shard_epoch,
            entry.expected_hash,
            entry.expected_canary,
        ) {
            crate::arena::CachedIntegrityVerdict::Intact => CachedRemaining(rem),
            crate::arena::CachedIntegrityVerdict::EpochStale => {
                self.invalidate(entry.user_base);
                CachedRemaining::MISS
            }
            crate::arena::CachedIntegrityVerdict::HeaderCorrupted => {
                self.invalidate(entry.user_base);
                let metrics = crate::metrics::global_metrics();
                crate::metrics::MembraneMetrics::inc(&metrics.fingerprint_failures);
                CachedRemaining::CORRUPTED
            }
            crate::arena::CachedIntegrityVerdict::CanaryCorrupted => {
                self.invalidate(entry.user_base);
                let metrics = crate::metrics::global_metrics();
                crate::metrics::MembraneMetrics::inc(&metrics.canary_failures);
                CachedRemaining::CORRUPTED
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn verify_range_validation_slow(
        &mut self,
        range_idx: usize,
        arena: &crate::arena::AllocationArena,
    ) -> bool {
        let entry = self.ranges[range_idx];
        self.verify_entry_validation_slow(entry, arena)
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[cold]
    #[inline(never)]
    fn verify_range_remaining_slow(
        &mut self,
        range_idx: usize,
        rem: usize,
        arena: &crate::arena::AllocationArena,
    ) -> CachedRemaining {
        let entry = self.ranges[range_idx];
        self.verify_entry_remaining_slow(entry, rem, arena)
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline(always)]
    fn check_entry_remaining_if_needed(
        &mut self,
        entry: CacheEntry,
        rem: usize,
        integrity: Option<(&crate::arena::AllocationArena, bool, usize)>,
    ) -> CachedRemaining {
        if let Some((arena, is_write, write_len)) = integrity
            && entry.has_integrity
        {
            self.cadence_counter = self.cadence_counter.wrapping_add(1);
            let near_tail = is_write && rem.saturating_sub(write_len) <= WARM_WRITE_TAIL_THRESHOLD;
            if near_tail || (self.cadence_counter & warm_integrity_cadence_mask()) == 0 {
                return self.verify_entry_remaining_slow(entry, rem, arena);
            }
        }
        CachedRemaining(rem)
    }

    /// A hit in the recently-validated allocation ranges.
    #[inline(always)]
    fn range_hit(
        &mut self,
        addr: usize,
        arena: Option<&crate::arena::AllocationArena>,
    ) -> Option<CachedValidation> {
        for idx in 0..self.ranges.len() {
            let user_base = self.ranges[idx].user_base;
            let user_size = self.ranges[idx].user_size;
            if addr.wrapping_sub(user_base) < user_size {
                let shard_idx = self.ranges[idx].shard_idx;
                if self.ranges[idx].shard_epoch == current_shard_epoch(shard_idx as usize) {
                    let generation = self.ranges[idx].generation;
                    let state = self.ranges[idx].state;
                    if let Some(arena_ref) = arena
                        && self.ranges[idx].has_integrity
                    {
                        self.cadence_counter = self.cadence_counter.wrapping_add(1);
                        if (self.cadence_counter & warm_integrity_cadence_mask()) == 0
                            && !self.verify_range_validation_slow(idx, arena_ref)
                        {
                            return None;
                        }
                    }
                    return Some(CachedValidation {
                        user_base,
                        user_size,
                        generation,
                        state,
                    });
                }
                self.ranges[idx].user_size = 0;
                self.ranges[idx].valid = false;
            }
        }
        None
    }

    /// Look up a pointer in the cache.
    ///
    /// Returns `Some(CachedValidation)` on hit. On a shard-epoch mismatch
    /// (the slot's home shard has been bumped since insertion, indicating
    /// a free) the entry is self-cleaned so subsequent lookups skip the
    /// mismatch comparison.
    #[inline]
    pub fn lookup(&mut self, addr: usize) -> Option<CachedValidation> {
        self.lookup_with_arena(addr, None)
    }

    /// Look up a pointer in the cache with optional hardened arena cadence verification.
    #[inline]
    pub(crate) fn lookup_with_arena(
        &mut self,
        addr: usize,
        arena: Option<&crate::arena::AllocationArena>,
    ) -> Option<CachedValidation> {
        if let Some(hit) = self.range_hit(addr, arena) {
            self.hits += 1;
            return Some(hit);
        }
        let found_entry = if let Some(entries) = self.entries.as_deref_mut() {
            let idx = Self::index(addr);
            let entry = &mut entries[idx];
            if entry.valid && entry.addr == addr {
                if entry.shard_epoch == current_shard_epoch(entry.shard_idx as usize) {
                    Some(*entry)
                } else {
                    entry.valid = false;
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(entry) = found_entry {
            if let Some(arena_ref) = arena
                && entry.has_integrity
            {
                self.cadence_counter = self.cadence_counter.wrapping_add(1);
                if (self.cadence_counter & warm_integrity_cadence_mask()) == 0
                    && !self.verify_entry_validation_slow(entry, arena_ref)
                {
                    self.misses += 1;
                    return None;
                }
            }
            self.hits += 1;
            return Some(CachedValidation {
                user_base: entry.user_base,
                user_size: entry.user_size,
                generation: entry.generation,
                state: entry.state,
            });
        }
        self.misses += 1;
        None
    }

    /// Look up a pointer and return only a valid hit.
    ///
    /// Unlike [`Self::lookup`], this intentionally does not count misses. It
    /// is used by speculative fast paths that fall back to the full pipeline,
    /// where the authoritative miss accounting still happens.
    #[inline]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lookup_hit_only(&mut self, addr: usize) -> Option<CachedValidation> {
        self.lookup_hit_only_with_arena(addr, None)
    }

    #[inline]
    pub(crate) fn lookup_hit_only_with_arena(
        &mut self,
        addr: usize,
        arena: Option<&crate::arena::AllocationArena>,
    ) -> Option<CachedValidation> {
        if let Some(hit) = self.range_hit(addr, arena) {
            self.hits += 1;
            return Some(hit);
        }
        let found_entry = if let Some(entries) = self.entries.as_deref_mut() {
            let idx = Self::index(addr);
            let entry = &mut entries[idx];
            if entry.valid && entry.addr == addr {
                if entry.shard_epoch == current_shard_epoch(entry.shard_idx as usize) {
                    Some(*entry)
                } else {
                    entry.valid = false;
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(entry) = found_entry {
            if let Some(arena_ref) = arena
                && entry.has_integrity
            {
                self.cadence_counter = self.cadence_counter.wrapping_add(1);
                if (self.cadence_counter & warm_integrity_cadence_mask()) == 0
                    && !self.verify_entry_validation_slow(entry, arena_ref)
                {
                    return None;
                }
            }
            self.hits += 1;
            return Some(CachedValidation {
                user_base: entry.user_base,
                user_size: entry.user_size,
                generation: entry.generation,
                state: entry.state,
            });
        }
        None
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline]
    fn lookup_hit_remaining_entries(
        &mut self,
        addr: usize,
        integrity: Option<(&crate::arena::AllocationArena, bool, usize)>,
    ) -> CachedRemaining {
        let found_entry = if let Some(entries) = self.entries.as_deref_mut() {
            let idx = Self::index(addr);
            let entry = &mut entries[idx];
            if entry.valid && entry.addr == addr {
                if entry.shard_epoch == current_shard_epoch(entry.shard_idx as usize) {
                    Some(*entry)
                } else {
                    entry.valid = false;
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(entry) = found_entry {
            let offset = addr.wrapping_sub(entry.user_base);
            if offset < entry.user_size {
                if let Some(rem) = Self::remaining_for_state(entry.state, entry.user_size - offset)
                {
                    let checked = self.check_entry_remaining_if_needed(entry, rem, integrity);
                    if checked.is_hit() {
                        self.hits += 1;
                    }
                    return checked;
                }
                self.hits += 1;
                return CachedRemaining::UNKNOWN;
            }
            self.hits += 1;
            return CachedRemaining(0);
        }
        CachedRemaining::MISS
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline(always)]
    fn lookup_range_remaining_const<const IS_WRITE: bool>(
        &mut self,
        addr: usize,
        arena: Option<&crate::arena::AllocationArena>,
        write_len: usize,
    ) -> CachedRemaining {
        for idx in 0..self.ranges.len() {
            let user_base = self.ranges[idx].user_base;
            let user_size = self.ranges[idx].user_size;
            let off = addr.wrapping_sub(user_base);
            if off < user_size {
                let shard_idx = self.ranges[idx].shard_idx;
                if self.ranges[idx].shard_epoch == current_shard_epoch(shard_idx as usize) {
                    let rem = user_size - off;
                    if let Some(arena_ref) = arena
                        && self.ranges[idx].has_integrity
                    {
                        let c = self.cadence_counter.wrapping_add(1);
                        self.cadence_counter = c;
                        let near_tail =
                            IS_WRITE && rem.saturating_sub(write_len) <= WARM_WRITE_TAIL_THRESHOLD;
                        if near_tail || (c & warm_integrity_cadence_mask()) == 0 {
                            return self.verify_range_remaining_slow(idx, rem, arena_ref);
                        }
                    }
                    return CachedRemaining(rem);
                }
                self.ranges[idx].user_size = 0;
                self.ranges[idx].valid = false;
                break;
            }
        }
        CachedRemaining::MISS
    }

    #[cfg(test)]
    #[inline(always)]
    pub(crate) fn lookup_hit_remaining_with_oracle(
        &mut self,
        addr: usize,
        page_oracle: &crate::page_oracle::PageOracle,
        integrity: Option<(&crate::arena::AllocationArena, bool, usize)>,
    ) -> CachedRemaining {
        match integrity {
            Some((arena, true, write_len)) => self.lookup_hit_remaining_with_oracle_const::<true>(
                addr,
                page_oracle,
                Some(arena),
                write_len,
            ),
            Some((arena, false, _)) => self.lookup_hit_remaining_with_oracle_const::<false>(
                addr,
                page_oracle,
                Some(arena),
                0,
            ),
            None => {
                self.lookup_hit_remaining_with_oracle_const::<false>(addr, page_oracle, None, 0)
            }
        }
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline(always)]
    pub(crate) fn lookup_hit_remaining_with_oracle_const<const IS_WRITE: bool>(
        &mut self,
        addr: usize,
        page_oracle: &crate::page_oracle::PageOracle,
        arena: Option<&crate::arena::AllocationArena>,
        write_len: usize,
    ) -> CachedRemaining {
        let range_rem = self.lookup_range_remaining_const::<IS_WRITE>(addr, arena, write_len);
        if range_rem.is_corrupted() {
            return range_rem;
        }
        if range_rem.is_known_bound() {
            self.hits += 1;
            let next_hits = self.unflushed_pipeline_hits + 1;
            if !self.unbacked && next_hits < HIT_METRICS_FLUSH_BATCH {
                self.unflushed_pipeline_hits = next_hits;
                return range_rem;
            }
            self.record_pipeline_hits(1);
            return range_rem;
        }
        if addr != 0 && !page_oracle.may_contain_addr_lockfree(addr) {
            let next = self.unflushed_bloom_misses + 1;
            if !self.unbacked && next < HIT_METRICS_FLUSH_BATCH {
                self.unflushed_bloom_misses = next;
            } else {
                self.record_bloom_misses(1);
            }
            return CachedRemaining::UNKNOWN;
        }
        self.lookup_hit_remaining_slow(addr, arena.map(|a| (a, IS_WRITE, write_len)))
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline(never)]
    fn lookup_hit_remaining_slow(
        &mut self,
        addr: usize,
        integrity: Option<(&crate::arena::AllocationArena, bool, usize)>,
    ) -> CachedRemaining {
        let hit = self.lookup_hit_remaining_entries(addr, integrity);
        if hit.is_hit() && !hit.is_corrupted() {
            self.record_pipeline_hits(1);
        }
        hit
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[inline(always)]
    pub(crate) fn lookup_hit_remaining_pair_with_oracle<const LHS_IS_WRITE: bool>(
        &mut self,
        lhs: usize,
        rhs: usize,
        page_oracle: &crate::page_oracle::PageOracle,
        arena: Option<&crate::arena::AllocationArena>,
        write_len: usize,
    ) -> (CachedRemaining, CachedRemaining) {
        let mut lhs_rem = CachedRemaining::MISS;
        let mut rhs_rem = CachedRemaining::MISS;
        let mut stepped_cadence = None;

        for idx in 0..self.ranges.len() {
            let user_base = self.ranges[idx].user_base;
            let user_size = self.ranges[idx].user_size;
            let lhs_off = lhs.wrapping_sub(user_base);
            if lhs_off < user_size {
                let shard_idx = self.ranges[idx].shard_idx;
                if self.ranges[idx].shard_epoch == current_shard_epoch(shard_idx as usize) {
                    let rem = user_size - lhs_off;
                    lhs_rem = if let Some(arena_ref) = arena
                        && self.ranges[idx].has_integrity
                    {
                        let c = self.cadence_counter.wrapping_add(1);
                        self.cadence_counter = c;
                        stepped_cadence = Some(c);
                        let near_tail = LHS_IS_WRITE
                            && rem.saturating_sub(write_len) <= WARM_WRITE_TAIL_THRESHOLD;
                        if near_tail || (c & warm_integrity_cadence_mask()) == 0 {
                            self.verify_range_remaining_slow(idx, rem, arena_ref)
                        } else {
                            CachedRemaining(rem)
                        }
                    } else {
                        CachedRemaining(rem)
                    };
                    if lhs_rem.is_known_bound() {
                        let rhs_off = rhs.wrapping_sub(user_base);
                        if rhs_off < user_size {
                            // Same live allocation; already passed epoch + cadence/write check.
                            rhs_rem = CachedRemaining(user_size - rhs_off);
                        }
                    } else if lhs_rem.is_corrupted() {
                        let rhs_off = rhs.wrapping_sub(user_base);
                        if rhs_off < user_size {
                            rhs_rem = CachedRemaining(0);
                        }
                    }
                } else {
                    self.ranges[idx].user_size = 0;
                    self.ranges[idx].valid = false;
                }
                break;
            }
        }

        if !rhs_rem.is_known_bound() && !rhs_rem.is_corrupted() {
            for idx in 0..self.ranges.len() {
                let user_base = self.ranges[idx].user_base;
                let user_size = self.ranges[idx].user_size;
                let off = rhs.wrapping_sub(user_base);
                if off < user_size {
                    let shard_idx = self.ranges[idx].shard_idx;
                    if self.ranges[idx].shard_epoch == current_shard_epoch(shard_idx as usize) {
                        let rem = user_size - off;
                        rhs_rem = if let Some(arena_ref) = arena
                            && self.ranges[idx].has_integrity
                        {
                            let c = stepped_cadence.unwrap_or_else(|| {
                                let next = self.cadence_counter.wrapping_add(1);
                                self.cadence_counter = next;
                                next
                            });
                            let mask = warm_integrity_cadence_mask();
                            let phase = if stepped_cadence.is_some() {
                                8 & mask
                            } else {
                                0
                            };
                            if (c & mask) == phase {
                                self.verify_range_remaining_slow(idx, rem, arena_ref)
                            } else {
                                CachedRemaining(rem)
                            }
                        } else {
                            CachedRemaining(rem)
                        };
                    } else {
                        self.ranges[idx].user_size = 0;
                        self.ranges[idx].valid = false;
                    }
                    break;
                }
            }
        }

        if lhs_rem.is_corrupted() || rhs_rem.is_corrupted() {
            return (lhs_rem, rhs_rem);
        }

        if lhs_rem.is_known_bound() && rhs_rem.is_known_bound() {
            self.hits += 2;
            let next_hits = self.unflushed_pipeline_hits + 2;
            if !self.unbacked && next_hits < HIT_METRICS_FLUSH_BATCH {
                self.unflushed_pipeline_hits = next_hits;
                return (lhs_rem, rhs_rem);
            }
            self.record_pipeline_hits(2);
            return (lhs_rem, rhs_rem);
        }

        let lhs_integrity = arena.map(|a| (a, LHS_IS_WRITE, write_len));
        let rhs_integrity = arena.map(|a| (a, false, 0));

        let lhs_maybe_owned = if lhs_rem.is_known_bound() {
            false
        } else if lhs != 0 && !page_oracle.may_contain_addr_lockfree(lhs) {
            lhs_rem = CachedRemaining::UNKNOWN;
            false
        } else {
            lhs != 0
        };

        let rhs_maybe_owned = if rhs_rem.is_known_bound() {
            false
        } else if rhs != 0 && !page_oracle.may_contain_addr_lockfree(rhs) {
            rhs_rem = CachedRemaining::UNKNOWN;
            false
        } else {
            rhs != 0
        };

        if !lhs_maybe_owned && !rhs_maybe_owned && lhs_rem.is_hit() && rhs_rem.is_hit() {
            let hits = u64::from(lhs_rem.is_known_bound()) + u64::from(rhs_rem.is_known_bound());
            let misses = 2 - hits;
            if hits != 0 {
                self.hits += hits;
                let next_hits = self.unflushed_pipeline_hits + hits;
                if !self.unbacked && next_hits < HIT_METRICS_FLUSH_BATCH {
                    self.unflushed_pipeline_hits = next_hits;
                } else {
                    self.record_pipeline_hits(hits);
                }
            }
            let next_misses = self.unflushed_bloom_misses + misses;
            if !self.unbacked && next_misses < HIT_METRICS_FLUSH_BATCH {
                self.unflushed_bloom_misses = next_misses;
            } else {
                self.record_bloom_misses(misses);
            }
            return (lhs_rem, rhs_rem);
        }

        self.lookup_hit_remaining_pair_slow_with_oracle(
            lhs,
            lhs_rem,
            lhs_maybe_owned,
            lhs_integrity,
            rhs,
            rhs_rem,
            rhs_maybe_owned,
            rhs_integrity,
        )
    }

    #[cfg(any(test, not(feature = "owned-tls-cache")))]
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn lookup_hit_remaining_pair_slow_with_oracle(
        &mut self,
        lhs: usize,
        lhs_rem: CachedRemaining,
        lhs_maybe_owned: bool,
        lhs_integrity: Option<(&crate::arena::AllocationArena, bool, usize)>,
        rhs: usize,
        rhs_rem: CachedRemaining,
        rhs_maybe_owned: bool,
        rhs_integrity: Option<(&crate::arena::AllocationArena, bool, usize)>,
    ) -> (CachedRemaining, CachedRemaining) {
        let mut misses = 0u64;
        let mut hits = 0u64;

        let lhs_hit = if lhs_rem.is_known_bound() {
            self.hits += 1;
            hits += 1;
            lhs_rem
        } else if lhs_maybe_owned {
            let h = self.lookup_hit_remaining_entries(lhs, lhs_integrity);
            if h.is_hit() && !h.is_corrupted() {
                hits += 1;
            }
            h
        } else if lhs_rem.is_hit() {
            misses += 1;
            lhs_rem
        } else {
            CachedRemaining::MISS
        };

        let rhs_hit = if rhs_rem.is_known_bound() {
            self.hits += 1;
            hits += 1;
            rhs_rem
        } else if rhs_maybe_owned {
            let h = self.lookup_hit_remaining_entries(rhs, rhs_integrity);
            if h.is_hit() && !h.is_corrupted() {
                hits += 1;
            }
            h
        } else if rhs_rem.is_hit() {
            misses += 1;
            rhs_rem
        } else {
            CachedRemaining::MISS
        };

        if misses != 0 {
            self.record_bloom_misses(misses);
        }
        if hits != 0 {
            self.record_pipeline_hits(hits);
        }
        (lhs_hit, rhs_hit)
    }

    /// Insert or update a cache entry (synthetic/untagged wrapper).
    pub fn insert(
        &mut self,
        addr: usize,
        validation: CachedValidation,
        shard_epochs: &[u64; NUM_TLS_CACHE_SHARDS],
    ) {
        self.insert_internal(addr, validation, 0, 0, 0, false, shard_epochs);
    }

    /// Insert or update a cache entry carrying verified 24B header and 8B trailing canary tags.
    pub(crate) fn insert_with_integrity(
        &mut self,
        addr: usize,
        validation: CachedValidation,
        slot_idx: u32,
        expected_hash: u64,
        expected_canary: u64,
        shard_epochs: &[u64; NUM_TLS_CACHE_SHARDS],
    ) {
        self.insert_internal(
            addr,
            validation,
            slot_idx,
            expected_hash,
            expected_canary,
            true,
            shard_epochs,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_internal(
        &mut self,
        addr: usize,
        validation: CachedValidation,
        slot_idx: u32,
        expected_hash: u64,
        expected_canary: u64,
        has_integrity: bool,
        shard_epochs: &[u64; NUM_TLS_CACHE_SHARDS],
    ) {
        let idx = Self::index(addr);
        let shard_idx = tls_cache_shard_for(validation.user_base);
        let entry = CacheEntry {
            addr,
            user_base: validation.user_base,
            user_size: validation.user_size,
            generation: validation.generation,
            expected_hash,
            expected_canary,
            shard_epoch: shard_epochs[shard_idx],
            slot_idx,
            state: validation.state,
            shard_idx: shard_idx as u8,
            has_integrity,
            valid: true,
        };
        let range_eligible = entry.user_size != 0
            && entry.user_base != 0
            && entry.user_base.checked_add(entry.user_size).is_some()
            && matches!(
                entry.state,
                SafetyState::Valid | SafetyState::Readable | SafetyState::Writable
            );
        let existing_or_empty_pos = if range_eligible {
            self.ranges
                .iter()
                .position(|r| r.valid && r.user_base == entry.user_base)
                .or_else(|| self.ranges.iter().position(|r| !r.valid))
        } else {
            None
        };
        let needs_backing_entries = !range_eligible
            || existing_or_empty_pos.is_none()
            || addr.wrapping_sub(entry.user_base) >= entry.user_size;
        if self.entries.is_none() && !self.unbacked && needs_backing_entries {
            self.entries = allocate_entries();
            if let Some(entries) = self.entries.as_deref_mut() {
                for r in &self.ranges {
                    if r.valid {
                        entries[Self::index(r.addr)] = *r;
                    }
                }
            }
        }
        if let Some(entries) = self.entries.as_deref_mut() {
            entries[idx] = entry;
        }
        if range_eligible {
            // Refresh the range already holding this allocation (or claim the
            // first empty slot, or evict the oldest slot) and move it to
            // index 0 so the inline range scan hits immediately.
            let mut i = existing_or_empty_pos.unwrap_or(self.ranges.len() - 1);
            while i > 0 {
                self.ranges[i] = self.ranges[i - 1];
                i -= 1;
            }
            self.ranges[0] = entry;
            self.next_range = (self.next_range + 1) & 3;
        }
    }

    /// Invalidate entries matching a specific allocation base.
    pub fn invalidate(&mut self, user_base: usize) {
        if let Some(entries) = self.entries.as_deref_mut() {
            for entry in entries.iter_mut() {
                if entry.valid && entry.user_base == user_base {
                    entry.valid = false;
                }
            }
        }
        for entry in &mut self.ranges {
            if entry.valid && entry.user_base == user_base {
                *entry = CacheEntry::EMPTY;
            }
        }
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&mut self) {
        if let Some(entries) = self.entries.as_deref_mut() {
            entries.fill(CacheEntry::EMPTY);
        }
        self.ranges = [CacheEntry::EMPTY; 4];
    }

    /// Get cache hit count.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Get cache miss count.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Compute cache index from pointer address.
    #[inline(always)]
    fn index(addr: usize) -> usize {
        // Use bits [4..14] (assume 16-byte alignment) to avoid massive collisions
        // for different allocations within the same page.
        (addr >> 4) & CACHE_MASK
    }
}

impl Drop for TlsValidationCache {
    fn drop(&mut self) {
        #[cfg(not(feature = "owned-tls-cache"))]
        #[allow(unsafe_code)]
        {
            let cache_ptr = TLS_CACHE_FAST_PTR.get();
            if !cache_ptr.is_null() {
                // SAFETY: `cache_ptr` points to this thread's live `TLS_CACHE`
                // `RefCell<TlsValidationCache>` until cleared here; `as_ptr()` only
                // computes the `UnsafeCell` payload address without borrowing.
                let tracked_inner = unsafe { (*cache_ptr).as_ptr() };
                if std::ptr::eq(tracked_inner, self) {
                    TLS_CACHE_FAST_PTR.set(std::ptr::null());
                }
            }
        }
        self.flush_pipeline_hits();
    }
}

impl Default for TlsValidationCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compact single-register representation of a TLS-cache remaining-bytes lookup.
///
/// Replaces `Option<Option<usize>>` (16 bytes per pointer, 32 bytes for a pair,
/// 40 bytes wrapped in `Option<...>`), which spilled to the stack via hidden
/// `sret` and caused a 45.57% store-to-load forwarding stall (`movups` across
/// two 8-byte `sret` stores) in `known_remaining_pair_in_guarded_string`.
///
/// `UNKNOWN` uses `usize::MAX` to match `KnownRemaining::UNKNOWN` in
/// `frankenlibc-abi`, allowing hits with unknown bounds (e.g. stack/foreign
/// pointers) to convert to `KnownRemaining` with zero bit manipulation.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedRemaining(usize);

impl CachedRemaining {
    pub const UNKNOWN: Self = Self(usize::MAX);
    pub const MISS: Self = Self(usize::MAX - 1);
    pub const CORRUPTED: Self = Self(usize::MAX - 2);

    #[inline(always)]
    pub const fn clamped_zero() -> Self {
        Self(0)
    }

    #[inline(always)]
    pub const fn from_option(rem: Option<usize>) -> Self {
        match rem {
            Some(n) => Self(n),
            None => Self::UNKNOWN,
        }
    }

    #[inline(always)]
    pub const fn is_hit(self) -> bool {
        self.0 != Self::MISS.0
    }

    #[inline(always)]
    pub const fn is_corrupted(self) -> bool {
        self.0 == Self::CORRUPTED.0
    }

    #[inline(always)]
    pub const fn is_known_bound(self) -> bool {
        self.0 < Self::CORRUPTED.0
    }

    #[inline(always)]
    pub const fn raw(self) -> usize {
        self.0
    }

    #[inline(always)]
    pub const fn decode(self) -> Option<Option<usize>> {
        if self.0 == Self::MISS.0 {
            None
        } else if self.0 == Self::UNKNOWN.0 {
            Some(None)
        } else if self.0 == Self::CORRUPTED.0 {
            Some(Some(0))
        } else {
            Some(Some(self.0))
        }
    }
}

/// Cached validation result.
#[derive(Debug, Clone, Copy)]
pub struct CachedValidation {
    pub user_base: usize,
    pub user_size: usize,
    pub generation: u64,
    pub state: SafetyState,
}

static NATIVE_THREAD_COMPILER_TLS_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Disable compiler-TLS (`%fs` / `tpidr_el0`) validation-cache lookups when the
/// runtime creates native `clone` threads without `CLONE_SETTLS`, preventing
/// threads that share a TCB from racing on `TLS_CACHE`.
#[inline]
pub fn disable_compiler_tls_cache_for_native_threads() {
    NATIVE_THREAD_COMPILER_TLS_DISABLED.store(true, std::sync::atomic::Ordering::Release);
}

#[inline(always)]
pub(crate) fn compiler_tls_disabled() -> bool {
    cfg!(feature = "owned-tls-cache")
        || NATIVE_THREAD_COMPILER_TLS_DISABLED.load(std::sync::atomic::Ordering::Acquire)
}

/// Access the thread-local validation cache.
#[cfg(not(feature = "owned-tls-cache"))]
#[inline]
pub fn with_tls_cache<F, R>(f: F) -> R
where
    F: FnOnce(&mut TlsValidationCache) -> R,
{
    if compiler_tls_disabled() {
        let mut fallback = TlsValidationCache::unbacked();
        return f(&mut fallback);
    }
    let mut maybe_f = Some(f);
    let result = TLS_CACHE.try_with(|cache| {
        TLS_CACHE_FAST_PTR.set(std::ptr::from_ref(cache));
        match cache.try_borrow_mut() {
            Ok(mut borrowed) => {
                let action = maybe_f
                    .take()
                    .expect("with_tls_cache closure must be consumed exactly once");
                Some(action(&mut borrowed))
            }
            Err(_) => None, // Re-entrant borrow
        }
    });

    match result {
        Ok(Some(value)) => value,
        _ => {
            // Either thread-local is destroyed OR re-entrant borrow occurred.
            // Execute with an allocation-free temporary cache.
            let mut fallback = TlsValidationCache::unbacked();
            let action = maybe_f
                .take()
                .expect("with_tls_cache fallback closure must be available");
            action(&mut fallback)
        }
    }
}

/// Fast hit-only access to the thread-local validation cache without constructing
/// a 240-byte fallback `TlsValidationCache::unbacked()` frame or wrapping the
/// return value in `Option<R>`.
///
/// Uses the `!Drop` `TLS_CACHE_FAST_PTR` (`statik::Key`) once initialized on the
/// current thread so steady-state hit lookups bypass `fast_local::Key::try_with`
/// state dispatch while still coordinating reentrancy through `RefCell::try_borrow_mut`.
#[cfg(not(feature = "owned-tls-cache"))]
#[inline(always)]
#[allow(unsafe_code)]
pub(crate) fn try_with_tls_cache_hit<F, R: Copy>(default: R, f: F) -> R
where
    F: FnOnce(&mut TlsValidationCache) -> R,
{
    if compiler_tls_disabled() {
        return default;
    }
    let mut cache_ptr = TLS_CACHE_FAST_PTR.get();
    if cache_ptr.is_null() {
        cache_ptr = init_tls_cache_fast_ptr_slow();
        if cache_ptr.is_null() {
            return default;
        }
    }
    // SAFETY: `cache_ptr` points to this thread's live `TLS_CACHE`
    // `RefCell<TlsValidationCache>`, populated after `TLS_CACHE` initialization
    // on this thread and cleared in `TlsValidationCache::drop` before teardown.
    // `RefCell::try_borrow_mut` prevents mutable aliasing across reentrant calls.
    let cache = unsafe { &*cache_ptr };
    match cache.try_borrow_mut() {
        Ok(mut borrowed) => f(&mut borrowed),
        Err(_) => default,
    }
}

#[cfg(not(feature = "owned-tls-cache"))]
#[inline(always)]
#[allow(unsafe_code)]
pub(crate) fn lookup_tls_cache_hit_remaining<const IS_WRITE: bool>(
    addr: usize,
    page_oracle: &crate::page_oracle::PageOracle,
    arena: Option<&crate::arena::AllocationArena>,
    write_len: usize,
) -> CachedRemaining {
    if compiler_tls_disabled() {
        return CachedRemaining::MISS;
    }
    let mut cache_ptr = TLS_CACHE_FAST_PTR.get();
    if cache_ptr.is_null() {
        cache_ptr = init_tls_cache_fast_ptr_slow();
        if cache_ptr.is_null() {
            return CachedRemaining::MISS;
        }
    }
    // SAFETY: same invariant as `try_with_tls_cache_hit`.
    let cache = unsafe { &*cache_ptr };
    match cache.try_borrow_mut() {
        Ok(mut borrowed) => borrowed.lookup_hit_remaining_with_oracle_const::<IS_WRITE>(
            addr,
            page_oracle,
            arena,
            write_len,
        ),
        Err(_) => CachedRemaining::MISS,
    }
}

#[cfg(not(feature = "owned-tls-cache"))]
#[inline(always)]
#[allow(unsafe_code)]
pub(crate) fn lookup_tls_cache_hit_remaining_pair<const LHS_IS_WRITE: bool>(
    lhs: usize,
    rhs: usize,
    page_oracle: &crate::page_oracle::PageOracle,
    arena: Option<&crate::arena::AllocationArena>,
    write_len: usize,
) -> (CachedRemaining, CachedRemaining) {
    if compiler_tls_disabled() {
        return (CachedRemaining::MISS, CachedRemaining::MISS);
    }
    let mut cache_ptr = TLS_CACHE_FAST_PTR.get();
    if cache_ptr.is_null() {
        cache_ptr = init_tls_cache_fast_ptr_slow();
        if cache_ptr.is_null() {
            return (CachedRemaining::MISS, CachedRemaining::MISS);
        }
    }
    // SAFETY: same invariant as `try_with_tls_cache_hit`.
    let cache = unsafe { &*cache_ptr };
    match cache.try_borrow_mut() {
        Ok(mut borrowed) => borrowed.lookup_hit_remaining_pair_with_oracle::<LHS_IS_WRITE>(
            lhs,
            rhs,
            page_oracle,
            arena,
            write_len,
        ),
        Err(_) => (CachedRemaining::MISS, CachedRemaining::MISS),
    }
}

#[cfg(not(feature = "owned-tls-cache"))]
#[cold]
#[inline(never)]
fn init_tls_cache_fast_ptr_slow() -> *const std::cell::RefCell<TlsValidationCache> {
    TLS_CACHE
        .try_with(|cache| {
            let ptr = std::ptr::from_ref(cache);
            TLS_CACHE_FAST_PTR.set(ptr);
            ptr
        })
        .unwrap_or(std::ptr::null())
}

#[cfg(not(feature = "owned-tls-cache"))]
pub(crate) fn flush_current_thread_hit_metrics() {
    if compiler_tls_disabled() {
        return;
    }
    let _ = TLS_CACHE.try_with(|cache| {
        if let Ok(mut borrowed) = cache.try_borrow_mut() {
            borrowed.flush_pipeline_hits();
        }
    });
}

#[cfg(not(feature = "owned-tls-cache"))]
const _: () = assert!(!std::mem::needs_drop::<
    std::cell::Cell<*const std::cell::RefCell<TlsValidationCache>>,
>());

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static TLS_CACHE: std::cell::RefCell<TlsValidationCache> = const {
        std::cell::RefCell::new(TlsValidationCache::const_new())
    };
    static TLS_CACHE_FAST_PTR: std::cell::Cell<*const std::cell::RefCell<TlsValidationCache>> = const {
        std::cell::Cell::new(std::ptr::null())
    };
}

/// Access the validation cache without emitting Rust TLS in replacement-mode
/// artifact experiments.
#[cfg(feature = "owned-tls-cache")]
pub fn with_tls_cache<F, R>(f: F) -> R
where
    F: FnOnce(&mut TlsValidationCache) -> R,
{
    let mut fallback = TlsValidationCache::unbacked();
    f(&mut fallback)
}

#[cfg(feature = "owned-tls-cache")]
#[inline(always)]
pub(crate) fn try_with_tls_cache_hit<F, R: Copy>(default: R, _f: F) -> R
where
    F: FnOnce(&mut TlsValidationCache) -> R,
{
    default
}

#[cfg(feature = "owned-tls-cache")]
#[inline(always)]
pub(crate) fn lookup_tls_cache_hit_remaining<const IS_WRITE: bool>(
    _addr: usize,
    _page_oracle: &crate::page_oracle::PageOracle,
    _arena: Option<&crate::arena::AllocationArena>,
    _write_len: usize,
) -> CachedRemaining {
    CachedRemaining::MISS
}

#[cfg(feature = "owned-tls-cache")]
#[inline(always)]
pub(crate) fn lookup_tls_cache_hit_remaining_pair<const LHS_IS_WRITE: bool>(
    _lhs: usize,
    _rhs: usize,
    _page_oracle: &crate::page_oracle::PageOracle,
    _arena: Option<&crate::arena::AllocationArena>,
    _write_len: usize,
) -> (CachedRemaining, CachedRemaining) {
    (CachedRemaining::MISS, CachedRemaining::MISS)
}

#[cfg(feature = "owned-tls-cache")]
pub(crate) fn flush_current_thread_hit_metrics() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct EpochGoldenContract {
        schema_version: u32,
        bead_id: String,
        original_bead_id: String,
        subject: String,
        cache_size_entries: usize,
        epoch_source: String,
        num_shards: usize,
        cases: Vec<EpochGoldenCase>,
    }

    impl EpochGoldenContract {
        fn case(&self, id: &str) -> &EpochGoldenCase {
            self.cases
                .iter()
                .find(|case| case.id == id)
                .expect("TLS cache epoch golden case must exist")
        }
    }

    #[derive(Debug, serde::Deserialize)]
    struct EpochGoldenCase {
        id: String,
        api: String,
        inserted_epoch: String,
        current_epoch: String,
        lookup_addr_matches: bool,
        expected_lookup: String,
        expected_hit_delta: u64,
        expected_miss_delta: u64,
        expected_entry_valid_after_lookup: bool,
    }

    fn load_epoch_golden_contract() -> EpochGoldenContract {
        serde_json::from_str(include_str!(
            "../../../tests/conformance/tls_cache_epoch_invalidation.golden.json"
        ))
        .expect("TLS cache epoch golden contract must be valid JSON")
    }

    fn assert_epoch_case_metadata(case: &EpochGoldenCase, api: &str) {
        assert_eq!(case.api, api, "case_id={} api drift", case.id);
        assert_eq!(
            case.inserted_epoch, "E",
            "case_id={} inserted epoch label drift",
            case.id
        );
        assert_eq!(
            case.current_epoch, "E+1",
            "case_id={} current epoch label drift",
            case.id
        );
        assert!(
            case.lookup_addr_matches,
            "case_id={} must exercise matching-address epoch mismatch",
            case.id
        );
    }

    fn assert_epoch_mismatch_observation(
        case: &EpochGoldenCase,
        lookup_was_miss: bool,
        hit_delta: u64,
        miss_delta: u64,
        entry_valid_after_lookup: bool,
    ) {
        assert_eq!(
            case.expected_lookup,
            if lookup_was_miss { "miss" } else { "hit" },
            "case_id={} lookup result drift",
            case.id
        );
        assert_eq!(
            hit_delta, case.expected_hit_delta,
            "case_id={} hit counter delta drift",
            case.id
        );
        assert_eq!(
            miss_delta, case.expected_miss_delta,
            "case_id={} miss counter delta drift",
            case.id
        );
        assert_eq!(
            entry_valid_after_lookup, case.expected_entry_valid_after_lookup,
            "case_id={} entry validity drift",
            case.id
        );
    }

    #[test]
    fn tls_cache_epoch_invalidation_golden_contract_is_current() {
        let contract = load_epoch_golden_contract();

        assert_eq!(contract.schema_version, 2);
        assert_eq!(contract.bead_id, "bd-66wz.2.1");
        assert_eq!(contract.original_bead_id, "bd-66wz.2");
        assert_eq!(contract.subject, "tls_cache_epoch_invalidation");
        assert_eq!(contract.cache_size_entries, CACHE_SIZE);
        assert_eq!(
            contract.epoch_source,
            "SHARD_EPOCHS[tls_cache_shard_for(user_base)]"
        );
        assert_eq!(contract.num_shards, NUM_TLS_CACHE_SHARDS);

        let case_ids: Vec<&str> = contract.cases.iter().map(|case| case.id.as_str()).collect();
        assert_eq!(
            case_ids,
            [
                "lookup_epoch_mismatch_forces_miss",
                "lookup_hit_only_epoch_mismatch_self_cleans_without_miss_accounting",
                "second_lookup_after_self_clean_still_misses"
            ]
        );
    }

    #[test]
    fn epoch_mismatch_counter_behavior_matches_golden_contract() {
        let contract = load_epoch_golden_contract();
        let case = contract.case("lookup_epoch_mismatch_forces_miss");
        assert_epoch_case_metadata(case, "lookup");

        let mut cache = TlsValidationCache::new();
        let addr = 0x5000;
        let val = CachedValidation {
            user_base: addr,
            user_size: 96,
            generation: 4,
            state: SafetyState::Valid,
        };

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            cache.insert(addr, val, &snapshot_shard_epochs());
            assert!(
                cache.lookup(addr).is_some(),
                "case_id={} setup must hit before epoch bump",
                case.id
            );
        }

        let hits_before = cache.hits();
        let misses_before = cache.misses();
        bump_shard_epoch(tls_cache_shard_for(addr));

        let result = cache.lookup(addr);
        let idx = TlsValidationCache::index(addr);
        assert_epoch_mismatch_observation(
            case,
            result.is_none(),
            cache.hits() - hits_before,
            cache.misses() - misses_before,
            cache.entry_valid(idx),
        );
    }

    #[test]
    fn hit_only_epoch_mismatch_matches_golden_contract() {
        let contract = load_epoch_golden_contract();
        let case =
            contract.case("lookup_hit_only_epoch_mismatch_self_cleans_without_miss_accounting");
        assert_epoch_case_metadata(case, "lookup_hit_only");

        let mut cache = TlsValidationCache::new();
        let addr = 0x6000;
        let val = CachedValidation {
            user_base: addr,
            user_size: 128,
            generation: 5,
            state: SafetyState::Valid,
        };

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            cache.insert(addr, val, &snapshot_shard_epochs());
            assert!(
                cache.lookup_hit_only(addr).is_some(),
                "case_id={} setup must hit before epoch bump",
                case.id
            );
        }

        let hits_before = cache.hits();
        let misses_before = cache.misses();
        bump_shard_epoch(tls_cache_shard_for(addr));

        let result = cache.lookup_hit_only(addr);
        let idx = TlsValidationCache::index(addr);
        assert_epoch_mismatch_observation(
            case,
            result.is_none(),
            cache.hits() - hits_before,
            cache.misses() - misses_before,
            cache.entry_valid(idx),
        );
    }

    #[test]
    fn second_lookup_after_self_clean_matches_golden_contract() {
        let contract = load_epoch_golden_contract();
        let case = contract.case("second_lookup_after_self_clean_still_misses");
        assert_epoch_case_metadata(case, "lookup");

        let mut cache = TlsValidationCache::new();
        let addr = 0x7000;
        let val = CachedValidation {
            user_base: addr,
            user_size: 160,
            generation: 6,
            state: SafetyState::Valid,
        };

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            cache.insert(addr, val, &snapshot_shard_epochs());
            assert!(
                cache.lookup(addr).is_some(),
                "case_id={} setup must hit before epoch bump",
                case.id
            );
        }

        bump_shard_epoch(tls_cache_shard_for(addr));
        assert!(
            cache.lookup(addr).is_none(),
            "case_id={} first stale lookup must self-clean",
            case.id
        );

        let hits_before = cache.hits();
        let misses_before = cache.misses();
        let result = cache.lookup(addr);
        let idx = TlsValidationCache::index(addr);
        assert_epoch_mismatch_observation(
            case,
            result.is_none(),
            cache.hits() - hits_before,
            cache.misses() - misses_before,
            cache.entry_valid(idx),
        );
    }

    #[test]
    fn cache_miss_on_empty() {
        let mut cache = TlsValidationCache::new();
        assert!(cache.lookup(0x1000).is_none());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn cache_hit_after_insert() {
        let mut cache = TlsValidationCache::new();
        let val = CachedValidation {
            user_base: 0x1000,
            user_size: 256,
            generation: 1,
            state: SafetyState::Valid,
        };
        let _epoch_guard = lock_tls_cache_epoch_for_tests();
        cache.insert(0x1000, val, &snapshot_shard_epochs());

        let result = cache.lookup(0x1000).expect("should hit");
        assert_eq!(result.user_base, 0x1000);
        assert_eq!(result.user_size, 256);
        assert_eq!(result.state, SafetyState::Valid);
        assert_eq!(cache.hits(), 1);
    }

    #[cfg(feature = "owned-tls-cache")]
    #[test]
    fn owned_tls_cache_lane_uses_ephemeral_storage() {
        let addr = 0x1000;
        let validation = CachedValidation {
            user_base: 0x1000,
            user_size: 64,
            generation: 7,
            state: SafetyState::Valid,
        };
        let snapshot = snapshot_shard_epochs();

        with_tls_cache(|cache| {
            assert!(cache.lookup(addr).is_none());
            cache.insert(addr, validation, &snapshot);
            let observed = cache.lookup(addr).expect("inserted value should hit");
            assert_eq!(observed.user_base, validation.user_base);
            assert_eq!(observed.user_size, validation.user_size);
            assert_eq!(observed.generation, validation.generation);
            assert_eq!(observed.state, validation.state);
        });

        with_tls_cache(|cache| {
            assert!(cache.lookup(addr).is_none());
        });
    }

    #[test]
    fn hit_only_probe_does_not_count_miss_before_fallback() {
        let mut cache = TlsValidationCache::new();
        assert!(cache.lookup_hit_only(0x1000).is_none());
        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);

        assert!(cache.lookup(0x1000).is_none());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn invalidation_works() {
        let mut cache = TlsValidationCache::new();
        let val = CachedValidation {
            user_base: 0x2000,
            user_size: 128,
            generation: 2,
            state: SafetyState::Valid,
        };
        let _epoch_guard = lock_tls_cache_epoch_for_tests();
        cache.insert(0x2000, val, &snapshot_shard_epochs());
        assert!(cache.lookup(0x2000).is_some());

        cache.invalidate(0x2000);
        assert!(cache.lookup(0x2000).is_none());
    }

    #[test]
    fn invalidate_all_clears_everything() {
        let mut cache = TlsValidationCache::new();
        let _epoch_guard = lock_tls_cache_epoch_for_tests();
        let snapshot = snapshot_shard_epochs();
        for i in 0..10 {
            let addr = (i + 1) * 0x1000;
            cache.insert(
                addr,
                CachedValidation {
                    user_base: addr,
                    user_size: 64,
                    generation: 1,
                    state: SafetyState::Valid,
                },
                &snapshot,
            );
        }
        cache.invalidate_all();
        for i in 0..10 {
            let addr = (i + 1) * 0x1000;
            assert!(cache.lookup(addr).is_none());
        }
    }

    #[test]
    fn epoch_bump_invalidates_entry_and_self_cleans() {
        let mut cache = TlsValidationCache::new();
        let addr = 0x4000;
        let val = CachedValidation {
            user_base: addr,
            user_size: 64,
            generation: 3,
            state: SafetyState::Valid,
        };

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            cache.insert(addr, val, &snapshot_shard_epochs());
            assert!(
                cache.lookup(addr).is_some(),
                "expected cache hit before epoch bump"
            );
        }

        bump_shard_epoch(tls_cache_shard_for(addr));

        let idx = TlsValidationCache::index(addr);
        assert!(
            cache.lookup(addr).is_none(),
            "expected cache miss after epoch bump"
        );
        assert!(
            !cache.entry_valid(idx),
            "expected entry self-clean invalidation on epoch mismatch"
        );

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            cache.insert(addr, val, &snapshot_shard_epochs());
            assert!(
                cache.lookup(addr).is_some(),
                "expected cache hit after reinsert at current epoch"
            );
        }
    }

    /// Bump of one shard's epoch must not invalidate a cached entry whose
    /// home shard is different. This is the core property the per-shard
    /// design buys over the previous global epoch.
    #[test]
    fn bump_of_unrelated_shard_does_not_invalidate_entry() {
        let _epoch_guard = lock_tls_cache_epoch_for_tests();
        let mut cache = TlsValidationCache::new();
        // Choose an address whose home shard differs from shard 0 so the
        // test exercises a real cross-shard isolation.
        let addr = 0x4000; // (0x4000 >> 12) % 16 == 4
        let home_shard = tls_cache_shard_for(addr);
        assert_ne!(home_shard, 0, "test invariant: home shard must not be 0");

        let val = CachedValidation {
            user_base: addr,
            user_size: 64,
            generation: 9,
            state: SafetyState::Valid,
        };

        cache.insert(addr, val, &snapshot_shard_epochs());
        assert!(cache.lookup(addr).is_some(), "must hit before any bump");

        // Bump every shard EXCEPT the entry's home shard. We use the raw
        // atomic increments rather than the public helper because we already
        // hold the test lock; the helper would deadlock.
        for (s, atomic) in SHARD_EPOCHS.iter().enumerate() {
            if s != home_shard {
                atomic.fetch_add(1, Ordering::Release);
            }
        }

        assert!(
            cache.lookup(addr).is_some(),
            "entry must survive bumps of unrelated shards"
        );

        // Now bump the home shard and confirm the entry IS invalidated.
        SHARD_EPOCHS[home_shard].fetch_add(1, Ordering::Release);
        assert!(
            cache.lookup(addr).is_none(),
            "entry must be invalidated when its own shard bumps"
        );
    }

    /// Compatibility check: `bump_tls_cache_epoch()` (the "bump all shards"
    /// wrapper) must still nuke every entry regardless of which shard each
    /// entry resides in.
    #[test]
    fn bump_tls_cache_epoch_nukes_every_shard() {
        let mut cache = TlsValidationCache::new();
        // Insert entries across multiple shards.
        let addrs: [usize; 4] = [0x1000, 0x4000, 0xA000, 0xF000];
        let mut home_shards = std::collections::HashSet::new();
        for &addr in &addrs {
            home_shards.insert(tls_cache_shard_for(addr));
        }
        assert!(
            home_shards.len() > 1,
            "test invariant: insertions must span multiple shards"
        );

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            let snapshot = snapshot_shard_epochs();
            for &addr in &addrs {
                cache.insert(
                    addr,
                    CachedValidation {
                        user_base: addr,
                        user_size: 64,
                        generation: 1,
                        state: SafetyState::Valid,
                    },
                    &snapshot,
                );
            }
            for &addr in &addrs {
                assert!(cache.lookup(addr).is_some(), "setup hit for {:#x}", addr);
            }
        }

        bump_tls_cache_epoch();

        for &addr in &addrs {
            assert!(
                cache.lookup(addr).is_none(),
                "bump_tls_cache_epoch must invalidate addr={:#x}",
                addr
            );
        }
    }

    /// Race-safety: if a free intervenes between snapshot and insert, the
    /// inserted entry's `shard_epoch` lags the live `SHARD_EPOCHS[shard]`,
    /// and the next lookup must miss. This is the moral equivalent of the
    /// "epoch captured before arena lookup" invariant in the old global
    /// design.
    #[test]
    fn insert_with_stale_snapshot_self_cleans_on_next_lookup() {
        let mut cache = TlsValidationCache::new();
        let addr = 0x8000;
        let val = CachedValidation {
            user_base: addr,
            user_size: 64,
            generation: 11,
            state: SafetyState::Valid,
        };

        let _epoch_guard = lock_tls_cache_epoch_for_tests();
        // Snapshot the world before the racing free.
        let snapshot = snapshot_shard_epochs();
        // Racing free completes before insert.
        SHARD_EPOCHS[tls_cache_shard_for(addr)].fetch_add(1, Ordering::Release);
        // Insert with the now-stale snapshot.
        cache.insert(addr, val, &snapshot);

        // Lookup must miss; the recorded shard_epoch is one behind live.
        assert!(
            cache.lookup(addr).is_none(),
            "stale-snapshot insert must self-clean on next lookup"
        );
    }

    #[test]
    fn interior_pointers_hit_recent_allocation_ranges_until_freed() {
        let mut cache = TlsValidationCache::new();
        let base = 0x9_0000;
        let val = CachedValidation {
            user_base: base,
            user_size: 4096,
            generation: 12,
            state: SafetyState::Valid,
        };
        let epoch_guard = lock_tls_cache_epoch_for_tests();
        cache.insert(base + 8, val, &snapshot_shard_epochs());

        // Any address inside the allocation hits, with its allocation bounds.
        let hit = cache
            .lookup(base + 4000)
            .expect("interior pointer hits by range");
        assert_eq!((hit.user_base, hit.user_size), (base, 4096));
        assert!(cache.lookup_hit_only(base + 1).is_some());
        // One past the end, and before the base, miss.
        assert!(cache.lookup(base + 4096).is_none());
        assert!(cache.lookup(base - 1).is_none());

        // Four ranges are kept; a fifth allocation evicts the oldest one.
        let other = |b: usize| CachedValidation {
            user_base: b,
            user_size: 256,
            generation: 13,
            state: SafetyState::Valid,
        };
        cache.insert(0xA_0000, other(0xA_0000), &snapshot_shard_epochs());
        cache.insert(0xB_0000, other(0xB_0000), &snapshot_shard_epochs());
        cache.insert(0xC_0000, other(0xC_0000), &snapshot_shard_epochs());
        assert!(cache.lookup(base + 100).is_some(), "all 4 ranges kept");
        assert!(cache.lookup(0xA_0000 + 100).is_some());
        assert!(cache.lookup(0xB_0000 + 100).is_some());
        assert!(cache.lookup(0xC_0000 + 100).is_some());
        cache.insert(0xD_0000, other(0xD_0000), &snapshot_shard_epochs());
        assert!(cache.lookup(0xA_0000 + 100).is_some());
        assert!(cache.lookup(0xB_0000 + 100).is_some());
        assert!(cache.lookup(0xC_0000 + 100).is_some());
        assert!(cache.lookup(0xD_0000 + 100).is_some());
        assert!(
            cache.lookup(base + 100).is_none(),
            "the oldest range was replaced on the 5th insert"
        );

        // A free in the allocation's shard invalidates its range.
        // (`bump_shard_epoch` takes the test lock itself: release ours.)
        drop(epoch_guard);
        bump_shard_epoch(tls_cache_shard_for(0xA_0000));
        assert!(cache.lookup(0xA_0000 + 100).is_none(), "freed range misses");

        // invalidate(user_base) clears ranges too.
        cache.invalidate(0xB_0000);
        assert!(cache.lookup(0xB_0000 + 100).is_none());
    }

    #[test]
    #[allow(unsafe_code)]
    fn warm_tls_cache_detects_tail_canary_corruption_immediately_on_near_tail_write_and_cadence() {
        let arena = crate::arena::AllocationArena::new();
        let page_oracle = crate::page_oracle::PageOracle::new();
        let metrics = crate::metrics::global_metrics();

        let alloc = arena.allocate(128).expect("alloc 128");
        page_oracle.insert(alloc.raw_base, alloc.total_size);
        let slot = arena.lookup(alloc.user_base).expect("live slot");
        let fp = crate::fingerprint::AllocationFingerprint::compute(
            slot.user_base,
            slot.user_size as u64,
            slot.generation,
        );
        let canary = fp.canary_for(slot.user_base);

        let epoch_guard = lock_tls_cache_epoch_for_tests();
        let epochs = snapshot_shard_epochs();
        let mut cache = TlsValidationCache::new();
        cache.insert_with_integrity(
            slot.user_base,
            CachedValidation {
                user_base: slot.user_base,
                user_size: slot.user_size,
                generation: slot.generation,
                state: slot.state,
            },
            slot.slot_idx,
            fp.hash,
            canary.as_u64(),
            &epochs,
        );

        // Intact hit returns full 128B bound.
        let intact = cache.lookup_hit_remaining_with_oracle(
            slot.user_base,
            &page_oracle,
            Some((&arena, false, 0)),
        );
        assert_eq!(intact, CachedRemaining(128));

        // Corrupt 1 bit of the trailing canary AFTER TLS cache is warm.
        // SAFETY: `[slot.user_base + 128 .. + 8]` is the live trailing canary.
        unsafe {
            let tail = (slot.user_base + 128) as *mut u8;
            *tail ^= 0x01;
        }

        // Negative control: unverified cold-only lookup (`integrity = None`) stays blind!
        let blind = cache.lookup_hit_remaining_with_oracle(slot.user_base, &page_oracle, None);
        assert_eq!(
            blind,
            CachedRemaining(128),
            "negative control: without warm-TLS integrity verification, corrupted tail returns stale 128"
        );

        // Positive check 1: near-tail write (`slot.user_base + 96` => remaining 32 <= 64)
        // detects corruption IMMEDIATELY on the very next call, evicts cache, and bumps `canary_failures`.
        let failures_before = crate::metrics::MembraneMetrics::get(&metrics.canary_failures);
        let near_tail = cache.lookup_hit_remaining_with_oracle(
            slot.user_base + 96,
            &page_oracle,
            Some((&arena, true, 8)),
        );
        assert_eq!(near_tail, CachedRemaining::CORRUPTED);
        assert_eq!(near_tail.decode(), Some(Some(0)));
        assert!(
            crate::metrics::MembraneMetrics::get(&metrics.canary_failures) > failures_before,
            "warm-TLS canary failure must increment canary_failures"
        );
        // Entry was evicted from both `ranges` and `entries`.
        assert_eq!(
            cache.lookup_hit_remaining_with_oracle(slot.user_base, &page_oracle, None),
            CachedRemaining::MISS
        );

        // Re-populate warm cache and verify 1-in-16 read cadence catches corruption even at offset 0.
        cache.insert_with_integrity(
            slot.user_base,
            CachedValidation {
                user_base: slot.user_base,
                user_size: slot.user_size,
                generation: slot.generation,
                state: slot.state,
            },
            slot.slot_idx,
            fp.hash,
            canary.as_u64(),
            &epochs,
        );
        let failures_before_cadence =
            crate::metrics::MembraneMetrics::get(&metrics.canary_failures);
        let mut detected_at = None;
        for step in 1..=16 {
            let res = cache.lookup_hit_remaining_with_oracle(
                slot.user_base,
                &page_oracle,
                Some((&arena, false, 0)),
            );
            if res.is_corrupted() {
                detected_at = Some(step);
                break;
            }
        }
        assert!(
            detected_at.is_some(),
            "1-in-16 warm-TLS cadence must detect tail corruption within 16 reads"
        );
        assert!(
            crate::metrics::MembraneMetrics::get(&metrics.canary_failures)
                > failures_before_cadence
        );

        drop(epoch_guard);
        let (_, drained) = arena.free(alloc.ptr);
        // SAFETY: test owns drained quarantine entries exclusively.
        unsafe { crate::arena::AllocationArena::deallocate_drained(&drained) };
    }

    #[test]
    #[allow(unsafe_code)]
    fn warm_tls_cache_detects_header_corruption_and_evicts_entry() {
        let arena = crate::arena::AllocationArena::new();
        let page_oracle = crate::page_oracle::PageOracle::new();
        let metrics = crate::metrics::global_metrics();

        let alloc = arena.allocate(48).expect("alloc 48");
        page_oracle.insert(alloc.raw_base, alloc.total_size);
        let slot = arena.lookup(alloc.user_base).expect("live slot");
        let fp = crate::fingerprint::AllocationFingerprint::compute(
            slot.user_base,
            slot.user_size as u64,
            slot.generation,
        );
        let canary = fp.canary_for(slot.user_base);

        let epoch_guard = lock_tls_cache_epoch_for_tests();
        let epochs = snapshot_shard_epochs();
        let mut cache = TlsValidationCache::new();
        cache.insert_with_integrity(
            slot.user_base,
            CachedValidation {
                user_base: slot.user_base,
                user_size: slot.user_size,
                generation: slot.generation,
                state: slot.state,
            },
            slot.slot_idx,
            fp.hash,
            canary.as_u64(),
            &epochs,
        );

        // Corrupt 1 bit of the 24B prepended fingerprint header (`user_base - 24`).
        // SAFETY: `[slot.user_base - 24 .. slot.user_base]` is the live header.
        let hdr_ptr = (slot.user_base - crate::fingerprint::FINGERPRINT_SIZE) as *mut u8;
        let saved = unsafe { *hdr_ptr };
        unsafe { *hdr_ptr = saved ^ 0x40 };

        let fp_failures_before =
            crate::metrics::MembraneMetrics::get(&metrics.fingerprint_failures);
        let res = cache.lookup_hit_remaining_with_oracle(
            slot.user_base,
            &page_oracle,
            Some((&arena, true, 8)),
        );
        assert_eq!(res, CachedRemaining::CORRUPTED);
        assert!(
            crate::metrics::MembraneMetrics::get(&metrics.fingerprint_failures)
                > fp_failures_before,
            "warm-TLS header failure must increment fingerprint_failures"
        );
        assert_eq!(
            cache.lookup_hit_remaining_with_oracle(slot.user_base, &page_oracle, None),
            CachedRemaining::MISS
        );

        // Restore header before freeing.
        unsafe { *hdr_ptr = saved };
        drop(epoch_guard);
        let (_, drained) = arena.free(alloc.ptr);
        unsafe { crate::arena::AllocationArena::deallocate_drained(&drained) };
    }

    #[test]
    #[allow(unsafe_code)]
    fn adaptive_warm_integrity_cadence_zero_catches_every_corrupted_read() {
        let epoch_guard = lock_tls_cache_epoch_for_tests();
        set_warm_integrity_source_escalated(INTEGRITY_SOURCE_PIPELINE_PTR_VALIDATOR, false);
        set_warm_integrity_source_escalated(INTEGRITY_SOURCE_ABI_HOT_FAMILIES, false);
        set_warm_integrity_cadence_mask(DEFAULT_WARM_INTEGRITY_CADENCE_MASK);

        let arena = crate::arena::AllocationArena::new();
        let page_oracle = crate::page_oracle::PageOracle::new();

        let alloc = arena.allocate(256).expect("allocate");
        page_oracle.insert(alloc.raw_base, alloc.total_size);
        let slot = arena.lookup(alloc.user_base).expect("slot");
        let fp = crate::fingerprint::AllocationFingerprint::compute(
            slot.user_base,
            slot.user_size as u64,
            slot.generation,
        );
        let canary = fp.canary_for(slot.user_base);

        let epochs = snapshot_shard_epochs();
        let mut cache = TlsValidationCache::new();
        cache.insert_with_integrity(
            slot.user_base,
            CachedValidation {
                user_base: slot.user_base,
                user_size: slot.user_size,
                generation: slot.generation,
                state: slot.state,
            },
            slot.slot_idx,
            fp.hash,
            canary.as_u64(),
            &epochs,
        );

        // Advance cadence_counter to 1 (non-multiple of 16).
        assert_eq!(
            cache.lookup_hit_remaining_with_oracle(
                slot.user_base,
                &page_oracle,
                Some((&arena, false, 0)),
            ),
            CachedRemaining(256)
        );

        // Corrupt trailing canary byte with a panic-safe restoration guard.
        let canary_ptr = (slot.user_base + slot.user_size) as *mut u8;
        let saved = unsafe { *canary_ptr };
        struct TestResetGuard {
            canary_ptr: *mut u8,
            saved: u8,
        }
        impl Drop for TestResetGuard {
            fn drop(&mut self) {
                unsafe { *self.canary_ptr = self.saved };
                set_warm_integrity_source_escalated(INTEGRITY_SOURCE_PIPELINE_PTR_VALIDATOR, false);
                set_warm_integrity_source_escalated(INTEGRITY_SOURCE_ABI_HOT_FAMILIES, false);
                set_warm_integrity_cadence_mask(DEFAULT_WARM_INTEGRITY_CADENCE_MASK);
            }
        }
        let reset_guard = TestResetGuard { canary_ptr, saved };
        unsafe { *canary_ptr = saved ^ 0xFF };

        // Under default mask (15), tick #2 skips slow verification and returns warm 256.
        assert_eq!(
            cache.lookup_hit_remaining_with_oracle(
                slot.user_base,
                &page_oracle,
                Some((&arena, false, 0)),
            ),
            CachedRemaining(256)
        );

        // Tighten adaptive mask to 0 (1-in-1): very next non-multiple-of-16 read catches corruption!
        set_warm_integrity_cadence_mask(ESCALATED_WARM_INTEGRITY_CADENCE_MASK);
        let res = cache.lookup_hit_remaining_with_oracle(
            slot.user_base,
            &page_oracle,
            Some((&arena, false, 0)),
        );
        assert_eq!(res, CachedRemaining::CORRUPTED);

        drop(reset_guard);
        drop(epoch_guard);
        let (_, drained) = arena.free(alloc.ptr);
        unsafe { crate::arena::AllocationArena::deallocate_drained(&drained) };
    }
}
