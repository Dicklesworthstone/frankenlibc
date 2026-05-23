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
static SHARD_EPOCHS: [AtomicU64; NUM_TLS_CACHE_SHARDS] = [
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
    AtomicU64::new(1),
];

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
#[inline]
#[must_use]
pub fn current_shard_epoch(shard_idx: usize) -> u64 {
    SHARD_EPOCHS[shard_idx].load(Ordering::Acquire)
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
    /// The safety state at time of validation.
    state: SafetyState,
    /// Shard that owns this allocation, computed via `tls_cache_shard_for`
    /// on `user_base` at insert time. The arena's free path bumps
    /// `SHARD_EPOCHS[shard_idx]` when it disposes of this slot.
    shard_idx: u8,
    /// Shard epoch captured at validation start. A free of this slot will
    /// leave the live `SHARD_EPOCHS[shard_idx]` ahead of this value,
    /// turning the next lookup into a miss.
    shard_epoch: u64,
    /// Whether this entry is populated.
    valid: bool,
}

impl CacheEntry {
    const EMPTY: Self = Self {
        addr: 0,
        user_base: 0,
        user_size: 0,
        generation: 0,
        state: SafetyState::Unknown,
        shard_idx: 0,
        shard_epoch: 0,
        valid: false,
    };
}

/// Thread-local validation cache.
pub struct TlsValidationCache {
    entries: Box<[CacheEntry; CACHE_SIZE]>,
    hits: u64,
    misses: u64,
}

impl TlsValidationCache {
    /// Create a new empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Box::new([CacheEntry::EMPTY; CACHE_SIZE]),
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a pointer in the cache.
    ///
    /// Returns `Some(CachedValidation)` on hit. On a shard-epoch mismatch
    /// (the slot's home shard has been bumped since insertion, indicating
    /// a free) the entry is self-cleaned so subsequent lookups skip the
    /// mismatch comparison.
    pub fn lookup(&mut self, addr: usize) -> Option<CachedValidation> {
        let idx = Self::index(addr);
        let entry = &mut self.entries[idx];

        if entry.valid && entry.addr == addr {
            let live_shard_epoch = current_shard_epoch(entry.shard_idx as usize);
            if entry.shard_epoch == live_shard_epoch {
                self.hits += 1;
                return Some(CachedValidation {
                    user_base: entry.user_base,
                    user_size: entry.user_size,
                    generation: entry.generation,
                    state: entry.state,
                });
            }
            // Shard epoch advanced; the slot was freed (or another slot in
            // the same shard was freed). Self-clean so we don't repay the
            // mismatch on the next lookup.
            entry.valid = false;
        }
        self.misses += 1;
        None
    }

    /// Look up a pointer and return only a valid hit.
    ///
    /// Unlike [`Self::lookup`], this intentionally does not count misses. It
    /// is used by speculative fast paths that fall back to the full pipeline,
    /// where the authoritative miss accounting still happens.
    pub(crate) fn lookup_hit_only(&mut self, addr: usize) -> Option<CachedValidation> {
        let idx = Self::index(addr);
        let entry = &mut self.entries[idx];

        if entry.valid && entry.addr == addr {
            let live_shard_epoch = current_shard_epoch(entry.shard_idx as usize);
            if entry.shard_epoch == live_shard_epoch {
                self.hits += 1;
                return Some(CachedValidation {
                    user_base: entry.user_base,
                    user_size: entry.user_size,
                    generation: entry.generation,
                    state: entry.state,
                });
            }
            entry.valid = false;
        }
        None
    }

    /// Insert or update a cache entry.
    ///
    /// `shard_epochs` is a snapshot taken at validation entry. The shard for
    /// the cached entry is derived from `validation.user_base`, and the
    /// recorded epoch is the snapshot's value for that shard, *not* the
    /// live `SHARD_EPOCHS[shard]` at insert time. This is what makes the
    /// per-shard scheme race-free: if a free intervened between snapshot
    /// and insert, the recorded `shard_epoch` lags the live value and the
    /// very next lookup will mismatch.
    pub fn insert(
        &mut self,
        addr: usize,
        validation: CachedValidation,
        shard_epochs: &[u64; NUM_TLS_CACHE_SHARDS],
    ) {
        let idx = Self::index(addr);
        let shard_idx = tls_cache_shard_for(validation.user_base);
        self.entries[idx] = CacheEntry {
            addr,
            user_base: validation.user_base,
            user_size: validation.user_size,
            generation: validation.generation,
            state: validation.state,
            shard_idx: shard_idx as u8,
            shard_epoch: shard_epochs[shard_idx],
            valid: true,
        };
    }

    /// Invalidate entries matching a specific allocation base.
    pub fn invalidate(&mut self, user_base: usize) {
        for entry in self.entries.iter_mut() {
            if entry.valid && entry.user_base == user_base {
                entry.valid = false;
            }
        }
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&mut self) {
        self.entries.fill(CacheEntry::EMPTY);
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
    fn index(addr: usize) -> usize {
        // Use bits [4..14] (assume 16-byte alignment) to avoid massive collisions
        // for different allocations within the same page.
        (addr >> 4) & CACHE_MASK
    }
}

impl Default for TlsValidationCache {
    fn default() -> Self {
        Self::new()
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

/// Access the thread-local validation cache.
#[cfg(not(feature = "owned-tls-cache"))]
pub fn with_tls_cache<F, R>(f: F) -> R
where
    F: FnOnce(&mut TlsValidationCache) -> R,
{
    let mut maybe_f = Some(f);
    let result = TLS_CACHE.try_with(|cache| {
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
            // Execute with a fresh temporary cache.
            let mut fallback = TlsValidationCache::new();
            let action = maybe_f
                .take()
                .expect("with_tls_cache fallback closure must be available");
            action(&mut fallback)
        }
    }
}

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static TLS_CACHE: std::cell::RefCell<TlsValidationCache> =
        std::cell::RefCell::new(TlsValidationCache::new());
}

/// Access the validation cache without emitting Rust TLS in replacement-mode
/// artifact experiments.
#[cfg(feature = "owned-tls-cache")]
pub fn with_tls_cache<F, R>(f: F) -> R
where
    F: FnOnce(&mut TlsValidationCache) -> R,
{
    let mut fallback = TlsValidationCache::new();
    f(&mut fallback)
}

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
            cache.entries[idx].valid,
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
            cache.entries[idx].valid,
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
            cache.entries[idx].valid,
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
            !cache.entries[idx].valid,
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
}
