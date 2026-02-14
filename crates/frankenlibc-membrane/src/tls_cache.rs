//! Thread-local validation cache.
//!
//! 1024-entry direct-mapped cache indexed by `ptr >> 12` (page-aligned).
//! Avoids global lock contention on the hot path by caching recent
//! validation results per-thread.

use crate::lattice::SafetyState;
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of entries in the TLS cache (must be power of 2).
const CACHE_SIZE: usize = 1024;
const CACHE_MASK: usize = CACHE_SIZE - 1;

// Cross-thread invalidation stamp.
//
// Any operation that changes pointer validity (e.g. free) bumps this epoch.
// Cache entries are tagged with the epoch at insertion time; lookups only hit
// when epochs match. This prevents stale CachedValid hits after frees.
static GLOBAL_TLS_CACHE_EPOCH: AtomicU64 = AtomicU64::new(1);

// Test-only synchronization to avoid flaky cache-hit expectations when other
// concurrently-running tests bump the global epoch (via allocator free paths).
//
// WARNING: Do not hold this lock while calling code paths that bump the epoch
// (e.g. arena free), or you'll deadlock.
#[cfg(test)]
static TLS_CACHE_EPOCH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[inline]
fn current_epoch() -> u64 {
    GLOBAL_TLS_CACHE_EPOCH.load(Ordering::Relaxed)
}

pub(crate) fn bump_tls_cache_epoch() {
    #[cfg(test)]
    let _guard = TLS_CACHE_EPOCH_TEST_LOCK
        .lock()
        .expect("TLS cache epoch test lock poisoned");
    // Relaxed is sufficient: this is an advisory invalidation stamp, not a
    // synchronization primitive for memory effects.
    let _ = GLOBAL_TLS_CACHE_EPOCH.fetch_add(1, Ordering::Relaxed);
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
    generation: u32,
    /// The safety state at time of validation.
    state: SafetyState,
    /// Global invalidation epoch at time of insertion.
    epoch: u64,
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
        epoch: 0,
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
    /// Returns `Some((user_base, user_size, generation, state))` on hit.
    pub fn lookup(&mut self, addr: usize) -> Option<CachedValidation> {
        let idx = Self::index(addr);
        let entry = &mut self.entries[idx];
        let epoch = current_epoch();

        if entry.valid && entry.addr == addr && entry.epoch == epoch {
            self.hits += 1;
            Some(CachedValidation {
                user_base: entry.user_base,
                user_size: entry.user_size,
                generation: entry.generation,
                state: entry.state,
            })
        } else {
            // If the address matches but the epoch does not, invalidate this entry
            // so we don't pay repeated epoch-mismatch checks on the hot path.
            if entry.valid && entry.addr == addr && entry.epoch != epoch {
                entry.valid = false;
            }
            self.misses += 1;
            None
        }
    }

    /// Insert or update a cache entry.
    pub fn insert(&mut self, addr: usize, validation: CachedValidation) {
        let idx = Self::index(addr);
        let epoch = current_epoch();
        self.entries[idx] = CacheEntry {
            addr,
            user_base: validation.user_base,
            user_size: validation.user_size,
            generation: validation.generation,
            state: validation.state,
            epoch,
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
        for entry in self.entries.iter_mut() {
            entry.valid = false;
        }
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
        // Use bits [12..22] (page-aligned, skip low bits)
        (addr >> 12) & CACHE_MASK
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
    pub generation: u32,
    pub state: SafetyState,
}

thread_local! {
    static TLS_CACHE: std::cell::RefCell<TlsValidationCache> =
        std::cell::RefCell::new(TlsValidationCache::new());
}

/// Access the thread-local validation cache.
pub fn with_tls_cache<F, R>(f: F) -> R
where
    F: FnOnce(&mut TlsValidationCache) -> R,
{
    let mut maybe_f = Some(f);
    match TLS_CACHE.try_with(|cache| {
        let action = maybe_f
            .take()
            .expect("with_tls_cache closure must be consumed exactly once");
        action(&mut cache.borrow_mut())
    }) {
        Ok(value) => value,
        Err(_) => {
            let mut fallback = TlsValidationCache::new();
            let action = maybe_f
                .take()
                .expect("with_tls_cache fallback closure must be available");
            action(&mut fallback)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        cache.insert(0x1000, val);

        let result = cache.lookup(0x1000).expect("should hit");
        assert_eq!(result.user_base, 0x1000);
        assert_eq!(result.user_size, 256);
        assert_eq!(result.state, SafetyState::Valid);
        assert_eq!(cache.hits(), 1);
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
        cache.insert(0x2000, val);
        assert!(cache.lookup(0x2000).is_some());

        cache.invalidate(0x2000);
        assert!(cache.lookup(0x2000).is_none());
    }

    #[test]
    fn invalidate_all_clears_everything() {
        let mut cache = TlsValidationCache::new();
        let _epoch_guard = lock_tls_cache_epoch_for_tests();
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
            cache.insert(addr, val);
            assert!(
                cache.lookup(addr).is_some(),
                "expected cache hit before epoch bump"
            );
        }

        bump_tls_cache_epoch();

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
            cache.insert(addr, val);
            assert!(
                cache.lookup(addr).is_some(),
                "expected cache hit after reinsert at current epoch"
            );
        }
    }
}
