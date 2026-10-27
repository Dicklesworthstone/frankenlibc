//! Process-keyed scratch storage for opt-in standalone TLS-removal experiments.
//!
//! This intentionally avoids Rust `thread_local!` so experiment lanes can
//! replace per-thread ABI scratch buffers without introducing a `__tls_get_addr`
//! relocation. It is feature-gated because the default ABI path still uses the
//! existing Rust TLS implementation until every tracked source surface has been
//! migrated and artifact-level nm/readelf checks prove the blocker is gone.

use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};

use frankenlibc_core::syscall;

pub(crate) struct OwnedTlsCache<T> {
    slots: Mutex<Vec<OwnedTlsSlot<T>>>,
    owner_tid: AtomicI32,
    init: fn() -> T,
}

struct AccessOwnerGuard<'a>(&'a AtomicI32);

impl Drop for AccessOwnerGuard<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

struct OwnedTlsSlot<T> {
    tid: i32,
    value: Box<T>,
}

impl<T> OwnedTlsCache<T>
where
    T: Send,
{
    pub(crate) const fn new(init: fn() -> T) -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            owner_tid: AtomicI32::new(0),
            init,
        }
    }

    /// Detect allocation reentry without consulting or locking this cache.
    /// Other threads may contend for the mutex without becoming reentrant.
    pub(crate) fn is_accessed_by_current_thread(&self) -> bool {
        let owner = self.owner_tid.load(Ordering::Acquire);
        owner != 0 && owner == syscall::sys_gettid()
    }

    pub(crate) fn with<R>(&'static self, f: impl FnOnce(&mut T) -> R) -> R {
        let tid = syscall::sys_gettid();
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // Publish before initialization or growing the Box/Vec: those
        // allocations can enter ABI policy again. Drop the marker before
        // releasing the mutex, including when the callback unwinds.
        self.owner_tid.store(tid, Ordering::Release);
        let _owner = AccessOwnerGuard(&self.owner_tid);
        let index = match slots.iter().position(|slot| slot.tid == tid) {
            Some(index) => index,
            None => {
                slots.push(OwnedTlsSlot {
                    tid,
                    value: Box::new((self.init)()),
                });
                slots.len() - 1
            }
        };
        f(slots[index].value.as_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedTlsCache;

    #[test]
    fn access_owner_covers_initialization_without_marking_other_threads() {
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| {
            assert!(CACHE.is_accessed_by_current_thread());
            41
        });
        assert!(!CACHE.is_accessed_by_current_thread());
        CACHE.with(|value| {
            assert_eq!(*value, 41);
            assert!(CACHE.is_accessed_by_current_thread());
            let other = std::thread::spawn(|| CACHE.is_accessed_by_current_thread());
            assert!(!other.join().unwrap());
            *value += 1;
        });
        assert!(!CACHE.is_accessed_by_current_thread());
        CACHE.with(|value| assert_eq!(*value, 42));
    }

    #[test]
    fn unwinding_releases_the_access_owner_before_reusing_the_cache() {
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 0);
        let result = std::panic::catch_unwind(|| {
            CACHE.with(|value| {
                *value = 7;
                assert!(CACHE.is_accessed_by_current_thread());
                panic!("owned-cache callback unwind");
            });
        });
        assert!(result.is_err());
        assert!(!CACHE.is_accessed_by_current_thread());
        CACHE.with(|value| {
            assert_eq!(*value, 7);
            assert!(CACHE.is_accessed_by_current_thread());
        });
        assert!(!CACHE.is_accessed_by_current_thread());
    }
}
