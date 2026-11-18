#![cfg_attr(not(feature = "owned-tls-cache"), allow(dead_code))]
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

pub(crate) struct OwnedTlsForkGuard<T: 'static> {
    cache: &'static OwnedTlsCache<T>,
    parent_tid: i32,
    guard: Option<std::sync::MutexGuard<'static, Vec<OwnedTlsSlot<T>>>>,
}

impl<T> OwnedTlsCache<T>
where
    T: Send + 'static,
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
        let mut slots = crate::runtime_policy::lock_std_mutex_preserving_errno(&self.slots);
        // Publish before initialization or growing the Box/Vec: those
        // allocations can enter ABI policy again. Drop the marker before
        // releasing the mutex, including when the callback unwinds.
        self.owner_tid.store(tid, Ordering::Release);
        let _owner = AccessOwnerGuard(&self.owner_tid);
        let index = match slots.iter().position(|slot| slot.tid == tid) {
            Some(index) => index,
            None => match slots.iter().position(|slot| slot.tid == 0) {
                Some(free_index) => {
                    slots[free_index].tid = tid;
                    *slots[free_index].value = (self.init)();
                    free_index
                }
                None => {
                    slots.push(OwnedTlsSlot {
                        tid,
                        value: Box::new((self.init)()),
                    });
                    slots.len() - 1
                }
            },
        };
        f(slots[index].value.as_mut())
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn release_tid(&'static self, tid: i32) {
        if tid <= 0 {
            return;
        }
        let caller_tid = syscall::sys_gettid();
        let mut slots = self.slots.lock().unwrap_or_else(|err| err.into_inner());
        self.owner_tid.store(caller_tid, Ordering::Release);
        let _owner = AccessOwnerGuard(&self.owner_tid);
        for slot in slots.iter_mut() {
            if slot.tid == tid {
                *slot.value = (self.init)();
                slot.tid = 0;
            }
        }
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn lock_for_fork(&'static self) -> OwnedTlsForkGuard<T> {
        let parent_tid = syscall::sys_gettid();
        let guard = crate::runtime_policy::lock_std_mutex_preserving_errno(&self.slots);
        OwnedTlsForkGuard {
            cache: self,
            parent_tid,
            guard: Some(guard),
        }
    }
}

impl<T: Send + 'static> OwnedTlsForkGuard<T> {
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn adopt_and_unlock_in_fork_child(&mut self) {
        if let Some(mut slots) = self.guard.take() {
            let child_tid = syscall::sys_gettid();
            self.cache.owner_tid.store(child_tid, Ordering::Release);
            let _owner = AccessOwnerGuard(&self.cache.owner_tid);
            for slot in slots.iter_mut() {
                if slot.tid == self.parent_tid {
                    slot.tid = child_tid;
                } else if slot.tid != 0 {
                    *slot.value = (self.cache.init)();
                    slot.tid = 0;
                }
            }
            drop(_owner);
            drop(slots);
        }
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
                panic!("owned-cache callback unwind"); // test helper
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

    #[test]
    fn release_tid_recycles_slot_without_growing_vec() {
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 99);
        let tid = frankenlibc_core::syscall::sys_gettid();
        CACHE.with(|v| *v = 123);
        CACHE.release_tid(tid);
        CACHE.with(|v| assert_eq!(*v, 99));
        let mut fork_guard = CACHE.lock_for_fork();
        fork_guard.adopt_and_unlock_in_fork_child();
        CACHE.with(|v| assert_eq!(*v, 99));
    }
}
