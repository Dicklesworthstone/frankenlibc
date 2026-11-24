#![cfg_attr(not(feature = "owned-tls-cache"), allow(dead_code))]
//! Process-keyed scratch storage for opt-in standalone TLS-removal experiments.
//! Lifecycle-owned runtime and scratch storage.
//!
//! This intentionally avoids Rust `thread_local!` so native clones never share
//! these values with the creator whose compiler TLS they inherit. Hosted fast
//! paths can retain compiler TLS; the `owned-tls-cache` experiment also uses
//! these slots to remove that dependency from additional ABI scratch buffers.
//!
//! The core private key table owns each slot's thread identity and destructor.
//! In particular, a recycled kernel TID must never inherit an exited thread's
//! locale, parser state, or policy state. No process-wide cache lock spans an
//! initializer or callback: two threads can use the same cache independently.
//! Each static cache retains one private key for its lifetime; per-thread
//! mappings are released after application thread destructors finish.

use std::cell::{Cell, UnsafeCell};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use frankenlibc_core::pthread::tls::{self, InternalTlsKey};
use frankenlibc_core::syscall;

/// Select storage by the caller's actual lifecycle, not its inherited compiler
/// thread pointer. Default hosted callers retain their original TLS values and
/// returned addresses after native-thread admission, including late host TLS
/// callbacks. Native clones must never read or mutate their creator's values,
/// including the final exit tail after their handle has been withdrawn.
#[cfg(not(feature = "owned-tls-cache"))]
#[inline]
pub(crate) fn uses_owned_tls() -> bool {
    if !frankenlibc_membrane::tls_cache::native_threads_may_share_compiler_tls() {
        return false;
    }
    let tid = syscall::sys_gettid();
    if tid <= 0 {
        // Without identity neither backend can establish unique ownership.
        std::process::abort();
    }
    frankenlibc_core::pthread::thread::handle_for_tid(tid).is_some()
        || tls::current_thread_is_exiting_native()
}

pub(crate) struct OwnedTlsCache<T> {
    key: AtomicU32,
    // PID/TID of the initial key publisher. The marker covers the core key
    // registry's copies before a per-thread slot exists. In a fork child a
    // vanished publisher cannot strand initialization behind its old PID.
    key_owner: AtomicU64,
    init: fn() -> T,
}

struct KeyOwnerGuard<'a>(&'a AtomicU64);

impl Drop for KeyOwnerGuard<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

struct AccessOwnerGuard<'a>(&'a Cell<bool>);

impl Drop for AccessOwnerGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

struct OwnedTlsSlot<T> {
    mapping: *mut u8,
    mapping_len: usize,
    key: InternalTlsKey,
    accessed: Cell<bool>,
    initialized: Cell<bool>,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> OwnedTlsSlot<T> {
    fn allocate(key: InternalTlsKey) -> *mut Self {
        let layout = std::alloc::Layout::new::<Self>();
        let len = layout
            .size()
            .checked_add(layout.align() - 1)
            .expect("owned TLS slot layout overflow");
        // SAFETY: anonymous storage has no allocator or compiler-TLS dependency.
        let mapping = unsafe { syscall::sys_mmap(std::ptr::null_mut(), len, 3, 0x22, -1, 0) }
            .unwrap_or_else(|_| std::process::abort());
        if mapping.is_null() {
            std::process::abort();
        }
        let padding = mapping.align_offset(layout.align());
        // SAFETY: mmap is page-aligned; the checked extent includes enough
        // alignment padding for the complete slot, including over-aligned T.
        let slot = unsafe { mapping.add(padding).cast::<Self>() };
        // Initialize only the header before publication. Writing a large T-sized
        // temporary here could call an interposed memcpy before the reentry
        // marker exists. Zeroed, uninitialized payload bytes are MaybeUninit<T>.
        // SAFETY: slot is aligned writable storage; these writes initialize
        // every header field before any reference or key value is published.
        unsafe {
            std::ptr::addr_of_mut!((*slot).mapping).write(mapping);
            std::ptr::addr_of_mut!((*slot).mapping_len).write(len);
            std::ptr::addr_of_mut!((*slot).key).write(key);
            std::ptr::addr_of_mut!((*slot).accessed).write(Cell::new(false));
            std::ptr::addr_of_mut!((*slot).initialized).write(Cell::new(false));
        }
        slot
    }
}

struct OwnedTlsMapping {
    base: *mut u8,
    len: usize,
}

impl Drop for OwnedTlsMapping {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns a detached slot's original mapping.
        // Payload destruction completes before the guard runs, including unwind.
        let _ = unsafe { syscall::sys_munmap(self.base, self.len) };
    }
}

unsafe extern "C" fn destroy_slot<T>(raw: *mut core::ffi::c_void) {
    // SAFETY: the core key registry clears the value before invoking its
    // matching destructor, transferring this thread's unique slot to us.
    unsafe { reclaim_slot::<T>(raw) };
}

unsafe fn reclaim_slot<T>(raw: *mut core::ffi::c_void) {
    // SAFETY: the caller withdrew this thread's slot from its private key.
    let slot = unsafe { &*raw.cast::<OwnedTlsSlot<T>>() };
    if slot.accessed.get() {
        // Explicit key teardown may be called from inside a cache callback.
        // Retain the slot for another destructor round instead of invalidating
        // the live borrow. Ordinary exit unwinds all access guards first.
        // SAFETY: this is the same live slot owned by this private key.
        let _ = unsafe { tls::internal_tls_setspecific(slot.key, raw as u64) };
        return;
    }
    let _mapping = OwnedTlsMapping {
        base: slot.mapping,
        len: slot.mapping_len,
    };
    if slot.initialized.replace(false) {
        // SAFETY: initialization completed and the slot is no longer borrowed.
        // No cache lock spans Drop; a destructor may populate a fresh key value.
        // The old mapping stays live until Drop finishes or unwinds.
        unsafe { std::ptr::drop_in_place((*slot.value.get()).as_mut_ptr()) };
    }
}

pub(crate) struct OwnedTlsForkGuard<T: 'static> {
    cache: &'static OwnedTlsCache<T>,
    parent_tid: i32,
}

impl<T> OwnedTlsCache<T>
where
    T: Send + 'static,
{
    pub(crate) const fn new(init: fn() -> T) -> Self {
        Self {
            key: AtomicU32::new(0),
            key_owner: AtomicU64::new(0),
            init,
        }
    }

    /// Publish the private key before starting a native thread. The per-thread
    /// payload stays lazy and is allocated from anonymous pages on first use.
    pub(crate) fn prepare_key(&self) {
        let _ = self.key();
    }

    /// Detect allocation reentry without consulting or locking this cache.
    /// Other threads' initializers and callbacks never mark this caller active.
    pub(crate) fn is_accessed_by_current_thread(&self) -> bool {
        let owner = self.key_owner.load(Ordering::Acquire);
        if owner != 0
            && owner as u32 == syscall::sys_gettid() as u32
            && (owner >> 32) as u32 == syscall::sys_getpid() as u32
        {
            return true;
        }
        let key = self.key.load(Ordering::Acquire);
        if key == 0 {
            return false;
        }
        let slot =
            tls::internal_tls_getspecific(InternalTlsKey { id: key }) as *const OwnedTlsSlot<T>;
        // SAFETY: only this thread can access or destroy its key value.
        !slot.is_null() && unsafe { (*slot).accessed.get() }
    }

    /// Read-only, non-allocating, reentrancy-safe inspection of an already
    /// initialized per-thread slot. Never creates keys, allocates memory, or
    /// calls host pthread hooks, making it safe inside `fork()` child setup
    /// while allocator/loader/stdio fork guards are held.
    pub(crate) fn try_peek<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        let key = self.key.load(Ordering::Acquire);
        if key == 0 {
            return None;
        }
        let raw =
            tls::internal_tls_getspecific(InternalTlsKey { id: key }) as *const OwnedTlsSlot<T>;
        if raw.is_null() {
            return None;
        }
        // SAFETY: only this thread can access or destroy its key value.
        let slot = unsafe { &*raw };
        if slot.accessed.get() || !slot.initialized.get() {
            return None;
        }
        // The callback can reenter this cache or request key teardown. Keep
        // its shared reference protected just like a mutable access: neither
        // path may overwrite or reclaim the payload until the callback returns.
        slot.accessed.set(true);
        let _access = AccessOwnerGuard(&slot.accessed);
        // SAFETY: initialized, and the guard excludes mutation and reclamation.
        Some(f(unsafe { (*slot.value.get()).assume_init_ref() }))
    }

    fn key(&self) -> InternalTlsKey {
        let mut key = self.key.load(Ordering::Acquire);
        if key != 0 {
            return InternalTlsKey { id: key };
        }
        let pid = syscall::sys_getpid() as u32 as u64;
        let identity = (pid << 32) | syscall::sys_gettid() as u32 as u64;
        loop {
            let owner = self.key_owner.load(Ordering::Acquire);
            assert_ne!(owner, identity, "reentrant owned TLS key initialization");
            if (owner == 0 || owner >> 32 != pid)
                && self
                    .key_owner
                    .compare_exchange(owner, identity, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                break;
            }
            key = self.key.load(Ordering::Acquire);
            if key != 0 {
                return InternalTlsKey { id: key };
            }
            syscall::sys_sched_yield();
        }
        let _owner = KeyOwnerGuard(&self.key_owner);
        key = self.key.load(Ordering::Acquire);
        if key == 0 {
            let mut created = InternalTlsKey::default();
            if tls::internal_tls_key_create(&mut created, Some(destroy_slot::<T>)) != 0 {
                std::process::abort();
            }
            // Core keys include a nonzero generation, so zero remains a valid
            // uninitialized sentinel even when the key uses registry slot zero.
            key = created.id;
            self.key.store(key, Ordering::Release);
        }
        InternalTlsKey { id: key }
    }

    pub(crate) fn with<R>(&'static self, f: impl FnOnce(&mut T) -> R) -> R {
        let key = self.key();
        let mut raw = tls::internal_tls_getspecific(key) as *mut OwnedTlsSlot<T>;
        if raw.is_null() {
            raw = OwnedTlsSlot::allocate(key);
            // SAFETY: this cache owns the key and its freshly allocated slot;
            // destroy_slot is the matching destructor for this exact T.
            if unsafe { tls::internal_tls_setspecific(key, raw as u64) } != 0
                || tls::internal_tls_getspecific(key) != raw as u64
            {
                // SAFETY: publication failed, and no T has been initialized.
                unsafe { destroy_slot::<T>(raw.cast()) };
                std::process::abort();
            }
        }
        // SAFETY: the key table isolates this live slot to its owning thread.
        // Reentry is checked before taking a mutable reference to the payload.
        let slot = unsafe { &*raw };
        assert!(
            !slot.accessed.replace(true),
            "reentrant owned TLS cache access"
        );
        let access = AccessOwnerGuard(&slot.accessed);
        if !slot.initialized.get() {
            let value = (self.init)();
            // SAFETY: this slot has never held an initialized T and is borrowed.
            unsafe { (*slot.value.get()).write(value) };
            slot.initialized.set(true);
        }
        drop(access);

        // Register the existing host-key bridge outside the initialization
        // borrow: finding the current backend can itself access PTHREAD_TLS.
        // Native clones already run the core key destructor protocol directly.
        #[cfg(not(test))]
        crate::pthread_abi::ensure_host_thread_key_teardown();

        assert!(
            !slot.accessed.replace(true),
            "reentrant owned TLS cache access"
        );
        let _access = AccessOwnerGuard(&slot.accessed);
        // SAFETY: initialized above, with one owner and one active mutable borrow.
        f(unsafe { (*slot.value.get()).assume_init_mut() })
    }

    /// Withdraw and destroy this thread's unborrowed key slot.
    ///
    /// The next `with` initializes a fresh slot, including reentry from the
    /// retiring payload's destructor. Such a replacement remains published.
    /// Another thread's slot is reclaimed by its own key destructor; this
    /// cannot reach it.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn release_tid(&'static self, tid: i32) {
        if tid <= 0 || tid != syscall::sys_gettid() {
            return;
        }
        let key = self.key.load(Ordering::Acquire);
        if key == 0 {
            return;
        }
        let key = InternalTlsKey { id: key };
        let raw = tls::internal_tls_getspecific(key) as *mut OwnedTlsSlot<T>;
        if raw.is_null() {
            return;
        }
        // SAFETY: the key table isolates this slot to the calling thread.
        let slot = unsafe { &*raw };
        if slot.accessed.get() {
            return;
        }
        // Clear publication before Drop can reenter. Reinitializing inside the
        // retiring payload would alias its live Drop(&mut self) reference.
        // SAFETY: this cache owns the private key and this thread's slot.
        if unsafe { tls::internal_tls_setspecific(key, 0) } != 0 {
            return;
        }
        // SAFETY: successful withdrawal transfers this unborrowed slot to us.
        // Use the Rust helper so explicit release preserves destructor unwind.
        unsafe { reclaim_slot::<T>(raw.cast()) };
    }

    /// Fork keeps only the calling thread. There is no shared slot table to lock.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn lock_for_fork(&'static self) -> OwnedTlsForkGuard<T> {
        OwnedTlsForkGuard {
            cache: self,
            parent_tid: syscall::sys_gettid(),
        }
    }
}

impl<T: Send + 'static> OwnedTlsForkGuard<T> {
    /// The child already owns the forking thread's key slot. Other threads
    /// did not survive, so their slots are not retargeted.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn adopt_and_unlock_in_fork_child(&mut self) {
        let _ = (self.cache, self.parent_tid);
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedTlsCache;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static PUBLIC_KEY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct ThreadTlsCleanup;

    impl Drop for ThreadTlsCleanup {
        fn drop(&mut self) {
            // Unit tests do not link the exported ABI host-exit bridge.
            frankenlibc_core::pthread::run_exiting_thread_key_destructors(
                frankenlibc_core::syscall::sys_gettid(),
            );
        }
    }

    #[test]
    fn access_owner_covers_initialization_without_marking_other_threads() {
        let _cleanup = ThreadTlsCleanup;
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
        let _cleanup = ThreadTlsCleanup;
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
    fn peek_holds_the_access_owner_until_its_callback_returns() {
        let _cleanup = ThreadTlsCleanup;
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 17);
        let tid = frankenlibc_core::syscall::sys_gettid();
        CACHE.with(|value| *value = 71);
        assert_eq!(
            CACHE.try_peek(|value| {
                assert!(CACHE.is_accessed_by_current_thread());
                assert!(CACHE.try_peek(|_| ()).is_none());
                CACHE.release_tid(tid);
                let reentry = std::panic::catch_unwind(|| CACHE.with(|inner| *inner = 99));
                assert!(reentry.is_err());
                assert!(CACHE.is_accessed_by_current_thread());
                *value
            }),
            Some(71)
        );
        assert!(!CACHE.is_accessed_by_current_thread());
        CACHE.with(|value| assert_eq!(*value, 71));
    }

    #[test]
    fn peek_unwind_releases_the_access_owner() {
        let _cleanup = ThreadTlsCleanup;
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 17);
        CACHE.with(|value| *value = 71);
        let result = std::panic::catch_unwind(|| {
            CACHE.try_peek(|_| panic!("owned-cache observer unwind"));
        });
        assert!(result.is_err());
        assert!(!CACHE.is_accessed_by_current_thread());
        CACHE.with(|value| *value += 1);
        assert_eq!(CACHE.try_peek(|value| *value), Some(72));
    }

    #[test]
    fn peek_does_not_initialize_missing_or_released_state() {
        let _cleanup = ThreadTlsCleanup;
        static INITIALIZATIONS: AtomicUsize = AtomicUsize::new(0);
        static CACHE: OwnedTlsCache<usize> =
            OwnedTlsCache::new(|| INITIALIZATIONS.fetch_add(1, Ordering::SeqCst) + 1);
        let tid = frankenlibc_core::syscall::sys_gettid();
        assert_eq!(CACHE.try_peek(|value| *value), None);
        assert_eq!(INITIALIZATIONS.load(Ordering::SeqCst), 0);
        CACHE.with(|value| assert_eq!(*value, 1));
        assert_eq!(CACHE.try_peek(|value| *value), Some(1));
        CACHE.release_tid(tid);
        assert_eq!(CACHE.try_peek(|value| *value), None);
        assert_eq!(INITIALIZATIONS.load(Ordering::SeqCst), 1);
        CACHE.with(|value| assert_eq!(*value, 2));
    }

    #[test]
    fn release_tid_reinitializes_the_cache() {
        let _cleanup = ThreadTlsCleanup;
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 99);
        let tid = frankenlibc_core::syscall::sys_gettid();
        CACHE.with(|v| *v = 123);
        CACHE.release_tid(tid);
        CACHE.with(|v| assert_eq!(*v, 99));
        let mut fork_guard = CACHE.lock_for_fork();
        fork_guard.adopt_and_unlock_in_fork_child();
        CACHE.with(|v| assert_eq!(*v, 99));
    }

    #[test]
    fn release_detaches_the_slot_before_a_destructor_repopulates_the_cache() {
        let _cleanup = ThreadTlsCleanup;
        static INITIALIZATIONS: AtomicUsize = AtomicUsize::new(0);
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct State {
            generation: usize,
            value: usize,
        }
        impl Drop for State {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
                if self.generation != 1 {
                    return;
                }
                let key = frankenlibc_core::pthread::tls::InternalTlsKey {
                    id: CACHE.key.load(Ordering::Acquire),
                };
                // Check the publication boundary before attempting reentry:
                // overwriting a still-published payload during Drop is invalid.
                assert_eq!(
                    frankenlibc_core::pthread::tls::internal_tls_getspecific(key),
                    0
                );
                let retiring_address = self as *mut Self as usize;
                CACHE.with(|replacement| {
                    assert_ne!(replacement as *mut State as usize, retiring_address);
                    assert_eq!(replacement.generation, 2);
                    replacement.value = 71;
                });
                assert_eq!(self.generation, 1);
                assert_eq!(self.value, 17);
            }
        }
        static CACHE: OwnedTlsCache<State> = OwnedTlsCache::new(|| State {
            generation: INITIALIZATIONS.fetch_add(1, Ordering::SeqCst) + 1,
            value: 17,
        });
        let tid = frankenlibc_core::syscall::sys_gettid();
        CACHE.with(|state| assert_eq!(state.generation, 1));
        CACHE.release_tid(tid);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        assert_eq!(INITIALIZATIONS.load(Ordering::SeqCst), 2);
        CACHE.with(|state| {
            assert_eq!(state.generation, 2);
            assert_eq!(state.value, 71);
        });
        CACHE.release_tid(tid);
        assert_eq!(DROPS.load(Ordering::SeqCst), 2);
        assert_eq!(CACHE.try_peek(|_| ()), None);
    }

    #[test]
    fn release_unwind_leaves_the_cache_ready_for_reinitialization() {
        let _cleanup = ThreadTlsCleanup;
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct State(usize);
        impl Drop for State {
            fn drop(&mut self) {
                if DROPS.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("owned-cache release unwind");
                }
            }
        }
        static CACHE: OwnedTlsCache<State> = OwnedTlsCache::new(|| State(17));
        let tid = frankenlibc_core::syscall::sys_gettid();
        CACHE.with(|state| state.0 = 71);
        assert!(std::panic::catch_unwind(|| CACHE.release_tid(tid)).is_err());
        assert_eq!(CACHE.try_peek(|_| ()), None);
        CACHE.with(|state| assert_eq!(state.0, 17));
        CACHE.release_tid(tid);
        assert_eq!(DROPS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn callbacks_on_different_threads_can_run_at_the_same_time() {
        let _cleanup = ThreadTlsCleanup;
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 1);
        let (tx, rx) = std::sync::mpsc::channel();
        let (worker, received) = CACHE.with(|value| {
            *value = 7;
            let worker = std::thread::spawn(move || {
                let _cleanup = ThreadTlsCleanup;
                CACHE.with(|value| {
                    let initial = *value;
                    *value = 99;
                    tx.send(initial).unwrap();
                });
            });
            // The first callback remains borrowed while the second enters.
            // A process-wide callback lock makes this bounded receive time out.
            let received = rx.recv_timeout(Duration::from_secs(5));
            assert_eq!(*value, 7);
            (worker, received)
        });
        worker.join().unwrap();
        assert_eq!(received.unwrap(), 1);
        CACHE.with(|value| assert_eq!(*value, 7));
    }

    #[test]
    fn recursive_access_is_rejected_without_aliasing_or_poisoning() {
        let _cleanup = ThreadTlsCleanup;
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 0);
        CACHE.with(|outer| {
            *outer = 7;
            let result = std::panic::catch_unwind(|| CACHE.with(|inner| *inner = 99));
            assert!(result.is_err());
            assert!(CACHE.is_accessed_by_current_thread());
            assert_eq!(*outer, 7);
        });
        assert!(!CACHE.is_accessed_by_current_thread());
        CACHE.with(|value| assert_eq!(*value, 7));
    }

    #[test]
    fn teardown_drops_state_before_the_same_tid_gets_a_fresh_slot() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct State(usize);
        impl Drop for State {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }
        static CACHE: OwnedTlsCache<State> = OwnedTlsCache::new(|| State(5));
        CACHE.with(|state| state.0 = 91);
        drop(ThreadTlsCleanup);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        CACHE.with(|state| assert_eq!(state.0, 5));
        drop(ThreadTlsCleanup);
        assert_eq!(DROPS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn application_key_destructors_still_observe_the_threads_cache_state() {
        use frankenlibc_core::pthread::tls;
        let _keys = PUBLIC_KEY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        static OBSERVED: AtomicUsize = AtomicUsize::new(0);
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct State(usize);
        impl Drop for State {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }
        static CACHE: OwnedTlsCache<State> = OwnedTlsCache::new(|| State(5));
        unsafe extern "C" fn application_destructor(_: *mut core::ffi::c_void) {
            CACHE.with(|state| OBSERVED.store(state.0, Ordering::SeqCst));
        }
        CACHE.with(|state| state.0 = 91);
        let mut key = tls::PthreadKey::default();
        assert_eq!(
            tls::pthread_key_create(&mut key, Some(application_destructor)),
            0
        );
        assert_eq!(tls::pthread_setspecific(key, 1), 0);
        drop(ThreadTlsCleanup);
        assert_eq!(OBSERVED.load(Ordering::SeqCst), 91);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        assert_eq!(tls::pthread_key_delete(key), 0);
    }

    #[test]
    fn first_cache_access_still_works_after_all_public_keys_are_in_use() {
        use frankenlibc_core::pthread::tls;
        let _keys = PUBLIC_KEY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _cleanup = ThreadTlsCleanup;
        struct PublicKeys(Vec<tls::PthreadKey>);
        impl Drop for PublicKeys {
            fn drop(&mut self) {
                for key in &self.0 {
                    assert_eq!(tls::pthread_key_delete(*key), 0);
                }
            }
        }
        let mut keys = PublicKeys(Vec::new());
        for _ in 0..tls::PTHREAD_KEYS_MAX {
            let mut key = tls::PthreadKey::default();
            assert_eq!(tls::pthread_key_create(&mut key, None), 0);
            keys.0.push(key);
        }
        assert_eq!(
            tls::pthread_key_create(&mut tls::PthreadKey::default(), None),
            11
        );
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| 73);
        CACHE.with(|value| assert_eq!(*value, 73));
    }

    #[test]
    fn a_destructor_can_repopulate_its_cache_for_the_next_exit_round() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct State;
        impl Drop for State {
            fn drop(&mut self) {
                if DROPS.fetch_add(1, Ordering::SeqCst) == 0 {
                    CACHE.with(|_| {});
                }
            }
        }
        static CACHE: OwnedTlsCache<State> = OwnedTlsCache::new(|| State);
        CACHE.with(|_| {});
        drop(ThreadTlsCleanup);
        assert_eq!(DROPS.load(Ordering::SeqCst), 2);
        assert!(!CACHE.is_accessed_by_current_thread());
    }

    #[test]
    fn failed_initialization_can_retry_without_dropping_uninitialized_state() {
        let _cleanup = ThreadTlsCleanup;
        static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
        static CACHE: OwnedTlsCache<usize> = OwnedTlsCache::new(|| {
            if ATTEMPTS.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("first initialization fails");
            }
            43
        });
        assert!(std::panic::catch_unwind(|| CACHE.with(|_| {})).is_err());
        assert!(!CACHE.is_accessed_by_current_thread());
        CACHE.with(|value| assert_eq!(*value, 43));
        assert_eq!(ATTEMPTS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn slot_storage_respects_payload_alignment_larger_than_a_page() {
        let _cleanup = ThreadTlsCleanup;
        #[repr(align(8192))]
        struct Aligned(u8);
        static CACHE: OwnedTlsCache<Aligned> = OwnedTlsCache::new(|| Aligned(19));
        CACHE.with(|value| {
            assert_eq!((value as *mut Aligned as usize) % 8192, 0);
            assert_eq!(value.0, 19);
        });
    }

    #[test]
    fn native_thread_exit_runs_the_owned_cache_destructor() {
        let _cleanup = ThreadTlsCleanup;
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct State(usize);
        impl Drop for State {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }
        static CACHE: OwnedTlsCache<State> = OwnedTlsCache::new(|| State(3));
        unsafe extern "C" fn worker(_: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
            // Native clones still inherit hardware TLS. This callback uses
            // only the owned slot, raw syscalls, and atomics, never host malloc.
            CACHE.with(|state| state.0 += 4);
            let value = CACHE
                .try_peek(|state| {
                    // A missing guard is reported before attempting release,
                    // so the regression never dereferences retired storage.
                    if !CACHE.is_accessed_by_current_thread() {
                        return 0;
                    }
                    CACHE.release_tid(frankenlibc_core::syscall::sys_gettid());
                    state.0
                })
                .unwrap_or(0);
            value as *mut core::ffi::c_void
        }
        CACHE.with(|state| state.0 = 55);
        let joined = CACHE.try_peek(|creator| {
            // SAFETY: valid C entry point, no borrowed argument, joined below.
            let handle = unsafe {
                frankenlibc_core::pthread::create_thread(worker as *const () as usize, 0, 0)
            }
            .expect("create native thread");
            // SAFETY: the successful create returned this live, joinable handle.
            let result = unsafe { frankenlibc_core::pthread::join_thread(handle) };
            assert_eq!(creator.0, 55);
            result
        });
        assert_eq!(joined, Some(Ok(7)));
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        CACHE.with(|state| assert_eq!(state.0, 55));
    }
}
