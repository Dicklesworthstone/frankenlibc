//! Lifecycle-owned scratch storage for opt-in TLS-removal experiments.
//!
//! This intentionally avoids Rust `thread_local!` so experiment lanes can
//! replace per-thread ABI scratch buffers without introducing a `__tls_get_addr`
//! relocation. It is feature-gated because the default ABI path still uses the
//! existing Rust TLS implementation until every tracked source surface has been
//! migrated and artifact-level nm/readelf checks prove the blocker is gone.
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

unsafe extern "C" fn destroy_slot<T>(raw: *mut core::ffi::c_void) {
    // SAFETY: the core key registry clears the value before invoking its
    // matching destructor, transferring this thread's unique slot to us.
    let slot = unsafe { &*raw.cast::<OwnedTlsSlot<T>>() };
    if slot.accessed.get() {
        // Explicit key teardown may be called from inside a cache callback.
        // Retain the slot for another destructor round instead of invalidating
        // the live mutable borrow. Ordinary exit unwinds all access guards first.
        // SAFETY: this is the same live slot owned by this private key.
        let _ = unsafe { tls::internal_tls_setspecific(slot.key, raw as u64) };
        return;
    }
    let mapping = slot.mapping;
    let mapping_len = slot.mapping_len;
    if slot.initialized.replace(false) {
        // SAFETY: initialization completed and the slot is no longer borrowed.
        // No cache lock spans Drop; a destructor may populate a fresh key value.
        unsafe { std::ptr::drop_in_place((*slot.value.get()).as_mut_ptr()) };
    }
    // SAFETY: this is the original owned mapping, after dropping its payload.
    let _ = unsafe { syscall::sys_munmap(mapping, mapping_len) };
}

impl<T> OwnedTlsCache<T>
where
    T: Send,
{
    pub(crate) const fn new(init: fn() -> T) -> Self {
        Self {
            key: AtomicU32::new(0),
            key_owner: AtomicU64::new(0),
            init,
        }
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
            7usize as *mut core::ffi::c_void
        }
        CACHE.with(|state| state.0 = 55);
        // SAFETY: valid C entry point, no borrowed argument, joined below.
        let handle =
            unsafe { frankenlibc_core::pthread::create_thread(worker as *const () as usize, 0, 0) }
                .expect("create native thread");
        // SAFETY: the successful create returned this live, joinable handle.
        let joined = unsafe { frankenlibc_core::pthread::join_thread(handle) };
        assert_eq!(joined, Ok(7));
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        CACHE.with(|state| assert_eq!(state.0, 55));
    }
}
