//! Shared internal utilities for ABI adapters.

use std::cell::{Cell, UnsafeCell};
use std::collections::{HashMap, HashSet};
use std::ffi::{c_char, c_void};
#[cfg(feature = "owned-tls-cache")]
use std::hash::{BuildHasherDefault, Hasher};
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

#[cfg(feature = "owned-tls-cache")]
#[derive(Clone)]
pub(crate) struct DeterministicHasher {
    state: u64,
}

#[cfg(feature = "owned-tls-cache")]
impl Default for DeterministicHasher {
    fn default() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }
}

#[cfg(feature = "owned-tls-cache")]
impl Hasher for DeterministicHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        for byte in bytes {
            self.state ^= u64::from(*byte);
            self.state = self.state.wrapping_mul(PRIME);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
}

#[cfg(feature = "owned-tls-cache")]
type ArtifactBuildHasher = BuildHasherDefault<DeterministicHasher>;

#[cfg(feature = "owned-tls-cache")]
pub(crate) type ArtifactHashMap<K, V> = HashMap<K, V, ArtifactBuildHasher>;
#[cfg(not(feature = "owned-tls-cache"))]
pub(crate) type ArtifactHashMap<K, V> = HashMap<K, V>;

#[cfg_attr(test, allow(dead_code))]
#[cfg(feature = "owned-tls-cache")]
pub(crate) type ArtifactHashSet<T> = HashSet<T, ArtifactBuildHasher>;
#[cfg_attr(test, allow(dead_code))]
#[cfg(not(feature = "owned-tls-cache"))]
pub(crate) type ArtifactHashSet<T> = HashSet<T>;

#[inline]
pub(crate) fn artifact_hash_map<K, V>() -> ArtifactHashMap<K, V> {
    ArtifactHashMap::default()
}

#[inline]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn artifact_hash_set<T>() -> ArtifactHashSet<T> {
    ArtifactHashSet::default()
}

/// Small ABI-internal reentrant mutex that avoids Rust TLS.
///
/// `parking_lot::ReentrantMutex` is excellent for normal Rust code, but its
/// owner tracking emits a thread-local RawThreadId key in the standalone
/// replacement artifact. ABI startup/interpose paths only need same-thread
/// recursion plus mutual exclusion, so this lock tracks ownership with the
/// kernel TID and backs off with `sched_yield` under contention.
pub(crate) struct AbiReentrantMutex<T> {
    owner_tid: AtomicUsize,
    recursion_depth: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: the lock serializes mutable access to `value`; sharing the mutex is
// sound when the protected value can move across threads.
unsafe impl<T: Send> Sync for AbiReentrantMutex<T> {}
// SAFETY: ownership transfer preserves the lock/value invariants.
unsafe impl<T: Send> Send for AbiReentrantMutex<T> {}

impl<T> AbiReentrantMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            owner_tid: AtomicUsize::new(0),
            recursion_depth: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub(crate) fn lock(&self) -> AbiReentrantMutexGuard<'_, T> {
        let tid = current_tid();
        if self.try_lock_for_tid(tid) {
            return AbiReentrantMutexGuard {
                lock: self,
                owner_tid: tid,
                _not_send_sync: PhantomData,
            };
        }
        self.lock_contended(tid)
    }

    #[cold]
    #[inline(never)]
    fn lock_contended(&self, tid: usize) -> AbiReentrantMutexGuard<'_, T> {
        loop {
            // Read-spin in Shared MESI state while another thread holds the lock so
            // waiters do not blast `LOCK CMPXCHG` RFOs onto the owner's cache line.
            let mut read_spins = 0u32;
            while self.owner_tid.load(Ordering::Relaxed) != 0 {
                read_spins = read_spins.wrapping_add(1);
                if read_spins & 0x3f == 0 {
                    frankenlibc_core::syscall::sys_sched_yield();
                } else {
                    std::hint::spin_loop();
                }
            }
            if self.try_lock_for_tid(tid) {
                return AbiReentrantMutexGuard {
                    lock: self,
                    owner_tid: tid,
                    _not_send_sync: PhantomData,
                };
            }
            std::hint::spin_loop();
        }
    }

    /// Exclusive access proves no other thread holds or can take the lock.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    #[inline]
    pub(crate) fn try_lock(&self) -> Option<AbiReentrantMutexGuard<'_, T>> {
        let tid = current_tid();
        self.try_lock_for_tid(tid).then(|| AbiReentrantMutexGuard {
            lock: self,
            owner_tid: tid,
            _not_send_sync: PhantomData,
        })
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn opaque_ptr(&self) -> *mut c_void {
        (self as *const Self).cast::<c_void>() as *mut c_void
    }

    /// Release one recursion level for a deliberately forgotten guard.
    ///
    /// # Safety
    ///
    /// The current thread must have acquired this lock and intentionally kept
    /// the guard alive with `mem::forget`.
    #[inline]
    #[allow(dead_code)]
    pub(crate) unsafe fn unlock_forgotten_guard(&self) {
        self.unlock_for_tid(current_tid());
    }

    /// Call in a `fork` child for a lock the forking thread held across the
    /// clone. The child's only thread has a new TID, so ownership recorded
    /// under the parent's TID would make the guard's drop a silent no-op and
    /// leave the lock held forever: the next `fork`/`setenv` in the child
    /// spun at 100% CPU (`tar -czf`, bd-rc0923-epic-eeuy4f.5). Transfers
    /// ownership (and recursion depth) to the child's thread.
    ///
    /// # Safety
    ///
    /// Must only be called in a freshly forked child, before any other thread
    /// exists, with `parent_tid` read by the forking thread before the clone.
    #[allow(dead_code)]
    #[inline]
    pub(crate) unsafe fn adopt_in_fork_child(&self, parent_tid: usize) {
        let _ = self.owner_tid.compare_exchange(
            parent_tid,
            current_tid(),
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }

    /// Owner key used for ownership, exposed so fork paths can record the parent's.
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn current_owner_tid() -> usize {
        current_tid()
    }

    #[inline]
    fn try_lock_for_tid(&self, tid: usize) -> bool {
        if self.owner_tid.load(Ordering::Acquire) == tid {
            let ok = self
                .recursion_depth
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |d| d.checked_add(1))
                .is_ok();
            assert!(ok, "AbiReentrantMutex recursion_depth overflow");
            return true;
        }

        if self
            .owner_tid
            .compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.recursion_depth.store(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    #[inline]
    fn unlock_for_tid(&self, tid: usize) {
        if self.owner_tid.load(Ordering::Acquire) != tid {
            return;
        }

        let depth = self.recursion_depth.load(Ordering::Relaxed);
        if depth > 1 {
            self.recursion_depth.store(depth - 1, Ordering::Relaxed);
            return;
        }

        self.recursion_depth.store(0, Ordering::Relaxed);
        self.owner_tid.store(0, Ordering::Release);
    }
}

#[inline]
fn current_tid() -> usize {
    #[cfg(not(test))]
    if let Some(owner_key) = crate::malloc_abi::fast_thread_owner_key() {
        return owner_key;
    }
    (frankenlibc_core::syscall::sys_gettid().max(1) as usize) << 1
}

/// An acquisition belongs to the current kernel thread, not just to the lock.
///
/// A bare `&AbiReentrantMutex<T>` would make this guard `Send + Sync` for any
/// `T: Send`, including `Cell<T>`. Moving it would let another thread access
/// the value while the owner recursively acquires it; sharing it would expose
/// a non-`Sync` value concurrently. A foreign-thread drop also cannot release
/// the owner's recursion level. Keep both auto traits disabled explicitly.
pub(crate) struct AbiReentrantMutexGuard<'a, T> {
    lock: &'a AbiReentrantMutex<T>,
    owner_tid: usize,
    _not_send_sync: PhantomData<*mut ()>,
}

impl<T> AbiReentrantMutexGuard<'_, T> {
    /// Transfer both the underlying lock's recorded owner and this guard's
    /// cached `owner_tid` to `new_tid` (or `current_tid()` in a fork child).
    ///
    /// Updating only `self.lock.owner_tid` leaves `self.owner_tid` holding the
    /// parent's TID, causing `Drop` (`unlock_for_tid(self.owner_tid)`) to
    /// mismatch `self.lock.owner_tid` and silently leak the lock forever in the
    /// forked child whenever `current_tid()` changes across `fork()`.
    ///
    /// # Safety
    ///
    /// Must only be called in a freshly forked child before any other thread
    /// exists in the child process.
    #[cfg_attr(test, allow(dead_code))]
    #[inline]
    pub(crate) unsafe fn adopt_in_fork_child(&mut self) {
        unsafe { self.adopt_for_tid(current_tid()) };
    }

    #[inline]
    unsafe fn adopt_for_tid(&mut self, child_tid: usize) {
        let _ = self.lock.owner_tid.compare_exchange(
            self.owner_tid,
            child_tid,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
        self.owner_tid = child_tid;
    }
}

impl<T> Deref for AbiReentrantMutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard proves this thread holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for AbiReentrantMutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.unlock_for_tid(self.owner_tid);
    }
}

#[inline]
fn allocation_bound(ptr: *const c_char) -> Option<usize> {
    #[cfg(not(test))]
    {
        crate::malloc_abi::known_remaining(ptr as usize)
    }

    #[cfg(test)]
    {
        test_allocation_bound(ptr as usize)
    }
}

/// Scan a C string with an optional hard bound.
///
/// Returns `(len, terminated)` where:
/// - `len` is the byte length before the first NUL or before the bound.
/// - `terminated` indicates whether a NUL byte was observed.
///
/// # NOT `string_abi::scan_c_string`, and the difference is a page fault
///
/// There are TWO functions with this name in this crate and their read
/// footprints differ. THIS one walks byte by byte and stops at the terminator,
/// so it never touches a byte past the NUL — which is why a caller may hand it a
/// DEFENSIVE CAP (a limit it invented for a string of unknown length, like
/// `MAX_PUBLISHED_PROGNAME_BYTES`) over a pointer it does not own.
/// [`crate::string_abi::scan_c_string`] is the SWAR/SIMD scanner: its bounded arm
/// treats the bound as a promise of readable bytes and loads whole 128-byte
/// windows under it, so the same call there faults on a string that ends flush
/// against a page boundary.
///
/// The 20 modules that `use crate::util::scan_c_string` therefore get the safe
/// one for free, and `string_abi`'s is only ever reached FULLY QUALIFIED. That
/// invariant is not decoration — bd-defensive-cap-scan-sweep-fhk28c was filed
/// against six cap sites on the strength of the other function's contract, and
/// all six turned out to call this one. `tests/capped_scans_use_the_scalar_scanner.rs`
/// pins it so a future `use crate::string_abi::scan_c_string` cannot silently
/// change which scanner those bare calls resolve to.
///
/// # Safety
///
/// `ptr` must be valid to read up to the discovered length (and bound when given).
pub unsafe fn scan_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    let effective_bound = match (bound, allocation_bound(ptr)) {
        (Some(limit), Some(alloc)) => Some(limit.min(alloc)),
        (Some(limit), None) => Some(limit),
        (None, Some(alloc)) => Some(alloc),
        (None, None) => None,
    };

    match effective_bound {
        Some(limit) => {
            for i in 0..limit {
                if unsafe { *ptr.add(i) } == 0 {
                    return (i, true);
                }
            }
            (limit, false)
        }
        None => {
            let mut i = 0usize;
            while unsafe { *ptr.add(i) } != 0 {
                i += 1;
            }
            (i, true)
        }
    }
}

// ===========================================================================
// Destructor-order-safe heap-backed TLS cell (`TlsHeapCell<T>`)
// ===========================================================================
//
// `std::thread_local!` keys storing `Box<T>` (or any `Drop` type) register an
// eager LIFO `__cxa_thread_atexit_impl` destructor on first access. On host
// threads under `LD_PRELOAD`, user `pthread_key_create` destructors run via
// `pthread_abi::run_host_thread_key_destructors` inside `__call_tls_dtors`
// AFTER any `Box<T>` TLS key initialized later on the same thread — causing
// `LocalKey::with()` to panic (`SIGABRT` across `extern "C"`) or freeing a
// buffer whose raw pointer was exposed (`__rpc_thread_svc_pollfd`).
//
// `TlsHeapCell<T>` is `#[repr(transparent)]` over `Cell<*mut T>` (`8` bytes in
// `.tbss`, `!needs_drop`, `const`-constructible) so `LocalKey::with()` never
// enters a destroyed state. Heap blocks are reclaimed strictly AFTER all user
// `pthread_key_create` destructors complete on both host and native threads.

const TLS_HEAP_ALLOC_MALLOC: u8 = 1;
const TLS_HEAP_ALLOC_MMAP: u8 = 2;

struct TlsHeapHeader {
    next: *mut TlsHeapHeader,
    cell_slot: *const Cell<*mut u8>,
    payload_offset: usize,
    alloc_size: usize,
    alloc_kind: u8,
    pre_free: Option<unsafe fn()>,
    drop_in_place: Option<unsafe fn(*mut u8)>,
}

type NativeTlsHeapMap = HashMap<(i32, usize), usize>;

static NATIVE_THREADS_CREATED: AtomicBool = AtomicBool::new(false);
static NATIVE_TLS_HEAP_MAP: AbiReentrantMutex<Option<NativeTlsHeapMap>> =
    AbiReentrantMutex::new(None);

std::thread_local! {
    static TLS_HEAP_HEAD: Cell<*mut TlsHeapHeader> = const { Cell::new(core::ptr::null_mut()) };
    static TLS_HEAP_OWNER_TID: Cell<i32> = const { Cell::new(0) };
    static TLS_HEAP_ATEXIT_REGISTERED: Cell<bool> = const { Cell::new(false) };
    static TLS_HEAP_PENDING_KEY_DTORS: Cell<bool> = const { Cell::new(false) };
}

struct TlsErrnoGuard {
    saved: i32,
}

impl TlsErrnoGuard {
    #[inline]
    fn new() -> Self {
        #[cfg(not(test))]
        let saved = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
        #[cfg(test)]
        let saved = unsafe { std::ptr::read_volatile(libc::__errno_location()) };
        Self { saved }
    }
}

impl Drop for TlsErrnoGuard {
    #[inline]
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            crate::errno_abi::set_abi_errno(self.saved);
        }
        #[cfg(test)]
        unsafe {
            std::ptr::write_volatile(libc::__errno_location(), self.saved);
        }
    }
}

#[inline]
unsafe fn drop_typed_in_place<T>(ptr: *mut u8) {
    unsafe { core::ptr::drop_in_place(ptr.cast::<T>()) };
}

#[inline]
unsafe fn alloc_tls_heap_block(total_bytes: usize, zeroed: bool) -> (*mut u8, usize, u8) {
    let bytes = total_bytes.max(1);
    #[cfg(not(test))]
    let raw = unsafe {
        let p = crate::malloc_abi::host_passthrough_malloc(bytes);
        if zeroed && !p.is_null() {
            core::ptr::write_bytes(p.cast::<u8>(), 0, bytes);
        }
        p
    };
    #[cfg(test)]
    let raw = unsafe {
        if zeroed {
            libc::calloc(1, bytes)
        } else {
            libc::malloc(bytes)
        }
    };
    if !raw.is_null() {
        return (raw.cast::<u8>(), bytes, TLS_HEAP_ALLOC_MALLOC);
    }

    let page_len = bytes.next_multiple_of(4096).max(4096);
    if let Ok(mapped) = unsafe {
        frankenlibc_core::syscall::sys_mmap(
            core::ptr::null_mut(),
            page_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } {
        return (mapped, page_len, TLS_HEAP_ALLOC_MMAP);
    }
    (core::ptr::null_mut(), 0, 0)
}

#[inline]
unsafe fn free_tls_heap_block(ptr: *mut u8, alloc_size: usize, alloc_kind: u8) {
    if ptr.is_null() {
        return;
    }
    match alloc_kind {
        TLS_HEAP_ALLOC_MALLOC => {
            #[cfg(not(test))]
            unsafe {
                crate::malloc_abi::host_passthrough_free(ptr.cast::<c_void>());
            }
            #[cfg(test)]
            unsafe {
                libc::free(ptr.cast::<c_void>());
            }
        }
        TLS_HEAP_ALLOC_MMAP => {
            let _ = unsafe { frankenlibc_core::syscall::sys_munmap(ptr, alloc_size) };
        }
        _ => {}
    }
}

#[inline]
unsafe fn destroy_tls_heap_node(node: *mut TlsHeapHeader) {
    let cell_slot = unsafe { (*node).cell_slot };
    if !cell_slot.is_null() {
        unsafe { (*cell_slot).set(core::ptr::null_mut()) };
    }
    if let Some(pre_free) = unsafe { (*node).pre_free } {
        unsafe { pre_free() };
    }
    if let Some(drop_fn) = unsafe { (*node).drop_in_place } {
        let payload = unsafe { (node.cast::<u8>()).add((*node).payload_offset) };
        unsafe { drop_fn(payload) };
    }
    let alloc_size = unsafe { (*node).alloc_size };
    let alloc_kind = unsafe { (*node).alloc_kind };
    unsafe { free_tls_heap_block(node.cast::<u8>(), alloc_size, alloc_kind) };
}

/// Mark that the current host thread has registered `pthread_key_create`
/// teardown so `TlsHeapCell` defers reclamation until after all key destructors.
#[cfg_attr(test, allow(dead_code))]
#[inline]
pub(crate) fn mark_thread_has_pending_key_destructors() {
    let _ = TLS_HEAP_PENDING_KEY_DTORS.try_with(|flag| flag.set(true));
}

/// Complete host-thread key-destructor phase and reclaim all `TlsHeapCell`s.
#[cfg_attr(test, allow(dead_code))]
#[inline]
pub(crate) fn finish_thread_key_destructors_and_reclaim_tls_heap() {
    let _ = TLS_HEAP_PENDING_KEY_DTORS.try_with(|flag| flag.set(false));
    reclaim_current_thread_tls_heap_cells();
}

/// Notify `TlsHeapCell` before creating a native-backend clone thread whose
/// hardware `%fs` TLS may alias its creator.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn note_native_thread_created() {
    frankenlibc_core::pthread::tls::install_native_thread_post_teardown_hook(
        reclaim_native_thread_tls_heap_cells,
    );
    NATIVE_THREADS_CREATED.store(true, Ordering::Release);
}

fn reclaim_native_thread_tls_heap_cells(tid: i32) {
    let _errno_guard = TlsErrnoGuard::new();
    loop {
        let mut drained = Vec::new();
        {
            let guard = NATIVE_TLS_HEAP_MAP.lock();
            let map_slot = unsafe { &mut *NATIVE_TLS_HEAP_MAP.value.get() };
            let _ = &guard;
            if let Some(map) = map_slot.as_mut() {
                map.retain(|&(entry_tid, _), &mut node_addr| {
                    if entry_tid == tid {
                        drained.push(node_addr as *mut TlsHeapHeader);
                        false
                    } else {
                        true
                    }
                });
            }
        }
        if drained.is_empty() {
            break;
        }
        for node in drained {
            unsafe { destroy_tls_heap_node(node) };
        }
    }
}

/// Reclaim all `TlsHeapCell` allocations owned by the calling host thread.
pub(crate) fn reclaim_current_thread_tls_heap_cells() {
    let _errno_guard = TlsErrnoGuard::new();
    let tid = frankenlibc_core::syscall::sys_gettid();
    if !TLS_HEAP_OWNER_TID
        .try_with(|owner| owner.get() == tid)
        .unwrap_or(false)
    {
        return;
    }
    let _ = TLS_HEAP_ATEXIT_REGISTERED.try_with(|reg| reg.set(false));
    while let Some(mut cursor) = TLS_HEAP_HEAD
        .try_with(|head| {
            let cur = head.replace(core::ptr::null_mut());
            (!cur.is_null()).then_some(cur)
        })
        .ok()
        .flatten()
    {
        while !cursor.is_null() {
            let next = unsafe { (*cursor).next };
            unsafe { destroy_tls_heap_node(cursor) };
            cursor = next;
        }
    }
}

unsafe extern "C" fn tls_heap_cxa_atexit_hook(_: *mut c_void) {
    if TLS_HEAP_PENDING_KEY_DTORS
        .try_with(Cell::get)
        .unwrap_or(false)
    {
        return;
    }
    reclaim_current_thread_tls_heap_cells();
}

fn ensure_host_tls_heap_atexit(tid: i32) {
    let _ = TLS_HEAP_OWNER_TID.try_with(|owner| {
        if owner.get() != tid {
            // If inherited across fork(), adopt ownership in the child thread.
            owner.set(tid);
        }
    });
    if TLS_HEAP_ATEXIT_REGISTERED
        .try_with(|reg| reg.replace(true))
        .unwrap_or(true)
    {
        return;
    }
    if tid == frankenlibc_core::syscall::sys_getpid() {
        return;
    }
    #[cfg(not(test))]
    unsafe {
        let _ = crate::startup_abi::__cxa_thread_atexit_impl(
            tls_heap_cxa_atexit_hook,
            core::ptr::null_mut(),
            (&raw const crate::unistd_abi::__dso_handle)
                .cast_mut()
                .cast(),
        );
    }
    #[cfg(test)]
    unsafe {
        unsafe extern "C" {
            fn __cxa_thread_atexit_impl(
                dtor: unsafe extern "C" fn(*mut c_void),
                obj: *mut c_void,
                dso_handle: *mut c_void,
            ) -> std::ffi::c_int;
        }
        let _ = __cxa_thread_atexit_impl(
            tls_heap_cxa_atexit_hook,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }
}

#[cfg_attr(test, allow(dead_code))]
#[inline]
pub(crate) fn lock_native_tls_heap_for_fork()
-> Option<AbiReentrantMutexGuard<'static, Option<NativeTlsHeapMap>>> {
    NATIVE_THREADS_CREATED
        .load(Ordering::Acquire)
        .then(|| NATIVE_TLS_HEAP_MAP.lock())
}

#[inline]
fn current_thread_uses_native_tls_map() -> Option<i32> {
    if !NATIVE_THREADS_CREATED.load(Ordering::Acquire) {
        return None;
    }
    #[cfg(not(test))]
    if frankenlibc_core::pthread::thread::current_thread_handle().is_some() {
        return Some(frankenlibc_core::syscall::sys_gettid());
    }
    None
}

/// Zero-drop, 8-byte `.tbss` pointer cell for lazy heap-backed thread-local state.
#[repr(transparent)]
pub struct TlsHeapCell<T: 'static> {
    ptr: Cell<*mut T>,
}

const _: () = {
    assert!(!core::mem::needs_drop::<TlsHeapCell<Vec<u8>>>());
    assert!(core::mem::size_of::<TlsHeapCell<Vec<u8>>>() == core::mem::size_of::<usize>());
};

impl<T: 'static> Default for TlsHeapCell<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: 'static> TlsHeapCell<T> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            ptr: Cell::new(core::ptr::null_mut()),
        }
    }

    #[inline]
    pub(crate) fn with_init<R>(&self, init: fn() -> T, f: impl FnOnce(&T) -> R) -> R {
        self.try_with_init(init, None, f)
            .unwrap_or_else(|| std::process::abort())
    }

    #[inline]
    pub(crate) fn try_with_init<R>(
        &self,
        init: fn() -> T,
        pre_free: Option<unsafe fn()>,
        f: impl FnOnce(&T) -> R,
    ) -> Option<R> {
        let ptr = self.get_or_alloc(false, Some(init), pre_free)?;
        Some(f(unsafe { &*ptr }))
    }

    #[inline]
    pub(crate) fn with_zeroed<R>(
        &self,
        pre_free: Option<unsafe fn()>,
        f: impl FnOnce(&T) -> R,
    ) -> R {
        self.try_with_zeroed(pre_free, f)
            .unwrap_or_else(|| std::process::abort())
    }

    #[inline]
    pub(crate) fn try_with_zeroed<R>(
        &self,
        pre_free: Option<unsafe fn()>,
        f: impl FnOnce(&T) -> R,
    ) -> Option<R> {
        let ptr = self.get_or_alloc(true, None, pre_free)?;
        Some(f(unsafe { &*ptr }))
    }

    #[inline]
    fn get_or_alloc(
        &self,
        zeroed: bool,
        init: Option<fn() -> T>,
        pre_free: Option<unsafe fn()>,
    ) -> Option<*mut T> {
        if let Some(native_tid) = current_thread_uses_native_tls_map() {
            return self.get_or_alloc_native_slow(native_tid, zeroed, init, pre_free);
        }
        let existing = self.ptr.get();
        if !existing.is_null() {
            return Some(existing);
        }
        self.alloc_host_slow(zeroed, init, pre_free)
    }

    #[cold]
    fn alloc_node_and_payload(
        &self,
        cell_slot: *const Cell<*mut u8>,
        zeroed: bool,
        init: Option<fn() -> T>,
        pre_free: Option<unsafe fn()>,
    ) -> Option<(*mut TlsHeapHeader, *mut T)> {
        let _errno_guard = TlsErrnoGuard::new();
        let align = core::mem::align_of::<T>().max(core::mem::align_of::<TlsHeapHeader>());
        let total = core::mem::size_of::<TlsHeapHeader>()
            .checked_add(align)?
            .checked_add(core::mem::size_of::<T>())?;
        let (base, alloc_size, alloc_kind) = unsafe { alloc_tls_heap_block(total, zeroed) };
        if base.is_null() {
            return None;
        }
        let header_end = unsafe { base.add(core::mem::size_of::<TlsHeapHeader>()) } as usize;
        let payload_addr = (header_end + (align - 1)) & !(align - 1);
        let payload_offset = payload_addr - (base as usize);
        let payload_ptr = unsafe { base.add(payload_offset) }.cast::<T>();
        if let Some(init_fn) = init {
            unsafe { payload_ptr.write(init_fn()) };
        }
        let drop_in_place = if core::mem::needs_drop::<T>() {
            Some(drop_typed_in_place::<T> as unsafe fn(*mut u8))
        } else {
            None
        };
        let node = base.cast::<TlsHeapHeader>();
        unsafe {
            node.write(TlsHeapHeader {
                next: core::ptr::null_mut(),
                cell_slot,
                payload_offset,
                alloc_size,
                alloc_kind,
                pre_free,
                drop_in_place,
            });
        }
        Some((node, payload_ptr))
    }

    #[cold]
    fn alloc_host_slow(
        &self,
        zeroed: bool,
        init: Option<fn() -> T>,
        pre_free: Option<unsafe fn()>,
    ) -> Option<*mut T> {
        let cell_slot = (&raw const self.ptr).cast::<Cell<*mut u8>>();
        let (node, payload_ptr) = self.alloc_node_and_payload(cell_slot, zeroed, init, pre_free)?;
        let tid = frankenlibc_core::syscall::sys_gettid();
        ensure_host_tls_heap_atexit(tid);
        let linked = TLS_HEAP_HEAD
            .try_with(|head| {
                unsafe { (*node).next = head.get() };
                head.set(node);
            })
            .is_ok();
        if !linked {
            unsafe { destroy_tls_heap_node(node) };
            return None;
        }
        self.ptr.set(payload_ptr);
        Some(payload_ptr)
    }

    #[cold]
    fn get_or_alloc_native_slow(
        &self,
        native_tid: i32,
        zeroed: bool,
        init: Option<fn() -> T>,
        pre_free: Option<unsafe fn()>,
    ) -> Option<*mut T> {
        let cell_key = core::ptr::from_ref(self) as usize;
        {
            let guard = NATIVE_TLS_HEAP_MAP.lock();
            let map_slot = unsafe { &*NATIVE_TLS_HEAP_MAP.value.get() };
            let _ = &guard;
            if let Some(map) = map_slot.as_ref()
                && let Some(&node_addr) = map.get(&(native_tid, cell_key))
            {
                let node = node_addr as *mut TlsHeapHeader;
                let payload = unsafe { (node.cast::<u8>()).add((*node).payload_offset) };
                return Some(payload.cast::<T>());
            }
        }
        let (node, payload_ptr) =
            self.alloc_node_and_payload(core::ptr::null(), zeroed, init, pre_free)?;
        let guard = NATIVE_TLS_HEAP_MAP.lock();
        let map_slot = unsafe { &mut *NATIVE_TLS_HEAP_MAP.value.get() };
        let _ = &guard;
        let map = map_slot.get_or_insert_with(HashMap::new);
        if let Some(&existing_addr) = map.get(&(native_tid, cell_key)) {
            drop(guard);
            unsafe { destroy_tls_heap_node(node) };
            let existing_node = existing_addr as *mut TlsHeapHeader;
            let payload =
                unsafe { (existing_node.cast::<u8>()).add((*existing_node).payload_offset) };
            return Some(payload.cast::<T>());
        }
        map.insert((native_tid, cell_key), node as usize);
        Some(payload_ptr)
    }
}

#[cfg(test)]
static TEST_ALLOC_BOUNDS: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn test_allocation_bound(addr: usize) -> Option<usize> {
    let guard = TEST_ALLOC_BOUNDS.lock().unwrap_or_else(|e| e.into_inner());
    guard.iter().find_map(|(base, len)| {
        let end = base.saturating_add(*len);
        (addr >= *base && addr < end).then_some(end - addr)
    })
}

#[cfg(test)]
mod tests {
    use super::{AbiReentrantMutex, AbiReentrantMutexGuard, TEST_ALLOC_BOUNDS, scan_c_string};
    use std::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    struct TestBoundGuard {
        base: usize,
        len: usize,
    }

    impl TestBoundGuard {
        fn new(bytes: &[u8]) -> Self {
            let base = bytes.as_ptr() as usize;
            let len = bytes.len();
            TEST_ALLOC_BOUNDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((base, len));
            Self { base, len }
        }
    }

    impl Drop for TestBoundGuard {
        fn drop(&mut self) {
            TEST_ALLOC_BOUNDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|entry| *entry != (self.base, self.len));
        }
    }

    #[test]
    fn scan_c_string_intersects_explicit_bound_with_tracked_allocation() {
        let bytes = *b"hello";
        let _guard = TestBoundGuard::new(&bytes);

        assert_eq!(
            unsafe { scan_c_string(bytes.as_ptr().cast::<std::ffi::c_char>(), Some(64)) },
            (5, false)
        );
    }

    #[test]
    fn scan_c_string_keeps_smaller_explicit_bound() {
        let bytes = *b"hello";
        let _guard = TestBoundGuard::new(&bytes);

        assert_eq!(
            unsafe { scan_c_string(bytes.as_ptr().cast::<std::ffi::c_char>(), Some(2)) },
            (2, false)
        );
    }

    #[test]
    fn abi_reentrant_mutex_allows_same_thread_recursion() {
        let lock = AbiReentrantMutex::new(Cell::new(0usize));
        let outer = lock.lock();
        outer.set(outer.get() + 1);

        {
            let inner = lock.lock();
            inner.set(inner.get() + 1);
        }

        assert_eq!(outer.get(), 2);
        drop(outer);
        assert_eq!(lock.lock().get(), 2);
    }

    #[test]
    fn abi_reentrant_mutex_try_lock_reports_same_thread_success() {
        let lock = AbiReentrantMutex::new(Cell::new(7usize));
        let _outer = lock.lock();
        let inner = lock
            .try_lock()
            .expect("same-thread recursive try_lock should succeed");
        assert_eq!(inner.get(), 7);
    }

    #[test]
    fn abi_reentrant_mutex_guard_is_neither_send_nor_sync() {
        // Inference is unambiguous only when the second impl does not apply.
        // Restoring either auto trait makes this test fail to compile, before
        // an unsound cross-thread access can execute. No extra dependency or
        // doctest visibility workaround is needed for these private types.
        macro_rules! assert_not_impl {
            ($ty:ty, $bound:path) => {{
                trait AmbiguousIfImpl<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                struct Implemented;
                impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
                let _ = <$ty as AmbiguousIfImpl<_>>::check;
            }};
        }

        assert_not_impl!(AbiReentrantMutexGuard<'static, usize>, Send);
        assert_not_impl!(AbiReentrantMutexGuard<'static, usize>, Sync);
        assert_not_impl!(AbiReentrantMutexGuard<'static, Cell<usize>>, Send);
        assert_not_impl!(AbiReentrantMutexGuard<'static, Cell<usize>>, Sync);

        // Only the acquisition is thread-bound: sharing the lock itself must
        // remain possible for Send-but-not-Sync protected values.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AbiReentrantMutex<Cell<usize>>>();
    }

    #[test]
    fn abi_reentrant_mutex_excludes_other_threads_until_final_guard_drop() {
        let lock = Arc::new(AbiReentrantMutex::new(Cell::new(7usize)));
        let outer = lock.lock();
        let inner = lock.try_lock().expect("recursive acquisition");

        let probe = Arc::clone(&lock);
        assert!(
            std::thread::spawn(move || probe.try_lock().is_none())
                .join()
                .expect("contending thread")
        );
        // Guards need not be dropped in acquisition order, but each one must
        // release exactly one level on the owner thread.
        drop(outer);
        inner.set(11);
        let probe = Arc::clone(&lock);
        assert!(
            std::thread::spawn(move || probe.try_lock().is_none())
                .join()
                .expect("contending thread")
        );
        drop(inner);

        let probe = Arc::clone(&lock);
        assert_eq!(
            std::thread::spawn(move || {
                let guard = probe.try_lock().expect("final drop releases lock");
                guard.get()
            })
            .join()
            .expect("next owner"),
            11
        );
    }

    #[test]
    fn abi_reentrant_mutex_serializes_recursive_cell_updates() {
        let lock = AbiReentrantMutex::new(Cell::new(0usize));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..250 {
                        let outer = lock.lock();
                        outer.set(outer.get() + 1);
                        let inner = lock.lock();
                        inner.set(inner.get() + 1);
                    }
                });
            }
        });
        assert_eq!(lock.lock().get(), 2000);
    }

    #[test]
    fn abi_reentrant_mutex_guard_adopt_transfers_ownership_and_unlocks_on_drop() {
        let lock = Arc::new(AbiReentrantMutex::new(Cell::new(42usize)));
        let mut guard = lock.lock();
        let parent_tid = guard.owner_tid;
        let synthetic_child_tid = parent_tid.wrapping_add(0x1000);

        // Simulate post-fork child TID transition before guard drop.
        unsafe { guard.adopt_for_tid(synthetic_child_tid) };
        assert_eq!(lock.owner_tid.load(Ordering::Acquire), synthetic_child_tid);
        assert_eq!(guard.owner_tid, synthetic_child_tid);

        drop(guard);
        assert_eq!(lock.owner_tid.load(Ordering::Acquire), 0);

        let probe = Arc::clone(&lock);
        assert_eq!(
            std::thread::spawn(move || probe.try_lock().map(|g| g.get()))
                .join()
                .expect("contender thread"),
            Some(42)
        );
    }

    #[test]
    fn tls_heap_cell_runs_drop_on_reclaim_and_allows_post_reclaim_reinit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DROPS: AtomicUsize = AtomicUsize::new(0);

        struct TrackedPayload(Vec<u8>);
        impl Drop for TrackedPayload {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        std::thread_local! {
            static TRACKED_TLS: super::TlsHeapCell<std::cell::RefCell<TrackedPayload>> =
                const { super::TlsHeapCell::new() };
            static ZEROED_TLS: super::TlsHeapCell<[u64; 8]> =
                const { super::TlsHeapCell::new() };
        }

        std::thread::spawn(|| {
            let before = DROPS.load(Ordering::SeqCst);
            TRACKED_TLS.with(|cell| {
                cell.with_init(
                    || std::cell::RefCell::new(TrackedPayload(vec![1, 2, 3, 4])),
                    |payload| {
                        assert_eq!(payload.borrow().0, vec![1, 2, 3, 4]);
                        payload.borrow_mut().0.push(5);
                    },
                );
            });
            ZEROED_TLS.with(|cell| {
                cell.with_zeroed(None, |arr| {
                    assert_eq!(*arr, [0u64; 8]);
                });
            });

            super::reclaim_current_thread_tls_heap_cells();
            assert_eq!(DROPS.load(Ordering::SeqCst), before + 1);

            // Simulate late access after reclamation: must lazily re-allocate cleanly without UAF.
            TRACKED_TLS.with(|cell| {
                cell.with_init(
                    || std::cell::RefCell::new(TrackedPayload(vec![9, 9])),
                    |payload| {
                        assert_eq!(payload.borrow().0, vec![9, 9]);
                    },
                );
            });
            super::reclaim_current_thread_tls_heap_cells();
            assert_eq!(DROPS.load(Ordering::SeqCst), before + 2);
        })
        .join()
        .expect("worker thread");
    }
}
