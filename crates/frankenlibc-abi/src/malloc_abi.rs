//! ABI layer for memory allocation functions (`malloc`, `free`, `calloc`, `realloc`).
//!
//! These functions integrate with the membrane's generational arena for temporal safety.
//! All allocations are tracked with fingerprint headers and canaries for buffer overflow
//! detection. Double-free and use-after-free are caught via generation counters and
//! quarantine queues.
//!
//! In test mode, this module is suppressed to avoid shadowing the system allocator
//! (which would cause infinite recursion in the test binary itself).

use std::cell::UnsafeCell;
use std::ffi::{c_int, c_void};
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};

use frankenlibc_core::errno::{EINVAL, ENOMEM};
use frankenlibc_membrane::MEMBRANE_SCHEMA_VERSION;
use frankenlibc_membrane::arena::{AllocationArena, FreeResult};
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::fingerprint::{AllocationFingerprint, CANARY_SIZE, FINGERPRINT_SIZE};
use frankenlibc_membrane::galois::PointerAbstraction;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::lattice::SafetyState;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};
use frankenlibc_membrane::util::now_utc_iso_like;

use crate::errno_abi::set_abi_errno;
use crate::htm_fast_path::HtmSite;
use crate::runtime_policy;
use crate::signal_abi::{SignalCriticalSectionKind, enter_signal_critical_section};
use frankenlibc_core::syscall as raw_syscall;

type HostMallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
type HostCallocFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;
type HostReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
type HostFreeFn = unsafe extern "C" fn(*mut c_void);
type HostMemalignFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;

static HOST_MALLOC_FN: OnceLock<usize> = OnceLock::new();
static HOST_CALLOC_FN: OnceLock<usize> = OnceLock::new();
static HOST_REALLOC_FN: OnceLock<usize> = OnceLock::new();
static HOST_FREE_FN: OnceLock<usize> = OnceLock::new();
static HOST_MEMALIGN_FN: OnceLock<usize> = OnceLock::new();
static HOST_ALLOCATOR_RAW_FALLBACK_HITS: AtomicU64 = AtomicU64::new(0);
static HOST_ALLOCATOR_DLVSYM_FALLBACK_HITS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAllocatorResolutionMetrics {
    pub raw_host_fallback_hits: u64,
    pub direct_dlvsym_fallback_hits: u64,
}

// ---------------------------------------------------------------------------
// Pre-TLS bootstrap bump allocator
// ---------------------------------------------------------------------------
// During early process startup, TLS is not initialized and the TLS-based
// reentry guard in `malloc` returns None. The host allocator path therefore
// must bypass our interposed exports and resolve the next libc implementation
// directly. When that resolution is unavailable or re-enters during bootstrap,
// we fall back to a small bump allocator to break recursive startup cycles.
//
// The bump allocator breaks this cycle.  When the atomic reentry guard
// detects recursion, we satisfy the allocation from a small static buffer.
// This is sufficient for the handful of allocations during startup (Rust
// runtime init, format strings in mode/policy setup) before TLS becomes
// available and the normal allocator path takes over.

// Recursion guards for the host allocator trampolines. This path must not use
// Rust TLS or OwnedTlsCache: both can touch allocator/bootstrap machinery before
// malloc is safe. A process-global AtomicBool previously caused cross-thread
// false positives (bd-wbqeo), so this table is keyed by raw kernel TID and uses
// only atomics plus the gettid syscall. If a slot cannot be acquired, callers
// keep the existing fail-closed behavior and use the bump fallback.
const ALLOCATOR_REENTRY_SLOT_COUNT: usize = 4096;
const ALLOCATOR_REENTRY_SLOT_MASK: usize = ALLOCATOR_REENTRY_SLOT_COUNT - 1;
const ALLOCATOR_REENTRY_SLOT_PROBE_LIMIT: usize = 64;
#[allow(dead_code)]
const NATIVE_REENTRY_MALLOC: u8 = 1 << 0;
#[allow(dead_code)]
const NATIVE_REENTRY_CALLOC: u8 = 1 << 1;
#[allow(dead_code)]
const NATIVE_REENTRY_REALLOC: u8 = 1 << 2;
#[allow(dead_code)]
const NATIVE_REENTRY_FREE: u8 = 1 << 3;
#[allow(dead_code)]
const NATIVE_REENTRY_MEMALIGN: u8 = 1 << 4;

struct AllocatorReentrySlot {
    tid: AtomicI32,
    thread_key: AtomicUsize,
    native_guard_bits: AtomicU8,
    allocator_depth: AtomicU32,
    fallback_cache_index: AtomicUsize,
}

impl AllocatorReentrySlot {
    const fn new() -> Self {
        Self {
            tid: AtomicI32::new(0),
            thread_key: AtomicUsize::new(0),
            native_guard_bits: AtomicU8::new(0),
            allocator_depth: AtomicU32::new(0),
            fallback_cache_index: AtomicUsize::new(usize::MAX),
        }
    }
}

static ALLOCATOR_REENTRY_SLOTS: [AllocatorReentrySlot; ALLOCATOR_REENTRY_SLOT_COUNT] =
    [const { AllocatorReentrySlot::new() }; ALLOCATOR_REENTRY_SLOT_COUNT];

// Global last-thread cache to eliminate gettid syscalls for single-threaded programs.
// Stores (tid << 32) | slot_index. Zero means "cache empty".
//
// SAFETY: For single-threaded programs (like Python startup), this provides O(1) lookup
// with zero syscalls after the first allocation. The syscall-free fast path keys on the
// glibc TCB self pointer alone, which is conclusive only while the process is
// single-threaded; once `MULTI_THREADED` latches, the fast path is bypassed and the live
// kernel tid is verified instead (see `current_allocator_reentry_slot`).
static LAST_THREAD_CACHE: AtomicU64 = AtomicU64::new(0);

// Soundness latch for the syscall-free fast path (bd-35hjg.3.1).
//
// `current_allocator_reentry_slot`'s fast path accepts a cached slot purely on a glibc
// TCB self-pointer match (`current_thread_key`). That is conclusive only while the
// process has never had more than one thread: the kernel can only recycle a tid, and
// glibc can only recycle a TCB address, *after* the owning thread has exited, so a
// single-threaded process can never alias one thread's reentry slot onto another. Once a
// second thread is seen, a freshly created thread can inherit an exited thread's recycled
// TCB address (matching the cached slot by key) while the kernel independently recycles
// the exited thread's tid for a third thread. The fast path must then fall back to
// verifying the kernel tid, which is unique among concurrently live threads.
//
// `MULTI_THREADED` is a one-way latch: set the first time two distinct tids reach the
// slot machinery and never cleared. `FIRST_OBSERVED_TID` records the first tid seen.
static MULTI_THREADED: AtomicBool = AtomicBool::new(false);
static FIRST_OBSERVED_TID: AtomicI32 = AtomicI32::new(0);

/// Reports whether `tid` is the second distinct tid recorded in `first`, which proves the
/// process is (or has been) multi-threaded. The first non-zero tid is stored; a later
/// different tid returns `true`. Non-positive tids are ignored.
#[inline]
fn observe_distinct_tid(first: &AtomicI32, tid: i32) -> bool {
    if tid <= 0 {
        return false;
    }
    match first.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => false,
        Err(previous) => previous != tid,
    }
}

/// Latches `MULTI_THREADED` once a second distinct tid reaches the reentry-slot
/// machinery, after which kernel tids and glibc TCB addresses may have been recycled and
/// the thread-key-only fast path is no longer sound on its own.
#[inline]
fn note_thread_tid(tid: i32) {
    if observe_distinct_tid(&FIRST_OBSERVED_TID, tid) {
        MULTI_THREADED.store(true, Ordering::SeqCst);
    }
}

#[inline]
fn allocator_reentry_slot_start(tid: i32) -> usize {
    (tid as usize).wrapping_mul(0x9e37_79b1_85eb_ca87) & ALLOCATOR_REENTRY_SLOT_MASK
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn current_thread_key() -> Option<usize> {
    let key: usize;
    unsafe {
        // SAFETY: reading fs:0 is a register-relative load of the Linux x86_64
        // thread-control-block self pointer. It does not call into libc or touch
        // allocator/TLS initialization machinery.
        core::arch::asm!(
            "mov {}, qword ptr fs:[0]",
            lateout(reg) key,
            options(nostack, preserves_flags, readonly)
        );
    }
    (key != 0).then_some(key)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn current_thread_key() -> Option<usize> {
    let key: usize;
    unsafe {
        // SAFETY: tpidr_el0 is the userspace thread-pointer register on Linux
        // aarch64. Reading it is side-effect free and does not invoke libc.
        core::arch::asm!(
            "mrs {out}, tpidr_el0",
            out = lateout(reg) key,
            options(nostack, preserves_flags, readonly)
        );
    }
    (key != 0).then_some(key)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn current_thread_key() -> Option<usize> {
    None
}

#[inline]
fn slot_matches_thread_key(slot: &AllocatorReentrySlot, thread_key: Option<usize>) -> bool {
    let Some(thread_key) = thread_key else {
        return false;
    };
    thread_key != 0 && slot.thread_key.load(Ordering::Acquire) == thread_key
}

#[inline]
fn bind_slot_to_thread_key(slot: &AllocatorReentrySlot, thread_key: Option<usize>) {
    let Some(thread_key) = thread_key else {
        return;
    };
    if thread_key == 0 {
        return;
    }
    let previous = slot.thread_key.swap(thread_key, Ordering::AcqRel);
    if previous != 0 && previous != thread_key {
        slot.native_guard_bits.store(0, Ordering::Release);
        slot.allocator_depth.store(0, Ordering::Release);
        slot.fallback_cache_index
            .store(usize::MAX, Ordering::Release);
    }
}

fn allocator_reentry_slot_for_tid(
    tid: i32,
    thread_key: Option<usize>,
) -> Option<&'static AllocatorReentrySlot> {
    if tid <= 0 {
        return None;
    }
    let start = allocator_reentry_slot_start(tid);
    for offset in 0..ALLOCATOR_REENTRY_SLOT_PROBE_LIMIT {
        let slot = &ALLOCATOR_REENTRY_SLOTS[(start + offset) & ALLOCATOR_REENTRY_SLOT_MASK];
        let observed = slot.tid.load(Ordering::Acquire);
        if observed == tid {
            bind_slot_to_thread_key(slot, thread_key);
            return Some(slot);
        }
        if observed == 0 {
            match slot
                .tid
                .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    bind_slot_to_thread_key(slot, thread_key);
                    return Some(slot);
                }
                Err(actual) if actual == tid => {
                    bind_slot_to_thread_key(slot, thread_key);
                    return Some(slot);
                }
                Err(_) => {}
            }
        }
    }
    None
}

/// Get the reentry slot for the current thread. Uses a global last-thread cache
/// to eliminate gettid syscalls for single-threaded programs.
///
/// Fast path (no syscall): while the process is single-threaded, a cached slot whose
/// stored glibc TCB self pointer matches this thread is returned directly. Tids and TCB
/// addresses cannot have been recycled with only one thread, so the key match is
/// conclusive.
///
/// Slow path (one syscall): on a cache miss, a key mismatch, or once the process has gone
/// multi-threaded (`MULTI_THREADED`), do gettid, probe for the slot keyed by the kernel
/// tid, and update the cache. The kernel tid is unique among concurrently live threads,
/// so it disambiguates threads that share a recycled TCB address (bd-35hjg.3.1).
///
/// This reduces gettid syscalls from O(allocations) to O(1) for single-threaded programs,
/// fixing the ~650x Python startup regression (bd-35hjg).
#[inline]
fn current_allocator_reentry_slot() -> Option<&'static AllocatorReentrySlot> {
    let thread_key = current_thread_key();

    // Fast path: check last-thread cache WITHOUT syscall. The cached slot is accepted
    // only when its no-syscall thread key matches the current thread AND the process is
    // still single-threaded. Once `MULTI_THREADED` latches, a recycled glibc TCB can give
    // a freshly created thread the same key as an exited thread, so a key match alone is
    // no longer sound and we fall through to verify the live kernel tid (bd-35hjg.3.1).
    let cached = LAST_THREAD_CACHE.load(Ordering::Relaxed);
    if cached != 0 {
        let cached_slot_idx = (cached & 0xFFFF_FFFF) as usize;
        if cached_slot_idx < ALLOCATOR_REENTRY_SLOT_COUNT {
            let slot = &ALLOCATOR_REENTRY_SLOTS[cached_slot_idx];
            if slot_matches_thread_key(slot, thread_key) && !MULTI_THREADED.load(Ordering::Relaxed)
            {
                return Some(slot);
            }
        }
    }

    // Slow path: need to determine actual TID via syscall
    let tid = raw_syscall::sys_gettid();
    if tid <= 0 {
        return None;
    }

    // Record this tid so a second distinct thread latches `MULTI_THREADED` and disables
    // the syscall-free fast path before tid/TCB recycling can alias slots.
    note_thread_tid(tid);

    // Look up or create slot for this TID
    let slot = allocator_reentry_slot_for_tid(tid, thread_key)?;

    // Update global cache for next fast-path lookup
    let slot_idx = (slot as *const _ as usize - ALLOCATOR_REENTRY_SLOTS.as_ptr() as usize)
        / std::mem::size_of::<AllocatorReentrySlot>();
    let packed = ((tid as u64) << 32) | (slot_idx as u64);
    LAST_THREAD_CACHE.store(packed, Ordering::Relaxed);

    Some(slot)
}

#[allow(dead_code)]
struct NativeAllocatorReentryGuard {
    slot: &'static AllocatorReentrySlot,
    mask: u8,
}

impl Drop for NativeAllocatorReentryGuard {
    fn drop(&mut self) {
        self.slot
            .native_guard_bits
            .fetch_and(!self.mask, Ordering::AcqRel);
    }
}

#[inline]
#[allow(dead_code)]
fn enter_native_reentry_guard(mask: u8) -> Option<NativeAllocatorReentryGuard> {
    let slot = current_allocator_reentry_slot()?;
    enter_native_reentry_guard_for_slot(slot, mask)
}

#[inline]
#[allow(dead_code)]
fn enter_native_reentry_guard_for_slot(
    slot: &'static AllocatorReentrySlot,
    mask: u8,
) -> Option<NativeAllocatorReentryGuard> {
    let previous = slot.native_guard_bits.fetch_or(mask, Ordering::AcqRel);
    if previous & mask == 0 {
        Some(NativeAllocatorReentryGuard { slot, mask })
    } else {
        None
    }
}

static BUMP_POS: AtomicUsize = AtomicUsize::new(0);
const BUMP_SIZE: usize = 256 * 1024 * 1024; // 256 MiB to cover strict preload startup.
const BUMP_ALIGN: usize = 16;
const BUMP_HEADER_WORDS: usize = 2;
const BUMP_HEADER_SIZE: usize = std::mem::size_of::<usize>() * BUMP_HEADER_WORDS;
const BUMP_MAGIC: usize = 0x4652_414E_4B42_554D;

/// Bump heap uses `UnsafeCell` to avoid mutable-static references
/// (forbidden in Rust 2024 edition).  Access is synchronized via
/// `BUMP_POS` atomic CAS — only one thread can advance the position.
#[repr(align(16))]
struct BumpHeap(std::cell::UnsafeCell<[u8; BUMP_SIZE]>);
// SAFETY: concurrent access is serialized by BUMP_POS atomic CAS.
unsafe impl Sync for BumpHeap {}
static BUMP_HEAP: BumpHeap = BumpHeap(std::cell::UnsafeCell::new([0u8; BUMP_SIZE]));

/// Raw allocator for internal ABI use.
///
/// Uses the native host-resolution path with the same bump fallback and
/// reentry protection as the public allocator entrypoints.
pub(crate) unsafe fn raw_alloc(size: usize) -> *mut c_void {
    let ptr = unsafe { native_libc_malloc(size) };
    fallback_insert_sized(ptr, size.max(1));
    ptr
}

/// Raw free for internally-allocated memory.
///
/// Uses the native host-resolution free path so internal allocations stay on
/// the same ownership model as `raw_alloc`.
pub(crate) unsafe fn raw_free(ptr: *mut c_void) {
    let _ = fallback_remove(ptr);
    unsafe { native_libc_free(ptr) }
}

/// Host allocator passthrough for ABI internals that must preserve libc heap ownership.
pub(crate) unsafe fn host_passthrough_malloc(size: usize) -> *mut c_void {
    unsafe { native_libc_malloc(size) }
}

/// Host realloc passthrough for ABI internals that must preserve libc heap ownership.
pub(crate) unsafe fn host_passthrough_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { native_libc_realloc(ptr, size) }
}

/// Host free passthrough for ABI internals that must preserve libc heap ownership.
pub(crate) unsafe fn host_passthrough_free(ptr: *mut c_void) {
    unsafe { native_libc_free(ptr) }
}

#[cold]
unsafe fn bump_alloc(size: usize) -> *mut c_void {
    let request = size.max(1);
    let total = BUMP_HEADER_SIZE.saturating_add(request);
    loop {
        let pos = BUMP_POS.load(Ordering::Relaxed);
        let aligned_pos = (pos + BUMP_ALIGN - 1) & !(BUMP_ALIGN - 1);
        let new_pos = aligned_pos.saturating_add(total);
        if new_pos > BUMP_SIZE {
            // Static bump heap exhausted — fall back to mmap.
            return unsafe { mmap_alloc(total) };
        }
        if BUMP_POS
            .compare_exchange_weak(pos, new_pos, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let base = BUMP_HEAP.0.get().cast::<u8>();
            // SAFETY: aligned_pos..new_pos is reserved for this allocation.
            unsafe {
                let header = base.add(aligned_pos).cast::<usize>();
                header.write(BUMP_MAGIC);
                header.add(1).write(request);
                return header.add(BUMP_HEADER_WORDS).cast();
            }
        }
    }
}

#[cold]
unsafe fn bump_alloc_aligned(size: usize, alignment: usize) -> *mut c_void {
    let request = size.max(1);
    let alignment = alignment.max(BUMP_ALIGN).next_power_of_two();
    let total = request
        .saturating_add(alignment)
        .saturating_add(BUMP_HEADER_SIZE);
    loop {
        let pos = BUMP_POS.load(Ordering::Relaxed);
        let aligned_pos = (pos + BUMP_ALIGN - 1) & !(BUMP_ALIGN - 1);
        let new_pos = aligned_pos.saturating_add(total);
        if new_pos > BUMP_SIZE {
            return std::ptr::null_mut();
        }
        if BUMP_POS
            .compare_exchange_weak(pos, new_pos, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let base = BUMP_HEAP.0.get().cast::<u8>();
            // SAFETY: aligned_pos..new_pos is reserved for this allocation.
            // The header is written immediately before the aligned user
            // pointer so the existing bump metadata lookup still works.
            unsafe {
                let reservation = base.add(aligned_pos) as usize;
                let user_addr = (reservation + BUMP_HEADER_SIZE + alignment - 1) & !(alignment - 1);
                let header = (user_addr - BUMP_HEADER_SIZE) as *mut usize;
                header.write(BUMP_MAGIC);
                header.add(1).write(request);
                return user_addr as *mut c_void;
            }
        }
    }
}

/// Fallback allocator using raw mmap syscall.  Used when the static bump
/// heap is exhausted.  No symbol resolution or libc calls — pure syscall.
#[cold]
unsafe fn mmap_alloc(size: usize) -> *mut c_void {
    // Hard-coded 4096: this runs during early bootstrap before sysconf is
    // available.  4096 is the minimum page size on all Linux architectures,
    // so rounding up to it is always safe (just potentially wastes alignment
    // headroom on 16K/64K page systems).
    let page_size = 4096usize;
    let alloc_size = (size + page_size - 1) & !(page_size - 1);
    let result = unsafe {
        raw_syscall::sys_mmap(
            std::ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    match result {
        Ok(ptr) => ptr as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

#[inline]
fn is_bump_ptr(ptr: *mut c_void) -> bool {
    let addr = ptr as usize;
    let base = BUMP_HEAP.0.get() as usize;
    if addr < base + BUMP_HEADER_SIZE || addr >= base + BUMP_SIZE {
        return false;
    }
    // Verify magic sentinel to prevent false positives if a host pointer
    // happens to fall in the bump heap address range.
    let header = unsafe { (ptr as *mut u8).sub(BUMP_HEADER_SIZE).cast::<usize>() };
    let magic = unsafe { header.read() };
    magic == BUMP_MAGIC
}

#[inline]
unsafe fn bump_allocation_size(ptr: *mut c_void) -> Option<usize> {
    if !is_bump_ptr(ptr) {
        return None;
    }
    // SAFETY: bump allocations reserve a fixed-size header immediately before
    // the user pointer.
    let header = unsafe { (ptr as *mut u8).sub(BUMP_HEADER_SIZE).cast::<usize>() };
    // SAFETY: header points into the bump heap allocation record.
    let magic = unsafe { header.read() };
    if magic != BUMP_MAGIC {
        return None;
    }
    // SAFETY: second header word stores the requested user size.
    Some(unsafe { header.add(1).read() })
}

#[inline]
unsafe fn resolve_host_allocator_symbol(name: &'static [u8]) -> *mut c_void {
    let symbol = name.strip_suffix(b"\0").unwrap_or(name);
    let Ok(symbol) = core::str::from_utf8(symbol) else {
        return std::ptr::null_mut();
    };
    crate::host_resolve::resolve_host_symbol_raw(symbol)
        .map(|addr| addr as *mut c_void)
        .unwrap_or_default()
}

/// Safe accessor: returns cached host fn or None (bump fallback).
/// Does NOT call get_or_init — that deadlocks during _dl_init.
macro_rules! host_fn_accessor {
    ($name:ident, $lock:ident, $ty:ty) => {
        #[allow(dead_code)]
        #[inline]
        unsafe fn $name() -> Option<$ty> {
            if let Some(&ptr) = $lock.get() {
                if ptr != 0 {
                    return Some(unsafe { std::mem::transmute::<usize, $ty>(ptr) });
                }
            }
            None
        }
    };
}

host_fn_accessor!(host_malloc_fn, HOST_MALLOC_FN, HostMallocFn);
host_fn_accessor!(host_calloc_fn, HOST_CALLOC_FN, HostCallocFn);
host_fn_accessor!(host_realloc_fn, HOST_REALLOC_FN, HostReallocFn);
host_fn_accessor!(host_free_fn, HOST_FREE_FN, HostFreeFn);
host_fn_accessor!(host_memalign_fn, HOST_MEMALIGN_FN, HostMemalignFn);

/// Resolve and cache host allocator symbols.
/// Called from __libc_start_main AFTER _dl_init, when dlvsym is safe.
pub(crate) fn prewarm_host_allocator_symbols() {
    crate::host_resolve::bootstrap_host_symbols();
    // SAFETY: called after dynamic linker init; dlvsym_next is safe.
    unsafe {
        let malloc_ptr = crate::host_resolve::host_malloc_raw()
            .map(|host_fn| host_fn as usize)
            .unwrap_or_else(|| resolve_host_allocator_symbol(b"malloc\0") as usize);
        let calloc_ptr = crate::host_resolve::host_calloc_raw()
            .map(|host_fn| host_fn as usize)
            .unwrap_or_else(|| resolve_host_allocator_symbol(b"calloc\0") as usize);
        let realloc_ptr = crate::host_resolve::host_realloc_raw()
            .map(|host_fn| host_fn as usize)
            .unwrap_or_else(|| resolve_host_allocator_symbol(b"realloc\0") as usize);
        let free_ptr = crate::host_resolve::host_free_raw()
            .map(|host_fn| host_fn as usize)
            .unwrap_or_else(|| resolve_host_allocator_symbol(b"free\0") as usize);
        let memalign_ptr = resolve_host_allocator_symbol(b"memalign\0") as usize;

        let _ = HOST_MALLOC_FN.get_or_init(|| malloc_ptr);
        let _ = HOST_CALLOC_FN.get_or_init(|| calloc_ptr);
        let _ = HOST_REALLOC_FN.get_or_init(|| realloc_ptr);
        let _ = HOST_FREE_FN.get_or_init(|| free_ptr);
        let _ = HOST_MEMALIGN_FN.get_or_init(|| memalign_ptr);
    }
    let _ = GLOBAL_ALLOC_STATS.get_or_init(FlatCombiningStats::new);
}

#[doc(hidden)]
pub fn prewarm_host_allocator_symbols_for_test() {
    prewarm_host_allocator_symbols();
}

#[doc(hidden)]
pub fn host_allocator_symbols_prewarmed_for_test() -> bool {
    let Some(&malloc_ptr) = HOST_MALLOC_FN.get() else {
        return false;
    };
    let Some(&calloc_ptr) = HOST_CALLOC_FN.get() else {
        return false;
    };
    let Some(&realloc_ptr) = HOST_REALLOC_FN.get() else {
        return false;
    };
    let Some(&free_ptr) = HOST_FREE_FN.get() else {
        return false;
    };
    malloc_ptr != 0 && calloc_ptr != 0 && realloc_ptr != 0 && free_ptr != 0
}

#[doc(hidden)]
pub fn reset_host_allocator_resolution_metrics_for_test() {
    HOST_ALLOCATOR_RAW_FALLBACK_HITS.store(0, Ordering::Relaxed);
    HOST_ALLOCATOR_DLVSYM_FALLBACK_HITS.store(0, Ordering::Relaxed);
}

#[doc(hidden)]
pub fn host_allocator_resolution_metrics_for_test() -> HostAllocatorResolutionMetrics {
    HostAllocatorResolutionMetrics {
        raw_host_fallback_hits: HOST_ALLOCATOR_RAW_FALLBACK_HITS.load(Ordering::Relaxed),
        direct_dlvsym_fallback_hits: HOST_ALLOCATOR_DLVSYM_FALLBACK_HITS.load(Ordering::Relaxed),
    }
}

#[doc(hidden)]
pub fn malloc_stats_init_for_tests() {
    let _ = GLOBAL_ALLOC_STATS.get_or_init(FlatCombiningStats::new);
}

#[doc(hidden)]
pub fn malloc_stats_reset_for_harness() {
    let stats = GLOBAL_ALLOC_STATS.get_or_init(FlatCombiningStats::new);
    stats.reset();
}

#[doc(hidden)]
pub fn malloc_stats_record_alloc_for_harness(size: usize) {
    let _ = GLOBAL_ALLOC_STATS.get_or_init(FlatCombiningStats::new);
    record_alloc_stats(size);
}

#[doc(hidden)]
pub fn malloc_stats_record_free_for_harness(size: usize) {
    let _ = GLOBAL_ALLOC_STATS.get_or_init(FlatCombiningStats::new);
    record_free_stats(size);
}

#[doc(hidden)]
pub fn malloc_htm_reset_for_tests() {
    MALLOC_STATS_HTM_SITE.reset_for_tests();
}

#[doc(hidden)]
#[must_use]
pub fn malloc_htm_snapshot_for_tests() -> crate::htm_fast_path::HtmSiteSnapshot {
    MALLOC_STATS_HTM_SITE.snapshot()
}

#[inline]
#[allow(clippy::needless_return)]
unsafe fn native_libc_malloc(size: usize) -> *mut c_void {
    // In standalone mode, use bump allocator directly (no host glibc)
    #[cfg(feature = "standalone")]
    {
        return unsafe { bump_alloc(size) };
    }
    #[cfg(not(feature = "standalone"))]
    {
        let Some(_reentry_guard) = enter_native_reentry_guard(NATIVE_REENTRY_MALLOC) else {
            return unsafe { bump_alloc(size) };
        };
        let ptr = if let Some(&ptr) = HOST_MALLOC_FN.get() {
            ptr
        } else if let Some(raw_host_malloc) = crate::host_resolve::host_malloc_raw() {
            HOST_ALLOCATOR_RAW_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            raw_host_malloc as usize
        } else {
            HOST_ALLOCATOR_DLVSYM_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            let resolved = unsafe { resolve_host_allocator_symbol(b"malloc\0") as usize };
            let _ = HOST_MALLOC_FN.set(resolved);
            resolved
        };
        if ptr != 0 {
            let f: HostMallocFn = unsafe { std::mem::transmute(ptr) }; // ubs:ignore - host malloc symbol is resolved as this exact ABI fn pointer.
            unsafe { f(size) }
        } else {
            unsafe { bump_alloc(size) }
        }
    }
}

#[inline]
#[allow(clippy::needless_return)]
unsafe fn native_libc_calloc(nmemb: usize, size: usize) -> *mut c_void {
    // In standalone mode, use bump allocator directly (no host glibc)
    #[cfg(feature = "standalone")]
    {
        let Some(total) = nmemb.checked_mul(size) else {
            return std::ptr::null_mut();
        };
        return unsafe { bump_alloc(total) };
    }
    #[cfg(not(feature = "standalone"))]
    {
        let Some(slot) = current_allocator_reentry_slot() else {
            let Some(total) = nmemb.checked_mul(size) else {
                return std::ptr::null_mut();
            };
            // bump_alloc returns zeroed memory (static initializer).
            return unsafe { bump_alloc(total) };
        };
        unsafe { native_libc_calloc_with_slot(slot, nmemb, size) }
    }
}

#[inline]
#[allow(clippy::needless_return)]
unsafe fn native_libc_calloc_with_slot(
    slot: &'static AllocatorReentrySlot,
    nmemb: usize,
    size: usize,
) -> *mut c_void {
    // In standalone mode, use bump allocator directly (no host glibc)
    #[cfg(feature = "standalone")]
    {
        let Some(total) = nmemb.checked_mul(size) else {
            return std::ptr::null_mut();
        };
        return unsafe { bump_alloc(total) };
    }
    #[cfg(not(feature = "standalone"))]
    {
        let Some(_reentry_guard) = enter_native_reentry_guard_for_slot(slot, NATIVE_REENTRY_CALLOC)
        else {
            let Some(total) = nmemb.checked_mul(size) else {
                return std::ptr::null_mut();
            };
            // bump_alloc returns zeroed memory (static initializer).
            return unsafe { bump_alloc(total) };
        };
        let ptr = if let Some(&ptr) = HOST_CALLOC_FN.get() {
            ptr
        } else if let Some(raw_host_calloc) = crate::host_resolve::host_calloc_raw() {
            HOST_ALLOCATOR_RAW_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            raw_host_calloc as usize
        } else {
            HOST_ALLOCATOR_DLVSYM_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            let resolved = unsafe { resolve_host_allocator_symbol(b"calloc\0") as usize };
            let _ = HOST_CALLOC_FN.set(resolved);
            resolved
        };
        if ptr != 0 {
            let host_calloc: HostCallocFn = unsafe { std::mem::transmute(ptr) }; // ubs:ignore - host calloc symbol is resolved as this exact ABI fn pointer.
            unsafe { host_calloc(nmemb, size) }
        } else {
            let total = nmemb.checked_mul(size).unwrap_or(0);
            if total == 0 && nmemb != 0 && size != 0 {
                // Overflow: return null
                std::ptr::null_mut()
            } else {
                unsafe { bump_alloc(total) }
            }
        }
    }
}

#[inline]
#[allow(clippy::needless_return)]
unsafe fn native_libc_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { native_libc_malloc(size) };
    }
    if let Some(old_size) = unsafe { bump_allocation_size(ptr) } {
        let out = unsafe { native_libc_malloc(size) };
        if !out.is_null() {
            let copy_size = old_size.min(size);
            unsafe {
                std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), out.cast::<u8>(), copy_size);
            }
        }
        return out;
    }
    // In standalone mode, all allocations are from bump allocator
    #[cfg(feature = "standalone")]
    {
        return unsafe { bump_alloc(size) };
    }
    #[cfg(not(feature = "standalone"))]
    {
        let Some(_reentry_guard) = enter_native_reentry_guard(NATIVE_REENTRY_REALLOC) else {
            return unsafe { bump_alloc(size) };
        };
        let host_ptr = if let Some(&host_ptr) = HOST_REALLOC_FN.get() {
            host_ptr
        } else if let Some(raw_host_realloc) = crate::host_resolve::host_realloc_raw() {
            HOST_ALLOCATOR_RAW_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            raw_host_realloc as usize
        } else {
            HOST_ALLOCATOR_DLVSYM_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            let resolved = unsafe { resolve_host_allocator_symbol(b"realloc\0") as usize };
            let _ = HOST_REALLOC_FN.set(resolved);
            resolved
        };
        if host_ptr != 0 {
            let host_realloc: HostReallocFn = unsafe { std::mem::transmute(host_ptr) }; // ubs:ignore - host realloc symbol is resolved as this exact ABI fn pointer.
            unsafe { host_realloc(ptr, size) }
        } else if let Some(old_size) = unsafe { bump_allocation_size(ptr) } {
            let out = unsafe { bump_alloc(size) };
            if !out.is_null() {
                let copy_size = old_size.min(size);
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), out.cast::<u8>(), copy_size);
                }
            }
            out
        } else {
            unsafe { bump_alloc(size) }
        }
    }
}

#[inline]
#[allow(clippy::needless_return)]
unsafe fn native_libc_free(ptr: *mut c_void) {
    if is_bump_ptr(ptr) {
        return; // Bump allocator: free is a no-op.
    }
    // In standalone mode, free is a no-op (bump allocator doesn't support freeing)
    #[cfg(feature = "standalone")]
    {
        return;
    }
    #[cfg(not(feature = "standalone"))]
    {
        let Some(slot) = current_allocator_reentry_slot() else {
            return; // Reentrant free of non-bump ptr: no-op to avoid recursion.
        };
        unsafe { native_libc_free_with_slot(slot, ptr) };
    }
}

#[inline]
#[allow(clippy::needless_return)]
unsafe fn native_libc_free_with_slot(slot: &'static AllocatorReentrySlot, ptr: *mut c_void) {
    if is_bump_ptr(ptr) {
        return; // Bump allocator: free is a no-op.
    }
    // In standalone mode, free is a no-op (bump allocator doesn't support freeing)
    #[cfg(feature = "standalone")]
    {
        return;
    }
    #[cfg(not(feature = "standalone"))]
    {
        let Some(_reentry_guard) = enter_native_reentry_guard_for_slot(slot, NATIVE_REENTRY_FREE)
        else {
            return; // Reentrant free of non-bump ptr: no-op to avoid recursion.
        };
        let host_ptr = if let Some(&host_ptr) = HOST_FREE_FN.get() {
            host_ptr
        } else if let Some(raw_host_free) = crate::host_resolve::host_free_raw() {
            HOST_ALLOCATOR_RAW_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            raw_host_free as usize
        } else {
            HOST_ALLOCATOR_DLVSYM_FALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
            let resolved = unsafe { resolve_host_allocator_symbol(b"free\0") as usize };
            let _ = HOST_FREE_FN.set(resolved);
            resolved
        };
        if host_ptr != 0 {
            let host_free: HostFreeFn = unsafe { std::mem::transmute(host_ptr) }; // ubs:ignore - host free symbol is resolved as this exact ABI fn pointer.
            unsafe { host_free(ptr) };
        }
    }
}

/// Bench-only probe: the bare host (main-namespace, real glibc) `calloc` that
/// the deployed `calloc` delegates to in strict mode, with NO membrane
/// bookkeeping (no fallback-table insert, no stats, no decide/observe). Lets a
/// head-to-head bench separate the membrane's own per-call cost from the cost of
/// the host allocator operating on the busy main-namespace heap. Diagnostic for
/// bd-f874go; do not use outside benches.
#[doc(hidden)]
#[must_use]
pub unsafe fn native_calloc_probe_for_bench(nmemb: usize, size: usize) -> *mut c_void {
    unsafe { native_libc_calloc(nmemb, size) }
}

/// Bench-only probe: bare host (main-namespace) `free`. See
/// [`native_calloc_probe_for_bench`].
#[doc(hidden)]
pub unsafe fn native_free_probe_for_bench(ptr: *mut c_void) {
    unsafe { native_libc_free(ptr) };
}

#[inline]
unsafe fn native_libc_posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    if memptr.is_null()
        || !alignment.is_power_of_two()
        || !alignment.is_multiple_of(std::mem::size_of::<usize>())
    {
        return EINVAL as c_int;
    }
    let req = size.max(1);
    // SAFETY: direct call to libc allocator symbol.
    let ptr = unsafe { native_libc_memalign(alignment, req) };
    if ptr.is_null() {
        return ENOMEM as c_int;
    }
    fallback_insert_sized(ptr, req);
    // SAFETY: memptr non-null and caller-provided writable out pointer.
    unsafe { *memptr = ptr };
    0
}

#[inline]
#[allow(clippy::needless_return)]
unsafe fn native_libc_memalign(alignment: usize, size: usize) -> *mut c_void {
    // In standalone mode, use bump allocator directly
    #[cfg(feature = "standalone")]
    {
        return unsafe { bump_alloc_aligned(size, alignment) };
    }
    #[cfg(not(feature = "standalone"))]
    {
        let Some(_reentry_guard) = enter_native_reentry_guard(NATIVE_REENTRY_MEMALIGN) else {
            return unsafe { bump_alloc_aligned(size, alignment) };
        };
        match unsafe { host_memalign_fn() } {
            Some(host_memalign) => unsafe { host_memalign(alignment, size) },
            None => unsafe { bump_alloc_aligned(size, alignment) },
        }
    }
}

#[inline]
unsafe fn native_libc_aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    // SAFETY: direct call to libc allocator symbol.
    unsafe { native_libc_memalign(alignment, size) }
}

const MALLOC_STATS_BIN_COUNT: usize = frankenlibc_core::malloc::size_class::NUM_SIZE_CLASSES + 1;
const FC_OP_ALLOC: usize = 1;
const FC_OP_FREE: usize = 2;
const FC_OP_SNAPSHOT: usize = 3;
static MALLOC_STATS_HTM_SITE: HtmSite = HtmSite::new("malloc_stats_combiner");

#[derive(Debug, Clone, Copy, Default)]
struct MallocStatsSnapshot {
    allocation_events: usize,
    free_events: usize,
    total_allocated: usize,
    total_freed: usize,
    active_allocations: usize,
    live_bytes: usize,
    peak_usage: usize,
}

#[derive(Debug, Clone, Copy)]
struct MallocStatsState {
    allocation_events: usize,
    free_events: usize,
    total_allocated: usize,
    total_freed: usize,
    active_allocations: usize,
    live_bytes: usize,
    peak_usage: usize,
    per_size_class: [usize; MALLOC_STATS_BIN_COUNT],
}

impl MallocStatsState {
    const fn new() -> Self {
        Self {
            allocation_events: 0,
            free_events: 0,
            total_allocated: 0,
            total_freed: 0,
            active_allocations: 0,
            live_bytes: 0,
            peak_usage: 0,
            per_size_class: [0; MALLOC_STATS_BIN_COUNT],
        }
    }

    const fn snapshot(self) -> MallocStatsSnapshot {
        MallocStatsSnapshot {
            allocation_events: self.allocation_events,
            free_events: self.free_events,
            total_allocated: self.total_allocated,
            total_freed: self.total_freed,
            active_allocations: self.active_allocations,
            live_bytes: self.live_bytes,
            peak_usage: self.peak_usage,
        }
    }
}

struct FlatCombiningStats {
    combiner_lock: AtomicBool,
    state: UnsafeCell<MallocStatsState>,
}

// SAFETY: access to `state` is serialized by `combiner_lock` on the fallback
// path or by HTM conflict detection on the optimistic path.
unsafe impl Sync for FlatCombiningStats {}

impl FlatCombiningStats {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            combiner_lock: AtomicBool::new(false),
            state: UnsafeCell::new(MallocStatsState::new()),
        }
    }

    fn apply_op(&self, op: usize, size: usize, bin: usize) -> MallocStatsSnapshot {
        if let Ok(Some(snapshot)) = MALLOC_STATS_HTM_SITE.run(|| {
            if self.combiner_lock.load(Ordering::Acquire) {
                return None;
            }

            // SAFETY: speculative mutation is safe because any conflicting
            // fallback combiner mutates either `combiner_lock` or `state`,
            // which forces the transaction to abort before commit.
            let state = unsafe { &mut *self.state.get() };
            Self::apply_locked(state, op, size, bin.min(MALLOC_STATS_BIN_COUNT - 1));
            Some(state.snapshot())
        }) {
            return snapshot;
        }

        self.apply_op_with_lock(op, size, bin.min(MALLOC_STATS_BIN_COUNT - 1))
    }

    fn apply_locked(state: &mut MallocStatsState, op: usize, size: usize, bin: usize) {
        match op {
            FC_OP_ALLOC => {
                state.allocation_events = state.allocation_events.saturating_add(1);
                state.total_allocated = state.total_allocated.saturating_add(size);
                state.active_allocations = state.active_allocations.saturating_add(1);
                state.live_bytes = state.live_bytes.saturating_add(size);
                state.peak_usage = state.peak_usage.max(state.live_bytes);
                state.per_size_class[bin] = state.per_size_class[bin].saturating_add(1);
            }
            FC_OP_FREE => {
                state.free_events = state.free_events.saturating_add(1);
                state.total_freed = state.total_freed.saturating_add(size);
                state.active_allocations = state.active_allocations.saturating_sub(1);
                state.live_bytes = state.live_bytes.saturating_sub(size);
                state.per_size_class[bin] = state.per_size_class[bin].saturating_sub(1);
            }
            FC_OP_SNAPSHOT => {}
            _ => {}
        }
    }

    fn apply_op_with_lock(&self, op: usize, size: usize, bin: usize) -> MallocStatsSnapshot {
        while self
            .combiner_lock
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            std::hint::spin_loop();
        }

        // SAFETY: `combiner_lock` is held exclusively for this stats update.
        let snapshot = unsafe {
            let state = &mut *self.state.get();
            Self::apply_locked(state, op, size, bin);
            state.snapshot()
        };
        self.combiner_lock.store(false, Ordering::Release);
        snapshot
    }

    fn record_alloc(&self, size: usize, bin: usize) {
        let _ = self.apply_op(FC_OP_ALLOC, size, bin);
    }

    fn record_free(&self, size: usize, bin: usize) {
        let _ = self.apply_op(FC_OP_FREE, size, bin);
    }

    fn snapshot(&self) -> MallocStatsSnapshot {
        self.apply_op(FC_OP_SNAPSHOT, 0, 0)
    }

    fn reset(&self) {
        while self
            .combiner_lock
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            std::hint::spin_loop();
        }

        // SAFETY: `combiner_lock` is held exclusively for this reset.
        unsafe {
            *self.state.get() = MallocStatsState::new();
        }

        self.combiner_lock.store(false, Ordering::Release);
    }
}

static GLOBAL_ALLOC_STATS: OnceLock<FlatCombiningStats> = OnceLock::new();

fn global_alloc_stats() -> Option<&'static FlatCombiningStats> {
    // Use get() not get_or_init() — OnceLock futex deadlocks during early init.
    // Stats are populated after prewarm. Before that, returns None (stats skipped).
    GLOBAL_ALLOC_STATS.get()
}

#[inline]
fn stats_bin_for_size(size: usize) -> usize {
    frankenlibc_core::malloc::size_class::bin_index(size.max(1)).min(MALLOC_STATS_BIN_COUNT - 1)
}

#[inline]
fn same_small_malloc_size_class(a: usize, b: usize) -> bool {
    let a_bin = frankenlibc_core::malloc::size_class::bin_index(a.max(1));
    let b_bin = frankenlibc_core::malloc::size_class::bin_index(b.max(1));
    a_bin < frankenlibc_core::malloc::size_class::NUM_SIZE_CLASSES && a_bin == b_bin
}

#[inline]
fn record_alloc_stats(size: usize) {
    if size == 0 {
        return;
    }
    if let Some(stats) = global_alloc_stats() {
        stats.record_alloc(size, stats_bin_for_size(size));
    }
}

#[inline]
fn record_free_stats(size: usize) {
    if size == 0 {
        return;
    }
    if let Some(stats) = global_alloc_stats() {
        stats.record_free(size, stats_bin_for_size(size));
    }
}

#[inline]
fn snapshot_alloc_stats() -> MallocStatsSnapshot {
    global_alloc_stats()
        .map(|s| s.snapshot())
        .unwrap_or_default()
}

fn sanitize_trace_component(component: &str) -> String {
    let sanitized: String = component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        String::from("unknown")
    } else {
        sanitized
    }
}

fn export_alloc_stats_snapshot_jsonl_from_snapshot(
    snapshot: MallocStatsSnapshot,
    bead_id: &str,
    run_id: &str,
    mode: &str,
) -> String {
    let bead = sanitize_trace_component(bead_id);
    let run = sanitize_trace_component(run_id);
    let mode = sanitize_trace_component(mode);
    let timestamp = now_utc_iso_like();
    let trace_id = format!("allocator::metrics::{bead}::{run}");
    let mut out = String::with_capacity(768);
    let _ = writeln!(
        &mut out,
        "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{trace_id}\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"decision_id\":0,\"schema_version\":\"{}\",\"level\":\"info\",\"event\":\"allocator_metrics_snapshot\",\"controller_id\":\"malloc_stats.v1\",\"mode\":\"{mode}\",\"api_family\":\"allocator\",\"symbol\":\"malloc::stats\",\"decision_path\":\"allocator::stats::snapshot\",\"decision_action\":\"observe\",\"outcome\":\"snapshot\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"allocations_total\":{},\"frees_total\":{},\"active_allocations\":{},\"bytes_allocated\":{},\"total_allocated_bytes\":{},\"total_freed_bytes\":{},\"peak_usage_bytes\":{},\"artifact_refs\":[\"crates/frankenlibc-abi/src/malloc_abi.rs\"]}}",
        MEMBRANE_SCHEMA_VERSION,
        snapshot.allocation_events,
        snapshot.free_events,
        snapshot.active_allocations,
        snapshot.live_bytes,
        snapshot.total_allocated,
        snapshot.total_freed,
        snapshot.peak_usage,
    );
    out
}

#[must_use]
pub fn export_alloc_stats_snapshot_jsonl(bead_id: &str, run_id: &str, mode: &str) -> String {
    export_alloc_stats_snapshot_jsonl_from_snapshot(snapshot_alloc_stats(), bead_id, run_id, mode)
}

// Native-fallback allocation tracking.
//
// Some bootstrap/reentrant paths intentionally allocate via native libc
// instead of the membrane arena. These pointers must later use native
// realloc/free semantics to preserve C behavior.
const FALLBACK_ALLOC_TABLE_SLOTS: usize = 262144;
const FALLBACK_SLOT_EMPTY: usize = 0;
const FALLBACK_SLOT_TOMBSTONE: usize = 1;
static FALLBACK_ALLOC_PTRS: [AtomicUsize; FALLBACK_ALLOC_TABLE_SLOTS] =
    [const { AtomicUsize::new(FALLBACK_SLOT_EMPTY) }; FALLBACK_ALLOC_TABLE_SLOTS];
static FALLBACK_ALLOC_SIZES: [AtomicUsize; FALLBACK_ALLOC_TABLE_SLOTS] =
    [const { AtomicUsize::new(0) }; FALLBACK_ALLOC_TABLE_SLOTS];
static FALLBACK_ALLOC_TABLE_LOCK: AtomicBool = AtomicBool::new(false);
static FALLBACK_ALLOC_MIN_ADDR: AtomicUsize = AtomicUsize::new(usize::MAX);
static FALLBACK_ALLOC_MAX_ADDR: AtomicUsize = AtomicUsize::new(0);

struct FallbackAllocTableGuard;

impl Drop for FallbackAllocTableGuard {
    fn drop(&mut self) {
        FALLBACK_ALLOC_TABLE_LOCK.store(false, Ordering::Release);
    }
}

fn lock_fallback_alloc_table() -> FallbackAllocTableGuard {
    while FALLBACK_ALLOC_TABLE_LOCK
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        std::hint::spin_loop();
    }
    FallbackAllocTableGuard
}

#[inline]
fn fallback_key(ptr: *mut c_void) -> Option<usize> {
    let key = ptr as usize;
    if key <= FALLBACK_SLOT_TOMBSTONE {
        None
    } else {
        Some(key)
    }
}

#[inline]
fn fallback_start_index(key: usize) -> usize {
    key.wrapping_mul(0x9e37_79b9_7f4a_7c15) % FALLBACK_ALLOC_TABLE_SLOTS
}

#[inline]
fn publish_fallback_range(key: usize, size: usize) {
    let end = key.saturating_add(size.max(1));
    if key < FALLBACK_ALLOC_MIN_ADDR.load(Ordering::Acquire) {
        FALLBACK_ALLOC_MIN_ADDR.fetch_min(key, Ordering::AcqRel);
    }
    if end > FALLBACK_ALLOC_MAX_ADDR.load(Ordering::Acquire) {
        FALLBACK_ALLOC_MAX_ADDR.fetch_max(end, Ordering::AcqRel);
    }
}

fn fallback_contains(ptr: *mut c_void) -> bool {
    let Some(key) = fallback_key(ptr) else {
        return false;
    };
    let _guard = lock_fallback_alloc_table();
    let start = fallback_start_index(key);
    for i in 0..1024 {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let slot = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Relaxed);
        if slot == key {
            return true;
        }
        if slot == FALLBACK_SLOT_EMPTY {
            return false;
        }
    }
    false
}

fn fallback_insert_sized_index(ptr: *mut c_void, size: usize) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    let Some(key) = fallback_key(ptr) else {
        return None;
    };
    let _guard = lock_fallback_alloc_table();
    let start = fallback_start_index(key);
    let mut first_tombstone: Option<usize> = None;
    for i in 0..1024 {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let slot = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Relaxed);
        if slot == key {
            if size != 0 {
                publish_fallback_range(key, size);
                FALLBACK_ALLOC_SIZES[idx].store(size, Ordering::Relaxed);
            }
            return Some(idx);
        }
        if slot == FALLBACK_SLOT_TOMBSTONE {
            if first_tombstone.is_none() {
                first_tombstone = Some(idx);
            }
            continue;
        }
        if slot == FALLBACK_SLOT_EMPTY {
            if let Some(tomb_idx) = first_tombstone {
                publish_fallback_range(key, size);
                FALLBACK_ALLOC_SIZES[tomb_idx].store(size, Ordering::Relaxed);
                FALLBACK_ALLOC_PTRS[tomb_idx].store(key, Ordering::Release);
                return Some(tomb_idx);
            }
            publish_fallback_range(key, size);
            FALLBACK_ALLOC_SIZES[idx].store(size, Ordering::Relaxed);
            FALLBACK_ALLOC_PTRS[idx].store(key, Ordering::Release);
            return Some(idx);
        }
    }

    if let Some(tomb_idx) = first_tombstone {
        publish_fallback_range(key, size);
        FALLBACK_ALLOC_SIZES[tomb_idx].store(size, Ordering::Relaxed);
        FALLBACK_ALLOC_PTRS[tomb_idx].store(key, Ordering::Release);
        return Some(tomb_idx);
    }
    None
}

fn fallback_insert_sized(ptr: *mut c_void, size: usize) {
    let _ = fallback_insert_sized_index(ptr, size);
}

#[inline]
fn remember_fallback_cache(slot: &'static AllocatorReentrySlot, ptr: *mut c_void, idx: usize) {
    if fallback_key(ptr).is_none() {
        return;
    }
    slot.fallback_cache_index.store(idx, Ordering::Release);
}

#[inline]
fn clear_fallback_cache(slot: &'static AllocatorReentrySlot) {
    slot.fallback_cache_index
        .store(usize::MAX, Ordering::Release);
}

fn fallback_insert_sized_for_slot(
    slot: &'static AllocatorReentrySlot,
    ptr: *mut c_void,
    size: usize,
) {
    if let Some(idx) = fallback_insert_sized_index(ptr, size) {
        remember_fallback_cache(slot, ptr, idx);
    } else {
        clear_fallback_cache(slot);
    }
}

fn fallback_remove(ptr: *mut c_void) -> bool {
    fallback_remove_sized(ptr).is_some()
}

fn fallback_remove_sized_for_slot(
    slot: &'static AllocatorReentrySlot,
    ptr: *mut c_void,
) -> Option<usize> {
    let key = fallback_key(ptr)?;
    if !MULTI_THREADED.load(Ordering::Relaxed) {
        let cached_idx = slot.fallback_cache_index.load(Ordering::Acquire);
        if cached_idx < FALLBACK_ALLOC_TABLE_SLOTS {
            let slot_key = FALLBACK_ALLOC_PTRS[cached_idx].load(Ordering::Acquire);
            if slot_key == key {
                let size = FALLBACK_ALLOC_SIZES[cached_idx].load(Ordering::Relaxed);
                FALLBACK_ALLOC_SIZES[cached_idx].store(0, Ordering::Relaxed);
                FALLBACK_ALLOC_PTRS[cached_idx].store(FALLBACK_SLOT_TOMBSTONE, Ordering::Release);
                clear_fallback_cache(slot);
                return Some(size);
            }
            clear_fallback_cache(slot);
        }
    }
    fallback_remove_sized(ptr)
}

fn fallback_remove_sized(ptr: *mut c_void) -> Option<usize> {
    let key = fallback_key(ptr)?;
    let _guard = lock_fallback_alloc_table();
    let start = fallback_start_index(key);
    for i in 0..1024 {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let slot = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Relaxed);
        if slot == key {
            let size = FALLBACK_ALLOC_SIZES[idx].load(Ordering::Relaxed);
            FALLBACK_ALLOC_SIZES[idx].store(0, Ordering::Relaxed);
            FALLBACK_ALLOC_PTRS[idx].store(FALLBACK_SLOT_TOMBSTONE, Ordering::Release);
            return Some(size);
        }
        if slot == FALLBACK_SLOT_EMPTY {
            return None;
        }
    }
    None
}

fn fallback_size(ptr: *mut c_void) -> Option<usize> {
    let key = fallback_key(ptr)?;
    let _guard = lock_fallback_alloc_table();
    let start = fallback_start_index(key);
    for i in 0..1024 {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let slot = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Relaxed);
        if slot == key {
            return Some(FALLBACK_ALLOC_SIZES[idx].load(Ordering::Relaxed));
        }
        if slot == FALLBACK_SLOT_EMPTY {
            return None;
        }
    }
    None
}

fn fallback_size_for_slot(slot: &'static AllocatorReentrySlot, ptr: *mut c_void) -> Option<usize> {
    let key = fallback_key(ptr)?;
    if !MULTI_THREADED.load(Ordering::Relaxed) {
        let cached_idx = slot.fallback_cache_index.load(Ordering::Acquire);
        if cached_idx < FALLBACK_ALLOC_TABLE_SLOTS {
            let slot_key = FALLBACK_ALLOC_PTRS[cached_idx].load(Ordering::Acquire);
            if slot_key == key {
                return Some(FALLBACK_ALLOC_SIZES[cached_idx].load(Ordering::Relaxed));
            }
            clear_fallback_cache(slot);
        }
    }
    fallback_size(ptr)
}

fn fallback_remaining(addr: usize) -> Option<usize> {
    if addr <= FALLBACK_SLOT_TOMBSTONE {
        return None;
    }
    let min_addr = FALLBACK_ALLOC_MIN_ADDR.load(Ordering::Acquire);
    let max_addr = FALLBACK_ALLOC_MAX_ADDR.load(Ordering::Acquire);
    if addr < min_addr || addr >= max_addr {
        return None;
    }
    // Fast path: use hash-based probing (up to 1024 slots) instead of full scan.
    // This is O(1) amortized instead of O(262144), at the cost of potentially
    // missing interior pointers that hash to a different slot. For exact-start
    // pointers (the common case), this finds the allocation immediately.
    let _guard = lock_fallback_alloc_table();
    let start = fallback_start_index(addr);
    for i in 0..1024 {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let base = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Relaxed);
        if base == FALLBACK_SLOT_EMPTY {
            // No more entries in this probe sequence
            return None;
        }
        if base <= FALLBACK_SLOT_TOMBSTONE {
            continue;
        }
        let size = FALLBACK_ALLOC_SIZES[idx].load(Ordering::Relaxed);
        if size == 0 {
            continue;
        }
        let Some(end) = base.checked_add(size) else {
            continue;
        };
        if base <= addr && addr < end {
            return Some(end - addr);
        }
    }
    None
}

#[must_use]
pub(crate) fn in_allocator_reentry_context() -> bool {
    current_allocator_reentry_slot()
        .map(|slot| slot.allocator_depth.load(Ordering::Acquire) > 0)
        .unwrap_or(true)
}

struct AllocatorReentryGuard {
    slot: &'static AllocatorReentrySlot,
}

impl Drop for AllocatorReentryGuard {
    fn drop(&mut self) {
        let current = self.slot.allocator_depth.load(Ordering::Acquire);
        self.slot
            .allocator_depth
            .store(current.saturating_sub(1), Ordering::Release);
    }
}

#[inline]
fn enter_allocator_reentry_guard() -> Option<AllocatorReentryGuard> {
    let slot = current_allocator_reentry_slot()?;
    let guard = slot
        .allocator_depth
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| AllocatorReentryGuard { slot })?;

    if runtime_policy::is_runtime_ready() {
        if runtime_policy::in_policy_reentry_context() {
            return None;
        }
        if !crate::pthread_abi::pthread_tls_access_active()
            && crate::pthread_abi::in_threading_policy_context()
        {
            return None;
        }
    }
    Some(guard)
}

/// Test hook: force allocator entrypoints down the reentrant fallback path and
/// return the previous depth so callers can restore it afterwards.
#[doc(hidden)]
pub fn malloc_swap_reentry_depth_for_tests(depth: u32) -> u32 {
    current_allocator_reentry_slot()
        .map(|slot| slot.allocator_depth.swap(depth, Ordering::AcqRel))
        .unwrap_or(0)
}

/// Test hook: restore allocator reentry depth after
/// [`malloc_swap_reentry_depth_for_tests`].
#[doc(hidden)]
pub fn malloc_restore_reentry_depth_for_tests(previous: u32) {
    if let Some(slot) = current_allocator_reentry_slot() {
        slot.allocator_depth.store(previous, Ordering::Release);
    }
}

/// Test hook (bd-35hjg.3.1): returns the allocator reentry-slot index bound to
/// the calling thread, exercising the full `current_allocator_reentry_slot`
/// fast/slow path. Two concurrently live threads must never observe the same
/// index, and the index is stable for the lifetime of a live thread.
#[doc(hidden)]
pub fn malloc_current_reentry_slot_index_for_tests() -> Option<usize> {
    current_allocator_reentry_slot().map(|slot| {
        (slot as *const AllocatorReentrySlot as usize - ALLOCATOR_REENTRY_SLOTS.as_ptr() as usize)
            / std::mem::size_of::<AllocatorReentrySlot>()
    })
}

/// Test hook (bd-35hjg.3.1): reports whether a second distinct thread has been
/// observed, which latches off the syscall-free thread-key-only fast path in
/// `current_allocator_reentry_slot` so every lookup verifies the live tid.
#[doc(hidden)]
pub fn malloc_reentry_multithreaded_latched_for_tests() -> bool {
    MULTI_THREADED.load(Ordering::SeqCst)
}

#[doc(hidden)]
pub fn signal_runtime_ready_for_tests() {
    runtime_policy::signal_runtime_ready();
}

#[doc(hidden)]
pub fn take_last_decision_gate_for_tests() -> Option<&'static str> {
    runtime_policy::take_last_explainability().map(|explain| explain.decision_gate)
}

#[doc(hidden)]
pub fn malloc_known_remaining_for_tests(ptr: *const c_void) -> Option<usize> {
    known_remaining(ptr as usize)
}

#[doc(hidden)]
pub fn malloc_fallback_range_for_tests() -> (usize, usize) {
    (
        FALLBACK_ALLOC_MIN_ADDR.load(Ordering::Acquire),
        FALLBACK_ALLOC_MAX_ADDR.load(Ordering::Acquire),
    )
}

const MCHECK_OK: c_int = 0;
const MCHECK_FREE: c_int = 1;
const MCHECK_HEAD: c_int = 2;
const MCHECK_TAIL: c_int = 3;

#[inline]
unsafe fn read_fixed<const N: usize>(ptr: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    // SAFETY: callers only pass addresses from live/quarantined arena slots,
    // which remain allocated while the slot is visible to lookup.
    unsafe { std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N) };
    out
}

#[must_use]
pub(crate) unsafe fn mprobe_status(ptr: *mut c_void) -> c_int {
    if ptr.is_null() {
        return MCHECK_HEAD;
    }

    if is_bump_ptr(ptr) || fallback_contains(ptr) {
        return MCHECK_OK;
    }

    let Some(pipeline) = crate::membrane_state::try_global_pipeline() else {
        return MCHECK_HEAD;
    };
    let Some(slot) = pipeline.arena.lookup(ptr as usize) else {
        return MCHECK_HEAD;
    };

    if slot.user_base != ptr as usize {
        return MCHECK_HEAD;
    }

    match slot.state {
        SafetyState::Quarantined | SafetyState::Freed => return MCHECK_FREE,
        SafetyState::Invalid | SafetyState::Unknown => return MCHECK_HEAD,
        state if !state.is_live() => return MCHECK_HEAD,
        _ => {}
    }

    let fingerprint_bytes = unsafe { read_fixed::<FINGERPRINT_SIZE>(slot.raw_base as *const u8) };
    let fingerprint = AllocationFingerprint::from_bytes(&fingerprint_bytes);
    if fingerprint.size != slot.user_size as u64
        || fingerprint.generation != slot.generation
        || !fingerprint.verify(slot.raw_base)
    {
        return MCHECK_HEAD;
    }

    let canary_ptr = slot.user_base.saturating_add(slot.user_size) as *const u8;
    let canary_bytes = unsafe { read_fixed::<CANARY_SIZE>(canary_ptr) };
    if !fingerprint.canary().verify(&canary_bytes) {
        return MCHECK_TAIL;
    }

    MCHECK_OK
}

#[inline]
fn strict_allocator_host_path_active() -> bool {
    // In standalone mode, always use native arena (no host glibc available)
    #[cfg(feature = "standalone")]
    {
        false
    }
    #[cfg(not(feature = "standalone"))]
    {
        !runtime_policy::mode().heals_enabled()
    }
}

#[inline]
fn allocator_bootstrap_passthrough_active() -> bool {
    !runtime_policy::is_runtime_ready()
}

#[inline]
unsafe fn bootstrap_malloc_passthrough(size: usize) -> *mut c_void {
    let req = size.max(1);
    // SAFETY: early loader/bootstrap allocations must bypass runtime policy
    // and use the same native/bump fallback path as reentrant allocator calls.
    let out = unsafe { native_libc_malloc(req) };
    fallback_insert_sized(out, req);
    if !out.is_null() {
        record_alloc_stats(req);
    }
    out
}

#[inline]
unsafe fn bootstrap_calloc_passthrough(nmemb: usize, size: usize) -> *mut c_void {
    // SAFETY: early loader/bootstrap allocations must bypass runtime policy
    // and use the same native/bump fallback path as reentrant allocator calls.
    let out = unsafe { native_libc_calloc(nmemb, size) };
    let req = nmemb.saturating_mul(size).max(1);
    fallback_insert_sized(out, req);
    if !out.is_null() {
        record_alloc_stats(req);
    }
    out
}

#[inline]
unsafe fn bootstrap_realloc_passthrough(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { bootstrap_malloc_passthrough(size) };
    }
    if size == 0 {
        unsafe { bootstrap_free_passthrough(ptr) };
        return std::ptr::null_mut();
    }
    // SAFETY: early loader/bootstrap reallocations must bypass runtime policy
    // and use the same native/bump fallback path as reentrant allocator calls.
    let out = unsafe { native_libc_realloc(ptr, size) };
    if !out.is_null() {
        let old_size = fallback_remove_sized(ptr);
        let req = size.max(1);
        fallback_insert_sized(out, req);
        if let Some(old_size) = old_size {
            record_free_stats(old_size);
        }
        record_alloc_stats(req);
    }
    out
}

#[inline]
unsafe fn bootstrap_free_passthrough(ptr: *mut c_void) {
    let tracked_size = fallback_remove_sized(ptr);
    // SAFETY: early loader/bootstrap frees must bypass runtime policy and
    // return host-owned allocations through the native fallback path.
    unsafe { native_libc_free(ptr) };
    if let Some(size) = tracked_size {
        record_free_stats(size);
    }
}

#[inline]
fn stage_index(ordering: &[CheckStage; 7], stage: CheckStage) -> usize {
    ordering.iter().position(|s| *s == stage).unwrap_or(0)
}

#[inline]
fn allocator_stage_context(addr_hint: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = (addr_hint & 0x7) == 0;
    let recent_page = addr_hint != 0 && check_ownership(addr_hint);
    let ordering = runtime_policy::check_ordering(ApiFamily::Allocator, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
fn record_allocator_stage_outcome(
    ordering: &[CheckStage; 7],
    aligned: bool,
    recent_page: bool,
    exit_stage: Option<usize>,
) {
    runtime_policy::note_check_order_outcome(
        ApiFamily::Allocator,
        aligned,
        recent_page,
        ordering,
        exit_stage,
    );
}

/// Returns the full safety abstraction for a pointer at `addr`.
///
/// Returns `None` if the pipeline is not yet initialized.
#[must_use]
pub(crate) fn validate_ptr(addr: usize) -> Option<PointerAbstraction> {
    if runtime_policy::proof_carried_pointer_validation_active() {
        return Some(PointerAbstraction::unknown(addr));
    }
    let pipeline = crate::membrane_state::ready_pipeline()?;
    pipeline.validate(addr).abstraction()
}

/// Cheaply check if an address is likely owned by the membrane.
///
/// Returns `false` if the pipeline is not yet initialized.
#[must_use]
pub(crate) fn check_ownership(addr: usize) -> bool {
    if runtime_policy::proof_carried_pointer_validation_active() {
        return false;
    }
    crate::membrane_state::ready_pipeline()
        .map(|p| p.check_ownership(addr))
        .unwrap_or(false)
}

/// Remaining bytes in a known live allocation at `addr`.
///
/// Returns `None` if the pipeline is not yet initialized (reentrant guard).
#[must_use]
#[inline(never)]
pub(crate) fn known_remaining(addr: usize) -> Option<usize> {
    // Strict mode skips the full membrane validator, but allocator-owned
    // fallback bookkeeping is still cheap and required for bounded C-string
    // scans that must reject unterminated tracked buffers before host passthrough.
    if runtime_policy::strict_passthrough_active() {
        return fallback_remaining(addr);
    }

    if runtime_policy::in_policy_reentry_context()
        || in_allocator_reentry_context()
        || crate::membrane_state::pipeline_initialization_active()
        || frankenlibc_membrane::ptr_validator::in_validation_context()
    {
        return fallback_remaining(addr);
    }

    validate_ptr(addr)
        .and_then(|abs| abs.remaining)
        .or_else(|| fallback_remaining(addr))
}

// ---------------------------------------------------------------------------
// malloc
// ---------------------------------------------------------------------------

/// POSIX `malloc` -- allocates `size` bytes of uninitialized memory.
///
/// Returns a pointer to the allocated memory, or null on failure.
/// The memory is not initialized.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let Some(reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        return unsafe { bootstrap_malloc_passthrough(size) };
    };

    if allocator_bootstrap_passthrough_active() {
        return unsafe { bootstrap_malloc_passthrough(size) };
    }

    let req = size.max(1);
    let _trace_scope = runtime_policy::entrypoint_scope("malloc");
    if strict_allocator_host_path_active() {
        if cfg!(not(test))
            && runtime_policy::is_runtime_ready()
            && runtime_policy::proof_carried_fast_path_active(
                ApiFamily::Allocator,
                req,
                true,
                false,
            )
        {
            let (_, decision) =
                runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);
            // SAFETY: strict-mode preload delegates allocator semantics to host libc
            // to preserve compatibility while the PCC gate records explainability.
            let out = unsafe { native_libc_malloc(req) };
            if !out.is_null() {
                fallback_insert_sized_for_slot(reentry_guard.slot, out, req);
                record_alloc_stats(req);
            }
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(8, req),
                out.is_null(),
            );
            return out;
        }
        // SAFETY: strict-mode preload delegates allocator semantics to host libc
        // to preserve process compatibility while hardened mode exercises the
        // membrane allocator and repair pipeline.
        let out = unsafe { native_libc_malloc(req) };
        if !out.is_null() {
            fallback_insert_sized_for_slot(reentry_guard.slot, out, req);
            record_alloc_stats(req);
        }
        return out;
    }
    let _signal_guard =
        enter_signal_critical_section(SignalCriticalSectionKind::MallocArenaLockAcquire);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate(req) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
            let out = unsafe { native_libc_malloc(req) };
            fallback_insert_sized(out, req);
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(8, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// free
// ---------------------------------------------------------------------------

/// POSIX `free` -- deallocates memory previously allocated by `malloc`, `calloc`,
/// or `realloc`.
///
/// If `ptr` is null, no operation is performed (per POSIX).
///
/// # Safety
///
/// `ptr` must have been returned by a previous call to `malloc`, `calloc`, or
/// `realloc`, and must not have been freed already.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    let Some(reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        unsafe { bootstrap_free_passthrough(ptr) };
        return;
    };

    if allocator_bootstrap_passthrough_active() {
        unsafe { bootstrap_free_passthrough(ptr) };
        return;
    }

    if is_bump_ptr(ptr) {
        let _ = fallback_remove(ptr);
        return;
    }
    if strict_allocator_host_path_active() {
        // Fast path (bd-f874go): a pointer present in the native-fallback table
        // is by construction a host-allocator allocation (it was inserted by the
        // strict malloc/calloc/bootstrap path), and arena allocations are never
        // inserted there — so a hit lets us free natively WITHOUT the
        // `check_ownership` PageOracle query. This removes `PageOracle::query`
        // from every deployed strict-mode free of a tracked pointer (the common
        // case). Behavior-preserving: such pointers always satisfied
        // `!check_ownership(ptr)` under the old combined gate.
        if let Some(size) = fallback_remove_sized_for_slot(reentry_guard.slot, ptr) {
            // SAFETY: tracked native-fallback allocation returned to the host.
            unsafe { native_libc_free_with_slot(reentry_guard.slot, ptr) };
            record_free_stats(size);
            return;
        }
        if !check_ownership(ptr as usize) {
            // SAFETY: strict-mode preserves host allocator semantics. Some glibc
            // internals allocate without crossing our public malloc symbol, so
            // unknown pointers must still be returned to the host allocator.
            unsafe { native_libc_free_with_slot(reentry_guard.slot, ptr) };
            return;
        }
        // Arena-owned pointer: fall through to the membrane free path below.
    }
    let _trace_scope = runtime_policy::entrypoint_scope("free");
    let _signal_guard =
        enter_signal_critical_section(SignalCriticalSectionKind::MallocFastbinMutation);
    let (aligned, recent_page, ordering) = allocator_stage_context(ptr as usize);
    if ptr.is_null() {
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Allocator, ptr as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Allocator, decision.profile, 6, true);
        return;
    }

    let Some(pipeline) = crate::membrane_state::try_global_pipeline() else {
        // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
        let _ = fallback_remove(ptr);
        unsafe { native_libc_free_with_slot(reentry_guard.slot, ptr) };
        runtime_policy::observe(ApiFamily::Allocator, decision.profile, 6, false);
        record_allocator_stage_outcome(&ordering, aligned, recent_page, None);
        return;
    };

    let known_size = pipeline
        .arena
        .lookup(ptr as usize)
        .and_then(|slot| (slot.user_base == ptr as usize).then_some(slot.user_size));

    let mut adverse = false;
    let result = pipeline.free(ptr.cast());

    match result {
        FreeResult::Freed => {
            if let Some(size) = known_size {
                record_free_stats(size);
            }
        }
        FreeResult::FreedWithCanaryCorruption => {
            // Buffer overflow was detected -- the canary after the allocation was
            // corrupted. In strict mode we still free (damage is done). Metrics
            // are recorded by the arena.
            adverse = true;
            if let Some(size) = known_size {
                record_free_stats(size);
            }
        }
        FreeResult::DoubleFree => {
            adverse = true;
            if runtime_policy::mode().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::IgnoreDoubleFree);
            }
            // Strict mode: double free is silently ignored too (safer than UB).
            // A real glibc would abort, but our membrane prioritizes defined behavior.
        }
        FreeResult::ForeignPointer => {
            if fallback_remove(ptr) {
                // SAFETY: pointer is tracked as native-fallback allocation.
                unsafe { native_libc_free_with_slot(reentry_guard.slot, ptr) };
            } else {
                adverse = true;
                if runtime_policy::mode().heals_enabled() {
                    let policy = global_healing_policy();
                    policy.record(&HealingAction::IgnoreForeignFree);
                }
                // Strict mode: foreign pointer free is ignored.
            }
        }
        FreeResult::InvalidPointer => {
            // Pointer is in an invalid state. Ignore to avoid undefined behavior.
            adverse = true;
        }
    }

    runtime_policy::observe(ApiFamily::Allocator, decision.profile, 20, adverse);
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if adverse {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
}

// ---------------------------------------------------------------------------
// calloc
// ---------------------------------------------------------------------------

/// POSIX `calloc` -- allocates memory for an array of `nmemb` elements of `size`
/// bytes each, and initializes all bytes to zero.
///
/// Returns null if the multiplication overflows or allocation fails.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[inline(never)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let Some(total) = nmemb.checked_mul(size).map(|total| total.max(1)) else {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        return std::ptr::null_mut();
    };

    let Some(reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        return unsafe { bootstrap_calloc_passthrough(nmemb, size) };
    };

    if allocator_bootstrap_passthrough_active() {
        return unsafe { bootstrap_calloc_passthrough(nmemb, size) };
    }

    if strict_allocator_host_path_active() {
        // SAFETY: strict-mode preload delegates allocator semantics to host libc.
        let out = unsafe { native_libc_calloc_with_slot(reentry_guard.slot, nmemb, size) };
        if !out.is_null() {
            fallback_insert_sized_for_slot(reentry_guard.slot, out, total);
            record_alloc_stats(total);
        }
        return out;
    }
    let _trace_scope = runtime_policy::entrypoint_scope("calloc");
    let _signal_guard =
        enter_signal_critical_section(SignalCriticalSectionKind::MallocArenaLockAcquire);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, total, total, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, total),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate(total) {
            Some(ptr) => {
                // SAFETY: ptr is valid for `total` bytes from the arena allocate contract.
                unsafe { std::ptr::write_bytes(ptr, 0, total) };
                ptr.cast()
            }
            None => std::ptr::null_mut(),
        },
        None => {
            // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
            let out = unsafe { native_libc_calloc_with_slot(reentry_guard.slot, nmemb, size) };
            fallback_insert_sized(out, total);
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(total);
    }
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, total),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// realloc
// ---------------------------------------------------------------------------

/// POSIX `realloc` -- changes the size of a previously allocated memory block.
///
/// - If `ptr` is null, behaves like `malloc(size)`.
/// - If `size` is 0 and `ptr` is non-null, behaves like `free(ptr)` and returns null.
/// - Otherwise, allocates new memory of `size`, copies the old data, frees the old.
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by `malloc`/`calloc`/`realloc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let Some(reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        return unsafe { bootstrap_realloc_passthrough(ptr, size) };
    };

    if allocator_bootstrap_passthrough_active() {
        return unsafe { bootstrap_realloc_passthrough(ptr, size) };
    }

    // realloc(NULL, size) == malloc(size)
    if ptr.is_null() {
        return unsafe { malloc(size) };
    }

    // realloc(ptr, 0) == free(ptr), return NULL
    if size == 0 {
        unsafe { free(ptr) };
        return std::ptr::null_mut();
    }

    if is_bump_ptr(ptr) {
        let out = unsafe { native_libc_malloc(size.max(1)) };
        if !out.is_null()
            && let Some(old_size) = unsafe { bump_allocation_size(ptr) }
        {
            let copy_size = old_size.min(size);
            unsafe {
                std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), out.cast::<u8>(), copy_size);
            }
        }
        let _ = fallback_remove(ptr);
        fallback_insert_sized(out, size.max(1));
        return out;
    }

    if strict_allocator_host_path_active() {
        if let Some(old_size) = fallback_size_for_slot(reentry_guard.slot, ptr) {
            let req = size.max(1);
            if req == old_size || (req < old_size && same_small_malloc_size_class(req, old_size)) {
                if req != old_size {
                    fallback_insert_sized(ptr, req);
                    record_free_stats(old_size);
                    record_alloc_stats(req);
                }
                return ptr;
            }

            // SAFETY: fallback-tracked pointers originate from the host allocator.
            let out = unsafe { native_libc_realloc(ptr, size) };
            if !out.is_null() {
                let removed_size = fallback_remove_sized(ptr).unwrap_or(old_size);
                fallback_insert_sized(out, req);
                record_free_stats(removed_size);
                record_alloc_stats(req);
            }
            return out;
        }

        if let Some(pipeline) = crate::membrane_state::try_global_pipeline()
            && let Some(slot) = pipeline.arena.lookup(ptr as usize)
            && slot.user_base == ptr as usize
        {
            // SAFETY: host allocation succeeds or returns null; copy stays within
            // the old/new allocation bounds, then the legacy membrane allocation
            // is retired through the pipeline.
            let out = unsafe { native_libc_malloc(size.max(1)) };
            if out.is_null() {
                return out;
            }
            let copy_size = slot.user_size.min(size);
            unsafe {
                std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), out.cast::<u8>(), copy_size);
            }
            let _ = pipeline.free(ptr.cast());
            fallback_insert_sized(out, size.max(1));
            record_alloc_stats(size.max(1));
            return out;
        }

        // Unknown pointer in strict mode: preserve host allocator semantics.
        // glibc internals can pass allocations that never crossed our public
        // malloc symbol, and strict mode must not rewrite those realloc calls.
        let out = unsafe { native_libc_realloc(ptr, size) };
        if !out.is_null() {
            fallback_insert_sized(out, size.max(1));
            record_alloc_stats(size.max(1));
        }
        return out;
    }
    let _trace_scope = runtime_policy::entrypoint_scope("realloc");
    let _signal_guard =
        enter_signal_critical_section(SignalCriticalSectionKind::MallocLargebinLink);

    let (aligned, recent_page, ordering) = allocator_stage_context(ptr as usize);
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Allocator, ptr as usize, size, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, size),
            true,
        );
        return std::ptr::null_mut();
    }

    let Some(pipeline) = crate::membrane_state::try_global_pipeline() else {
        // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
        let out = unsafe { native_libc_realloc(ptr, size) };
        if !out.is_null() {
            let _ = fallback_remove(ptr);
            fallback_insert_sized(out, size.max(1));
        }
        return out;
    };
    let arena: &AllocationArena = &pipeline.arena;

    // Look up old allocation to get its size
    let old_addr = ptr as usize;
    let old_size = match arena.lookup(old_addr) {
        Some(slot) if slot.user_base == old_addr => slot.user_size,
        Some(_) => {
            // Inner pointer or metadata pointer. Invalid to realloc.
            record_allocator_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(6, size),
                true,
            );
            return std::ptr::null_mut();
        }
        None => {
            if fallback_contains(ptr) {
                // Pointer originated from native fallback allocation path.
                // Preserve realloc copy semantics by delegating to native realloc.
                let out = unsafe { native_libc_realloc(ptr, size) };
                if !out.is_null() {
                    let _ = fallback_remove(ptr);
                    fallback_insert_sized(out, size.max(1));
                }
                record_allocator_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    if out.is_null() {
                        Some(stage_index(&ordering, CheckStage::Arena))
                    } else {
                        None
                    },
                );
                runtime_policy::observe(
                    ApiFamily::Allocator,
                    decision.profile,
                    runtime_policy::scaled_cost(12, size),
                    out.is_null(),
                );
                return out;
            }

            // Foreign pointer -- in hardened mode, treat as malloc
            if runtime_policy::mode().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::ReallocAsMalloc { size });
                record_allocator_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Arena)),
                );
                runtime_policy::observe(
                    ApiFamily::Allocator,
                    decision.profile,
                    runtime_policy::scaled_cost(6, size),
                    true,
                );
                return unsafe { malloc(size) };
            }
            // Strict mode: cannot determine old size; treat as malloc
            record_allocator_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(6, size),
                true,
            );
            return unsafe { malloc(size) };
        }
    };

    // In-place shrink / same-size fast path: the live block's capacity is at
    // least its previous logical size (`old_size`), which is >= the requested
    // `size`, so it already satisfies the request — return it unchanged with no
    // alloc/copy/free. The first `size` bytes are preserved (they are a prefix of
    // the existing contents), and keeping the tracked size at `old_size` is safe:
    // a later realloc copies at most `min(old_size, new)` bytes, never losing the
    // caller's data. This also matches glibc, which shrinks realloc in place.
    // (In-place GROWTH into the block's size-class slack is bd-tkcv3c: it must
    // update the tracked size, so it needs a test-capable turn.)
    if size <= old_size {
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(4, size),
            false,
        );
        record_allocator_stage_outcome(&ordering, aligned, recent_page, None);
        return ptr;
    }

    // Allocate new block
    let new_ptr = match pipeline.allocate(size) {
        Some(p) => p,
        None => {
            record_allocator_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, size),
                true,
            );
            return std::ptr::null_mut();
        }
    };

    // Copy old data (up to the smaller of old and new sizes)
    let copy_size = old_size.min(size);

    // SAFETY: old ptr is valid for old_size bytes, new ptr is valid for size bytes.
    // copy_size <= min(old_size, size), so both reads and writes are in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), new_ptr, copy_size);
    }

    // Account new live allocation first so failed old-block release does not undercount.
    record_alloc_stats(size);

    // Free old block and account deallocation only if arena confirms it was released.
    let old_free = pipeline.free(ptr.cast());
    if matches!(
        old_free,
        FreeResult::Freed | FreeResult::FreedWithCanaryCorruption
    ) {
        record_free_stats(old_size);
    }
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(18, size),
        false,
    );
    record_allocator_stage_outcome(&ordering, aligned, recent_page, None);
    new_ptr.cast()
}

// ---------------------------------------------------------------------------
// posix_memalign
// ---------------------------------------------------------------------------

/// POSIX `posix_memalign` -- allocates `size` bytes of memory with specified alignment.
///
/// Stores the address of the allocated memory in `*memptr`.
/// Returns 0 on success, or an error code (EINVAL, ENOMEM) on failure.
///
/// # Safety
///
/// `memptr` must be a valid pointer to a `*mut c_void`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    if memptr.is_null()
        || !alignment.is_power_of_two()
        || !alignment.is_multiple_of(std::mem::size_of::<usize>())
    {
        return EINVAL as c_int;
    }

    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: forwards arguments to libc-compatible fallback implementation.
        return unsafe { native_libc_posix_memalign(memptr, alignment, size) };
    };

    if allocator_bootstrap_passthrough_active() {
        // SAFETY: early loader/bootstrap aligned allocations must avoid
        // runtime-policy trace state until the runtime-ready boundary.
        let rc = unsafe { native_libc_posix_memalign(memptr, alignment, size) };
        if rc == 0 {
            // SAFETY: successful posix_memalign stores an allocation pointer.
            let out = unsafe { *memptr };
            fallback_insert_sized(out, size.max(1));
        }
        return rc;
    }

    let _trace_scope = runtime_policy::entrypoint_scope("posix_memalign");
    let req = size.max(1);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return ENOMEM as c_int;
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate_aligned(req, alignment) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
            let ptr = unsafe { native_libc_memalign(alignment, req) };
            if !ptr.is_null() {
                fallback_insert_sized(ptr, req);
            }
            ptr
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }

    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );

    if out.is_null() {
        ENOMEM as c_int
    } else {
        unsafe { *memptr = out };
        0
    }
}

// ---------------------------------------------------------------------------
// memalign
// ---------------------------------------------------------------------------

/// Legacy `memalign` -- allocates `size` bytes of memory with specified alignment.
///
/// Returns a pointer to the allocated memory, or null on failure.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    // POSIX requires alignment to be a power of two.
    if alignment == 0 || !alignment.is_power_of_two() {
        unsafe { set_abi_errno(EINVAL as c_int) };
        return std::ptr::null_mut();
    }

    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: direct delegation avoids recursive aligned-allocation lock paths.
        let out = unsafe { native_libc_memalign(alignment, size) };
        fallback_insert_sized(out, size.max(1));
        return out;
    };

    if allocator_bootstrap_passthrough_active() {
        // SAFETY: early loader/bootstrap aligned allocations must avoid
        // runtime-policy trace state until the runtime-ready boundary.
        let out = unsafe { native_libc_memalign(alignment, size) };
        fallback_insert_sized(out, size.max(1));
        return out;
    }

    let _trace_scope = runtime_policy::entrypoint_scope("memalign");
    let req = size.max(1);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate_aligned(req, alignment) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            let out = unsafe { native_libc_memalign(alignment, req) };
            if !out.is_null() {
                fallback_insert_sized(out, req);
            }
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }

    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// aligned_alloc
// ---------------------------------------------------------------------------

/// C11 `aligned_alloc` -- allocates `size` bytes of memory with specified alignment.
///
/// `alignment` must be a valid alignment supported by the implementation.
/// `size` must be a multiple of `alignment`.
/// Returns a pointer to the allocated memory, or null on failure.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    // C11 requires alignment to be a power of two and size to be a multiple of alignment.
    if alignment == 0 || !alignment.is_power_of_two() || !size.is_multiple_of(alignment) {
        unsafe { set_abi_errno(EINVAL as c_int) };
        return std::ptr::null_mut();
    }

    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: direct delegation avoids recursive aligned-allocation lock paths.
        let out = unsafe { native_libc_aligned_alloc(alignment, size) };
        fallback_insert_sized(out, size.max(1));
        return out;
    };

    if allocator_bootstrap_passthrough_active() {
        // SAFETY: early loader/bootstrap aligned allocations must avoid
        // runtime-policy trace state until the runtime-ready boundary.
        let out = unsafe { native_libc_aligned_alloc(alignment, size) };
        fallback_insert_sized(out, size.max(1));
        return out;
    }

    let _trace_scope = runtime_policy::entrypoint_scope("aligned_alloc");
    let req = size.max(1);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate_aligned(req, alignment) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            let out = unsafe { native_libc_aligned_alloc(alignment, req) };
            if !out.is_null() {
                fallback_insert_sized(out, req);
            }
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }

    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// valloc
// ---------------------------------------------------------------------------

/// Legacy `valloc` -- allocates `size` bytes of page-aligned memory.
///
/// Returns a pointer to the allocated memory, or null on failure.
/// Equivalent to `memalign(page_size, size)`.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    let page_sz = page_size();
    unsafe { memalign(page_sz, size) }
}

// ---------------------------------------------------------------------------
// pvalloc
// ---------------------------------------------------------------------------

/// GNU extension `pvalloc` -- allocates memory with page alignment and size
/// rounded up to the next page boundary.
///
/// Returns a pointer to the allocated memory, or null on failure.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    let page_sz = page_size();
    // Round up to next page boundary
    let rounded = match size.checked_add(page_sz - 1) {
        Some(v) => v & !(page_sz - 1),
        None => {
            unsafe { set_abi_errno(ENOMEM as c_int) };
            return std::ptr::null_mut();
        }
    };
    unsafe { memalign(page_sz, rounded) }
}

// ---------------------------------------------------------------------------
// cfree
// ---------------------------------------------------------------------------

/// BSD legacy `cfree` -- identical to `free`. Provided for compatibility.
///
/// # Safety
///
/// Same as `free`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfree(ptr: *mut c_void) {
    unsafe { free(ptr) }
}

// ---------------------------------------------------------------------------
// mallopt
// ---------------------------------------------------------------------------

/// GNU `mallopt` -- set allocator tuning parameters.
///
/// FrankenLibC uses its own allocator with a fixed policy, so the tuning itself
/// is a no-op — but glibc's RETURN contract is preserved: only M_MXFAST
/// (param 1) is range-validated (value must lie in [0, MAX_FAST_SIZE], glibc's
/// `80 * SIZE_SZ / 4` = 160 on LP64), otherwise mallopt returns 0 (failure).
/// Every other parameter is accepted (returns 1), matching glibc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mallopt(param: c_int, value: c_int) -> c_int {
    const M_MXFAST: c_int = 1;
    let max_fast_size = 80 * std::mem::size_of::<usize>() as c_int / 4;
    if param == M_MXFAST && !(0..=max_fast_size).contains(&value) {
        return 0;
    }
    1
}

// ---------------------------------------------------------------------------
// malloc_usable_size
// ---------------------------------------------------------------------------

/// GNU `malloc_usable_size` -- returns the number of usable bytes in the
/// allocation pointed to by `ptr`.
///
/// If `ptr` is null, returns 0.
///
/// # Safety
///
/// `ptr` must be null or a valid pointer returned by `malloc`/`calloc`/`realloc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }

    // Bump/mmap allocations: size is unknown, return 0.
    if is_bump_ptr(ptr) {
        return 0;
    }

    let addr = ptr as usize;

    // Look up in membrane arena first
    if let Some(pipeline) = crate::membrane_state::try_global_pipeline()
        && let Some(slot) = pipeline.arena.lookup(addr)
        && slot.user_base == addr
    {
        return slot.user_size;
    }

    if let Some(size) = fallback_size(ptr) {
        return size;
    }

    // For all other pointers (fallback, host-allocated), return 0.
    // We cannot safely delegate to the host malloc_usable_size because
    // our unversioned export shadows the host's versioned symbol, causing
    // infinite recursion.  Returning 0 is safe — callers that need exact
    // sizes should use their own tracking.
    0
}

// ---------------------------------------------------------------------------
// malloc_trim
// ---------------------------------------------------------------------------

/// GNU `malloc_trim` -- release free memory from the allocator back to the OS.
///
/// Returns 1 if memory was released, 0 otherwise.
/// Since FrankenLibC uses its own arena-based allocator, this is a
/// compatibility stub that returns 1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_trim(_pad: usize) -> c_int {
    1
}

// ---------------------------------------------------------------------------
// mallinfo / mallinfo2
// ---------------------------------------------------------------------------

/// The `mallinfo` struct returned by `mallinfo()`.
///
/// Fields use `c_int` (which truncates on 64-bit systems where total
/// allocations exceed 2 GiB). Use `mallinfo2` for accurate results.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Mallinfo {
    pub arena: c_int,
    pub ordblks: c_int,
    pub smblks: c_int,
    pub hblks: c_int,
    pub hblkhd: c_int,
    pub usmblks: c_int,
    pub fsmblks: c_int,
    pub uordblks: c_int,
    pub fordblks: c_int,
    pub keepcost: c_int,
}

/// The `mallinfo2` struct returned by `mallinfo2()`.
///
/// Same as `mallinfo` but uses `usize` (size_t) fields.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Mallinfo2 {
    pub arena: usize,
    pub ordblks: usize,
    pub smblks: usize,
    pub hblks: usize,
    pub hblkhd: usize,
    pub usmblks: usize,
    pub fsmblks: usize,
    pub uordblks: usize,
    pub fordblks: usize,
    pub keepcost: usize,
}

/// Collect raw allocation statistics from the flat-combining allocator stats state.
fn collect_alloc_stats() -> (usize, usize, usize) {
    let snapshot = snapshot_alloc_stats();
    (
        snapshot.live_bytes,
        snapshot.active_allocations,
        snapshot.peak_usage.max(snapshot.live_bytes),
    )
}

/// GNU `mallinfo` -- returns allocation statistics.
///
/// Note: `c_int` fields truncate values exceeding `i32::MAX`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mallinfo() -> Mallinfo {
    let (allocated, count, capacity) = collect_alloc_stats();
    let free_space = capacity.saturating_sub(allocated);
    Mallinfo {
        arena: capacity.min(c_int::MAX as usize) as c_int,
        ordblks: count.min(c_int::MAX as usize) as c_int,
        smblks: 0,
        hblks: 0,
        hblkhd: 0,
        usmblks: 0,
        fsmblks: 0,
        uordblks: allocated.min(c_int::MAX as usize) as c_int,
        fordblks: free_space.min(c_int::MAX as usize) as c_int,
        keepcost: 0,
    }
}

/// GNU `mallinfo2` -- returns allocation statistics with `size_t` fields.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mallinfo2() -> Mallinfo2 {
    let (allocated, count, capacity) = collect_alloc_stats();
    let free_space = capacity.saturating_sub(allocated);
    Mallinfo2 {
        arena: capacity,
        ordblks: count,
        smblks: 0,
        hblks: 0,
        hblkhd: 0,
        usmblks: 0,
        fsmblks: 0,
        uordblks: allocated,
        fordblks: free_space,
        keepcost: 0,
    }
}

// ---------------------------------------------------------------------------
// malloc_stats
// ---------------------------------------------------------------------------

/// GNU `malloc_stats` -- print allocation statistics to stderr.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_stats() {
    let info = unsafe { mallinfo2() };
    let msg = format!(
        "Arena 0:\nsystem bytes     = {}\nin use bytes     = {}\nTotal (incl. mmap):\nsystem bytes     = {}\nin use bytes     = {}\nmax mmap regions = {}\nmax mmap bytes   = {}\n",
        info.arena, info.uordblks, info.arena, info.uordblks, info.hblks, info.hblkhd,
    );
    // SAFETY: write(2, buf, len) - writing to stderr fd.
    unsafe {
        crate::unistd_abi::write(2, msg.as_ptr().cast(), msg.len());
    }
}

// ---------------------------------------------------------------------------
// malloc_info
// ---------------------------------------------------------------------------

/// GNU `malloc_info` -- print allocation statistics as XML to `stream`.
///
/// `options` must be 0. Returns 0 on success, -1 on error.
///
/// # Safety
///
/// `stream` must be a valid `FILE*` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_info(options: c_int, stream: *mut c_void) -> c_int {
    if options != 0 || stream.is_null() {
        unsafe { set_abi_errno(EINVAL as c_int) };
        return -1;
    }

    let info = unsafe { mallinfo2() };
    let xml = format!(
        "<malloc version=\"1\">\n<heap nr=\"0\">\n<sizes>\n</sizes>\n<total type=\"fast\" count=\"0\" size=\"0\"/>\n<total type=\"rest\" count=\"{}\" size=\"{}\"/>\n<system type=\"current\" size=\"{}\"/>\n<system type=\"max\" size=\"{}\"/>\n<aspace type=\"total\" size=\"{}\"/>\n<aspace type=\"mprotect\" size=\"{}\"/>\n</heap>\n<total type=\"fast\" count=\"0\" size=\"0\"/>\n<total type=\"rest\" count=\"{}\" size=\"{}\"/>\n<system type=\"current\" size=\"{}\"/>\n<system type=\"max\" size=\"{}\"/>\n<aspace type=\"total\" size=\"{}\"/>\n<aspace type=\"mprotect\" size=\"{}\"/>\n</malloc>\n",
        info.ordblks,
        info.uordblks,
        info.arena,
        info.arena,
        info.arena,
        info.arena,
        info.ordblks,
        info.uordblks,
        info.arena,
        info.arena,
        info.arena,
        info.arena,
    );

    // SAFETY: caller guarantees stream is a valid FILE*.
    unsafe extern "C" {
        fn fputs(s: *const std::ffi::c_char, stream: *mut c_void) -> c_int;
    }
    let c_xml = std::ffi::CString::new(xml).unwrap_or_default();
    let rc = unsafe { fputs(c_xml.as_ptr(), stream) };
    if rc < 0 { -1 } else { 0 }
}

// ---------------------------------------------------------------------------
// Helper: page size
// ---------------------------------------------------------------------------

#[inline]
fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) is always safe and returns the page size.
    let ps = unsafe { crate::unistd_abi::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 { ps as usize } else { 4096 }
}

// ===========================================================================
// __libc_* internal aliases — glibc exports these for internal use
// ===========================================================================

/// `__libc_freeres` — release all libc internal resources (no-op).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_freeres() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_metrics_snapshot_jsonl_exports_dashboard_fields() {
        let row: serde_json::Value = serde_json::from_str(
            export_alloc_stats_snapshot_jsonl_from_snapshot(
                MallocStatsSnapshot {
                    allocation_events: 9,
                    free_events: 4,
                    total_allocated: 16_384,
                    total_freed: 6_144,
                    active_allocations: 5,
                    live_bytes: 10_240,
                    peak_usage: 12_288,
                },
                "bd-282v",
                "smoke",
                "hardened",
            )
            .trim(),
        )
        .expect("allocator metrics snapshot should parse");

        assert_eq!(row["event"].as_str(), Some("allocator_metrics_snapshot"));
        assert_eq!(row["api_family"].as_str(), Some("allocator"));
        assert_eq!(row["symbol"].as_str(), Some("malloc::stats"));
        assert_eq!(row["allocations_total"].as_u64(), Some(9));
        assert_eq!(row["frees_total"].as_u64(), Some(4));
        assert_eq!(row["active_allocations"].as_u64(), Some(5));
        assert_eq!(row["bytes_allocated"].as_u64(), Some(10_240));
        assert_eq!(row["total_allocated_bytes"].as_u64(), Some(16_384));
        assert_eq!(row["total_freed_bytes"].as_u64(), Some(6_144));
        assert_eq!(row["peak_usage_bytes"].as_u64(), Some(12_288));
        assert_eq!(row["bead_id"].as_str(), Some("bd-282v"));
        assert_eq!(row["scenario_id"].as_str(), Some("smoke"));
    }

    #[test]
    fn malloc_stats_reset_for_harness_clears_exported_snapshot() {
        malloc_stats_reset_for_harness();
        malloc_stats_record_alloc_for_harness(256);
        malloc_stats_record_alloc_for_harness(128);
        malloc_stats_record_free_for_harness(128);

        let seeded: serde_json::Value = serde_json::from_str(
            export_alloc_stats_snapshot_jsonl("bd-282v", "seeded", "hardened").trim(),
        )
        .expect("seeded allocator snapshot should parse");
        assert_eq!(seeded["allocations_total"].as_u64(), Some(2));
        assert_eq!(seeded["frees_total"].as_u64(), Some(1));
        assert_eq!(seeded["active_allocations"].as_u64(), Some(1));
        assert_eq!(seeded["bytes_allocated"].as_u64(), Some(256));

        malloc_stats_reset_for_harness();

        let cleared: serde_json::Value = serde_json::from_str(
            export_alloc_stats_snapshot_jsonl("bd-282v", "cleared", "hardened").trim(),
        )
        .expect("cleared allocator snapshot should parse");
        assert_eq!(cleared["allocations_total"].as_u64(), Some(0));
        assert_eq!(cleared["frees_total"].as_u64(), Some(0));
        assert_eq!(cleared["active_allocations"].as_u64(), Some(0));
        assert_eq!(cleared["bytes_allocated"].as_u64(), Some(0));
    }
}
