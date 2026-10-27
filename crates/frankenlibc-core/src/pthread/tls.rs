//! POSIX thread-local storage (TLS) key management.
//!
//! Implements `pthread_key_create`, `pthread_key_delete`, `pthread_getspecific`,
//! and `pthread_setspecific` using a global key registry with per-thread value
//! storage via a fixed-size concurrent lookup table.
//!
//! ## Design
//!
//! - **Key registry**: A fixed array of `PTHREAD_KEYS_MAX` (1024) slots protected
//!   by a `Mutex`. Each slot tracks in-use state and optional destructor.
//!
//! - **Per-thread values**: A static open-addressed hash table mapping kernel TID
//!   to a pointer to a `[u64; PTHREAD_KEYS_MAX]` array. For clone-based threads,
//!   the array is embedded in `ThreadHandle` (allocated by the parent). For the
//!   main thread, a separate static block is used.
//!
//! - **Allocation safety**: Registration, lookup, and teardown are completely
//!   allocation-free, which is critical because clone-based threads without
//!   `CLONE_SETTLS` cannot safely call the system allocator (glibc malloc uses
//!   `__thread` per-thread arenas).
//!
//! ## Thread Integration (bd-rth1)
//!
//! The thread trampoline in `thread.rs` calls:
//! - `tls::register_thread_tls(tid, ptr)` after startup (no allocation)
//! - `tls::teardown_thread_tls(tid)` after user function returns (no allocation)

#![allow(unsafe_code)]

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::syscall;

use crate::rcu;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Maximum number of TLS keys (POSIX requires >= 128; glibc uses 1024).
pub const PTHREAD_KEYS_MAX: usize = 1024;

/// Maximum destructor-call iterations on thread exit (POSIX requires >= 4).
pub const PTHREAD_DESTRUCTOR_ITERATIONS: usize = 4;

/// Maximum concurrent threads tracked in the TLS table.
const TLS_TABLE_SLOTS: usize = 4096;

/// Empty slot marker in `TLS_TIDS`.
const TLS_SLOT_EMPTY: i32 = 0;
/// Tombstone marker for deleted slots in `TLS_TIDS`.
///
/// Thread IDs are strictly positive, so `-1` is never a real TID.
const TLS_SLOT_TOMBSTONE: i32 = -1;

const EAGAIN: i32 = 11;
const EINVAL: i32 = 22;

/// Thread-local storage key.
/// Contains the index in the lower 10 bits and the generation sequence in the upper 22 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PthreadKey {
    pub id: u32,
}

/// A thread-local entry containing the generation sequence and the value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct TlsEntry {
    pub seq: u32,
    pub value: u64,
}

// ---------------------------------------------------------------------------
// Global key registry
// ---------------------------------------------------------------------------

/// A single slot in the global key registry.
#[derive(Clone, Copy)]
struct KeySlot {
    in_use: bool,
    destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Generation counter — incremented on create and delete to detect stale keys.
    seq: u32,
}

const EMPTY_SLOT: KeySlot = KeySlot {
    in_use: false,
    destructor: None,
    seq: 0,
};

#[derive(Clone)]
struct KeyRegistry {
    slots: [KeySlot; PTHREAD_KEYS_MAX],
}

/// RCU-protected key registry for lock-free reads on the hot path.
/// Writers serialize via KEY_WRITE_LOCK and publish new versions atomically.
/// Old versions are intentionally leaked (bounded: ~16KB per key lifecycle
/// call, typically < 100 calls in a program's lifetime).
static KEY_REGISTRY_RCU: rcu::RcuDomain<KeyRegistry> = rcu::RcuDomain::new();

/// Writer serialization lock for pthread_key_create / pthread_key_delete.
static KEY_WRITE_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Per-thread value storage — allocation-free concurrent table
// ---------------------------------------------------------------------------

/// TID array for open-addressed hash table.
///
/// - `TLS_SLOT_EMPTY` (`0`) means never occupied and terminates lookups.
/// - `TLS_SLOT_TOMBSTONE` (`-1`) means previously occupied (deleted) and must
///   not terminate lookups.
static TLS_TIDS: [AtomicI32; TLS_TABLE_SLOTS] = [const { AtomicI32::new(0) }; TLS_TABLE_SLOTS];

/// Pointer array (paired with TLS_TIDS). Stores `*mut [TlsEntry; PTHREAD_KEYS_MAX]`
/// cast to usize. 0 = no pointer.
static TLS_PTRS: [AtomicUsize; TLS_TABLE_SLOTS] = [const { AtomicUsize::new(0) }; TLS_TABLE_SLOTS];

// Thread-local fallback values for threads that are not explicitly registered
// in the TID -> pointer table.
//
// This preserves per-thread isolation for host-created threads while remaining
// allocation-free for clone-based threads (which are expected to register).
//
// Layout mirrors glibc (32 inline key slots in the thread descriptor, the rest
// allocated on first use): a full `[TlsEntry; PTHREAD_KEYS_MAX]` inline was
// 16 KB of static TLS on EVERY thread of every preloaded process, and glibc
// carves static TLS out of each thread's stack, so host `pthread_create`
// rejected ordinary small stacks with EINVAL (node/libuv 32 KiB stacks;
// bd-rc0923-epic-eeuy4f.9). Reads of unset high keys never allocate.
#[cfg(not(feature = "owned-tls-cache"))]
const FALLBACK_INLINE_KEYS: usize = 32;

#[cfg(not(feature = "owned-tls-cache"))]
struct FallbackTls {
    inline: [core::cell::Cell<TlsEntry>; FALLBACK_INLINE_KEYS],
    /// Heap block of `PTHREAD_KEYS_MAX - FALLBACK_INLINE_KEYS` entries, or null.
    spill: core::cell::Cell<*mut core::cell::Cell<TlsEntry>>,
}

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static FALLBACK_TLS_VALUES: FallbackTls = const {
        FallbackTls {
            inline: [const { core::cell::Cell::new(TlsEntry { seq: 0, value: 0 }) };
                FALLBACK_INLINE_KEYS],
            spill: core::cell::Cell::new(core::ptr::null_mut()),
        }
    };
}

#[cfg(not(feature = "owned-tls-cache"))]
const FALLBACK_SPILL_KEYS: usize = PTHREAD_KEYS_MAX - FALLBACK_INLINE_KEYS;

#[cfg(not(feature = "owned-tls-cache"))]
impl FallbackTls {
    fn get(&self, key_id: usize) -> TlsEntry {
        if key_id < FALLBACK_INLINE_KEYS {
            return self.inline[key_id].get();
        }
        let spill = self.spill.get();
        if spill.is_null() {
            return TlsEntry::default();
        }
        // SAFETY: `spill` is this thread's live block of FALLBACK_SPILL_KEYS
        // entries; key_id < PTHREAD_KEYS_MAX is checked by callers.
        unsafe { (*spill.add(key_id - FALLBACK_INLINE_KEYS)).get() }
    }

    fn set(&self, key_id: usize, entry: TlsEntry) {
        if key_id < FALLBACK_INLINE_KEYS {
            self.inline[key_id].set(entry);
            return;
        }
        let mut spill = self.spill.get();
        if spill.is_null() {
            if entry.value == 0 {
                // Clearing a never-set high key: nothing to store.
                return;
            }
            // Allocate directly on the heap (a stack temporary of this size
            // would itself overflow the small stacks this layout protects).
            let block: Box<[core::cell::Cell<TlsEntry>]> = (0..FALLBACK_SPILL_KEYS)
                .map(|_| core::cell::Cell::new(TlsEntry::default()))
                .collect();
            spill = Box::into_raw(block).cast::<core::cell::Cell<TlsEntry>>();
            self.spill.set(spill);
        }
        // SAFETY: as in `get`.
        unsafe { (*spill.add(key_id - FALLBACK_INLINE_KEYS)).set(entry) };
    }

    #[cfg(test)]
    fn clear_all(&self) {
        for slot in &self.inline {
            slot.set(TlsEntry::default());
        }
        self.release_spill();
    }

    /// Free the spill block (thread teardown / reset).
    fn release_spill(&self) {
        let spill = self.spill.replace(core::ptr::null_mut());
        if !spill.is_null() {
            // SAFETY: `spill` came from `Box::into_raw` of a boxed slice of
            // exactly FALLBACK_SPILL_KEYS entries and is no longer reachable.
            drop(unsafe {
                Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                    spill,
                    FALLBACK_SPILL_KEYS,
                ))
            });
        }
    }
}

// The standalone owned-TLS artifact lane cannot emit Rust TLS. Preserve the
// same unregistered-thread fallback semantics with a small non-TLS table keyed
// by kernel TID. Native clone-created threads still use TLS_TIDS/TLS_PTRS above.
#[cfg(feature = "owned-tls-cache")]
static FALLBACK_TLS_TIDS: [AtomicI32; TLS_TABLE_SLOTS] =
    [const { AtomicI32::new(TLS_SLOT_EMPTY) }; TLS_TABLE_SLOTS];

#[cfg(feature = "owned-tls-cache")]
static FALLBACK_TLS_PTRS: [AtomicUsize; TLS_TABLE_SLOTS] =
    [const { AtomicUsize::new(0) }; TLS_TABLE_SLOTS];

#[cfg(feature = "owned-tls-cache")]
fn allocate_fallback_tls_block() -> *mut TlsEntry {
    Box::into_raw(Box::new([TlsEntry::default(); PTHREAD_KEYS_MAX])) as *mut TlsEntry
}

#[cfg(feature = "owned-tls-cache")]
fn fallback_tls_block_for_slot(index: usize) -> *mut TlsEntry {
    let values = FALLBACK_TLS_PTRS[index].load(Ordering::Acquire) as *mut TlsEntry;
    if values.is_null() {
        return allocate_fallback_tls_block();
    }
    // A fork child retains other threads' allocations as unassigned blocks.
    // This caller has claimed the slot, so no live thread can access the old
    // values. Clear every key before giving the block to its new owner.
    // SAFETY: only owned fallback allocations are retained in this table;
    // each block contains exactly PTHREAD_KEYS_MAX entries, all zero-valid.
    unsafe { core::ptr::write_bytes(values, 0, PTHREAD_KEYS_MAX) };
    values
}

#[cfg(feature = "owned-tls-cache")]
unsafe fn drop_fallback_tls_block(values_ptr: *mut TlsEntry) {
    if !values_ptr.is_null() {
        // SAFETY: values_ptr was produced by allocate_fallback_tls_block and has
        // not been dropped yet; table_remove/reset ensure single ownership.
        unsafe {
            drop(Box::from_raw(
                values_ptr as *mut [TlsEntry; PTHREAD_KEYS_MAX],
            ));
        }
    }
}

#[cfg(feature = "owned-tls-cache")]
fn fallback_table_lookup(tid: i32) -> *mut TlsEntry {
    if tid <= 0 {
        return core::ptr::null_mut();
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = FALLBACK_TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            return FALLBACK_TLS_PTRS[idx].load(Ordering::Acquire) as *mut TlsEntry;
        }
        if stored_tid == TLS_SLOT_EMPTY {
            return core::ptr::null_mut();
        }
    }
    core::ptr::null_mut()
}

#[cfg(feature = "owned-tls-cache")]
fn fallback_table_get_or_insert(tid: i32) -> *mut TlsEntry {
    if tid <= 0 {
        return core::ptr::null_mut();
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    let mut first_tombstone: Option<usize> = None;
    let mut owned_ptr: *mut TlsEntry = core::ptr::null_mut();

    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let current = FALLBACK_TLS_TIDS[idx].load(Ordering::Acquire);
        if current == tid {
            if !owned_ptr.is_null() {
                // SAFETY: owned_ptr was allocated in this call and never stored.
                unsafe { drop_fallback_tls_block(owned_ptr) };
            }
            return FALLBACK_TLS_PTRS[idx].load(Ordering::Acquire) as *mut TlsEntry;
        }

        if current == TLS_SLOT_TOMBSTONE {
            if first_tombstone.is_none() {
                first_tombstone = Some(idx);
            }
            continue;
        }

        if current == TLS_SLOT_EMPTY {
            let target = first_tombstone.unwrap_or(idx);
            let expected = if first_tombstone.is_some() {
                TLS_SLOT_TOMBSTONE
            } else {
                TLS_SLOT_EMPTY
            };
            if FALLBACK_TLS_TIDS[target]
                .compare_exchange(expected, tid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if owned_ptr.is_null() {
                    owned_ptr = fallback_tls_block_for_slot(target);
                }
                FALLBACK_TLS_PTRS[target].store(owned_ptr as usize, Ordering::Release);
                return owned_ptr;
            }
            first_tombstone = None;
        }
    }

    if let Some(tomb_idx) = first_tombstone
        && FALLBACK_TLS_TIDS[tomb_idx]
            .compare_exchange(TLS_SLOT_TOMBSTONE, tid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        if owned_ptr.is_null() {
            owned_ptr = fallback_tls_block_for_slot(tomb_idx);
        }
        FALLBACK_TLS_PTRS[tomb_idx].store(owned_ptr as usize, Ordering::Release);
        return owned_ptr;
    }

    if !owned_ptr.is_null() {
        // SAFETY: owned_ptr was allocated in this call and never stored.
        unsafe { drop_fallback_tls_block(owned_ptr) };
    }
    core::ptr::null_mut()
}

#[cfg(feature = "owned-tls-cache")]
fn fallback_table_remove(tid: i32) -> *mut TlsEntry {
    if tid <= 0 {
        return core::ptr::null_mut();
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = FALLBACK_TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            let ptr = FALLBACK_TLS_PTRS[idx].swap(0, Ordering::AcqRel);
            FALLBACK_TLS_TIDS[idx].store(TLS_SLOT_TOMBSTONE, Ordering::Release);
            return ptr as *mut TlsEntry;
        }
        if stored_tid == TLS_SLOT_EMPTY {
            return core::ptr::null_mut();
        }
    }
    core::ptr::null_mut()
}

/// Register a TID → values-pointer mapping in the global table.
///
/// This function is **allocation-free** and safe to call from clone-based threads.
fn table_register(tid: i32, values_ptr: *mut TlsEntry) {
    if tid <= 0 {
        return;
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    let mut first_tombstone: Option<usize> = None;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let current = TLS_TIDS[idx].load(Ordering::Acquire);
        if current == tid {
            // Already registered (shouldn't happen, but handle gracefully).
            TLS_PTRS[idx].store(values_ptr as usize, Ordering::Release);
            return;
        }

        if current == TLS_SLOT_TOMBSTONE {
            if first_tombstone.is_none() {
                first_tombstone = Some(idx);
            }
            continue;
        }

        if current == TLS_SLOT_EMPTY {
            if let Some(tomb_idx) = first_tombstone {
                if TLS_TIDS[tomb_idx]
                    .compare_exchange(TLS_SLOT_TOMBSTONE, tid, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    TLS_PTRS[tomb_idx].store(values_ptr as usize, Ordering::Release);
                    return;
                }
                first_tombstone = None;
                continue;
            }

            if TLS_TIDS[idx]
                .compare_exchange(TLS_SLOT_EMPTY, tid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                TLS_PTRS[idx].store(values_ptr as usize, Ordering::Release);
                return;
            }
        }
    }
    // Table full. Best effort: if we observed a tombstone, retry claiming it.
    if let Some(tomb_idx) = first_tombstone
        && TLS_TIDS[tomb_idx]
            .compare_exchange(TLS_SLOT_TOMBSTONE, tid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        TLS_PTRS[tomb_idx].store(values_ptr as usize, Ordering::Release);
    }
}

/// Look up the TLS values pointer for a given TID.
///
/// Returns a raw pointer to `[TlsEntry; PTHREAD_KEYS_MAX]`, or null if not found.
/// **Allocation-free.**
pub(crate) fn table_lookup(tid: i32) -> *mut TlsEntry {
    if tid <= 0 {
        return core::ptr::null_mut();
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            let ptr = TLS_PTRS[idx].load(Ordering::Acquire);
            return ptr as *mut TlsEntry;
        }
        if stored_tid == TLS_SLOT_EMPTY {
            return core::ptr::null_mut();
        }
    }
    core::ptr::null_mut()
}

/// Remove a TID from the table and return its values pointer.
///
/// **Allocation-free.**
fn table_remove(tid: i32) -> *mut TlsEntry {
    if tid <= 0 {
        return core::ptr::null_mut();
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            let ptr = TLS_PTRS[idx].swap(0, Ordering::AcqRel);
            TLS_TIDS[idx].store(TLS_SLOT_TOMBSTONE, Ordering::Release);
            return ptr as *mut TlsEntry;
        }
        if stored_tid == TLS_SLOT_EMPTY {
            return core::ptr::null_mut();
        }
    }
    core::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Thread identification
// ---------------------------------------------------------------------------

/// Get the calling thread's kernel TID.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn current_tid() -> i32 {
    if TID_CACHE_DISABLED.load(Ordering::Relaxed) {
        return syscall::sys_gettid();
    }
    let epoch = TID_CACHE_EPOCH.load(Ordering::Acquire);
    if let Ok((tid, cached_epoch)) = CACHED_TID.try_with(core::cell::Cell::get)
        && tid > 0
        && cached_epoch == epoch
    {
        return tid;
    }
    let tid = syscall::sys_gettid();
    let _ = CACHED_TID.try_with(|cached| cached.set((tid, epoch)));
    tid
}

std::thread_local! {
    /// This thread's kernel tid and the fork epoch it was read in. Every
    /// pthread_getspecific/setspecific needs the tid, and asking the kernel
    /// each time made them a syscall each (glibc reads it from the TCB);
    /// OpenSSL calls them constantly.
    static CACHED_TID: core::cell::Cell<(i32, u32)> = const { core::cell::Cell::new((0, 0)) };
}

/// Bumped in a fork child: it inherits the forking thread's TLS, cached tid
/// included, under a new tid.
static TID_CACHE_EPOCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Set before the first native-backend thread is cloned: those threads share
/// their creator's TLS (no CLONE_SETTLS), so a TLS-cached tid would be the
/// creator's.
static TID_CACHE_DISABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Rebuild one inherited TID table around the sole surviving thread.
///
/// Old hash positions cannot be relabeled: the child's new TID has a different
/// probe sequence. Native blocks are borrowed from their ThreadHandles; only
/// the survivor remains reachable. Owned fallback blocks for vanished threads
/// remain unassigned and are cleared/reused by the next slot claimant. No
/// allocator, destructor, lock, or caller callback runs in this fork hook.
fn rekey_fork_child_table(
    tids: &[AtomicI32; TLS_TABLE_SLOTS],
    pointers: &[AtomicUsize; TLS_TABLE_SLOTS],
    parent_tid: i32,
    child_tid: i32,
    retain_unused_blocks: bool,
) {
    let survivor_index = tids
        .iter()
        .position(|tid| tid.load(Ordering::Acquire) == parent_tid);
    let survivor = survivor_index
        .map(|index| pointers[index].swap(0, Ordering::AcqRel))
        .unwrap_or(0);
    for index in 0..TLS_TABLE_SLOTS {
        tids[index].store(TLS_SLOT_EMPTY, Ordering::Release);
        if !retain_unused_blocks {
            pointers[index].store(0, Ordering::Release);
        }
    }
    if survivor != 0 {
        let destination = child_tid as u32 as usize % TLS_TABLE_SLOTS;
        let spare = pointers[destination].swap(survivor, Ordering::AcqRel);
        if let Some(source) = survivor_index
            && spare != 0
        {
            // Keep the displaced owned allocation in the survivor's vacated
            // slot. Native tables were cleared above and never enter here.
            pointers[source].store(spare, Ordering::Release);
        }
        tids[destination].store(child_tid, Ordering::Release);
    }
}

/// Call first thing in a fork child, before anything reads a TLS key.
///
/// # Safety
/// The caller is the sole surviving thread in a freshly forked address space,
/// and parent_tid is its kernel TID captured before fork. Inherited table
/// metadata must not be accessed concurrently while it is rebuilt.
pub unsafe fn note_fork_child(parent_tid: i32) {
    let child_tid = syscall::sys_gettid();
    rekey_fork_child_table(&TLS_TIDS, &TLS_PTRS, parent_tid, child_tid, false);
    #[cfg(feature = "owned-tls-cache")]
    rekey_fork_child_table(
        &FALLBACK_TLS_TIDS,
        &FALLBACK_TLS_PTRS,
        parent_tid,
        child_tid,
        true,
    );
    TID_CACHE_EPOCH.fetch_add(1, Ordering::AcqRel);
}

/// Call before cloning a thread that shares its creator's TLS.
pub(crate) fn disable_tid_cache() {
    TID_CACHE_DISABLED.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Internal: read/write per-thread TLS value
// ---------------------------------------------------------------------------

/// Read a TLS value for the given TID and key index.
/// Falls back to thread-local storage if the TID is not in the table.
fn read_tls_value(tid: i32, key_id: usize, expected_seq: u32) -> u64 {
    let ptr = table_lookup(tid);
    if !ptr.is_null() {
        // SAFETY: ptr points to a valid `[TlsEntry; PTHREAD_KEYS_MAX]` that is either
        // embedded in a ThreadHandle (alive while the thread runs) or in a
        // test-allocated block. key_id < PTHREAD_KEYS_MAX checked by caller.
        let entry = unsafe { *ptr.add(key_id) };
        if entry.seq == expected_seq {
            entry.value
        } else {
            0
        }
    } else {
        // Unregistered thread: use thread-local fallback storage.
        #[cfg(not(feature = "owned-tls-cache"))]
        {
            FALLBACK_TLS_VALUES.with(|values| {
                let entry = values.get(key_id);
                if entry.seq == expected_seq {
                    entry.value
                } else {
                    0
                }
            })
        }
        #[cfg(feature = "owned-tls-cache")]
        {
            let fallback_ptr = fallback_table_lookup(tid);
            if fallback_ptr.is_null() {
                return 0;
            }
            // SAFETY: fallback_ptr points to an owned fallback block for this
            // kernel TID. key_id < PTHREAD_KEYS_MAX checked by caller.
            let entry = unsafe { *fallback_ptr.add(key_id) };
            if entry.seq == expected_seq {
                entry.value
            } else {
                0
            }
        }
    }
}

/// Write a TLS value for the given TID and key index.
/// Falls back to thread-local storage if the TID is not in the table.
fn write_tls_value(tid: i32, key_id: usize, expected_seq: u32, value: u64) {
    let ptr = table_lookup(tid);
    if !ptr.is_null() {
        // SAFETY: ptr points to a valid `[TlsEntry; PTHREAD_KEYS_MAX]` owned by this
        // thread. Only the owning thread writes to its own values.
        unsafe {
            *ptr.add(key_id) = TlsEntry {
                seq: expected_seq,
                value,
            }
        };
    } else {
        // Unregistered thread: use thread-local fallback storage.
        #[cfg(not(feature = "owned-tls-cache"))]
        {
            FALLBACK_TLS_VALUES.with(|values| {
                values.set(
                    key_id,
                    TlsEntry {
                        seq: expected_seq,
                        value,
                    },
                );
            });
        }
        #[cfg(feature = "owned-tls-cache")]
        {
            let fallback_ptr = fallback_table_get_or_insert(tid);
            if fallback_ptr.is_null() {
                return;
            }
            // SAFETY: fallback_ptr points to an owned fallback block for this
            // kernel TID. Only the owning thread writes its fallback values.
            unsafe {
                *fallback_ptr.add(key_id) = TlsEntry {
                    seq: expected_seq,
                    value,
                };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Publish `registry` as the new RCU version, allocating it with `mmap`
/// rather than on the heap.
///
/// pthread_key_create must not call malloc: a program that brings its own
/// allocator creates keys while initialising it (jemalloc's malloc_tsd_boot0,
/// in rustc among others), and a heap allocation here re-entered that half-
/// initialised allocator, which returned NULL, and fl's allocation-failure
/// handler aborted the process ('memory allocation of 16384 bytes failed').
/// glibc keeps its keys in static storage. Versions are never freed (the RCU
/// update leaks the old one by design), so a private anonymous mapping per
/// version costs nothing extra; the heap is only the fallback if mmap fails.
fn publish_registry(registry: KeyRegistry) -> *mut KeyRegistry {
    use crate::mmap::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
    // SAFETY: a fresh private anonymous mapping, owned by nobody else.
    let mapped = unsafe {
        syscall::sys_mmap(
            core::ptr::null_mut(),
            core::mem::size_of::<KeyRegistry>(),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let new_ptr = match mapped {
        // Page-aligned, so aligned for KeyRegistry.
        Ok(address) => address.cast::<KeyRegistry>(),
        Err(_) => return Box::into_raw(Box::new(registry)),
    };
    // SAFETY: `new_ptr` is a writable, suitably aligned KeyRegistry-sized block.
    unsafe { new_ptr.write(registry) };
    new_ptr
}

/// Creates a thread-local storage key.
///
/// Equivalent to C `pthread_key_create`. The optional `destructor` is called
/// when a thread exits with a non-null value for this key.
///
/// Returns 0 on success, `EAGAIN` if all keys are in use.
pub fn pthread_key_create(
    key: &mut PthreadKey,
    destructor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> i32 {
    let _write_guard = KEY_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Read current registry via RCU and clone it.
    let mut new_reg = unsafe {
        match KEY_REGISTRY_RCU.read() {
            Some(r) => (*r).clone(),
            None => KeyRegistry {
                slots: [EMPTY_SLOT; PTHREAD_KEYS_MAX],
            },
        }
    };

    for i in 0..PTHREAD_KEYS_MAX {
        if !new_reg.slots[i].in_use {
            new_reg.slots[i].in_use = true;
            new_reg.slots[i].destructor = destructor;
            new_reg.slots[i].seq = new_reg.slots[i].seq.wrapping_add(1);
            let seq = new_reg.slots[i].seq;
            key.id = (seq << 10) | (i as u32);

            // Publish new version via RCU.
            let new_ptr = publish_registry(new_reg);
            let _old_ptr = unsafe { KEY_REGISTRY_RCU.update(new_ptr) };
            // Old version is intentionally leaked. key_create is called O(1)
            // times; each version is ~16KB. Avoids QSBR synchronize deadlocks.
            return 0;
        }
    }
    EAGAIN
}

/// Deletes a thread-local storage key.
///
/// Equivalent to C `pthread_key_delete`. Per POSIX, this does NOT call
/// destructors and does not affect values already set in existing threads.
///
/// Returns 0 on success, `EINVAL` if the key is invalid.
pub fn pthread_key_delete(key: PthreadKey) -> i32 {
    let id = (key.id & 1023) as usize;
    let expected_seq = key.id >> 10;
    if id >= PTHREAD_KEYS_MAX {
        return EINVAL;
    }
    let _write_guard = KEY_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Read current registry via RCU and clone it.
    let mut new_reg = unsafe {
        match KEY_REGISTRY_RCU.read() {
            Some(r) => (*r).clone(),
            None => return EINVAL, // No registry = no keys exist.
        }
    };

    if !new_reg.slots[id].in_use || new_reg.slots[id].seq != expected_seq {
        return EINVAL;
    }
    new_reg.slots[id].in_use = false;
    new_reg.slots[id].destructor = None;
    new_reg.slots[id].seq = new_reg.slots[id].seq.wrapping_add(1);

    // Publish new version via RCU.
    let new_ptr = publish_registry(new_reg);
    let _old_ptr = unsafe { KEY_REGISTRY_RCU.update(new_ptr) };
    // Old version intentionally leaked (same rationale as key_create).
    0
}

/// Gets the value associated with the TLS key for the calling thread.
///
/// Equivalent to C `pthread_getspecific`. Returns the value, or 0 if
/// no value has been set (or the key is invalid).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn pthread_getspecific(key: PthreadKey) -> u64 {
    let id = (key.id & 1023) as usize;
    let expected_seq = key.id >> 10;
    if id >= PTHREAD_KEYS_MAX {
        return 0;
    }
    let tid = current_tid();
    read_tls_value(tid, id, expected_seq)
}

/// Sets the value associated with the TLS key for the calling thread.
///
/// Equivalent to C `pthread_setspecific`. Returns 0 on success, `EINVAL`
/// if the key is invalid or deleted.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn pthread_setspecific(key: PthreadKey, value: u64) -> i32 {
    let id = (key.id & 1023) as usize;
    let expected_seq = key.id >> 10;
    if id >= PTHREAD_KEYS_MAX {
        return EINVAL;
    }
    let tid = current_tid();

    // Ensure RCU registration for lock-free reads.
    let _ = rcu::rcu_register_thread(tid as u32);

    // Validate key is active via RCU read (no mutex).
    rcu::rcu_read_lock();
    let in_use = unsafe {
        match KEY_REGISTRY_RCU.read() {
            Some(reg) => reg.slots[id].in_use && reg.slots[id].seq == expected_seq,
            None => false,
        }
    };
    rcu::rcu_read_unlock();
    rcu::rcu_quiescent_state(tid as u32);

    if !in_use {
        return EINVAL;
    }
    write_tls_value(tid, id, expected_seq, value);
    0
}

// ---------------------------------------------------------------------------
// Thread lifecycle integration (called from thread.rs trampoline)
// ---------------------------------------------------------------------------

/// Register a thread's TLS values pointer in the global table.
///
/// `values_ptr` must point to a `[u64; PTHREAD_KEYS_MAX]` array that lives
/// at least as long as the thread. For clone-based threads, this is the
/// `tls_values` field in `ThreadHandle`.
///
/// **Allocation-free** — safe to call from clone-based threads.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn register_thread_tls(tid: i32, values_ptr: *mut TlsEntry) {
    table_register(tid, values_ptr);
    // Register with RCU for lock-free KEY_REGISTRY reads.
    let _ = rcu::rcu_register_thread(tid as u32);
}

/// Run the POSIX key destructors of the exiting thread `tid`: the hook for
/// threads whose lifecycle belongs to the host libc, which never sees fl's key
/// table (the native clone trampoline calls [`teardown_thread_tls`] itself).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn run_exiting_thread_key_destructors(tid: i32) {
    teardown_thread_tls(tid);
}

/// Run TLS destructors for an exiting thread and remove its table entry.
///
/// The registered-thread path is allocation-free and uses constant stack
/// space, including when all keys have destructors on a minimum-size stack.
///
/// Per POSIX, destructors are called up to `PTHREAD_DESTRUCTOR_ITERATIONS`
/// times. Each key's value is cleared immediately before invoking its
/// destructor, with no registry guard held over application code. Re-read
/// the registry for the next key: a destructor may delete or replace it.
///
/// After all iterations, the thread's table entry is removed.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn teardown_thread_tls(tid: i32) {
    let values_ptr = table_lookup(tid);
    // Native threads own the block in their ThreadHandle. Their inherited
    // hardware TLS can still belong to the creator, so neither access nor
    // reclaim fallback storage when this registered block exists.
    let registered = !values_ptr.is_null();
    #[cfg(feature = "owned-tls-cache")]
    let fallback_values_ptr = if registered {
        core::ptr::null_mut()
    } else {
        fallback_table_lookup(tid)
    };

    // Ensure RCU registration for lock-free registry reads. Required for the
    // registered-thread path; the fallback path also needs an RCU read lock to
    // snapshot the key registry safely.
    let _ = rcu::rcu_register_thread(tid as u32);

    for _iteration in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        let mut called = false;
        for index in 0..PTHREAD_KEYS_MAX {
            rcu::rcu_read_lock();
            // SAFETY: the read section protects the immutable registry. Copy
            // one slot so no registry reference escapes into a destructor.
            let slot = unsafe { KEY_REGISTRY_RCU.read().map(|reg| reg.slots[index]) };
            rcu::rcu_read_unlock();
            let Some(slot) = slot.filter(|slot| slot.in_use) else {
                continue;
            };

            let value = if registered {
                // SAFETY: this thread exclusively owns its registered block,
                // which remains live until all destructor rounds finish.
                let entry = unsafe { &mut *values_ptr.add(index) };
                if entry.seq == slot.seq {
                    core::mem::replace(&mut entry.value, 0)
                } else {
                    0
                }
            } else {
                #[cfg(not(feature = "owned-tls-cache"))]
                {
                    FALLBACK_TLS_VALUES.with(|values| {
                        let entry = values.get(index);
                        if entry.seq == slot.seq && entry.value != 0 {
                            values.set(
                                index,
                                TlsEntry {
                                    seq: entry.seq,
                                    value: 0,
                                },
                            );
                            entry.value
                        } else {
                            0
                        }
                    })
                }
                #[cfg(feature = "owned-tls-cache")]
                {
                    if fallback_values_ptr.is_null() {
                        0
                    } else {
                        // SAFETY: this unregistered thread owns the fallback
                        // block until it is removed below, after all callbacks.
                        let entry = unsafe { &mut *fallback_values_ptr.add(index) };
                        if entry.seq == slot.seq {
                            core::mem::replace(&mut entry.value, 0)
                        } else {
                            0
                        }
                    }
                }
            };
            if value != 0
                && let Some(dtor) = slot.destructor
            {
                called = true;
                // QSBR read_unlock is a no-op: explicitly leave the read
                // period before running application code.
                rcu::rcu_quiescent_state(tid as u32);
                // SAFETY: the callback was registered for this generation,
                // and the owning thread's value was cleared before the call.
                unsafe { dtor(value as *mut c_void) };
            }
        }
        rcu::rcu_quiescent_state(tid as u32);
        if !called {
            break;
        }
    }

    if registered {
        table_remove(tid);
    } else {
        // Only unregistered threads own fallback storage. A native child must
        // not release its creator's high-key spill block on its way out.
        #[cfg(not(feature = "owned-tls-cache"))]
        let _ = FALLBACK_TLS_VALUES.try_with(FallbackTls::release_spill);
        #[cfg(feature = "owned-tls-cache")]
        {
            let fallback_ptr = fallback_table_remove(tid);
            // SAFETY: removal transfers ownership of the fallback allocation.
            unsafe { drop_fallback_tls_block(fallback_ptr) };
        }
    }
    let _ = rcu::rcu_unregister_thread(tid as u32);
}

// ---------------------------------------------------------------------------
// Test support: reset global state between tests
// ---------------------------------------------------------------------------

/// Reset all TLS global state. For testing only.
#[cfg(test)]
pub(crate) fn reset_tls_state() {
    // Reset RCU global state (epoch, reader slots, callbacks).
    crate::rcu::reset_rcu_state();

    // Publish a fresh empty registry. The old version is leaked like every
    // other: versions come from `publish_registry` (mmap, heap only as a
    // fallback), so there is no single right way to free one.
    let fresh = publish_registry(KeyRegistry {
        slots: [EMPTY_SLOT; PTHREAD_KEYS_MAX],
    });
    let _old = unsafe { KEY_REGISTRY_RCU.update(fresh) };

    // Clear the table.
    for i in 0..TLS_TABLE_SLOTS {
        TLS_TIDS[i].store(TLS_SLOT_EMPTY, Ordering::Release);
        TLS_PTRS[i].store(0, Ordering::Release);
    }
    // Clear fallback values for the current thread.
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        FALLBACK_TLS_VALUES.with(FallbackTls::clear_all);
    }
    #[cfg(feature = "owned-tls-cache")]
    {
        for i in 0..TLS_TABLE_SLOTS {
            let ptr = FALLBACK_TLS_PTRS[i].swap(0, Ordering::AcqRel);
            FALLBACK_TLS_TIDS[i].store(TLS_SLOT_EMPTY, Ordering::Release);
            // SAFETY: reset runs under the serialized test lock after global
            // state has been quiesced; each stored pointer is owned by the
            // fallback table.
            unsafe { drop_fallback_tls_block(ptr as *mut TlsEntry) };
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as AtomicOrdering};

    /// Acquire the shared RCU/TLS test lock and reset global state.
    fn lock_and_reset() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::rcu::rcu_test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_tls_state();
        guard
    }

    /// Helper: create a key, return it.
    fn create_key(dtor: Option<unsafe extern "C" fn(*mut c_void)>) -> PthreadKey {
        let mut key = PthreadKey::default();
        let rc = pthread_key_create(&mut key, dtor);
        assert_eq!(rc, 0, "pthread_key_create failed");
        key
    }

    /// Per-thread values block for tests (heap-allocated, registered in table).
    struct TestTlsBlock {
        values: [TlsEntry; PTHREAD_KEYS_MAX],
    }

    impl TestTlsBlock {
        fn new() -> Box<Self> {
            Box::new(Self {
                values: [TlsEntry::default(); PTHREAD_KEYS_MAX],
            })
        }

        fn as_mut_ptr(&mut self) -> *mut TlsEntry {
            self.values.as_mut_ptr()
        }

        /// Set a value for a key, encoding the correct sequence.
        fn set(&mut self, key: &PthreadKey, value: u64) {
            let idx = (key.id & 1023) as usize;
            let seq = key.id >> 10;
            self.values[idx] = TlsEntry { seq, value };
        }
    }

    /// Helper: extract key's slot index and sequence.
    fn key_parts(key: &PthreadKey) -> (usize, u32) {
        ((key.id & 1023) as usize, key.id >> 10)
    }

    #[test]
    fn key_create_returns_zero() {
        let _g = lock_and_reset();
        let mut key = PthreadKey::default();
        assert_eq!(pthread_key_create(&mut key, None), 0);
    }

    #[test]
    fn key_create_assigns_different_ids() {
        let _g = lock_and_reset();
        let k1 = create_key(None);
        let k2 = create_key(None);
        assert_ne!(k1.id, k2.id, "two keys should have different IDs");
    }

    #[test]
    fn key_delete_returns_zero() {
        let _g = lock_and_reset();
        let key = create_key(None);
        assert_eq!(pthread_key_delete(key), 0);
    }

    #[test]
    fn key_delete_invalid_returns_einval() {
        let _g = lock_and_reset();
        let key = PthreadKey { id: 9999 };
        assert_eq!(pthread_key_delete(key), EINVAL);
    }

    #[test]
    fn key_delete_already_deleted_returns_einval() {
        let _g = lock_and_reset();
        let key = create_key(None);
        assert_eq!(pthread_key_delete(key), 0);
        assert_eq!(pthread_key_delete(key), EINVAL);
    }

    #[test]
    fn key_delete_slot_reused() {
        let _g = lock_and_reset();
        let k1 = create_key(None);
        let slot1 = k1.id & 1023; // Extract slot index from lower 10 bits
        assert_eq!(pthread_key_delete(k1), 0);
        let k2 = create_key(None);
        let slot2 = k2.id & 1023;
        assert_eq!(slot2, slot1, "deleted slot should be reused");
        // Full ID differs because generation counter increments on create and delete
        assert_ne!(k2.id, k1.id, "generation should differ after delete+create");
    }

    #[test]
    fn key_exhaustion_returns_eagain() {
        let _g = lock_and_reset();
        for _ in 0..PTHREAD_KEYS_MAX {
            let _ = create_key(None);
        }
        let mut key = PthreadKey::default();
        assert_eq!(pthread_key_create(&mut key, None), EAGAIN);
    }

    #[test]
    fn getspecific_default_is_zero() {
        let _g = lock_and_reset();
        let key = create_key(None);
        assert_eq!(pthread_getspecific(key), 0);
    }

    #[test]
    fn setspecific_and_getspecific_roundtrip() {
        let _g = lock_and_reset();
        let key = create_key(None);
        assert_eq!(pthread_setspecific(key, 0xDEAD_BEEF), 0);
        assert_eq!(pthread_getspecific(key), 0xDEAD_BEEF);
    }

    #[test]
    fn fork_child_table_rekeys_collisions_and_preserves_only_owned_spares() {
        for retain_unused in [false, true] {
            // Private tables keep this hash-placement check independent of
            // other tests' live thread state. The old probe chain intersects
            // the child's destination and contains a second vanished thread.
            let tids = [const { AtomicI32::new(0) }; TLS_TABLE_SLOTS];
            let pointers = [const { AtomicUsize::new(0) }; TLS_TABLE_SLOTS];
            tids[100].store(100, Ordering::Relaxed);
            pointers[100].store(0x1000, Ordering::Relaxed);
            tids[101].store(100 + TLS_TABLE_SLOTS as i32, Ordering::Relaxed);
            pointers[101].store(0x2000, Ordering::Relaxed);
            tids[102].store(101 + TLS_TABLE_SLOTS as i32, Ordering::Relaxed);
            pointers[102].store(0x3000, Ordering::Relaxed);

            rekey_fork_child_table(&tids, &pointers, 100, 101, retain_unused);

            assert_eq!(tids[101].load(Ordering::Relaxed), 101);
            assert_eq!(pointers[101].load(Ordering::Relaxed), 0x1000);
            assert_eq!(
                tids.iter()
                    .filter(|tid| tid.load(Ordering::Relaxed) != TLS_SLOT_EMPTY)
                    .count(),
                1,
                "only the survivor remains a live thread"
            );
            assert_eq!(
                pointers[100].load(Ordering::Relaxed),
                if retain_unused { 0x2000 } else { 0 },
                "only owned fallback storage may be retained for reuse"
            );
            assert_eq!(
                pointers[102].load(Ordering::Relaxed),
                if retain_unused { 0x3000 } else { 0 }
            );
        }
    }

    #[test]
    fn fork_child_preserves_values_and_destructor_rounds() {
        let _g = lock_and_reset();
        static KEY: AtomicU32 = AtomicU32::new(0);
        static ROUNDS: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn rearm(value: *mut c_void) {
            ROUNDS.fetch_add(1, AtomicOrdering::SeqCst);
            if (value as usize) < 3 {
                let key = PthreadKey {
                    id: KEY.load(AtomicOrdering::SeqCst),
                };
                if pthread_setspecific(key, value as u64 + 1) != 0 {
                    syscall::sys_exit_group(102);
                }
            }
        }
        let key = create_key(Some(rearm));
        KEY.store(key.id, AtomicOrdering::SeqCst);
        ROUNDS.store(0, AtomicOrdering::SeqCst);
        assert_eq!(pthread_setspecific(key, 1), 0);
        let parent_tid = syscall::sys_gettid();
        #[cfg(feature = "owned-tls-cache")]
        let spare_tid = parent_tid + TLS_TABLE_SLOTS as i32;
        #[cfg(feature = "owned-tls-cache")]
        {
            let (index, sequence) = key_parts(&key);
            write_tls_value(spare_tid, index, sequence, 77);
        }

        unsafe extern "C" {
            fn fork() -> i32;
        }
        // SAFETY: the host fork resets its allocator/runtime locks. The child
        // uses the production fork hook and exits without returning to the
        // test harness or dropping its inherited serialization guard.
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // SAFETY: this is the sole surviving thread in the copied process.
            unsafe { note_fork_child(parent_tid) };
            if pthread_getspecific(key) != 1 {
                syscall::sys_exit_group(103);
            }
            #[cfg(feature = "owned-tls-cache")]
            {
                if !fallback_table_lookup(parent_tid).is_null()
                    || (spare_tid != syscall::sys_gettid()
                        && !fallback_table_lookup(spare_tid).is_null())
                {
                    syscall::sys_exit_group(104);
                }
                // Claim a retained spare directly by its empty table slot.
                // Reuse must clear stale key values instead of inheriting a
                // vanished thread's data, and must not allocate another block.
                let spare = FALLBACK_TLS_TIDS
                    .iter()
                    .zip(FALLBACK_TLS_PTRS.iter())
                    .position(|(tid, ptr)| {
                        tid.load(Ordering::Acquire) == TLS_SLOT_EMPTY
                            && ptr.load(Ordering::Acquire) != 0
                    });
                let Some(index) = spare else {
                    syscall::sys_exit_group(105)
                };
                let reusable = FALLBACK_TLS_PTRS[index].load(Ordering::Acquire);
                let fresh_tid = index as i32 + TLS_TABLE_SLOTS as i32;
                let reused = fallback_table_get_or_insert(fresh_tid);
                let (key_index, sequence) = key_parts(&key);
                if reused as usize != reusable
                    || read_tls_value(fresh_tid, key_index, sequence) != 0
                {
                    syscall::sys_exit_group(106);
                }
                // This is owned fallback storage, reclaimed after host fork
                // has reset the allocator; native borrowed blocks never enter.
                unsafe { drop_fallback_tls_block(fallback_table_remove(fresh_tid)) };
            }
            teardown_thread_tls(syscall::sys_gettid());
            if ROUNDS.load(AtomicOrdering::SeqCst) != 3 || pthread_getspecific(key) != 0 {
                syscall::sys_exit_group(107);
            }
            syscall::sys_exit_group(0);
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut status = 0;
        loop {
            // SAFETY: status is writable and pid names this test's own child.
            match unsafe { syscall::sys_wait4(pid, &mut status, 1, core::ptr::null_mut()) } {
                Ok(0) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Ok(found) if found == pid => break,
                Err(4) if std::time::Instant::now() < deadline => continue,
                other => {
                    let _ = syscall::sys_kill(pid, 9);
                    // SAFETY: reap only this test's child after a timeout/error.
                    let _ =
                        unsafe { syscall::sys_wait4(pid, &mut status, 0, core::ptr::null_mut()) };
                    panic!("fork child did not finish: {other:?}");
                }
            }
        }
        assert_eq!(status, 0, "fork child rejected inherited TLS state");
        assert_eq!(pthread_getspecific(key), 1, "child mutated parent TLS");
        assert_eq!(ROUNDS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(pthread_setspecific(key, 0), 0);
        assert_eq!(pthread_key_delete(key), 0);
    }

    #[test]
    fn setspecific_invalid_key_returns_einval() {
        let _g = lock_and_reset();
        let key = create_key(None);
        assert_eq!(pthread_key_delete(key), 0);
        assert_eq!(pthread_setspecific(key, 42), EINVAL);
    }

    #[test]
    fn multiple_keys_independent() {
        let _g = lock_and_reset();
        let k1 = create_key(None);
        let k2 = create_key(None);
        assert_eq!(pthread_setspecific(k1, 100), 0);
        assert_eq!(pthread_setspecific(k2, 200), 0);
        assert_eq!(pthread_getspecific(k1), 100);
        assert_eq!(pthread_getspecific(k2), 200);
    }

    #[test]
    fn setspecific_overwrites_previous_value() {
        let _g = lock_and_reset();
        let key = create_key(None);
        assert_eq!(pthread_setspecific(key, 1), 0);
        assert_eq!(pthread_setspecific(key, 2), 0);
        assert_eq!(pthread_getspecific(key), 2);
    }

    #[test]
    fn registered_thread_has_isolated_values() {
        let _g = lock_and_reset();
        let key = create_key(None);
        let tid = current_tid();

        // Register a test TLS block for the current thread.
        let mut block = TestTlsBlock::new();
        let ptr = block.as_mut_ptr();
        table_register(tid, ptr);

        // Set via the registered block.
        assert_eq!(pthread_setspecific(key, 42), 0);
        assert_eq!(pthread_getspecific(key), 42);

        // Clean up.
        table_remove(tid);
        // After removal, falls back to main thread block (value = 0).
        assert_eq!(pthread_getspecific(key), 0);
    }

    #[test]
    fn destructor_called_on_teardown() {
        let _g = lock_and_reset();
        static DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        DTOR_COUNT.store(0, AtomicOrdering::SeqCst);

        unsafe extern "C" fn dtor(_val: *mut c_void) {
            DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }

        let key = create_key(Some(dtor));
        let tid = current_tid();

        let mut block = TestTlsBlock::new();
        block.set(&key, 42);
        let ptr = block.as_mut_ptr();
        table_register(tid, ptr);

        teardown_thread_tls(tid);
        assert_eq!(DTOR_COUNT.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn registered_teardown_preserves_fallback_values_and_spill() {
        let _g = lock_and_reset();
        static CALLS: AtomicU32 = AtomicU32::new(0);
        static SUM: AtomicU64 = AtomicU64::new(0);
        CALLS.store(0, AtomicOrdering::SeqCst);
        SUM.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(value: *mut c_void) {
            CALLS.fetch_add(1, AtomicOrdering::SeqCst);
            SUM.fetch_add(value as u64, AtomicOrdering::SeqCst);
        }

        // Populate both inline and high-key fallback storage before adding a
        // registered block. A native clone inherits this same hardware TLS.
        let keys: Vec<_> = (0..40).map(|_| create_key(Some(dtor))).collect();
        assert_eq!(pthread_setspecific(keys[0], 11), 0);
        assert_eq!(pthread_setspecific(keys[39], 33), 0);
        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.set(&keys[0], 22);
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        assert_eq!(CALLS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(SUM.load(AtomicOrdering::SeqCst), 22);
        assert_eq!(pthread_getspecific(keys[0]), 11);
        assert_eq!(
            pthread_getspecific(keys[39]),
            33,
            "creator spill was reclaimed"
        );

        // The surviving owner still gets both callbacks at its own teardown.
        teardown_thread_tls(tid);
        assert_eq!(CALLS.load(AtomicOrdering::SeqCst), 3);
        assert_eq!(SUM.load(AtomicOrdering::SeqCst), 66);
    }

    #[test]
    fn destructor_can_observe_and_replace_a_later_key() {
        let _g = lock_and_reset();
        static NEXT_KEY: AtomicU32 = AtomicU32::new(0);
        static OBSERVED: AtomicU64 = AtomicU64::new(0);
        static RECEIVED: AtomicU64 = AtomicU64::new(0);
        static CALLS: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn first(_: *mut c_void) {
            let next = PthreadKey {
                id: NEXT_KEY.load(AtomicOrdering::SeqCst),
            };
            OBSERVED.store(pthread_getspecific(next), AtomicOrdering::SeqCst);
            let _ = pthread_setspecific(next, 33);
        }
        unsafe extern "C" fn second(value: *mut c_void) {
            RECEIVED.store(value as u64, AtomicOrdering::SeqCst);
            CALLS.fetch_add(1, AtomicOrdering::SeqCst);
        }

        for registered in [false, true] {
            OBSERVED.store(0, AtomicOrdering::SeqCst);
            RECEIVED.store(0, AtomicOrdering::SeqCst);
            CALLS.store(0, AtomicOrdering::SeqCst);
            let first = create_key(Some(first));
            let second = create_key(Some(second));
            NEXT_KEY.store(second.id, AtomicOrdering::SeqCst);
            let tid = current_tid();
            let mut block = TestTlsBlock::new();
            if registered {
                table_register(tid, block.as_mut_ptr());
            }
            assert_eq!(pthread_setspecific(first, 11), 0);
            assert_eq!(pthread_setspecific(second, 22), 0);

            teardown_thread_tls(tid);

            assert_eq!(OBSERVED.load(AtomicOrdering::SeqCst), 22);
            assert_eq!(RECEIVED.load(AtomicOrdering::SeqCst), 33);
            assert_eq!(CALLS.load(AtomicOrdering::SeqCst), 1);
            assert_eq!(pthread_key_delete(first), 0);
            assert_eq!(pthread_key_delete(second), 0);
        }
    }

    #[test]
    fn destructor_can_delete_and_recreate_a_later_key() {
        let _g = lock_and_reset();
        static NEXT_KEY: AtomicU32 = AtomicU32::new(0);
        static OLD_CALLS: AtomicU32 = AtomicU32::new(0);
        static NEW_VALUE: AtomicU64 = AtomicU64::new(0);
        static ERRORS: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn old(_: *mut c_void) {
            OLD_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
        }
        unsafe extern "C" fn replacement(value: *mut c_void) {
            NEW_VALUE.fetch_add(value as u64, AtomicOrdering::SeqCst);
        }
        unsafe extern "C" fn first(_: *mut c_void) {
            let next = PthreadKey {
                id: NEXT_KEY.load(AtomicOrdering::SeqCst),
            };
            if pthread_key_delete(next) != 0 {
                ERRORS.fetch_add(1, AtomicOrdering::SeqCst);
                return;
            }
            let mut new_key = PthreadKey::default();
            if pthread_key_create(&mut new_key, Some(replacement)) != 0 {
                ERRORS.fetch_add(1, AtomicOrdering::SeqCst);
                return;
            }
            NEXT_KEY.store(new_key.id, AtomicOrdering::SeqCst);
            if pthread_setspecific(new_key, 33) != 0 {
                ERRORS.fetch_add(1, AtomicOrdering::SeqCst);
            }
        }

        for registered in [false, true] {
            OLD_CALLS.store(0, AtomicOrdering::SeqCst);
            NEW_VALUE.store(0, AtomicOrdering::SeqCst);
            ERRORS.store(0, AtomicOrdering::SeqCst);
            let first = create_key(Some(first));
            let second = create_key(Some(old));
            NEXT_KEY.store(second.id, AtomicOrdering::SeqCst);
            let tid = current_tid();
            let mut block = TestTlsBlock::new();
            if registered {
                table_register(tid, block.as_mut_ptr());
            }
            assert_eq!(pthread_setspecific(first, 11), 0);
            assert_eq!(pthread_setspecific(second, 22), 0);

            teardown_thread_tls(tid);

            assert_eq!(ERRORS.load(AtomicOrdering::SeqCst), 0);
            assert_eq!(OLD_CALLS.load(AtomicOrdering::SeqCst), 0);
            assert_eq!(NEW_VALUE.load(AtomicOrdering::SeqCst), 33);
            assert_eq!(pthread_key_delete(first), 0);
            assert_eq!(
                pthread_key_delete(PthreadKey {
                    id: NEXT_KEY.load(AtomicOrdering::SeqCst)
                }),
                0
            );
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn native_minimum_stack_runs_key_destructors() {
        let _g = lock_and_reset();
        static KEY: AtomicU32 = AtomicU32::new(0);
        static CALLS: AtomicU32 = AtomicU32::new(0);
        CALLS.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(value: *mut c_void) {
            CALLS.fetch_add(1, AtomicOrdering::SeqCst);
            if value as usize == 1 {
                let key = PthreadKey {
                    id: KEY.load(AtomicOrdering::SeqCst),
                };
                let _ = pthread_setspecific(key, 2);
            }
        }
        unsafe extern "C" fn worker(_: usize) -> usize {
            let key = PthreadKey {
                id: KEY.load(AtomicOrdering::SeqCst),
            };
            pthread_setspecific(key, 1) as usize
        }
        let key = create_key(Some(dtor));
        KEY.store(key.id, AtomicOrdering::SeqCst);

        // SAFETY: the worker and destructor reference only live static state;
        // join waits for the kernel to finish using the guarded native stack.
        let handle = unsafe {
            super::super::thread::create_thread(worker as *const () as usize, 0, 16 * 1024)
        }
        .expect("minimum-size native stack");
        assert_eq!(unsafe { super::super::thread::join_thread(handle) }, Ok(0));
        assert_eq!(CALLS.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(pthread_key_delete(key), 0);
    }

    #[test]
    fn fallback_tls_destructor_runs_on_unregistered_teardown() {
        let _g = lock_and_reset();
        static DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        static DTOR_VALUE: AtomicU64 = AtomicU64::new(0);
        DTOR_COUNT.store(0, AtomicOrdering::SeqCst);
        DTOR_VALUE.store(0, AtomicOrdering::SeqCst);

        unsafe extern "C" fn dtor(val: *mut c_void) {
            DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
            DTOR_VALUE.store(val as u64, AtomicOrdering::SeqCst);
        }

        let key = create_key(Some(dtor));
        let tid = current_tid();
        assert!(
            table_lookup(tid).is_null(),
            "test starts on fallback TLS path"
        );

        assert_eq!(pthread_setspecific(key, 0xBEEF), 0);
        assert_eq!(pthread_getspecific(key), 0xBEEF);

        teardown_thread_tls(tid);

        assert_eq!(DTOR_COUNT.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(DTOR_VALUE.load(AtomicOrdering::SeqCst), 0xBEEF);
        assert_eq!(
            pthread_getspecific(key),
            0,
            "fallback TLS value should be cleared before teardown returns"
        );
    }

    #[test]
    fn destructor_iterates_when_value_reset() {
        let _g = lock_and_reset();
        static ITER_COUNT: AtomicU32 = AtomicU32::new(0);
        ITER_COUNT.store(0, AtomicOrdering::SeqCst);
        static KEY_ID: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn dtor_reset(val: *mut c_void) {
            let count = ITER_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
            if count < 2 {
                // Re-set the value so teardown iterates again.
                let key = PthreadKey {
                    id: KEY_ID.load(AtomicOrdering::SeqCst),
                };
                let _ = pthread_setspecific(key, val as u64 + 1);
            }
        }

        let key = create_key(Some(dtor_reset));
        KEY_ID.store(key.id, AtomicOrdering::SeqCst);

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.set(&key, 1);
        let ptr = block.as_mut_ptr();
        table_register(tid, ptr);

        teardown_thread_tls(tid);
        let count = ITER_COUNT.load(AtomicOrdering::SeqCst);
        assert!(count >= 3, "destructor should iterate: got {count}");
    }

    #[test]
    fn teardown_removes_table_entry() {
        let _g = lock_and_reset();
        let key = create_key(None);
        let (idx, seq) = key_parts(&key);
        let tid = current_tid();

        let mut block = TestTlsBlock::new();
        let ptr = block.as_mut_ptr();
        table_register(tid, ptr);

        write_tls_value(tid, idx, seq, 99);
        assert_eq!(read_tls_value(tid, idx, seq), 99);

        teardown_thread_tls(tid);

        // After teardown, table entry removed — falls back to main block.
        assert_eq!(read_tls_value(tid, idx, seq), 0);
    }

    #[test]
    fn no_destructor_means_no_call() {
        let _g = lock_and_reset();
        let key = create_key(None); // No destructor.
        let tid = current_tid();

        let mut block = TestTlsBlock::new();
        block.set(&key, 42);
        let ptr = block.as_mut_ptr();
        table_register(tid, ptr);

        // Teardown should complete without error.
        teardown_thread_tls(tid);
    }

    // -----------------------------------------------------------------------
    // Additional edge-case and adversarial tests (bd-1j2u, bd-122j)
    // -----------------------------------------------------------------------

    #[test]
    fn getspecific_out_of_bounds_key_returns_zero() {
        let _g = lock_and_reset();
        let key = PthreadKey {
            id: PTHREAD_KEYS_MAX as u32 + 1,
        };
        assert_eq!(pthread_getspecific(key), 0);
    }

    #[test]
    fn setspecific_out_of_bounds_key_returns_einval() {
        let _g = lock_and_reset();
        let key = PthreadKey {
            id: PTHREAD_KEYS_MAX as u32 + 1,
        };
        assert_eq!(pthread_setspecific(key, 42), EINVAL);
    }

    #[test]
    fn key_create_delete_create_reuses_slot_with_new_destructor() {
        let _g = lock_and_reset();
        static DTOR1_COUNT: AtomicU32 = AtomicU32::new(0);
        static DTOR2_COUNT: AtomicU32 = AtomicU32::new(0);
        DTOR1_COUNT.store(0, AtomicOrdering::SeqCst);
        DTOR2_COUNT.store(0, AtomicOrdering::SeqCst);

        unsafe extern "C" fn dtor1(_: *mut c_void) {
            DTOR1_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }
        unsafe extern "C" fn dtor2(_: *mut c_void) {
            DTOR2_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }

        let k1 = create_key(Some(dtor1));
        let slot1 = k1.id & 1023; // Extract slot index
        assert_eq!(pthread_key_delete(k1), 0);

        // Create with a different destructor — should reuse the same slot.
        let k2 = create_key(Some(dtor2));
        let slot2 = k2.id & 1023;
        assert_eq!(slot2, slot1, "slot should be reused");

        // Set a value and tear down to verify the new destructor fires.
        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.set(&k2, 99);
        table_register(tid, block.as_mut_ptr());
        teardown_thread_tls(tid);

        assert_eq!(
            DTOR1_COUNT.load(AtomicOrdering::SeqCst),
            0,
            "old destructor should not fire"
        );
        assert_eq!(
            DTOR2_COUNT.load(AtomicOrdering::SeqCst),
            1,
            "new destructor should fire"
        );
    }

    #[test]
    fn generation_counter_increments_on_create_and_delete() {
        let _g = lock_and_reset();
        let k = create_key(None);
        let slot = (k.id & 1023) as usize; // Extract slot index from lower 10 bits

        // Read initial seq via RCU.
        let seq_after_create = unsafe {
            KEY_REGISTRY_RCU
                .read()
                .map(|r| r.slots[slot].seq)
                .unwrap_or(0)
        };
        assert!(seq_after_create >= 1, "seq should be >= 1 after create");

        assert_eq!(pthread_key_delete(k), 0);
        let seq_after_delete = unsafe {
            KEY_REGISTRY_RCU
                .read()
                .map(|r| r.slots[slot].seq)
                .unwrap_or(0)
        };
        assert_eq!(
            seq_after_delete,
            seq_after_create + 1,
            "seq should increment on delete"
        );
    }

    #[test]
    fn table_register_same_tid_twice_overwrites() {
        let _g = lock_and_reset();
        let tid = current_tid();

        let mut block1 = TestTlsBlock::new();
        block1.values[0] = TlsEntry { seq: 0, value: 111 };
        table_register(tid, block1.as_mut_ptr());
        assert_eq!(read_tls_value(tid, 0, 0), 111);

        // Re-register with a different block.
        let mut block2 = TestTlsBlock::new();
        block2.values[0] = TlsEntry { seq: 0, value: 222 };
        table_register(tid, block2.as_mut_ptr());
        assert_eq!(read_tls_value(tid, 0, 0), 222);

        table_remove(tid);
    }

    #[test]
    fn double_teardown_is_safe() {
        let _g = lock_and_reset();
        let tid = current_tid();

        let mut block = TestTlsBlock::new();
        table_register(tid, block.as_mut_ptr());
        teardown_thread_tls(tid);
        // Second teardown should be a no-op (entry already removed).
        teardown_thread_tls(tid);
    }

    #[test]
    fn table_remove_nonexistent_tid_returns_null() {
        let _g = lock_and_reset();
        let ptr = table_remove(99999);
        assert!(ptr.is_null());
    }

    #[test]
    fn table_lookup_nonexistent_tid_returns_null() {
        let _g = lock_and_reset();
        let ptr = table_lookup(99999);
        assert!(ptr.is_null());
    }

    #[test]
    fn table_remove_keeps_collision_probe_chain_intact() {
        let _g = lock_and_reset();
        let tid_a = 1_i32;
        let tid_b = tid_a + TLS_TABLE_SLOTS as i32;

        let mut block_a = TestTlsBlock::new();
        let mut block_b = TestTlsBlock::new();
        block_a.values[0] = TlsEntry { seq: 0, value: 111 };
        block_b.values[0] = TlsEntry { seq: 0, value: 222 };

        table_register(tid_a, block_a.as_mut_ptr());
        table_register(tid_b, block_b.as_mut_ptr());

        assert!(!table_lookup(tid_a).is_null());
        assert!(!table_lookup(tid_b).is_null());

        let removed = table_remove(tid_a);
        assert!(!removed.is_null());

        let ptr_b = table_lookup(tid_b);
        assert!(
            !ptr_b.is_null(),
            "collision-chain lookup broke after removing earlier slot"
        );
        // SAFETY: ptr_b points to block_b values for key index 0.
        assert_eq!(unsafe { (*ptr_b).value }, 222);
    }

    #[test]
    fn table_register_reuses_tombstone_without_hiding_colliders() {
        let _g = lock_and_reset();
        let tid_a = 5_i32;
        let tid_b = tid_a + TLS_TABLE_SLOTS as i32;
        let tid_c = tid_b + TLS_TABLE_SLOTS as i32;

        let mut block_a = TestTlsBlock::new();
        let mut block_b = TestTlsBlock::new();
        let mut block_c = TestTlsBlock::new();
        block_a.values[0] = TlsEntry { seq: 0, value: 11 };
        block_b.values[0] = TlsEntry { seq: 0, value: 22 };
        block_c.values[0] = TlsEntry { seq: 0, value: 33 };

        table_register(tid_a, block_a.as_mut_ptr());
        table_register(tid_b, block_b.as_mut_ptr());
        let _ = table_remove(tid_a);

        table_register(tid_c, block_c.as_mut_ptr());

        let ptr_b = table_lookup(tid_b);
        let ptr_c = table_lookup(tid_c);
        assert!(
            !ptr_b.is_null(),
            "existing collider should remain discoverable"
        );
        assert!(
            !ptr_c.is_null(),
            "new collider should be inserted successfully"
        );
        // SAFETY: ptr_b/ptr_c point to valid test blocks for key index 0.
        assert_eq!(unsafe { (*ptr_b).value }, 22);
        // SAFETY: ptr_b/ptr_c point to valid test blocks for key index 0.
        assert_eq!(unsafe { (*ptr_c).value }, 33);
    }

    #[test]
    fn many_keys_independent_values() {
        let _g = lock_and_reset();
        const N: usize = 64;
        let mut keys = Vec::with_capacity(N);
        for _ in 0..N {
            keys.push(create_key(None));
        }
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(pthread_setspecific(*k, (i + 1) as u64), 0);
        }
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(pthread_getspecific(*k), (i + 1) as u64);
        }
    }

    /// Keys beyond the 32 inline fallback slots live in a lazily allocated
    /// spill block (bd-rc0923-epic-eeuy4f.9). Unset high keys read 0 without
    /// allocating; set ones round-trip, run their destructor at teardown, and
    /// the block is released so a later value starts from zero.
    #[test]
    fn fallback_spill_keys_roundtrip_destruct_and_release() {
        let _g = lock_and_reset();
        static DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        DTOR_COUNT.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(_val: *mut c_void) {
            DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }
        let tid = current_tid();
        assert!(
            table_lookup(tid).is_null(),
            "test starts on fallback TLS path"
        );
        let mut keys = Vec::new();
        for _ in 0..40 {
            keys.push(create_key(Some(dtor)));
        }
        let high = keys[39];
        assert_eq!(pthread_getspecific(high), 0);
        #[cfg(not(feature = "owned-tls-cache"))]
        FALLBACK_TLS_VALUES.with(|f| assert!(f.spill.get().is_null(), "read must not allocate"));
        #[cfg(feature = "owned-tls-cache")]
        assert!(
            fallback_table_lookup(tid).is_null(),
            "read must not allocate"
        );
        assert_eq!(pthread_setspecific(high, 0x5151), 0);
        assert_eq!(pthread_getspecific(high), 0x5151);
        assert_eq!(
            pthread_getspecific(keys[38]),
            0,
            "neighbouring spill key unaffected"
        );
        teardown_thread_tls(tid);
        assert_eq!(DTOR_COUNT.load(AtomicOrdering::SeqCst), 1);
        #[cfg(not(feature = "owned-tls-cache"))]
        FALLBACK_TLS_VALUES.with(|f| assert!(f.spill.get().is_null(), "teardown frees spill"));
        #[cfg(feature = "owned-tls-cache")]
        assert!(fallback_table_lookup(tid).is_null(), "teardown frees block");
        assert_eq!(pthread_getspecific(high), 0);
    }

    #[test]
    fn key_delete_does_not_call_destructors() {
        let _g = lock_and_reset();
        static DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        DTOR_COUNT.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(_: *mut c_void) {
            DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }

        let key = create_key(Some(dtor));
        assert_eq!(pthread_setspecific(key, 42), 0);
        // Per POSIX, key_delete does NOT call destructors.
        assert_eq!(pthread_key_delete(key), 0);
        assert_eq!(DTOR_COUNT.load(AtomicOrdering::SeqCst), 0);
    }

    #[test]
    fn setspecific_zero_value_is_valid() {
        let _g = lock_and_reset();
        let key = create_key(None);
        assert_eq!(pthread_setspecific(key, 42), 0);
        assert_eq!(pthread_getspecific(key), 42);
        // Setting to 0 is explicitly valid.
        assert_eq!(pthread_setspecific(key, 0), 0);
        assert_eq!(pthread_getspecific(key), 0);
    }

    #[test]
    fn destructor_not_called_for_zero_value() {
        let _g = lock_and_reset();
        static DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        DTOR_COUNT.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(_: *mut c_void) {
            DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }

        let _key = create_key(Some(dtor));
        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        // Value is 0 (default) — destructor should NOT be called.
        table_register(tid, block.as_mut_ptr());
        teardown_thread_tls(tid);
        assert_eq!(DTOR_COUNT.load(AtomicOrdering::SeqCst), 0);
    }

    // -----------------------------------------------------------------------
    // Destructor pass policy tests (bd-14gj)
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_keys_all_destructors_fire() {
        let _g = lock_and_reset();
        static DTOR_SUM: AtomicU32 = AtomicU32::new(0);
        DTOR_SUM.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(val: *mut c_void) {
            DTOR_SUM.fetch_add(val as u32, AtomicOrdering::SeqCst);
        }

        const N: usize = 8;
        let mut keys = Vec::with_capacity(N);
        for _ in 0..N {
            keys.push(create_key(Some(dtor)));
        }

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        for (i, k) in keys.iter().enumerate() {
            block.set(k, (i + 1) as u64);
        }
        table_register(tid, block.as_mut_ptr());
        teardown_thread_tls(tid);

        // Sum of 1..=8 = 36
        assert_eq!(DTOR_SUM.load(AtomicOrdering::SeqCst), 36);
    }

    #[test]
    fn destructor_iteration_is_bounded_at_max() {
        let _g = lock_and_reset();
        static DTOR_CALLS: AtomicU32 = AtomicU32::new(0);
        static KEY_SLOT: AtomicU32 = AtomicU32::new(0);
        DTOR_CALLS.store(0, AtomicOrdering::SeqCst);

        // This destructor always re-sets the value, forcing iteration.
        unsafe extern "C" fn dtor_always_reset(_val: *mut c_void) {
            let count = DTOR_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
            // Always re-set, even past the iteration limit.
            let key = PthreadKey {
                id: KEY_SLOT.load(AtomicOrdering::SeqCst),
            };
            let _ = pthread_setspecific(key, (count as u64) + 100);
        }

        let key = create_key(Some(dtor_always_reset));
        KEY_SLOT.store(key.id, AtomicOrdering::SeqCst);

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.set(&key, 1);
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        let calls = DTOR_CALLS.load(AtomicOrdering::SeqCst);
        // Should be bounded by PTHREAD_DESTRUCTOR_ITERATIONS (4).
        assert!(
            calls <= PTHREAD_DESTRUCTOR_ITERATIONS as u32,
            "destructor calls ({calls}) should be bounded by PTHREAD_DESTRUCTOR_ITERATIONS ({})",
            PTHREAD_DESTRUCTOR_ITERATIONS
        );
        assert!(
            calls >= 1,
            "destructor should have been called at least once"
        );
    }

    #[test]
    fn mixed_destructors_some_with_some_without() {
        let _g = lock_and_reset();
        static WITH_DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        WITH_DTOR_COUNT.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(_: *mut c_void) {
            WITH_DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }

        // Create 4 keys: 2 with destructor, 2 without.
        let k_with_1 = create_key(Some(dtor));
        let k_without_1 = create_key(None);
        let k_with_2 = create_key(Some(dtor));
        let k_without_2 = create_key(None);

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.set(&k_with_1, 10);
        block.set(&k_without_1, 20);
        block.set(&k_with_2, 30);
        block.set(&k_without_2, 40);
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        // Only the 2 keys with destructors should fire.
        assert_eq!(WITH_DTOR_COUNT.load(AtomicOrdering::SeqCst), 2);
    }

    #[test]
    fn destructor_receives_correct_value() {
        let _g = lock_and_reset();
        static RECEIVED_VALUE: AtomicU64 = AtomicU64::new(0);
        RECEIVED_VALUE.store(0, AtomicOrdering::SeqCst);
        unsafe extern "C" fn dtor(val: *mut c_void) {
            RECEIVED_VALUE.store(val as u64, AtomicOrdering::SeqCst);
        }

        let key = create_key(Some(dtor));
        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.set(&key, 0xCAFE_BABE);
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        assert_eq!(RECEIVED_VALUE.load(AtomicOrdering::SeqCst), 0xCAFE_BABE);
    }

    #[test]
    fn destructor_clears_value_before_calling() {
        let _g = lock_and_reset();
        static OBSERVED_VALUES: Mutex<Vec<u64>> = Mutex::new(Vec::new());
        static KEY_SLOT2: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn dtor_check_cleared(val: *mut c_void) {
            OBSERVED_VALUES.lock().unwrap().push(val as u64);
            // Read the value for this key — it should already be cleared to 0.
            let key = PthreadKey {
                id: KEY_SLOT2.load(AtomicOrdering::SeqCst),
            };
            let current = pthread_getspecific(key);
            // The value was cleared before destructor was called.
            // If we're on a registered thread, it should be 0.
            // (On main/fallback thread it might differ, but the contract is clear.)
            assert_eq!(current, 0, "value should be cleared before destructor runs");
        }

        let key = create_key(Some(dtor_check_cleared));
        KEY_SLOT2.store(key.id, AtomicOrdering::SeqCst);
        {
            let mut v = OBSERVED_VALUES.lock().unwrap();
            v.clear();
        }

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.values[(key.id & 1023) as usize] = TlsEntry {
            seq: key.id >> 10,
            value: 777,
        };
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        let vals = OBSERVED_VALUES.lock().unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0], 777, "destructor should receive the original value");
    }
}
