//! POSIX thread-local storage (TLS) key management.
//!
//! Implements `pthread_key_create`, `pthread_key_delete`, `pthread_getspecific`,
//! and `pthread_setspecific` using a global key registry with per-thread value
//! storage via a fixed-size concurrent lookup table.
//!
//! ## Design
//!
//! - **Key registry**: 1024 public POSIX slots, plus private runtime and
//!   scratch-cache slots, with serialized publication.
//!
//! - **Per-thread values**: A static open-addressed hash table mapping kernel TID
//!   to a pointer to a `[TlsEntry; TLS_KEY_SLOTS]` array. For clone-based threads,
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

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Maximum number of TLS keys (POSIX requires >= 128; glibc uses 1024).
pub const PTHREAD_KEYS_MAX: usize = 1024;

// Internal libc scratch state must remain available to application key
// destructors, and exhausting public keys must not break an unrelated libc
// call. Native policy state also needs these keys when hosted scratch caches
// retain their compiler-TLS fast path. Keep the public budget unchanged.
const INTERNAL_TLS_KEYS_MAX: usize = 128;
pub(crate) const TLS_KEY_SLOTS: usize = PTHREAD_KEYS_MAX + INTERNAL_TLS_KEYS_MAX;

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

/// Encode a positive `tid` (`>= 1`) into a transient negative claiming sentinel
/// (`<= -3`) so an asynchronous signal handler interrupting the same thread mid-CAS
/// detects self-reentry immediately instead of spinning forever.
#[inline]
const fn tls_slot_claiming_for_tid(tid: i32) -> i32 {
    if tid >= i32::MAX - 1 {
        i32::MIN
    } else if tid <= 1 {
        -3
    } else {
        -(tid + 2)
    }
}

#[inline]
const fn is_tls_slot_claiming(stored: i32) -> bool {
    stored <= -2
}

const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;

/// Thread-local storage key.
/// Contains the index in the lower 10 bits and the generation sequence in the upper 22 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PthreadKey {
    pub id: u32,
}

/// Private libc key domain, reclaimed after application thread destructors.
#[doc(hidden)]
#[derive(Clone, Copy, Default)]
pub struct InternalTlsKey {
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

/// Ten low bits encode the slot. Retire a slot when its generation no longer
/// fits in the key, so a long-lived thread's stale value can never match again.
const LAST_KEY_GENERATION: u32 = u32::MAX >> 10;

// Allocators create keys during bootstrap, so registry storage must already
// exist. Permanently retaining a new snapshot per update exhausted memory in
// processes that repeatedly created and deleted keys.
struct KeySlot {
    /// Odd when allocated, even when free. Writers hold KeyRegistryWriteGuard.
    generation: AtomicU32,
    destructor: core::sync::atomic::AtomicPtr<()>,
}

impl KeySlot {
    const EMPTY: Self = Self {
        generation: AtomicU32::new(0),
        destructor: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    };

    /// Seeing the destructor store for a later key also observes the earlier
    /// deletion, so the second generation check rejects the mixed snapshot.
    fn snapshot(&self) -> Option<(u32, *mut ())> {
        let generation = self.generation.load(Ordering::Acquire);
        if generation & 1 == 0 {
            return None;
        }
        let destructor = self.destructor.load(Ordering::Acquire);
        (self.generation.load(Ordering::Acquire) == generation).then_some((generation, destructor))
    }
}

static KEY_SLOTS: [KeySlot; TLS_KEY_SLOTS] = [const { KeySlot::EMPTY }; TLS_KEY_SLOTS];

/// PID/TID of the key-registry writer. A fork child may take ownership from a
/// vanished parent writer instead of inheriting a permanently locked mutex.
static KEY_WRITE_OWNER: AtomicU64 = AtomicU64::new(0);

struct KeyRegistryWriteGuard;

impl KeyRegistryWriteGuard {
    fn lock() -> Self {
        let pid = syscall::sys_getpid() as u32 as u64;
        let owner = (pid << 32) | syscall::sys_gettid() as u32 as u64;
        loop {
            let current = KEY_WRITE_OWNER.load(Ordering::Acquire);
            if (current == 0 || current >> 32 != pid)
                && KEY_WRITE_OWNER
                    .compare_exchange(current, owner, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return Self;
            }
            syscall::sys_sched_yield();
        }
    }
}

impl Drop for KeyRegistryWriteGuard {
    fn drop(&mut self) {
        KEY_WRITE_OWNER.store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Per-thread value storage — allocation-free concurrent table
// ---------------------------------------------------------------------------

/// TID array for open-addressed hash table.
///
/// - `TLS_SLOT_EMPTY` (`0`) means never occupied and terminates lookups.
/// - `TLS_SLOT_TOMBSTONE` (`-1`) means previously occupied (deleted) and must
///   not terminate lookups.
static TLS_TIDS: [AtomicI32; TLS_TABLE_SLOTS] = [const { AtomicI32::new(0) }; TLS_TABLE_SLOTS];

/// Pointer array (paired with TLS_TIDS). Stores `*mut [TlsEntry; TLS_KEY_SLOTS]`
/// cast to usize. 0 = no pointer.
static TLS_PTRS: [AtomicUsize; TLS_TABLE_SLOTS] = [const { AtomicUsize::new(0) }; TLS_TABLE_SLOTS];

/// Native cancellation belongs to one registration, not a reusable handle
/// address. The low bit is pending; the remaining bits identify the lifetime.
/// Remote callers update this static word without dereferencing a handle that
/// a detached thread could concurrently free. Removal retires the generation
/// before the pointer is cleared, so an in-flight request cannot hit a new
/// occupant of either the table slot or the allocation.
static TLS_CANCEL_WORDS: [AtomicU64; TLS_TABLE_SLOTS] =
    [const { AtomicU64::new(0) }; TLS_TABLE_SLOTS];
static TLS_CANCEL_FLAGS: [AtomicU32; TLS_TABLE_SLOTS] =
    [const { AtomicU32::new(0) }; TLS_TABLE_SLOTS];
static NEXT_CANCEL_GENERATION: AtomicU64 = AtomicU64::new(2);
const CANCEL_PENDING: u64 = 1;

/// Per-registration cancellation state flags observed by `pthread_cancel` to
/// decide whether `NATIVE_SIGCANCEL` should interrupt a kernel wait or async loop.
pub const CANCEL_FLAG_DISABLED: u32 = 1 << 0;
pub const CANCEL_FLAG_ASYNC: u32 = 1 << 1;
pub const CANCEL_FLAG_IN_POINT: u32 = 1 << 2;

const UNREGISTERED_CANCEL_SLOTS: usize = 64;
static UNREGISTERED_CANCEL_USED: AtomicBool = AtomicBool::new(false);
static UNREGISTERED_CANCEL_TIDS: [AtomicI32; UNREGISTERED_CANCEL_SLOTS] =
    [const { AtomicI32::new(TLS_SLOT_EMPTY) }; UNREGISTERED_CANCEL_SLOTS];
static UNREGISTERED_CANCEL_WORDS: [AtomicU64; UNREGISTERED_CANCEL_SLOTS] =
    [const { AtomicU64::new(0) }; UNREGISTERED_CANCEL_SLOTS];
static UNREGISTERED_CANCEL_FLAGS: [AtomicU32; UNREGISTERED_CANCEL_SLOTS] =
    [const { AtomicU32::new(0) }; UNREGISTERED_CANCEL_SLOTS];

/// Whether a target thread's flags warrant delivering `NATIVE_SIGCANCEL`.
#[inline]
pub const fn native_cancel_signal_needed(flags: u32) -> bool {
    (flags & CANCEL_FLAG_DISABLED) == 0 && (flags & (CANCEL_FLAG_IN_POINT | CANCEL_FLAG_ASYNC)) != 0
}

/// One native thread's cancellation word for a wait on multiple futexes.
///
/// The word has static storage, even after the registration or handle retires.
/// Only the owning thread obtains a descriptor, and it must obtain a fresh one
/// after changing cancellation state. The marker keeps copies on that thread.
/// Rust accesses the complete atomic word; the kernel alone reads its low half.
#[derive(Clone, Copy)]
pub struct CancellationWait {
    word: &'static AtomicU64,
    generation: u64,
    tid: i32,
    owner: core::marker::PhantomData<*const ()>,
}

impl CancellationWait {
    /// Kernel TID of the owning thread when this wait descriptor was obtained.
    #[inline]
    pub fn tid(&self) -> i32 {
        self.tid
    }

    /// Aligned address of the pending bit's 32-bit word for a private futex.
    #[inline]
    pub fn address(&self) -> *const u32 {
        cancellation_word_address(self.word)
    }

    /// Value to compare before parking. A pending request always differs.
    #[inline]
    pub fn expected(&self) -> u32 {
        self.generation as u32
    }

    /// Inspect this registration's request without consuming it.
    ///
    /// Comparing the complete generation prevents an old descriptor from
    /// reporting a replacement occupant's request, including low-word wrap.
    #[inline]
    pub fn pending(&self) -> bool {
        self.word.load(Ordering::SeqCst) == (self.generation | CANCEL_PENDING)
    }
}

#[inline]
fn cancellation_word_address(word: &AtomicU64) -> *const u32 {
    let address = word.as_ptr().cast::<u32>();
    #[cfg(target_endian = "big")]
    // SAFETY: the low half is the second aligned u32 within this u64.
    let address = unsafe { address.add(1) };
    address
}

fn publish_tls_slot(index: usize, values_ptr: *mut TlsEntry, generation: u64) {
    TLS_CANCEL_WORDS[index].store(0, Ordering::Release);
    TLS_CANCEL_FLAGS[index].store(0, Ordering::Release);
    TLS_PTRS[index].store(values_ptr as usize, Ordering::Release);
    TLS_CANCEL_WORDS[index].store(generation, Ordering::Release);
}

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
const FALLBACK_INLINE_KEYS: usize = 4;

#[cfg(not(feature = "owned-tls-cache"))]
struct FallbackTls {
    inline: [core::cell::Cell<TlsEntry>; FALLBACK_INLINE_KEYS],
    /// Owned mapping of `TLS_KEY_SLOTS - FALLBACK_INLINE_KEYS` entries, or null.
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
const FALLBACK_SPILL_KEYS: usize = TLS_KEY_SLOTS - FALLBACK_INLINE_KEYS;

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
        // entries; key_id < TLS_KEY_SLOTS is checked by callers.
        unsafe { (*spill.add(key_id - FALLBACK_INLINE_KEYS)).get() }
    }

    fn set(&self, key_id: usize, entry: TlsEntry) -> i32 {
        if key_id < FALLBACK_INLINE_KEYS {
            self.inline[key_id].set(entry);
            return 0;
        }
        let mut spill = self.spill.get();
        if spill.is_null() {
            if entry.value == 0 {
                // Clearing a never-set high key: nothing to store.
                return 0;
            }
            // Private runtime keys can be initialized by the allocator itself.
            // A Box would recurse before its owned cache slot is published.
            // Anonymous zeroed pages initialize every Cell<TlsEntry> without
            // touching the host allocator or creating a large stack temporary.
            // SAFETY: this thread exclusively owns the fresh zero-valid array.
            spill = unsafe {
                syscall::sys_mmap(
                    core::ptr::null_mut(),
                    core::mem::size_of::<[core::cell::Cell<TlsEntry>; FALLBACK_SPILL_KEYS]>(),
                    3,    // PROT_READ | PROT_WRITE
                    0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                    -1,
                    0,
                )
                .unwrap_or(core::ptr::null_mut())
                .cast()
            };
            if spill.is_null() {
                return ENOMEM;
            }
            self.spill.set(spill);
        }
        // SAFETY: as in `get`.
        unsafe { (*spill.add(key_id - FALLBACK_INLINE_KEYS)).set(entry) };
        0
    }

    #[cfg(test)]
    fn clear_all(&self) {
        for slot in &self.inline {
            slot.set(TlsEntry::default());
        }
        self.release_spill();
    }

    /// Unmap the spill block (thread teardown / reset).
    fn release_spill(&self) {
        let spill = self.spill.replace(core::ptr::null_mut());
        if !spill.is_null() {
            // SAFETY: this is the original mapping of FALLBACK_SPILL_KEYS
            // entries, detached from this thread after all key destructors.
            let _ = unsafe {
                syscall::sys_munmap(
                    spill.cast(),
                    core::mem::size_of::<[core::cell::Cell<TlsEntry>; FALLBACK_SPILL_KEYS]>(),
                )
            };
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
    // Internal owned caches use this table during allocator/policy bootstrap.
    // A Box allocation here would reenter those caches before their first
    // value can be published. Anonymous mappings are already zero initialized.
    // SAFETY: one page-aligned, zero-valid array with no host allocator or TLS.
    unsafe {
        syscall::sys_mmap(
            core::ptr::null_mut(),
            core::mem::size_of::<[TlsEntry; TLS_KEY_SLOTS]>(),
            3,    // PROT_READ | PROT_WRITE
            0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            -1,
            0,
        )
        .unwrap_or(core::ptr::null_mut())
        .cast()
    }
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
    // each block contains exactly TLS_KEY_SLOTS entries, all zero-valid.
    for index in 0..TLS_KEY_SLOTS {
        // Do not call an interposed memset before an internal cache can
        // publish its first value into this newly claimed fallback table.
        unsafe {
            let entry = values.add(index);
            core::ptr::addr_of_mut!((*entry).seq).write_volatile(0);
            core::ptr::addr_of_mut!((*entry).value).write_volatile(0);
        }
    }
    values
}

#[cfg(feature = "owned-tls-cache")]
unsafe fn drop_fallback_tls_block(values_ptr: *mut TlsEntry) {
    if !values_ptr.is_null() {
        // SAFETY: allocation created exactly this anonymous mapping;
        // table_remove/reset transfer its unique ownership to this call.
        let _ = unsafe {
            syscall::sys_munmap(
                values_ptr.cast(),
                core::mem::size_of::<[TlsEntry; TLS_KEY_SLOTS]>(),
            )
        };
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
fn publish_fallback_block(index: usize, tid: i32) -> *mut TlsEntry {
    let values = fallback_tls_block_for_slot(index);
    if values.is_null() {
        // Release our claim without breaking a concurrent probe chain.
        FALLBACK_TLS_TIDS[index].store(TLS_SLOT_TOMBSTONE, Ordering::Release);
    } else {
        FALLBACK_TLS_PTRS[index].store(values as usize, Ordering::Relaxed);
        FALLBACK_TLS_TIDS[index].store(tid, Ordering::Release);
    }
    values
}

#[cfg(feature = "owned-tls-cache")]
fn fallback_table_get_or_insert(tid: i32) -> *mut TlsEntry {
    if tid <= 0 {
        return core::ptr::null_mut();
    }
    let self_claiming = tls_slot_claiming_for_tid(tid);
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;

    'retry: for _ in 0..16 {
        let mut first_tombstone: Option<usize> = None;
        for i in 0..TLS_TABLE_SLOTS {
            let idx = (start + i) % TLS_TABLE_SLOTS;
            let mut current = FALLBACK_TLS_TIDS[idx].load(Ordering::Acquire);
            while is_tls_slot_claiming(current) {
                if current == self_claiming {
                    return core::ptr::null_mut();
                }
                core::hint::spin_loop();
                current = FALLBACK_TLS_TIDS[idx].load(Ordering::Acquire);
            }
            if current == tid {
                return FALLBACK_TLS_PTRS[idx].load(Ordering::Acquire) as *mut TlsEntry;
            }

            if current == TLS_SLOT_TOMBSTONE {
                if first_tombstone.is_none() {
                    first_tombstone = Some(idx);
                }
                continue;
            }

            if current == TLS_SLOT_EMPTY {
                let (target, expected) = match first_tombstone {
                    Some(tomb) => (tomb, TLS_SLOT_TOMBSTONE),
                    None => (idx, TLS_SLOT_EMPTY),
                };
                if FALLBACK_TLS_TIDS[target]
                    .compare_exchange(expected, self_claiming, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return publish_fallback_block(target, tid);
                }
                continue 'retry;
            }
        }

        if let Some(tomb_idx) = first_tombstone {
            if FALLBACK_TLS_TIDS[tomb_idx]
                .compare_exchange(
                    TLS_SLOT_TOMBSTONE,
                    self_claiming,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return publish_fallback_block(tomb_idx, tid);
            }
            continue 'retry;
        }
        break;
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
fn table_register(tid: i32, values_ptr: *mut TlsEntry) -> bool {
    if tid <= 0 {
        return false;
    }
    TLS_TABLE_USED.store(true, Ordering::Release);
    // Refuse further registrations on exhaustion instead of ever reusing a
    // generation. In practice this permits over nine quintillion lifetimes.
    let Ok(generation) =
        NEXT_CANCEL_GENERATION.try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(2)
        })
    else {
        return false;
    };
    let self_claiming = tls_slot_claiming_for_tid(tid);
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    'retry: for _ in 0..16 {
        let mut first_tombstone: Option<usize> = None;
        for i in 0..TLS_TABLE_SLOTS {
            let idx = (start + i) % TLS_TABLE_SLOTS;
            let mut current = TLS_TIDS[idx].load(Ordering::Acquire);
            while is_tls_slot_claiming(current) {
                if current == self_claiming {
                    return false;
                }
                core::hint::spin_loop();
                current = TLS_TIDS[idx].load(Ordering::Acquire);
            }
            if current == tid {
                // Already registered (shouldn't happen, but handle gracefully).
                publish_tls_slot(idx, values_ptr, generation);
                return true;
            }

            if current == TLS_SLOT_TOMBSTONE {
                if first_tombstone.is_none() {
                    first_tombstone = Some(idx);
                }
                continue;
            }

            if current == TLS_SLOT_EMPTY {
                let (target, expected) = match first_tombstone {
                    Some(tomb_idx) => (tomb_idx, TLS_SLOT_TOMBSTONE),
                    None => (idx, TLS_SLOT_EMPTY),
                };
                if TLS_TIDS[target]
                    .compare_exchange(expected, self_claiming, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    publish_tls_slot(target, values_ptr, generation);
                    TLS_TIDS[target].store(tid, Ordering::Release);
                    return true;
                }
                continue 'retry;
            }
        }
        if let Some(tomb_idx) = first_tombstone {
            if TLS_TIDS[tomb_idx]
                .compare_exchange(
                    TLS_SLOT_TOMBSTONE,
                    self_claiming,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                publish_tls_slot(tomb_idx, values_ptr, generation);
                TLS_TIDS[tomb_idx].store(tid, Ordering::Release);
                return true;
            }
            continue 'retry;
        }
        return false;
    }
    false
}

/// Look up the TLS values pointer for a given TID.
///
/// Returns a raw pointer to `[TlsEntry; TLS_KEY_SLOTS]`, or null if not found.
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

/// Set a request only while the observed registration is still alive.
fn request_cancel_generation(index: usize, mut observed: u64) -> bool {
    let generation = observed & !CANCEL_PENDING;
    if generation == 0 {
        return false;
    }
    loop {
        match TLS_CANCEL_WORDS[index].compare_exchange(
            observed,
            observed | CANCEL_PENDING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                // Publish before waking. A waiter that has not parked sees the
                // changed expected value; one already parked receives the wake.
                // The address is static, so retirement/reuse can at worst cause
                // a harmless spurious wake of the replacement registration.
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                unsafe {
                    let _ = syscall::sys_futex(
                        cancellation_word_address(&TLS_CANCEL_WORDS[index]),
                        0x81, // FUTEX_WAKE_PRIVATE
                        1,
                        0,
                        0,
                        0,
                    );
                }
                return true;
            }
            Err(current) if current & !CANCEL_PENDING == generation => observed = current,
            Err(_) => return false,
        }
    }
}

/// Request cancellation by an opaque native TLS-storage address. Neither the
/// caller nor this table needs to dereference the target's allocation.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn request_thread_cancellation(values_address: usize) -> bool {
    request_thread_cancellation_with_info(values_address, || Ok(()))
        .ok()
        .flatten()
        .is_some()
}

/// Request cancellation by an opaque native TLS-storage address and return the
/// target's `(tid, cancel_flags)` snapshot observed in `SeqCst` order after
/// publishing `CANCEL_PENDING`.
/// `prepare` runs before publication, without dereferencing the target. If it
/// fails, no request is queued; retirement during preparation still invalidates
/// the captured generation before the pending-bit CAS can succeed.
pub(crate) fn request_thread_cancellation_with_info(
    values_address: usize,
    prepare: impl FnOnce() -> Result<(), i32>,
) -> Result<Option<(i32, u32)>, i32> {
    if values_address == 0 {
        return Ok(None);
    }
    for index in 0..TLS_TABLE_SLOTS {
        // Acquire the generation before comparing the pointer. Publishing a
        // replacement pointer also replaces this generation; the CAS detects
        // removal/reuse even when the allocator returns the identical address.
        let observed = TLS_CANCEL_WORDS[index].load(Ordering::Acquire);
        if observed != 0 && TLS_PTRS[index].load(Ordering::Acquire) == values_address {
            let tid = TLS_TIDS[index].load(Ordering::Acquire);
            prepare()?;
            if request_cancel_generation(index, observed) {
                let flags = TLS_CANCEL_FLAGS[index].load(Ordering::SeqCst);
                return Ok(Some((tid, flags)));
            }
            return Ok(None);
        }
    }
    Ok(None)
}

/// Obtain the calling native thread's wait word without borrowing its handle.
/// The caller has checked its owned cancellation state and exit protocol.
pub(crate) fn thread_cancellation_wait(tid: i32) -> Option<CancellationWait> {
    if tid <= 0 {
        return None;
    }
    let start = tid as u32 as usize % TLS_TABLE_SLOTS;
    for offset in 0..TLS_TABLE_SLOTS {
        let index = (start + offset) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[index].load(Ordering::Acquire);
        if stored_tid == tid {
            let word = &TLS_CANCEL_WORDS[index];
            let generation = word.load(Ordering::Acquire) & !CANCEL_PENDING;
            return (generation != 0).then_some(CancellationWait {
                word,
                generation,
                tid,
                owner: core::marker::PhantomData,
            });
        }
        if stored_tid == TLS_SLOT_EMPTY {
            break;
        }
    }
    None
}

/// Consume the calling native thread's request. Its registration cannot be
/// removed until this same thread enters final teardown.
pub(crate) fn take_thread_cancellation(tid: i32) -> bool {
    if tid <= 0 {
        return false;
    }
    let start = tid as u32 as usize % TLS_TABLE_SLOTS;
    for offset in 0..TLS_TABLE_SLOTS {
        let index = (start + offset) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[index].load(Ordering::Acquire);
        if stored_tid == tid {
            return TLS_CANCEL_WORDS[index].fetch_and(!CANCEL_PENDING, Ordering::AcqRel)
                & CANCEL_PENDING
                != 0;
        }
        if stored_tid == TLS_SLOT_EMPTY {
            break;
        }
    }
    false
}

fn ensure_unregistered_cancel_slot(tid: i32) -> Option<usize> {
    if tid <= 0 {
        return None;
    }
    let self_claiming = tls_slot_claiming_for_tid(tid);
    UNREGISTERED_CANCEL_USED.store(true, Ordering::Release);
    let start = (tid as u32 as usize) % UNREGISTERED_CANCEL_SLOTS;
    'retry: for _ in 0..16 {
        let mut first_tombstone: Option<usize> = None;
        for i in 0..UNREGISTERED_CANCEL_SLOTS {
            let idx = (start + i) % UNREGISTERED_CANCEL_SLOTS;
            let mut stored = UNREGISTERED_CANCEL_TIDS[idx].load(Ordering::Acquire);
            while is_tls_slot_claiming(stored) {
                if stored == self_claiming {
                    return None;
                }
                core::hint::spin_loop();
                stored = UNREGISTERED_CANCEL_TIDS[idx].load(Ordering::Acquire);
            }
            if stored == tid {
                return Some(idx);
            }
            if stored == TLS_SLOT_TOMBSTONE {
                if first_tombstone.is_none() {
                    first_tombstone = Some(idx);
                }
                continue;
            }
            if stored == TLS_SLOT_EMPTY {
                let (target, expected) = match first_tombstone {
                    Some(tomb) => (tomb, TLS_SLOT_TOMBSTONE),
                    None => (idx, TLS_SLOT_EMPTY),
                };
                let generation = NEXT_CANCEL_GENERATION
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                        next.checked_add(2)
                    })
                    .ok()?;
                if UNREGISTERED_CANCEL_TIDS[target]
                    .compare_exchange(expected, self_claiming, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    UNREGISTERED_CANCEL_FLAGS[target].store(0, Ordering::Relaxed);
                    UNREGISTERED_CANCEL_WORDS[target].store(generation, Ordering::Relaxed);
                    UNREGISTERED_CANCEL_TIDS[target].store(tid, Ordering::Release);
                    return Some(target);
                }
                continue 'retry;
            }
        }
        if let Some(tomb) = first_tombstone {
            let generation = NEXT_CANCEL_GENERATION
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(2)
                })
                .ok()?;
            if UNREGISTERED_CANCEL_TIDS[tomb]
                .compare_exchange(
                    TLS_SLOT_TOMBSTONE,
                    self_claiming,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                UNREGISTERED_CANCEL_FLAGS[tomb].store(0, Ordering::Relaxed);
                UNREGISTERED_CANCEL_WORDS[tomb].store(generation, Ordering::Relaxed);
                UNREGISTERED_CANCEL_TIDS[tomb].store(tid, Ordering::Release);
                return Some(tomb);
            }
            continue 'retry;
        }
        return None;
    }
    None
}

/// Async-signal-safe, lock-free check whether an unregistered native thread
/// (`tid`) currently has asynchronous cancellation enabled and active.
#[inline]
pub fn unregistered_native_async_cancel_ready_for_tid(tid: i32) -> bool {
    if tid <= 0 || !UNREGISTERED_CANCEL_USED.load(Ordering::Acquire) {
        return false;
    }
    let start = (tid as u32 as usize) % UNREGISTERED_CANCEL_SLOTS;
    for i in 0..UNREGISTERED_CANCEL_SLOTS {
        let idx = (start + i) % UNREGISTERED_CANCEL_SLOTS;
        let stored = UNREGISTERED_CANCEL_TIDS[idx].load(Ordering::Acquire);
        if stored == tid {
            let flags = UNREGISTERED_CANCEL_FLAGS[idx].load(Ordering::Acquire);
            return (flags & (CANCEL_FLAG_ASYNC | CANCEL_FLAG_DISABLED)) == CANCEL_FLAG_ASYNC;
        }
        if stored == TLS_SLOT_EMPTY {
            break;
        }
    }
    false
}

/// Obtain a `CancellationWait` descriptor for an unregistered native thread
/// (such as the initial `main` thread under native threading or standalone mode).
pub fn unregistered_cancellation_wait(tid: i32) -> Option<CancellationWait> {
    let idx = ensure_unregistered_cancel_slot(tid)?;
    let word = &UNREGISTERED_CANCEL_WORDS[idx];
    let generation = word.load(Ordering::Acquire) & !CANCEL_PENDING;
    (generation != 0).then_some(CancellationWait {
        word,
        generation,
        tid,
        owner: core::marker::PhantomData,
    })
}

/// Publish a cooperative cancellation request for an unregistered native thread
/// (`tid`), waking any futex waiter and returning its `SeqCst` flags snapshot.
pub fn request_unregistered_cancellation_with_flags(tid: i32) -> Option<u32> {
    let idx = ensure_unregistered_cancel_slot(tid)?;
    let mut observed = UNREGISTERED_CANCEL_WORDS[idx].load(Ordering::Acquire);
    let generation = observed & !CANCEL_PENDING;
    if generation == 0 {
        return None;
    }
    loop {
        match UNREGISTERED_CANCEL_WORDS[idx].compare_exchange(
            observed,
            observed | CANCEL_PENDING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                unsafe {
                    let _ = syscall::sys_futex(
                        cancellation_word_address(&UNREGISTERED_CANCEL_WORDS[idx]),
                        0x81, // FUTEX_WAKE_PRIVATE
                        1,
                        0,
                        0,
                        0,
                    );
                }
                return Some(UNREGISTERED_CANCEL_FLAGS[idx].load(Ordering::SeqCst));
            }
            Err(current) if current & !CANCEL_PENDING == generation => observed = current,
            Err(_) => return None,
        }
    }
}

/// Consume a pending request for an unregistered native thread.
pub fn take_unregistered_cancellation(tid: i32) -> bool {
    if tid <= 0 || !UNREGISTERED_CANCEL_USED.load(Ordering::Acquire) {
        return false;
    }
    let start = (tid as u32 as usize) % UNREGISTERED_CANCEL_SLOTS;
    for i in 0..UNREGISTERED_CANCEL_SLOTS {
        let idx = (start + i) % UNREGISTERED_CANCEL_SLOTS;
        let stored = UNREGISTERED_CANCEL_TIDS[idx].load(Ordering::Acquire);
        if stored == tid {
            return UNREGISTERED_CANCEL_WORDS[idx].fetch_and(!CANCEL_PENDING, Ordering::AcqRel)
                & CANCEL_PENDING
                != 0;
        }
        if stored == TLS_SLOT_EMPTY {
            break;
        }
    }
    false
}

/// Retire an unregistered native thread's cancellation slot on final exit.
pub fn retire_unregistered_cancellation(tid: i32) {
    if tid <= 0 || !UNREGISTERED_CANCEL_USED.load(Ordering::Acquire) {
        return;
    }
    let start = (tid as u32 as usize) % UNREGISTERED_CANCEL_SLOTS;
    for i in 0..UNREGISTERED_CANCEL_SLOTS {
        let idx = (start + i) % UNREGISTERED_CANCEL_SLOTS;
        let stored = UNREGISTERED_CANCEL_TIDS[idx].load(Ordering::Acquire);
        if stored == tid {
            UNREGISTERED_CANCEL_WORDS[idx].store(0, Ordering::Release);
            UNREGISTERED_CANCEL_FLAGS[idx].store(0, Ordering::Release);
            UNREGISTERED_CANCEL_TIDS[idx].store(TLS_SLOT_TOMBSTONE, Ordering::Release);
            return;
        }
        if stored == TLS_SLOT_EMPTY {
            break;
        }
    }
}

fn update_native_cancel_flag(tid: i32, mask: u32, set: bool) -> bool {
    if tid <= 0 {
        return false;
    }
    if TLS_TABLE_USED.load(Ordering::Acquire) {
        let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
        for offset in 0..TLS_TABLE_SLOTS {
            let index = (start + offset) % TLS_TABLE_SLOTS;
            let stored_tid = TLS_TIDS[index].load(Ordering::Acquire);
            if stored_tid == tid {
                let prev = if set {
                    TLS_CANCEL_FLAGS[index].fetch_or(mask, Ordering::SeqCst)
                } else {
                    TLS_CANCEL_FLAGS[index].fetch_and(!mask, Ordering::SeqCst)
                };
                return prev & mask != 0;
            }
            if stored_tid == TLS_SLOT_EMPTY {
                break;
            }
        }
    }
    if let Some(idx) = ensure_unregistered_cancel_slot(tid) {
        let prev = if set {
            UNREGISTERED_CANCEL_FLAGS[idx].fetch_or(mask, Ordering::SeqCst)
        } else {
            UNREGISTERED_CANCEL_FLAGS[idx].fetch_and(!mask, Ordering::SeqCst)
        };
        return prev & mask != 0;
    }
    false
}

/// Update `CANCEL_FLAG_DISABLED` for a native thread (`registered` or `unregistered`).
pub fn set_native_cancel_disabled(tid: i32, disabled: bool) {
    let _ = update_native_cancel_flag(tid, CANCEL_FLAG_DISABLED, disabled);
}

/// Update `CANCEL_FLAG_ASYNC` for a native thread (`registered` or `unregistered`).
pub fn set_native_cancel_async(tid: i32, async_mode: bool) {
    let _ = update_native_cancel_flag(tid, CANCEL_FLAG_ASYNC, async_mode);
}

/// Update `CANCEL_FLAG_IN_POINT` for a native thread (`registered` or `unregistered`),
/// returning whether `CANCEL_FLAG_IN_POINT` was already set prior to this call.
pub fn set_native_cancel_point_active(tid: i32, active: bool) -> bool {
    update_native_cancel_flag(tid, CANCEL_FLAG_IN_POINT, active)
}

/// Remove a TID from the table and return its values pointer.
///
/// **Allocation-free.**
fn detach_table_ptr_keep_exiting_tid(tid: i32) {
    if tid <= 0 {
        return;
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            TLS_CANCEL_WORDS[idx].store(0, Ordering::Release);
            TLS_CANCEL_FLAGS[idx].store(0, Ordering::Release);
            TLS_PTRS[idx].store(0, Ordering::Release);
            return;
        }
        if stored_tid == TLS_SLOT_EMPTY {
            return;
        }
    }
}

/// Returns `true` when the calling thread is a native `clone` thread that has
/// already detached its `ThreadHandle` pointer during exit teardown (and
/// therefore must not fall back to its creator's `%fs` `errno` slot).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
pub fn current_thread_is_exiting_native() -> bool {
    if !native_threads_may_exist() {
        return false;
    }
    let tid = syscall::sys_gettid();
    if tid <= 0 {
        return false;
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            return TLS_PTRS[idx].load(Ordering::Acquire) == 0;
        }
        if stored_tid == TLS_SLOT_EMPTY {
            return false;
        }
    }
    false
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
pub(crate) fn finish_exiting_native_tid(tid: i32) {
    let _ = table_remove(tid);
}

fn table_remove(tid: i32) -> *mut TlsEntry {
    if tid <= 0 {
        return core::ptr::null_mut();
    }
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            TLS_CANCEL_WORDS[idx].store(0, Ordering::Release);
            TLS_CANCEL_FLAGS[idx].store(0, Ordering::Release);
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
#[inline]
pub fn current_tid() -> i32 {
    #[cfg(feature = "owned-tls-cache")]
    {
        // This lookup is part of owned-cache bootstrap. Even the small host
        // TLS cache can call __tls_get_addr before our key value is published.
        syscall::sys_gettid()
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
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
}

#[cfg(not(feature = "owned-tls-cache"))]
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

/// Set when at least one native thread registers in `TLS_TIDS`. Ordinary hosted
/// processes never register in `TLS_TIDS`, so skipping `rekey_fork_child_table`
/// avoids scanning and COW-faulting 80 KiB of `.bss` on every `fork()`.
static TLS_TABLE_USED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

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
    cancellation: Option<(&[AtomicU64; TLS_TABLE_SLOTS], &[AtomicU32; TLS_TABLE_SLOTS])>,
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
    let (survivor_cancel, survivor_flags) =
        cancellation
            .zip(survivor_index)
            .map_or((0, 0), |((words, flags), index)| {
                (
                    words[index].load(Ordering::Acquire),
                    flags[index].load(Ordering::Acquire) & !CANCEL_FLAG_IN_POINT,
                )
            });
    for index in 0..TLS_TABLE_SLOTS {
        if let Some((words, flags)) = cancellation {
            if words[index].load(Ordering::Relaxed) != 0 {
                words[index].store(0, Ordering::Release);
            }
            if flags[index].load(Ordering::Relaxed) != 0 {
                flags[index].store(0, Ordering::Release);
            }
        }
        if tids[index].load(Ordering::Relaxed) != TLS_SLOT_EMPTY {
            tids[index].store(TLS_SLOT_EMPTY, Ordering::Release);
        }
        if !retain_unused_blocks && pointers[index].load(Ordering::Relaxed) != 0 {
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
        if let Some((words, flags)) = cancellation {
            flags[destination].store(survivor_flags, Ordering::Release);
            words[destination].store(survivor_cancel, Ordering::Release);
        }
    }
}

fn rekey_fork_child_unregistered_cancel(parent_tid: i32, child_tid: i32) {
    let survivor_index = UNREGISTERED_CANCEL_TIDS
        .iter()
        .position(|tid| tid.load(Ordering::Acquire) == parent_tid);
    let survivor_word = survivor_index.map_or(0, |idx| {
        UNREGISTERED_CANCEL_WORDS[idx].load(Ordering::Acquire)
    });
    let survivor_flags = survivor_index.map_or(0, |idx| {
        UNREGISTERED_CANCEL_FLAGS[idx].load(Ordering::Acquire) & !CANCEL_FLAG_IN_POINT
    });
    for idx in 0..UNREGISTERED_CANCEL_SLOTS {
        UNREGISTERED_CANCEL_WORDS[idx].store(0, Ordering::Release);
        UNREGISTERED_CANCEL_FLAGS[idx].store(0, Ordering::Release);
        UNREGISTERED_CANCEL_TIDS[idx].store(TLS_SLOT_EMPTY, Ordering::Release);
    }
    if survivor_word != 0 && child_tid > 0 {
        let dst = (child_tid as u32 as usize) % UNREGISTERED_CANCEL_SLOTS;
        UNREGISTERED_CANCEL_FLAGS[dst].store(survivor_flags, Ordering::Release);
        UNREGISTERED_CANCEL_WORDS[dst].store(survivor_word, Ordering::Release);
        UNREGISTERED_CANCEL_TIDS[dst].store(child_tid, Ordering::Release);
    }
}

/// Call first thing in a fork child, before anything reads a TLS key.
///
/// # Safety
/// The caller is the sole surviving thread in a freshly forked address space,
/// and parent_tid is its kernel TID captured before fork. Inherited table
/// metadata must not be accessed concurrently while it is rebuilt.
pub unsafe fn note_fork_child(parent_tid: i32) {
    // First: the table rekey below can compile to an interposed memcpy. The
    // survivor must retain validation recursion ownership while inherited
    // pipeline guards still hold their locks. Fork callers keep signals masked.
    unsafe { frankenlibc_membrane::ptr_validator::note_validation_fork_child(parent_tid) };
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    super::thread::reset_live_native_threads_after_fork();
    syscall::reset_native_cancel_syscalls_after_fork();
    let child_tid = syscall::sys_gettid();

    if TLS_TABLE_USED.load(Ordering::Acquire) {
        rekey_fork_child_table(
            &TLS_TIDS,
            &TLS_PTRS,
            Some((&TLS_CANCEL_WORDS, &TLS_CANCEL_FLAGS)),
            parent_tid,
            child_tid,
            false,
        );
    }
    if UNREGISTERED_CANCEL_USED.load(Ordering::Acquire) {
        rekey_fork_child_unregistered_cancel(parent_tid, child_tid);
    }
    #[cfg(feature = "owned-tls-cache")]
    {
        rekey_fork_child_table(
            &FALLBACK_TLS_TIDS,
            &FALLBACK_TLS_PTRS,
            None,
            parent_tid,
            child_tid,
            true,
        );
    }
    TID_CACHE_EPOCH.fetch_add(1, Ordering::AcqRel);
}

/// Call before cloning a thread that shares its creator's TLS.
pub fn disable_tid_cache() {
    // Publish the membrane transition before a native child can inherit the
    // creator's compiler TLS. Existing creator borrows may finish; no new
    // native or hosted membrane entry may borrow that compiler-TLS state.
    frankenlibc_membrane::tls_cache::note_native_thread_tls_sharing();
    TID_CACHE_DISABLED.store(true, Ordering::SeqCst);
}

/// Whether a native thread may share the caller's inherited compiler TLS.
#[inline(always)]
pub fn native_threads_may_exist() -> bool {
    TID_CACHE_DISABLED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Internal: read/write per-thread TLS value
// ---------------------------------------------------------------------------

/// Read a TLS value for the given TID and key index.
/// Falls back to thread-local storage if the TID is not in the table.
fn read_tls_value(tid: i32, key_id: usize, expected_seq: u32) -> u64 {
    let ptr = table_lookup(tid);
    if !ptr.is_null() {
        // SAFETY: ptr points to a valid `[TlsEntry; TLS_KEY_SLOTS]` that is either
        // embedded in a ThreadHandle (alive while the thread runs) or in a
        // test-allocated block. key_id < TLS_KEY_SLOTS checked by caller.
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
            // kernel TID. key_id < TLS_KEY_SLOTS checked by caller.
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
fn write_tls_value(tid: i32, key_id: usize, expected_seq: u32, value: u64) -> i32 {
    let ptr = table_lookup(tid);
    if !ptr.is_null() {
        // SAFETY: ptr points to a valid `[TlsEntry; TLS_KEY_SLOTS]` owned by this
        // thread. Only the owning thread writes to its own values.
        unsafe {
            let entry = ptr.add(key_id);
            (*entry).seq = expected_seq;
            (*entry).value = value;
        };
        0
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
                )
            })
        }
        #[cfg(feature = "owned-tls-cache")]
        {
            let fallback_ptr = if value == 0 {
                fallback_table_lookup(tid)
            } else {
                fallback_table_get_or_insert(tid)
            };
            if fallback_ptr.is_null() {
                return if value == 0 { 0 } else { ENOMEM };
            }
            // SAFETY: fallback_ptr points to an owned fallback block for this
            // kernel TID. Only the owning thread writes its fallback values.
            unsafe {
                let entry = fallback_ptr.add(key_id);
                (*entry).seq = expected_seq;
                (*entry).value = value;
            }
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Creates a thread-local storage key.
///
/// Equivalent to C `pthread_key_create`. The optional `destructor` is called
/// when a thread exits with a non-null value for this key.
///
/// Returns 0 on success, `EAGAIN` if the key space is exhausted.
pub fn pthread_key_create(
    key: &mut PthreadKey,
    destructor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> i32 {
    create_key_in_domain(&mut key.id, destructor, 0, PTHREAD_KEYS_MAX)
}

/// Allocate a private key without consuming the public POSIX key budget.
#[doc(hidden)]
pub fn internal_tls_key_create(
    key: &mut InternalTlsKey,
    destructor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> i32 {
    create_key_in_domain(
        &mut key.id,
        destructor,
        PTHREAD_KEYS_MAX,
        INTERNAL_TLS_KEYS_MAX,
    )
}

fn create_key_in_domain(
    key: &mut u32,
    destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    offset: usize,
    capacity: usize,
) -> i32 {
    let _write_guard = KeyRegistryWriteGuard::lock();
    for (index, slot) in KEY_SLOTS[offset..offset + capacity].iter().enumerate() {
        let previous = slot.generation.load(Ordering::Relaxed);
        if previous & 1 == 0 && previous < LAST_KEY_GENERATION {
            let generation = previous + 1;
            slot.destructor.store(
                destructor.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
                Ordering::Release,
            );
            slot.generation.store(generation, Ordering::Release);
            *key = (generation << 10) | index as u32;
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
    let _write_guard = KeyRegistryWriteGuard::lock();
    let slot = &KEY_SLOTS[id];
    if expected_seq & 1 == 0 || slot.generation.load(Ordering::Relaxed) != expected_seq {
        return EINVAL;
    }
    // The next creation overwrites the callback before publishing a new odd
    // generation. Leaving it untouched here keeps deletion a single store.
    slot.generation.store(expected_seq + 1, Ordering::Release);
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
/// if the key is invalid or deleted, or `ENOMEM` if storage is unavailable.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn pthread_setspecific(key: PthreadKey, value: u64) -> i32 {
    let id = (key.id & 1023) as usize;
    let expected_seq = key.id >> 10;
    if id >= PTHREAD_KEYS_MAX {
        return EINVAL;
    }
    set_specific_entry(id, expected_seq, value)
}

/// Read only the calling thread's private libc key value.
#[doc(hidden)]
pub fn internal_tls_getspecific(key: InternalTlsKey) -> u64 {
    let id = (key.id & 1023) as usize;
    if id >= INTERNAL_TLS_KEYS_MAX {
        return 0;
    }
    read_tls_value(current_tid(), PTHREAD_KEYS_MAX + id, key.id >> 10)
}

/// Set only the calling thread's private libc key value.
///
/// # Safety
/// The caller must own this private key. A nonzero value must satisfy the
/// registered destructor's contract and remain valid until replaced or torn
/// down by this thread; overwriting another cache's key violates its ownership.
#[doc(hidden)]
pub unsafe fn internal_tls_setspecific(key: InternalTlsKey, value: u64) -> i32 {
    let id = (key.id & 1023) as usize;
    if id >= INTERNAL_TLS_KEYS_MAX {
        return EINVAL;
    }
    set_specific_entry(PTHREAD_KEYS_MAX + id, key.id >> 10, value)
}

fn set_specific_entry(id: usize, expected_seq: u32, value: u64) -> i32 {
    if expected_seq & 1 == 0 || KEY_SLOTS[id].generation.load(Ordering::Acquire) != expected_seq {
        return EINVAL;
    }
    write_tls_value(current_tid(), id, expected_seq, value)
}

// ---------------------------------------------------------------------------
// Thread lifecycle integration (called from thread.rs trampoline)
// ---------------------------------------------------------------------------

/// Register a thread's TLS values pointer in the global table.
///
/// `values_ptr` must point to a `[TlsEntry; TLS_KEY_SLOTS]` array that lives
/// at least as long as the thread. For clone-based threads, this is the
/// `tls_values` field in `ThreadHandle`.
///
/// **Allocation-free** — safe to call from clone-based threads.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn register_thread_tls(tid: i32, values_ptr: *mut TlsEntry) -> bool {
    table_register(tid, values_ptr)
}

static NATIVE_POST_TEARDOWN_HOOK: std::sync::OnceLock<fn(i32)> = std::sync::OnceLock::new();
static NATIVE_POST_HANDLE_DROP_HOOK: std::sync::OnceLock<fn(i32)> = std::sync::OnceLock::new();

/// Register an optional ABI-layer callback invoked after all POSIX key
/// destructors have completed for a native registered thread (`tid`).
pub fn install_native_thread_post_teardown_hook(hook: fn(i32)) {
    let _ = NATIVE_POST_TEARDOWN_HOOK.set(hook);
}

/// Register an optional allocation-free ABI-layer callback invoked after a
/// detached native thread drops its boxed `ThreadHandle` (`free`) and right
/// before unmapping its stack / exiting the thread.
pub fn install_native_thread_post_handle_drop_hook(hook: fn(i32)) {
    let _ = NATIVE_POST_HANDLE_DROP_HOOK.set(hook);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn run_native_post_handle_drop_hook(tid: i32) {
    if let Some(hook) = NATIVE_POST_HANDLE_DROP_HOOK.get() {
        hook(tid);
    }
}

/// Withdraw a prepared native thread that never entered application code.
/// Its application signals are still blocked and no key/runtime destructor
/// may run on failed publication. The creator retains the backing mapping.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn discard_thread_tls_before_entry(tid: i32) {
    table_remove(tid);
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
    teardown_thread_tls_impl(tid, false);
}

/// Native exit must stop application signal handlers before withdrawing the
/// identity that owns errno and cancellation settings. Destructors still run
/// with the application's signal mask and the live native handle.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn teardown_native_thread_tls(tid: i32) {
    teardown_thread_tls_impl(tid, true);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn run_thread_key_destructor_rounds(
    _tid: i32,
    values_ptr: *mut TlsEntry,
    first: usize,
    end: usize,
) {
    // Native threads own the block in their ThreadHandle. Their inherited
    // hardware TLS can still belong to the creator, so neither access nor
    // reclaim fallback storage when this registered block exists.
    let registered = !values_ptr.is_null();
    #[cfg(feature = "owned-tls-cache")]
    let fallback_values_ptr = if registered {
        core::ptr::null_mut()
    } else {
        fallback_table_lookup(_tid)
    };

    for _iteration in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        let mut called = false;
        for (offset, slot) in KEY_SLOTS[first..end].iter().enumerate() {
            let index = first + offset;
            let Some((generation, destructor)) = slot.snapshot() else {
                continue;
            };

            let value = if registered {
                // SAFETY: this thread exclusively owns its registered block,
                // which remains live until all destructor rounds finish.
                let entry = unsafe { &mut *values_ptr.add(index) };
                if entry.seq == generation {
                    core::mem::replace(&mut entry.value, 0)
                } else {
                    0
                }
            } else {
                #[cfg(not(feature = "owned-tls-cache"))]
                {
                    FALLBACK_TLS_VALUES.with(|values| {
                        let entry = values.get(index);
                        if entry.seq == generation && entry.value != 0 {
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
                        if entry.seq == generation {
                            core::mem::replace(&mut entry.value, 0)
                        } else {
                            0
                        }
                    }
                }
            };
            if value != 0 && !destructor.is_null() {
                called = true;
                // SAFETY: the callback was registered for this generation,
                // and the owning thread's value was cleared before the call.
                // C and C-unwind share the machine ABI. A destructor entered
                // after ordinary thread return can reach a cancellation point;
                // do not introduce a nounwind boundary around application code.
                // No registry guard or reference to its value spans this call, and
                // clearing the value first prevents a resumed teardown from
                // invoking the same destructor again.
                let dtor: unsafe extern "C-unwind" fn(*mut c_void) =
                    unsafe { core::mem::transmute(destructor) };
                unsafe { dtor(value as *mut c_void) };
            }
        }
        if !called {
            break;
        }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn teardown_thread_tls_impl(tid: i32, native_exit: bool) {
    let values_ptr = table_lookup(tid);
    let registered = !values_ptr.is_null();
    run_thread_key_destructor_rounds(tid, values_ptr, 0, PTHREAD_KEYS_MAX);

    if native_exit {
        let blocked = u64::MAX;
        // SAFETY: both supported Linux ABIs use this eight-byte signal set.
        // The identical syscall/mask succeeded before clone. If application
        // seccomp policy now forbids it, terminating the process is safer than
        // exposing a reclaimed handle to an application signal handler.
        if unsafe {
            syscall::sys_rt_sigprocmask(
                2, // SIG_SETMASK
                core::ptr::from_ref(&blocked).cast(),
                core::ptr::null_mut(),
                core::mem::size_of::<u64>(),
            )
        }
        .is_err()
        {
            syscall::sys_exit_group(127);
        }
        // Keep the native handle registered through late C++ TLS callbacks
        // created by POSIX key destructors. No signal may create new state
        // between its final drain and reclamation.
        super::thread::reclaim_native_runtime_tls(tid);

        // The last worker terminates the process with exit(0) semantics. Its
        // atexit callbacks and FILE flushing must still see the native handle,
        // errno cell, and usable thread-specific storage. Reclaiming private
        // values or withdrawing the handle first would switch these callbacks
        // to the creator's compiler TLS and an invalid pthread_self().
        // SAFETY: native teardown reaches this point once, after application
        // destructors finish and before the current stack or handle is freed.
        unsafe { super::thread::maybe_exit_process_as_last_native_thread() };
    }

    // Locale, parser cursors, scratch buffers, and policy state must remain
    // live through every application destructor, including late native C++
    // callbacks. Only then reclaim private cache values, keeping their lookup
    // table registered so cache Drop implementations can reenter safely.
    run_thread_key_destructor_rounds(tid, values_ptr, PTHREAD_KEYS_MAX, TLS_KEY_SLOTS);
    if registered {
        // Run ABI heap-cell teardown BEFORE `table_remove(tid)` so
        // `current_thread_handle()` still resolves to this thread's private
        // `errno` cell rather than falling through to creator `%fs` TLS.
        if let Some(hook) = NATIVE_POST_TEARDOWN_HOOK.get() {
            hook(tid);
        }
        if native_exit {
            detach_table_ptr_keep_exiting_tid(tid);
        } else {
            table_remove(tid);
        }
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
        retire_unregistered_cancellation(tid);
    }
}

// ---------------------------------------------------------------------------
// Test support: reset global state between tests
// ---------------------------------------------------------------------------

/// Reset all TLS global state. For testing only.
#[cfg(test)]
pub(crate) fn reset_tls_state() {
    for slot in &KEY_SLOTS {
        slot.generation.store(0, Ordering::Release);
        slot.destructor
            .store(core::ptr::null_mut(), Ordering::Release);
    }

    // Clear the table.
    for i in 0..TLS_TABLE_SLOTS {
        TLS_CANCEL_WORDS[i].store(0, Ordering::Release);
        TLS_CANCEL_FLAGS[i].store(0, Ordering::Release);
        TLS_TIDS[i].store(TLS_SLOT_EMPTY, Ordering::Release);
        TLS_PTRS[i].store(0, Ordering::Release);
    }
    for i in 0..UNREGISTERED_CANCEL_SLOTS {
        UNREGISTERED_CANCEL_WORDS[i].store(0, Ordering::Release);
        UNREGISTERED_CANCEL_FLAGS[i].store(0, Ordering::Release);
        UNREGISTERED_CANCEL_TIDS[i].store(TLS_SLOT_EMPTY, Ordering::Release);
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
    use std::sync::Mutex;

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
        values: [TlsEntry; TLS_KEY_SLOTS],
    }

    impl TestTlsBlock {
        fn new() -> Box<Self> {
            Box::new(Self {
                values: [TlsEntry::default(); TLS_KEY_SLOTS],
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
    fn private_keys_preserve_public_capacity_and_last_slot_isolation() {
        let _g = lock_and_reset();
        let mut private = [InternalTlsKey::default(); INTERNAL_TLS_KEYS_MAX];
        for key in &mut private {
            assert_eq!(internal_tls_key_create(key, None), 0);
        }
        assert_eq!(
            internal_tls_key_create(&mut InternalTlsKey::default(), None),
            EAGAIN
        );
        let mut public = [PthreadKey::default(); PTHREAD_KEYS_MAX];
        for key in &mut public {
            assert_eq!(pthread_key_create(key, None), 0);
        }
        assert_eq!(pthread_key_create(&mut PthreadKey::default(), None), EAGAIN);
        let last_private = private[INTERNAL_TLS_KEYS_MAX - 1];
        let last_public = public[PTHREAD_KEYS_MAX - 1];
        // SAFETY: this test owns all private keys; these have no destructor.
        assert_eq!(unsafe { internal_tls_setspecific(last_private, 0xcafe) }, 0);
        assert_eq!(pthread_setspecific(last_public, 0xbeef), 0);
        assert_eq!(internal_tls_getspecific(last_private), 0xcafe);
        assert_eq!(pthread_getspecific(last_public), 0xbeef);
        assert_eq!(internal_tls_getspecific(private[0]), 0);
        assert_eq!(pthread_getspecific(public[INTERNAL_TLS_KEYS_MAX - 1]), 0);
        teardown_thread_tls(current_tid());
        assert_eq!(internal_tls_getspecific(last_private), 0);
        assert_eq!(pthread_getspecific(last_public), 0);
    }

    #[test]
    fn fork_child_can_publish_keys_while_parent_writer_is_locked() {
        let _g = lock_and_reset();
        let inherited_key = create_key(None);
        let writer = KeyRegistryWriteGuard::lock();
        let child = syscall::sys_clone_fork(17).expect("fork"); // SIGCHLD
        if child == 0 {
            // A stale inherited writer must never make this child wait forever.
            // Use only raw syscalls and the allocation-independent key path.
            syscall::sys_alarm(3);
            let mut created = PthreadKey::default();
            let rc = pthread_key_create(&mut created, None);
            syscall::sys_exit_group(if rc == 0 && created != inherited_key {
                0
            } else {
                1
            });
        }
        drop(writer);
        let mut status = -1;
        // SAFETY: status is writable; no resource-usage output is requested.
        let waited = unsafe { syscall::sys_wait4(child, &mut status, 0, core::ptr::null_mut()) };
        assert_eq!(waited, Ok(child));
        assert_eq!(status, 0, "fork child could not publish a TLS key");
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
            let cancellation = [const { AtomicU64::new(0) }; TLS_TABLE_SLOTS];
            let flags = [const { AtomicU32::new(0) }; TLS_TABLE_SLOTS];
            tids[100].store(100, Ordering::Relaxed);
            pointers[100].store(0x1000, Ordering::Relaxed);
            cancellation[100].store(3, Ordering::Relaxed);
            flags[100].store(
                CANCEL_FLAG_DISABLED | CANCEL_FLAG_IN_POINT,
                Ordering::Relaxed,
            );
            tids[101].store(100 + TLS_TABLE_SLOTS as i32, Ordering::Relaxed);
            pointers[101].store(0x2000, Ordering::Relaxed);
            cancellation[101].store(5, Ordering::Relaxed);
            flags[101].store(CANCEL_FLAG_ASYNC, Ordering::Relaxed);
            tids[102].store(101 + TLS_TABLE_SLOTS as i32, Ordering::Relaxed);
            pointers[102].store(0x3000, Ordering::Relaxed);

            rekey_fork_child_table(
                &tids,
                &pointers,
                Some((&cancellation, &flags)),
                100,
                101,
                retain_unused,
            );

            assert_eq!(tids[101].load(Ordering::Relaxed), 101);
            assert_eq!(pointers[101].load(Ordering::Relaxed), 0x1000);
            assert_eq!(cancellation[101].load(Ordering::Relaxed), 3);
            assert_eq!(flags[101].load(Ordering::Relaxed), CANCEL_FLAG_DISABLED);
            assert_eq!(cancellation[100].load(Ordering::Relaxed), 0);
            assert_eq!(flags[100].load(Ordering::Relaxed), 0);
            assert_eq!(cancellation[102].load(Ordering::Relaxed), 0);
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
        static PRIVATE_DROPS: AtomicU32 = AtomicU32::new(0);
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
        PRIVATE_DROPS.store(0, AtomicOrdering::SeqCst);
        assert_eq!(pthread_setspecific(key, 1), 0);
        unsafe extern "C" fn drop_private(value: *mut c_void) {
            if value as usize != 0xcafe || ROUNDS.load(AtomicOrdering::SeqCst) != 3 {
                syscall::sys_exit_group(108);
            }
            PRIVATE_DROPS.fetch_add(1, AtomicOrdering::SeqCst);
        }
        let mut private = InternalTlsKey::default();
        assert_eq!(internal_tls_key_create(&mut private, Some(drop_private)), 0);
        // SAFETY: this key's destructor accepts exactly this sentinel value.
        assert_eq!(unsafe { internal_tls_setspecific(private, 0xcafe) }, 0);
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
            if pthread_getspecific(key) != 1 || internal_tls_getspecific(private) != 0xcafe {
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
            if ROUNDS.load(AtomicOrdering::SeqCst) != 3
                || pthread_getspecific(key) != 0
                || PRIVATE_DROPS.load(AtomicOrdering::SeqCst) != 1
                || internal_tls_getspecific(private) != 0
            {
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
        assert_eq!(internal_tls_getspecific(private), 0xcafe);
        assert_eq!(PRIVATE_DROPS.load(AtomicOrdering::SeqCst), 0);
        // SAFETY: the parent owns this key; clear its sentinel without a drop.
        assert_eq!(unsafe { internal_tls_setspecific(private, 0) }, 0);
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
    fn key_reuse_needs_no_additional_address_space() {
        let _g = lock_and_reset();
        let child = syscall::sys_clone_fork(17).expect("fork");
        if child == 0 {
            syscall::sys_alarm(3);
            // New mappings fail even when the parent has abundant memory.
            // Existing data and stack remain accessible in this child.
            let limit = [0u64; 2];
            if unsafe {
                syscall::sys_prlimit64(
                    0,
                    crate::resource::RLIMIT_AS as u32,
                    limit.as_ptr().cast(),
                    core::ptr::null_mut(),
                )
            }
            .is_err()
            {
                syscall::sys_exit_group(1);
            }
            for _ in 0..4096 {
                let mut key = PthreadKey::default();
                if pthread_key_create(&mut key, None) != 0 || pthread_key_delete(key) != 0 {
                    syscall::sys_exit_group(2);
                }
            }
            syscall::sys_exit_group(0);
        }
        let mut status = -1;
        // SAFETY: status is writable, no resource-usage output is requested.
        assert_eq!(
            unsafe { syscall::sys_wait4(child, &mut status, 0, core::ptr::null_mut()) },
            Ok(child)
        );
        assert_eq!(status, 0);
    }

    #[test]
    fn setspecific_storage_failure_is_retryable() {
        let _g = lock_and_reset();
        let mut key = PthreadKey::default();
        // Exceed the compiler-TLS inline slots. Both storage profiles need
        // a fresh mapping on the first non-null write in the child.
        for _ in 0..8 {
            assert_eq!(pthread_key_create(&mut key, None), 0);
        }
        let child = syscall::sys_clone_fork(17).expect("fork");
        if child == 0 {
            syscall::sys_alarm(10);
            let mut original = [0u64; 2];
            let resource = crate::resource::RLIMIT_AS as u32;
            // SAFETY: these buffers have Linux's two-u64 rlimit64 layout.
            let saved = unsafe {
                syscall::sys_prlimit64(0, resource, core::ptr::null(), original.as_mut_ptr().cast())
            };
            if saved.is_err() {
                syscall::sys_exit_group(1);
            }
            let restricted = [0, original[1]];
            let set_limit = |limit: &[u64; 2]| unsafe {
                syscall::sys_prlimit64(0, resource, limit.as_ptr().cast(), core::ptr::null_mut())
            };
            if set_limit(&restricted).is_err()
                || pthread_setspecific(key, 0) != 0
                || pthread_setspecific(key, 42) != ENOMEM
                || pthread_getspecific(key) != 0
            {
                syscall::sys_exit_group(2);
            }
            if set_limit(&original).is_err()
                || pthread_setspecific(key, 42) != 0
                || pthread_getspecific(key) != 42
            {
                syscall::sys_exit_group(3);
            }
            syscall::sys_exit_group(0);
        }
        let mut status = -1;
        // SAFETY: status is writable, no resource-usage output is requested.
        assert_eq!(
            unsafe { syscall::sys_wait4(child, &mut status, 0, core::ptr::null_mut()) },
            Ok(child)
        );
        assert_eq!(status, 0);
    }

    #[cfg(feature = "owned-tls-cache")]
    #[test]
    fn setspecific_reports_exhausted_fallback_table() {
        let _g = lock_and_reset();
        let key = create_key(None);
        for (index, tid) in FALLBACK_TLS_TIDS.iter().enumerate() {
            tid.store(i32::MAX - index as i32, Ordering::Release);
        }
        assert_eq!(pthread_setspecific(key, 0), 0);
        assert_eq!(pthread_setspecific(key, 7), ENOMEM);
        assert_eq!(pthread_getspecific(key), 0);
        FALLBACK_TLS_TIDS[0].store(TLS_SLOT_TOMBSTONE, Ordering::Release);
        assert_eq!(pthread_setspecific(key, 7), 0);
        assert_eq!(pthread_getspecific(key), 7);
    }

    #[test]
    fn exhausted_generation_never_aliases_stale_values() {
        let _g = lock_and_reset();
        KEY_SLOTS[0]
            .generation
            .store(LAST_KEY_GENERATION - 1, Ordering::Release);
        let last = create_key(None);
        assert_eq!(last.id >> 10, LAST_KEY_GENERATION);
        assert_eq!(pthread_setspecific(last, 0xbeef), 0);
        assert_eq!(pthread_key_delete(last), 0);
        let next = create_key(None);
        assert_eq!(next.id & 1023, 1);
        assert_eq!(pthread_setspecific(next, 0xcafe), 0);
        assert_eq!(pthread_getspecific(next), 0xcafe);
        assert_eq!(pthread_setspecific(last, 1), EINVAL);
    }

    #[test]
    fn generation_counter_increments_on_create_and_delete() {
        let _g = lock_and_reset();
        let k = create_key(None);
        let slot = (k.id & 1023) as usize; // Extract slot index from lower 10 bits

        let seq_after_create = KEY_SLOTS[slot].generation.load(Ordering::Acquire);
        assert!(seq_after_create >= 1, "seq should be >= 1 after create");

        assert_eq!(pthread_key_delete(k), 0);
        let seq_after_delete = KEY_SLOTS[slot].generation.load(Ordering::Acquire);
        assert_eq!(
            seq_after_delete,
            seq_after_create + 1,
            "seq should increment on delete"
        );
    }

    #[test]
    fn full_identity_table_rejects_native_creation_before_user_code() {
        let _g = lock_and_reset();
        static ENTERED: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn entry(_: usize) -> usize {
            ENTERED.fetch_add(1, AtomicOrdering::SeqCst);
            0
        }
        ENTERED.store(0, AtomicOrdering::SeqCst);
        let mut block = TestTlsBlock::new();
        for index in 0..TLS_TABLE_SLOTS {
            // Linux TIDs cannot reach this range. Each fake identity occupies
            // one slot without interfering with the real creator/child TIDs.
            table_register(i32::MAX - index as i32, block.as_mut_ptr());
        }
        let result =
            unsafe { super::super::thread::create_thread(entry as *const () as usize, 0, 0) };
        let error = match result {
            Err(error) => error,
            Ok(handle) => {
                // Reclaim the unexpected child before reporting a regression.
                let _ = unsafe { super::super::thread::join_thread(handle) };
                0
            }
        };
        for index in 0..TLS_TABLE_SLOTS {
            table_remove(i32::MAX - index as i32);
        }
        assert_eq!(error, 11, "identity exhaustion must report EAGAIN");
        assert_eq!(ENTERED.load(AtomicOrdering::SeqCst), 0);
    }

    #[test]
    fn cancellation_requests_retire_with_native_identity() {
        let _g = lock_and_reset();
        let first_tid = 1001;
        let next_tid = first_tid + TLS_TABLE_SLOTS as i32;
        let index = first_tid as usize % TLS_TABLE_SLOTS;
        let mut block = TestTlsBlock::new();
        let address = block.as_mut_ptr() as usize;
        assert!(table_register(first_tid, block.as_mut_ptr()));
        let old_generation = TLS_CANCEL_WORDS[index].load(Ordering::Acquire);
        assert!(request_thread_cancellation(address));
        assert!(take_thread_cancellation(first_tid));
        assert!(!take_thread_cancellation(first_tid));

        // Return with an unconsumed request, then reuse both the registration
        // slot and the allocation address for a different thread.
        assert!(request_thread_cancellation(address));
        table_remove(first_tid);
        assert!(!request_thread_cancellation(address));
        assert!(table_register(next_tid, block.as_mut_ptr()));
        assert!(!take_thread_cancellation(next_tid));

        // A requester paused between observing the old address/generation and
        // publishing its request must not cancel the replacement identity.
        assert!(!request_cancel_generation(index, old_generation));
        assert!(!take_thread_cancellation(next_tid));
        assert!(request_thread_cancellation(address));
        assert!(take_thread_cancellation(next_tid));
        table_remove(next_tid);
    }

    #[test]
    fn cancellation_preparation_failure_does_not_publish_a_request() {
        let _g = lock_and_reset();
        let tid = 1001;
        let mut block = TestTlsBlock::new();
        let address = block.as_mut_ptr() as usize;
        assert!(table_register(tid, block.as_mut_ptr()));
        let wait = thread_cancellation_wait(tid).unwrap();

        assert_eq!(
            request_thread_cancellation_with_info(address, || Err(1)),
            Err(1),
            "EPERM from signal setup must reject the whole request"
        );
        assert!(!wait.pending());
        assert!(!take_thread_cancellation(tid));

        assert_eq!(
            request_thread_cancellation_with_info(address, || Ok(())),
            Ok(Some((tid, 0))),
            "a failed preparation must remain retryable"
        );
        assert!(wait.pending());
        assert!(take_thread_cancellation(tid));
        table_remove(tid);

        assert_eq!(
            request_thread_cancellation_with_info(address, || panic!("absent target")),
            Ok(None),
            "non-native targets must not initialize native signal delivery"
        );
    }

    #[test]
    fn cancellation_preparation_cannot_cross_a_reused_identity() {
        let _g = lock_and_reset();
        let first_tid = 1001;
        let next_tid = first_tid + TLS_TABLE_SLOTS as i32;
        let mut block = TestTlsBlock::new();
        let address = block.as_mut_ptr() as usize;
        assert!(table_register(first_tid, block.as_mut_ptr()));

        let result = request_thread_cancellation_with_info(address, || {
            // Simulate exit and allocator/table-slot reuse while signal setup
            // runs. The request must still belong to the captured generation.
            assert_eq!(table_remove(first_tid) as usize, address);
            assert!(table_register(next_tid, block.as_mut_ptr()));
            Ok(())
        });
        assert_eq!(result, Ok(None));
        assert!(!take_thread_cancellation(next_tid));
        assert!(request_thread_cancellation(address));
        assert!(take_thread_cancellation(next_tid));
        table_remove(next_tid);
    }

    #[test]
    fn cancellation_wait_tracks_pending_without_consuming_it() {
        let _g = lock_and_reset();
        let tid = 1001;
        let mut block = TestTlsBlock::new();
        let address = block.as_mut_ptr() as usize;
        assert!(thread_cancellation_wait(tid).is_none());
        assert!(table_register(tid, block.as_mut_ptr()));
        let wait = thread_cancellation_wait(tid).unwrap();
        assert_eq!(wait.address() as usize % core::mem::align_of::<u32>(), 0);
        assert_eq!(wait.expected() & CANCEL_PENDING as u32, 0);
        assert!(!wait.pending());

        assert!(request_thread_cancellation(address));
        assert!(wait.pending());
        assert!(wait.pending(), "inspection must not consume the request");
        let pending_wait = thread_cancellation_wait(tid).unwrap();
        assert_eq!(pending_wait.expected(), wait.expected());
        assert!(pending_wait.pending());
        assert!(take_thread_cancellation(tid));
        assert!(!wait.pending());
        assert!(!take_thread_cancellation(tid));
        table_remove(tid);
        assert!(!wait.pending());
        assert!(thread_cancellation_wait(tid).is_none());
    }

    #[test]
    fn cancellation_wait_rejects_reused_generation_with_same_low_word() {
        let _g = lock_and_reset();
        let tid = 1001;
        let next_tid = tid + TLS_TABLE_SLOTS as i32;
        let index = tid as usize % TLS_TABLE_SLOTS;
        let mut block = TestTlsBlock::new();
        let address = block.as_mut_ptr() as usize;
        assert!(table_register(tid, block.as_mut_ptr()));
        let old = thread_cancellation_wait(tid).unwrap();
        assert!(request_thread_cancellation(address));
        assert!(old.pending());
        table_remove(tid);

        assert!(table_register(next_tid, block.as_mut_ptr()));
        // Model the low 32-bit generation wrapping while the complete lifetime
        // remains distinct. Neither descriptor dereferences the retired handle.
        TLS_CANCEL_WORDS[index].store(old.generation + (1u64 << 32), Ordering::Release);
        let next = thread_cancellation_wait(next_tid).unwrap();
        assert_eq!(old.address(), next.address());
        assert_eq!(old.expected(), next.expected());
        assert!(!request_cancel_generation(index, old.generation));
        assert!(request_thread_cancellation(address));
        assert!(!old.pending());
        assert!(next.pending());
        assert!(take_thread_cancellation(next_tid));
        table_remove(next_tid);
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn cancellation_wait_pending_request_cannot_park() {
        let _g = lock_and_reset();
        let tid = 1001;
        let mut block = TestTlsBlock::new();
        assert!(table_register(tid, block.as_mut_ptr()));
        let wait = thread_cancellation_wait(tid).unwrap();
        assert!(request_thread_cancellation(block.as_mut_ptr() as usize));
        let timeout = syscall::Timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        // The request preceded the wait, so correctness depends on the changed
        // word, not on the already-completed wake. The deadline bounds a broken
        // address/endianness implementation instead of hanging the test.
        let result = unsafe {
            syscall::sys_futex(
                wait.address(),
                0x80, // FUTEX_WAIT_PRIVATE
                wait.expected(),
                core::ptr::from_ref(&timeout) as usize,
                0,
                0,
            )
        };
        table_remove(tid);
        assert_eq!(result, Err(EAGAIN));
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn cancellation_request_wakes_an_already_parked_waiter() {
        let _g = lock_and_reset();
        let mut block = TestTlsBlock::new();
        let values_address = block.as_mut_ptr() as usize;
        let waiter_tid = AtomicI32::new(0);
        let waiter_address = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                let tid = current_tid();
                // A container can mount procfs from a parent PID namespace.
                // Resolve this task's proc-visible ID instead of assuming that
                // the kernel TID returned in our namespace names its proc path.
                let task = std::fs::read_link("/proc/thread-self").unwrap();
                let proc_tid = task.file_name().unwrap().to_str().unwrap().parse().unwrap();
                assert!(table_register(tid, values_address as *mut TlsEntry));
                let wait = thread_cancellation_wait(tid).unwrap();
                waiter_address.store(wait.address() as usize, Ordering::Release);
                waiter_tid.store(proc_tid, Ordering::Release);
                let timeout = syscall::Timespec {
                    tv_sec: 3,
                    tv_nsec: 0,
                };
                let result = unsafe {
                    syscall::sys_futex(
                        wait.address(),
                        0x80, // FUTEX_WAIT_PRIVATE
                        wait.expected(),
                        core::ptr::from_ref(&timeout) as usize,
                        0,
                        0,
                    )
                };
                let pending = wait.pending();
                table_remove(tid);
                (result, pending)
            });

            // Observe the actual syscall, rather than treating publication of
            // a readiness flag as proof that the kernel has parked the waiter.
            let limit = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut parked = false;
            while std::time::Instant::now() < limit {
                let tid = waiter_tid.load(Ordering::Acquire);
                if tid > 0
                    && let Ok(snapshot) =
                        std::fs::read_to_string(format!("/proc/self/task/{tid}/syscall"))
                {
                    let mut fields = snapshot.split_whitespace();
                    let number = fields.next().and_then(|field| field.parse::<usize>().ok());
                    let address = fields
                        .next()
                        .and_then(|field| field.strip_prefix("0x"))
                        .and_then(|field| usize::from_str_radix(field, 16).ok());
                    if number == Some(syscall::SYS_FUTEX)
                        && address == Some(waiter_address.load(Ordering::Acquire))
                    {
                        // /proc reports "running" for an active task. Require
                        // the sleeping state as well, so a request cannot race
                        // mere syscall entry before the kernel has parked it.
                        if let Ok(state) =
                            std::fs::read_to_string(format!("/proc/self/task/{tid}/stat"))
                            && state
                                .rsplit_once(") ")
                                .is_some_and(|(_, rest)| rest.as_bytes().first() == Some(&b'S'))
                        {
                            parked = true;
                            break;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let requested = request_thread_cancellation(values_address);
            let (result, pending) = waiter.join().unwrap();
            assert!(
                parked,
                "the cancellation target never reached its futex wait"
            );
            assert!(requested, "the live registration must accept cancellation");
            assert_eq!(
                result,
                Ok(0),
                "the cancellation request must wake the futex"
            );
            assert!(pending, "waking must leave delivery to the owner");
        });
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

    #[test]
    fn unregistered_native_cancellation_tracks_flags_and_retires_cleanly() {
        let _g = lock_and_reset();
        let tid = 424_242;
        set_native_cancel_disabled(tid, true);
        set_native_cancel_point_active(tid, true);
        let flags = request_unregistered_cancellation_with_flags(tid).expect("slot allocated");
        assert!(!native_cancel_signal_needed(flags));

        set_native_cancel_disabled(tid, false);
        let wait = unregistered_cancellation_wait(tid).expect("wait descriptor");
        assert_eq!(wait.tid(), tid);
        assert!(wait.pending());
        assert!(take_unregistered_cancellation(tid));
        assert!(!wait.pending());

        let flags_live = request_unregistered_cancellation_with_flags(tid).expect("slot live");
        assert!(native_cancel_signal_needed(flags_live));

        retire_unregistered_cancellation(tid);
        assert!(!wait.pending());
        assert!(!take_unregistered_cancellation(tid));
    }
}
