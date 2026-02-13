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

#[cfg(target_arch = "x86_64")]
use crate::syscall;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Maximum number of TLS keys (POSIX requires >= 128; glibc uses 1024).
pub const PTHREAD_KEYS_MAX: usize = 1024;

/// Maximum destructor-call iterations on thread exit (POSIX requires >= 4).
pub const PTHREAD_DESTRUCTOR_ITERATIONS: usize = 4;

/// Maximum concurrent threads tracked in the TLS table.
const TLS_TABLE_SLOTS: usize = 4096;

const EAGAIN: i32 = 11;
const EINVAL: i32 = 22;

/// Thread-local storage key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PthreadKey {
    /// Key index into the global registry (0..PTHREAD_KEYS_MAX-1).
    pub(crate) id: u32,
}

// ---------------------------------------------------------------------------
// Global key registry
// ---------------------------------------------------------------------------

/// A single slot in the global key registry.
#[derive(Clone, Copy)]
struct KeySlot {
    in_use: bool,
    destructor: Option<fn(u64)>,
    /// Generation counter — incremented on create and delete to detect stale keys.
    seq: u32,
}

const EMPTY_SLOT: KeySlot = KeySlot {
    in_use: false,
    destructor: None,
    seq: 0,
};

struct KeyRegistry {
    slots: [KeySlot; PTHREAD_KEYS_MAX],
}

static KEY_REGISTRY: Mutex<KeyRegistry> = Mutex::new(KeyRegistry {
    slots: [EMPTY_SLOT; PTHREAD_KEYS_MAX],
});

// ---------------------------------------------------------------------------
// Per-thread value storage — allocation-free concurrent table
// ---------------------------------------------------------------------------

/// TID array for open-addressed hash table. 0 = empty slot.
static TLS_TIDS: [AtomicI32; TLS_TABLE_SLOTS] =
    [const { AtomicI32::new(0) }; TLS_TABLE_SLOTS];

/// Pointer array (paired with TLS_TIDS). Stores `*mut [u64; PTHREAD_KEYS_MAX]`
/// cast to usize. 0 = no pointer.
static TLS_PTRS: [AtomicUsize; TLS_TABLE_SLOTS] =
    [const { AtomicUsize::new(0) }; TLS_TABLE_SLOTS];

/// Static TLS values for the main thread (and any thread that calls setspecific
/// before being explicitly registered).
static MAIN_TLS_VALUES: MainTlsBlock = MainTlsBlock::new();

/// Wrapper around a fixed TLS value array for the main thread.
/// Uses a Mutex for interior mutability since we can't use UnsafeCell in safe code
/// across threads. The main thread can safely take the lock.
struct MainTlsBlock {
    values: [AtomicUsize; PTHREAD_KEYS_MAX],
}

impl MainTlsBlock {
    const fn new() -> Self {
        Self {
            values: [const { AtomicUsize::new(0) }; PTHREAD_KEYS_MAX],
        }
    }
}

/// Register a TID → values-pointer mapping in the global table.
///
/// This function is **allocation-free** and safe to call from clone-based threads.
fn table_register(tid: i32, values_ptr: *mut u64) {
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let current = TLS_TIDS[idx].load(Ordering::Acquire);
        if current == 0 {
            // Try to claim this empty slot.
            if TLS_TIDS[idx]
                .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                TLS_PTRS[idx].store(values_ptr as usize, Ordering::Release);
                return;
            }
            // CAS failed — another thread took this slot. Continue probing.
        }
        if current == tid {
            // Already registered (shouldn't happen, but handle gracefully).
            TLS_PTRS[idx].store(values_ptr as usize, Ordering::Release);
            return;
        }
    }
    // Table full. In practice, 4096 slots is sufficient.
}

/// Look up the TLS values pointer for a given TID.
///
/// Returns a raw pointer to `[u64; PTHREAD_KEYS_MAX]`, or null if not found.
/// **Allocation-free.**
fn table_lookup(tid: i32) -> *mut u64 {
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            let ptr = TLS_PTRS[idx].load(Ordering::Acquire);
            return ptr as *mut u64;
        }
        if stored_tid == 0 {
            return core::ptr::null_mut();
        }
    }
    core::ptr::null_mut()
}

/// Remove a TID from the table and return its values pointer.
///
/// **Allocation-free.**
fn table_remove(tid: i32) -> *mut u64 {
    let start = (tid as u32 as usize) % TLS_TABLE_SLOTS;
    for i in 0..TLS_TABLE_SLOTS {
        let idx = (start + i) % TLS_TABLE_SLOTS;
        let stored_tid = TLS_TIDS[idx].load(Ordering::Acquire);
        if stored_tid == tid {
            let ptr = TLS_PTRS[idx].swap(0, Ordering::AcqRel);
            TLS_TIDS[idx].store(0, Ordering::Release);
            return ptr as *mut u64;
        }
        if stored_tid == 0 {
            return core::ptr::null_mut();
        }
    }
    core::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Thread identification
// ---------------------------------------------------------------------------

/// Get the calling thread's kernel TID.
#[cfg(target_arch = "x86_64")]
fn current_tid() -> i32 {
    syscall::sys_gettid()
}

// ---------------------------------------------------------------------------
// Internal: read/write per-thread TLS value
// ---------------------------------------------------------------------------

/// Read a TLS value for the given TID and key index.
/// Falls back to the main thread's static block if the TID is not in the table.
fn read_tls_value(tid: i32, key_id: usize) -> u64 {
    let ptr = table_lookup(tid);
    if !ptr.is_null() {
        // SAFETY: ptr points to a valid `[u64; PTHREAD_KEYS_MAX]` that is either
        // embedded in a ThreadHandle (alive while the thread runs) or in a
        // test-allocated block. key_id < PTHREAD_KEYS_MAX checked by caller.
        unsafe { *ptr.add(key_id) }
    } else {
        // Main thread or unregistered thread: use static block.
        MAIN_TLS_VALUES.values[key_id].load(Ordering::Acquire) as u64
    }
}

/// Write a TLS value for the given TID and key index.
/// Falls back to the main thread's static block if the TID is not in the table.
fn write_tls_value(tid: i32, key_id: usize, value: u64) {
    let ptr = table_lookup(tid);
    if !ptr.is_null() {
        // SAFETY: ptr points to a valid `[u64; PTHREAD_KEYS_MAX]` owned by this
        // thread. Only the owning thread writes to its own values.
        unsafe { *ptr.add(key_id) = value };
    } else {
        // Main thread or unregistered thread: use static block.
        MAIN_TLS_VALUES.values[key_id].store(value as usize, Ordering::Release);
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
/// Returns 0 on success, `EAGAIN` if all keys are in use.
pub fn pthread_key_create(key: &mut PthreadKey, destructor: Option<fn(u64)>) -> i32 {
    let mut reg = KEY_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    for i in 0..PTHREAD_KEYS_MAX {
        if !reg.slots[i].in_use {
            reg.slots[i].in_use = true;
            reg.slots[i].destructor = destructor;
            reg.slots[i].seq = reg.slots[i].seq.wrapping_add(1);
            key.id = i as u32;
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
    let id = key.id as usize;
    if id >= PTHREAD_KEYS_MAX {
        return EINVAL;
    }
    let mut reg = KEY_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if !reg.slots[id].in_use {
        return EINVAL;
    }
    reg.slots[id].in_use = false;
    reg.slots[id].destructor = None;
    reg.slots[id].seq = reg.slots[id].seq.wrapping_add(1);
    0
}

/// Gets the value associated with the TLS key for the calling thread.
///
/// Equivalent to C `pthread_getspecific`. Returns the value, or 0 if
/// no value has been set (or the key is invalid).
#[cfg(target_arch = "x86_64")]
pub fn pthread_getspecific(key: PthreadKey) -> u64 {
    let id = key.id as usize;
    if id >= PTHREAD_KEYS_MAX {
        return 0;
    }
    let tid = current_tid();
    read_tls_value(tid, id)
}

/// Sets the value associated with the TLS key for the calling thread.
///
/// Equivalent to C `pthread_setspecific`. Returns 0 on success, `EINVAL`
/// if the key is invalid or deleted.
#[cfg(target_arch = "x86_64")]
pub fn pthread_setspecific(key: PthreadKey, value: u64) -> i32 {
    let id = key.id as usize;
    if id >= PTHREAD_KEYS_MAX {
        return EINVAL;
    }
    // Validate key is active.
    {
        let reg = KEY_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if !reg.slots[id].in_use {
            return EINVAL;
        }
    }
    let tid = current_tid();
    write_tls_value(tid, id, value);
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
#[cfg(target_arch = "x86_64")]
pub(crate) fn register_thread_tls(tid: i32, values_ptr: *mut u64) {
    table_register(tid, values_ptr);
}

/// Run TLS destructors for an exiting thread and remove its table entry.
///
/// **Allocation-free** — safe to call from clone-based threads.
///
/// Per POSIX, destructors are called up to `PTHREAD_DESTRUCTOR_ITERATIONS`
/// times. Each iteration:
/// 1. For each active key with a non-null value, snapshot the value and
///    set it to 0.
/// 2. Call the destructor with the snapshotted value.
/// 3. If any destructor set new non-null values, repeat.
///
/// After all iterations, the thread's table entry is removed.
#[cfg(target_arch = "x86_64")]
pub(crate) fn teardown_thread_tls(tid: i32) {
    let values_ptr = table_lookup(tid);
    if values_ptr.is_null() {
        return;
    }

    for _iteration in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        // Snapshot destructors and values under the key registry lock.
        // We collect into a stack-allocated array to avoid heap allocation.
        let mut call_count = 0usize;
        // Max 64 destructor calls per iteration to bound stack usage.
        // POSIX doesn't limit this but 64 is more than enough for practice.
        const MAX_CALLS: usize = 64;
        let mut calls: [(u64, fn(u64)); MAX_CALLS] = [(0, noop_destructor); MAX_CALLS];

        {
            let reg = KEY_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            for i in 0..PTHREAD_KEYS_MAX {
                if call_count >= MAX_CALLS {
                    break;
                }
                if reg.slots[i].in_use {
                    // SAFETY: values_ptr points to a valid [u64; PTHREAD_KEYS_MAX].
                    let value = unsafe { *values_ptr.add(i) };
                    if value != 0 {
                        // Clear the value before calling destructor.
                        unsafe { *values_ptr.add(i) = 0 };
                        if let Some(dtor) = reg.slots[i].destructor {
                            calls[call_count] = (value, dtor);
                            call_count += 1;
                        }
                    }
                }
            }
        }

        if call_count == 0 {
            break;
        }

        // Call destructors outside the lock.
        for &(value, dtor) in calls.iter().take(call_count) {
            dtor(value);
        }
    }

    // Remove from the table.
    table_remove(tid);
}

/// No-op destructor used as default in the calls array.
fn noop_destructor(_: u64) {}

// ---------------------------------------------------------------------------
// Test support: reset global state between tests
// ---------------------------------------------------------------------------

/// Reset all TLS global state. For testing only.
#[cfg(test)]
pub(crate) fn reset_tls_state() {
    {
        let mut reg = KEY_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        reg.slots = [EMPTY_SLOT; PTHREAD_KEYS_MAX];
    }
    // Clear the table.
    for i in 0..TLS_TABLE_SLOTS {
        TLS_TIDS[i].store(0, Ordering::Release);
        TLS_PTRS[i].store(0, Ordering::Release);
    }
    // Clear main thread values.
    for i in 0..PTHREAD_KEYS_MAX {
        MAIN_TLS_VALUES.values[i].store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as AtomicOrdering};

    // All TLS tests share global state (KEY_REGISTRY, TLS table). Serialize
    // them with a mutex so `reset_tls_state()` doesn't race with other tests.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire the test lock and reset global state.
    fn lock_and_reset() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_tls_state();
        guard
    }

    /// Helper: create a key, return it.
    fn create_key(dtor: Option<fn(u64)>) -> PthreadKey {
        let mut key = PthreadKey::default();
        let rc = pthread_key_create(&mut key, dtor);
        assert_eq!(rc, 0, "pthread_key_create failed");
        key
    }

    /// Per-thread values block for tests (heap-allocated, registered in table).
    struct TestTlsBlock {
        values: [u64; PTHREAD_KEYS_MAX],
    }

    impl TestTlsBlock {
        fn new() -> Box<Self> {
            Box::new(Self {
                values: [0; PTHREAD_KEYS_MAX],
            })
        }

        fn as_mut_ptr(&mut self) -> *mut u64 {
            self.values.as_mut_ptr()
        }
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
        let id1 = k1.id;
        assert_eq!(pthread_key_delete(k1), 0);
        let k2 = create_key(None);
        assert_eq!(k2.id, id1, "deleted slot should be reused");
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

        fn dtor(_val: u64) {
            DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
        }

        let key = create_key(Some(dtor));
        let tid = current_tid();

        let mut block = TestTlsBlock::new();
        block.values[key.id as usize] = 42;
        let ptr = block.as_mut_ptr();
        table_register(tid, ptr);

        teardown_thread_tls(tid);
        assert_eq!(DTOR_COUNT.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn destructor_iterates_when_value_reset() {
        let _g = lock_and_reset();
        static ITER_COUNT: AtomicU32 = AtomicU32::new(0);
        ITER_COUNT.store(0, AtomicOrdering::SeqCst);
        static KEY_ID: AtomicU32 = AtomicU32::new(0);

        fn dtor_reset(val: u64) {
            let count = ITER_COUNT.fetch_add(1, AtomicOrdering::SeqCst);
            if count < 2 {
                // Re-set the value so teardown iterates again.
                let key = PthreadKey {
                    id: KEY_ID.load(AtomicOrdering::SeqCst),
                };
                let _ = pthread_setspecific(key, val + 1);
            }
        }

        let key = create_key(Some(dtor_reset));
        KEY_ID.store(key.id, AtomicOrdering::SeqCst);

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.values[key.id as usize] = 1;
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
        let tid = current_tid();

        let mut block = TestTlsBlock::new();
        let ptr = block.as_mut_ptr();
        table_register(tid, ptr);

        write_tls_value(tid, key.id as usize, 99);
        assert_eq!(read_tls_value(tid, key.id as usize), 99);

        teardown_thread_tls(tid);

        // After teardown, table entry removed — falls back to main block.
        assert_eq!(read_tls_value(tid, key.id as usize), 0);
    }

    #[test]
    fn no_destructor_means_no_call() {
        let _g = lock_and_reset();
        let key = create_key(None); // No destructor.
        let tid = current_tid();

        let mut block = TestTlsBlock::new();
        block.values[key.id as usize] = 42;
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
        let key = PthreadKey { id: PTHREAD_KEYS_MAX as u32 + 1 };
        assert_eq!(pthread_getspecific(key), 0);
    }

    #[test]
    fn setspecific_out_of_bounds_key_returns_einval() {
        let _g = lock_and_reset();
        let key = PthreadKey { id: PTHREAD_KEYS_MAX as u32 + 1 };
        assert_eq!(pthread_setspecific(key, 42), EINVAL);
    }

    #[test]
    fn key_create_delete_create_reuses_slot_with_new_destructor() {
        let _g = lock_and_reset();
        static DTOR1_COUNT: AtomicU32 = AtomicU32::new(0);
        static DTOR2_COUNT: AtomicU32 = AtomicU32::new(0);
        DTOR1_COUNT.store(0, AtomicOrdering::SeqCst);
        DTOR2_COUNT.store(0, AtomicOrdering::SeqCst);

        fn dtor1(_: u64) { DTOR1_COUNT.fetch_add(1, AtomicOrdering::SeqCst); }
        fn dtor2(_: u64) { DTOR2_COUNT.fetch_add(1, AtomicOrdering::SeqCst); }

        let k1 = create_key(Some(dtor1));
        let id = k1.id;
        assert_eq!(pthread_key_delete(k1), 0);

        // Create with a different destructor — should reuse the same slot.
        let k2 = create_key(Some(dtor2));
        assert_eq!(k2.id, id, "slot should be reused");

        // Set a value and tear down to verify the new destructor fires.
        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.values[k2.id as usize] = 99;
        table_register(tid, block.as_mut_ptr());
        teardown_thread_tls(tid);

        assert_eq!(DTOR1_COUNT.load(AtomicOrdering::SeqCst), 0, "old destructor should not fire");
        assert_eq!(DTOR2_COUNT.load(AtomicOrdering::SeqCst), 1, "new destructor should fire");
    }

    #[test]
    fn generation_counter_increments_on_create_and_delete() {
        let _g = lock_and_reset();
        let k = create_key(None);
        let id = k.id as usize;

        // Read initial seq via the registry.
        let seq_after_create = {
            let reg = KEY_REGISTRY.lock().unwrap();
            reg.slots[id].seq
        };
        assert!(seq_after_create >= 1, "seq should be >= 1 after create");

        assert_eq!(pthread_key_delete(k), 0);
        let seq_after_delete = {
            let reg = KEY_REGISTRY.lock().unwrap();
            reg.slots[id].seq
        };
        assert_eq!(seq_after_delete, seq_after_create + 1, "seq should increment on delete");
    }

    #[test]
    fn table_register_same_tid_twice_overwrites() {
        let _g = lock_and_reset();
        let tid = current_tid();

        let mut block1 = TestTlsBlock::new();
        block1.values[0] = 111;
        table_register(tid, block1.as_mut_ptr());
        assert_eq!(read_tls_value(tid, 0), 111);

        // Re-register with a different block.
        let mut block2 = TestTlsBlock::new();
        block2.values[0] = 222;
        table_register(tid, block2.as_mut_ptr());
        assert_eq!(read_tls_value(tid, 0), 222);

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

    #[test]
    fn key_delete_does_not_call_destructors() {
        let _g = lock_and_reset();
        static DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        DTOR_COUNT.store(0, AtomicOrdering::SeqCst);
        fn dtor(_: u64) { DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst); }

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
        fn dtor(_: u64) { DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst); }

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
        fn dtor(val: u64) { DTOR_SUM.fetch_add(val as u32, AtomicOrdering::SeqCst); }

        const N: usize = 8;
        let mut keys = Vec::with_capacity(N);
        for _ in 0..N {
            keys.push(create_key(Some(dtor)));
        }

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        for (i, k) in keys.iter().enumerate() {
            block.values[k.id as usize] = (i + 1) as u64;
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
        fn dtor_always_reset(_val: u64) {
            let count = DTOR_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
            // Always re-set, even past the iteration limit.
            let key = PthreadKey { id: KEY_SLOT.load(AtomicOrdering::SeqCst) };
            let _ = pthread_setspecific(key, (count as u64) + 100);
        }

        let key = create_key(Some(dtor_always_reset));
        KEY_SLOT.store(key.id, AtomicOrdering::SeqCst);

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.values[key.id as usize] = 1;
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        let calls = DTOR_CALLS.load(AtomicOrdering::SeqCst);
        // Should be bounded by PTHREAD_DESTRUCTOR_ITERATIONS (4).
        assert!(
            calls <= PTHREAD_DESTRUCTOR_ITERATIONS as u32,
            "destructor calls ({calls}) should be bounded by PTHREAD_DESTRUCTOR_ITERATIONS ({})",
            PTHREAD_DESTRUCTOR_ITERATIONS
        );
        assert!(calls >= 1, "destructor should have been called at least once");
    }

    #[test]
    fn mixed_destructors_some_with_some_without() {
        let _g = lock_and_reset();
        static WITH_DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
        WITH_DTOR_COUNT.store(0, AtomicOrdering::SeqCst);
        fn dtor(_: u64) { WITH_DTOR_COUNT.fetch_add(1, AtomicOrdering::SeqCst); }

        // Create 4 keys: 2 with destructor, 2 without.
        let k_with_1 = create_key(Some(dtor));
        let k_without_1 = create_key(None);
        let k_with_2 = create_key(Some(dtor));
        let k_without_2 = create_key(None);

        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.values[k_with_1.id as usize] = 10;
        block.values[k_without_1.id as usize] = 20;
        block.values[k_with_2.id as usize] = 30;
        block.values[k_without_2.id as usize] = 40;
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
        fn dtor(val: u64) { RECEIVED_VALUE.store(val, AtomicOrdering::SeqCst); }

        let key = create_key(Some(dtor));
        let tid = current_tid();
        let mut block = TestTlsBlock::new();
        block.values[key.id as usize] = 0xCAFE_BABE;
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        assert_eq!(RECEIVED_VALUE.load(AtomicOrdering::SeqCst), 0xCAFE_BABE);
    }

    #[test]
    fn destructor_clears_value_before_calling() {
        let _g = lock_and_reset();
        static OBSERVED_VALUES: Mutex<Vec<u64>> = Mutex::new(Vec::new());
        static KEY_SLOT2: AtomicU32 = AtomicU32::new(0);

        fn dtor_check_cleared(val: u64) {
            OBSERVED_VALUES.lock().unwrap().push(val);
            // Read the value for this key — it should already be cleared to 0.
            let key = PthreadKey { id: KEY_SLOT2.load(AtomicOrdering::SeqCst) };
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
        block.values[key.id as usize] = 777;
        table_register(tid, block.as_mut_ptr());

        teardown_thread_tls(tid);

        let vals = OBSERVED_VALUES.lock().unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0], 777, "destructor should receive the original value");
    }
}
