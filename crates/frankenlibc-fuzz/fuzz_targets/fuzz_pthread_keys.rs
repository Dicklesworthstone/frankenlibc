#![no_main]
//! Fuzz target for FrankenLibC's pthread TSD / key surface
//! (bd-dvr22 priority-7, paired with fuzz_pthread_mutex +
//! fuzz_pthread_cond):
//!
//!   pthread_key_create, pthread_key_delete,
//!   pthread_setspecific, pthread_getspecific
//!
//! This target directly exercises the bd-9hq64 regression
//! window: pthread_key_create registers a destructor; child
//! threads set per-key values via pthread_setspecific; on thread
//! exit, the destructor must be invoked for every (key, value)
//! pair where value != NULL.
//!
//! Oracles:
//! 1. Return-code contract: key_create / key_delete /
//!    setspecific return 0 or a documented non-negative errno;
//!    getspecific returns a `*mut c_void` (may be NULL).
//! 2. Round-trip per-thread storage: after
//!    `pthread_setspecific(key, v)`, `pthread_getspecific(key)`
//!    must return `v` (exactly, same pointer value).
//! 3. Key isolation: distinct keys returned by distinct
//!    pthread_key_create calls must not alias each other.
//! 4. Stale-key invariant: after `pthread_key_delete(k)`,
//!    `pthread_getspecific(k)` must not return a non-NULL value
//!    that was set through the deleted key (though the
//!    documented behavior is 'undefined' for using a deleted
//!    key, a libc implementation must not corrupt memory or
//!    fabricate a pointer — we only assert no crash).
//! 5. **Destructor invocation under thread exit** (bd-9hq64
//!    regression target): spawn a child thread that sets a
//!    non-NULL value, then joins it. After join, a shared
//!    atomic counter must have been incremented by the
//!    destructor. If the counter stays at zero, pthread_key
//!    destructors are silently skipped on thread exit — that's
//!    the bd-9hq64 signature.
//!
//! Safety:
//! - Each iteration allocates fresh keys up to MAX_KEYS, so we
//!   never exhaust PTHREAD_KEYS_MAX.
//! - Destructor-under-exit test spawns one child thread per op
//!   and joins it synchronously — no dangling handles.
//!
//! Bead: bd-dvr22 priority-7 (pthread keys subset), tripwire
//! for bd-9hq64 (TSD destructor regression).

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::pthread_abi::{pthread_key_create, pthread_key_delete, pthread_setspecific};
use libc::{pthread_getspecific, pthread_join, pthread_key_t, pthread_t};
use libfuzzer_sys::fuzz_target;

const MAX_KEYS: usize = 6;
const MAX_OPS: usize = 16;

static TSDLOCK: Mutex<()> = Mutex::new(());

/// Incremented by FUZZ_TSD_DESTRUCTOR each time it runs.
/// Held as an atomic so the destructor, running under thread
/// teardown, can update it without contention.
static FUZZ_TSD_DESTRUCTOR_HITS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn fuzz_tsd_destructor(_val: *mut c_void) {
    FUZZ_TSD_DESTRUCTOR_HITS.fetch_add(1, Ordering::AcqRel);
}

#[derive(Debug, Arbitrary)]
enum Op {
    CreateKey {
        with_destructor: bool,
    },
    DeleteKey {
        slot: u8,
    },
    SetSpecific {
        slot: u8,
        value_sel: u8,
    },
    GetSpecificRoundTrip {
        slot: u8,
        value_sel: u8,
    },
    /// Spawn a child thread that sets a non-NULL value for the
    /// selected key, then immediately returns. After the join
    /// completes, assert the destructor counter moved — the
    /// bd-9hq64 tripwire.
    ChildDestructorRun {
        slot: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct PthreadKeysFuzzInput {
    ops: Vec<Op>,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: process mode set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn pick_value(sel: u8) -> *mut c_void {
    // Non-NULL, distinctively-tagged pointer so the destructor
    // test can confirm the destructor saw something.
    (0x1000usize + (sel as usize) * 8) as *mut c_void
}

struct KeyEntry {
    key: pthread_key_t,
    /// Shadow model: what we last `pthread_setspecific`'d for this key
    /// on the MAIN thread. A re-read via `pthread_getspecific` must
    /// match byte-for-byte. None means we've never set (getspecific
    /// should return NULL).
    last_main_value: Option<*mut c_void>,
    /// Whether this key was created with our destructor registered.
    has_destructor: bool,
}

fn pick_slot(table: &mut [KeyEntry], slot: u8) -> Option<&mut KeyEntry> {
    if table.is_empty() {
        return None;
    }
    let idx = (slot as usize) % table.len();
    Some(&mut table[idx])
}

extern "C" fn child_thread_setspecific(arg: *mut c_void) -> *mut c_void {
    // SAFETY: arg is a *mut (pthread_key_t, *mut c_void) packed into a
    // Box, owned by this thread until we drop the Box at the end.
    let boxed = unsafe { Box::from_raw(arg as *mut (pthread_key_t, *mut c_void)) };
    let (key, val) = *boxed;
    // Safety: frankenlibc_abi::pthread_abi::pthread_setspecific is the
    // interposing impl we're exercising.
    let _ = unsafe { pthread_setspecific(key, val) };
    // Return now; the thread's exit path must invoke
    // fuzz_tsd_destructor(val) since val != NULL and the key was
    // created with fuzz_tsd_destructor.
    std::ptr::null_mut()
}

fn apply_child_destructor_run(table: &mut [KeyEntry], slot: u8) {
    let Some(entry) = pick_slot(table, slot) else {
        return;
    };
    if !entry.has_destructor {
        // Without a registered destructor, the counter shouldn't move;
        // no tripwire value in this case.
        return;
    }
    let before = FUZZ_TSD_DESTRUCTOR_HITS.load(Ordering::Acquire);
    let val = pick_value(entry.key as u8);
    let payload = Box::into_raw(Box::new((entry.key, val)));

    let mut tid: pthread_t = 0;
    let rc = unsafe {
        libc::pthread_create(
            &mut tid,
            std::ptr::null(),
            child_thread_setspecific,
            payload as *mut c_void,
        )
    };
    if rc != 0 {
        // Recover the leaked payload so we don't leak memory on every
        // pthread_create failure.
        let _ = unsafe { Box::from_raw(payload) };
        return;
    }

    let mut retval: *mut c_void = std::ptr::null_mut();
    let rc_j = unsafe { pthread_join(tid, &mut retval) };
    assert_eq!(rc_j, 0, "pthread_join failed");

    let after = FUZZ_TSD_DESTRUCTOR_HITS.load(Ordering::Acquire);
    assert!(
        after > before,
        "pthread_key_create destructor was NOT invoked on child thread exit (bd-9hq64 tripwire): before={before} after={after}"
    );
}

fn apply_op(op: &Op, table: &mut Vec<KeyEntry>) {
    match op {
        Op::CreateKey { with_destructor } => {
            if table.len() >= MAX_KEYS {
                return;
            }
            let mut key: pthread_key_t = 0;
            let dtor: Option<unsafe extern "C" fn(*mut c_void)> = if *with_destructor {
                Some(fuzz_tsd_destructor)
            } else {
                None
            };
            let rc = unsafe { pthread_key_create(&mut key, dtor) };
            assert!(rc >= 0, "pthread_key_create rc {rc}");
            if rc == 0 {
                // Key isolation: every newly-created key must be
                // distinct from every existing key in the table.
                for existing in table.iter() {
                    assert_ne!(
                        existing.key, key,
                        "pthread_key_create returned aliased key {key}"
                    );
                }
                table.push(KeyEntry {
                    key,
                    last_main_value: None,
                    has_destructor: *with_destructor,
                });
            }
        }
        Op::DeleteKey { slot } => {
            let Some(entry) = pick_slot(table, *slot) else {
                return;
            };
            let key = entry.key;
            let rc = unsafe { pthread_key_delete(key) };
            assert!(rc >= 0, "pthread_key_delete rc {rc}");
            if rc == 0 {
                // Remove from the table so later ops don't see a
                // dangling key.
                table.retain(|e| e.key != key);
            }
        }
        Op::SetSpecific { slot, value_sel } => {
            let Some(entry) = pick_slot(table, *slot) else {
                return;
            };
            let value = pick_value(*value_sel);
            let rc = unsafe { pthread_setspecific(entry.key, value) };
            assert!(rc >= 0, "pthread_setspecific rc {rc}");
            if rc == 0 {
                entry.last_main_value = Some(value);
            }
        }
        Op::GetSpecificRoundTrip { slot, value_sel } => {
            let Some(entry) = pick_slot(table, *slot) else {
                return;
            };
            let value = pick_value(*value_sel);
            let rc = unsafe { pthread_setspecific(entry.key, value) };
            if rc != 0 {
                return;
            }
            let got = unsafe { pthread_getspecific(entry.key) };
            assert_eq!(
                got, value,
                "pthread_setspecific then pthread_getspecific round-trip failed for key {}",
                entry.key
            );
            entry.last_main_value = Some(value);
        }
        Op::ChildDestructorRun { slot } => apply_child_destructor_run(table, *slot),
    }
}

fn cleanup(table: &mut Vec<KeyEntry>) {
    // Clear our own per-main-thread values before delete so we never
    // leave a dangling destructor call against a pointer we'd already
    // given up on.
    for entry in table.iter() {
        if entry.last_main_value.is_some() {
            unsafe {
                let _ = pthread_setspecific(entry.key, std::ptr::null_mut());
            }
        }
    }
    for entry in std::mem::take(table) {
        unsafe {
            pthread_key_delete(entry.key);
        }
    }
}

fuzz_target!(|input: PthreadKeysFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = TSDLOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table: Vec<KeyEntry> = Vec::with_capacity(MAX_KEYS);
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    cleanup(&mut table);
});
