#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // C11 threads ABI entry points

//! Relocated from an inline `#[cfg(test)]` block in `c11threads_abi.rs`
//! (bd-xh08pf). That module is declared `#[cfg(not(test))]` in lib.rs, so the
//! block was dead by construction and its five assertions had never executed.
//!
//! Three moved unchanged. Two could not: they read module-PRIVATE items
//! (`pthread_rc_to_thrd`, and the `THRD_*` / `MTX_*` constants). Rather than
//! widen the ABI surface just to keep a test compiling, they are rewritten to
//! assert the same contract through PUBLIC entry points — which is a stronger
//! test, because it checks the values callers actually observe rather than that
//! a private constant equals a literal.
//!
//! The expected numbers are not from memory: they are the values glibc's
//! `<threads.h>` defines on this platform, and fl's private constants agree
//! with them.
//!   thrd_success 0, thrd_busy 1, thrd_error 2, thrd_nomem 3, thrd_timedout 4
//!   mtx_plain 0, mtx_recursive 1, mtx_timed 2

use std::ffi::c_int;

use frankenlibc_abi::c11threads_abi as c11;

// C11 return codes, per glibc <threads.h> on this platform.
const THRD_SUCCESS: c_int = 0;
const THRD_BUSY: c_int = 1;
const THRD_ERROR: c_int = 2;
const THRD_TIMEDOUT: c_int = 4;

// C11 mutex kinds.
const MTX_PLAIN: c_int = 0;
const MTX_TIMED: c_int = 2;

type MtxT = libc::pthread_mutex_t;

fn fresh_mtx() -> MtxT {
    // SAFETY: pthread_mutex_t is a POD blob; mtx_init initialises it below.
    unsafe { std::mem::zeroed() }
}

#[test]
fn thrd_current_returns_nonzero() {
    let tid = c11::thrd_current();
    // On Linux pthread_self() is always non-zero.
    assert_ne!(tid, 0);
}

#[test]
fn thrd_equal_same_thread() {
    let tid = c11::thrd_current();
    assert_ne!(c11::thrd_equal(tid, tid), 0);
}

#[test]
fn mtx_init_rejects_invalid_flags() {
    let mut mtx = fresh_mtx();
    // SAFETY: `mtx` is a valid, owned mutex slot.
    let rc = unsafe { c11::mtx_init(&mut mtx as *mut MtxT, 0x4) };
    assert_eq!(rc, THRD_ERROR, "an unknown mutex kind must be thrd_error");
}

/// Replaces the old `constants_match_c11_spec`, which asserted that private
/// constants equalled literals — nearly tautological, and invisible to callers.
/// This asserts the values fl actually RETURNS from public entry points.
#[test]
fn public_entry_points_return_c11_codes() {
    let mut mtx = fresh_mtx();
    // SAFETY: valid slot; destroyed at the end.
    unsafe {
        assert_eq!(
            c11::mtx_init(&mut mtx as *mut MtxT, MTX_PLAIN),
            THRD_SUCCESS,
            "mtx_init(mtx_plain) must return thrd_success (0)"
        );
        assert_eq!(
            c11::mtx_lock(&mut mtx as *mut MtxT),
            THRD_SUCCESS,
            "mtx_lock must return thrd_success (0)"
        );
        assert_eq!(
            c11::mtx_unlock(&mut mtx as *mut MtxT),
            THRD_SUCCESS,
            "mtx_unlock must return thrd_success (0)"
        );
        c11::mtx_destroy(&mut mtx as *mut MtxT);
    }
}

/// Replaces the old `pthread_rc_mapping`, which called the private
/// `pthread_rc_to_thrd` helper directly. The mapping is observable through
/// public behaviour for the codes that can actually be provoked, so it is
/// asserted that way instead.
///
/// Only the provokable arms are covered — EBUSY and ETIMEDOUT. EAGAIN/ENOMEM
/// (-> thrd_nomem) cannot be induced without exhausting resources, so they are
/// deliberately NOT asserted here rather than faked; the old inline test could
/// only check them because it reached into the helper, and it never ran anyway.
#[test]
fn error_mapping_is_observable_through_public_api() {
    // EBUSY -> thrd_busy: trylock on a mutex this thread already holds.
    let mut mtx = fresh_mtx();
    // SAFETY: valid slot, locked then released below.
    unsafe {
        assert_eq!(c11::mtx_init(&mut mtx as *mut MtxT, MTX_PLAIN), THRD_SUCCESS);
        assert_eq!(c11::mtx_lock(&mut mtx as *mut MtxT), THRD_SUCCESS);
        assert_eq!(
            c11::mtx_trylock(&mut mtx as *mut MtxT),
            THRD_BUSY,
            "trylock on a held mutex must map EBUSY -> thrd_busy (1)"
        );
        assert_eq!(c11::mtx_unlock(&mut mtx as *mut MtxT), THRD_SUCCESS);
        c11::mtx_destroy(&mut mtx as *mut MtxT);
    }

    // ETIMEDOUT -> thrd_timedout: timedlock a held mutex with a past deadline.
    // Uses a second thread to hold the lock, because a plain mutex re-locked by
    // its owner is undefined rather than guaranteed to time out.
    let holder = std::sync::Arc::new(std::sync::Mutex::new(()));
    let mut tmtx = fresh_mtx();
    // SAFETY: valid slot for the duration of this block.
    unsafe {
        assert_eq!(c11::mtx_init(&mut tmtx as *mut MtxT, MTX_TIMED), THRD_SUCCESS);
    }
    let addr = &mut tmtx as *mut MtxT as usize;
    let gate = std::sync::Arc::clone(&holder);
    let guard = holder.lock().unwrap();
    let t = std::thread::spawn(move || {
        let p = addr as *mut MtxT;
        // SAFETY: the mutex outlives this thread; the main thread joins below.
        unsafe {
            assert_eq!(c11::mtx_lock(p), THRD_SUCCESS);
        }
        // Hold until the main thread has observed the timeout and released.
        let _held = gate.lock().unwrap();
        // SAFETY: same mutex, still valid.
        unsafe {
            assert_eq!(c11::mtx_unlock(p), THRD_SUCCESS);
        }
    });

    // Give the holder a moment to acquire.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let past = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    // SAFETY: valid mutex and timespec.
    let rc = unsafe { c11::mtx_timedlock(&mut tmtx as *mut MtxT, &past) };
    assert_eq!(
        rc, THRD_TIMEDOUT,
        "timedlock past its deadline must map ETIMEDOUT -> thrd_timedout (4)"
    );

    drop(guard);
    t.join().expect("holder thread");
    // SAFETY: no longer referenced by any thread.
    unsafe { c11::mtx_destroy(&mut tmtx as *mut MtxT) };
}
