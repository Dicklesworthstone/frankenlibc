#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cancel oracle; real fl-managed threads

//! Gate for the `pthread` cancellation state machine (bd-xh08pf).
//!
//! ## The three tests this replaces could not have passed
//!
//! `pthread_abi.rs` is `#[cfg(not(test))] pub mod` in lib.rs, so its inline
//! `#[cfg(test)]` block is dead — the file says so itself, in the comment
//! introducing its `__test_*` hooks. Three of the six stranded tests covered
//! cancellation, and TWO OF THEM ASSERT PAST A CALL THAT TERMINATES THE THREAD:
//!
//! ```ignore
//! pthread_setcancelstate(PTHREAD_CANCEL_ENABLE_STATE, null_mut());
//! pthread_testcancel();
//! assert!(!current_thread_pending_cancel());   // <- unreachable
//! ```
//!
//! `pthread_testcancel` (pthread_abi.rs:4437) is
//! `if consume_pending_cancel_for_current_thread() { pthread_exit(PTHREAD_CANCELED) }`.
//! When a cancel is pending and cancellation is enabled it consumes the flag AND
//! EXITS. The assertion after it is never reached; had that test ever run it
//! would have terminated the libtest worker thread rather than failing. The
//! async variant has the same shape, because `pthread_cancel` on an async
//! self-cancel calls `pthread_testcancel` internally (:4335).
//!
//! So these are not relocated and not merely rewritten against public entry
//! points — the property they were reaching for is restated as the one POSIX
//! actually specifies and that is externally observable: **a cancelled thread
//! terminates with `PTHREAD_CANCELED` as its join value.** Each scenario runs on
//! its own fl-created thread and is observed through `pthread_join`, so a thread
//! exiting is the expected outcome rather than a harness casualty.
//!
//! ## Which arms are differential, and why the rest cannot be
//!
//! Only the input-validation arm compares against live glibc. The consumption
//! arms deliberately do NOT: glibc's `pthread_testcancel` with a pending cancel
//! terminates the calling thread too, so a "differential" version would have to
//! kill a thread in each libc and compare the corpses. The validation arm is
//! safe because both implementations reject the invalid value *before* any
//! cancellation state is touched — in fl's case at `pthread_abi.rs:4343`, ahead
//! of the host-delegation branch below it.
//!
//! ## Why the threads are fl-created
//!
//! `pthread_setcancelstate`, `pthread_testcancel` and `pthread_cancel` all
//! delegate to host glibc when the backend resolves to `THREAD_BACKEND_HOST`.
//! Testing fl's own state machine therefore requires an fl-MANAGED thread;
//! otherwise this file would be measuring glibc against glibc, the hollow-oracle
//! shape bd-v0388t exists for. `ThreadingForceNativeGuard` forces the native
//! path for the `pthread_create` call, and the resulting thread is managed, so
//! its own cancel calls stay inside fl without needing any override in the child.

use std::ffi::{c_int, c_void};
use std::ptr;

use frankenlibc_abi::pthread_abi::*;

// POSIX cancel constants (not always exported by the libc crate).
const PTHREAD_CANCEL_ENABLE: c_int = 0;
const PTHREAD_CANCEL_DISABLE: c_int = 1;
#[allow(dead_code)]
const PTHREAD_CANCEL_DEFERRED: c_int = 0;
const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 1;

/// POSIX `PTHREAD_CANCELED` is `((void *) -1)`.
fn canceled() -> *mut c_void {
    !0usize as *mut c_void
}

/// A value no cancellation path produces, returned by a thread that reached its
/// own end. Distinguishes "ran to completion" from "was cancelled".
const RAN_TO_COMPLETION: usize = 0x5A5A_1234;

struct ThreadingForceNativeGuard {
    previous: bool,
}

impl Drop for ThreadingForceNativeGuard {
    fn drop(&mut self) {
        pthread_threading_restore_for_tests(self.previous);
    }
}

/// Run `start` on an fl-created thread and return its join value.
///
/// The force-native override is TLS-scoped and held only across `pthread_create`
/// — that is what routes creation through fl's own path, making the thread
/// fl-managed. Its cancel calls then stay inside fl by managed-handle detection,
/// so the child needs no override of its own (and could not reliably drop one,
/// since these threads exit via `pthread_exit`).
fn join_fl_thread(start: unsafe extern "C" fn(*mut c_void) -> *mut c_void) -> *mut c_void {
    let mut thread: libc::pthread_t = 0;
    // SAFETY: `thread` is a valid out-parameter; default attributes; the start
    // routine has the required C signature and ignores its argument.
    unsafe {
        {
            let _guard = ThreadingForceNativeGuard {
                previous: pthread_threading_swap_force_native_for_tests(),
            };
            assert_eq!(
                pthread_create(&mut thread, ptr::null(), Some(start), ptr::null_mut()),
                0,
                "fl pthread_create should succeed under the native override"
            );
        }
        let mut retval: *mut c_void = ptr::null_mut();
        assert_eq!(pthread_join(thread, &mut retval), 0, "pthread_join");
        retval
    }
}

/// Cancellation DISABLED: `pthread_testcancel` must not act, so the thread runs
/// to its own end and joins with its own value.
unsafe extern "C" fn disabled_then_testcancel(_arg: *mut c_void) -> *mut c_void {
    // SAFETY: all calls are fl's own pthread entry points on this thread.
    unsafe {
        assert_eq!(
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, ptr::null_mut()),
            0
        );
        let me = pthread_self();
        assert_eq!(pthread_cancel(me), 0, "cancel of a live self should succeed");
        pthread_testcancel();
    }
    RAN_TO_COMPLETION as *mut c_void
}

/// Cancellation ENABLED (the documented default): `pthread_testcancel` consumes
/// the pending request and exits with `PTHREAD_CANCELED`. The trailing return is
/// unreachable, and that is the assertion — if it were reached, the join value
/// would be `RAN_TO_COMPLETION`.
unsafe extern "C" fn enabled_then_testcancel(_arg: *mut c_void) -> *mut c_void {
    // SAFETY: as above.
    unsafe {
        let me = pthread_self();
        assert_eq!(pthread_cancel(me), 0);
        pthread_testcancel();
    }
    RAN_TO_COMPLETION as *mut c_void
}

/// ASYNCHRONOUS type: `pthread_cancel` on self acts immediately, without any
/// explicit `pthread_testcancel`.
unsafe extern "C" fn async_self_cancel(_arg: *mut c_void) -> *mut c_void {
    // SAFETY: as above.
    unsafe {
        assert_eq!(
            pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, ptr::null_mut()),
            0
        );
        let me = pthread_self();
        assert_eq!(pthread_cancel(me), 0);
    }
    RAN_TO_COMPLETION as *mut c_void
}

#[test]
fn testcancel_is_a_no_op_while_cancellation_is_disabled() {
    let retval = join_fl_thread(disabled_then_testcancel);
    assert_eq!(
        retval as usize, RAN_TO_COMPLETION,
        "a pending cancel must NOT be acted on while cancellation is disabled; \
         the thread should have run to its own end, got {retval:?}"
    );
}

#[test]
fn testcancel_consumes_a_pending_cancel_and_exits_with_pthread_canceled() {
    let retval = join_fl_thread(enabled_then_testcancel);
    let ran_past = retval as usize == RAN_TO_COMPLETION;
    assert_eq!(
        retval,
        canceled(),
        "with cancellation enabled, testcancel must consume the pending request \
         and terminate the thread with PTHREAD_CANCELED; got {retval:?}{}",
        if ran_past { " — the thread ran PAST testcancel" } else { "" }
    );
}

#[test]
fn async_self_cancel_terminates_without_an_explicit_testcancel() {
    let retval = join_fl_thread(async_self_cancel);
    assert_eq!(
        retval,
        canceled(),
        "an asynchronous self-cancel must act immediately; got {retval:?}"
    );
}

/// The input-validation contract, the one arm that CAN be compared against live
/// glibc: both must reject an out-of-range state or type with `EINVAL`, and both
/// must do so without disturbing the caller's cancellation state.
///
/// fl performs this check at `pthread_abi.rs:4343`, ahead of the host-delegation
/// branch, so it is fl's own code even when the backend is the host — which is
/// what makes this arm meaningful without forcing native threading.
///
/// The oracle is resolved by `dlsym` rather than declared at link time: fl
/// exports these symbols itself, and a link-time reference in this binary is not
/// reliably glibc (bd-v0388t).
#[test]
fn invalid_cancelstate_and_canceltype_are_rejected_like_glibc() {
    type SetCancel = unsafe extern "C" fn(c_int, *mut c_int) -> c_int;

    // SAFETY: the name is a NUL-terminated constant; RTLD_LOCAL keeps the handle
    // out of the global namespace.
    let handle =
        unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6 — the oracle is unavailable");

    let resolve = |name: &std::ffi::CStr, fl_addr: usize| -> SetCancel {
        // SAFETY: handle came from dlopen; the name is NUL-terminated.
        let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!raw.is_null(), "dlsym {name:?}");
        assert_ne!(
            raw as usize, fl_addr,
            "the resolved oracle IS fl's {name:?} — this arm would compare fl to itself"
        );
        // SAFETY: the symbol has exactly this signature.
        unsafe { std::mem::transmute::<*mut c_void, SetCancel>(raw) }
    };

    let host_state = resolve(
        c"pthread_setcancelstate",
        pthread_setcancelstate as *const () as usize,
    );
    let host_type = resolve(
        c"pthread_setcanceltype",
        pthread_setcanceltype as *const () as usize,
    );

    // Values outside {ENABLE, DISABLE} and {DEFERRED, ASYNCHRONOUS}. `-1` and a
    // large positive both matter: a check written as `> MAX` would miss the
    // negative one.
    for bad in [99, -1, i32::MAX, i32::MIN] {
        // SAFETY: a NULL old-value pointer is permitted; neither call reaches
        // any cancellation state, because both reject the argument first.
        let fl_state = unsafe { pthread_setcancelstate(bad, ptr::null_mut()) };
        let gl_state = unsafe { host_state(bad, ptr::null_mut()) };
        assert_eq!(
            fl_state, gl_state,
            "pthread_setcancelstate({bad}): fl={fl_state} glibc={gl_state}"
        );
        assert_eq!(
            gl_state,
            libc::EINVAL,
            "live glibc should reject state {bad} with EINVAL"
        );

        // SAFETY: as above.
        let fl_type = unsafe { pthread_setcanceltype(bad, ptr::null_mut()) };
        let gl_type = unsafe { host_type(bad, ptr::null_mut()) };
        assert_eq!(
            fl_type, gl_type,
            "pthread_setcanceltype({bad}): fl={fl_type} glibc={gl_type}"
        );
        assert_eq!(
            gl_type,
            libc::EINVAL,
            "live glibc should reject type {bad} with EINVAL"
        );
    }

    // A rejected call must leave the state alone: setting ENABLE afterwards must
    // still report ENABLE as the previous value, not the rejected argument.
    // SAFETY: `old` is a valid out-parameter.
    let mut old: c_int = -1;
    unsafe {
        assert_eq!(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &mut old), 0);
    }
    assert!(
        old == PTHREAD_CANCEL_ENABLE || old == PTHREAD_CANCEL_DISABLE,
        "a rejected setcancelstate must not have stored its argument; got old={old}"
    );
}
