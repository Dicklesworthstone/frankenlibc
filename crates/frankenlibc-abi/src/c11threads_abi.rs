//! C11 `<threads.h>` ABI entrypoints.
//!
//! Thin wrappers over the existing pthread_abi implementations.
//! C11 threads map 1:1 onto POSIX threads with different return value conventions.

use std::ffi::c_int;
use std::ffi::c_void;

// ---------------------------------------------------------------------------
// C11 thread return codes
// ---------------------------------------------------------------------------

const THRD_SUCCESS: c_int = 0;
const THRD_ERROR: c_int = 2;
const THRD_NOMEM: c_int = 3;
const THRD_TIMEDOUT: c_int = 4;
const THRD_BUSY: c_int = 5;

// ---------------------------------------------------------------------------
// C11 mutex type flags
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const MTX_PLAIN: c_int = 0;
#[allow(dead_code)]
const MTX_TIMED: c_int = 1;
const MTX_RECURSIVE: c_int = 2;

// ---------------------------------------------------------------------------
// C11 opaque types — same layout as pthread equivalents on glibc/Linux
// ---------------------------------------------------------------------------

type ThrdT = libc::pthread_t;
type MtxT = libc::pthread_mutex_t;
type CndT = libc::pthread_cond_t;
type TssT = libc::pthread_key_t;
type OnceFlag = libc::pthread_once_t;

// C11 thread start function: int (*)(void *), unlike pthread's void* (*)(void *)
type ThrdStartT = unsafe extern "C" fn(*mut c_void) -> c_int;
type TssDtorT = unsafe extern "C" fn(*mut c_void);

// ---------------------------------------------------------------------------
// Helper: convert pthread errno to C11 thread return code
// ---------------------------------------------------------------------------

fn pthread_rc_to_thrd(rc: c_int) -> c_int {
    match rc {
        0 => THRD_SUCCESS,
        libc::ETIMEDOUT => THRD_TIMEDOUT,
        libc::EBUSY => THRD_BUSY,
        libc::ENOMEM => THRD_NOMEM,
        _ => THRD_ERROR,
    }
}

// ===========================================================================
// Thread management (thrd_*)
// ===========================================================================

// thrd_create — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_create` — create a new thread.
///
/// The C11 start function returns `int` while pthread uses `void*`.
/// We wrap the start function to bridge the calling convention.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_create(
    thr: *mut ThrdT,
    func: Option<ThrdStartT>,
    arg: *mut c_void,
) -> c_int {
    if thr.is_null() || func.is_none() {
        return THRD_ERROR;
    }

    // We need to wrap the C11 start function (returns int) into a pthread
    // start function (returns void*). We heap-allocate a trampoline context.
    struct TrampolineCtx {
        func: ThrdStartT,
        arg: *mut c_void,
    }
    // SAFETY: TrampolineCtx is a plain struct with no drop glue concerns.
    unsafe impl Send for TrampolineCtx {}

    extern "C" fn trampoline(ctx_ptr: *mut c_void) -> *mut c_void {
        let ctx = unsafe { Box::from_raw(ctx_ptr as *mut TrampolineCtx) };
        let rc = unsafe { (ctx.func)(ctx.arg) };
        rc as usize as *mut c_void
    }

    let ctx = Box::new(TrampolineCtx {
        func: func.unwrap(),
        arg,
    });
    let ctx_ptr = Box::into_raw(ctx) as *mut c_void;

    let rc = unsafe { libc::pthread_create(thr, std::ptr::null(), trampoline, ctx_ptr) };
    if rc != 0 {
        // Clean up on failure — reclaim the Box.
        drop(unsafe { Box::from_raw(ctx_ptr as *mut TrampolineCtx) });
    }
    pthread_rc_to_thrd(rc)
}

// thrd_join — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_join` — wait for thread termination.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_join(thr: ThrdT, res: *mut c_int) -> c_int {
    let mut retval: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { crate::pthread_abi::pthread_join(thr, &mut retval) };
    if rc == 0 && !res.is_null() {
        unsafe { *res = retval as usize as c_int };
    }
    pthread_rc_to_thrd(rc)
}

// thrd_detach — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_detach` — detach a thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_detach(thr: ThrdT) -> c_int {
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_detach(thr) })
}

// thrd_exit — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_exit` — terminate the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_exit(res: c_int) -> ! {
    unsafe { crate::pthread_abi::pthread_exit(res as usize as *mut c_void) }
}

// thrd_current — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_current` — return the calling thread's ID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn thrd_current() -> ThrdT {
    unsafe { crate::pthread_abi::pthread_self() }
}

// thrd_equal — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_equal` — compare two thread IDs.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn thrd_equal(lhs: ThrdT, rhs: ThrdT) -> c_int {
    unsafe { crate::pthread_abi::pthread_equal(lhs, rhs) }
}

// thrd_sleep — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_sleep` — sleep for a duration.
///
/// Returns 0 on success, -1 if interrupted by a signal, or a negative value on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_sleep(
    duration: *const libc::timespec,
    remaining: *mut libc::timespec,
) -> c_int {
    if duration.is_null() {
        return -2;
    }
    let rc = unsafe { libc::syscall(libc::SYS_nanosleep as i64, duration, remaining) as c_int };
    if rc == 0 {
        0
    } else {
        let e = unsafe { *libc::__errno_location() };
        if e == libc::EINTR { -1 } else { -2 }
    }
}

// thrd_yield — Implemented
// ---------------------------------------------------------------------------

/// C11 `thrd_yield` — yield the processor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn thrd_yield() {
    unsafe { libc::syscall(libc::SYS_sched_yield as i64) as c_int };
}

// ===========================================================================
// Mutex (mtx_*)
// ===========================================================================

// mtx_init — Implemented
// ---------------------------------------------------------------------------

/// C11 `mtx_init` — create a mutex.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_init(mtx: *mut MtxT, typ: c_int) -> c_int {
    if mtx.is_null() {
        return THRD_ERROR;
    }

    let mut attr: libc::pthread_mutexattr_t = unsafe { std::mem::zeroed() };
    unsafe { crate::pthread_abi::pthread_mutexattr_init(&mut attr) };

    // C11 MTX_RECURSIVE flag means recursive mutex.
    if typ & MTX_RECURSIVE != 0 {
        unsafe { crate::pthread_abi::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE) };
    }

    let rc = unsafe { crate::pthread_abi::pthread_mutex_init(mtx, &attr) };
    unsafe { crate::pthread_abi::pthread_mutexattr_destroy(&mut attr) };
    pthread_rc_to_thrd(rc)
}

// mtx_lock — Implemented
// ---------------------------------------------------------------------------

/// C11 `mtx_lock` — lock a mutex.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_lock(mtx: *mut MtxT) -> c_int {
    if mtx.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_mutex_lock(mtx) })
}

// mtx_trylock — Implemented
// ---------------------------------------------------------------------------

/// C11 `mtx_trylock` — try to lock a mutex without blocking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_trylock(mtx: *mut MtxT) -> c_int {
    if mtx.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_mutex_trylock(mtx) })
}

// mtx_timedlock — Implemented
// ---------------------------------------------------------------------------

/// C11 `mtx_timedlock` — lock a mutex with timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_timedlock(mtx: *mut MtxT, ts: *const libc::timespec) -> c_int {
    if mtx.is_null() || ts.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_mutex_timedlock(mtx, ts) })
}

// mtx_unlock — Implemented
// ---------------------------------------------------------------------------

/// C11 `mtx_unlock` — unlock a mutex.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_unlock(mtx: *mut MtxT) -> c_int {
    if mtx.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_mutex_unlock(mtx) })
}

// mtx_destroy — Implemented
// ---------------------------------------------------------------------------

/// C11 `mtx_destroy` — destroy a mutex.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_destroy(mtx: *mut MtxT) {
    if !mtx.is_null() {
        unsafe { crate::pthread_abi::pthread_mutex_destroy(mtx) };
    }
}

// ===========================================================================
// Condition variables (cnd_*)
// ===========================================================================

// cnd_init — Implemented
// ---------------------------------------------------------------------------

/// C11 `cnd_init` — create a condition variable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_init(cond: *mut CndT) -> c_int {
    if cond.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_cond_init(cond, std::ptr::null()) })
}

// cnd_signal — Implemented
// ---------------------------------------------------------------------------

/// C11 `cnd_signal` — wake one thread waiting on a condition variable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_signal(cond: *mut CndT) -> c_int {
    if cond.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_cond_signal(cond) })
}

// cnd_broadcast — Implemented
// ---------------------------------------------------------------------------

/// C11 `cnd_broadcast` — wake all threads waiting on a condition variable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_broadcast(cond: *mut CndT) -> c_int {
    if cond.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_cond_broadcast(cond) })
}

// cnd_wait — Implemented
// ---------------------------------------------------------------------------

/// C11 `cnd_wait` — wait on a condition variable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_wait(cond: *mut CndT, mtx: *mut MtxT) -> c_int {
    if cond.is_null() || mtx.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_cond_wait(cond, mtx) })
}

// cnd_timedwait — Implemented
// ---------------------------------------------------------------------------

/// C11 `cnd_timedwait` — wait on a condition variable with timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_timedwait(
    cond: *mut CndT,
    mtx: *mut MtxT,
    ts: *const libc::timespec,
) -> c_int {
    if cond.is_null() || mtx.is_null() || ts.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_cond_timedwait(cond, mtx, ts) })
}

// cnd_destroy — Implemented
// ---------------------------------------------------------------------------

/// C11 `cnd_destroy` — destroy a condition variable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_destroy(cond: *mut CndT) {
    if !cond.is_null() {
        unsafe { crate::pthread_abi::pthread_cond_destroy(cond) };
    }
}

// ===========================================================================
// Thread-specific storage (tss_*)
// ===========================================================================

// tss_create — Implemented
// ---------------------------------------------------------------------------

/// C11 `tss_create` — create thread-specific storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tss_create(key: *mut TssT, dtor: Option<TssDtorT>) -> c_int {
    if key.is_null() {
        return THRD_ERROR;
    }
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_key_create(key, dtor) })
}

// tss_get — Implemented
// ---------------------------------------------------------------------------

/// C11 `tss_get` — get thread-specific storage value.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn tss_get(key: TssT) -> *mut c_void {
    unsafe { crate::pthread_abi::pthread_getspecific(key) }
}

// tss_set — Implemented
// ---------------------------------------------------------------------------

/// C11 `tss_set` — set thread-specific storage value.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tss_set(key: TssT, val: *mut c_void) -> c_int {
    pthread_rc_to_thrd(unsafe { crate::pthread_abi::pthread_setspecific(key, val) })
}

// tss_delete — Implemented
// ---------------------------------------------------------------------------

/// C11 `tss_delete` — delete thread-specific storage key.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tss_delete(key: TssT) {
    unsafe { crate::pthread_abi::pthread_key_delete(key) };
}

// ===========================================================================
// call_once
// ===========================================================================

// call_once — Implemented
// ---------------------------------------------------------------------------

/// C11 `call_once` — execute a callable exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn call_once(flag: *mut OnceFlag, func: Option<extern "C" fn()>) {
    if flag.is_null() || func.is_none() {
        return;
    }
    // C11 call_once returns void (unlike pthread_once which returns int).
    unsafe { libc::pthread_once(flag, func.unwrap()) };
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pthread_rc_mapping() {
        assert_eq!(pthread_rc_to_thrd(0), THRD_SUCCESS);
        assert_eq!(pthread_rc_to_thrd(libc::ETIMEDOUT), THRD_TIMEDOUT);
        assert_eq!(pthread_rc_to_thrd(libc::EBUSY), THRD_BUSY);
        assert_eq!(pthread_rc_to_thrd(libc::ENOMEM), THRD_NOMEM);
        assert_eq!(pthread_rc_to_thrd(libc::EINVAL), THRD_ERROR);
    }

    #[test]
    fn constants_match_c11_spec() {
        // C11 defines thrd_success = 0
        assert_eq!(THRD_SUCCESS, 0);
        // MTX_PLAIN is 0, MTX_TIMED is 1, MTX_RECURSIVE is 2
        assert_eq!(MTX_PLAIN, 0);
        assert_eq!(MTX_TIMED, 1);
        assert_eq!(MTX_RECURSIVE, 2);
    }

    #[test]
    fn thrd_current_returns_nonzero() {
        let tid = thrd_current();
        // On Linux, pthread_self() always returns a non-zero value.
        assert_ne!(tid, 0);
    }

    #[test]
    fn thrd_equal_same_thread() {
        let tid = thrd_current();
        assert_ne!(thrd_equal(tid, tid), 0);
    }
}
