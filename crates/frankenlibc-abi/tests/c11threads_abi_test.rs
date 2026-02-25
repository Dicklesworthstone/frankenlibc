#![cfg(target_os = "linux")]

//! Integration tests for C11 `<threads.h>` ABI entrypoints.

use std::ffi::c_int;
use std::ffi::c_void;
use std::sync::atomic::{AtomicI32, Ordering};

use frankenlibc_abi::c11threads_abi::{
    call_once, cnd_broadcast, cnd_destroy, cnd_init, cnd_signal, cnd_wait, mtx_destroy, mtx_init,
    mtx_lock, mtx_trylock, mtx_unlock, thrd_create, thrd_current, thrd_equal, thrd_join,
    thrd_sleep, thrd_yield, tss_create, tss_delete, tss_get, tss_set,
};
use frankenlibc_abi::dirent_abi::versionsort;
use frankenlibc_abi::time_abi::{timespec_get, timespec_getres};

const THRD_SUCCESS: c_int = 0;

// ===========================================================================
// thrd_* tests
// ===========================================================================

unsafe extern "C" fn simple_thread_func(arg: *mut c_void) -> c_int {
    let val = arg as usize as c_int;
    val + 10
}

#[test]
fn test_thrd_create_join() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = thrd_create(&mut thr, Some(simple_thread_func), 42 as *mut c_void);
        assert_eq!(rc, THRD_SUCCESS, "thrd_create failed");

        let mut res: c_int = 0;
        let rc = thrd_join(thr, &mut res);
        assert_eq!(rc, THRD_SUCCESS, "thrd_join failed");
        assert_eq!(res, 52, "thread should return arg+10");
    }
}

#[test]
fn test_thrd_create_null_returns_error() {
    unsafe {
        let rc = thrd_create(
            std::ptr::null_mut(),
            Some(simple_thread_func),
            std::ptr::null_mut(),
        );
        assert_ne!(rc, THRD_SUCCESS);
    }
}

#[test]
fn test_thrd_current_equal() {
    let tid = thrd_current();
    assert_ne!(tid, 0, "thrd_current should return non-zero");
    assert_ne!(thrd_equal(tid, tid), 0, "same thread should be equal");
}

#[test]
fn test_thrd_yield_does_not_crash() {
    thrd_yield();
}

#[test]
fn test_thrd_sleep_short() {
    unsafe {
        let dur = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        }; // 1ms
        let rc = thrd_sleep(&dur, std::ptr::null_mut());
        assert_eq!(rc, 0, "thrd_sleep should return 0 on success");
    }
}

// ===========================================================================
// mtx_* tests
// ===========================================================================

#[test]
fn test_mtx_init_lock_unlock_destroy() {
    unsafe {
        let mut mtx: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(mtx_init(&mut mtx, 0), THRD_SUCCESS);
        assert_eq!(mtx_lock(&mut mtx), THRD_SUCCESS);
        assert_eq!(mtx_unlock(&mut mtx), THRD_SUCCESS);
        mtx_destroy(&mut mtx);
    }
}

#[test]
fn test_mtx_trylock() {
    unsafe {
        let mut mtx: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(mtx_init(&mut mtx, 0), THRD_SUCCESS);
        assert_eq!(mtx_trylock(&mut mtx), THRD_SUCCESS);
        assert_eq!(mtx_unlock(&mut mtx), THRD_SUCCESS);
        mtx_destroy(&mut mtx);
    }
}

#[test]
fn test_mtx_recursive() {
    unsafe {
        let mut mtx: libc::pthread_mutex_t = std::mem::zeroed();
        // MTX_RECURSIVE = 2
        assert_eq!(mtx_init(&mut mtx, 2), THRD_SUCCESS);
        assert_eq!(mtx_lock(&mut mtx), THRD_SUCCESS);
        assert_eq!(mtx_lock(&mut mtx), THRD_SUCCESS); // second lock OK for recursive
        assert_eq!(mtx_unlock(&mut mtx), THRD_SUCCESS);
        assert_eq!(mtx_unlock(&mut mtx), THRD_SUCCESS);
        mtx_destroy(&mut mtx);
    }
}

// ===========================================================================
// cnd_* tests
// ===========================================================================

static COND_COUNTER: AtomicI32 = AtomicI32::new(0);

#[test]
fn test_cnd_init_signal_destroy() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(cnd_init(&mut cond), THRD_SUCCESS);
        // Signal with no waiters is a no-op but should succeed.
        assert_eq!(cnd_signal(&mut cond), THRD_SUCCESS);
        assert_eq!(cnd_broadcast(&mut cond), THRD_SUCCESS);
        cnd_destroy(&mut cond);
    }
}

#[test]
fn test_cnd_wait_signal() {
    // Shared state between main and spawned thread.
    struct Shared {
        mtx: libc::pthread_mutex_t,
        cond: libc::pthread_cond_t,
        ready: bool,
    }

    unsafe extern "C" fn waiter(arg: *mut c_void) -> c_int {
        unsafe {
            let shared = &mut *(arg as *mut Shared);
            mtx_lock(&mut shared.mtx);
            while !shared.ready {
                cnd_wait(&mut shared.cond, &mut shared.mtx);
            }
            COND_COUNTER.fetch_add(1, Ordering::SeqCst);
            mtx_unlock(&mut shared.mtx);
        }
        0
    }

    unsafe {
        let mut shared = Shared {
            mtx: std::mem::zeroed(),
            cond: std::mem::zeroed(),
            ready: false,
        };
        mtx_init(&mut shared.mtx, 0);
        cnd_init(&mut shared.cond);

        COND_COUNTER.store(0, Ordering::SeqCst);

        let mut thr: libc::pthread_t = 0;
        thrd_create(&mut thr, Some(waiter), &mut shared as *mut _ as *mut c_void);

        // Give the waiter thread time to start waiting.
        std::thread::sleep(std::time::Duration::from_millis(10));

        mtx_lock(&mut shared.mtx);
        shared.ready = true;
        cnd_signal(&mut shared.cond);
        mtx_unlock(&mut shared.mtx);

        thrd_join(thr, std::ptr::null_mut());
        assert_eq!(COND_COUNTER.load(Ordering::SeqCst), 1);

        cnd_destroy(&mut shared.cond);
        mtx_destroy(&mut shared.mtx);
    }
}

// ===========================================================================
// tss_* tests
// ===========================================================================

#[test]
fn test_tss_create_get_set_delete() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(tss_create(&mut key, None), THRD_SUCCESS);

        let val = 0xDEAD_BEEFusize as *mut c_void;
        assert_eq!(tss_set(key, val), THRD_SUCCESS);

        let got = tss_get(key);
        assert_eq!(got, val);

        tss_delete(key);
    }
}

// ===========================================================================
// call_once tests
// ===========================================================================

static ONCE_COUNTER: AtomicI32 = AtomicI32::new(0);

extern "C" fn once_init_func() {
    ONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn test_call_once_idempotent() {
    static mut FLAG: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    ONCE_COUNTER.store(0, Ordering::SeqCst);
    unsafe {
        call_once(&raw mut FLAG, Some(once_init_func));
        call_once(&raw mut FLAG, Some(once_init_func));
        call_once(&raw mut FLAG, Some(once_init_func));
    }
    assert_eq!(ONCE_COUNTER.load(Ordering::SeqCst), 1);
}

// ===========================================================================
// timespec_get / timespec_getres tests
// ===========================================================================

#[test]
fn test_timespec_get_utc() {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let rc = timespec_get(&mut ts, 1); // TIME_UTC = 1
        assert_eq!(rc, 1, "timespec_get should return base on success");
        assert!(
            ts.tv_sec > 0,
            "timespec_get should return a reasonable time"
        );
    }
}

#[test]
fn test_timespec_get_invalid_base() {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let rc = timespec_get(&mut ts, 99);
        assert_eq!(rc, 0, "timespec_get should return 0 for invalid base");
    }
}

#[test]
fn test_timespec_get_null_ts() {
    unsafe {
        let rc = timespec_get(std::ptr::null_mut(), 1);
        assert_eq!(rc, 0, "timespec_get should return 0 for null ts");
    }
}

#[test]
fn test_timespec_getres_utc() {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let rc = timespec_getres(&mut ts, 1);
        assert_eq!(rc, 1, "timespec_getres should return base on success");
        // Resolution should be positive (typically 1ns on modern Linux).
        assert!(
            ts.tv_sec > 0 || ts.tv_nsec > 0,
            "resolution should be positive"
        );
    }
}

#[test]
fn test_timespec_getres_null_ts() {
    unsafe {
        // With null ts, just verifies the base is supported.
        let rc = timespec_getres(std::ptr::null_mut(), 1);
        assert_eq!(rc, 1);
    }
}

// ===========================================================================
// versionsort tests
// ===========================================================================

fn make_dirent_with_name(name: &[u8]) -> libc::dirent {
    let mut d: libc::dirent = unsafe { std::mem::zeroed() };
    let len = name.len().min(d.d_name.len() - 1);
    for (i, &b) in name[..len].iter().enumerate() {
        d.d_name[i] = b as i8;
    }
    d.d_name[len] = 0;
    d
}

#[test]
fn test_versionsort_basic() {
    let a = make_dirent_with_name(b"file1");
    let b = make_dirent_with_name(b"file10");
    let c = make_dirent_with_name(b"file2");

    let ap: *const libc::dirent = &a;
    let bp: *const libc::dirent = &b;
    let cp: *const libc::dirent = &c;

    unsafe {
        // file1 < file2 in version order
        let r = versionsort(
            &ap as *const _ as *mut *const libc::dirent,
            &cp as *const _ as *mut *const libc::dirent,
        );
        assert!(r < 0, "file1 should sort before file2");

        // file2 < file10 in version order
        let r = versionsort(
            &cp as *const _ as *mut *const libc::dirent,
            &bp as *const _ as *mut *const libc::dirent,
        );
        assert!(r < 0, "file2 should sort before file10");
    }
}

#[test]
fn test_versionsort_equal() {
    let a = make_dirent_with_name(b"file1");
    let b = make_dirent_with_name(b"file1");

    let ap: *const libc::dirent = &a;
    let bp: *const libc::dirent = &b;

    unsafe {
        let r = versionsort(
            &ap as *const _ as *mut *const libc::dirent,
            &bp as *const _ as *mut *const libc::dirent,
        );
        assert_eq!(r, 0);
    }
}
