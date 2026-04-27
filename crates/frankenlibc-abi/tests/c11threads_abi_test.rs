#![cfg(target_os = "linux")]

//! Integration tests for C11 `<threads.h>` ABI entrypoints.

use std::ffi::c_int;
use std::ffi::c_void;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use frankenlibc_abi::c11threads_abi::{
    call_once, cnd_broadcast, cnd_destroy, cnd_init, cnd_signal, cnd_timedwait, cnd_wait,
    mtx_destroy, mtx_init, mtx_lock, mtx_timedlock, mtx_trylock, mtx_unlock, thrd_create,
    thrd_current, thrd_detach, thrd_equal, thrd_join, thrd_sleep, thrd_yield, tss_create,
    tss_delete, tss_get, tss_set,
};
use frankenlibc_abi::dirent_abi::versionsort;
use frankenlibc_abi::time_abi::{timespec_get, timespec_getres};

const THRD_SUCCESS: c_int = 0;

static C11_THREAD_SELF_SNAPSHOT: AtomicUsize = AtomicUsize::new(0);

fn tracked_zeroed_bytes(len: usize) -> *mut c_void {
    assert!(len > 0);
    unsafe {
        let raw = frankenlibc_abi::malloc_abi::malloc(len);
        assert!(!raw.is_null());
        std::ptr::write_bytes(raw.cast::<u8>(), 0, len);
        raw
    }
}

fn free_tracked(raw: *mut c_void) {
    unsafe { frankenlibc_abi::malloc_abi::free(raw) };
}

fn assert_known_short(raw: *const c_void, required: usize) {
    let remaining =
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(raw).unwrap_or(usize::MAX);
    assert!(
        remaining < required,
        "test allocation should be tracked shorter than {required}; got {remaining}"
    );
}

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

unsafe extern "C" fn c11_lifecycle_contract_probe(arg: *mut c_void) -> c_int {
    let parent = unsafe { *(arg as *const libc::pthread_t) };
    let self_id = thrd_current();
    C11_THREAD_SELF_SNAPSHOT.store(self_id as usize, Ordering::SeqCst);
    if self_id == 0 {
        return -10;
    }
    if thrd_equal(parent, self_id) != 0 {
        return -11;
    }
    73
}

#[test]
fn test_thrd_create_join_default_backend_contract() {
    unsafe {
        C11_THREAD_SELF_SNAPSHOT.store(0, Ordering::SeqCst);
        let parent = thrd_current();
        assert_ne!(parent, 0, "parent thrd_current should be non-zero");

        let mut thr: libc::pthread_t = 0;
        let rc = thrd_create(
            &mut thr,
            Some(c11_lifecycle_contract_probe),
            (&parent as *const libc::pthread_t).cast_mut().cast(),
        );
        assert_eq!(rc, THRD_SUCCESS, "thrd_create failed");
        assert_ne!(thr, 0, "thrd_create should publish a joinable handle");

        let mut res: c_int = 0;
        let rc = thrd_join(thr, &mut res);
        assert_eq!(rc, THRD_SUCCESS, "thrd_join failed");
        assert_eq!(res, 73, "join must propagate the C11 start return");

        let child_self = C11_THREAD_SELF_SNAPSHOT.load(Ordering::SeqCst) as libc::pthread_t;
        assert_ne!(child_self, 0, "child thrd_current should be recorded");
        assert_eq!(
            thrd_equal(parent, child_self),
            0,
            "parent and child thread IDs should not compare equal"
        );
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
// thrd_detach test
// ===========================================================================

#[test]
fn test_thrd_detach() {
    unsafe extern "C" fn detach_func(_arg: *mut c_void) -> c_int {
        0
    }
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = thrd_create(&mut thr, Some(detach_func), std::ptr::null_mut());
        assert_eq!(rc, THRD_SUCCESS, "thrd_create failed");
        let rc = thrd_detach(thr);
        assert_eq!(rc, THRD_SUCCESS, "thrd_detach should succeed");
        // Give detached thread time to finish
        std::thread::sleep(std::time::Duration::from_millis(10));
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
// mtx_timedlock test
// ===========================================================================

#[test]
fn test_mtx_timedlock_succeeds_when_available() {
    unsafe {
        let mut mtx: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(mtx_init(&mut mtx, 0), THRD_SUCCESS);

        // Get a future timestamp
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_sec += 1; // 1 second from now

        let rc = mtx_timedlock(&mut mtx, &ts);
        assert_eq!(
            rc, THRD_SUCCESS,
            "mtx_timedlock should succeed on available mutex"
        );
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
// cnd_timedwait test
// ===========================================================================

#[test]
fn test_cnd_timedwait_timeout() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        let mut mtx: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(cnd_init(&mut cond), THRD_SUCCESS);
        assert_eq!(mtx_init(&mut mtx, 0), THRD_SUCCESS);

        // Set timeout slightly in the past to trigger immediate timeout
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        // Don't subtract to avoid underflow; just use current time (will timeout immediately)

        assert_eq!(mtx_lock(&mut mtx), THRD_SUCCESS);
        let rc = cnd_timedwait(&mut cond, &mut mtx, &ts);
        // Should return thrd_timedout (2) or thrd_error
        assert_ne!(
            rc, THRD_SUCCESS,
            "cnd_timedwait with past deadline should not succeed"
        );
        assert_eq!(mtx_unlock(&mut mtx), THRD_SUCCESS);

        cnd_destroy(&mut cond);
        mtx_destroy(&mut mtx);
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

#[test]
fn test_tss_default_null() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(tss_create(&mut key, None), THRD_SUCCESS);
        // Before setting, should be null
        let val = tss_get(key);
        assert!(val.is_null(), "tss_get before set should return null");
        tss_delete(key);
    }
}

#[test]
fn test_tss_create_null_key_returns_error() {
    unsafe {
        let rc = tss_create(std::ptr::null_mut(), None);
        assert_ne!(rc, THRD_SUCCESS, "tss_create with null key should fail");
    }
}

// ===========================================================================
// Multi-threaded mtx contention
// ===========================================================================

static MTX_COUNTER: AtomicI32 = AtomicI32::new(0);

#[test]
fn test_mtx_multi_threaded_contention() {
    unsafe extern "C" fn increment_func(arg: *mut c_void) -> c_int {
        unsafe {
            let mtx = arg as *mut libc::pthread_mutex_t;
            for _ in 0..100 {
                mtx_lock(mtx);
                MTX_COUNTER.fetch_add(1, Ordering::SeqCst);
                mtx_unlock(mtx);
            }
        }
        0
    }

    unsafe {
        let mut mtx: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(mtx_init(&mut mtx, 0), THRD_SUCCESS);
        MTX_COUNTER.store(0, Ordering::SeqCst);

        let mut threads = [0 as libc::pthread_t; 4];
        for thr in threads.iter_mut() {
            thrd_create(thr, Some(increment_func), &mut mtx as *mut _ as *mut c_void);
        }
        for &thr in threads.iter() {
            thrd_join(thr, std::ptr::null_mut());
        }

        assert_eq!(MTX_COUNTER.load(Ordering::SeqCst), 400);
        mtx_destroy(&mut mtx);
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
// thrd_sleep — edge cases
// ===========================================================================

#[test]
fn test_thrd_sleep_zero_duration() {
    unsafe {
        let dur = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = thrd_sleep(&dur, std::ptr::null_mut());
        assert_eq!(rc, 0, "thrd_sleep(0) should return 0");
    }
}

#[test]
fn test_thrd_sleep_with_remaining() {
    unsafe {
        let dur = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        }; // 1ms
        let mut rem: libc::timespec = std::mem::zeroed();
        let rc = thrd_sleep(&dur, &mut rem);
        assert_eq!(rc, 0);
    }
}

#[test]
fn test_thrd_sleep_rejects_tracked_short_duration() {
    let required = std::mem::size_of::<libc::timespec>();
    let raw = tracked_zeroed_bytes(required - 1);
    assert_known_short(raw, required);

    let rc = unsafe { thrd_sleep(raw.cast::<libc::timespec>(), std::ptr::null_mut()) };

    assert_eq!(rc, -2);
    free_tracked(raw);
}

// ===========================================================================
// tss_* — additional scenarios
// ===========================================================================

#[test]
fn test_tss_overwrite_value() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(tss_create(&mut key, None), THRD_SUCCESS);

        let val1 = 0x1111usize as *mut c_void;
        let val2 = 0x2222usize as *mut c_void;
        assert_eq!(tss_set(key, val1), THRD_SUCCESS);
        assert_eq!(tss_get(key), val1);

        assert_eq!(tss_set(key, val2), THRD_SUCCESS);
        assert_eq!(tss_get(key), val2);

        tss_delete(key);
    }
}

#[test]
fn test_tss_multiple_keys_independent() {
    unsafe {
        let mut key1: libc::pthread_key_t = 0;
        let mut key2: libc::pthread_key_t = 0;
        assert_eq!(tss_create(&mut key1, None), THRD_SUCCESS);
        assert_eq!(tss_create(&mut key2, None), THRD_SUCCESS);

        let v1 = 0xAAAAusize as *mut c_void;
        let v2 = 0xBBBBusize as *mut c_void;
        assert_eq!(tss_set(key1, v1), THRD_SUCCESS);
        assert_eq!(tss_set(key2, v2), THRD_SUCCESS);

        assert_eq!(tss_get(key1), v1);
        assert_eq!(tss_get(key2), v2);

        tss_delete(key1);
        tss_delete(key2);
    }
}

#[test]
fn test_tss_set_null_value() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(tss_create(&mut key, None), THRD_SUCCESS);

        let val = 0xDEADusize as *mut c_void;
        assert_eq!(tss_set(key, val), THRD_SUCCESS);
        assert_eq!(tss_get(key), val);

        // Set back to null
        assert_eq!(tss_set(key, std::ptr::null_mut()), THRD_SUCCESS);
        assert!(tss_get(key).is_null());

        tss_delete(key);
    }
}

// ===========================================================================
// thrd_equal — different threads
// ===========================================================================

#[test]
fn test_thrd_equal_different_threads() {
    unsafe extern "C" fn get_tid(_arg: *mut c_void) -> c_int {
        // Just return; main thread captures our pthread_t
        0
    }
    unsafe {
        let main_tid = thrd_current();
        let mut child: libc::pthread_t = 0;
        let rc = thrd_create(&mut child, Some(get_tid), std::ptr::null_mut());
        assert_eq!(rc, THRD_SUCCESS);
        thrd_join(child, std::ptr::null_mut());

        // main_tid and child should not be equal (child has exited, but the IDs differ)
        assert_eq!(
            thrd_equal(main_tid, child),
            0,
            "main thread and child thread should not be equal"
        );
    }
}

// ===========================================================================
// thrd_create — various return codes
// ===========================================================================

unsafe extern "C" fn returns_zero(_arg: *mut c_void) -> c_int {
    0
}

unsafe extern "C" fn returns_negative(_arg: *mut c_void) -> c_int {
    -1
}

unsafe extern "C" fn returns_large(_arg: *mut c_void) -> c_int {
    255
}

#[test]
fn test_thrd_join_propagates_zero() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        thrd_create(&mut thr, Some(returns_zero), std::ptr::null_mut());
        let mut res: c_int = -999;
        thrd_join(thr, &mut res);
        assert_eq!(res, 0);
    }
}

#[test]
fn test_thrd_join_propagates_negative() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        thrd_create(&mut thr, Some(returns_negative), std::ptr::null_mut());
        let mut res: c_int = 0;
        thrd_join(thr, &mut res);
        assert_eq!(res, -1);
    }
}

#[test]
fn test_thrd_join_propagates_large() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        thrd_create(&mut thr, Some(returns_large), std::ptr::null_mut());
        let mut res: c_int = 0;
        thrd_join(thr, &mut res);
        assert_eq!(res, 255);
    }
}

// ===========================================================================
// call_once — multi-threaded
// ===========================================================================

static MULTI_ONCE_COUNTER: AtomicI32 = AtomicI32::new(0);

extern "C" fn multi_once_func() {
    MULTI_ONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn test_call_once_multi_threaded() {
    static mut MULTI_FLAG: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    MULTI_ONCE_COUNTER.store(0, Ordering::SeqCst);

    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| unsafe {
                call_once(&raw mut MULTI_FLAG, Some(multi_once_func));
            })
        })
        .collect();

    for handle in handles {
        assert!(
            handle.join().is_ok(),
            "call_once worker thread should not panic"
        );
    }
    assert_eq!(
        MULTI_ONCE_COUNTER.load(Ordering::SeqCst),
        1,
        "call_once should execute exactly once across threads"
    );
}

// ===========================================================================
// cnd_broadcast — wake multiple waiters
// ===========================================================================

static BROADCAST_COUNTER: AtomicI32 = AtomicI32::new(0);

#[test]
fn test_cnd_broadcast_wakes_all() {
    struct Shared {
        mtx: libc::pthread_mutex_t,
        cond: libc::pthread_cond_t,
        ready: bool,
    }

    unsafe extern "C" fn broadcast_waiter(arg: *mut c_void) -> c_int {
        unsafe {
            let shared = &mut *(arg as *mut Shared);
            mtx_lock(&mut shared.mtx);
            while !shared.ready {
                cnd_wait(&mut shared.cond, &mut shared.mtx);
            }
            BROADCAST_COUNTER.fetch_add(1, Ordering::SeqCst);
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
        BROADCAST_COUNTER.store(0, Ordering::SeqCst);

        let mut threads = [0 as libc::pthread_t; 3];
        for thr in threads.iter_mut() {
            thrd_create(
                thr,
                Some(broadcast_waiter),
                &mut shared as *mut _ as *mut c_void,
            );
        }

        std::thread::sleep(std::time::Duration::from_millis(20));

        mtx_lock(&mut shared.mtx);
        shared.ready = true;
        cnd_broadcast(&mut shared.cond);
        mtx_unlock(&mut shared.mtx);

        for &thr in threads.iter() {
            thrd_join(thr, std::ptr::null_mut());
        }
        assert_eq!(
            BROADCAST_COUNTER.load(Ordering::SeqCst),
            3,
            "broadcast should wake all 3 waiters"
        );

        cnd_destroy(&mut shared.cond);
        mtx_destroy(&mut shared.mtx);
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
