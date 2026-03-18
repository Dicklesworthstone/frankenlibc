#![cfg(target_os = "linux")]

//! Integration tests for pthread_once.

use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use frankenlibc_abi::pthread_abi::{pthread_create, pthread_join, pthread_once};

static TEST_GUARD: Mutex<()> = Mutex::new(());

static INIT_COUNTER: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn increment_counter() {
    INIT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn once_runs_exactly_once() {
    let _guard = TEST_GUARD.lock().unwrap();
    INIT_COUNTER.store(0, Ordering::Relaxed);

    let mut once: libc::pthread_once_t = 0;
    assert_eq!(
        unsafe { pthread_once(&mut once, Some(increment_counter)) },
        0
    );
    assert_eq!(INIT_COUNTER.load(Ordering::Relaxed), 1);

    // Second call with same once_control should NOT run the routine again.
    assert_eq!(
        unsafe { pthread_once(&mut once, Some(increment_counter)) },
        0
    );
    assert_eq!(INIT_COUNTER.load(Ordering::Relaxed), 1);
}

#[test]
fn once_null_control_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap();
    assert_eq!(
        unsafe { pthread_once(std::ptr::null_mut(), Some(increment_counter)) },
        libc::EINVAL
    );
}

#[test]
fn once_null_routine_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap();
    let mut once: libc::pthread_once_t = 0;
    assert_eq!(unsafe { pthread_once(&mut once, None) }, libc::EINVAL);
}

static MT_INIT_COUNTER: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn mt_increment_counter() {
    MT_INIT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

/// Shared state for the multi-threaded once test.
/// Using a raw mutable pointer because pthread_once_t must be at a fixed address.
static mut SHARED_ONCE: libc::pthread_once_t = 0;

unsafe extern "C" fn thread_call_once(_arg: *mut c_void) -> *mut c_void {
    unsafe { pthread_once(&raw mut SHARED_ONCE, Some(mt_increment_counter)) };
    std::ptr::null_mut()
}

#[test]
fn once_concurrent_threads_run_exactly_once() {
    let _guard = TEST_GUARD.lock().unwrap();
    MT_INIT_COUNTER.store(0, Ordering::Relaxed);
    unsafe { SHARED_ONCE = 0 };

    const N: usize = 8;
    let mut tids = [0u64; N];

    for tid in &mut tids {
        let rc = unsafe {
            pthread_create(
                tid as *mut libc::pthread_t,
                std::ptr::null(),
                Some(thread_call_once),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "pthread_create failed");
    }

    for &tid in &tids {
        let rc = unsafe { pthread_join(tid, std::ptr::null_mut()) };
        assert_eq!(rc, 0, "pthread_join failed");
    }

    assert_eq!(
        MT_INIT_COUNTER.load(Ordering::Relaxed),
        1,
        "init_routine should run exactly once across all threads"
    );
}

static COUNTER_A: AtomicU32 = AtomicU32::new(0);
static COUNTER_B: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn inc_a() {
    COUNTER_A.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn inc_b() {
    COUNTER_B.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn independent_once_controls_run_independently() {
    let _guard = TEST_GUARD.lock().unwrap();
    COUNTER_A.store(0, Ordering::Relaxed);
    COUNTER_B.store(0, Ordering::Relaxed);

    let mut once_a: libc::pthread_once_t = 0;
    let mut once_b: libc::pthread_once_t = 0;

    assert_eq!(unsafe { pthread_once(&mut once_a, Some(inc_a)) }, 0);
    assert_eq!(unsafe { pthread_once(&mut once_b, Some(inc_b)) }, 0);

    assert_eq!(COUNTER_A.load(Ordering::Relaxed), 1);
    assert_eq!(COUNTER_B.load(Ordering::Relaxed), 1);

    // Second calls should be no-ops
    assert_eq!(unsafe { pthread_once(&mut once_a, Some(inc_a)) }, 0);
    assert_eq!(unsafe { pthread_once(&mut once_b, Some(inc_b)) }, 0);

    assert_eq!(COUNTER_A.load(Ordering::Relaxed), 1);
    assert_eq!(COUNTER_B.load(Ordering::Relaxed), 1);
}

#[test]
fn once_triple_call_idempotent() {
    let _guard = TEST_GUARD.lock().unwrap();
    INIT_COUNTER.store(0, Ordering::Relaxed);

    let mut once: libc::pthread_once_t = 0;
    for _ in 0..10 {
        assert_eq!(
            unsafe { pthread_once(&mut once, Some(increment_counter)) },
            0
        );
    }
    assert_eq!(
        INIT_COUNTER.load(Ordering::Relaxed),
        1,
        "routine should run exactly once despite 10 calls"
    );
}

static SIDE_EFFECT: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn set_side_effect() {
    SIDE_EFFECT.store(42, Ordering::Relaxed);
}

#[test]
fn once_routine_side_effect_visible_after_return() {
    let _guard = TEST_GUARD.lock().unwrap();
    SIDE_EFFECT.store(0, Ordering::Relaxed);

    let mut once: libc::pthread_once_t = 0;
    assert_eq!(unsafe { pthread_once(&mut once, Some(set_side_effect)) }, 0);
    assert_eq!(
        SIDE_EFFECT.load(Ordering::Relaxed),
        42,
        "side effect from once routine should be visible"
    );
}

static HEAVY_COUNTER: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn heavy_increment() {
    HEAVY_COUNTER.fetch_add(1, Ordering::Relaxed);
}

static mut HEAVY_ONCE: libc::pthread_once_t = 0;

unsafe extern "C" fn heavy_thread_fn(_arg: *mut c_void) -> *mut c_void {
    unsafe { pthread_once(&raw mut HEAVY_ONCE, Some(heavy_increment)) };
    std::ptr::null_mut()
}

#[test]
fn once_high_thread_count_still_runs_once() {
    let _guard = TEST_GUARD.lock().unwrap();
    HEAVY_COUNTER.store(0, Ordering::Relaxed);
    unsafe { HEAVY_ONCE = 0 };

    const N: usize = 16;
    let mut tids = [0u64; N];

    for tid in &mut tids {
        assert_eq!(
            unsafe {
                pthread_create(
                    tid as *mut libc::pthread_t,
                    std::ptr::null(),
                    Some(heavy_thread_fn),
                    std::ptr::null_mut(),
                )
            },
            0
        );
    }

    for &tid in &tids {
        assert_eq!(unsafe { pthread_join(tid, std::ptr::null_mut()) }, 0);
    }

    assert_eq!(
        HEAVY_COUNTER.load(Ordering::Relaxed),
        1,
        "16 threads should still result in exactly 1 execution"
    );
}

#[test]
fn once_both_null_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap();
    assert_eq!(
        unsafe { pthread_once(std::ptr::null_mut(), None) },
        libc::EINVAL
    );
}

static LATE_COUNTER: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn late_increment() {
    LATE_COUNTER.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn once_completed_with_different_routine_is_noop() {
    let _guard = TEST_GUARD.lock().unwrap();
    INIT_COUNTER.store(0, Ordering::Relaxed);
    LATE_COUNTER.store(0, Ordering::Relaxed);

    let mut once: libc::pthread_once_t = 0;
    // First call with increment_counter.
    assert_eq!(
        unsafe { pthread_once(&mut once, Some(increment_counter)) },
        0
    );
    assert_eq!(INIT_COUNTER.load(Ordering::Relaxed), 1);

    // Second call with a DIFFERENT routine — should still be a no-op.
    assert_eq!(unsafe { pthread_once(&mut once, Some(late_increment)) }, 0);
    assert_eq!(
        LATE_COUNTER.load(Ordering::Relaxed),
        0,
        "second routine should not run after once is complete"
    );
    assert_eq!(
        INIT_COUNTER.load(Ordering::Relaxed),
        1,
        "original counter should remain at 1"
    );
}
