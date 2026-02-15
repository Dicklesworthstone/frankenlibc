#![cfg(target_os = "linux")]

//! Integration tests for pthread_once.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

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
