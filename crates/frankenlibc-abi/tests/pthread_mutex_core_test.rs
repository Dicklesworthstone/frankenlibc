#![cfg(target_os = "linux")]

use std::sync::{Arc, Barrier, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use frankenlibc_abi::pthread_abi::{
    pthread_mutex_branch_counters_for_tests, pthread_mutex_destroy, pthread_mutex_init,
    pthread_mutex_lock, pthread_mutex_reset_state_for_tests, pthread_mutex_trylock,
    pthread_mutex_unlock,
};

static TEST_GUARD: Mutex<()> = Mutex::new(());

fn alloc_mutex_ptr() -> *mut libc::pthread_mutex_t {
    let boxed: Box<libc::pthread_mutex_t> = Box::new(unsafe { std::mem::zeroed() });
    Box::into_raw(boxed)
}

unsafe fn free_mutex_ptr(ptr: *mut libc::pthread_mutex_t) {
    // SAFETY: pointer was allocated with Box::into_raw in alloc_mutex_ptr.
    unsafe { drop(Box::from_raw(ptr)) };
}

fn wait_for_counter_increase(
    label: &str,
    before: (u64, u64, u64),
    timeout: Duration,
) -> (u64, u64, u64) {
    let start = std::time::Instant::now();
    loop {
        let now = pthread_mutex_branch_counters_for_tests();
        if now.0 > before.0 || now.1 > before.1 || now.2 > before.2 {
            return now;
        }
        if start.elapsed() > timeout {
            panic!(
                "timeout waiting for mutex counter increase ({label}): before={before:?} now={now:?}"
            );
        }
        std::thread::yield_now();
    }
}

#[test]
fn futex_mutex_roundtrip_and_trylock_busy() {
    let _guard = TEST_GUARD.lock().unwrap();
    pthread_mutex_reset_state_for_tests();

    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);
        assert_eq!(pthread_mutex_trylock(mutex), libc::EBUSY);
        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn futex_mutex_contention_increments_wait_and_wake_counters() {
    let _guard = TEST_GUARD.lock().unwrap();
    pthread_mutex_reset_state_for_tests();

    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);
    }

    let before = pthread_mutex_branch_counters_for_tests();
    let barrier = Arc::new(Barrier::new(2));
    let barrier_worker = Arc::clone(&barrier);
    let started = Arc::new(AtomicBool::new(false));
    let started_worker = Arc::clone(&started);
    let mutex_addr = mutex as usize;

    let handle = std::thread::spawn(move || {
        barrier_worker.wait();
        started_worker.store(true, Ordering::Release);
        unsafe {
            assert_eq!(
                pthread_mutex_lock(mutex_addr as *mut libc::pthread_mutex_t),
                0
            );
            assert_eq!(
                pthread_mutex_unlock(mutex_addr as *mut libc::pthread_mutex_t),
                0
            );
        }
    });

    barrier.wait();
    assert!(
        started.load(Ordering::Acquire),
        "worker did not start lock attempt"
    );

    // Keep the mutex locked until we observe at least one counter increase, proving
    // the contended path executed. Avoid fixed sleeps for determinism.
    let _ = wait_for_counter_increase("contention", before, Duration::from_millis(200));
    unsafe {
        assert_eq!(pthread_mutex_unlock(mutex), 0);
    }

    handle.join().unwrap();
    let after = pthread_mutex_branch_counters_for_tests();

    assert!(
        after.0 >= before.0 + 1,
        "spin did not increase: before={before:?} after={after:?}"
    );
    assert!(
        after.1 >= before.1 + 1,
        "wait did not increase: before={before:?} after={after:?}"
    );
    assert!(
        after.2 >= before.2 + 1,
        "wake did not increase: before={before:?} after={after:?}"
    );

    unsafe {
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn futex_mutex_destroy_while_locked_is_ebusy() {
    let _guard = TEST_GUARD.lock().unwrap();
    pthread_mutex_reset_state_for_tests();

    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);
        assert_eq!(pthread_mutex_destroy(mutex), libc::EBUSY);
        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn futex_mutex_unlock_without_lock_is_eperm() {
    let _guard = TEST_GUARD.lock().unwrap();
    pthread_mutex_reset_state_for_tests();

    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_unlock(mutex), libc::EPERM);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_mutex_ptr(mutex);
    }
}
