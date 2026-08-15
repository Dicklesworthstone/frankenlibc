#![cfg(target_os = "linux")]

//! Integration tests for pthread_rwlock_tryrdlock and pthread_rwlock_trywrlock.

use std::sync::Mutex;

use frankenlibc_abi::pthread_abi::{
    pthread_rwlock_destroy, pthread_rwlock_init, pthread_rwlock_rdlock, pthread_rwlock_tryrdlock,
    pthread_rwlock_trywrlock, pthread_rwlock_unlock, pthread_rwlock_wrlock,
};

/// Acquire poison-tolerantly, so a failing assertion reports as one failure instead of
/// poisoning this guard and taking every later test with it (bd-9ri7g1).
static TEST_GUARD: Mutex<()> = Mutex::new(());

fn alloc_rwlock() -> *mut libc::pthread_rwlock_t {
    let boxed: Box<libc::pthread_rwlock_t> = Box::new(unsafe { std::mem::zeroed() });
    Box::into_raw(boxed)
}

unsafe fn free_rwlock(ptr: *mut libc::pthread_rwlock_t) {
    unsafe { drop(Box::from_raw(ptr)) };
}

#[test]
fn tryrdlock_succeeds_when_unlocked() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn tryrdlock_succeeds_when_read_locked() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    // Take a read lock, then try another read lock — should succeed.
    assert_eq!(unsafe { pthread_rwlock_rdlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, 0);

    // Unlock both.
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn tryrdlock_fails_when_write_locked() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_wrlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, libc::EBUSY);

    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn trywrlock_succeeds_when_unlocked() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_trywrlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn trywrlock_fails_when_read_locked() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_rdlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_trywrlock(rwl) }, libc::EBUSY);

    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn trywrlock_fails_when_write_locked() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_wrlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_trywrlock(rwl) }, libc::EBUSY);

    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn tryrdlock_null_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        unsafe { pthread_rwlock_tryrdlock(std::ptr::null_mut()) },
        libc::EINVAL
    );
}

#[test]
fn trywrlock_null_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        unsafe { pthread_rwlock_trywrlock(std::ptr::null_mut()) },
        libc::EINVAL
    );
}

#[test]
fn tryrdlock_multiple_concurrent_reads_succeed() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    // Take 3 read locks via tryrdlock — all should succeed.
    for _ in 0..3 {
        assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, 0);
    }
    // Unlock all 3.
    for _ in 0..3 {
        assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    }

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn trywrlock_after_read_unlock_succeeds() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_rdlock(rwl) }, 0);
    // trywrlock should fail while read-locked.
    assert_eq!(unsafe { pthread_rwlock_trywrlock(rwl) }, libc::EBUSY);
    // Release the read lock.
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    // Now trywrlock should succeed.
    assert_eq!(unsafe { pthread_rwlock_trywrlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn tryrdlock_after_write_unlock_succeeds() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_wrlock(rwl) }, 0);
    // tryrdlock should fail while write-locked.
    assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, libc::EBUSY);
    // Release the write lock.
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    // Now tryrdlock should succeed.
    assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn tryrdlock_trywrlock_interleaved_cycle() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    for _ in 0..10 {
        // Read lock cycle
        assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, 0);
        assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
        // Write lock cycle
        assert_eq!(unsafe { pthread_rwlock_trywrlock(rwl) }, 0);
        assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);
    }

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}
