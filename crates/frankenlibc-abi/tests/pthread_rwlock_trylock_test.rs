#![cfg(target_os = "linux")]

//! Integration tests for pthread_rwlock_tryrdlock and pthread_rwlock_trywrlock.

use std::sync::Mutex;

use frankenlibc_abi::pthread_abi::{
    pthread_rwlock_destroy, pthread_rwlock_init, pthread_rwlock_rdlock, pthread_rwlock_tryrdlock,
    pthread_rwlock_trywrlock, pthread_rwlock_unlock, pthread_rwlock_wrlock,
};

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
    let _guard = TEST_GUARD.lock().unwrap();
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_tryrdlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn tryrdlock_succeeds_when_read_locked() {
    let _guard = TEST_GUARD.lock().unwrap();
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
    let _guard = TEST_GUARD.lock().unwrap();
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
    let _guard = TEST_GUARD.lock().unwrap();
    let rwl = alloc_rwlock();
    assert_eq!(unsafe { pthread_rwlock_init(rwl, std::ptr::null()) }, 0);

    assert_eq!(unsafe { pthread_rwlock_trywrlock(rwl) }, 0);
    assert_eq!(unsafe { pthread_rwlock_unlock(rwl) }, 0);

    assert_eq!(unsafe { pthread_rwlock_destroy(rwl) }, 0);
    unsafe { free_rwlock(rwl) };
}

#[test]
fn trywrlock_fails_when_read_locked() {
    let _guard = TEST_GUARD.lock().unwrap();
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
    let _guard = TEST_GUARD.lock().unwrap();
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
    let _guard = TEST_GUARD.lock().unwrap();
    assert_eq!(
        unsafe { pthread_rwlock_tryrdlock(std::ptr::null_mut()) },
        libc::EINVAL
    );
}

#[test]
fn trywrlock_null_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap();
    assert_eq!(
        unsafe { pthread_rwlock_trywrlock(std::ptr::null_mut()) },
        libc::EINVAL
    );
}
