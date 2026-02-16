#![cfg(target_os = "linux")]

use frankenlibc_abi::pthread_abi::{
    pthread_cond_broadcast, pthread_cond_destroy, pthread_cond_init, pthread_cond_signal,
    pthread_cond_timedwait, pthread_cond_wait, pthread_mutex_destroy, pthread_mutex_init,
    pthread_mutex_lock, pthread_mutex_reset_state_for_tests, pthread_mutex_unlock,
};

fn alloc_mutex_ptr() -> *mut libc::pthread_mutex_t {
    let boxed: Box<libc::pthread_mutex_t> = Box::new(unsafe { std::mem::zeroed() });
    Box::into_raw(boxed)
}

fn alloc_cond_ptr() -> *mut libc::pthread_cond_t {
    let boxed: Box<libc::pthread_cond_t> = Box::new(unsafe { std::mem::zeroed() });
    Box::into_raw(boxed)
}

unsafe fn free_mutex_ptr(ptr: *mut libc::pthread_mutex_t) {
    // SAFETY: pointer was allocated with Box::into_raw in alloc_mutex_ptr.
    unsafe { drop(Box::from_raw(ptr)) };
}

unsafe fn free_cond_ptr(ptr: *mut libc::pthread_cond_t) {
    // SAFETY: pointer was allocated with Box::into_raw in alloc_cond_ptr.
    unsafe { drop(Box::from_raw(ptr)) };
}

fn realtime_abstime_after(millis: i64) -> libc::timespec {
    assert!(millis >= 0);
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts as *mut libc::timespec) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_REALTIME) must succeed");

    ts.tv_sec += millis / 1000;
    ts.tv_nsec += (millis % 1000) * 1_000_000;
    if ts.tv_nsec >= 1_000_000_000 {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1_000_000_000;
    }
    ts
}

#[test]
fn condvar_roundtrip_signal_broadcast_destroy() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        assert_eq!(pthread_cond_signal(cond), 0);
        assert_eq!(pthread_cond_broadcast(cond), 0);
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_wait_rejects_unmanaged_and_null_mutex() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        // Uninitialized mutex is not managed by our futex mutex core.
        assert_eq!(pthread_cond_wait(cond, mutex), libc::EINVAL);
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_wait(cond, std::ptr::null_mut()), libc::EINVAL);
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_init_accepts_initialized_attr() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mut attr: libc::pthread_condattr_t = unsafe { std::mem::zeroed() };
    unsafe {
        assert_eq!(libc::pthread_condattr_init(&mut attr), 0);
        assert_eq!(
            pthread_cond_init(cond, &attr as *const libc::pthread_condattr_t),
            0
        );
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(libc::pthread_condattr_destroy(&mut attr), 0);
        free_cond_ptr(cond);
    }
}

#[test]
fn condvar_init_accepts_monotonic_attr_clock() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mut attr: libc::pthread_condattr_t = unsafe { std::mem::zeroed() };
    unsafe {
        assert_eq!(libc::pthread_condattr_init(&mut attr), 0);
        assert_eq!(
            libc::pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC),
            0
        );
        assert_eq!(
            pthread_cond_init(cond, &attr as *const libc::pthread_condattr_t),
            0
        );
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(libc::pthread_condattr_destroy(&mut attr), 0);
        free_cond_ptr(cond);
    }
}

#[test]
fn condvar_timedwait_timeout_relocks_mutex() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);

        let abstime = realtime_abstime_after(25);
        assert_eq!(
            pthread_cond_timedwait(cond, mutex, &abstime as *const libc::timespec),
            libc::ETIMEDOUT
        );

        // POSIX contract: timedwait must reacquire mutex before returning.
        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_mutex_unlock(mutex), libc::EPERM);

        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_repeated_timedwait_timeout_is_stable() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);

        for _ in 0..32 {
            assert_eq!(pthread_mutex_lock(mutex), 0);
            let abstime = realtime_abstime_after(2);
            assert_eq!(
                pthread_cond_timedwait(cond, mutex, &abstime as *const libc::timespec),
                libc::ETIMEDOUT
            );
            assert_eq!(pthread_mutex_unlock(mutex), 0);
        }

        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}
