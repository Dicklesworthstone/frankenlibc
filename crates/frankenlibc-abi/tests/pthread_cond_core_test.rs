#![cfg(target_os = "linux")]

use frankenlibc_abi::pthread_abi::{
    pthread_cond_broadcast, pthread_cond_destroy, pthread_cond_init, pthread_cond_signal,
    pthread_cond_wait, pthread_mutex_destroy, pthread_mutex_init,
    pthread_mutex_reset_state_for_tests,
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
