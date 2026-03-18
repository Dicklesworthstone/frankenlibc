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

#[test]
fn condvar_timedwait_rejects_null_abstime_and_invalid_nsec() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);

        assert_eq!(
            pthread_cond_timedwait(cond, mutex, std::ptr::null()),
            libc::EINVAL
        );

        let invalid_nsec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        };
        assert_eq!(
            pthread_cond_timedwait(cond, mutex, &invalid_nsec as *const libc::timespec),
            libc::EINVAL
        );

        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_init_null_is_einval() {
    pthread_mutex_reset_state_for_tests();
    unsafe {
        assert_eq!(
            pthread_cond_init(std::ptr::null_mut(), std::ptr::null()),
            libc::EINVAL
        );
    }
}

#[test]
fn condvar_destroy_null_is_einval() {
    pthread_mutex_reset_state_for_tests();
    unsafe {
        assert_eq!(pthread_cond_destroy(std::ptr::null_mut()), libc::EINVAL);
    }
}

#[test]
fn condvar_signal_null_is_einval() {
    pthread_mutex_reset_state_for_tests();
    unsafe {
        assert_eq!(pthread_cond_signal(std::ptr::null_mut()), libc::EINVAL);
    }
}

#[test]
fn condvar_broadcast_null_is_einval() {
    pthread_mutex_reset_state_for_tests();
    unsafe {
        assert_eq!(pthread_cond_broadcast(std::ptr::null_mut()), libc::EINVAL);
    }
}

#[test]
fn condvar_signal_wakes_timedwait_thread() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();

    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
    }

    let signaled = Arc::new(AtomicBool::new(false));
    let signaled_clone = Arc::clone(&signaled);
    let cond_addr = cond as usize;
    let mutex_addr = mutex as usize;

    let handle = std::thread::spawn(move || {
        let c = cond_addr as *mut libc::pthread_cond_t;
        let m = mutex_addr as *mut libc::pthread_mutex_t;
        unsafe {
            assert_eq!(pthread_mutex_lock(m), 0);
            // Use timedwait with a generous timeout
            let abstime = realtime_abstime_after(2000);
            let rc = pthread_cond_timedwait(c, m, &abstime as *const libc::timespec);
            signaled_clone.store(true, Ordering::Release);
            assert_eq!(rc, 0, "should wake from signal, not timeout");
            assert_eq!(pthread_mutex_unlock(m), 0);
        }
    });

    // Give the waiter time to enter timedwait
    std::thread::sleep(std::time::Duration::from_millis(50));
    unsafe {
        assert_eq!(pthread_cond_signal(cond), 0);
    }

    handle.join().unwrap();
    assert!(signaled.load(Ordering::Acquire));

    unsafe {
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_init_destroy_reinit() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    unsafe {
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        assert_eq!(pthread_cond_destroy(cond), 0);
        // Reinit after destroy should succeed
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        assert_eq!(pthread_cond_signal(cond), 0);
        assert_eq!(pthread_cond_destroy(cond), 0);
        free_cond_ptr(cond);
    }
}

#[test]
fn condvar_wait_null_cond_is_einval() {
    pthread_mutex_reset_state_for_tests();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);
        assert_eq!(pthread_cond_wait(std::ptr::null_mut(), mutex), libc::EINVAL);
        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_timedwait_null_cond_is_einval() {
    pthread_mutex_reset_state_for_tests();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);
        let abstime = realtime_abstime_after(100);
        assert_eq!(
            pthread_cond_timedwait(
                std::ptr::null_mut(),
                mutex,
                &abstime as *const libc::timespec
            ),
            libc::EINVAL
        );
        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_timedwait_past_abstime_returns_etimedout() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);

        // abstime in the past: epoch 0
        let past = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            pthread_cond_timedwait(cond, mutex, &past as *const libc::timespec),
            libc::ETIMEDOUT
        );

        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_timedwait_negative_nsec_is_einval() {
    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);

        let bad_ts = libc::timespec {
            tv_sec: 1_000_000,
            tv_nsec: -1,
        };
        assert_eq!(
            pthread_cond_timedwait(cond, mutex, &bad_ts as *const libc::timespec),
            libc::EINVAL
        );

        assert_eq!(pthread_mutex_unlock(mutex), 0);
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}

#[test]
fn condvar_broadcast_wakes_multiple_timedwait_threads() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    pthread_mutex_reset_state_for_tests();
    let cond = alloc_cond_ptr();
    let mutex = alloc_mutex_ptr();

    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_cond_init(cond, std::ptr::null()), 0);
    }

    let woke_count = Arc::new(AtomicU32::new(0));
    let cond_addr = cond as usize;
    let mutex_addr = mutex as usize;

    let mut handles = Vec::new();
    for _ in 0..3 {
        let wc = Arc::clone(&woke_count);
        handles.push(std::thread::spawn(move || {
            let c = cond_addr as *mut libc::pthread_cond_t;
            let m = mutex_addr as *mut libc::pthread_mutex_t;
            unsafe {
                assert_eq!(pthread_mutex_lock(m), 0);
                let abstime = realtime_abstime_after(2000);
                let rc = pthread_cond_timedwait(c, m, &abstime as *const libc::timespec);
                if rc == 0 {
                    wc.fetch_add(1, Ordering::Relaxed);
                }
                assert_eq!(pthread_mutex_unlock(m), 0);
            }
        }));
    }

    // Let all waiters enter timedwait.
    std::thread::sleep(std::time::Duration::from_millis(50));
    unsafe {
        assert_eq!(pthread_cond_broadcast(cond), 0);
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        woke_count.load(Ordering::Relaxed),
        3,
        "broadcast should wake all 3 waiters"
    );

    unsafe {
        assert_eq!(pthread_cond_destroy(cond), 0);
        assert_eq!(pthread_mutex_destroy(mutex), 0);
        free_cond_ptr(cond);
        free_mutex_ptr(mutex);
    }
}
