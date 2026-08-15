#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use frankenlibc_abi::pthread_abi::{
    pthread_rwlock_destroy, pthread_rwlock_init, pthread_rwlock_rdlock, pthread_rwlock_unlock,
    pthread_rwlock_wrlock,
};

/// Acquire poison-tolerantly, so a failing assertion reports as one failure instead of
/// poisoning this guard and taking every later test with it (bd-9ri7g1).
static TEST_GUARD: Mutex<()> = Mutex::new(());

fn alloc_rwlock_ptr() -> *mut libc::pthread_rwlock_t {
    let boxed: Box<libc::pthread_rwlock_t> = Box::new(unsafe { std::mem::zeroed() });
    Box::into_raw(boxed)
}

unsafe fn free_rwlock_ptr(ptr: *mut libc::pthread_rwlock_t) {
    // SAFETY: pointer was returned by `Box::into_raw` in `alloc_rwlock_ptr`.
    unsafe { drop(Box::from_raw(ptr)) };
}

#[test]
fn rwlock_roundtrip_read_and_write() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();

    // SAFETY: pointer identity is stable for test lifetime.
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        assert_eq!(pthread_rwlock_wrlock(rwlock), 0);
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_destroy_busy_and_validation_contract() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();

    // SAFETY: pointer identity is stable for test lifetime.
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        assert_eq!(
            pthread_rwlock_init(rwlock, &mut attr as *mut libc::pthread_rwlockattr_t),
            libc::EINVAL
        );

        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), libc::EBUSY);
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);

        let unmanaged = alloc_rwlock_ptr();
        assert_eq!(pthread_rwlock_rdlock(unmanaged), libc::EINVAL);
        assert_eq!(pthread_rwlock_wrlock(unmanaged), libc::EINVAL);
        assert_eq!(pthread_rwlock_unlock(unmanaged), libc::EINVAL);
        assert_eq!(pthread_rwlock_destroy(unmanaged), libc::EINVAL);
        free_rwlock_ptr(unmanaged);

        assert_eq!(pthread_rwlock_rdlock(std::ptr::null_mut()), libc::EINVAL);
        assert_eq!(pthread_rwlock_wrlock(std::ptr::null_mut()), libc::EINVAL);
        assert_eq!(pthread_rwlock_unlock(std::ptr::null_mut()), libc::EINVAL);

        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_writer_blocks_reader_until_unlock() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();

    // SAFETY: pointer identity is stable for test lifetime.
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        assert_eq!(pthread_rwlock_wrlock(rwlock), 0);
    }

    let reader_entered = Arc::new(AtomicBool::new(false));
    let entered_clone = Arc::clone(&reader_entered);
    let rwlock_addr = rwlock as usize;

    let handle = std::thread::spawn(move || {
        // SAFETY: pointer identity is stable for test lifetime.
        unsafe {
            assert_eq!(
                pthread_rwlock_rdlock(rwlock_addr as *mut libc::pthread_rwlock_t),
                0
            );
            entered_clone.store(true, Ordering::Release);
            assert_eq!(
                pthread_rwlock_unlock(rwlock_addr as *mut libc::pthread_rwlock_t),
                0
            );
        }
    });

    std::thread::sleep(Duration::from_millis(20));
    assert!(
        !reader_entered.load(Ordering::Acquire),
        "reader acquired lock while writer still held it"
    );

    // SAFETY: pointer identity is stable for test lifetime.
    unsafe {
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
    }
    handle.join().unwrap();

    assert!(
        reader_entered.load(Ordering::Acquire),
        "reader never acquired lock after writer unlock"
    );

    // SAFETY: pointer identity is stable for test lifetime.
    unsafe {
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_multiple_concurrent_readers() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
    }

    // Take 4 read locks — all should succeed since readers don't block readers.
    let rwlock_addr = rwlock as usize;
    let barrier = Arc::new(std::sync::Barrier::new(5)); // 4 readers + main
    let all_locked = Arc::new(AtomicBool::new(false));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let b = Arc::clone(&barrier);
            let locked = Arc::clone(&all_locked);
            std::thread::spawn(move || {
                let rwl = rwlock_addr as *mut libc::pthread_rwlock_t;
                unsafe {
                    assert_eq!(pthread_rwlock_rdlock(rwl), 0);
                }
                b.wait(); // all readers hold locks
                // Wait until main signals we can unlock
                while !locked.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                unsafe {
                    assert_eq!(pthread_rwlock_unlock(rwl), 0);
                }
            })
        })
        .collect();

    barrier.wait(); // all 4 readers hold read locks concurrently
    all_locked.store(true, Ordering::Release);

    for h in handles {
        h.join().unwrap();
    }

    unsafe {
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_init_null_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert_eq!(
            pthread_rwlock_init(std::ptr::null_mut(), std::ptr::null()),
            libc::EINVAL
        );
    }
}

#[test]
fn rwlock_rdlock_then_rdlock_same_thread() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        // Multiple read locks from the same thread should succeed
        assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
        assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_destroy_null_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert_eq!(pthread_rwlock_destroy(std::ptr::null_mut()), libc::EINVAL);
    }
}

#[test]
fn rwlock_init_destroy_reinit() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        // Reinit after destroy should work
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_write_then_write_different_thread_blocks() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        assert_eq!(pthread_rwlock_wrlock(rwlock), 0);
    }

    let writer_entered = Arc::new(AtomicBool::new(false));
    let entered_clone = Arc::clone(&writer_entered);
    let rwlock_addr = rwlock as usize;

    let handle = std::thread::spawn(move || {
        let rwl = rwlock_addr as *mut libc::pthread_rwlock_t;
        unsafe {
            assert_eq!(pthread_rwlock_wrlock(rwl), 0);
            entered_clone.store(true, Ordering::Release);
            assert_eq!(pthread_rwlock_unlock(rwl), 0);
        }
    });

    std::thread::sleep(Duration::from_millis(20));
    assert!(
        !writer_entered.load(Ordering::Acquire),
        "second writer should be blocked"
    );

    unsafe {
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
    }
    handle.join().unwrap();

    assert!(writer_entered.load(Ordering::Acquire));

    unsafe {
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_read_lock_unlock_repeated_cycle() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        for _ in 0..20 {
            assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
            assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        }
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_write_lock_unlock_repeated_cycle() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        for _ in 0..20 {
            assert_eq!(pthread_rwlock_wrlock(rwlock), 0);
            assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        }
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}

#[test]
fn rwlock_read_then_write_interleaved_cycle() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rwlock = alloc_rwlock_ptr();
    unsafe {
        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        for _ in 0..10 {
            assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
            assert_eq!(pthread_rwlock_unlock(rwlock), 0);
            assert_eq!(pthread_rwlock_wrlock(rwlock), 0);
            assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        }
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);
        free_rwlock_ptr(rwlock);
    }
}
