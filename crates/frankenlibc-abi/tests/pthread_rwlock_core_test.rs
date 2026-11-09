#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use frankenlibc_abi::pthread_abi::{
    pthread_rwlock_destroy, pthread_rwlock_init, pthread_rwlock_rdlock, pthread_rwlock_unlock,
    pthread_rwlock_wrlock, pthread_rwlockattr_init,
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
        // glibc accepts an initialized (default) attribute.
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        assert_eq!(pthread_rwlockattr_init(&mut attr), 0);
        assert_eq!(pthread_rwlock_init(rwlock, &attr), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);

        assert_eq!(pthread_rwlock_init(rwlock, std::ptr::null()), 0);
        assert_eq!(pthread_rwlock_rdlock(rwlock), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), libc::EBUSY);
        assert_eq!(pthread_rwlock_unlock(rwlock), 0);
        assert_eq!(pthread_rwlock_destroy(rwlock), 0);

        // All-zero storage is PTHREAD_RWLOCK_INITIALIZER, which glibc
        // accepts; garbage storage (a nonzero word and no managed magic) is
        // what fl rejects.
        let zeroed = alloc_rwlock_ptr();
        assert_eq!(pthread_rwlock_rdlock(zeroed), 0);
        assert_eq!(pthread_rwlock_unlock(zeroed), 0);
        free_rwlock_ptr(zeroed);
        let unmanaged = alloc_rwlock_ptr();
        std::ptr::write_bytes(
            unmanaged.cast::<u8>(),
            0xA5,
            std::mem::size_of::<libc::pthread_rwlock_t>(),
        );
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

#[test]
fn rwlock_static_initializer_adoption_survives_concurrent_acquire() {
    use frankenlibc_abi::pthread_abi::pthread_rwlock_is_managed_observed_for_tests;
    use std::sync::mpsc;

    #[derive(Debug, PartialEq, Eq)]
    struct Outcome {
        write_owner: bool,
        paused_after_zero_magic: bool,
        acquisition: i32,
        resumed: bool,
        recognition: Option<(bool, usize)>,
        unlock: i32,
        destroy: i32,
    }

    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let mut outcomes = Vec::new();
    for write_owner in [false, true] {
        // Use the public static initializer. The test never writes internal
        // lock state; a real read/write acquisition performs the adoption.
        let mut rwlock = Box::new(libc::PTHREAD_RWLOCK_INITIALIZER);
        let address = (&mut *rwlock as *mut libc::pthread_rwlock_t) as usize;
        let (paused_tx, paused_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let validator = std::thread::spawn(move || {
            let mut observations = 0;
            // SAFETY: the caller retains this aligned static-initializer
            // storage until the validator joins. The observer only schedules
            // threads; it cannot read or mutate the rwlock's internal state.
            let recognized = unsafe {
                pthread_rwlock_is_managed_observed_for_tests(
                    address as *mut libc::pthread_rwlock_t,
                    || {
                        observations += 1;
                        if observations == 1 {
                            let _ = paused_tx.send(());
                            let _ = resume_rx.recv();
                        }
                    },
                )
            };
            (recognized, observations)
        });

        let paused = paused_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        // SAFETY: the validator is paused after observing zero magic, before
        // its owner-word load. This thread adopts the same live rwlock and
        // keeps its read/write ownership until validation has finished.
        let acquisition = if paused {
            unsafe {
                if write_owner {
                    pthread_rwlock_wrlock(address as *mut libc::pthread_rwlock_t)
                } else {
                    pthread_rwlock_rdlock(address as *mut libc::pthread_rwlock_t)
                }
            }
        } else {
            libc::EINVAL
        };
        // Always release the scheduling pause and join before asserting, even
        // when the old validator incorrectly rejects the now-owned lock.
        let resumed = resume_tx.send(()).is_ok();
        let recognition = validator.join().ok();
        // SAFETY: the validator has joined; release any acquired ownership
        // before destruction and before the Box can free its storage.
        let (unlock, destroy) = unsafe {
            let unlock = if acquisition == 0 {
                pthread_rwlock_unlock(address as *mut libc::pthread_rwlock_t)
            } else {
                libc::EINVAL
            };
            let destroy = pthread_rwlock_destroy(address as *mut libc::pthread_rwlock_t);
            (unlock, destroy)
        };
        outcomes.push(Outcome {
            write_owner,
            paused_after_zero_magic: paused,
            acquisition,
            resumed,
            recognition,
            unlock,
            destroy,
        });
    }

    // Both schedules have run and every worker/owner has been cleaned up
    // before a red assertion can stop the test.
    let expected: Vec<_> = [false, true]
        .into_iter()
        .map(|write_owner| Outcome {
            write_owner,
            paused_after_zero_magic: true,
            acquisition: 0,
            resumed: true,
            recognition: Some((true, 1)),
            unlock: 0,
            destroy: 0,
        })
        .collect();
    assert_eq!(outcomes, expected);
}
