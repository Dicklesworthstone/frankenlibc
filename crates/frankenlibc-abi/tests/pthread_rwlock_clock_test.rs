//! Absolute rwlock deadlines must retain their clock, even at time_t extremes.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
use frankenlibc_abi::{glibc_internal_abi, pthread_abi as p};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

const OPERATIONS: [(usize, libc::clockid_t); 6] = [
    (0, libc::CLOCK_REALTIME),
    (1, libc::CLOCK_REALTIME),
    (2, libc::CLOCK_REALTIME),
    (3, libc::CLOCK_REALTIME),
    (2, libc::CLOCK_MONOTONIC),
    (3, libc::CLOCK_MONOTONIC),
];

unsafe fn wait(
    operation: usize,
    clock: libc::clockid_t,
    rw: *mut libc::pthread_rwlock_t,
    ts: &libc::timespec,
) -> i32 {
    // SAFETY: each test owns initialized storage until every worker has joined.
    unsafe {
        match operation {
            0 => p::pthread_rwlock_timedrdlock(rw, ts),
            1 => p::pthread_rwlock_timedwrlock(rw, ts),
            2 => p::pthread_rwlock_clockrdlock(rw, clock, ts),
            3 => p::pthread_rwlock_clockwrlock(rw, clock, ts),
            _ => unreachable!(),
        }
    }
}

fn future(clock: libc::clockid_t, ns: i64) -> libc::timespec {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a writable timespec and both requested clocks are supported.
    assert_eq!(unsafe { libc::clock_gettime(clock, &mut ts) }, 0);
    ts.tv_nsec += ns;
    ts.tv_sec += ts.tv_nsec / 1_000_000_000;
    ts.tv_nsec %= 1_000_000_000;
    ts
}

fn lock(shared: bool, writer_preference: bool) -> Box<libc::pthread_rwlock_t> {
    // SAFETY: initialized caller-owned attribute and rwlock storage.
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        let mut rw: Box<libc::pthread_rwlock_t> = Box::new(std::mem::zeroed());
        assert_eq!(p::pthread_rwlockattr_init(&mut attr), 0);
        assert_eq!(
            p::pthread_rwlockattr_setpshared(
                &mut attr,
                if shared {
                    libc::PTHREAD_PROCESS_SHARED
                } else {
                    libc::PTHREAD_PROCESS_PRIVATE
                }
            ),
            0
        );
        if writer_preference {
            assert_eq!(
                glibc_internal_abi::pthread_rwlockattr_setkind_np(
                    (&mut attr as *mut libc::pthread_rwlockattr_t).cast(),
                    2
                ),
                0
            );
        }
        assert_eq!(p::pthread_rwlock_init(&mut *rw, &attr), 0);
        assert_eq!(p::pthread_rwlockattr_destroy(&mut attr), 0);
        rw
    }
}

fn isolated(name: &str, body: fn()) {
    if std::env::var_os("FL_RWLOCK_CLOCK_CHILD").is_some() {
        body();
        return;
    }
    for mode in ["strict", "hardened"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_RWLOCK_CLOCK_CHILD", "1")
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}/{mode}: {status}");
                break;
            }
            if Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}/{mode}: timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn rwclock_free_locks_accept_past_and_extreme_deadlines() {
    isolated(
        "rwclock_free_locks_accept_past_and_extreme_deadlines",
        || {
            for shared in [false, true] {
                let mut rw = lock(shared, false);
                for (op, clock) in OPERATIONS {
                    for seconds in [0, -1, i64::MIN, i64::MAX] {
                        let ts = libc::timespec {
                            tv_sec: seconds,
                            tv_nsec: 999_999_999,
                        };
                        // SAFETY: no competing owner; release every successful acquisition.
                        unsafe {
                            assert_eq!(
                                wait(op, clock, &mut *rw, &ts),
                                0,
                                "op={op}, clock={clock}, seconds={seconds}"
                            );
                            assert_eq!(p::pthread_rwlock_unlock(&mut *rw), 0);
                        }
                    }
                }
                assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
            }
        },
    );
}

#[test]
fn rwclock_monotonic_maximum_does_not_overflow_in_abi() {
    isolated("rwclock_monotonic_maximum_does_not_overflow_in_abi", || {
        let mut rw = lock(false, false);
        let ts = libc::timespec {
            tv_sec: i64::MAX,
            tv_nsec: 999_999_999,
        };
        for op in [2, 3] {
            assert_eq!(unsafe { wait(op, libc::CLOCK_MONOTONIC, &mut *rw, &ts) }, 0);
            assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
        }
        assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
    });
}

#[test]
fn rwclock_invalid_inputs_do_not_acquire_or_release_a_lock() {
    isolated(
        "rwclock_invalid_inputs_do_not_acquire_or_release_a_lock",
        || {
            let mut rw = lock(false, false);
            for held in [false, true] {
                if held {
                    assert_eq!(unsafe { p::pthread_rwlock_wrlock(&mut *rw) }, 0);
                }
                for (op, clock) in OPERATIONS {
                    for nsec in [-1, 1_000_000_000, i64::MIN, i64::MAX] {
                        let ts = libc::timespec {
                            tv_sec: i64::MAX,
                            tv_nsec: nsec,
                        };
                        assert_eq!(unsafe { wait(op, clock, &mut *rw, &ts) }, libc::EINVAL);
                    }
                }
                let ts = libc::timespec {
                    tv_sec: i64::MAX,
                    tv_nsec: 0,
                };
                for clock in [-1, libc::CLOCK_BOOTTIME, libc::CLOCK_PROCESS_CPUTIME_ID] {
                    for op in [2, 3] {
                        assert_eq!(unsafe { wait(op, clock, &mut *rw, &ts) }, libc::EINVAL);
                    }
                }
                let rc = unsafe { p::pthread_rwlock_trywrlock(&mut *rw) };
                assert_eq!(rc, if held { libc::EBUSY } else { 0 });
                assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
            }
            assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
        },
    );
}

#[test]
fn rwclock_expired_waiters_time_out_while_owner_still_holds_lock() {
    isolated(
        "rwclock_expired_waiters_time_out_while_owner_still_holds_lock",
        || {
            for shared in [false, true] {
                let mut rw = lock(shared, false);
                assert_eq!(unsafe { p::pthread_rwlock_wrlock(&mut *rw) }, 0);
                let address = (&mut *rw as *mut libc::pthread_rwlock_t) as usize;
                for (op, clock) in OPERATIONS {
                    for seconds in [0, -1, i64::MIN] {
                        let worker = std::thread::spawn(move || {
                            let ts = libc::timespec {
                                tv_sec: seconds,
                                tv_nsec: 0,
                            };
                            unsafe { wait(op, clock, address as *mut _, &ts) }
                        });
                        assert_eq!(
                            worker.join().unwrap(),
                            libc::ETIMEDOUT,
                            "op={op}, clock={clock}, seconds={seconds}"
                        );
                    }
                }
                assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
                assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
            }
        },
    );
}

#[test]
fn rwclock_finite_timeouts_and_far_future_handoffs() {
    isolated("rwclock_finite_timeouts_and_far_future_handoffs", || {
        for shared in [false, true] {
            let mut rw = lock(shared, false);
            let address = (&mut *rw as *mut libc::pthread_rwlock_t) as usize;
            for (op, clock) in OPERATIONS {
                assert_eq!(unsafe { p::pthread_rwlock_wrlock(&mut *rw) }, 0);
                let worker = std::thread::spawn(move || {
                    let start = Instant::now();
                    let ts = future(clock, 30_000_000);
                    let rc = unsafe { wait(op, clock, address as *mut _, &ts) };
                    (rc, start.elapsed())
                });
                let (rc, elapsed) = worker.join().unwrap();
                assert_eq!(rc, libc::ETIMEDOUT);
                assert!(
                    elapsed >= Duration::from_millis(25),
                    "early timeout: {elapsed:?}"
                );
                assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
                assert_eq!(unsafe { p::pthread_rwlock_wrlock(&mut *rw) }, 0);
                let ready = Arc::new(AtomicBool::new(false));
                let returned = Arc::new(AtomicBool::new(false));
                let (ready_worker, returned_worker) = (ready.clone(), returned.clone());
                let worker = std::thread::spawn(move || {
                    let ts = libc::timespec {
                        tv_sec: i64::MAX,
                        tv_nsec: 999_999_999,
                    };
                    ready_worker.store(true, Ordering::Release);
                    let rc = unsafe { wait(op, clock, address as *mut _, &ts) };
                    returned_worker.store(true, Ordering::Release);
                    if rc == 0 {
                        assert_eq!(unsafe { p::pthread_rwlock_unlock(address as *mut _) }, 0);
                    }
                    rc
                });
                while !ready.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                std::thread::sleep(Duration::from_millis(10));
                assert!(
                    !returned.load(Ordering::Acquire),
                    "far-future waiter returned before unlock"
                );
                assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
                assert_eq!(worker.join().unwrap(), 0);
            }
            assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
        }
    });
}

#[test]
fn rwclock_writer_timeout_releases_queued_readers() {
    isolated("rwclock_writer_timeout_releases_queued_readers", || {
        for shared in [false, true] {
            let mut rw = lock(shared, true);
            assert_eq!(unsafe { p::pthread_rwlock_rdlock(&mut *rw) }, 0);
            let address = (&mut *rw as *mut libc::pthread_rwlock_t) as usize;
            let writer = std::thread::spawn(move || {
                let ts = future(libc::CLOCK_MONOTONIC, 1_000_000_000);
                unsafe { wait(3, libc::CLOCK_MONOTONIC, address as *mut _, &ts) }
            });
            // White-box witness only: offset 8 is fl's atomic queued-writer count.
            // Reading it proves the writer registered; no test changes lock state.
            let queued = unsafe { &*((address + 8) as *const AtomicI32) };
            let until = Instant::now() + Duration::from_millis(900);
            while queued.load(Ordering::Acquire) == 0 {
                assert!(Instant::now() < until, "writer never registered");
                std::thread::yield_now();
            }
            let reader = std::thread::spawn(move || {
                let ts = future(libc::CLOCK_MONOTONIC, 3_000_000_000);
                let rc = unsafe { wait(2, libc::CLOCK_MONOTONIC, address as *mut _, &ts) };
                if rc == 0 {
                    assert_eq!(unsafe { p::pthread_rwlock_unlock(address as *mut _) }, 0);
                }
                rc
            });
            assert_eq!(writer.join().unwrap(), libc::ETIMEDOUT);
            assert_eq!(
                reader.join().unwrap(),
                0,
                "reader must wake before original reader unlocks"
            );
            assert_eq!(queued.load(Ordering::Acquire), 0);
            assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
            assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
        }
    });
}
