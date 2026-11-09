//! Absolute rwlock deadlines must retain their clock, even at time_t extremes.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
use frankenlibc_abi::{glibc_internal_abi, pthread_abi as p};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, mpsc};
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

#[test]
fn rwclock_reader_registration_cannot_miss_writer_timeout() {
    isolated(
        "rwclock_reader_registration_cannot_miss_writer_timeout",
        || {
            let mut failures = Vec::new();
            for shared in [false, true] {
                for clock in [
                    None,
                    Some(libc::CLOCK_REALTIME),
                    Some(libc::CLOCK_MONOTONIC),
                ] {
                    let mut rw = lock(shared, true);
                    // SAFETY: the original reader retains this lock until the
                    // completion observation, then every worker is joined.
                    assert_eq!(unsafe { p::pthread_rwlock_rdlock(&mut *rw) }, 0);
                    let address = (&mut *rw as *mut libc::pthread_rwlock_t) as usize;
                    let writer = std::thread::spawn(move || {
                        let ts = future(libc::CLOCK_MONOTONIC, 1_000_000_000);
                        // SAFETY: the test retains initialized storage.
                        unsafe { wait(3, libc::CLOCK_MONOTONIC, address as *mut _, &ts) }
                    });
                    // SAFETY: this native-only layout observation is read-only;
                    // the counter is atomic and the rwlock remains initialized.
                    let queued = unsafe { &*((address + 8) as *const AtomicI32) };
                    let until = Instant::now() + Duration::from_millis(900);
                    while queued.load(Ordering::Acquire) == 0 {
                        assert!(Instant::now() < until, "writer never registered");
                        std::thread::yield_now();
                    }
                    let (observed_tx, observed_rx) = mpsc::channel();
                    let (resume_tx, resume_rx) = mpsc::channel();
                    let (finished_tx, finished_rx) = mpsc::channel();
                    let reader = std::thread::spawn(move || {
                        let deadline = clock.map(|clock| (clock, future(clock, 10_000_000_000)));
                        let mut observed = false;
                        // SAFETY: only this caller's scheduling is paused. The
                        // real read-lock implementation chooses its wait word.
                        let rc = unsafe {
                            p::pthread_rwlock_read_wait_observed_for_tests(
                                address as *mut _,
                                deadline,
                                |word, expected| {
                                    if !observed {
                                        observed = true;
                                        observed_tx.send((word, expected)).unwrap();
                                        resume_rx.recv().unwrap();
                                    }
                                },
                            )
                        };
                        if rc == 0 {
                            // SAFETY: this thread acquired its own read lock.
                            assert_eq!(unsafe { p::pthread_rwlock_unlock(address as *mut _) }, 0);
                        }
                        finished_tx.send(rc).unwrap();
                        rc
                    });
                    let (_, expected) = observed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    assert!(
                        expected > 0,
                        "reader did not observe an exclusion predicate"
                    );
                    let writer_rc = writer.join().unwrap();
                    assert_eq!(queued.load(Ordering::Acquire), 0);
                    resume_tx.send(()).unwrap();

                    // This is a positive progress requirement, not a sleep
                    // followed by an assertion that a thread stayed blocked.
                    // Keep the original reader locked while awaiting success.
                    let before_owner_unlock = finished_rx.recv_timeout(Duration::from_secs(2));
                    // Rescue a stranded old-algorithm reader, then join before
                    // asserting. Success after this unlock cannot satisfy the test.
                    assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
                    let reader_rc = reader.join().unwrap();
                    assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
                    if writer_rc != libc::ETIMEDOUT
                        || before_owner_unlock != Ok(0)
                        || reader_rc != 0
                    {
                        failures.push(format!(
                            "shared={shared}, clock={clock:?}: writer={writer_rc}, before_owner_unlock={before_owner_unlock:?}, reader={reader_rc}"
                        ));
                    }
                }
            }
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        },
    );
}

fn observe_kernel_futex(path: &std::path::Path, address: usize, expected: Option<i32>) -> bool {
    let until = Instant::now() + Duration::from_secs(2);
    let mut last_snapshot = String::new();
    while Instant::now() < until {
        let snapshot = std::fs::read_to_string(path).expect("read live worker syscall snapshot");
        let fields: Vec<_> = snapshot.split_whitespace().collect();
        let hex = |index: usize| {
            fields
                .get(index)
                .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        };
        if fields.first().and_then(|value| value.parse::<i64>().ok()) == Some(libc::SYS_futex)
            && hex(1) == Some(address as u64)
            && matches!(hex(2).map(|op| op & 0x7f), Some(0 | 9))
            && expected.is_none_or(|value| hex(3) == Some(u64::from(value as u32)))
        {
            return true;
        }
        last_snapshot = snapshot;
        std::thread::yield_now();
    }
    eprintln!(
        "futex observation expired: path={}, address={address:#x}, expected={expected:?}, last={last_snapshot:?}",
        path.display(),
    );
    false
}

#[test]
fn rwclock_last_writer_acquisition_transfers_reader_waits() {
    isolated(
        "rwclock_last_writer_acquisition_transfers_reader_waits",
        || {
            for shared in [false, true] {
                for clock in [
                    None,
                    Some(libc::CLOCK_REALTIME),
                    Some(libc::CLOCK_MONOTONIC),
                ] {
                    let mut rw = lock(shared, true);
                    // SAFETY: all worker accesses finish before destruction.
                    assert_eq!(unsafe { p::pthread_rwlock_rdlock(&mut *rw) }, 0);
                    let address = (&mut *rw as *mut libc::pthread_rwlock_t) as usize;
                    let (acquired_tx, acquired_rx) = mpsc::channel();
                    let (release_tx, release_rx) = mpsc::channel();
                    let writer = std::thread::spawn(move || {
                        // SAFETY: this worker receives live initialized storage.
                        let rc = unsafe { p::pthread_rwlock_wrlock(address as *mut _) };
                        acquired_tx.send(rc).unwrap();
                        if rc == 0 {
                            release_rx.recv().unwrap();
                            // SAFETY: this thread owns the write lock.
                            assert_eq!(unsafe { p::pthread_rwlock_unlock(address as *mut _) }, 0);
                        }
                        rc
                    });
                    // SAFETY: native-layout atomic observation only; no state mutation.
                    let queued = unsafe { &*((address + 8) as *const AtomicI32) };
                    let until = Instant::now() + Duration::from_secs(2);
                    while queued.load(Ordering::Acquire) == 0 {
                        assert!(Instant::now() < until, "writer never registered");
                        std::thread::yield_now();
                    }
                    let (observed_tx, observed_rx) = mpsc::channel();
                    let (finished_tx, finished_rx) = mpsc::channel();
                    let reader = std::thread::spawn(move || {
                        // procfs may expose a different PID namespace from gettid.
                        let task = std::fs::read_link("/proc/thread-self").unwrap();
                        let syscall_path = std::path::Path::new("/proc").join(task).join("syscall");
                        let deadline = clock.map(|clock| (clock, future(clock, 20_000_000_000)));
                        let mut observed = false;
                        // SAFETY: the observer reports scheduling and addresses
                        // only; the production algorithm performs the actual wait.
                        let rc = unsafe {
                            p::pthread_rwlock_read_wait_observed_for_tests(
                                address as *mut _,
                                deadline,
                                |word, expected| {
                                    if !observed {
                                        observed = true;
                                        observed_tx
                                            .send((syscall_path.clone(), word, expected))
                                            .unwrap();
                                    }
                                },
                            )
                        };
                        if rc == 0 {
                            // SAFETY: this thread owns a read lock.
                            assert_eq!(unsafe { p::pthread_rwlock_unlock(address as *mut _) }, 0);
                        }
                        finished_tx.send(rc).unwrap();
                        rc
                    });
                    let (path, first_word, expected) =
                        observed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    let queued_reader_parked =
                        observe_kernel_futex(&path, first_word, Some(expected));
                    // SAFETY: release only this thread's original read ownership.
                    assert_eq!(unsafe { p::pthread_rwlock_unlock(&mut *rw) }, 0);
                    let acquired = acquired_rx.recv_timeout(Duration::from_secs(2));
                    // A successful last-writer dequeue must wake the queued reader
                    // so it can move to the active writer's owner-word wait.
                    // The syscall retains its historical expected value if the
                    // writer acquired after the reader entered the owner wait.
                    let moved_to_owner = observe_kernel_futex(&path, address, None);
                    release_tx.send(()).unwrap();
                    let before_rescue = finished_rx.recv_timeout(Duration::from_secs(2));
                    if before_rescue != Ok(0) {
                        // SAFETY: cleanup-only wake on a still-live observed futex.
                        // Its necessity was already recorded as a failure above.
                        unsafe {
                            libc::syscall(
                                libc::SYS_futex,
                                first_word as *const u32,
                                libc::FUTEX_WAKE
                                    | if shared { 0 } else { libc::FUTEX_PRIVATE_FLAG },
                                i32::MAX,
                            );
                        }
                    }
                    let writer_rc = writer.join().unwrap();
                    let reader_rc = reader.join().unwrap();
                    assert_eq!(queued.load(Ordering::Acquire), 0);
                    // SAFETY: both workers have joined and every lock is released.
                    assert_eq!(unsafe { p::pthread_rwlock_destroy(&mut *rw) }, 0);
                    assert!(queued_reader_parked, "reader never parked before handoff");
                    assert!(
                        moved_to_owner,
                        "last writer did not transfer the reader wait"
                    );
                    assert_eq!(acquired, Ok(0));
                    assert_eq!(
                        before_rescue,
                        Ok(0),
                        "reader needed an external rescue wake"
                    );
                    assert_eq!((writer_rc, reader_rc), (0, 0));
                }
            }
        },
    );
}
