//! Explicit-clock waits select a kernel clock without rewriting condition state.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
use frankenlibc_abi::pthread_abi as p;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

unsafe extern "C" {
    #[link_name = "pthread_mutex_clocklock"]
    fn host_mutex_clocklock(
        mutex: *mut libc::pthread_mutex_t,
        clock: libc::clockid_t,
        deadline: *const libc::timespec,
    ) -> libc::c_int;
}

const MUTEX_CLOCKS: [Option<libc::clockid_t>; 3] = [
    None,
    Some(libc::CLOCK_REALTIME),
    Some(libc::CLOCK_MONOTONIC),
];
const ROBUST: u8 = 1;
const PI: u8 = 2;
const SHARED: u8 = 4;
type MutexOp = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> libc::c_int;

fn mutex_ops(native: bool) -> (MutexOp, MutexOp, MutexOp) {
    if native {
        (
            p::pthread_mutex_lock,
            p::pthread_mutex_unlock,
            p::pthread_mutex_destroy,
        )
    } else {
        (
            libc::pthread_mutex_lock,
            libc::pthread_mutex_unlock,
            libc::pthread_mutex_destroy,
        )
    }
}

fn mutex(native: bool, flags: u8) -> Box<libc::pthread_mutex_t> {
    mutex_with_type(native, flags, libc::PTHREAD_MUTEX_NORMAL)
}

fn mutex_with_type(native: bool, flags: u8, kind: libc::c_int) -> Box<libc::pthread_mutex_t> {
    type AttrOp = unsafe extern "C" fn(*mut libc::pthread_mutexattr_t) -> libc::c_int;
    type AttrSet = unsafe extern "C" fn(*mut libc::pthread_mutexattr_t, libc::c_int) -> libc::c_int;
    type Init = unsafe extern "C" fn(
        *mut libc::pthread_mutex_t,
        *const libc::pthread_mutexattr_t,
    ) -> libc::c_int;
    let (attr_init, attr_destroy, set_robust, set_protocol, set_shared, set_type, init): (
        AttrOp,
        AttrOp,
        AttrSet,
        AttrSet,
        AttrSet,
        AttrSet,
        Init,
    ) = if native {
        (
            p::pthread_mutexattr_init,
            p::pthread_mutexattr_destroy,
            p::pthread_mutexattr_setrobust,
            p::pthread_mutexattr_setprotocol,
            p::pthread_mutexattr_setpshared,
            p::pthread_mutexattr_settype,
            p::pthread_mutex_init,
        )
    } else {
        (
            libc::pthread_mutexattr_init,
            libc::pthread_mutexattr_destroy,
            libc::pthread_mutexattr_setrobust,
            libc::pthread_mutexattr_setprotocol,
            libc::pthread_mutexattr_setpshared,
            libc::pthread_mutexattr_settype,
            libc::pthread_mutex_init,
        )
    };
    // SAFETY: each provider initializes its own aligned attributes and mutex;
    // the box stays alive until all threads using its address have joined.
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        let mut mutex = Box::new(std::mem::zeroed());
        assert_eq!(attr_init(&mut attr), 0);
        assert_eq!(set_type(&mut attr, kind), 0);
        if flags & ROBUST != 0 {
            assert_eq!(set_robust(&mut attr, libc::PTHREAD_MUTEX_ROBUST), 0);
        }
        if flags & PI != 0 {
            assert_eq!(set_protocol(&mut attr, libc::PTHREAD_PRIO_INHERIT), 0);
        }
        if flags & SHARED != 0 {
            assert_eq!(set_shared(&mut attr, libc::PTHREAD_PROCESS_SHARED), 0);
        }
        assert_eq!(init(&mut *mutex, &attr), 0);
        assert_eq!(attr_destroy(&mut attr), 0);
        mutex
    }
}

unsafe fn mutex_wait(
    native: bool,
    clock: Option<libc::clockid_t>,
    mutex: *mut libc::pthread_mutex_t,
    deadline: &libc::timespec,
) -> libc::c_int {
    // SAFETY: callers retain initialized mutex storage throughout the wait.
    unsafe {
        match (native, clock) {
            (false, None) => libc::pthread_mutex_timedlock(mutex, deadline),
            (false, Some(clock)) => host_mutex_clocklock(mutex, clock, deadline),
            (true, None) => p::pthread_mutex_timedlock(mutex, deadline),
            (true, Some(clock)) => p::pthread_mutex_clocklock(mutex, clock, deadline),
        }
    }
}

fn isolated_mutex_deadline(name: &str, body: fn()) {
    if std::env::var_os("FL_MUTEX_CLOCK_CHILD").is_some() {
        body();
        return;
    }
    for mode in ["strict", "hardened"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_MUTEX_CLOCK_CHILD", "1")
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
fn mutex_deadlines_free_locks_accept_past_and_extreme_deadlines() {
    isolated_mutex_deadline(
        "mutex_deadlines_free_locks_accept_past_and_extreme_deadlines",
        || {
            for native in [false, true] {
                let (_, unlock, destroy) = mutex_ops(native);
                for flags in 0..8 {
                    let mut mutex = mutex(native, flags);
                    for clock in MUTEX_CLOCKS {
                        for seconds in [0, -1, i64::MIN, i64::MAX] {
                            let deadline = libc::timespec {
                                tv_sec: seconds,
                                tv_nsec: 999_999_999,
                            };
                            // SAFETY: this thread exclusively owns the mutex storage.
                            unsafe {
                                assert_eq!(
                                    mutex_wait(native, clock, &mut *mutex, &deadline),
                                    0,
                                    "native={native}, flags={flags}, clock={clock:?}, seconds={seconds}"
                                );
                                assert_eq!(unlock(&mut *mutex), 0);
                            }
                        }
                    }
                    assert_eq!(unsafe { destroy(&mut *mutex) }, 0);
                }
            }
        },
    );
}

#[test]
fn mutex_deadlines_expired_waiters_match_host_errors() {
    isolated_mutex_deadline("mutex_deadlines_expired_waiters_match_host_errors", || {
        for native in [false, true] {
            let (lock, unlock, destroy) = mutex_ops(native);
            for flags in 0..8 {
                let mut mutex = mutex(native, flags);
                let address = (&mut *mutex as *mut libc::pthread_mutex_t) as usize;
                // SAFETY: the owner retains storage until every waiter has joined.
                assert_eq!(unsafe { lock(&mut *mutex) }, 0);
                for clock in MUTEX_CLOCKS {
                    for seconds in [-1, i64::MIN] {
                        let worker = std::thread::spawn(move || {
                            let deadline = libc::timespec {
                                tv_sec: seconds,
                                tv_nsec: 999_999_999,
                            };
                            // SAFETY: the parent holds a live mutex throughout the call.
                            unsafe { mutex_wait(native, clock, address as *mut _, &deadline) }
                        });
                        assert_eq!(
                            worker.join().unwrap(),
                            if flags & PI != 0 {
                                libc::EINVAL
                            } else {
                                libc::ETIMEDOUT
                            },
                            "native={native}, flags={flags}, clock={clock:?}, seconds={seconds}"
                        );
                    }
                }
                // SAFETY: all waiters failed and joined; the parent still owns the mutex.
                unsafe {
                    assert_eq!(unlock(&mut *mutex), 0);
                    assert_eq!(destroy(&mut *mutex), 0);
                }
            }
        }
    });
}

#[test]
fn normal_pi_self_wait_honors_deadline_and_preserves_errno() {
    isolated_mutex_deadline(
        "normal_pi_self_wait_honors_deadline_and_preserves_errno",
        || {
            for native in [false, true] {
                let (lock, unlock, destroy) = mutex_ops(native);
                for flags in 0..8 {
                    let mut mutex = mutex(native, flags);
                    // SAFETY: this thread owns the initialized mutex for the entire test.
                    unsafe {
                        assert_eq!(lock(&mut *mutex), 0);
                        for clock in MUTEX_CLOCKS {
                            let clock_id = clock.unwrap_or(libc::CLOCK_REALTIME);
                            let mut deadline = std::mem::zeroed();
                            assert_eq!(libc::clock_gettime(clock_id, &mut deadline), 0);
                            deadline.tv_nsec += 5_000_000;
                            if deadline.tv_nsec >= 1_000_000_000 {
                                deadline.tv_sec += 1;
                                deadline.tv_nsec -= 1_000_000_000;
                            }
                            let errno = if native {
                                frankenlibc_abi::errno_abi::__errno_location()
                            } else {
                                libc::__errno_location()
                            };
                            *errno = libc::EDOM;
                            let status = mutex_wait(native, clock, &mut *mutex, &deadline);
                            let after = *errno;
                            assert_eq!(
                                (status, after),
                                (libc::ETIMEDOUT, libc::EDOM),
                                "native={native}, flags={flags}, clock={clock:?}"
                            );
                            let mut now = std::mem::zeroed();
                            assert_eq!(libc::clock_gettime(clock_id, &mut now), 0);
                            assert!(
                                (now.tv_sec, now.tv_nsec) >= (deadline.tv_sec, deadline.tv_nsec)
                            );
                        }
                        assert_eq!(unlock(&mut *mutex), 0);
                        assert_eq!(destroy(&mut *mutex), 0);
                    }
                }
            }
        },
    );
}

#[test]
fn mutex_deadlines_invalid_nanoseconds_are_not_normalized() {
    isolated_mutex_deadline(
        "mutex_deadlines_invalid_nanoseconds_are_not_normalized",
        || {
            for native in [false, true] {
                let (lock, unlock, destroy) = mutex_ops(native);
                for flags in 0..8 {
                    let mut mutex = mutex(native, flags);
                    let address = (&mut *mutex as *mut libc::pthread_mutex_t) as usize;
                    // SAFETY: storage outlives each waiter and only the parent owns the lock.
                    assert_eq!(unsafe { lock(&mut *mutex) }, 0);
                    for clock in MUTEX_CLOCKS {
                        for nanos in [-1, 1_000_000_000, i64::MIN, i64::MAX] {
                            let worker = std::thread::spawn(move || {
                                let deadline = libc::timespec {
                                    tv_sec: 0,
                                    tv_nsec: nanos,
                                };
                                // SAFETY: initialized mutex and readable timespec remain live.
                                unsafe { mutex_wait(native, clock, address as *mut _, &deadline) }
                            });
                            assert_eq!(
                                worker.join().unwrap(),
                                libc::EINVAL,
                                "native={native}, flags={flags}, clock={clock:?}, nanos={nanos}"
                            );
                        }
                    }
                    // SAFETY: no wait succeeded; all threads have joined.
                    unsafe {
                        assert_eq!(unlock(&mut *mutex), 0);
                        assert_eq!(destroy(&mut *mutex), 0);
                    }
                }
            }
        },
    );
}

fn extreme_mutex_handoff(clocks: &[Option<libc::clockid_t>]) {
    for native in [false, true] {
        let (lock, unlock, destroy) = mutex_ops(native);
        for flags in 0..8 {
            let mut mutex = mutex(native, flags);
            let address = (&mut *mutex as *mut libc::pthread_mutex_t) as usize;
            for &clock in clocks {
                // SAFETY: all workers join before the owning box is destroyed.
                assert_eq!(unsafe { lock(&mut *mutex) }, 0);
                let (ready_tx, ready_rx) = mpsc::channel();
                let (result_tx, result_rx) = mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let deadline = libc::timespec {
                        tv_sec: i64::MAX,
                        tv_nsec: 999_999_999,
                    };
                    ready_tx.send(()).unwrap();
                    // SAFETY: the parent retains storage until this thread joins.
                    let result = unsafe { mutex_wait(native, clock, address as *mut _, &deadline) };
                    if result == 0 {
                        // SAFETY: this thread acquired the mutex above.
                        assert_eq!(unsafe { unlock(address as *mut _) }, 0);
                    }
                    result_tx.send(result).unwrap();
                });
                ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                assert_eq!(
                    result_rx.recv_timeout(Duration::from_millis(20)),
                    Err(mpsc::RecvTimeoutError::Timeout),
                    "wait must remain pending: native={native}, flags={flags}, clock={clock:?}"
                );
                // SAFETY: the parent still owns the lock, then hands it to the waiter.
                assert_eq!(unsafe { unlock(&mut *mutex) }, 0);
                assert_eq!(
                    result_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                    0,
                    "native={native}, flags={flags}, clock={clock:?}"
                );
                worker.join().unwrap();
            }
            assert_eq!(unsafe { destroy(&mut *mutex) }, 0);
        }
    }
}

#[test]
fn mutex_deadlines_realtime_extremes_preserve_contended_handoff() {
    isolated_mutex_deadline(
        "mutex_deadlines_realtime_extremes_preserve_contended_handoff",
        || extreme_mutex_handoff(&[None, Some(libc::CLOCK_REALTIME)]),
    );
}

#[test]
fn mutex_deadlines_monotonic_extremes_preserve_contended_handoff() {
    isolated_mutex_deadline(
        "mutex_deadlines_monotonic_extremes_preserve_contended_handoff",
        || extreme_mutex_handoff(&[Some(libc::CLOCK_MONOTONIC)]),
    );
}

#[test]
fn mutex_deadline_ordering_free_invalid_nanoseconds() {
    isolated_mutex_deadline("mutex_deadline_ordering_free_invalid_nanoseconds", || {
        for native in [false, true] {
            let (_, unlock, destroy) = mutex_ops(native);
            for flags in 0..8 {
                let mut mutex = mutex(native, flags);
                for clock in MUTEX_CLOCKS {
                    for nanos in [-1, 1_000_000_000, i64::MIN, i64::MAX] {
                        let deadline = libc::timespec {
                            tv_sec: 100,
                            tv_nsec: nanos,
                        };
                        // SAFETY: storage is initialized and no other thread uses it.
                        unsafe {
                            assert_eq!(
                                mutex_wait(native, clock, &mut *mutex, &deadline),
                                0,
                                "native={native}, flags={flags}, clock={clock:?}, nanos={nanos}"
                            );
                            assert_eq!(unlock(&mut *mutex), 0);
                        }
                    }
                }
                assert_eq!(unsafe { destroy(&mut *mutex) }, 0);
            }
        }
    });
}

const ORDERING_DEADLINES: [libc::timespec; 4] = [
    libc::timespec {
        tv_sec: 100,
        tv_nsec: -1,
    },
    libc::timespec {
        tv_sec: 100,
        tv_nsec: 1_000_000_000,
    },
    libc::timespec {
        tv_sec: -1,
        tv_nsec: 0,
    },
    libc::timespec {
        tv_sec: i64::MIN,
        tv_nsec: 0,
    },
];

#[test]
fn mutex_deadline_ordering_self_owned_locks() {
    isolated_mutex_deadline("mutex_deadline_ordering_self_owned_locks", || {
        for native in [false, true] {
            let (lock, unlock, destroy) = mutex_ops(native);
            for flags in 0..8 {
                for kind in [
                    libc::PTHREAD_MUTEX_ERRORCHECK,
                    libc::PTHREAD_MUTEX_RECURSIVE,
                ] {
                    let mut mutex = mutex_with_type(native, flags, kind);
                    // SAFETY: only this thread owns and accesses the live mutex.
                    assert_eq!(unsafe { lock(&mut *mutex) }, 0);
                    for clock in MUTEX_CLOCKS {
                        for deadline in ORDERING_DEADLINES {
                            let expected = if kind == libc::PTHREAD_MUTEX_RECURSIVE {
                                0
                            } else {
                                libc::EDEADLK
                            };
                            // SAFETY: same-owner relocking is defined for both tested kinds.
                            let result =
                                unsafe { mutex_wait(native, clock, &mut *mutex, &deadline) };
                            assert_eq!(
                                result, expected,
                                "native={native}, flags={flags}, kind={kind}, clock={clock:?}, \
                                 seconds={}, nanos={}",
                                deadline.tv_sec, deadline.tv_nsec
                            );
                            if result == 0 {
                                // SAFETY: remove only the recursive acquisition just made.
                                assert_eq!(unsafe { unlock(&mut *mutex) }, 0);
                            }
                        }
                    }
                    // SAFETY: release the original ownership before destroying the mutex.
                    unsafe {
                        assert_eq!(unlock(&mut *mutex), 0);
                        assert_eq!(destroy(&mut *mutex), 0);
                    }
                }
            }
        }
    });
}

fn abandon_robust_mutex(native: bool, mutex: &mut libc::pthread_mutex_t) {
    let (lock, _, _) = mutex_ops(native);
    let address = mutex as *mut libc::pthread_mutex_t as usize;
    let worker = std::thread::spawn(move || {
        // SAFETY: the parent retains the initialized robust mutex until this
        // thread exits; leaving it locked deliberately exercises owner death.
        unsafe { lock(address as *mut _) }
    });
    assert_eq!(worker.join().unwrap(), 0);
}

#[test]
fn mutex_deadline_ordering_robust_recovery_and_poison() {
    isolated_mutex_deadline("mutex_deadline_ordering_robust_recovery_and_poison", || {
        for native in [false, true] {
            let (lock, unlock, destroy) = mutex_ops(native);
            let consistent: MutexOp = if native {
                p::pthread_mutex_consistent
            } else {
                libc::pthread_mutex_consistent
            };
            for flags in [ROBUST, ROBUST | PI, ROBUST | SHARED, ROBUST | PI | SHARED] {
                for clock in MUTEX_CLOCKS {
                    for deadline in ORDERING_DEADLINES {
                        for poisoned in [false, true] {
                            let mut mutex = mutex(native, flags);
                            abandon_robust_mutex(native, &mut mutex);
                            // SAFETY: the former owner has joined; this thread retains storage.
                            unsafe {
                                if poisoned {
                                    assert_eq!(lock(&mut *mutex), libc::EOWNERDEAD);
                                    // Unlocking without consistent makes the state unrecoverable.
                                    assert_eq!(unlock(&mut *mutex), 0);
                                }
                                let result = mutex_wait(native, clock, &mut *mutex, &deadline);
                                let expected = if poisoned {
                                    libc::ENOTRECOVERABLE
                                } else if flags & PI != 0 {
                                    libc::EINVAL
                                } else {
                                    libc::EOWNERDEAD
                                };
                                assert_eq!(
                                    result, expected,
                                    "native={native}, flags={flags}, clock={clock:?}, \
                                     poisoned={poisoned}, seconds={}, nanos={}",
                                    deadline.tv_sec, deadline.tv_nsec
                                );
                                if !poisoned {
                                    if result == libc::EINVAL {
                                        // A rejected PI deadline must leave recovery to this lock.
                                        assert_eq!(lock(&mut *mutex), libc::EOWNERDEAD);
                                    }
                                    assert_eq!(consistent(&mut *mutex), 0);
                                    assert_eq!(unlock(&mut *mutex), 0);
                                }
                                assert_eq!(destroy(&mut *mutex), 0);
                            }
                        }
                    }
                }
            }
        }
    });
}

#[test]
fn expired_cross_clock_deadlines_are_timeouts_with_the_mutex_reacquired() {
    for configured in [libc::CLOCK_REALTIME, libc::CLOCK_MONOTONIC] {
        for requested in [libc::CLOCK_REALTIME, libc::CLOCK_MONOTONIC] {
            for seconds in [0, -1, i64::MIN] {
                // SAFETY: caller-owned aligned storage is initialized before use;
                // no pointer escapes and every held mutex is unlocked on return.
                unsafe {
                    let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
                    let mut cond: libc::pthread_cond_t = std::mem::zeroed();
                    let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
                    assert_eq!(p::pthread_condattr_init(&mut attr), 0);
                    assert_eq!(p::pthread_condattr_setclock(&mut attr, configured), 0);
                    assert_eq!(p::pthread_cond_init(&mut cond, &attr), 0);
                    assert_eq!(p::pthread_condattr_destroy(&mut attr), 0);
                    assert_eq!(p::pthread_mutex_init(&mut mutex, std::ptr::null()), 0);
                    assert_eq!(p::pthread_mutex_lock(&mut mutex), 0);
                    let deadline = libc::timespec {
                        tv_sec: seconds,
                        tv_nsec: 0,
                    };
                    let result =
                        p::pthread_cond_clockwait(&mut cond, &mut mutex, requested, &deadline);
                    let ownership = p::pthread_mutex_trylock(&mut mutex);
                    assert_eq!(p::pthread_mutex_unlock(&mut mutex), 0);
                    assert_eq!(p::pthread_cond_destroy(&mut cond), 0);
                    assert_eq!(p::pthread_mutex_destroy(&mut mutex), 0);
                    assert_eq!(
                        result,
                        libc::ETIMEDOUT,
                        "configured={configured}, requested={requested}, seconds={seconds}"
                    );
                    assert_eq!(ownership, libc::EBUSY, "wait must return holding the mutex");
                }
            }
        }
    }
}

#[test]
fn invalid_clock_and_nanoseconds_leave_owned_mutex_state_untouched() {
    // SAFETY: initialized local POSIX storage with no concurrent access.
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(p::pthread_cond_init(&mut cond, std::ptr::null()), 0);
        assert_eq!(p::pthread_mutex_init(&mut mutex, std::ptr::null()), 0);
        assert_eq!(p::pthread_mutex_lock(&mut mutex), 0);
        for (clock, nanos) in [
            (libc::CLOCK_BOOTTIME, 0),
            (libc::CLOCK_REALTIME, -1),
            (libc::CLOCK_MONOTONIC, 1_000_000_000),
        ] {
            let deadline = libc::timespec {
                tv_sec: 0,
                tv_nsec: nanos,
            };
            assert_eq!(
                p::pthread_cond_clockwait(&mut cond, &mut mutex, clock, &deadline),
                libc::EINVAL
            );
            assert_eq!(p::pthread_mutex_trylock(&mut mutex), libc::EBUSY);
        }
        assert_eq!(p::pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(p::pthread_cond_destroy(&mut cond), 0);
        assert_eq!(p::pthread_mutex_destroy(&mut mutex), 0);
    }
}
