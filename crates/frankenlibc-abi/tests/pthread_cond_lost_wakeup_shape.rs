#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // drives the real fl pthread ABI with real condvar/mutex objects

//! The conformance `pthread_cond` arms synchronise with `sleep()`, and that shape
//! can lose a wakeup and block forever (bd-j05zw5).
//!
//! `execute_pthread_cond_wait_case`'s `predicate_loop` arm runs:
//!
//! ```text
//! notifier: sleep 20ms; cond_signal(); sleep 20ms; predicate.store(1); cond_signal();
//! main:     lock(mutex); while predicate.load() == 0 { cond_wait(cond, mutex); }
//! ```
//!
//! The predicate is written and both signals are sent WITHOUT holding the mutex,
//! so nothing orders "main reads the predicate" against "notifier sets it and
//! signals". If the notifier's second `store` + `signal` land after main has read
//! the predicate as 0 but before main is parked, POSIX says the signal is a no-op
//! -- there is no waiter yet -- and main then blocks on a condvar nobody will ever
//! signal again. The only thing making that rare is the 20ms sleeps, which is why
//! it showed up under host load and not in 600 unloaded runs.
//!
//! These gates force the interleaving instead of racing for it, so the defect is
//! deterministic rather than a 1-in-N. Each runs the shape on a worker thread and
//! fails on a bounded timeout, so a regression REPORTS rather than wedging the
//! suite -- which is the whole complaint bd-u2daxd filed against hangs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use frankenlibc_abi::pthread_abi as fl;

const WATCHDOG: Duration = Duration::from_secs(10);

/// Boxed so the object has a stable address for the lifetime of the test.
fn new_mutex() -> Box<libc::pthread_mutex_t> {
    let mut m: Box<libc::pthread_mutex_t> = Box::new(unsafe { std::mem::zeroed() });
    assert_eq!(
        unsafe { fl::pthread_mutex_init(&mut *m, std::ptr::null()) },
        0,
        "mutex init"
    );
    m
}

fn new_cond() -> Box<libc::pthread_cond_t> {
    let mut c: Box<libc::pthread_cond_t> = Box::new(unsafe { std::mem::zeroed() });
    assert_eq!(
        unsafe { fl::pthread_cond_init(&mut *c, std::ptr::null()) },
        0,
        "cond init"
    );
    c
}

/// Run `body` on a worker thread and fail if it does not finish inside
/// `WATCHDOG`. A lost wakeup blocks forever, so without this the "failure" is an
/// unkillable test binary rather than a red line.
fn with_watchdog(name: &str, body: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    // Deliberately DETACHED, not joined: the whole point is that `body` may block
    // forever on a lost wakeup, and joining it would reintroduce exactly the hang
    // this gate exists to convert into a reported failure.
    std::thread::spawn(move || {
        body();
        let _ = tx.send(());
    });
    if rx.recv_timeout(WATCHDOG).is_err() {
        panic!(
            "{name}: blocked for more than {:?} — a condvar wakeup was lost. The \
             notifier must publish the predicate and signal while HOLDING the \
             mutex, so the signal cannot land between the waiter's predicate read \
             and its park.",
            WATCHDOG
        );
    }
}

/// THE NEGATIVE CASE, forced rather than raced.
///
/// The waiter announces it is about to wait, then deliberately delays before
/// calling `pthread_cond_wait`. The notifier publishes the predicate and signals
/// inside that window. Any implementation of this shape that signals WITHOUT the
/// mutex loses the wakeup every time; holding the mutex makes the window
/// unreachable, because the waiter owns the mutex from its predicate read until
/// `pthread_cond_wait` has atomically released it.
#[test]
fn predicate_published_under_the_mutex_survives_a_signal_before_the_park() {
    with_watchdog("predicate_under_mutex", || {
        let mut mutex = new_mutex();
        let mut cond = new_cond();
        let mptr: *mut libc::pthread_mutex_t = &mut *mutex;
        let cptr: *mut libc::pthread_cond_t = &mut *cond;
        let (maddr, caddr) = (mptr as usize, cptr as usize);

        let predicate = Arc::new(AtomicU32::new(0));
        let about_to_wait = Arc::new(AtomicU32::new(0));

        let pred_n = Arc::clone(&predicate);
        let atw_n = Arc::clone(&about_to_wait);
        let notifier = std::thread::spawn(move || {
            let m = maddr as *mut libc::pthread_mutex_t;
            let c = caddr as *mut libc::pthread_cond_t;
            while atw_n.load(Ordering::Acquire) == 0 {
                std::hint::spin_loop();
            }
            // THE FIX under test: take the mutex before publishing + signalling.
            // The waiter cannot be between its predicate read and its park while
            // we hold this, so the signal cannot be lost.
            assert_eq!(unsafe { fl::pthread_mutex_lock(m) }, 0, "notifier lock");
            pred_n.store(1, Ordering::Release);
            let rc = unsafe { fl::pthread_cond_broadcast(c) };
            assert_eq!(unsafe { fl::pthread_mutex_unlock(m) }, 0, "notifier unlock");
            rc
        });

        assert_eq!(unsafe { fl::pthread_mutex_lock(mptr) }, 0, "waiter lock");
        while predicate.load(Ordering::Acquire) == 0 {
            // Announce, then stall, so the notifier gets every chance to signal
            // before we are parked. Holding the mutex is what makes that safe.
            about_to_wait.store(1, Ordering::Release);
            std::thread::sleep(Duration::from_millis(50));
            let rc = unsafe { fl::pthread_cond_wait(cptr, mptr) };
            assert_eq!(rc, 0, "pthread_cond_wait should succeed");
        }
        assert_eq!(
            unsafe { fl::pthread_mutex_unlock(mptr) },
            0,
            "waiter unlock"
        );

        let notify_rc = notifier.join().expect("notifier panicked");
        assert_eq!(notify_rc, 0, "broadcast should succeed");
        assert_eq!(predicate.load(Ordering::Acquire), 1, "predicate published");

        unsafe {
            fl::pthread_cond_destroy(cptr);
            fl::pthread_mutex_destroy(mptr);
        }
    });
}

/// fl's own contract, independent of the arms: a signal sent while no thread is
/// waiting is a no-op, so a waiter that parks afterwards is NOT woken by it.
///
/// This is the POSIX behaviour the arms were relying on NOT happening. Asserting
/// it here means the next person who reads "the notifier signals first, so the
/// waiter must wake" has a test telling them otherwise. `pthread_cond_timedwait`
/// bounds the wait so this documents the semantics without risking a hang.
#[test]
fn a_signal_with_no_waiter_is_not_delivered_to_a_later_waiter() {
    with_watchdog("signal_before_wait_is_lost", || {
        let mut mutex = new_mutex();
        let mut cond = new_cond();
        let mptr: *mut libc::pthread_mutex_t = &mut *mutex;
        let cptr: *mut libc::pthread_cond_t = &mut *cond;

        // No waiter exists yet.
        assert_eq!(unsafe { fl::pthread_cond_signal(cptr) }, 0, "signal");
        assert_eq!(unsafe { fl::pthread_cond_broadcast(cptr) }, 0, "broadcast");

        assert_eq!(unsafe { fl::pthread_mutex_lock(mptr) }, 0, "lock");
        let mut abstime: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut abstime) },
            0
        );
        abstime.tv_sec += 1;
        let rc = unsafe { fl::pthread_cond_timedwait(cptr, mptr, &abstime) };
        assert_eq!(
            rc,
            libc::ETIMEDOUT,
            "a signal sent before any thread waited must NOT wake the later \
             waiter; it must time out. If this ever returns 0, the arms' \
             sleep-based ordering would be safe and this gate can go."
        );
        assert_eq!(unsafe { fl::pthread_mutex_unlock(mptr) }, 0, "unlock");

        unsafe {
            fl::pthread_cond_destroy(cptr);
            fl::pthread_mutex_destroy(mptr);
        }
    });
}
