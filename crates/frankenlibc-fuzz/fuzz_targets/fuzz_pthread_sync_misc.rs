#![no_main]
//! Fuzz target for FrankenLibC's remaining pthread sync primitives
//! (bd-dvr22 priority-7, completing the non-TSan pthread family):
//!
//!   pthread_barrier_init, pthread_barrier_destroy,
//!   pthread_barrier_wait,
//!   pthread_barrierattr_init, pthread_barrierattr_destroy,
//!   pthread_barrierattr_setpshared, pthread_barrierattr_getpshared,
//!   pthread_spin_init, pthread_spin_destroy,
//!   pthread_spin_lock, pthread_spin_trylock, pthread_spin_unlock,
//!   pthread_once
//!
//! Single-threaded per iteration — a TSan campaign is still the
//! right way to catch the interesting races; this target catches
//! the lifecycle / init / attr-round-trip / self-contained-contract
//! bugs that are true regardless of concurrency.
//!
//! Oracles:
//! - Return-code contract: rc >= 0 on every call.
//! - Barrier attr round-trip: setpshared → getpshared recovers
//!   the same value.
//! - Barrier with count=1: `pthread_barrier_wait` from the sole
//!   participant thread MUST return `PTHREAD_BARRIER_SERIAL_THREAD`
//!   (the serial-thread sentinel) — POSIX §2.9.4 says exactly one
//!   thread returns the serial value and all others return 0; with
//!   count=1, the single waiter is the serial thread.
//! - Spinlock: successive trylock from the same thread after lock
//!   must fail (single-thread exclusion) for a plain spinlock.
//! - Once: pthread_once(&flag, init_fn) runs init_fn exactly once
//!   across multiple calls; the hit counter must equal 1 after N
//!   pthread_once calls.
//!
//! Bead: bd-dvr22 priority-7 (pthread barrier/once/spin subset).

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::pthread_abi::{
    pthread_barrier_destroy, pthread_barrier_init, pthread_barrier_wait,
    pthread_barrierattr_destroy, pthread_barrierattr_getpshared, pthread_barrierattr_init,
    pthread_barrierattr_setpshared, pthread_once, pthread_spin_destroy, pthread_spin_init,
    pthread_spin_lock, pthread_spin_trylock, pthread_spin_unlock,
};
use libfuzzer_sys::fuzz_target;

const MAX_OPS: usize = 16;

static MISCLOCK: Mutex<()> = Mutex::new(());

/// Hit counter for pthread_once init routine.
static FUZZ_ONCE_HITS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn fuzz_once_init() {
    FUZZ_ONCE_HITS.fetch_add(1, Ordering::AcqRel);
}

#[derive(Debug, Arbitrary)]
enum Op {
    BarrierAttrRoundTripPshared { pshared: bool },
    BarrierSingleThreadCount1,
    SpinlockTryTwice { pshared: bool },
    PthreadOnceSingle,
    PthreadOnceRepeated { times: u8 },
}

#[derive(Debug, Arbitrary)]
struct PthreadMiscFuzzInput {
    ops: Vec<Op>,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: process mode set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn apply_barrier_attr_round_trip(pshared: bool) {
    let mut attr: std::mem::MaybeUninit<libc::pthread_barrierattr_t> =
        std::mem::MaybeUninit::zeroed();
    let rc_init = unsafe { pthread_barrierattr_init(attr.as_mut_ptr()) };
    assert_eq!(rc_init, 0, "pthread_barrierattr_init failed");
    let mut attr = unsafe { attr.assume_init() };

    let want = if pshared {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    };
    let rc_set = unsafe { pthread_barrierattr_setpshared(&mut attr, want) };
    if rc_set == 0 {
        let mut got: c_int = -1;
        let rc_get = unsafe { pthread_barrierattr_getpshared(&attr, &mut got) };
        assert_eq!(rc_get, 0);
        assert_eq!(got, want, "barrierattr pshared round-trip failed");
    }
    let rc_d = unsafe { pthread_barrierattr_destroy(&mut attr) };
    assert_eq!(rc_d, 0);
}

fn apply_barrier_single_thread_count1() {
    // A barrier with count=1 and a single waiter is the simplest
    // way to exercise the serial-thread-return-value invariant
    // without needing multi-thread coordination.
    let mut barrier: std::mem::MaybeUninit<libc::pthread_barrier_t> =
        std::mem::MaybeUninit::zeroed();
    let rc_init =
        unsafe { pthread_barrier_init(barrier.as_mut_ptr().cast::<c_void>(), std::ptr::null(), 1) };
    if rc_init != 0 {
        return;
    }
    let mut barrier = unsafe { barrier.assume_init() };
    let rc_wait = unsafe { pthread_barrier_wait(&mut barrier as *mut _ as *mut c_void) };
    assert_eq!(
        rc_wait,
        libc::PTHREAD_BARRIER_SERIAL_THREAD,
        "pthread_barrier_wait with count=1 must return PTHREAD_BARRIER_SERIAL_THREAD ({}), got {rc_wait}",
        libc::PTHREAD_BARRIER_SERIAL_THREAD
    );
    let rc_d = unsafe { pthread_barrier_destroy(&mut barrier as *mut _ as *mut c_void) };
    assert!(rc_d >= 0, "pthread_barrier_destroy rc {rc_d}");
}

fn apply_spinlock_try_twice(pshared: bool) {
    let mut lock: std::mem::MaybeUninit<libc::pthread_spinlock_t> =
        std::mem::MaybeUninit::zeroed();
    let pshared_v = if pshared {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    };
    let rc_init =
        unsafe { pthread_spin_init(lock.as_mut_ptr().cast::<c_void>(), pshared_v) };
    if rc_init != 0 {
        return;
    }
    let mut lock = unsafe { lock.assume_init() };
    let lock_ptr = &mut lock as *mut _ as *mut c_void;

    // First lock must succeed.
    let rc1 = unsafe { pthread_spin_lock(lock_ptr) };
    assert_eq!(rc1, 0, "pthread_spin_lock first-acquire rc {rc1}");

    // Second trylock from same thread must fail (EBUSY / EDEADLK).
    // Plain spinlocks don't support recursion.
    let rc2 = unsafe { pthread_spin_trylock(lock_ptr) };
    assert!(
        rc2 != 0,
        "pthread_spin_trylock on a lock already held by us should not succeed (got rc {rc2})"
    );

    let rc_u = unsafe { pthread_spin_unlock(lock_ptr) };
    assert_eq!(rc_u, 0, "pthread_spin_unlock rc {rc_u}");

    let rc_d = unsafe { pthread_spin_destroy(lock_ptr) };
    assert!(rc_d >= 0, "pthread_spin_destroy rc {rc_d}");
}

fn apply_pthread_once_single() {
    // Each op fires its own ONCE_INIT so the "init runs at most
    // once" invariant is per-op, not global to the fuzz process.
    let mut flag: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    let before = FUZZ_ONCE_HITS.load(Ordering::Acquire);
    let rc = unsafe { pthread_once(&mut flag, Some(fuzz_once_init)) };
    assert_eq!(rc, 0, "pthread_once rc {rc}");
    let after = FUZZ_ONCE_HITS.load(Ordering::Acquire);
    assert_eq!(
        after,
        before + 1,
        "pthread_once must invoke init_routine exactly once on fresh ONCE_INIT: before={before} after={after}"
    );
}

fn apply_pthread_once_repeated(times: u8) {
    // Build a fresh flag, then call pthread_once `times` additional
    // times. The init routine must fire exactly once regardless.
    let mut flag: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    let before = FUZZ_ONCE_HITS.load(Ordering::Acquire);
    let n = (times as usize % 5) + 1;
    for _ in 0..n {
        let rc = unsafe { pthread_once(&mut flag, Some(fuzz_once_init)) };
        assert_eq!(rc, 0, "pthread_once rc {rc}");
    }
    let after = FUZZ_ONCE_HITS.load(Ordering::Acquire);
    assert_eq!(
        after - before,
        1,
        "pthread_once: after {n} calls on the same flag, init must have fired exactly once: delta={}",
        after - before
    );
}

fn apply_op(op: &Op) {
    match op {
        Op::BarrierAttrRoundTripPshared { pshared } => apply_barrier_attr_round_trip(*pshared),
        Op::BarrierSingleThreadCount1 => apply_barrier_single_thread_count1(),
        Op::SpinlockTryTwice { pshared } => apply_spinlock_try_twice(*pshared),
        Op::PthreadOnceSingle => apply_pthread_once_single(),
        Op::PthreadOnceRepeated { times } => apply_pthread_once_repeated(*times),
    }
}

fuzz_target!(|input: PthreadMiscFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = MISCLOCK.lock().unwrap_or_else(|p| p.into_inner());

    for op in &input.ops {
        apply_op(op);
    }
});
