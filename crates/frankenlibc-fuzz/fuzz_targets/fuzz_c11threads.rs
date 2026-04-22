#![no_main]
//! Fuzz target for FrankenLibC's C11 threads surface
//! (bd-dvr22 priority-8 — the last non-TSan item in the drain):
//!
//!   mtx_init, mtx_destroy, mtx_lock, mtx_trylock,
//!   mtx_timedlock, mtx_unlock,
//!   cnd_init, cnd_destroy, cnd_signal, cnd_broadcast,
//!   cnd_timedwait,
//!   tss_create, tss_set, tss_delete,
//!   call_once,
//!   thrd_create, thrd_join, thrd_detach, thrd_sleep
//!
//! C11 threads aliases onto pthread types (ThrdT = pthread_t,
//! MtxT = pthread_mutex_t, etc.), so bugs here are often bugs in
//! the pthread backend surfaced through a different name. This
//! target is single-threaded per iteration and focuses on:
//!
//! - Return-code contract (thrd_success / thrd_error / thrd_busy
//!   / thrd_nomem / thrd_timedout — all are small non-negative ints).
//! - Mutex + condvar lifecycle (init / destroy / reuse).
//! - call_once exactly-once invariant.
//! - thrd_create + thrd_join round-trip with a trivial worker.
//! - thrd_sleep with a very short duration (< 1 ms).
//!
//! Safety:
//! - mtx_destroy / cnd_destroy / tss_delete return () in this ABI,
//!   not c_int — the harness treats them as side-effect only.
//! - thrd_exit is `-> !` and would terminate the fuzz process —
//!   deliberately NOT exercised here.
//! - Global C11LOCK serializes iterations.
//!
//! Bead: bd-dvr22 priority-8 (c11threads subset).

use std::ffi::{c_int, c_void};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::c11threads_abi::{
    call_once, cnd_broadcast, cnd_destroy, cnd_init, cnd_signal, cnd_timedwait, mtx_destroy,
    mtx_init, mtx_lock, mtx_timedlock, mtx_trylock, mtx_unlock, thrd_create, thrd_detach,
    thrd_join, thrd_sleep, tss_create, tss_delete, tss_set,
};
use libfuzzer_sys::fuzz_target;

const MAX_OPS: usize = 16;

static C11LOCK: Mutex<()> = Mutex::new(());
static FUZZ_CALL_ONCE_HITS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn fuzz_call_once_init() {
    FUZZ_CALL_ONCE_HITS.fetch_add(1, Ordering::AcqRel);
}

// A minimal no-op worker for thrd_create.
extern "C" fn fuzz_thrd_worker(_arg: *mut c_void) -> c_int {
    // mthreads.rs contract: returning from the top frame ends the
    // thread normally with the returned status.
    0
}

#[derive(Debug, Arbitrary)]
enum Op {
    MtxRoundTripPlain,
    MtxRoundTripTimedShort,
    CndRoundTrip,
    CndBroadcastNoWaiter,
    CndTimedwaitShort,
    TssCreateSetDelete { value_sel: u8 },
    CallOnceExactlyOnce { times: u8 },
    ThrdCreateJoinRoundTrip,
    ThrdCreateDetach,
    ThrdSleepShort,
}

#[derive(Debug, Arbitrary)]
struct C11FuzzInput {
    ops: Vec<Op>,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode is set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn short_abstime() -> libc::timespec {
    let mut now: libc::timespec = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    libc::timespec {
        tv_sec: now.tv_sec,
        tv_nsec: (now.tv_nsec + 1_000).min(999_999_999),
    }
}

fn apply_mtx_round_trip_plain() {
    let mut mtx: MaybeUninit<libc::pthread_mutex_t> = MaybeUninit::zeroed();
    // C11 mtx_plain is 0 per POSIX convention; our impl uses a small
    // enum so anything reasonable works.
    let rc_i = unsafe { mtx_init(mtx.as_mut_ptr(), 0) };
    if rc_i != 0 {
        return;
    }
    let mut mtx = unsafe { mtx.assume_init() };
    let rc_l = unsafe { mtx_lock(&mut mtx) };
    assert!(rc_l >= 0, "mtx_lock rc {rc_l}");
    if rc_l == 0 {
        let rc_u = unsafe { mtx_unlock(&mut mtx) };
        assert!(rc_u >= 0, "mtx_unlock rc {rc_u}");
    }
    unsafe { mtx_destroy(&mut mtx) };
}

fn apply_mtx_round_trip_timed_short() {
    let mut mtx: MaybeUninit<libc::pthread_mutex_t> = MaybeUninit::zeroed();
    let rc_i = unsafe { mtx_init(mtx.as_mut_ptr(), 0) };
    if rc_i != 0 {
        return;
    }
    let mut mtx = unsafe { mtx.assume_init() };
    let rc_t = unsafe { mtx_trylock(&mut mtx) };
    assert!(rc_t >= 0, "mtx_trylock rc {rc_t}");
    if rc_t == 0 {
        unsafe { mtx_unlock(&mut mtx) };
    }
    let abs = short_abstime();
    let rc_tl = unsafe { mtx_timedlock(&mut mtx, &abs) };
    assert!(rc_tl >= 0, "mtx_timedlock rc {rc_tl}");
    if rc_tl == 0 {
        unsafe { mtx_unlock(&mut mtx) };
    }
    unsafe { mtx_destroy(&mut mtx) };
}

fn apply_cnd_round_trip() {
    let mut cond: MaybeUninit<libc::pthread_cond_t> = MaybeUninit::zeroed();
    let rc = unsafe { cnd_init(cond.as_mut_ptr()) };
    if rc != 0 {
        return;
    }
    let mut cond = unsafe { cond.assume_init() };
    // Signal / broadcast on a condvar with no waiter is a no-op.
    let rc_s = unsafe { cnd_signal(&mut cond) };
    assert!(rc_s >= 0, "cnd_signal rc {rc_s}");
    let rc_b = unsafe { cnd_broadcast(&mut cond) };
    assert!(rc_b >= 0, "cnd_broadcast rc {rc_b}");
    unsafe { cnd_destroy(&mut cond) };
}

fn apply_cnd_broadcast_no_waiter() {
    apply_cnd_round_trip()
}

fn apply_cnd_timedwait_short() {
    let mut cond: MaybeUninit<libc::pthread_cond_t> = MaybeUninit::zeroed();
    if unsafe { cnd_init(cond.as_mut_ptr()) } != 0 {
        return;
    }
    let mut cond = unsafe { cond.assume_init() };
    let mut mtx: MaybeUninit<libc::pthread_mutex_t> = MaybeUninit::zeroed();
    if unsafe { mtx_init(mtx.as_mut_ptr(), 0) } != 0 {
        unsafe { cnd_destroy(&mut cond) };
        return;
    }
    let mut mtx = unsafe { mtx.assume_init() };
    let rc_l = unsafe { mtx_lock(&mut mtx) };
    if rc_l != 0 {
        unsafe {
            cnd_destroy(&mut cond);
            mtx_destroy(&mut mtx);
        }
        return;
    }
    let abs = short_abstime();
    let rc = unsafe { cnd_timedwait(&mut cond, &mut mtx, &abs) };
    // Expect 0 (spurious wake) or thrd_timedout — both non-negative.
    assert!(rc >= 0, "cnd_timedwait rc {rc}");
    let _ = unsafe { mtx_unlock(&mut mtx) };
    unsafe {
        cnd_destroy(&mut cond);
        mtx_destroy(&mut mtx);
    }
}

fn apply_tss_create_set_delete(value_sel: u8) {
    let mut key: libc::pthread_key_t = 0;
    let rc_c = unsafe { tss_create(&mut key, None) };
    if rc_c != 0 {
        return;
    }
    let val = ((value_sel as usize) * 8 + 0x1000) as *mut c_void;
    let rc_s = unsafe { tss_set(key, val) };
    assert!(rc_s >= 0, "tss_set rc {rc_s}");
    // tss_delete returns void; just call and ensure no crash.
    unsafe { tss_delete(key) };
}

fn apply_call_once_exactly_once(times: u8) {
    let mut flag: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    let before = FUZZ_CALL_ONCE_HITS.load(Ordering::Acquire);
    let n = (times as usize % 5) + 1;
    for _ in 0..n {
        unsafe {
            call_once(&mut flag, Some(fuzz_call_once_init));
        }
    }
    let after = FUZZ_CALL_ONCE_HITS.load(Ordering::Acquire);
    assert_eq!(
        after - before,
        1,
        "call_once init must fire exactly once after {n} invocations on the same flag"
    );
}

fn apply_thrd_create_join_round_trip() {
    let mut thr: libc::pthread_t = 0;
    let rc_c = unsafe {
        thrd_create(
            &mut thr,
            Some(fuzz_thrd_worker),
            std::ptr::null_mut(),
        )
    };
    if rc_c != 0 {
        return;
    }
    let mut res: c_int = -1;
    let rc_j = unsafe { thrd_join(thr, &mut res) };
    assert!(rc_j >= 0, "thrd_join rc {rc_j}");
    if rc_j == 0 {
        assert_eq!(res, 0, "fuzz_thrd_worker returns 0");
    }
}

fn apply_thrd_create_detach() {
    let mut thr: libc::pthread_t = 0;
    let rc_c = unsafe {
        thrd_create(
            &mut thr,
            Some(fuzz_thrd_worker),
            std::ptr::null_mut(),
        )
    };
    if rc_c != 0 {
        return;
    }
    let rc_d = unsafe { thrd_detach(thr) };
    assert!(rc_d >= 0, "thrd_detach rc {rc_d}");
    // Give the detached thread a tiny window to exit; we can't
    // pthread_join it, but we don't need to — this path is about
    // asserting detach doesn't crash, not waiting for completion.
}

fn apply_thrd_sleep_short() {
    let d = libc::timespec { tv_sec: 0, tv_nsec: 1_000 }; // 1 µs
    let rc = unsafe { thrd_sleep(&d, std::ptr::null_mut()) };
    // 0 on full sleep, >0 on interrupt. Never negative.
    assert!(rc >= 0, "thrd_sleep rc {rc}");
}

fn apply_op(op: &Op) {
    match op {
        Op::MtxRoundTripPlain => apply_mtx_round_trip_plain(),
        Op::MtxRoundTripTimedShort => apply_mtx_round_trip_timed_short(),
        Op::CndRoundTrip => apply_cnd_round_trip(),
        Op::CndBroadcastNoWaiter => apply_cnd_broadcast_no_waiter(),
        Op::CndTimedwaitShort => apply_cnd_timedwait_short(),
        Op::TssCreateSetDelete { value_sel } => apply_tss_create_set_delete(*value_sel),
        Op::CallOnceExactlyOnce { times } => apply_call_once_exactly_once(*times),
        Op::ThrdCreateJoinRoundTrip => apply_thrd_create_join_round_trip(),
        Op::ThrdCreateDetach => apply_thrd_create_detach(),
        Op::ThrdSleepShort => apply_thrd_sleep_short(),
    }
}

fuzz_target!(|input: C11FuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = C11LOCK.lock().unwrap_or_else(|p| p.into_inner());

    for op in &input.ops {
        apply_op(op);
    }
});
