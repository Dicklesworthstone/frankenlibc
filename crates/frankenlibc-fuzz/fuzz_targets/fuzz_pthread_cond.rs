#![no_main]
//! Stateful fuzz target for FrankenLibC's pthread condvar surface
//! (bd-dvr22 priority-7 subset, paired with fuzz_pthread_mutex):
//!
//!   pthread_cond_init, pthread_cond_destroy,
//!   pthread_cond_signal, pthread_cond_broadcast,
//!   pthread_cond_timedwait, pthread_cond_clockwait,
//!   pthread_condattr_init, pthread_condattr_destroy,
//!   pthread_condattr_setclock, pthread_condattr_getclock,
//!   pthread_condattr_setpshared, pthread_condattr_getpshared
//!
//! Single-threaded per iteration — exercises the condvar lifecycle,
//! attribute round-trip, and signal-without-waiter no-op contract.
//! A TSan campaign for true wait/signal races is tracked separately
//! under the bd-dvr22 pthread-TSan follow-up.
//!
//! Both condattrs are initialized through OUR
//! frankenlibc_abi::pthread_abi::pthread_condattr_init so we don't
//! tripwire bd-6kwnr (where host-initialized condattrs were being
//! rejected by our cond_init). When bd-6kwnr's fix is verified, a
//! future variant of this harness can deliberately mix the host and
//! ours — for now we stay on the internally-consistent path.
//!
//! Bead: bd-dvr22 priority-7 (pthread cond subset)

use std::ffi::c_int;
use std::mem::MaybeUninit;
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::pthread_abi::{
    pthread_cond_broadcast, pthread_cond_destroy, pthread_cond_init, pthread_cond_signal,
    pthread_cond_timedwait, pthread_condattr_destroy, pthread_condattr_getclock,
    pthread_condattr_getpshared, pthread_condattr_init, pthread_condattr_setclock,
    pthread_condattr_setpshared, pthread_mutex_destroy, pthread_mutex_init, pthread_mutex_lock,
    pthread_mutex_unlock,
};
use libfuzzer_sys::fuzz_target;

const MAX_CONDS: usize = 4;
const MAX_OPS: usize = 16;

static CONDLOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Arbitrary)]
enum Op {
    AttrRoundTripClock { clock_sel: u8 },
    AttrRoundTripPshared { pshared: bool },
    InitDefault,
    InitWithAttr { clock_sel: u8, pshared: bool },
    Destroy { slot: u8 },
    Signal { slot: u8 },
    Broadcast { slot: u8 },
    TimedwaitShortTimeout { slot: u8, nsec_offset: u32 },
    MarkStale { slot: u8 },
}

#[derive(Debug, Arbitrary)]
struct PthreadCondFuzzInput {
    ops: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Live,
    Stale,
}

struct CondSlot {
    cond: Box<libc::pthread_cond_t>,
    mutex: Box<libc::pthread_mutex_t>,
    state: State,
    /// Clock the cond was attached to via condattr_setclock at
    /// init time. TimedwaitShortTimeout must build the absolute
    /// deadline against THIS clock, not whatever
    /// CLOCK_REALTIME-by-default the harness initially used.
    /// Otherwise a CLOCK_MONOTONIC cond gets a CLOCK_REALTIME
    /// abstime far in the future and timedwait blocks for
    /// decades — manifests as a libFuzzer "timeout" report.
    clock: libc::clockid_t,
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

fn pick_clock(sel: u8) -> libc::clockid_t {
    match sel & 1 {
        0 => libc::CLOCK_REALTIME,
        _ => libc::CLOCK_MONOTONIC,
    }
}

fn new_cond_slot() -> CondSlot {
    let cond: Box<libc::pthread_cond_t> = unsafe { Box::new(MaybeUninit::zeroed().assume_init()) };
    let mutex: Box<libc::pthread_mutex_t> =
        unsafe { Box::new(MaybeUninit::zeroed().assume_init()) };
    CondSlot {
        cond,
        mutex,
        state: State::Live,
        clock: libc::CLOCK_REALTIME,
    }
}

fn pick_slot(table: &mut [CondSlot], slot: u8) -> Option<&mut CondSlot> {
    if table.is_empty() {
        return None;
    }
    let idx = (slot as usize) % table.len();
    Some(&mut table[idx])
}

fn apply_attr_clock(clock_sel: u8) {
    let mut attr: MaybeUninit<libc::pthread_condattr_t> = MaybeUninit::zeroed();
    let rc_init = unsafe { pthread_condattr_init(attr.as_mut_ptr()) };
    assert_eq!(rc_init, 0, "pthread_condattr_init failed");
    let mut attr = unsafe { attr.assume_init() };

    let want = pick_clock(clock_sel);
    let rc_set = unsafe { pthread_condattr_setclock(&mut attr, want) };
    assert!(rc_set >= 0, "setclock rc {rc_set}");
    if rc_set == 0 {
        let mut got: libc::clockid_t = -1;
        let rc_get = unsafe { pthread_condattr_getclock(&attr, &mut got) };
        assert_eq!(rc_get, 0);
        assert_eq!(got, want, "condattr clock round-trip failed");
    }
    let rc_d = unsafe { pthread_condattr_destroy(&mut attr) };
    assert_eq!(rc_d, 0);
}

fn apply_attr_pshared(pshared: bool) {
    let mut attr: MaybeUninit<libc::pthread_condattr_t> = MaybeUninit::zeroed();
    let rc_init = unsafe { pthread_condattr_init(attr.as_mut_ptr()) };
    assert_eq!(rc_init, 0);
    let mut attr = unsafe { attr.assume_init() };
    let want = if pshared {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    };
    let rc_set = unsafe { pthread_condattr_setpshared(&mut attr, want) };
    if rc_set == 0 {
        let mut got: c_int = -1;
        let rc_get = unsafe { pthread_condattr_getpshared(&attr, &mut got) };
        assert_eq!(rc_get, 0);
        assert_eq!(got, want, "condattr pshared round-trip failed");
    }
    unsafe { pthread_condattr_destroy(&mut attr) };
}

fn apply_init_default(table: &mut Vec<CondSlot>) {
    if table.len() >= MAX_CONDS {
        return;
    }
    let mut slot = new_cond_slot();
    let rc_m = unsafe { pthread_mutex_init(&mut *slot.mutex, std::ptr::null()) };
    assert_eq!(rc_m, 0, "pthread_mutex_init failed");
    let rc_c = unsafe { pthread_cond_init(&mut *slot.cond, std::ptr::null()) };
    assert_eq!(rc_c, 0, "pthread_cond_init(null attr) failed");
    table.push(slot);
}

fn apply_init_with_attr(table: &mut Vec<CondSlot>, clock_sel: u8, pshared: bool) {
    if table.len() >= MAX_CONDS {
        return;
    }
    let mut attr: MaybeUninit<libc::pthread_condattr_t> = MaybeUninit::zeroed();
    let rc_init = unsafe { pthread_condattr_init(attr.as_mut_ptr()) };
    if rc_init != 0 {
        return;
    }
    let mut attr = unsafe { attr.assume_init() };
    let chosen_clock = pick_clock(clock_sel);
    let _ = unsafe { pthread_condattr_setclock(&mut attr, chosen_clock) };
    let pshared_v = if pshared {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    };
    let _ = unsafe { pthread_condattr_setpshared(&mut attr, pshared_v) };

    let mut slot = new_cond_slot();
    slot.clock = chosen_clock;
    let rc_m = unsafe { pthread_mutex_init(&mut *slot.mutex, std::ptr::null()) };
    assert_eq!(rc_m, 0);
    let rc_c = unsafe { pthread_cond_init(&mut *slot.cond, &attr) };
    let _ = unsafe { pthread_condattr_destroy(&mut attr) };
    if rc_c == 0 {
        table.push(slot);
    } else {
        // Must clean up the mutex we initialized but are not storing.
        unsafe { pthread_mutex_destroy(&mut *slot.mutex) };
    }
}

fn apply_op(op: &Op, table: &mut Vec<CondSlot>) {
    match op {
        Op::AttrRoundTripClock { clock_sel } => apply_attr_clock(*clock_sel),
        Op::AttrRoundTripPshared { pshared } => apply_attr_pshared(*pshared),
        Op::InitDefault => apply_init_default(table),
        Op::InitWithAttr { clock_sel, pshared } => {
            apply_init_with_attr(table, *clock_sel, *pshared)
        }
        Op::Destroy { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            let rc = unsafe { pthread_cond_destroy(&mut *s.cond) };
            if s.state == State::Stale {
                assert!(rc >= 0, "double-destroy cond rc {rc}");
                return;
            }
            assert!(rc >= 0, "cond destroy rc {rc}");
            if rc == 0 {
                unsafe { pthread_mutex_destroy(&mut *s.mutex) };
                s.state = State::Stale;
            }
        }
        Op::Signal { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            // pthread_cond_signal with no waiter is a documented no-op.
            let rc = unsafe { pthread_cond_signal(&mut *s.cond) };
            if s.state == State::Stale {
                assert!(rc >= 0, "signal on stale cond rc {rc}");
                return;
            }
            assert!(rc >= 0, "signal rc {rc}");
        }
        Op::Broadcast { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            let rc = unsafe { pthread_cond_broadcast(&mut *s.cond) };
            if s.state == State::Stale {
                assert!(rc >= 0, "broadcast on stale cond rc {rc}");
                return;
            }
            assert!(rc >= 0, "broadcast rc {rc}");
        }
        Op::TimedwaitShortTimeout { slot, nsec_offset } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                return;
            }
            // Build a near-future absolute deadline. nsec_offset capped
            // to < 1s so we never block the harness for more than a
            // millisecond of wall clock. Critically, query the cond's
            // CONFIGURED clock — pthread_cond_timedwait interprets
            // abstime against the clock the cond was attached to via
            // condattr_setclock; mixing CLOCK_REALTIME abstime with a
            // CLOCK_MONOTONIC cond made the deadline ~50 years away
            // and the harness timed out.
            let mut now: libc::timespec = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe { libc::clock_gettime(s.clock, &mut now) };
            let nsec_add = ((*nsec_offset % 1_000_000) as i64).min(999_000);
            let abs = libc::timespec {
                tv_sec: now.tv_sec,
                tv_nsec: (now.tv_nsec + nsec_add).min(999_999_999),
            };
            // timedwait requires the mutex to be locked.
            let rc_lock = unsafe { pthread_mutex_lock(&mut *s.mutex) };
            if rc_lock != 0 {
                return;
            }
            let rc = unsafe { pthread_cond_timedwait(&mut *s.cond, &mut *s.mutex, &abs) };
            // The expected rc is 0 (spurious wake) or ETIMEDOUT; occasionally
            // EINVAL on an attr/clock mismatch.
            assert!(rc >= 0, "timedwait rc {rc}");
            let _ = unsafe { pthread_mutex_unlock(&mut *s.mutex) };
        }
        Op::MarkStale { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state != State::Live {
                return;
            }
            let rc = unsafe { pthread_cond_destroy(&mut *s.cond) };
            if rc == 0 {
                unsafe { pthread_mutex_destroy(&mut *s.mutex) };
                s.state = State::Stale;
            }
        }
    }
}

fn cleanup(table: &mut Vec<CondSlot>) {
    for mut s in std::mem::take(table) {
        if s.state == State::Live {
            unsafe {
                pthread_cond_destroy(&mut *s.cond);
                pthread_mutex_destroy(&mut *s.mutex);
            }
        }
    }
}

fuzz_target!(|input: PthreadCondFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = CONDLOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table: Vec<CondSlot> = Vec::with_capacity(MAX_CONDS);
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    cleanup(&mut table);
});
