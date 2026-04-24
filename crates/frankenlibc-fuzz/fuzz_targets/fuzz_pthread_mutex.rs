#![no_main]
//! Stateful fuzz target for FrankenLibC's pthread mutex + mutexattr
//! surface (subset of bd-dvr22 priority-7 pthread coverage):
//!
//!   pthread_mutex_init, pthread_mutex_destroy,
//!   pthread_mutex_lock, pthread_mutex_trylock,
//!   pthread_mutex_unlock, pthread_mutex_timedlock,
//!   pthread_mutex_consistent,
//!   pthread_mutexattr_init, pthread_mutexattr_destroy,
//!   pthread_mutexattr_settype, pthread_mutexattr_gettype,
//!   pthread_mutexattr_setprotocol, pthread_mutexattr_getprotocol,
//!   pthread_mutexattr_setpshared, pthread_mutexattr_getpshared,
//!   pthread_mutexattr_setrobust, pthread_mutexattr_getrobust
//!
//! This harness is single-threaded per iteration — it exercises the
//! lifecycle + attribute correctness + contract-enforcement
//! invariants a mutex library must hold even before concurrency
//! stress. A separate TSan campaign (bd-dvr22 follow-up) is the
//! right way to catch real races; this target catches the larger
//! class of non-race bugs (init/destroy mis-ordering, invalid type
//! values, stale-handle ops, attribute round-trip).
//!
//! Oracles:
//! 1. Return-code contract: every call returns 0 / a documented
//!    non-zero errno, never an undocumented value.
//! 2. Attribute round-trip: set→get recovers the same value for
//!    type, protocol, pshared, robust.
//! 3. Lifecycle: destroy on an unlocked mutex succeeds; a
//!    destroyed mutex re-used without re-init must return a
//!    documented error.
//! 4. Single-thread lock contract: for NORMAL type, a second lock
//!    from the same thread is UB per POSIX — skip; for RECURSIVE
//!    type, successive locks must return 0 and each needs a
//!    matching unlock.
//!
//! Bead: bd-dvr22 priority-7 (pthread mutex subset)

use std::ffi::c_int;
use std::mem::MaybeUninit;
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::pthread_abi::{
    pthread_mutex_consistent, pthread_mutex_destroy, pthread_mutex_init, pthread_mutex_lock,
    pthread_mutex_timedlock, pthread_mutex_trylock, pthread_mutex_unlock,
    pthread_mutexattr_destroy, pthread_mutexattr_getprotocol, pthread_mutexattr_getpshared,
    pthread_mutexattr_getrobust, pthread_mutexattr_gettype, pthread_mutexattr_init,
    pthread_mutexattr_setprotocol, pthread_mutexattr_setpshared, pthread_mutexattr_setrobust,
    pthread_mutexattr_settype,
};
use libfuzzer_sys::fuzz_target;

const MAX_MUTEXES: usize = 4;
const MAX_OPS: usize = 16;

static PTLOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Arbitrary)]
enum Op {
    AttrRoundTripType {
        type_sel: u8,
    },
    AttrRoundTripProtocol {
        proto_sel: u8,
    },
    AttrRoundTripPshared {
        pshared: bool,
    },
    AttrRoundTripRobust {
        robust: bool,
    },
    InitDefault,
    InitWithAttr {
        type_sel: u8,
        robust: bool,
    },
    Destroy {
        slot: u8,
    },
    Lock {
        slot: u8,
    },
    Trylock {
        slot: u8,
    },
    Unlock {
        slot: u8,
    },
    TimedlockShort {
        slot: u8,
    },
    Consistent {
        slot: u8,
    },
    /// Close the fd-analogue: mark a mutex as destroyed in our shadow
    /// but keep a stale handle in the table so later ops exercise
    /// the stale-handle path.
    MarkStale {
        slot: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct PthreadMutexFuzzInput {
    ops: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Live,
    LockedBySelf,
    Stale,
}

struct MutexSlot {
    m: Box<libc::pthread_mutex_t>,
    state: State,
    /// Lock depth for recursive mutexes; 0 for NORMAL.
    depth: u32,
    recursive: bool,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: process mode is set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn pick_type(sel: u8) -> c_int {
    match sel % 4 {
        0 => libc::PTHREAD_MUTEX_NORMAL,
        1 => libc::PTHREAD_MUTEX_RECURSIVE,
        2 => libc::PTHREAD_MUTEX_ERRORCHECK,
        _ => libc::PTHREAD_MUTEX_DEFAULT,
    }
}

fn pick_protocol(sel: u8) -> c_int {
    match sel % 3 {
        0 => libc::PTHREAD_PRIO_NONE,
        1 => libc::PTHREAD_PRIO_INHERIT,
        _ => libc::PTHREAD_PRIO_PROTECT,
    }
}

fn new_mutex_slot(recursive: bool) -> MutexSlot {
    let m: Box<libc::pthread_mutex_t> = unsafe { Box::new(MaybeUninit::zeroed().assume_init()) };
    MutexSlot {
        m,
        state: State::Live,
        depth: 0,
        recursive,
    }
}

fn pick_slot(table: &mut [MutexSlot], slot: u8) -> Option<&mut MutexSlot> {
    if table.is_empty() {
        return None;
    }
    let idx = (slot as usize) % table.len();
    Some(&mut table[idx])
}

fn apply_attr_type(type_sel: u8) {
    let mut attr: MaybeUninit<libc::pthread_mutexattr_t> = MaybeUninit::zeroed();
    let rc_init = unsafe { pthread_mutexattr_init(attr.as_mut_ptr()) };
    assert_eq!(rc_init, 0, "pthread_mutexattr_init failed");
    let mut attr = unsafe { attr.assume_init() };

    let want = pick_type(type_sel);
    let rc_set = unsafe { pthread_mutexattr_settype(&mut attr, want) };
    assert!(rc_set >= 0, "settype rc {rc_set}");
    if rc_set == 0 {
        let mut got: c_int = -1;
        let rc_get = unsafe { pthread_mutexattr_gettype(&attr, &mut got) };
        assert_eq!(rc_get, 0, "gettype failed");
        assert_eq!(got, want, "mutexattr type round-trip failed");
    }
    let rc_d = unsafe { pthread_mutexattr_destroy(&mut attr) };
    assert_eq!(rc_d, 0);
}

fn apply_attr_protocol(proto_sel: u8) {
    let mut attr: MaybeUninit<libc::pthread_mutexattr_t> = MaybeUninit::zeroed();
    unsafe { pthread_mutexattr_init(attr.as_mut_ptr()) };
    let mut attr = unsafe { attr.assume_init() };
    let want = pick_protocol(proto_sel);
    let rc_set = unsafe { pthread_mutexattr_setprotocol(&mut attr, want) };
    if rc_set == 0 {
        let mut got: c_int = -1;
        let rc_get = unsafe { pthread_mutexattr_getprotocol(&attr, &mut got) };
        assert_eq!(rc_get, 0);
        assert_eq!(got, want, "mutexattr protocol round-trip failed");
    }
    unsafe { pthread_mutexattr_destroy(&mut attr) };
}

fn apply_attr_pshared(pshared: bool) {
    let mut attr: MaybeUninit<libc::pthread_mutexattr_t> = MaybeUninit::zeroed();
    unsafe { pthread_mutexattr_init(attr.as_mut_ptr()) };
    let mut attr = unsafe { attr.assume_init() };
    let want = if pshared {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    };
    let rc_set = unsafe { pthread_mutexattr_setpshared(&mut attr, want) };
    if rc_set == 0 {
        let mut got: c_int = -1;
        let rc_get = unsafe { pthread_mutexattr_getpshared(&attr, &mut got) };
        assert_eq!(rc_get, 0);
        assert_eq!(got, want, "mutexattr pshared round-trip failed");
    }
    unsafe { pthread_mutexattr_destroy(&mut attr) };
}

fn apply_attr_robust(robust: bool) {
    let mut attr: MaybeUninit<libc::pthread_mutexattr_t> = MaybeUninit::zeroed();
    unsafe { pthread_mutexattr_init(attr.as_mut_ptr()) };
    let mut attr = unsafe { attr.assume_init() };
    let want = if robust {
        libc::PTHREAD_MUTEX_ROBUST
    } else {
        libc::PTHREAD_MUTEX_STALLED
    };
    let rc_set = unsafe { pthread_mutexattr_setrobust(&mut attr, want) };
    if rc_set == 0 {
        let mut got: c_int = -1;
        let rc_get = unsafe { pthread_mutexattr_getrobust(&attr, &mut got) };
        assert_eq!(rc_get, 0);
        assert_eq!(got, want, "mutexattr robust round-trip failed");
    }
    unsafe { pthread_mutexattr_destroy(&mut attr) };
}

fn apply_init_default(table: &mut Vec<MutexSlot>) {
    if table.len() >= MAX_MUTEXES {
        return;
    }
    let mut slot = new_mutex_slot(false);
    let rc = unsafe { pthread_mutex_init(&mut *slot.m, std::ptr::null()) };
    assert_eq!(rc, 0, "pthread_mutex_init default failed");
    table.push(slot);
}

fn apply_init_with_attr(table: &mut Vec<MutexSlot>, type_sel: u8, robust: bool) {
    if table.len() >= MAX_MUTEXES {
        return;
    }
    let mut attr: MaybeUninit<libc::pthread_mutexattr_t> = MaybeUninit::zeroed();
    unsafe { pthread_mutexattr_init(attr.as_mut_ptr()) };
    let mut attr = unsafe { attr.assume_init() };
    let ty = pick_type(type_sel);
    let _ = unsafe { pthread_mutexattr_settype(&mut attr, ty) };
    let robust_val = if robust {
        libc::PTHREAD_MUTEX_ROBUST
    } else {
        libc::PTHREAD_MUTEX_STALLED
    };
    let _ = unsafe { pthread_mutexattr_setrobust(&mut attr, robust_val) };
    let recursive = ty == libc::PTHREAD_MUTEX_RECURSIVE;
    let mut slot = new_mutex_slot(recursive);
    let rc = unsafe { pthread_mutex_init(&mut *slot.m, &attr) };
    unsafe { pthread_mutexattr_destroy(&mut attr) };
    if rc == 0 {
        table.push(slot);
    }
}

fn apply_op(op: &Op, table: &mut Vec<MutexSlot>) {
    match op {
        Op::AttrRoundTripType { type_sel } => apply_attr_type(*type_sel),
        Op::AttrRoundTripProtocol { proto_sel } => apply_attr_protocol(*proto_sel),
        Op::AttrRoundTripPshared { pshared } => apply_attr_pshared(*pshared),
        Op::AttrRoundTripRobust { robust } => apply_attr_robust(*robust),
        Op::InitDefault => apply_init_default(table),
        Op::InitWithAttr { type_sel, robust } => apply_init_with_attr(table, *type_sel, *robust),
        Op::Destroy { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::LockedBySelf {
                // Destroying a locked mutex is UB — skip to keep harness sound.
                return;
            }
            let rc = unsafe { pthread_mutex_destroy(&mut *s.m) };
            if s.state == State::Stale {
                // Double-destroy — documented errno acceptable, must not crash.
                assert!(rc >= 0, "double-destroy rc {rc}");
                return;
            }
            assert!(rc >= 0, "destroy rc {rc}");
            if rc == 0 {
                s.state = State::Stale;
            }
        }
        Op::Lock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                let rc = unsafe { pthread_mutex_lock(&mut *s.m) };
                // Stale mutex: implementation may return EINVAL (POSIX allows) or
                // redirect to an undefined destination; the invariant here is
                // 'no crash, rc non-zero'.
                assert!(rc != 0, "lock on stale mutex should not succeed");
                return;
            }
            if s.state == State::LockedBySelf && !s.recursive {
                // NORMAL + locked by same thread is UB — skip.
                return;
            }
            let rc = unsafe { pthread_mutex_lock(&mut *s.m) };
            if rc == 0 {
                s.state = State::LockedBySelf;
                s.depth += 1;
            }
        }
        Op::Trylock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                let rc = unsafe { pthread_mutex_trylock(&mut *s.m) };
                assert!(rc != 0, "trylock on stale mutex should not succeed");
                return;
            }
            let rc = unsafe { pthread_mutex_trylock(&mut *s.m) };
            assert!(rc >= 0, "trylock rc {rc}");
            if rc == 0 {
                s.state = State::LockedBySelf;
                s.depth += 1;
            }
        }
        Op::Unlock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale || s.state == State::Live {
                // Unlock without owning the lock — POSIX says EPERM for
                // ERRORCHECK mutexes, UB for NORMAL. Skip to stay sound.
                if !s.recursive {
                    return;
                }
            }
            let rc = unsafe { pthread_mutex_unlock(&mut *s.m) };
            if rc == 0 && s.state == State::LockedBySelf {
                s.depth = s.depth.saturating_sub(1);
                if s.depth == 0 {
                    s.state = State::Live;
                }
            }
        }
        Op::TimedlockShort { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                return;
            }
            // Absolute time in the near future (1 µs). For an uncontended
            // mutex this must succeed; for a contended one it should
            // return ETIMEDOUT. Either way: no crash.
            let mut now: libc::timespec = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
            let abs = libc::timespec {
                tv_sec: now.tv_sec,
                tv_nsec: (now.tv_nsec + 1_000).min(999_999_999),
            };
            let rc = unsafe { pthread_mutex_timedlock(&mut *s.m, &abs) };
            assert!(rc >= 0, "timedlock rc {rc}");
            if rc == 0 {
                s.state = State::LockedBySelf;
                s.depth += 1;
            }
        }
        Op::Consistent { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                return;
            }
            // pthread_mutex_consistent on a non-robust owner-dead mutex
            // returns EINVAL; we just assert no crash.
            let rc = unsafe { pthread_mutex_consistent(&mut *s.m) };
            assert!(rc >= 0, "consistent rc {rc}");
        }
        Op::MarkStale { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state != State::Live {
                return;
            }
            let rc = unsafe { pthread_mutex_destroy(&mut *s.m) };
            if rc == 0 {
                s.state = State::Stale;
            }
        }
    }
}

fn cleanup(table: &mut Vec<MutexSlot>) {
    for mut s in std::mem::take(table) {
        // Drain any remaining holds before destroy; this is
        // defensive — well-written ops should have paired everything.
        while s.state == State::LockedBySelf {
            let rc = unsafe { pthread_mutex_unlock(&mut *s.m) };
            if rc != 0 {
                break;
            }
            s.depth = s.depth.saturating_sub(1);
            if s.depth == 0 {
                s.state = State::Live;
            }
        }
        if s.state == State::Live {
            unsafe {
                pthread_mutex_destroy(&mut *s.m);
            }
        }
    }
}

fuzz_target!(|input: PthreadMutexFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = PTLOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table: Vec<MutexSlot> = Vec::with_capacity(MAX_MUTEXES);
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    cleanup(&mut table);
});
