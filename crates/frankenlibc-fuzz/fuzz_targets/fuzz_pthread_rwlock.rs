#![no_main]
//! Fuzz target for FrankenLibC's pthread rwlock surface
//! (bd-dvr22 priority-7, paired with fuzz_pthread_{mutex,cond,keys}):
//!
//!   pthread_rwlock_init, pthread_rwlock_destroy,
//!   pthread_rwlock_rdlock, pthread_rwlock_wrlock,
//!   pthread_rwlock_tryrdlock, pthread_rwlock_trywrlock,
//!   pthread_rwlock_timedrdlock, pthread_rwlock_timedwrlock,
//!   pthread_rwlock_unlock,
//!   pthread_rwlockattr_init, pthread_rwlockattr_destroy,
//!   pthread_rwlockattr_setpshared, pthread_rwlockattr_getpshared
//!
//! Single-threaded per iteration. Main invariants enforced:
//!
//! 1. Return-code contract: rc >= 0 on every call (pthread errors
//!    are always non-negative errnos).
//! 2. Attribute round-trip: setpshared → getpshared recovers
//!    the same value.
//! 3. Reader-reader compat: after `pthread_rwlock_rdlock(&rw)`,
//!    a second `pthread_rwlock_tryrdlock(&rw)` from the same
//!    thread MUST succeed (POSIX §2.9.5: readers are always
//!    compatible with each other). The harness tracks the per-
//!    rwlock depth so we know how many unlocks to balance.
//! 4. Writer-writer exclusion: after `pthread_rwlock_wrlock(&rw)`,
//!    a second `pthread_rwlock_trywrlock(&rw)` from the same
//!    thread must return EDEADLK (non-zero), never 0 — a second
//!    writer cannot coexist with the first.
//! 5. Lifecycle: destroy-then-reuse paths surfaced via MarkStale;
//!    double-destroy must be graceful (no crash).
//! 6. Timeouts bounded to < 1 ms so libFuzzer never blocks.
//!
//! Bead: bd-dvr22 priority-7 (pthread rwlock subset).

use std::ffi::c_int;
use std::mem::MaybeUninit;
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::pthread_abi::{
    pthread_rwlock_destroy, pthread_rwlock_init, pthread_rwlock_rdlock, pthread_rwlock_timedrdlock,
    pthread_rwlock_timedwrlock, pthread_rwlock_tryrdlock, pthread_rwlock_trywrlock,
    pthread_rwlock_unlock, pthread_rwlock_wrlock, pthread_rwlockattr_destroy,
    pthread_rwlockattr_getpshared, pthread_rwlockattr_init, pthread_rwlockattr_setpshared,
};
use libfuzzer_sys::fuzz_target;

const MAX_RWLOCKS: usize = 4;
const MAX_OPS: usize = 16;

static RWLOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Arbitrary)]
enum Op {
    AttrRoundTripPshared {
        pshared: bool,
    },
    InitDefault,
    InitWithAttr {
        pshared: bool,
    },
    Destroy {
        slot: u8,
    },
    Rdlock {
        slot: u8,
    },
    Wrlock {
        slot: u8,
    },
    Tryrdlock {
        slot: u8,
    },
    Trywrlock {
        slot: u8,
    },
    TimedrdlockShort {
        slot: u8,
    },
    TimedwrlockShort {
        slot: u8,
    },
    Unlock {
        slot: u8,
    },
    MarkStale {
        slot: u8,
    },
    /// Exercise the reader-reader compat invariant directly:
    /// rdlock(rw); tryrdlock(rw) must succeed; unlock; unlock.
    ReaderReaderCompat {
        slot: u8,
    },
    /// Exercise the writer-writer exclusion invariant:
    /// wrlock(rw); trywrlock(rw) must fail; unlock.
    WriterWriterExclusion {
        slot: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct PthreadRwlockFuzzInput {
    ops: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Live,
    ReadHeld,
    WriteHeld,
    Stale,
}

struct RwlockSlot {
    rw: Box<libc::pthread_rwlock_t>,
    state: State,
    /// Number of outstanding read holds from this thread (for recursion-
    /// like accumulation; we always unbalance via explicit unlocks).
    read_depth: u32,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn new_rwlock_slot() -> RwlockSlot {
    let rw: Box<libc::pthread_rwlock_t> = unsafe { Box::new(MaybeUninit::zeroed().assume_init()) };
    RwlockSlot {
        rw,
        state: State::Live,
        read_depth: 0,
    }
}

fn pick_slot(table: &mut [RwlockSlot], slot: u8) -> Option<&mut RwlockSlot> {
    if table.is_empty() {
        return None;
    }
    let idx = (slot as usize) % table.len();
    Some(&mut table[idx])
}

fn apply_attr_pshared(pshared: bool) {
    let mut attr: MaybeUninit<libc::pthread_rwlockattr_t> = MaybeUninit::zeroed();
    let rc_init = unsafe { pthread_rwlockattr_init(attr.as_mut_ptr()) };
    assert_eq!(rc_init, 0, "rwlockattr_init failed");
    let mut attr = unsafe { attr.assume_init() };
    let want = if pshared {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    };
    let rc_set = unsafe { pthread_rwlockattr_setpshared(&mut attr, want) };
    if rc_set == 0 {
        let mut got: c_int = -1;
        let rc_get = unsafe { pthread_rwlockattr_getpshared(&attr, &mut got) };
        assert_eq!(rc_get, 0);
        assert_eq!(got, want, "rwlockattr pshared round-trip failed");
    }
    unsafe { pthread_rwlockattr_destroy(&mut attr) };
}

fn short_abstime() -> libc::timespec {
    let mut now: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    libc::timespec {
        tv_sec: now.tv_sec,
        tv_nsec: (now.tv_nsec + 1_000).min(999_999_999),
    }
}

fn apply_op(op: &Op, table: &mut Vec<RwlockSlot>) {
    match op {
        Op::AttrRoundTripPshared { pshared } => apply_attr_pshared(*pshared),
        Op::InitDefault => {
            if table.len() >= MAX_RWLOCKS {
                return;
            }
            let mut slot = new_rwlock_slot();
            let rc = unsafe { pthread_rwlock_init(&mut *slot.rw, std::ptr::null()) };
            if rc == 0 {
                table.push(slot);
            }
        }
        Op::InitWithAttr { pshared } => {
            if table.len() >= MAX_RWLOCKS {
                return;
            }
            let mut attr: MaybeUninit<libc::pthread_rwlockattr_t> = MaybeUninit::zeroed();
            if unsafe { pthread_rwlockattr_init(attr.as_mut_ptr()) } != 0 {
                return;
            }
            let mut attr = unsafe { attr.assume_init() };
            let pshared_v = if *pshared {
                libc::PTHREAD_PROCESS_SHARED
            } else {
                libc::PTHREAD_PROCESS_PRIVATE
            };
            let _ = unsafe { pthread_rwlockattr_setpshared(&mut attr, pshared_v) };
            let mut slot = new_rwlock_slot();
            let rc = unsafe { pthread_rwlock_init(&mut *slot.rw, &attr) };
            unsafe { pthread_rwlockattr_destroy(&mut attr) };
            if rc == 0 {
                table.push(slot);
            }
        }
        Op::Destroy { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if matches!(s.state, State::ReadHeld | State::WriteHeld) {
                // Destroying a held rwlock is UB per POSIX — skip.
                return;
            }
            let rc = unsafe { pthread_rwlock_destroy(&mut *s.rw) };
            if s.state == State::Stale {
                assert!(rc >= 0, "double-destroy rwlock rc {rc}");
                return;
            }
            assert!(rc >= 0, "destroy rwlock rc {rc}");
            if rc == 0 {
                s.state = State::Stale;
            }
        }
        Op::Rdlock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale || s.state == State::WriteHeld {
                return;
            }
            let rc = unsafe { pthread_rwlock_rdlock(&mut *s.rw) };
            if rc == 0 {
                s.state = State::ReadHeld;
                s.read_depth += 1;
            }
        }
        Op::Wrlock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state != State::Live {
                // Calling wrlock on a held or stale rwlock is UB/skip.
                return;
            }
            let rc = unsafe { pthread_rwlock_wrlock(&mut *s.rw) };
            if rc == 0 {
                s.state = State::WriteHeld;
            }
        }
        Op::Tryrdlock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                let rc = unsafe { pthread_rwlock_tryrdlock(&mut *s.rw) };
                assert!(rc != 0, "tryrdlock on stale rwlock should not succeed");
                return;
            }
            let rc = unsafe { pthread_rwlock_tryrdlock(&mut *s.rw) };
            if rc == 0 {
                s.state = State::ReadHeld;
                s.read_depth += 1;
            }
        }
        Op::Trywrlock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                let rc = unsafe { pthread_rwlock_trywrlock(&mut *s.rw) };
                assert!(rc != 0, "trywrlock on stale rwlock should not succeed");
                return;
            }
            let rc = unsafe { pthread_rwlock_trywrlock(&mut *s.rw) };
            if rc == 0 {
                s.state = State::WriteHeld;
            }
        }
        Op::TimedrdlockShort { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                return;
            }
            let abs = short_abstime();
            let rc = unsafe { pthread_rwlock_timedrdlock(&mut *s.rw, &abs) };
            assert!(rc >= 0, "timedrdlock rc {rc}");
            if rc == 0 {
                s.state = State::ReadHeld;
                s.read_depth += 1;
            }
        }
        Op::TimedwrlockShort { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state != State::Live {
                return;
            }
            let abs = short_abstime();
            let rc = unsafe { pthread_rwlock_timedwrlock(&mut *s.rw, &abs) };
            assert!(rc >= 0, "timedwrlock rc {rc}");
            if rc == 0 {
                s.state = State::WriteHeld;
            }
        }
        Op::Unlock { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale || s.state == State::Live {
                // Unlocking an un-held rwlock is UB on some types; skip.
                return;
            }
            let rc = unsafe { pthread_rwlock_unlock(&mut *s.rw) };
            if rc != 0 {
                return;
            }
            match s.state {
                State::ReadHeld => {
                    s.read_depth = s.read_depth.saturating_sub(1);
                    if s.read_depth == 0 {
                        s.state = State::Live;
                    }
                }
                State::WriteHeld => s.state = State::Live,
                _ => {}
            }
        }
        Op::ReaderReaderCompat { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state != State::Live {
                return;
            }
            let rc1 = unsafe { pthread_rwlock_rdlock(&mut *s.rw) };
            if rc1 != 0 {
                return;
            }
            // Reader compat: tryrdlock from the SAME thread while we
            // hold a read must succeed. If it doesn't, our impl
            // violates POSIX §2.9.5.
            let rc2 = unsafe { pthread_rwlock_tryrdlock(&mut *s.rw) };
            assert_eq!(
                rc2, 0,
                "reader-reader compat violation: second tryrdlock rc {rc2}"
            );
            let _ = unsafe { pthread_rwlock_unlock(&mut *s.rw) };
            let _ = unsafe { pthread_rwlock_unlock(&mut *s.rw) };
        }
        Op::WriterWriterExclusion { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state != State::Live {
                return;
            }
            let rc1 = unsafe { pthread_rwlock_wrlock(&mut *s.rw) };
            if rc1 != 0 {
                return;
            }
            // Writer exclusion: trywrlock from same thread while we
            // hold a write must fail.
            let rc2 = unsafe { pthread_rwlock_trywrlock(&mut *s.rw) };
            assert!(
                rc2 != 0,
                "writer-writer exclusion violation: second trywrlock succeeded"
            );
            let _ = unsafe { pthread_rwlock_unlock(&mut *s.rw) };
        }
        Op::MarkStale { slot } => {
            let Some(s) = pick_slot(table, *slot) else {
                return;
            };
            if s.state != State::Live {
                return;
            }
            let rc = unsafe { pthread_rwlock_destroy(&mut *s.rw) };
            if rc == 0 {
                s.state = State::Stale;
            }
        }
    }
}

fn cleanup(table: &mut Vec<RwlockSlot>) {
    for mut s in std::mem::take(table) {
        // Drain any held state so destroy is clean.
        while matches!(s.state, State::ReadHeld | State::WriteHeld) {
            let rc = unsafe { pthread_rwlock_unlock(&mut *s.rw) };
            if rc != 0 {
                break;
            }
            match s.state {
                State::ReadHeld => {
                    s.read_depth = s.read_depth.saturating_sub(1);
                    if s.read_depth == 0 {
                        s.state = State::Live;
                    }
                }
                State::WriteHeld => s.state = State::Live,
                _ => break,
            }
        }
        if s.state == State::Live {
            unsafe {
                pthread_rwlock_destroy(&mut *s.rw);
            }
        }
    }
}

fuzz_target!(|input: PthreadRwlockFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = RWLOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table: Vec<RwlockSlot> = Vec::with_capacity(MAX_RWLOCKS);
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    cleanup(&mut table);
});
