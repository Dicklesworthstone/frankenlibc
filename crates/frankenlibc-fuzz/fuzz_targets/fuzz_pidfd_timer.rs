#![no_main]
//! Stateful fuzz target for FrankenLibC's pidfd + POSIX timer surface:
//!
//!   pidfd_open, pidfd_send_signal
//!   timer_create, timer_settime, timer_gettime, timer_getoverrun,
//!   timer_delete
//!
//! These syscalls are sequence-sensitive: their behavior depends on
//! which handles are live vs stale, and regression-test pins on
//! single-call errno parity cannot catch interactions between
//! create → use → close → reuse transitions. This target generates
//! short action sequences and keeps a handle table so later ops can
//! reference earlier ones (valid, stale, or out-of-table by design).
//!
//! Oracles:
//! 1. **Return-code contract**: every ABI call must return 0, a
//!    documented non-negative value (fd for pidfd_open, overrun
//!    count for timer_getoverrun), or -1. Nothing else.
//! 2. **Lifecycle invariant**: once a pidfd is closed or a timer is
//!    deleted, subsequent use on that exact id must return -1 (stale
//!    handle). The harness tracks which ids are live vs stale and
//!    asserts the rc matches the expected bucket.
//! 3. **No-crash** on invalid signal numbers, null itimerspec
//!    pointers, and mixed valid/stale sequencing.
//!
//! Safety:
//! - Every pidfd target pid is either `0`, the current process's own
//!   pid, or a huge-nonexistent pid guaranteed to never resolve. We
//!   never open a pidfd on some unrelated live process.
//! - Signals sent via `pidfd_send_signal` are restricted to a small
//!   safe set `{0, SIGWINCH, SIGURG}` whose delivery does not
//!   terminate the fuzz binary (sig 0 is the POSIX "probe existence"
//!   sentinel; SIGWINCH + SIGURG are normally ignored).
//! - The handle table is capped so the fuzzer cannot exhaust file
//!   descriptors or kernel timer slots.
//!
//! Not included in this initial harness:
//! - libc-symbol differential (`extern "C" fn pidfd_open` binds to
//!   only one impl at link time; a full differential needs
//!   `dlsym(RTLD_NEXT, ...)` plumbing). Tracked as follow-up.
//! - Real signal-delivery observation (would need sigaction state
//!   isolation). The harness asserts only the return-value / errno
//!   contract; it does not verify the delivered signal was handled.
//!
//! Bead: bd-36hiy

use std::ffi::{c_int, c_uint, c_void};
use std::mem::MaybeUninit;
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::unistd_abi::{
    pidfd_open, pidfd_send_signal, timer_create, timer_delete, timer_getoverrun, timer_gettime,
    timer_settime,
};
use libfuzzer_sys::fuzz_target;

const MAX_HANDLES: usize = 8;
const MAX_OPS: usize = 16;
const NONEXISTENT_PID: libc::pid_t = 0x3F_FF_FF_FE;

/// Signals we are willing to deliver to the fuzz binary itself.
const SAFE_SIGNALS: [c_int; 3] = [0, libc::SIGWINCH, libc::SIGURG];

#[derive(Debug, Arbitrary)]
enum Op {
    PidfdOpen {
        pid_class: u8,
        flags: u32,
    },
    PidfdSendSignal {
        slot: u8,
        sig_idx: u8,
        flags: u32,
        // When `use_stale` is true and the slot points at a closed
        // pidfd, re-use it anyway to exercise the stale-handle path.
        use_stale: bool,
    },
    PidfdClose {
        slot: u8,
    },
    TimerCreate {
        clockid: i32,
    },
    TimerSettime {
        slot: u8,
        flags: i32,
        sec: i64,
        nsec: i64,
        interval_sec: i64,
        interval_nsec: i64,
        null_new: bool,
        null_old: bool,
    },
    TimerGettime {
        slot: u8,
        null_curr: bool,
    },
    TimerGetoverrun {
        slot: u8,
    },
    TimerDelete {
        slot: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct PidfdTimerInput {
    ops: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HandleState {
    Live,
    Stale,
}

struct HandleTable {
    /// Stores (pidfd, state). We allow a freed pidfd to linger in the
    /// table so the fuzzer can attempt stale-handle reuse.
    pidfds: Vec<(c_int, HandleState)>,
    /// Stores (timer_id, state). `timer_id` is the i32 the kernel
    /// returned from SYS_timer_create; the ABI casts it into a
    /// `*mut c_void` at the C boundary.
    timers: Vec<(i32, HandleState)>,
}

impl HandleTable {
    fn new() -> Self {
        Self {
            pidfds: Vec::new(),
            timers: Vec::new(),
        }
    }

    fn pick_pidfd(&self, slot: u8) -> Option<(c_int, HandleState, usize)> {
        if self.pidfds.is_empty() {
            return None;
        }
        let idx = (slot as usize) % self.pidfds.len();
        let (fd, state) = self.pidfds[idx];
        Some((fd, state, idx))
    }

    fn pick_timer(&self, slot: u8) -> Option<(i32, HandleState, usize)> {
        if self.timers.is_empty() {
            return None;
        }
        let idx = (slot as usize) % self.timers.len();
        let (id, state) = self.timers[idx];
        Some((id, state, idx))
    }
}

static LOCK: Mutex<()> = Mutex::new(());

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode is set once before any ABI call runs.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn pick_pid(pid_class: u8) -> libc::pid_t {
    match pid_class & 0b11 {
        0 => 0,
        1 => std::process::id() as libc::pid_t,
        2 => NONEXISTENT_PID,
        _ => -1_i32 as libc::pid_t,
    }
}

fn pick_signal(sig_idx: u8) -> c_int {
    SAFE_SIGNALS[(sig_idx as usize) % SAFE_SIGNALS.len()]
}

fn pick_clockid(clockid: i32) -> libc::clockid_t {
    // Bias toward legal clocks; keep a dash of noise so the invalid
    // path is also reached.
    const VALID: &[libc::clockid_t] = &[
        libc::CLOCK_REALTIME,
        libc::CLOCK_MONOTONIC,
        libc::CLOCK_BOOTTIME,
    ];
    if (clockid as u32) & 0b111 == 0 {
        // One-in-eight chance to hit the invalid path intentionally.
        clockid as libc::clockid_t
    } else {
        VALID[(clockid as usize) % VALID.len()]
    }
}

fn clamp_nsec(n: i64) -> i64 {
    // Kernel rejects anything outside 0..1_000_000_000 except 0 with
    // special flags — let the fuzzer explore both the valid and
    // oversize halves but bound the value so we do not probe
    // negative huge.
    n.rem_euclid(1_500_000_000)
}

fn apply_op(op: &Op, table: &mut HandleTable) {
    match op {
        Op::PidfdOpen { pid_class, flags } => {
            if table.pidfds.len() >= MAX_HANDLES {
                return;
            }
            let pid = pick_pid(*pid_class);
            let fd = unsafe { pidfd_open(pid, *flags as c_uint) };
            assert!(fd == -1 || fd >= 0, "pidfd_open rc out of contract: {fd}");
            if fd >= 0 {
                table.pidfds.push((fd, HandleState::Live));
            }
        }
        Op::PidfdSendSignal {
            slot,
            sig_idx,
            flags,
            use_stale,
        } => {
            let Some((fd, state, _idx)) = table.pick_pidfd(*slot) else {
                return;
            };
            if state == HandleState::Stale && !use_stale {
                return;
            }
            let sig = pick_signal(*sig_idx);
            let rc = unsafe {
                pidfd_send_signal(fd, sig, std::ptr::null(), *flags as c_uint)
            };
            assert!(rc == 0 || rc == -1, "pidfd_send_signal rc: {rc}");
            if state == HandleState::Stale {
                assert_eq!(
                    rc, -1,
                    "pidfd_send_signal must fail on stale fd ({fd})"
                );
            }
        }
        Op::PidfdClose { slot } => {
            let Some((fd, state, idx)) = table.pick_pidfd(*slot) else {
                return;
            };
            if state == HandleState::Stale {
                return;
            }
            // Close via raw libc::close (the ABI does not expose its
            // own close wrapper under the same name path here).
            let rc = unsafe { libc::close(fd) };
            assert!(rc == 0 || rc == -1, "close(pidfd) rc: {rc}");
            // Poison the fd so subsequent use_stale ops on this slot
            // target -1 (always fails) instead of the just-closed fd
            // integer which the kernel may reuse for a subsequent
            // PidfdOpen. Same fd-reuse pattern as fuzz_socket
            // MarkStale (bd-tw26d / 756dcfb1).
            table.pidfds[idx] = (-1, HandleState::Stale);
        }
        Op::TimerCreate { clockid } => {
            if table.timers.len() >= MAX_HANDLES {
                return;
            }
            let mut id: i32 = 0;
            let rc = unsafe {
                timer_create(
                    pick_clockid(*clockid),
                    std::ptr::null_mut(),
                    &mut id as *mut _ as *mut c_void,
                )
            };
            assert!(rc == 0 || rc == -1, "timer_create rc: {rc}");
            if rc == 0 {
                table.timers.push((id, HandleState::Live));
            }
        }
        Op::TimerSettime {
            slot,
            flags,
            sec,
            nsec,
            interval_sec,
            interval_nsec,
            null_new,
            null_old,
        } => {
            let Some((id, state, _idx)) = table.pick_timer(*slot) else {
                return;
            };
            // i64::abs() panics in debug mode for i64::MIN (overflow).
            // cargo-fuzz compiles with -Cdebug-assertions for ASan, so
            // a fuzzer-generated i64::MIN sec/interval triggers a
            // libFuzzer "deadly signal". Use saturating_abs which
            // clamps to i64::MAX instead of panicking.
            let new_value = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: interval_sec.saturating_abs() % 10,
                    tv_nsec: clamp_nsec(*interval_nsec),
                },
                it_value: libc::timespec {
                    tv_sec: sec.saturating_abs() % 10,
                    tv_nsec: clamp_nsec(*nsec),
                },
            };
            let mut old_value: MaybeUninit<libc::itimerspec> = MaybeUninit::zeroed();
            let new_ptr: *const c_void = if *null_new {
                std::ptr::null()
            } else {
                &new_value as *const _ as *const c_void
            };
            let old_ptr: *mut c_void = if *null_old {
                std::ptr::null_mut()
            } else {
                old_value.as_mut_ptr().cast::<c_void>()
            };
            let rc = unsafe {
                timer_settime(id as *mut c_void, *flags as c_int, new_ptr, old_ptr)
            };
            assert!(rc == 0 || rc == -1, "timer_settime rc: {rc}");
            if state == HandleState::Stale {
                assert_eq!(
                    rc, -1,
                    "timer_settime must fail on stale timer id ({id})"
                );
            }
        }
        Op::TimerGettime { slot, null_curr } => {
            let Some((id, state, _idx)) = table.pick_timer(*slot) else {
                return;
            };
            let mut curr: MaybeUninit<libc::itimerspec> = MaybeUninit::zeroed();
            let curr_ptr: *mut c_void = if *null_curr {
                std::ptr::null_mut()
            } else {
                curr.as_mut_ptr().cast::<c_void>()
            };
            let rc = unsafe { timer_gettime(id as *mut c_void, curr_ptr) };
            assert!(rc == 0 || rc == -1, "timer_gettime rc: {rc}");
            if state == HandleState::Stale {
                assert_eq!(rc, -1, "timer_gettime must fail on stale id ({id})");
            }
            if rc == 0 && !*null_curr {
                let t = unsafe { curr.assume_init() };
                assert!(
                    t.it_value.tv_nsec >= 0 && t.it_value.tv_nsec < 1_000_000_000,
                    "timer_gettime returned non-canonical nsec"
                );
            }
        }
        Op::TimerGetoverrun { slot } => {
            let Some((id, state, _idx)) = table.pick_timer(*slot) else {
                return;
            };
            let rc = unsafe { timer_getoverrun(id as *mut c_void) };
            assert!(
                rc == -1 || rc >= 0,
                "timer_getoverrun rc out of contract: {rc}"
            );
            if state == HandleState::Stale {
                assert_eq!(rc, -1, "timer_getoverrun must fail on stale id ({id})");
            }
        }
        Op::TimerDelete { slot } => {
            let Some((id, state, idx)) = table.pick_timer(*slot) else {
                return;
            };
            let rc = unsafe { timer_delete(id as *mut c_void) };
            assert!(rc == 0 || rc == -1, "timer_delete rc: {rc}");
            if state == HandleState::Stale {
                assert_eq!(rc, -1, "timer_delete must fail on stale id ({id})");
            } else if rc == 0 {
                table.timers[idx] = (id, HandleState::Stale);
            }
        }
    }
}

fn cleanup(table: &mut HandleTable) {
    for (fd, state) in std::mem::take(&mut table.pidfds) {
        if state == HandleState::Live {
            unsafe {
                libc::close(fd);
            }
        }
    }
    for (id, state) in std::mem::take(&mut table.timers) {
        if state == HandleState::Live {
            unsafe {
                timer_delete(id as *mut c_void);
            }
        }
    }
}

fuzz_target!(|input: PidfdTimerInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table = HandleTable::new();
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    cleanup(&mut table);
});
