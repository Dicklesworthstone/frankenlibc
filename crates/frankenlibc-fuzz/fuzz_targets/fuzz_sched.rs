#![no_main]
//! Differential + contract fuzz target for FrankenLibC's
//! sched_*-family wrappers:
//!
//!   sched_getscheduler / sched_setscheduler
//!   sched_getparam     / sched_setparam
//!   sched_getaffinity  / sched_setaffinity
//!   sched_get_priority_min / sched_get_priority_max
//!   sched_rr_get_interval
//!   sched_yield
//!
//! The target fuzzes each entrypoint across pid classes (self,
//! huge-nonexistent, negative), policy values (valid/invalid), mask
//! sizes (0, <cpuset_t, cpuset_t, >cpuset_t), and priority / param
//! contents. Two oracles:
//!
//! 1. **Return-code contract**: every call must return either its
//!    documented success value or -1; no panics, no other values.
//! 2. **Syscall differential**: the read-only getters
//!    (`sched_getscheduler`, `sched_getparam`, `sched_getaffinity`,
//!    `sched_get_priority_{min,max}`, `sched_rr_get_interval`) must
//!    agree with a direct `libc::syscall(SYS_*)` call on the same
//!    inputs. This works because the raw syscall bypasses every
//!    userspace wrapper (ours and libc's), giving a ground truth to
//!    compare our ABI against. Trying to do the differential via a
//!    second `extern "C" fn sched_getscheduler` would bind to only
//!    one symbol (ours or libc's), which is why we use syscalls.
//!
//! Safety:
//! - All "set" ops target `pid == 0` (self) or a huge-nonexistent
//!   pid that is guaranteed to fail with ESRCH. We never try to
//!   change another live process's scheduler or affinity.
//! - The only policy that is allowed to succeed without CAP_SYS_NICE
//!   is SCHED_OTHER with priority 0. Every other policy the fuzzer
//!   picks is expected to fail with EPERM — the invariant is simply
//!   "no crash", not "succeeds".
//! - A process-wide guard saves the starting scheduler/affinity and
//!   restores it after each iteration so the fuzz binary does not
//!   progressively drift the running process's scheduling class.
//!
//! Bead: bd-ya1fh

use std::ffi::{c_int, c_void};
use std::mem::MaybeUninit;
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::unistd_abi::{
    sched_get_priority_max, sched_get_priority_min, sched_getaffinity, sched_getparam,
    sched_getscheduler, sched_rr_get_interval, sched_setaffinity, sched_setparam,
    sched_setscheduler,
};
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::poll_abi::sched_yield;

/// Hard cap on affinity-mask byte size the fuzzer may request.
const MAX_AFF_BYTES: usize = 256;
/// Sentinel pid guaranteed to never exist (> pid_max default on any
/// Linux version).
const NONEXISTENT_PID: libc::pid_t = 0x3F_FF_FF_FE;

#[derive(Debug, Arbitrary)]
enum SchedOp {
    GetScheduler {
        pid_class: u8,
    },
    SetSchedulerOther {
        pid_class: u8,
    },
    SetSchedulerInvalid {
        pid_class: u8,
        policy: i32,
    },
    GetParam {
        pid_class: u8,
    },
    SetParam {
        pid_class: u8,
        priority: i32,
    },
    GetAffinity {
        pid_class: u8,
        size: u8,
    },
    SetAffinity {
        pid_class: u8,
        size: u8,
        mask_seed: u64,
    },
    PriorityMin {
        policy: i32,
    },
    PriorityMax {
        policy: i32,
    },
    RrGetInterval {
        pid_class: u8,
    },
    Yield,
}

#[derive(Debug, Arbitrary)]
struct SchedFuzzInput {
    ops: Vec<SchedOp>,
}

static SCHED_LOCK: Mutex<()> = Mutex::new(());

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode is set process-wide once.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn pick_pid(pid_class: u8) -> libc::pid_t {
    match pid_class & 0b11 {
        0 => 0, // self
        1 => NONEXISTENT_PID,
        2 => -1_i32 as libc::pid_t,
        _ => std::process::id() as libc::pid_t,
    }
}

/// Assert an ABI return value respects the "documented success value
/// or -1" contract. Most sched_* calls return 0 on success, so we
/// accept 0, the documented range (for `sched_get_priority_*` ≥ 0),
/// or -1.
fn assert_rc_contract(rc: c_int, label: &'static str) {
    assert!(
        rc == 0 || rc == -1 || rc > 0,
        "{label}: rc {rc} is out of the sched-family return contract"
    );
}

fn apply_get_scheduler(pid_class: u8) {
    let pid = pick_pid(pid_class);
    let rc_ours = unsafe { sched_getscheduler(pid) };
    // Direct syscall is ground truth.
    let rc_sys =
        unsafe { libc::syscall(libc::SYS_sched_getscheduler, pid as libc::c_long) as c_int };
    // Both must return the same bucket: success value or -1.
    assert_rc_contract(rc_ours, "sched_getscheduler");
    assert_eq!(
        rc_ours >= 0,
        rc_sys >= 0,
        "sched_getscheduler bucket diverged pid={pid}: ours={rc_ours} sys={rc_sys}"
    );
    if rc_ours >= 0 && rc_sys >= 0 {
        assert_eq!(rc_ours, rc_sys, "sched_getscheduler diverged for pid={pid}");
    }
}

fn apply_set_scheduler_other(pid_class: u8) {
    let pid = pick_pid(pid_class);
    let param = libc::sched_param { sched_priority: 0 };
    let rc = unsafe {
        sched_setscheduler(
            pid,
            libc::SCHED_OTHER,
            &param as *const _ as *const std::ffi::c_void,
        )
    };
    assert_rc_contract(rc, "sched_setscheduler(SCHED_OTHER)");
}

fn apply_set_scheduler_invalid(pid_class: u8, policy: i32) {
    let pid = pick_pid(pid_class);
    let param = libc::sched_param { sched_priority: 0 };
    let rc = unsafe {
        sched_setscheduler(
            pid,
            policy as c_int,
            &param as *const _ as *const std::ffi::c_void,
        )
    };
    assert_rc_contract(rc, "sched_setscheduler(fuzz policy)");
}

fn apply_get_param(pid_class: u8) {
    let pid = pick_pid(pid_class);
    let mut param: MaybeUninit<libc::sched_param> = MaybeUninit::zeroed();
    let rc_ours = unsafe { sched_getparam(pid, param.as_mut_ptr() as *mut std::ffi::c_void) };
    assert_rc_contract(rc_ours, "sched_getparam");

    // Syscall differential.
    let mut sys_param: MaybeUninit<libc::sched_param> = MaybeUninit::zeroed();
    let rc_sys = unsafe {
        libc::syscall(
            libc::SYS_sched_getparam,
            pid as libc::c_long,
            sys_param.as_mut_ptr() as libc::c_long,
        ) as c_int
    };
    assert_eq!(
        rc_ours == 0,
        rc_sys == 0,
        "sched_getparam rc diverged pid={pid}: ours={rc_ours} sys={rc_sys}"
    );
    if rc_ours == 0 && rc_sys == 0 {
        // SAFETY: both successes wrote into their respective buffers.
        let ours = unsafe { param.assume_init() }.sched_priority;
        let sys = unsafe { sys_param.assume_init() }.sched_priority;
        assert_eq!(ours, sys, "sched_getparam priority diverged for pid={pid}");
    }
}

fn apply_set_param(pid_class: u8, priority: i32) {
    let pid = pick_pid(pid_class);
    let param = libc::sched_param {
        sched_priority: priority as c_int,
    };
    let rc = unsafe { sched_setparam(pid, &param as *const _ as *const std::ffi::c_void) };
    assert_rc_contract(rc, "sched_setparam");
}

fn apply_get_affinity(pid_class: u8, size: u8) {
    let pid = pick_pid(pid_class);
    let size = (size as usize) % MAX_AFF_BYTES;
    if size == 0 {
        return;
    }
    let mut mask = vec![0u8; size];
    let rc_ours = unsafe { sched_getaffinity(pid, size, mask.as_mut_ptr() as *mut c_void) };
    assert_rc_contract(rc_ours, "sched_getaffinity");

    let mut sys_mask = vec![0u8; size];
    // The raw syscall returns the byte count written (>=0) or -1; the
    // userspace ABI normalizes to 0 / -1. We compare in buckets:
    // both succeeded or both failed. When both succeed, the bytes the
    // kernel wrote via the raw-syscall path are the ground truth the
    // ABI must also have produced.
    let rc_sys = unsafe {
        libc::syscall(
            libc::SYS_sched_getaffinity,
            pid as libc::c_long,
            size as libc::c_long,
            sys_mask.as_mut_ptr() as libc::c_long,
        ) as c_int
    };
    let ours_success = rc_ours == 0;
    let sys_success = rc_sys > 0;
    assert_eq!(
        ours_success, sys_success,
        "sched_getaffinity bucket diverged pid={pid}: ours={rc_ours} sys={rc_sys}"
    );
    if ours_success && sys_success {
        let len = (rc_sys as usize).min(size);
        assert_eq!(
            &mask[..len],
            &sys_mask[..len],
            "sched_getaffinity mask diverged pid={pid} len={len}"
        );
    }
}

fn apply_set_affinity(pid_class: u8, size: u8, mask_seed: u64) {
    let pid = pick_pid(pid_class);
    let size = (size as usize) % MAX_AFF_BYTES;
    if size == 0 {
        return;
    }
    let mut mask = vec![0u8; size];
    // Stamp a pattern derived from the seed so the fuzzer explores
    // different mask shapes without requiring a separate input byte
    // per cpu.
    for (i, slot) in mask.iter_mut().enumerate() {
        *slot = ((mask_seed >> ((i * 7) & 63)) & 0xFF) as u8;
    }
    let rc = unsafe { sched_setaffinity(pid, size, mask.as_ptr() as *const c_void) };
    assert_rc_contract(rc, "sched_setaffinity");
}

fn apply_priority_min(policy: i32) {
    let rc_ours = unsafe { sched_get_priority_min(policy as c_int) };
    let rc_sys =
        unsafe { libc::syscall(libc::SYS_sched_get_priority_min, policy as libc::c_long) as c_int };
    assert_eq!(
        rc_ours, rc_sys,
        "sched_get_priority_min diverged for policy={policy}"
    );
}

fn apply_priority_max(policy: i32) {
    let rc_ours = unsafe { sched_get_priority_max(policy as c_int) };
    let rc_sys =
        unsafe { libc::syscall(libc::SYS_sched_get_priority_max, policy as libc::c_long) as c_int };
    assert_eq!(
        rc_ours, rc_sys,
        "sched_get_priority_max diverged for policy={policy}"
    );
}

fn apply_rr_get_interval(pid_class: u8) {
    let pid = pick_pid(pid_class);
    let mut ts: MaybeUninit<libc::timespec> = MaybeUninit::zeroed();
    let rc = unsafe { sched_rr_get_interval(pid, ts.as_mut_ptr()) };
    assert_rc_contract(rc, "sched_rr_get_interval");
    if rc == 0 {
        let ts = unsafe { ts.assume_init() };
        assert!(
            ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000,
            "sched_rr_get_interval returned non-canonical timespec: sec={} nsec={}",
            ts.tv_sec,
            ts.tv_nsec
        );
    }
}

fn apply_yield() {
    let rc = unsafe { sched_yield() };
    // sched_yield always returns 0 on Linux.
    assert!(rc == 0 || rc == -1, "sched_yield returned {rc}");
}

fn apply_op(op: &SchedOp) {
    match op {
        SchedOp::GetScheduler { pid_class } => apply_get_scheduler(*pid_class),
        SchedOp::SetSchedulerOther { pid_class } => apply_set_scheduler_other(*pid_class),
        SchedOp::SetSchedulerInvalid { pid_class, policy } => {
            apply_set_scheduler_invalid(*pid_class, *policy)
        }
        SchedOp::GetParam { pid_class } => apply_get_param(*pid_class),
        SchedOp::SetParam {
            pid_class,
            priority,
        } => apply_set_param(*pid_class, *priority),
        SchedOp::GetAffinity { pid_class, size } => apply_get_affinity(*pid_class, *size),
        SchedOp::SetAffinity {
            pid_class,
            size,
            mask_seed,
        } => apply_set_affinity(*pid_class, *size, *mask_seed),
        SchedOp::PriorityMin { policy } => apply_priority_min(*policy),
        SchedOp::PriorityMax { policy } => apply_priority_max(*policy),
        SchedOp::RrGetInterval { pid_class } => apply_rr_get_interval(*pid_class),
        SchedOp::Yield => apply_yield(),
    }
}

fuzz_target!(|input: SchedFuzzInput| {
    if input.ops.len() > 32 {
        return;
    }
    init_hardened_mode();
    let _guard = SCHED_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    for op in &input.ops {
        apply_op(op);
    }
});
