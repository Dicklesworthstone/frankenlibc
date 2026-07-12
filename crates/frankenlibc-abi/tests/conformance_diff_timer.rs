#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc POSIX-timer oracle

//! Differential gate for the POSIX timer family (bd-liwaip): timer_create /
//! timer_settime / timer_gettime / timer_getoverrun / timer_delete — all were
//! ungated. timer_t is opaque and fl's representation differs from glibc's (fl
//! stores the kernel id, glibc a pointer), so timer_t is never cross-passed:
//! each impl runs its OWN create->settime->gettime->getoverrun->delete flow and
//! the return codes + the plausibility of the remaining time are compared.
//! SIGEV_NONE is used so no signal is delivered. The invalid-clockid error path
//! is compared exactly. No mocks.

use std::ffi::{c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn timer_create(
            clockid: libc::clockid_t,
            sevp: *mut libc::sigevent,
            t: *mut libc::timer_t,
        ) -> c_int;
        pub fn timer_settime(
            t: libc::timer_t,
            flags: c_int,
            new: *const libc::itimerspec,
            old: *mut libc::itimerspec,
        ) -> c_int;
        pub fn timer_gettime(t: libc::timer_t, cur: *mut libc::itimerspec) -> c_int;
        pub fn timer_getoverrun(t: libc::timer_t) -> c_int;
        pub fn timer_delete(t: libc::timer_t) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}
use frankenlibc_abi::unistd_abi as fl;

fn zeroed_sev_none() -> libc::sigevent {
    let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
    sev.sigev_notify = libc::SIGEV_NONE;
    sev
}

/// glibc happy-path flow; returns (create_rc, settime_rc, gettime_rc, remaining_secs, overrun, delete_rc).
fn glibc_flow() -> (c_int, c_int, c_int, i64, c_int, c_int) {
    unsafe {
        let mut sev = zeroed_sev_none();
        let mut tid: libc::timer_t = std::mem::zeroed();
        let c = g::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut tid);
        let its = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 100,
                tv_nsec: 0,
            },
        };
        let s = g::timer_settime(tid, 0, &its, std::ptr::null_mut());
        let mut cur: libc::itimerspec = std::mem::zeroed();
        let gt = g::timer_gettime(tid, &mut cur);
        let ov = g::timer_getoverrun(tid);
        let d = g::timer_delete(tid);
        (c, s, gt, cur.it_value.tv_sec, ov, d)
    }
}

fn fl_flow() -> (c_int, c_int, c_int, i64, c_int, c_int) {
    unsafe {
        let mut sev = zeroed_sev_none();
        let mut tid: libc::timer_t = std::mem::zeroed();
        let c = fl::timer_create(
            libc::CLOCK_MONOTONIC,
            &mut sev as *mut _ as *mut c_void,
            &mut tid as *mut _ as *mut c_void,
        );
        let its = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 100,
                tv_nsec: 0,
            },
        };
        let s = fl::timer_settime(
            tid as *mut c_void,
            0,
            &its as *const _ as *const c_void,
            std::ptr::null_mut(),
        );
        let mut cur: libc::itimerspec = std::mem::zeroed();
        let gt = fl::timer_gettime(tid as *mut c_void, &mut cur as *mut _ as *mut c_void);
        let ov = fl::timer_getoverrun(tid as *mut c_void);
        let d = fl::timer_delete(tid as *mut c_void);
        (c, s, gt, cur.it_value.tv_sec, ov, d)
    }
}

#[test]
fn timer_flow_matches_glibc() {
    let g = glibc_flow();
    let f = fl_flow();
    // Return codes + overrun must match; remaining time must be plausibly in
    // (95, 100] for both (timing differs, so not cross-equal).
    assert_eq!(
        (f.0, f.1, f.2, f.4, f.5),
        (g.0, g.1, g.2, g.4, g.5),
        "timer flow rcs: fl={f:?} glibc={g:?}"
    );
    assert_eq!(g.0, 0, "glibc timer_create should succeed");
    for (who, secs) in [("glibc", g.3), ("fl", f.3)] {
        assert!(
            (95..=100).contains(&secs),
            "{who} remaining {secs}s not in (95,100]"
        );
    }
}

#[test]
fn timer_create_invalid_clockid_matches_glibc() {
    let bad: libc::clockid_t = 0x7fff_ffff;
    let g = unsafe {
        let mut sev = zeroed_sev_none();
        let mut tid: libc::timer_t = std::mem::zeroed();
        *g::__errno_location() = 0;
        let rc = g::timer_create(bad, &mut sev, &mut tid);
        (rc, *g::__errno_location())
    };
    let f = unsafe {
        let mut sev = zeroed_sev_none();
        let mut tid: libc::timer_t = std::mem::zeroed();
        *g::__errno_location() = 0;
        let rc = fl::timer_create(
            bad,
            &mut sev as *mut _ as *mut c_void,
            &mut tid as *mut _ as *mut c_void,
        );
        (rc, *g::__errno_location())
    };
    assert_eq!(f, g, "timer_create(bad clockid): fl={f:?} glibc={g:?}");
    assert_eq!(g.0, -1, "glibc rejects bad clockid");
}
