#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc posix_spawnattr oracle (no spawning)

//! Differential gate for the posix_spawnattr getter/setter round-trips
//! (bd-2uqsly). conformance_diff_posix_spawn.rs exercises spawn *behavior*, but
//! the attribute getters (getflags/getpgroup/getsigmask/getsigdefault/
//! getschedparam/getschedpolicy) had no round-trip gate. Each impl inits its own
//! attr object, sets each attribute, reads it back, and the recovered values are
//! compared vs glibc. No process is spawned. No mocks.

use std::ffi::{c_int, c_short, c_void};
use std::mem::MaybeUninit;

const FLAGS: c_short = 0x3F; // RESETIDS|SETPGROUP|SETSIGDEF|SETSIGMASK|SETSCHEDPARAM|SETSCHEDULER
const PGRP: i32 = 4321;
const SCHED_FIFO: c_int = 1;
const PRIO: c_int = 7;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn posix_spawnattr_init(a: *mut c_void) -> c_int;
        pub fn posix_spawnattr_destroy(a: *mut c_void) -> c_int;
        pub fn posix_spawnattr_setflags(a: *mut c_void, f: c_short) -> c_int;
        pub fn posix_spawnattr_getflags(a: *const c_void, f: *mut c_short) -> c_int;
        pub fn posix_spawnattr_setpgroup(a: *mut c_void, p: i32) -> c_int;
        pub fn posix_spawnattr_getpgroup(a: *const c_void, p: *mut i32) -> c_int;
        pub fn posix_spawnattr_setsigmask(a: *mut c_void, s: *const libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_getsigmask(a: *const c_void, s: *mut libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_setsigdefault(a: *mut c_void, s: *const libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_getsigdefault(a: *const c_void, s: *mut libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_setschedpolicy(a: *mut c_void, p: c_int) -> c_int;
        pub fn posix_spawnattr_getschedpolicy(a: *const c_void, p: *mut c_int) -> c_int;
        pub fn posix_spawnattr_setschedparam(a: *mut c_void, p: *const libc::sched_param) -> c_int;
        pub fn posix_spawnattr_getschedparam(a: *const c_void, p: *mut libc::sched_param) -> c_int;
    }
}
use frankenlibc_abi::process_abi as fl;

fn mkset(sig: c_int) -> libc::sigset_t {
    unsafe {
        let mut s = MaybeUninit::<libc::sigset_t>::zeroed();
        libc::sigemptyset(s.as_mut_ptr());
        libc::sigaddset(s.as_mut_ptr(), sig);
        s.assume_init()
    }
}

/// (flags, pgroup, mask_has_usr1, def_has_usr2, policy, prio); rcs must all be 0.
type R = (c_short, i32, i32, i32, c_int, c_int, [c_int; 7]);

macro_rules! round_trip {
    ($m:ident) => {{
        unsafe {
            let mut attr = MaybeUninit::<libc::posix_spawnattr_t>::zeroed();
            let a = attr.as_mut_ptr() as *mut c_void;
            let ac = attr.as_ptr() as *const c_void;
            let mut rc = [0i32; 7];
            rc[0] = $m::posix_spawnattr_init(a);
            rc[1] = $m::posix_spawnattr_setflags(a, FLAGS);
            let mut flags: c_short = 0;
            $m::posix_spawnattr_getflags(ac, &mut flags);
            rc[2] = $m::posix_spawnattr_setpgroup(a, PGRP);
            let mut pgrp: i32 = -1;
            $m::posix_spawnattr_getpgroup(ac, &mut pgrp);
            let smask = mkset(libc::SIGUSR1);
            rc[3] = $m::posix_spawnattr_setsigmask(a, &smask);
            let mut omask = MaybeUninit::<libc::sigset_t>::zeroed();
            $m::posix_spawnattr_getsigmask(ac, omask.as_mut_ptr());
            let mhas = libc::sigismember(omask.as_ptr(), libc::SIGUSR1);
            let sdef = mkset(libc::SIGUSR2);
            rc[4] = $m::posix_spawnattr_setsigdefault(a, &sdef);
            let mut odef = MaybeUninit::<libc::sigset_t>::zeroed();
            $m::posix_spawnattr_getsigdefault(ac, odef.as_mut_ptr());
            let dhas = libc::sigismember(odef.as_ptr(), libc::SIGUSR2);
            rc[5] = $m::posix_spawnattr_setschedpolicy(a, SCHED_FIFO);
            let mut pol: c_int = -1;
            $m::posix_spawnattr_getschedpolicy(ac, &mut pol);
            let sp = libc::sched_param { sched_priority: PRIO };
            rc[6] = $m::posix_spawnattr_setschedparam(a, &sp);
            let mut osp = MaybeUninit::<libc::sched_param>::zeroed();
            $m::posix_spawnattr_getschedparam(ac, osp.as_mut_ptr());
            let prio = osp.assume_init().sched_priority;
            $m::posix_spawnattr_destroy(a);
            (flags, pgrp, mhas, dhas, pol, prio, rc)
        }
    }};
}

#[test]
fn posix_spawnattr_round_trips_match_glibc() {
    let g: R = round_trip!(g);
    let f: R = round_trip!(fl);
    assert_eq!(f, g, "posix_spawnattr round-trips: fl={f:?} glibc={g:?}");
    assert_eq!((g.0, g.1, g.2, g.3, g.4, g.5), (FLAGS, PGRP, 1, 1, SCHED_FIFO, PRIO), "glibc reference values");
    assert_eq!(g.6, [0; 7], "glibc: all setters/init/destroy return 0");
}
