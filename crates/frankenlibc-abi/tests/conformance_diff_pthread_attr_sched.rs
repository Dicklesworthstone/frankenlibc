#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pthread_attr oracle (no thread creation)

//! Differential gate for the pthread_attr SCHEDULING getter round-trips
//! (bd-5jdlyz). conformance_diff_pthread_attr.rs covers detachstate/guardsize/
//! stacksize and the errno gate covers the scheduling SETTERS' error paths, but
//! the set->get round-trips for inheritsched / schedpolicy / schedparam / scope
//! were ungated. Each impl inits its own attr, sets each scheduling attribute,
//! reads it back, and the recovered values + setter rcs are compared vs glibc.
//! No thread is created. No mocks.

use std::ffi::c_int;
use std::mem::MaybeUninit;

const PTHREAD_EXPLICIT_SCHED: c_int = 1;
const SCHED_FIFO: c_int = 1;
const PTHREAD_SCOPE_SYSTEM: c_int = 0;
const PRIO: c_int = 10;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn pthread_attr_init(a: *mut libc::pthread_attr_t) -> c_int;
        pub fn pthread_attr_destroy(a: *mut libc::pthread_attr_t) -> c_int;
        pub fn pthread_attr_setinheritsched(a: *mut libc::pthread_attr_t, v: c_int) -> c_int;
        pub fn pthread_attr_getinheritsched(a: *const libc::pthread_attr_t, v: *mut c_int) -> c_int;
        pub fn pthread_attr_setschedpolicy(a: *mut libc::pthread_attr_t, v: c_int) -> c_int;
        pub fn pthread_attr_getschedpolicy(a: *const libc::pthread_attr_t, v: *mut c_int) -> c_int;
        pub fn pthread_attr_setschedparam(a: *mut libc::pthread_attr_t, p: *const libc::sched_param) -> c_int;
        pub fn pthread_attr_getschedparam(a: *const libc::pthread_attr_t, p: *mut libc::sched_param) -> c_int;
        pub fn pthread_attr_setscope(a: *mut libc::pthread_attr_t, v: c_int) -> c_int;
        pub fn pthread_attr_getscope(a: *const libc::pthread_attr_t, v: *mut c_int) -> c_int;
    }
}
use frankenlibc_abi::pthread_abi as fl;

/// (inheritsched, policy, prio, scope, setter_rcs)
type R = (c_int, c_int, c_int, c_int, [c_int; 6]);

macro_rules! round_trip {
    ($m:ident) => {{
        unsafe {
            let mut attr = MaybeUninit::<libc::pthread_attr_t>::zeroed();
            let a = attr.as_mut_ptr();
            let ac = attr.as_ptr();
            let mut rc = [0i32; 6];
            rc[0] = $m::pthread_attr_init(a);
            rc[1] = $m::pthread_attr_setinheritsched(a, PTHREAD_EXPLICIT_SCHED);
            let mut inh = -1;
            $m::pthread_attr_getinheritsched(ac, &mut inh);
            rc[2] = $m::pthread_attr_setschedpolicy(a, SCHED_FIFO);
            let mut pol = -1;
            $m::pthread_attr_getschedpolicy(ac, &mut pol);
            let sp = libc::sched_param { sched_priority: PRIO };
            rc[3] = $m::pthread_attr_setschedparam(a, &sp);
            let mut osp = MaybeUninit::<libc::sched_param>::zeroed();
            $m::pthread_attr_getschedparam(ac, osp.as_mut_ptr());
            let prio = osp.assume_init().sched_priority;
            rc[4] = $m::pthread_attr_setscope(a, PTHREAD_SCOPE_SYSTEM);
            let mut scope = -1;
            $m::pthread_attr_getscope(ac, &mut scope);
            rc[5] = $m::pthread_attr_destroy(a);
            (inh, pol, prio, scope, rc)
        }
    }};
}

#[test]
fn pthread_attr_sched_round_trips_match_glibc() {
    let g: R = round_trip!(g);
    let f: R = round_trip!(fl);
    assert_eq!(f, g, "pthread_attr sched round-trips: fl={f:?} glibc={g:?}");
    assert_eq!((g.0, g.1, g.2, g.3), (PTHREAD_EXPLICIT_SCHED, SCHED_FIFO, PRIO, PTHREAD_SCOPE_SYSTEM), "glibc reference");
    assert_eq!(g.4, [0; 6], "glibc: all init/setters/destroy return 0");
}
