#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pthread barrierattr/condattr oracle

//! Differential gate for the pthread barrierattr / condattr round-trips
//! (bd-s79pk9) — barrierattr (pshared) and condattr (pshared, clock) had no
//! round-trip gate. Each impl inits its own attr object, sets process-shared
//! both ways (PRIVATE then SHARED) and the condattr clock (MONOTONIC), reads
//! each back, and the recovered values + rcs are compared vs glibc. No mocks.

use std::ffi::c_int;
use std::mem::MaybeUninit;

const PTHREAD_PROCESS_PRIVATE: c_int = 0;
const PTHREAD_PROCESS_SHARED: c_int = 1;
const CLOCK_MONOTONIC: c_int = 1;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn pthread_barrierattr_init(a: *mut libc::pthread_barrierattr_t) -> c_int;
        pub fn pthread_barrierattr_destroy(a: *mut libc::pthread_barrierattr_t) -> c_int;
        pub fn pthread_barrierattr_setpshared(
            a: *mut libc::pthread_barrierattr_t,
            v: c_int,
        ) -> c_int;
        pub fn pthread_barrierattr_getpshared(
            a: *const libc::pthread_barrierattr_t,
            v: *mut c_int,
        ) -> c_int;
        pub fn pthread_condattr_init(a: *mut libc::pthread_condattr_t) -> c_int;
        pub fn pthread_condattr_destroy(a: *mut libc::pthread_condattr_t) -> c_int;
        pub fn pthread_condattr_setpshared(a: *mut libc::pthread_condattr_t, v: c_int) -> c_int;
        pub fn pthread_condattr_getpshared(
            a: *const libc::pthread_condattr_t,
            v: *mut c_int,
        ) -> c_int;
        pub fn pthread_condattr_setclock(
            a: *mut libc::pthread_condattr_t,
            v: libc::clockid_t,
        ) -> c_int;
        pub fn pthread_condattr_getclock(
            a: *const libc::pthread_condattr_t,
            v: *mut libc::clockid_t,
        ) -> c_int;
    }
}
use frankenlibc_abi::pthread_abi as fl;

/// barrier: (pshared_after_private, pshared_after_shared, [init,set_priv,set_shared,destroy] rcs)
type B = (c_int, c_int, [c_int; 4]);
/// cond: (pshared_after_shared, clock_after_monotonic, [init,set_pshared,set_clock,destroy] rcs)
type C = (c_int, libc::clockid_t, [c_int; 4]);

macro_rules! barrier {
    ($m:ident) => {{
        unsafe {
            let mut a = MaybeUninit::<libc::pthread_barrierattr_t>::zeroed();
            let p = a.as_mut_ptr();
            let pc = a.as_ptr();
            let mut rc = [0i32; 4];
            rc[0] = $m::pthread_barrierattr_init(p);
            rc[1] = $m::pthread_barrierattr_setpshared(p, PTHREAD_PROCESS_PRIVATE);
            let mut v1 = -1;
            $m::pthread_barrierattr_getpshared(pc, &mut v1);
            rc[2] = $m::pthread_barrierattr_setpshared(p, PTHREAD_PROCESS_SHARED);
            let mut v2 = -1;
            $m::pthread_barrierattr_getpshared(pc, &mut v2);
            rc[3] = $m::pthread_barrierattr_destroy(p);
            (v1, v2, rc)
        }
    }};
}
macro_rules! cond {
    ($m:ident) => {{
        unsafe {
            let mut a = MaybeUninit::<libc::pthread_condattr_t>::zeroed();
            let p = a.as_mut_ptr();
            let pc = a.as_ptr();
            let mut rc = [0i32; 4];
            rc[0] = $m::pthread_condattr_init(p);
            rc[1] = $m::pthread_condattr_setpshared(p, PTHREAD_PROCESS_SHARED);
            let mut sh = -1;
            $m::pthread_condattr_getpshared(pc, &mut sh);
            rc[2] = $m::pthread_condattr_setclock(p, CLOCK_MONOTONIC as libc::clockid_t);
            let mut clk = -1;
            $m::pthread_condattr_getclock(pc, &mut clk);
            rc[3] = $m::pthread_condattr_destroy(p);
            (sh, clk, rc)
        }
    }};
}

#[test]
fn barrierattr_pshared_matches_glibc() {
    let g: B = barrier!(g);
    let f: B = barrier!(fl);
    assert_eq!(f, g, "barrierattr pshared: fl={f:?} glibc={g:?}");
    assert_eq!(
        (g.0, g.1),
        (PTHREAD_PROCESS_PRIVATE, PTHREAD_PROCESS_SHARED),
        "glibc reference"
    );
    assert_eq!(g.2, [0; 4], "glibc: all rcs 0");
}

#[test]
fn condattr_pshared_clock_matches_glibc() {
    let g: C = cond!(g);
    let f: C = cond!(fl);
    assert_eq!(f, g, "condattr pshared+clock: fl={f:?} glibc={g:?}");
    assert_eq!(
        (g.0, g.1),
        (PTHREAD_PROCESS_SHARED, CLOCK_MONOTONIC as libc::clockid_t),
        "glibc reference"
    );
    assert_eq!(g.2, [0; 4], "glibc: all rcs 0");
}
