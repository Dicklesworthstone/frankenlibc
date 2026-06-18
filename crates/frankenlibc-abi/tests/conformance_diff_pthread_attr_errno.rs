#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pthread *attr oracle

//! Differential gate for invalid-value error codes across the pthread *attr
//! setter family (bd-5cbz3r). conformance_diff_pthread_attr covers
//! setdetachstate/stacksize invalid cases, but not the rest — which is the gap
//! that hid the setscope EINVAL-vs-ENOTSUP bug (bd-9bmtq2). For each setter, an
//! invalid value must yield the SAME return code as glibc (EINVAL, except
//! setscope's PTHREAD_SCOPE_PROCESS which is ENOTSUP). No mocks.

use std::ffi::{c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn pthread_attr_init(a: *mut c_void) -> c_int;
        pub fn pthread_attr_destroy(a: *mut c_void) -> c_int;
        pub fn pthread_attr_setinheritsched(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_attr_setschedpolicy(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_attr_setscope(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_mutexattr_init(a: *mut c_void) -> c_int;
        pub fn pthread_mutexattr_destroy(a: *mut c_void) -> c_int;
        pub fn pthread_mutexattr_settype(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_mutexattr_setprotocol(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_mutexattr_setpshared(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_mutexattr_setrobust(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_condattr_init(a: *mut c_void) -> c_int;
        pub fn pthread_condattr_destroy(a: *mut c_void) -> c_int;
        pub fn pthread_condattr_setclock(a: *mut c_void, v: c_int) -> c_int;
        pub fn pthread_rwlockattr_init(a: *mut c_void) -> c_int;
        pub fn pthread_rwlockattr_destroy(a: *mut c_void) -> c_int;
        pub fn pthread_rwlockattr_setkind_np(a: *mut c_void, v: c_int) -> c_int;
    }
}
use frankenlibc_abi::glibc_internal_abi as fge;
use frankenlibc_abi::pthread_abi as fp;

// A generously-sized, aligned attr buffer usable for any pthread *attr_t.
#[repr(C, align(16))]
struct Attr([u8; 64]);
fn buf() -> Attr {
    Attr([0u8; 64])
}

macro_rules! diff_attr {
    ($name:literal, $ginit:path, $gdestroy:path, $gset:path, $finit:path, $fdestroy:path, $fset:path, $val:expr) => {{
        let mut ga = buf();
        let mut fa = buf();
        unsafe {
            $ginit((&mut ga as *mut Attr).cast());
            $finit((&mut fa as *mut Attr).cast());
            let gr = $gset((&mut ga as *mut Attr).cast(), $val);
            let fr = $fset((&mut fa as *mut Attr).cast(), $val);
            $gdestroy((&mut ga as *mut Attr).cast());
            $fdestroy((&mut fa as *mut Attr).cast());
            assert_eq!(fr, gr, "{}({}) rc: fl={fr} glibc={gr}", $name, $val);
        }
    }};
}

#[test]
fn pthread_attr_setters_invalid_errno_match_glibc() {
    // pthread_attr_*
    for v in [99, -1, 7, c_int::MAX] {
        diff_attr!("attr_setinheritsched", g::pthread_attr_init, g::pthread_attr_destroy, g::pthread_attr_setinheritsched,
            fp::pthread_attr_init, fp::pthread_attr_destroy, fp::pthread_attr_setinheritsched, v);
        diff_attr!("attr_setschedpolicy", g::pthread_attr_init, g::pthread_attr_destroy, g::pthread_attr_setschedpolicy,
            fp::pthread_attr_init, fp::pthread_attr_destroy, fp::pthread_attr_setschedpolicy, v);
        // setscope: PROCESS(1)=ENOTSUP, others=EINVAL, SYSTEM(0)=ok
        diff_attr!("attr_setscope", g::pthread_attr_init, g::pthread_attr_destroy, g::pthread_attr_setscope,
            fp::pthread_attr_init, fp::pthread_attr_destroy, fp::pthread_attr_setscope, v);
    }
    // mutexattr
    for v in [99, -1, 7] {
        diff_attr!("mutexattr_settype", g::pthread_mutexattr_init, g::pthread_mutexattr_destroy, g::pthread_mutexattr_settype,
            fp::pthread_mutexattr_init, fp::pthread_mutexattr_destroy, fp::pthread_mutexattr_settype, v);
        diff_attr!("mutexattr_setprotocol", g::pthread_mutexattr_init, g::pthread_mutexattr_destroy, g::pthread_mutexattr_setprotocol,
            fp::pthread_mutexattr_init, fp::pthread_mutexattr_destroy, fp::pthread_mutexattr_setprotocol, v);
        diff_attr!("mutexattr_setpshared", g::pthread_mutexattr_init, g::pthread_mutexattr_destroy, g::pthread_mutexattr_setpshared,
            fp::pthread_mutexattr_init, fp::pthread_mutexattr_destroy, fp::pthread_mutexattr_setpshared, v);
        diff_attr!("mutexattr_setrobust", g::pthread_mutexattr_init, g::pthread_mutexattr_destroy, g::pthread_mutexattr_setrobust,
            fp::pthread_mutexattr_init, fp::pthread_mutexattr_destroy, fp::pthread_mutexattr_setrobust, v);
    }
    // condattr / rwlockattr
    for v in [99, -1, 7] {
        diff_attr!("condattr_setclock", g::pthread_condattr_init, g::pthread_condattr_destroy, g::pthread_condattr_setclock,
            fp::pthread_condattr_init, fp::pthread_condattr_destroy, fp::pthread_condattr_setclock, v);
        diff_attr!("rwlockattr_setkind_np", g::pthread_rwlockattr_init, g::pthread_rwlockattr_destroy, g::pthread_rwlockattr_setkind_np,
            fp::pthread_rwlockattr_init, fp::pthread_rwlockattr_destroy, fge::pthread_rwlockattr_setkind_np, v);
    }
}
