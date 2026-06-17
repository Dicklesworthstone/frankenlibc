//! Differential gate: getloadavg vs live host glibc.
//!
//! fl returned -1 for nelem <= 0, but glibc opens /proc/loadavg and then loops
//! `for i in 0..min(nelem,3)`, so nelem <= 0 fills nothing and returns 0. We
//! compare the return count for a spread of nelem and the filled load values
//! (same /proc/loadavg snapshot ⇒ identical). glibc is reached via dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::stdlib_abi as fl;
use std::ffi::{c_double, c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}
type Fn_ = unsafe extern "C" fn(*mut c_double, c_int) -> c_int;

fn glibc() -> Fn_ {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"getloadavg".as_ptr()))
    }
}

#[test]
fn getloadavg_count_matches_glibc() {
    let g = glibc();
    let mut mism = Vec::new();
    for nelem in [-2i32, -1, 0, 1, 2, 3, 4, 8] {
        let mut gb = [0f64; 8];
        let mut fb = [0f64; 8];
        let gr = unsafe { g(gb.as_mut_ptr(), nelem) };
        let fr = unsafe { fl::getloadavg(fb.as_mut_ptr(), nelem) };
        if gr != fr {
            mism.push(format!("nelem={nelem}: count glibc={gr} fl={fr}"));
            continue;
        }
        // The filled entries come from the same /proc/loadavg snapshot; allow a
        // tiny tolerance in case the kernel updates between the two reads.
        for i in 0..gr.max(0) as usize {
            if (gb[i] - fb[i]).abs() > 0.5 {
                mism.push(format!("nelem={nelem} idx={i}: glibc={} fl={}", gb[i], fb[i]));
            }
        }
    }
    assert!(mism.is_empty(), "getloadavg diverged:\n{}", mism.join("\n"));
}
