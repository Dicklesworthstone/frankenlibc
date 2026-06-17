//! Differential gate: mallopt return contract vs live host glibc.
//!
//! fl's allocator ignores mallopt tuning, but the RETURN value must match glibc:
//! only M_MXFAST (param 1) is range-validated (value in [0, MAX_FAST_SIZE]); all
//! other params return 1. fl previously returned 1 unconditionally, diverging on
//! M_MXFAST with an out-of-range value. glibc is reached via dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::malloc_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}
type MalloptFn = unsafe extern "C" fn(c_int, c_int) -> c_int;

fn glibc_mallopt() -> MalloptFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"mallopt".as_ptr()))
    }
}

#[test]
fn mallopt_return_contract_matches_glibc() {
    let g = glibc_mallopt();
    let params = [
        -10i32, -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 999, -100, i32::MAX, i32::MIN,
    ];
    let values = [
        -100i32, -1, 0, 1, 2, 80, 159, 160, 161, 162, 1024, 131072, i32::MAX,
    ];
    let mut mism = Vec::new();
    for &p in &params {
        for &v in &values {
            // NOTE: glibc mallopt actually applies tuning to the live allocator.
            // We only compare the documented return value; it is deterministic
            // per (param, value) and independent of allocator state here.
            let gr = unsafe { g(p, v) };
            let fr = unsafe { fl::mallopt(p, v) };
            if gr != fr && mism.len() < 40 {
                mism.push(format!("mallopt(param={p}, value={v}): glibc={gr} fl={fr}"));
            }
        }
    }
    assert!(mism.is_empty(), "mallopt diverged ({}):\n{}", mism.len(), mism.join("\n"));
}
