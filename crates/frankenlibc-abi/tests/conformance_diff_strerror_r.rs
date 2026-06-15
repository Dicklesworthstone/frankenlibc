//! Differential gate: the GNU `strerror_r` (the bare exported symbol) returns
//! `char *`, not `int`.
//!
//! glibc's default `_GNU_SOURCE` `strerror_r` returns a pointer to the message:
//! a static immutable string for a known errno (leaving `buf` untouched) or
//! `buf` itself, holding "Unknown error N", for an unknown one. fl previously
//! exported the XSI int-returning behavior under this symbol, so a `_GNU_SOURCE`
//! caller read the int as a pointer. This compares fl against the live host
//! glibc (via dlsym) on message content and the static-vs-buffer return
//! behavior.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type StrerrorRFn = extern "C" fn(c_int, *mut c_char, usize) -> *mut c_char;

#[test]
fn strerror_r_gnu_matches_glibc() {
    let g: StrerrorRFn = unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen libc.so.6 failed");
        let s = dlsym(lib, c"strerror_r".as_ptr());
        assert!(!s.is_null(), "dlsym strerror_r failed");
        std::mem::transmute::<*mut c_void, StrerrorRFn>(s)
    };

    // Known errnos across the Linux range, plus unknown/edge ones.
    let codes: Vec<c_int> = (0..40)
        .chain([95, 100, 125, 131, 133].into_iter())
        .chain([99999, -5, 134, 4095].into_iter())
        .collect();

    let mut mismatches = Vec::new();
    for code in codes {
        let mut gbuf = [0u8; 256];
        let gp = g(code, gbuf.as_mut_ptr() as *mut c_char, gbuf.len());
        let gmsg = unsafe { CStr::from_ptr(gp) }.to_bytes().to_vec();
        let g_is_buf = gp == gbuf.as_mut_ptr() as *mut c_char;

        let mut fbuf = [0u8; 256];
        let fp = unsafe { fl::strerror_r(code, fbuf.as_mut_ptr() as *mut c_char, fbuf.len()) };
        let fmsg = unsafe { CStr::from_ptr(fp) }.to_bytes().to_vec();
        let f_is_buf = fp == fbuf.as_mut_ptr() as *mut c_char;

        if gmsg != fmsg {
            mismatches.push(format!(
                "errno {code}: msg glibc={:?} fl={:?}",
                String::from_utf8_lossy(&gmsg),
                String::from_utf8_lossy(&fmsg)
            ));
        }
        // Static-vs-buffer return behavior must also agree (known -> static,
        // unknown -> caller buffer).
        if g_is_buf != f_is_buf {
            mismatches.push(format!(
                "errno {code}: returns-buffer glibc={g_is_buf} fl={f_is_buf}"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "GNU strerror_r diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
