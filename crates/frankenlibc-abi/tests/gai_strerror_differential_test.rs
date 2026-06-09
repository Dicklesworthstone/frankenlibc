#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc gai_strerror oracle

//! Differential test for `gai_strerror` (getaddrinfo EAI_* error strings) vs
//! host glibc across the full code range, including the unknown fallback.

use std::ffi::CStr;

use frankenlibc_abi::resolv_abi as fl;

unsafe extern "C" {
    fn gai_strerror(errcode: libc::c_int) -> *const libc::c_char;
}

#[test]
fn gai_strerror_matches_glibc() {
    let mut fails = Vec::new();
    for code in -20..=5 {
        let f = unsafe { CStr::from_ptr(fl::gai_strerror(code)) }.to_string_lossy().into_owned();
        let g = unsafe { CStr::from_ptr(gai_strerror(code)) }.to_string_lossy().into_owned();
        if f != g {
            fails.push(format!("gai_strerror({code}): fl={f:?} glibc={g:?}"));
        }
    }
    assert!(fails.is_empty(), "gai_strerror diverged from glibc:\n{}", fails.join("\n"));
}
