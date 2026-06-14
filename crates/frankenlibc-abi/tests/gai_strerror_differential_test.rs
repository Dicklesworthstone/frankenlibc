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
    // -20..=5 covers the standard EAI_* codes and the unknown fallback;
    // -110..=-95 covers the GNU getaddrinfo_a / IDN extensions
    // (EAI_INPROGRESS=-100 .. EAI_IDN_ENCODE=-105), which the original range
    // missed.
    let codes = (-20..=5).chain(-110..=-95);
    for code in codes {
        let f = unsafe { CStr::from_ptr(fl::gai_strerror(code)) }
            .to_string_lossy()
            .into_owned();
        let g = unsafe { CStr::from_ptr(gai_strerror(code)) }
            .to_string_lossy()
            .into_owned();
        if f != g {
            fails.push(format!("gai_strerror({code}): fl={f:?} glibc={g:?}"));
        }
    }
    assert!(
        fails.is_empty(),
        "gai_strerror diverged from glibc:\n{}",
        fails.join("\n")
    );
}
