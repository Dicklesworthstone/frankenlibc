#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strerror oracle (libc, linked by std)

//! Exhaustive differential scan of the error-string functions
//! `strerror` / `strerrorname_np` / `strerrordesc_np` (errno 0..=140) plus
//! `gai_strerror` (EAI codes) and `hstrerror` (h_errno) vs host glibc. The GNU
//! `*_np` variants are newer (glibc 2.32+) and easy to have gaps / wrong macro
//! names; strerror's "Unknown error N" wording and out-of-range handling are
//! also bug-prone. All are deterministic, stateless strings.

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_abi::resolv_abi::gai_strerror as fl_gai_strerror;
use frankenlibc_abi::string_abi::{
    strerror as fl_strerror, strerrordesc_np as fl_strerrordesc_np,
    strerrorname_np as fl_strerrorname_np,
};
use frankenlibc_abi::unistd_abi::hstrerror as fl_hstrerror;

unsafe extern "C" {
    fn strerror(errnum: c_int) -> *mut c_char;
    fn strerrorname_np(errnum: c_int) -> *const c_char;
    fn strerrordesc_np(errnum: c_int) -> *const c_char;
    fn gai_strerror(ecode: c_int) -> *const c_char;
    fn hstrerror(err: c_int) -> *const c_char;
}

fn s(p: *const c_char) -> String {
    if p.is_null() {
        return "<null>".into();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[test]
fn strerror_family_matches_host_glibc() {
    let mut divs: Vec<String> = Vec::new();
    for e in -2..=140i32 {
        let f = s(unsafe { fl_strerror(e) });
        let h = s(unsafe { strerror(e) });
        if f != h {
            divs.push(format!("strerror({e}): fl={f:?} glibc={h:?}"));
        }
        let f = s(unsafe { fl_strerrorname_np(e) });
        let h = s(unsafe { strerrorname_np(e) });
        if f != h {
            divs.push(format!("strerrorname_np({e}): fl={f:?} glibc={h:?}"));
        }
        let f = s(unsafe { fl_strerrordesc_np(e) });
        let h = s(unsafe { strerrordesc_np(e) });
        if f != h {
            divs.push(format!("strerrordesc_np({e}): fl={f:?} glibc={h:?}"));
        }
    }
    for e in -2..=20i32 {
        let f = s(unsafe { fl_gai_strerror(e) });
        let h = s(unsafe { gai_strerror(e) });
        if f != h {
            divs.push(format!("gai_strerror({e}): fl={f:?} glibc={h:?}"));
        }
    }
    for e in -2..=10i32 {
        let f = s(unsafe { fl_hstrerror(e) });
        let h = s(unsafe { hstrerror(e) });
        if f != h {
            divs.push(format!("hstrerror({e}): fl={f:?} glibc={h:?}"));
        }
    }
    assert!(
        divs.is_empty(),
        "error strings diverged from host glibc on {} case(s):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("strerror family scan: errno -2..=140 + gai/h, 0 divergences vs host glibc");
}
