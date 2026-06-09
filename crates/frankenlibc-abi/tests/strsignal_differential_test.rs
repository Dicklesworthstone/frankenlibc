#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strsignal oracle

//! Differential test for `strsignal` vs host glibc across the full signal-number
//! range, including the standard signals (1..31), the glibc-reserved slots
//! (32/33), the real-time range ("Real-time signal N"), and out-of-range /
//! negative codes ("Unknown signal N"). Compares the rendered description bytes.

use std::ffi::CStr;

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn strsignal(sig: libc::c_int) -> *mut libc::c_char;
}

fn fl_str(sig: i32) -> String {
    let p = unsafe { fl::strsignal(sig) };
    if p.is_null() {
        return "<NULL>".into();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn lc_str(sig: i32) -> String {
    let p = unsafe { strsignal(sig) };
    if p.is_null() {
        return "<NULL>".into();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[test]
fn strsignal_matches_glibc_full_range() {
    let mut fails = Vec::new();
    for sig in -5..=70 {
        let f = fl_str(sig);
        let g = lc_str(sig);
        if f != g {
            fails.push(format!("strsignal({sig}): fl={f:?} glibc={g:?}"));
        }
    }
    assert!(fails.is_empty(), "strsignal diverged from glibc:\n{}", fails.join("\n"));
}
