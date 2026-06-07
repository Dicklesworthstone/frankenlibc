#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc signal-string oracle (libc, linked by std)

//! Exhaustive differential scan of the signal-description functions
//! `strsignal` / `sigdescr_np` / `sigabbrev_np` over the full signal-number
//! range (incl. real-time signals and out-of-range values) vs host glibc.
//! These return NUL/NULL-terminated strings and are deterministic; the bug-prone
//! cases are real-time signals (RTMIN..RTMAX numbering / "RTn" abbreviations),
//! the "Unknown signal"/"Real-time signal" wording, and NULL vs string on
//! invalid input.

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_abi::string_abi::strsignal as fl_strsignal;
use frankenlibc_abi::signal_abi::{sigabbrev_np as fl_sigabbrev_np, sigdescr_np as fl_sigdescr_np};

unsafe extern "C" {
    fn strsignal(sig: c_int) -> *mut c_char;
    fn sigdescr_np(sig: c_int) -> *const c_char;
    fn sigabbrev_np(sig: c_int) -> *const c_char;
}

fn s(p: *const c_char) -> String {
    if p.is_null() {
        return "<null>".into();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[test]
fn signal_strings_match_host_glibc() {
    let mut divs: Vec<String> = Vec::new();
    for sig in -2..=70i32 {
        let fl_ss = s(unsafe { fl_strsignal(sig) });
        let h_ss = s(unsafe { strsignal(sig) });
        if fl_ss != h_ss {
            divs.push(format!("strsignal({sig}): fl={fl_ss:?} glibc={h_ss:?}"));
        }
        let fl_d = s(unsafe { fl_sigdescr_np(sig) });
        let h_d = s(unsafe { sigdescr_np(sig) });
        if fl_d != h_d {
            divs.push(format!("sigdescr_np({sig}): fl={fl_d:?} glibc={h_d:?}"));
        }
        let fl_a = s(unsafe { fl_sigabbrev_np(sig) });
        let h_a = s(unsafe { sigabbrev_np(sig) });
        if fl_a != h_a {
            divs.push(format!("sigabbrev_np({sig}): fl={fl_a:?} glibc={h_a:?}"));
        }
    }
    assert!(
        divs.is_empty(),
        "signal strings diverged from host glibc on {} case(s):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("signal strings scan: -2..=70, 0 divergences vs host glibc");
}
