#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle

//! `printf` NULL `%s`/`%ls` precision parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc substitutes "(null)" for a NULL string argument, but only when the
//! precision is unspecified or at least 6 (the length of "(null)"); a smaller
//! precision yields the empty string, NOT a truncated "(nu". fl previously fed
//! "(null)" through the precision-truncation path. This gate compares the
//! rendered output (and return value) for the NULL-pointer string conversions
//! across a precision/width matrix.

use std::ffi::{CString, c_char, c_void};
use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn snprintf(b: *mut c_char, s: usize, f: *const c_char, ...) -> i32;
}

fn render(eng: u8, fmt: &str) -> (i32, String) {
    let cf = CString::new(fmt).unwrap();
    let mut b = [0u8; 64];
    let n = if eng == 0 {
        unsafe { fl::snprintf(b.as_mut_ptr() as *mut c_char, 64, cf.as_ptr(), std::ptr::null::<c_void>()) }
    } else {
        unsafe { snprintf(b.as_mut_ptr() as *mut c_char, 64, cf.as_ptr(), std::ptr::null::<c_void>()) }
    };
    (n, String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned())
}

#[test]
fn printf_null_string_precision_matches_glibc() {
    let fmts = [
        "%s", "%.0s", "%.1s", "%.3s", "%.4s", "%.5s", "%.6s", "%.7s", "%.10s",
        "%10s", "%-10s|", "%5.3s", "%-8.2s|", "%6.6s", "%.6s|", "%2.0s|",
        // %ls follows the same NULL substitution.
        "%ls", "%.3ls", "%.6ls", "%5.2ls",
    ];
    for fmt in fmts {
        let a = render(0, fmt);
        let b = render(1, fmt);
        assert_eq!(a, b, "snprintf({fmt:?}, NULL): fl={a:?} glibc={b:?}");
    }
}
