#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strptime oracle

//! Focused differential gate for strptime's timezone directives (bd-zw4a7s):
//!   %Z — consume leading whitespace then a run of non-whitespace, no
//!        interpretation, never fails (glibc time/strptime_l.c case 'Z').
//!   %z — [+-]HH[[:]MM] or 'Z' (==+0000), setting tm_gmtoff.
//! Compares, for each input: whether the parse succeeded, the number of bytes
//! consumed, and tm_gmtoff, vs glibc. No mocks.

use std::ffi::{c_char, CString};

unsafe extern "C" {
    fn strptime(s: *const c_char, fmt: *const c_char, tm: *mut libc::tm) -> *mut c_char;
}

/// (consumed-bytes or -1 on NULL, tm_gmtoff)
fn run_glibc(input: &str, fmt: &str) -> (isize, i64) {
    let ci = CString::new(input).unwrap();
    let cf = CString::new(fmt).unwrap();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { strptime(ci.as_ptr(), cf.as_ptr(), &mut tm) };
    let consumed = if end.is_null() { -1 } else { (end as usize - ci.as_ptr() as usize) as isize };
    (consumed, tm.tm_gmtoff)
}

fn run_fl(input: &str, fmt: &str) -> (isize, i64) {
    let ci = CString::new(input).unwrap();
    let cf = CString::new(fmt).unwrap();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe {
        frankenlibc_abi::time_abi::strptime(ci.as_ptr(), cf.as_ptr(), &mut tm)
    };
    let consumed = if end.is_null() { -1 } else { (end as usize - ci.as_ptr() as usize) as isize };
    (consumed, tm.tm_gmtoff)
}

#[test]
fn strptime_tz_directives_match_glibc() {
    let cases: &[(&str, &str)] = &[
        // %Z: consume a non-whitespace run, no interpretation
        ("UTC", "%Z"),
        ("GMT rest", "%Z rest"),
        ("America/New_York", "%Z"),
        ("EST5EDT", "%Z"),
        ("  PST", "%Z"),            // leading whitespace skipped
        ("", "%Z"),                 // empty token at EOF still succeeds
        ("PST 2024", "%Z %Y"),      // %Z then a year
        // %z: numeric offset forms
        ("+0530", "%z"),
        ("-0800", "%z"),
        ("Z", "%z"),
        ("+05:30", "%z"),
        ("+05", "%z"),
        ("+0000", "%z"),
        ("-0000", "%z"),
        ("garbage", "%z"),          // invalid offset -> NULL
    ];
    for &(input, fmt) in cases {
        let g = run_glibc(input, fmt);
        let f = run_fl(input, fmt);
        assert_eq!(f, g, "strptime({input:?}, {fmt:?}): fl=(consumed {}, gmtoff {}) glibc=(consumed {}, gmtoff {})", f.0, f.1, g.0, g.1);
    }
}
