#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strptime oracle

//! `strptime` `%Z` (timezone name) parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc's `%Z` consumes — but does not interpret — a timezone name: it skips
//! leading whitespace, then consumes a run of non-whitespace bytes (letters,
//! digits, '/', '_', …), performs no conversion, and never fails (even an empty
//! token at end-of-input succeeds). fl previously had no `%Z` case and rejected
//! any format containing it. This gate drives both engines and compares match
//! success + the number of input bytes consumed (the return-pointer offset),
//! plus that a following directive keeps parsing.

use frankenlibc_abi::time_abi as flt;
use std::ffi::CString;

unsafe extern "C" {
    fn strptime(s: *const i8, f: *const i8, tm: *mut libc::tm) -> *mut i8;
    fn setlocale(c: i32, l: *const i8) -> *mut i8;
    fn tzset();
}

// (matched, consumed-bytes, mon, mday, year)
fn run(eng: u8, inp: &str, fmt: &str) -> (bool, isize, i32, i32, i32) {
    let s = CString::new(inp).unwrap();
    let f = CString::new(fmt).unwrap();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = if eng == 0 {
        unsafe { flt::strptime(s.as_ptr(), f.as_ptr(), &mut tm) }
    } else {
        unsafe { strptime(s.as_ptr(), f.as_ptr(), &mut tm) }
    };
    let consumed = if r.is_null() {
        -1
    } else {
        (r as usize - s.as_ptr() as usize) as isize
    };
    (!r.is_null(), consumed, tm.tm_mon, tm.tm_mday, tm.tm_year)
}

fn check(inp: &str, fmt: &str) {
    let a = run(0, inp, fmt);
    let b = run(1, inp, fmt);
    assert_eq!(
        a, b,
        "strptime({inp:?}, {fmt:?}) diverged: fl={a:?} glibc={b:?}"
    );
}

#[test]
fn strptime_tzname_matches_glibc() {
    unsafe {
        // %Z's behaviour here is locale/TZ-independent (no interpretation), but
        // pin TZ=UTC + C locale for determinism.
        std::env::set_var("TZ", "UTC");
        tzset();
        let l = CString::new("C").unwrap();
        setlocale(6, l.as_ptr());
    }

    // Bare %Z: names, lowercase, digits, punctuation, leading whitespace, empty.
    for inp in [
        "UTC",
        "GMT",
        "EST",
        "utc",
        "gmt",
        "123",
        "UTC123",
        "UTC abc",
        "America/New_York",
        "",
        " UTC",
        "  GMT",
        "Z",
        "CEST",
        "PDT",
        "foobar",
        "A",
        "AbC",
        "123ABC",
        "+05:30",
        "GMT+1",
    ] {
        check(inp, "%Z");
    }

    // %Z embedded in a larger format: the name stops at whitespace and the next
    // directive keeps parsing the rest.
    check("UTC X", "%Z X");
    check("2024-06-15 EST", "%Y-%m-%d %Z");
    check("EST 2024", "%Z %Y");
    check("2024 EST 06", "%Y %Z %m");
    check("10:30 PST", "%H:%M %Z");
    // Trailing literal after the consumed name.
    check("GMT.", "%Z.");
    // No whitespace between name and a numeric directive: %Z eats the digits too,
    // so the following %Y has nothing left — both engines must agree on that.
    check("UTC2024", "%Z%Y");
}
