//! Conformance gate: strptime %p (AM/PM) hour adjustment and %j (day-of-year)
//! end-of-parse field recompute, vs host glibc semantics.
//!
//! Two parity bugs this pins (golden values captured from a gcc strptime oracle,
//! all TZ-independent):
//!   - %p only adjusts the hour when it was parsed from a 12-hour clock (%I/%r).
//!     A %p paired with %H (24-hour) or standing alone must NOT change tm_hour.
//!     fl previously added 12 unconditionally (e.g. "13 PM","%H %p" -> 25-ish,
//!     "PM","%p" -> 12). The 12 AM -> 0 / 12 PM -> 12 corners are also checked.
//!   - A bare day-of-year ("166","%j") sets tm_yday but does NOT recompute
//!     tm_wday — glibc only triggers the want_xday recompute for year/month/day
//!     (or a date derived from %Y+%j / %Y+%U). fl previously recomputed tm_wday
//!     from a bogus (year 1900, mon 0, mday 0) date.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::time_abi::strptime as fl_strptime;
use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn setlocale(c: c_int, n: *const c_char) -> *mut c_char;
}

/// Parse with a zeroed tm; return the resulting tm.
fn parse(input: &str, fmt: &str) -> libc::tm {
    let ci = std::ffi::CString::new(input).unwrap();
    let cf = std::ffi::CString::new(fmt).unwrap();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { fl_strptime(ci.as_ptr(), cf.as_ptr(), &mut tm) };
    assert!(
        !r.is_null(),
        "strptime({input:?},{fmt:?}) unexpectedly failed"
    );
    tm
}

#[test]
fn strptime_ampm_hour_adjustment_matches_glibc() {
    unsafe { setlocale(libc::LC_ALL, b"C\0".as_ptr() as *const c_char) };
    // (input, format, expected tm_hour)
    let cases: &[(&str, &str, i32)] = &[
        ("PM", "%p", 0), // %p alone: no hour to adjust
        ("AM", "%p", 0),
        ("3 PM", "%I %p", 15),
        ("3 AM", "%I %p", 3),
        ("12 AM", "%I %p", 0),  // midnight
        ("12 PM", "%I %p", 12), // noon
        ("11 PM", "%I %p", 23),
        ("13 PM", "%H %p", 13), // 24-hour: %p ignored
        ("11 PM", "%H %p", 11),
        ("3 PM", "%H %p", 3),
        ("03:45:30 PM", "%r", 15), // %r contains %I
        ("03:45:30 AM", "%r", 3),
    ];
    for &(input, fmt, want) in cases {
        let tm = parse(input, fmt);
        assert_eq!(
            tm.tm_hour, want,
            "strptime({input:?},{fmt:?}) tm_hour = {}, want {want}",
            tm.tm_hour
        );
    }
}

#[test]
fn strptime_day_of_year_recompute_matches_glibc() {
    unsafe { setlocale(libc::LC_ALL, b"C\0".as_ptr() as *const c_char) };

    // %j alone: tm_yday set, tm_wday left untouched (stays 0 from the zeroed tm).
    let tm = parse("166", "%j");
    assert_eq!(tm.tm_yday, 165, "%j sets tm_yday");
    assert_eq!(tm.tm_wday, 0, "%j alone must NOT recompute tm_wday");
    assert_eq!(tm.tm_mon, 0, "%j alone leaves tm_mon");

    // %Y + %j: glibc derives mon/mday and recomputes wday/yday.
    let tm = parse("2008 182", "%Y %j");
    assert_eq!(tm.tm_yday, 181, "%Y %j tm_yday");
    assert_eq!(tm.tm_mon, 5, "%Y %j -> June");
    assert_eq!(tm.tm_mday, 30, "%Y %j -> 30");
    assert_eq!(
        tm.tm_wday, 1,
        "%Y %j recomputes tm_wday (2008-06-30 = Monday)"
    );

    // %b %d (no year): wday recomputed from the 1900-default date.
    let tm = parse("Mar 14", "%b %d");
    assert_eq!(tm.tm_mon, 2, "%b -> March");
    assert_eq!(tm.tm_mday, 14, "%d -> 14");
    assert_eq!(tm.tm_wday, 3, "1900-03-14 = Wednesday");

    // Full date.
    let tm = parse("2024-03-14", "%Y-%m-%d");
    assert_eq!(tm.tm_wday, 4, "2024-03-14 = Thursday");
    assert_eq!(tm.tm_yday, 73, "2024-03-14 yday");
}
