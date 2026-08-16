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

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// This gate used to have NO host arm at all (bd-v0388t).
///
/// Its header described the expected values as "golden values captured from a
/// gcc strptime oracle", i.e. read off glibc ONCE, offline, and frozen into
/// literals — while both test names end in `_matches_glibc`. That is a stronger
/// claim than the code made: nothing here ever called glibc, so the gate could
/// only ever confirm that fl still agreed with a snapshot of glibc's behaviour
/// taken at authoring time.
///
/// The distinction is not academic on this host. glibc 2.42 rewrote `ecvt`/`fcvt`
/// to shortest-representation and broke four gates in this suite, so glibc DOES
/// move underneath frozen literals. A gate whose name promises parity has to
/// measure it.
///
/// The golden literals are kept — they encode what the fix intended — and a live
/// glibc arm is added alongside. Now a divergence identifies WHICH side moved:
/// fl regressing fails the golden assertion, glibc changing fails the
/// differential one.
type StrptimeFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;

fn host_strptime() -> StrptimeFn {
    // SAFETY: signature matches POSIX strptime exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"strptime",
            frankenlibc_abi::time_abi::strptime as *const (),
        )
    }
}

fn host_setlocale() -> SetlocaleFn {
    // SAFETY: signature matches C's setlocale exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"setlocale",
            frankenlibc_abi::locale_abi::setlocale as *const (),
        )
    }
}

/// Put BOTH implementations in the C locale. Each owns its own locale state, so
/// setting only one would let the arms disagree over what a month name is rather
/// than over the parsing rule under test.
fn both_c_locale() {
    let c = c"C";
    // SAFETY: LC_ALL with a NUL-terminated constant, through each arm in turn.
    unsafe {
        host_setlocale()(libc::LC_ALL, c.as_ptr());
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c.as_ptr());
    }
}

/// Every field strptime is allowed to touch, so a divergence cannot hide in a
/// field this gate happens not to assert.
fn fields(tm: &libc::tm) -> [i32; 9] {
    [
        tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon, tm.tm_year, tm.tm_wday,
        tm.tm_yday, tm.tm_isdst,
    ]
}

/// Parse with a zeroed tm through BOTH arms, assert they agree, return fl's tm.
///
/// The consumed-length comparison matters as much as the fields: an arm that
/// stops early can still leave a correct-looking tm.
fn parse(input: &str, fmt: &str) -> libc::tm {
    let ci = std::ffi::CString::new(input).unwrap();
    let cf = std::ffi::CString::new(fmt).unwrap();

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { fl_strptime(ci.as_ptr(), cf.as_ptr(), &mut tm) };
    assert!(
        !r.is_null(),
        "strptime({input:?},{fmt:?}) unexpectedly failed"
    );

    let mut gtm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: same NUL-terminated inputs, against the host implementation.
    let gr = unsafe { host_strptime()(ci.as_ptr(), cf.as_ptr(), &mut gtm) };
    assert!(
        !gr.is_null(),
        "host glibc strptime({input:?},{fmt:?}) failed where fl succeeded"
    );

    assert_eq!(
        fields(&tm),
        fields(&gtm),
        "strptime({input:?},{fmt:?}) diverged from live glibc \
         [sec,min,hour,mday,mon,year,wday,yday,isdst]"
    );
    assert_eq!(
        (r as usize) - (ci.as_ptr() as usize),
        (gr as usize) - (ci.as_ptr() as usize),
        "strptime({input:?},{fmt:?}) consumed a different number of bytes than glibc"
    );
    tm
}

#[test]
fn strptime_ampm_hour_adjustment_matches_glibc() {
    both_c_locale();
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
    both_c_locale();

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
