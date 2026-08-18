#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live glibc strptime oracle

//! Leading whitespace before `strptime`'s numeric fields.
//!
//! bd-smhq4c. glibc skips whitespace inside its `get_number` macro, so EVERY
//! numeric conversion accepts it. fl skipped it for `%d`/`%e` only, so
//! `strptime("  7", "%H", &tm)` returned NULL where glibc succeeds — sixteen of
//! seventeen numeric call sites were missing it.
//!
//! ## Three behaviours, and only the first is obvious
//!
//! ```text
//!   strptime("  7",   "%H")  -> ok,   tm_hour = 7      spaces skipped
//!   strptime("\t7",   "%H")  -> ok,   tm_hour = 7      tabs too
//!   strptime("   ",   "%H")  -> NULL, tm_hour untouched   whitespace alone FAILS
//!   strptime("  +7",  "%H")  -> NULL                      a SIGN is not accepted
//!   strptime("  -7",  "%H")  -> NULL
//! ```
//!
//! The last two matter because the natural implementation — skip whitespace,
//! then call a general integer parser — accepts signs and would diverge on
//! input no test with well-formed data ever reaches.

use std::ffi::{CStr, CString, c_char};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type StrptimeFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char;

fn host_strptime() -> StrptimeFn {
    // SAFETY: `char *strptime(const char *, const char *, struct tm *)`, with
    // fl's own export supplied so the oracle refuses to resolve back to fl.
    unsafe {
        host_fn(
            c"strptime",
            frankenlibc_abi::time_abi::strptime as *const (),
        )
    }
}

/// A `tm` with every field poisoned, so "untouched" is observable.
fn poisoned() -> libc::tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_sec = -1;
    tm.tm_min = -1;
    tm.tm_hour = -1;
    tm.tm_mday = -1;
    tm.tm_mon = -1;
    tm.tm_year = -1;
    tm.tm_wday = -1;
    tm.tm_yday = -1;
    tm.tm_isdst = -1;
    tm
}

/// `(consumed_all, field_value)` — `None` when the call returned NULL.
fn run(f: StrptimeFn, input: &CStr, fmt: &CStr, field: fn(&libc::tm) -> c_int) -> Option<c_int> {
    let mut tm = poisoned();
    // SAFETY: both strings are NUL-terminated and `tm` is a live local.
    let rest = unsafe { f(input.as_ptr(), fmt.as_ptr(), &mut tm) };
    if rest.is_null() {
        None
    } else {
        Some(field(&tm))
    }
}

use std::ffi::c_int;

#[test]
fn leading_whitespace_is_accepted_before_every_numeric_field() {
    let host = host_strptime();
    let cases: &[(&CStr, &CStr, fn(&libc::tm) -> c_int, c_int)] = &[
        (c"  7", c"%H", |t| t.tm_hour, 7),
        (c"\t7", c"%H", |t| t.tm_hour, 7),
        (c"7", c"%H", |t| t.tm_hour, 7),
        (c"  5", c"%d", |t| t.tm_mday, 5),
        (c" 12", c"%m", |t| t.tm_mon, 11),
        (c"  9", c"%S", |t| t.tm_sec, 9),
        (c"  3", c"%M", |t| t.tm_min, 3),
        (c" 1999", c"%Y", |t| t.tm_year, 99),
    ];

    let mut divergences = Vec::new();
    for (input, fmt, field, expected) in cases {
        let host_out = run(host, input, fmt, *field);
        assert_eq!(
            host_out,
            Some(*expected),
            "host glibc no longer accepts {input:?} for {fmt:?}"
        );
        // SAFETY: fl's entry point with the same arguments.
        let fl_out = run(frankenlibc_abi::time_abi::strptime, input, fmt, *field);
        if fl_out != host_out {
            divergences.push(format!(
                "  {input:?} {fmt:?}: fl {fl_out:?} glibc {host_out:?}"
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "strptime whitespace divergences:\n{}",
        divergences.join("\n")
    );
}

/// Whitespace with no digit after it is a FAILURE, not a zero — and a sign is
/// not a digit. These are the arms a "skip spaces then strtol" implementation
/// fails.
#[test]
fn whitespace_alone_and_signed_input_are_rejected() {
    let host = host_strptime();
    for input in [c"   ", c"  +7", c"  -7", c""] {
        let host_out = run(host, input, c"%H", |t| t.tm_hour);
        assert_eq!(
            host_out, None,
            "host glibc should reject {input:?} for %H; the probe is wrong if not"
        );
        let fl_out = run(frankenlibc_abi::time_abi::strptime, input, c"%H", |t| {
            t.tm_hour
        });
        assert_eq!(
            fl_out, host_out,
            "fl must reject {input:?} too — accepting a sign here is what a \
             general integer parser would do (bd-smhq4c)"
        );
    }
}

/// `%e`'s blank padding still works now that the skip moved into the shared
/// parser: the explicit per-arm skip it used to carry has been removed, and
/// this is what proves the removal was safe.
#[test]
fn percent_e_blank_padding_still_parses() {
    let host = host_strptime();
    for input in [c" 5", c"  5", c"05", c"5"] {
        let host_out = run(host, input, c"%e", |t| t.tm_mday);
        let fl_out = run(frankenlibc_abi::time_abi::strptime, input, c"%e", |t| {
            t.tm_mday
        });
        assert_eq!(fl_out, host_out, "%e with input {input:?}");
    }
}
