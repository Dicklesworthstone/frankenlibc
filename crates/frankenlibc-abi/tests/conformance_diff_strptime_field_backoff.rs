//! Conformance gate: strptime numeric-field digit "back-off" vs host glibc.
//!
//! glibc's `get_number` stops consuming digits as soon as reading another one
//! would push the value past the field's maximum, so e.g. "%m" on "34" yields
//! month 3 (leaving "4") rather than a range error, and packed numeric formats
//! like "%m%d" split "312" into 3 / 12. fl previously read the full field width
//! greedily and then range-checked, so it returned NULL on these inputs. Golden
//! (consumed, fields) captured from a gcc strptime oracle; all TZ-independent.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::time_abi::strptime as fl_strptime;
use std::os::raw::{c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// This gate had NO host arm (bd-v0388t): the GOLDEN table was, per the header,
/// "captured from a gcc strptime oracle" — read off glibc once, offline, and
/// frozen — while the test name claims it "matches_glibc". Nothing here called
/// glibc, so it could only confirm fl still agreed with a snapshot.
///
/// That matters because glibc moves: 2.42 rewrote `ecvt`/`fcvt` to
/// shortest-representation and broke four gates in this suite. The back-off rule
/// under test lives in glibc's `get_number`, which is exactly the kind of internal
/// parsing detail a release can retune.
///
/// The GOLDEN table is kept, and a live arm is added on the same inputs. A
/// divergence now says WHICH side moved: fl regressing fails the golden check,
/// glibc changing fails the live one.
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

/// Both implementations own separate locale state; set both, or the arms could
/// disagree about the locale rather than about the back-off rule.
fn both_c_locale() {
    let c = c"C";
    // SAFETY: LC_ALL with a NUL-terminated constant, through each arm in turn.
    unsafe {
        host_setlocale()(libc::LC_ALL, c.as_ptr());
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c.as_ptr());
    }
}

type GoldenCase = (&'static str, &'static str, i64, i32, i32, i32, i32, i32);

// (input, format, consumed, hour, min, sec, mday, mon)
const GOLDEN: &[GoldenCase] = &[
    ("34", "%m", 1, 0, 0, 0, 0, 2),
    ("312", "%m%d", 3, 0, 0, 0, 12, 2),
    ("3112", "%d%m", 4, 0, 0, 0, 31, 11),
    ("934", "%H%M", 3, 9, 34, 0, 0, 0),
    ("61", "%H", 1, 6, 0, 0, 0, 0),
    ("99", "%S", 1, 0, 0, 9, 0, 0),
    ("75", "%M", 1, 0, 7, 0, 0, 0),
    ("45", "%d", 1, 0, 0, 0, 4, 0),
    ("60", "%U", 1, 0, 0, 0, 0, 0),
    ("2X", "%m", 1, 0, 0, 0, 0, 1),
    ("123059", "%H%M%S", 6, 12, 30, 59, 0, 0),
    ("0103", "%m%d", 4, 0, 0, 0, 3, 0),
];

#[test]
fn strptime_numeric_field_backoff_matches_glibc() {
    both_c_locale();
    let mut fails = Vec::new();
    for &(input, fmt, consumed, hour, min, sec, mday, mon) in GOLDEN {
        let ci = std::ffi::CString::new(input).unwrap();
        let cf = std::ffi::CString::new(fmt).unwrap();
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let r = unsafe { fl_strptime(ci.as_ptr(), cf.as_ptr(), &mut tm) };
        let got_consumed = if r.is_null() {
            -1
        } else {
            (r as usize - ci.as_ptr() as usize) as i64
        };
        let got = (
            got_consumed,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            tm.tm_mday,
            tm.tm_mon,
        );
        let want = (consumed, hour, min, sec, mday, mon);
        if got != want {
            fails.push(format!(
                "strptime({input:?},{fmt:?}): fl got {got:?}, golden want {want:?}"
            ));
        }

        // Live arm, same input, same zeroed tm. A NULL return is encoded as -1
        // exactly as fl's is, so "one arm rejected the input" is compared rather
        // than skipped — that was the original defect's whole shape.
        let mut gtm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: NUL-terminated input and format, against the host.
        let gr = unsafe { host_strptime()(ci.as_ptr(), cf.as_ptr(), &mut gtm) };
        let g_consumed = if gr.is_null() {
            -1
        } else {
            (gr as usize - ci.as_ptr() as usize) as i64
        };
        let g = (
            g_consumed,
            gtm.tm_hour,
            gtm.tm_min,
            gtm.tm_sec,
            gtm.tm_mday,
            gtm.tm_mon,
        );
        if got != g {
            fails.push(format!(
                "strptime({input:?},{fmt:?}): fl {got:?} vs LIVE glibc {g:?}"
            ));
        }
        if g != want {
            fails.push(format!(
                "strptime({input:?},{fmt:?}): LIVE glibc {g:?} vs golden {want:?} \
                 — the frozen oracle no longer matches this host's glibc"
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "strptime numeric-field back-off diverged from glibc:\n{}",
        fails.join("\n")
    );
}
