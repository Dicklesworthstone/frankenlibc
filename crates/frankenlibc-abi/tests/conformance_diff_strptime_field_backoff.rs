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

unsafe extern "C" {
    fn setlocale(c: c_int, n: *const c_char) -> *mut c_char;
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
    unsafe { setlocale(libc::LC_ALL, c"C".as_ptr()) };
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
                "strptime({input:?},{fmt:?}): got {got:?}, want {want:?}"
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "strptime numeric-field back-off diverged from glibc:\n{}",
        fails.join("\n")
    );
}
