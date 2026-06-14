//! Conformance gate: strftime %a/%A/%b/%B emit "?" for out-of-range tm_wday /
//! tm_mon, matching glibc (malformed-tm parity).
//!
//! glibc's strftime prints a literal "?" when tm_wday is outside 0..=6 or
//! tm_mon is outside 0..=11, rather than indexing the name table. fl previously
//! reduced the index modulo 7 / 12, so e.g. tm_wday = 8 wrongly printed "Mon"
//! and tm_mon = 13 printed "Feb" — silently wrong on a malformed tm. Valid
//! values are unaffected.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::time_abi::strftime as fl_strftime;
use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn setlocale(c: c_int, n: *const c_char) -> *mut c_char;
}

fn fmt(spec: &str, tm: &libc::tm) -> String {
    let cf = std::ffi::CString::new(spec).unwrap();
    let mut buf = vec![0u8; 64];
    let n = unsafe { fl_strftime(buf.as_mut_ptr() as *mut c_char, buf.len(), cf.as_ptr(), tm) };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn tm_with(wday: i32, mon: i32) -> libc::tm {
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    t.tm_wday = wday;
    t.tm_mon = mon;
    t.tm_mday = 1;
    t
}

#[test]
fn strftime_out_of_range_wday_mon_emit_question_mark() {
    unsafe { setlocale(libc::LC_ALL, b"C\0".as_ptr() as *const c_char) };

    // Out-of-range weekday -> "?" for %a and %A (7 and -1 are both invalid).
    for bad in [7, 8, 99, -1, -100] {
        let tm = tm_with(bad, 0);
        assert_eq!(fmt("%a", &tm), "?", "%a with tm_wday={bad}");
        assert_eq!(fmt("%A", &tm), "?", "%A with tm_wday={bad}");
    }
    // Out-of-range month -> "?" for %b/%h and %B (12 and -1 are both invalid).
    for bad in [12, 13, 99, -1, -100] {
        let tm = tm_with(0, bad);
        assert_eq!(fmt("%b", &tm), "?", "%b with tm_mon={bad}");
        assert_eq!(fmt("%h", &tm), "?", "%h with tm_mon={bad}");
        assert_eq!(fmt("%B", &tm), "?", "%B with tm_mon={bad}");
    }

    // In-range values still produce the correct names (no regression).
    let valid = tm_with(3, 2); // Wednesday, March
    assert_eq!(fmt("%a", &valid), "Wed");
    assert_eq!(fmt("%A", &valid), "Wednesday");
    assert_eq!(fmt("%b", &valid), "Mar");
    assert_eq!(fmt("%B", &valid), "March");
    let edge = tm_with(6, 11); // Saturday, December (range ends)
    assert_eq!(fmt("%a", &edge), "Sat");
    assert_eq!(fmt("%B", &edge), "December");
    let zero = tm_with(0, 0); // Sunday, January (range starts)
    assert_eq!(fmt("%a", &zero), "Sun");
    assert_eq!(fmt("%b", &zero), "Jan");
}
