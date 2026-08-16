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

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// This gate had NO host arm (bd-v0388t). Its header asserts "matching glibc
/// (malformed-tm parity)" and it compares fl against the literal "?" — a claim
/// about glibc that was never measured against glibc.
///
/// It is the riskiest shape of frozen expectation in this suite, because the
/// behaviour it pins is UNSPECIFIED. What strftime does with a tm_wday of 99 is
/// not fixed by C or POSIX; it is a glibc implementation detail, and unspecified
/// behaviour is precisely what an implementation is free to change between
/// releases. A literal "?" in a test file records what one glibc did once.
///
/// A live arm is added on the same inputs, so the gate now measures the parity
/// its name promises. The valid-value assertions ("Wed", "March") are kept and
/// also compared live, since those ARE specified and a divergence there would be
/// a real defect in either implementation.
type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;

fn host_strftime() -> StrftimeFn {
    // SAFETY: signature matches C's strftime exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"strftime",
            frankenlibc_abi::time_abi::strftime as *const (),
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

/// Both implementations own separate locale state, and %a/%b read the locale's
/// name tables, so setting only one arm's locale would compare locales rather
/// than the out-of-range rule.
fn both_c_locale() {
    let c = c"C";
    // SAFETY: LC_ALL with a NUL-terminated constant, through each arm in turn.
    unsafe {
        host_setlocale()(libc::LC_ALL, c.as_ptr());
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c.as_ptr());
    }
}

/// Render through BOTH arms, assert they agree, and return fl's string.
fn fmt(spec: &str, tm: &libc::tm) -> String {
    let cf = std::ffi::CString::new(spec).unwrap();

    let mut buf = vec![0u8; 64];
    let n = unsafe { fl_strftime(buf.as_mut_ptr() as *mut c_char, buf.len(), cf.as_ptr(), tm) };
    let fl_out = String::from_utf8_lossy(&buf[..n]).into_owned();

    let mut gbuf = vec![0u8; 64];
    // SAFETY: same format and tm, into a distinct 64-byte destination.
    let gn = unsafe { host_strftime()(gbuf.as_mut_ptr() as *mut c_char, gbuf.len(), cf.as_ptr(), tm) };
    let gl_out = String::from_utf8_lossy(&gbuf[..gn]).into_owned();

    assert_eq!(
        (n, fl_out.as_str()),
        (gn, gl_out.as_str()),
        "strftime({spec:?}) with tm_wday={} tm_mon={}: fl vs live glibc",
        tm.tm_wday,
        tm.tm_mon
    );
    fl_out
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
    both_c_locale();

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
