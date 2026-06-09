#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime oracle

//! `strftime` `%z` (UTC offset) parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc formats `%z` as ±HHMM from the broken-down time's `tm_gmtoff` field,
//! regardless of how it was set (localtime, `strptime %z`, or by hand). fl
//! previously hardcoded "+0000". This gate fills `tm_gmtoff` with a range of
//! offsets and compares the rendered `%z` (alone and embedded) against the live
//! host.
//!
//! Out of scope (documented divergence): `%Z` (timezone name) reads the opaque
//! `tm_zone` pointer and, when null, falls back to the process timezone — both
//! beyond fl's UTC-only, never-dereference-tm_zone model.

use std::ffi::{CString, c_char};
use frankenlibc_abi::time_abi as fl;

unsafe extern "C" {
    fn strftime(s: *mut c_char, m: usize, f: *const c_char, tm: *const libc::tm) -> usize;
    fn gmtime_r(t: *const i64, tm: *mut libc::tm) -> *mut libc::tm;
    fn setlocale(c: i32, l: *const c_char) -> *mut c_char;
}

fn render(eng: u8, fmt: &str, tm: &libc::tm) -> String {
    let cf = CString::new(fmt).unwrap();
    let mut buf = vec![0i8; 96];
    let n = if eng == 0 {
        unsafe { fl::strftime(buf.as_mut_ptr(), 96, cf.as_ptr(), tm) }
    } else {
        unsafe { strftime(buf.as_mut_ptr(), 96, cf.as_ptr(), tm) }
    };
    String::from_utf8_lossy(&buf[..n].iter().map(|&b| b as u8).collect::<Vec<_>>()).into_owned()
}

#[test]
fn strftime_gmtoff_z_matches_glibc() {
    let loc = CString::new("C").unwrap();
    unsafe { setlocale(6, loc.as_ptr()) };

    let t = 1_718_450_000i64;
    let mut base: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { gmtime_r(&t, &mut base) };

    // Whole-hour, half-hour, quarter-hour, negative, and sub-minute offsets.
    let offsets: [i64; 11] = [
        0, 3600, -3600, 19800, -28800, -1800, 34200, 50400, -43200, 900, -45900,
    ];
    for off in offsets {
        let mut tm = base;
        tm.tm_gmtoff = off;
        tm.tm_zone = std::ptr::null(); // %z is independent of the name
        for fmt in ["%z", "%H:%M:%S %z", "[%z]"] {
            let a = render(0, fmt, &tm);
            let b = render(1, fmt, &tm);
            assert_eq!(a, b, "strftime({fmt:?}) gmtoff={off}: fl={a:?} glibc={b:?}");
        }
    }
}
