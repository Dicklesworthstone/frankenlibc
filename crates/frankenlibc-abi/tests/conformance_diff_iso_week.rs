#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime oracle

//! Differential gate for strftime ISO 8601 week-date boundaries (bd-106d3i).
//! %V (ISO week 01..53), %G (ISO week-based year), %g (2-digit %G) are subtle at
//! year boundaries: early-January days can belong to the PREVIOUS year's
//! week 52/53, and late-December days to the NEXT year's week 01. conformance_
//! diff_time omits %V from its deterministic cases; the fuzz hits boundaries
//! only stochastically. This pins the known-tricky dates (53-week years,
//! year-straddling weeks) deterministically: fl's "%G-W%V-%u" / "%g" must equal
//! glibc byte-for-byte. No mocks.

use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn strftime(s: *mut c_char, max: usize, fmt: *const c_char, tm: *const libc::tm) -> usize;
    fn timegm(tm: *mut libc::tm) -> libc::time_t;
}

fn tm_for(y: i32, mon: i32, mday: i32) -> libc::tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = y - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = mday;
    unsafe { timegm(&mut tm) }; // normalize tm_wday/tm_yday
    tm
}

fn fmt_glibc(tm: &libc::tm, f: &str) -> Vec<u8> {
    let fc = CString::new(f).unwrap();
    let mut buf = vec![0u8; 64];
    let n = unsafe { strftime(buf.as_mut_ptr() as *mut c_char, buf.len(), fc.as_ptr(), tm) };
    buf[..n].to_vec()
}
fn fmt_fl(tm: &libc::tm, f: &str) -> Vec<u8> {
    let fc = CString::new(f).unwrap();
    let mut buf = vec![0u8; 64];
    let n = unsafe {
        frankenlibc_abi::time_abi::strftime(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fc.as_ptr(),
            tm as *const libc::tm,
        )
    };
    buf[..n].to_vec()
}

#[test]
fn strftime_iso_week_boundaries_match_glibc() {
    // (year, month, day) at/around ISO-week year boundaries.
    let dates = [
        (2021, 1, 1),   // -> 2020-W53-5
        (2020, 12, 31), // -> 2020-W53-4
        (2023, 1, 1),   // -> 2022-W52-7
        (2024, 12, 30), // -> 2025-W01-1
        (2018, 12, 31), // -> 2019-W01-1
        (2016, 1, 1),   // -> 2015-W53-5
        (2024, 1, 1),   // -> 2024-W01-1
        (2025, 12, 31), // -> 2026-W01-3
        (2015, 12, 31), // -> 2015-W53-4
        (2017, 1, 1),   // -> 2016-W52-7
        (2026, 1, 1),   // -> 2026-W01-4
        (2000, 1, 1),   // -> 1999-W52-6
    ];
    for &(y, m, d) in &dates {
        let tm = tm_for(y, m, d);
        for f in ["%G-W%V-%u", "%g", "%V", "%G"] {
            let g = fmt_glibc(&tm, f);
            let fl = fmt_fl(&tm, f);
            assert_eq!(
                fl,
                g,
                "strftime({f:?}) for {y}-{m:02}-{d:02}: fl={:?} glibc={:?}",
                String::from_utf8_lossy(&fl),
                String::from_utf8_lossy(&g),
            );
        }
    }
}
