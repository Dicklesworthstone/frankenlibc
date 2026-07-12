#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strptime oracle

//! Differential gate for strptime leading-whitespace numeric parsing
//! (bd-smhq4c). glibc's get_number macro skips leading whitespace before every
//! numeric directive, so blank-padded / space-prefixed fields parse. This
//! validates that fl matches glibc across %H/%I/%d/%m/%S/%M/%Y/%j/%y with
//! leading spaces in the input (and no-space controls), comparing accept/reject,
//! consumed length, and the parsed field. No mocks.

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn strptime(s: *const c_char, format: *const c_char, tm: *mut libc::tm) -> *mut c_char;
}

fn field(tm: &libc::tm, which: u8) -> c_int {
    match which {
        b'H' | b'I' => tm.tm_hour,
        b'd' => tm.tm_mday,
        b'm' => tm.tm_mon,
        b'S' => tm.tm_sec,
        b'M' => tm.tm_min,
        b'Y' | b'y' => tm.tm_year,
        b'j' => tm.tm_yday,
        _ => 0,
    }
}

fn run(
    strp: unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char,
    input: &str,
    fmt: &str,
    which: u8,
) -> (bool, isize, c_int) {
    let ic = CString::new(input).unwrap();
    let fc = CString::new(fmt).unwrap();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe { strp(ic.as_ptr(), fc.as_ptr(), &mut tm) };
    if r.is_null() {
        (false, -1, 0)
    } else {
        (true, r as isize - ic.as_ptr() as isize, field(&tm, which))
    }
}

#[test]
fn strptime_leading_whitespace_matches_glibc() {
    let g = strptime;
    let f: unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char =
        frankenlibc_abi::time_abi::strptime;

    // (input, format, field-selector)
    let cases: &[(&str, &str, u8)] = &[
        (" 4", "%H", b'H'),
        ("  4", "%H", b'H'),
        ("14", "%H", b'H'), // control: no space
        (" 3", "%I", b'I'),
        (" 7", "%d", b'd'),
        ("\t9", "%d", b'd'), // tab counts as whitespace in get_number
        (" 2", "%m", b'm'),
        (" 5", "%S", b'S'),
        (" 30", "%M", b'M'),
        (" 2024", "%Y", b'Y'),
        (" 200", "%j", b'j'),
        ("   ", "%H", b'H'), // only whitespace, no digit -> both reject
    ];
    for &(inp, fmt, which) in cases {
        let gr = run(g, inp, fmt, which);
        let fr = run(f, inp, fmt, which);
        assert_eq!(
            fr, gr,
            "strptime({inp:?}, {fmt:?}): fl=(ok {},consumed {},field {}) glibc=(ok {},consumed {},field {})",
            fr.0, fr.1, fr.2, gr.0, gr.1, gr.2
        );
    }
}
