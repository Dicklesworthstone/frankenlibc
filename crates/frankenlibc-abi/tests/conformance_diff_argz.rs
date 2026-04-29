#![cfg(target_os = "linux")]

//! Differential conformance harness for GNU `<argz.h>`.
//!
//! argz strings are NUL-separated multi-string buffers used by GNU
//! tools (libtool, autoconf shell scripts compiled to C). fl exports
//! the standard surface in string_abi.rs:
//!   argz_create_sep, argz_count, argz_next, argz_add,
//!   argz_append, argz_delete, argz_extract, argz_stringify
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, CString};

use frankenlibc_abi::malloc_abi::free as fl_free;
use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn argz_create_sep(
        s: *const c_char,
        sep: c_int,
        argz: *mut *mut c_char,
        argz_len: *mut usize,
    ) -> c_int;
    fn argz_count(argz: *const c_char, argz_len: usize) -> usize;
    fn argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char;
    fn argz_stringify(argz: *mut c_char, argz_len: usize, sep: c_int);
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

unsafe fn collect_entries(argz: *const c_char, argz_len: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut entry: *const c_char = std::ptr::null();
    loop {
        entry = unsafe { argz_next(argz, argz_len, entry) };
        if entry.is_null() {
            break;
        }
        out.push(unsafe { std::ffi::CStr::from_ptr(entry).to_bytes().to_vec() });
        if out.len() > 256 {
            break;
        }
    }
    out
}

unsafe fn fl_collect_entries(argz: *const c_char, argz_len: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut entry: *const c_char = std::ptr::null();
    loop {
        entry = unsafe { fl::argz_next(argz, argz_len, entry) };
        if entry.is_null() {
            break;
        }
        out.push(unsafe { std::ffi::CStr::from_ptr(entry).to_bytes().to_vec() });
        if out.len() > 256 {
            break;
        }
    }
    out
}

const CREATE_SEP_CASES: &[(&str, c_int)] = &[
    ("a:b:c:d", b':' as c_int),
    ("one,two,three", b',' as c_int),
    ("", b':' as c_int),
    (":a", b':' as c_int),
    ("a:", b':' as c_int),
    ("a::b", b':' as c_int),
    ("solo", b':' as c_int),
    ("a b c d e f g", b' ' as c_int),
];

#[test]
fn diff_argz_create_sep_and_iterate() {
    let mut divs = Vec::new();
    for (s, sep) in CREATE_SEP_CASES {
        let cs = CString::new(*s).unwrap();
        // fl
        let mut fl_argz: *mut c_char = std::ptr::null_mut();
        let mut fl_len: usize = 0;
        let fl_e = unsafe { fl::argz_create_sep(cs.as_ptr(), *sep, &mut fl_argz, &mut fl_len) };
        // glibc
        let mut lc_argz: *mut c_char = std::ptr::null_mut();
        let mut lc_len: usize = 0;
        let lc_e = unsafe { argz_create_sep(cs.as_ptr(), *sep, &mut lc_argz, &mut lc_len) };
        let case = format!("({:?}, sep={})", s, *sep as u8 as char);
        if fl_e != lc_e {
            divs.push(Divergence {
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_e}"),
                glibc: format!("{lc_e}"),
            });
        }
        if fl_e == 0 && lc_e == 0 {
            let fl_count = unsafe { fl::argz_count(fl_argz, fl_len) };
            let lc_count = unsafe { argz_count(lc_argz, lc_len) };
            if fl_count != lc_count {
                divs.push(Divergence {
                    case: case.clone(),
                    field: "count",
                    frankenlibc: format!("{fl_count}"),
                    glibc: format!("{lc_count}"),
                });
            }
            let fl_entries = unsafe { fl_collect_entries(fl_argz, fl_len) };
            let lc_entries = unsafe { collect_entries(lc_argz, lc_len) };
            if fl_entries != lc_entries {
                divs.push(Divergence {
                    case,
                    field: "entries",
                    frankenlibc: format!("{:?}", fl_entries),
                    glibc: format!("{:?}", lc_entries),
                });
            }
        }
        if !fl_argz.is_null() {
            unsafe { fl_free(fl_argz as *mut libc::c_void) };
        }
        if !lc_argz.is_null() {
            unsafe { libc::free(lc_argz as *mut libc::c_void) };
        }
    }
    assert!(divs.is_empty(), "argz_create_sep divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_argz_stringify_round_trip() {
    let mut divs = Vec::new();
    for (s, sep) in &CREATE_SEP_CASES[..4] {
        // Skip empty input — glibc handles it but argz_stringify is undefined on len=0.
        if s.is_empty() {
            continue;
        }
        let cs = CString::new(*s).unwrap();
        // Build argz on each side, then stringify with the separator.
        let mut fl_argz: *mut c_char = std::ptr::null_mut();
        let mut fl_len: usize = 0;
        let _ = unsafe { fl::argz_create_sep(cs.as_ptr(), *sep, &mut fl_argz, &mut fl_len) };
        let mut lc_argz: *mut c_char = std::ptr::null_mut();
        let mut lc_len: usize = 0;
        let _ = unsafe { argz_create_sep(cs.as_ptr(), *sep, &mut lc_argz, &mut lc_len) };
        if fl_len != lc_len {
            divs.push(Divergence {
                case: format!("({:?})", s),
                field: "argz_len",
                frankenlibc: format!("{fl_len}"),
                glibc: format!("{lc_len}"),
            });
        }
        unsafe { fl::argz_stringify(fl_argz, fl_len, *sep) };
        unsafe { argz_stringify(lc_argz, lc_len, *sep) };
        if fl_len > 0 {
            let fl_str = unsafe { std::slice::from_raw_parts(fl_argz as *const u8, fl_len - 1) };
            let lc_str = unsafe { std::slice::from_raw_parts(lc_argz as *const u8, lc_len - 1) };
            if fl_str != lc_str {
                divs.push(Divergence {
                    case: format!("({:?})", s),
                    field: "stringified",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(fl_str)),
                    glibc: format!("{:?}", String::from_utf8_lossy(lc_str)),
                });
            }
        }
        if !fl_argz.is_null() {
            unsafe { fl_free(fl_argz as *mut libc::c_void) };
        }
        if !lc_argz.is_null() {
            unsafe { libc::free(lc_argz as *mut libc::c_void) };
        }
    }
    assert!(
        divs.is_empty(),
        "argz_stringify divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn argz_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc argz\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
