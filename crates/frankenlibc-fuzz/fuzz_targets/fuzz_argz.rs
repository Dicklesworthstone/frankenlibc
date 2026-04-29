#![no_main]
//! Differential fuzz target: `frankenlibc_abi::string_abi::argz_*` vs host
//! glibc's `<argz.h>` (linked from libc.so).
//!
//! argz strings are NUL-separated multi-string buffers used by GNU
//! tools. fl exports the standard surface in string_abi.rs:
//!   argz_create_sep, argz_count, argz_next, argz_stringify,
//!   argz_add, argz_append, argz_delete
//!
//! The conformance harness (tests/conformance_diff_argz.rs) covers 8
//! hand-crafted shapes; this target widens that to arbitrary printable-
//! ASCII inputs across multiple delimiter choices.
//!
//! ## Input layout
//!
//! ```text
//! byte[0]              sep_choice (mod 4): selects from {':', ',', ' ', ';'}
//! byte[1..]            input string fed to argz_create_sep
//! ```
//!
//! ## What we assert
//!
//! 1. fl::argz_create_sep determinism: a second call on identical input
//!    must produce identical (argz_len, count, entry sequence).
//! 2. Differential against host glibc: argz_len, argz_count, every
//!    argz_next entry, and argz_stringify round-trip output must match
//!    bit-for-bit.
//!
//! Filed under [bd-xn6p8] follow-up — fuzz coverage extension.

use std::ffi::{c_char, c_int, CStr, CString};

use frankenlibc_abi::malloc_abi::free as fl_free;
use frankenlibc_abi::string_abi as fl;
use libfuzzer_sys::fuzz_target;

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

const MAX_INPUT: usize = 256;

fn sep_for(byte: u8) -> c_int {
    match byte % 4 {
        0 => b':' as c_int,
        1 => b',' as c_int,
        2 => b' ' as c_int,
        _ => b';' as c_int,
    }
}

fn sanitize(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|&b| b.is_ascii_alphanumeric() || matches!(b, b':' | b',' | b' ' | b';' | b'_' | b'-' | b'='))
        .take(MAX_INPUT)
        .collect()
}

unsafe fn collect_lc(argz: *const c_char, argz_len: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut entry: *const c_char = std::ptr::null();
    for _ in 0..256 {
        entry = unsafe { argz_next(argz, argz_len, entry) };
        if entry.is_null() {
            break;
        }
        out.push(unsafe { CStr::from_ptr(entry) }.to_bytes().to_vec());
    }
    out
}

unsafe fn collect_fl(argz: *const c_char, argz_len: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut entry: *const c_char = std::ptr::null();
    for _ in 0..256 {
        entry = unsafe { fl::argz_next(argz, argz_len, entry) };
        if entry.is_null() {
            break;
        }
        out.push(unsafe { CStr::from_ptr(entry) }.to_bytes().to_vec());
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }
    let sep = sep_for(data[0]);
    let body = sanitize(&data[1..]);
    let cs = match CString::new(body.clone()) {
        Ok(s) => s,
        Err(_) => return,
    };

    // ---- determinism: fl twice on same input ----
    let mut fl_a: *mut c_char = std::ptr::null_mut();
    let mut fl_a_len: usize = 0;
    let r1 = unsafe { fl::argz_create_sep(cs.as_ptr(), sep, &mut fl_a, &mut fl_a_len) };
    let mut fl_b: *mut c_char = std::ptr::null_mut();
    let mut fl_b_len: usize = 0;
    let r2 = unsafe { fl::argz_create_sep(cs.as_ptr(), sep, &mut fl_b, &mut fl_b_len) };
    assert_eq!(r1, r2, "fl argz_create_sep non-deterministic return: {r1} vs {r2}");
    assert_eq!(fl_a_len, fl_b_len, "fl argz_len non-deterministic");
    if r1 == 0 {
        let entries_a = unsafe { collect_fl(fl_a, fl_a_len) };
        let entries_b = unsafe { collect_fl(fl_b, fl_b_len) };
        assert_eq!(entries_a, entries_b, "fl argz_next non-deterministic");
    }

    // ---- differential: fl vs glibc ----
    let mut lc_a: *mut c_char = std::ptr::null_mut();
    let mut lc_a_len: usize = 0;
    let r_lc = unsafe { argz_create_sep(cs.as_ptr(), sep, &mut lc_a, &mut lc_a_len) };
    assert_eq!(r1, r_lc, "argz_create_sep return differs: fl={r1} glibc={r_lc}");
    if r1 == 0 && r_lc == 0 {
        assert_eq!(fl_a_len, lc_a_len, "argz_len differs");
        let fl_count = unsafe { fl::argz_count(fl_a, fl_a_len) };
        let lc_count = unsafe { argz_count(lc_a, lc_a_len) };
        assert_eq!(fl_count, lc_count, "argz_count differs");
        let fl_entries = unsafe { collect_fl(fl_a, fl_a_len) };
        let lc_entries = unsafe { collect_lc(lc_a, lc_a_len) };
        assert_eq!(fl_entries, lc_entries, "argz_next entries differ");

        // Stringify both back; results must match.
        unsafe { fl::argz_stringify(fl_a, fl_a_len, sep) };
        unsafe { argz_stringify(lc_a, lc_a_len, sep) };
        if fl_a_len > 0 {
            let fl_str =
                unsafe { std::slice::from_raw_parts(fl_a as *const u8, fl_a_len.saturating_sub(1)) };
            let lc_str =
                unsafe { std::slice::from_raw_parts(lc_a as *const u8, lc_a_len.saturating_sub(1)) };
            assert_eq!(fl_str, lc_str, "argz_stringify differs");
        }
    }

    // Free everything.
    if !fl_a.is_null() {
        unsafe { fl_free(fl_a as *mut libc::c_void) };
    }
    if !fl_b.is_null() {
        unsafe { fl_free(fl_b as *mut libc::c_void) };
    }
    if !lc_a.is_null() {
        unsafe { libc::free(lc_a as *mut libc::c_void) };
    }
});
