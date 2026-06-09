#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc c16rtomb oracle

//! C11 `c16rtomb` (char16_t -> multibyte) surrogate-pair parity vs host glibc
//! (bd-2g7oyh.NEW — coverage). The decode side (`mbrtoc16`) is fuzzed, but the
//! stateful surrogate-pair *encoder* had no vs-glibc differential. This gate
//! drives a sequence of UTF-16 code units through both engines with a shared
//! mbstate and compares each call's (return value, errno, emitted bytes) over:
//! BMP characters, astral characters as high+low surrogate pairs, a lone high
//! surrogate (pends, returns 0), and the EILSEQ cases (lone low surrogate, a
//! high surrogate not followed by a low one).

use std::ffi::{CString, c_char, c_void};
use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn c16rtomb(s: *mut c_char, c16: u16, ps: *mut c_void) -> usize;
    fn setlocale(c: i32, l: *const c_char) -> *mut c_char;
    fn __errno_location() -> *mut i32;
}

fn step(eng: u8, c16: u16, st: *mut c_void) -> (i64, i32, Vec<u8>) {
    let mut buf = [0u8; 8];
    unsafe { *__errno_location() = 0 };
    let r = if eng == 0 {
        unsafe { fl::c16rtomb(buf.as_mut_ptr() as *mut c_char, c16, st) }
    } else {
        unsafe { c16rtomb(buf.as_mut_ptr() as *mut c_char, c16, st) }
    };
    let e = unsafe { *__errno_location() };
    let written = if r == usize::MAX { 0 } else { r.min(8) };
    (r as isize as i64, e, buf[..written].to_vec())
}

fn seq(eng: u8, units: &[u16]) -> Vec<(i64, i32, Vec<u8>)> {
    let mut st = [0u8; 8];
    let p = st.as_mut_ptr() as *mut c_void;
    units.iter().map(|&u| step(eng, u, p)).collect()
}

#[test]
fn c16rtomb_matches_glibc() {
    let loc = CString::new("C.UTF-8").unwrap();
    if unsafe { setlocale(6, loc.as_ptr()) }.is_null() {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }

    let cases: &[&[u16]] = &[
        &[0x0041],                 // 'A'
        &[0x00E9],                 // é (2-byte)
        &[0x20AC],                 // € (3-byte)
        &[0xD800, 0xDC00],         // U+10000 (surrogate pair, 4-byte)
        &[0xD83D, 0xDE00],         // U+1F600 emoji
        &[0xDBFF, 0xDFFF],         // U+10FFFF (max)
        &[0xDC00],                 // lone low surrogate -> EILSEQ
        &[0xD800, 0x0041],         // high then non-low -> EILSEQ
        &[0xD800, 0xD800],         // high then high -> EILSEQ
        &[0xD800],                 // lone high (incomplete) -> returns 0
        &[0xDBFF],                 // lone high
        &[0x20AC, 0xD83D, 0xDE00], // BMP then astral pair
        &[0x0041, 0xDC00],         // ascii then lone low -> EILSEQ
        &[0xD800, 0xDC00, 0x0042], // pair then ascii
    ];
    for units in cases {
        let a = seq(0, units);
        let b = seq(1, units);
        assert_eq!(a, b, "c16rtomb sequence {units:04x?}: fl={a:?} glibc={b:?}");
    }

    // s == NULL resets the conversion state and returns 1 (a single NUL); pin it.
    let mut st = [0u8; 8];
    let p = st.as_mut_ptr() as *mut c_void;
    let fr = unsafe { fl::c16rtomb(std::ptr::null_mut(), 0, p) };
    let mut st2 = [0u8; 8];
    let p2 = st2.as_mut_ptr() as *mut c_void;
    let gr = unsafe { c16rtomb(std::ptr::null_mut(), 0, p2) };
    assert_eq!(fr, gr, "c16rtomb(NULL) reset return");
}
