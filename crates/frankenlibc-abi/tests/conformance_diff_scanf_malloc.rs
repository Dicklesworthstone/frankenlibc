#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sscanf oracle

//! GNU `m` assignment-allocation modifier (`%ms` / `%m[` / `%mc`) and the
//! `%Nc` width-exceeds-input rule, vs host glibc (bd-2g7oyh.NEW).
//!
//! fl had no `m` modifier (so `%ms` failed outright) and its narrow `%Nc`
//! required the full width to be present (failing where glibc reads what is
//! available). This gate drives both engines and compares the return count and
//! the produced bytes. fl-allocated buffers are freed with fl's allocator and
//! glibc's with the system allocator.

use std::ffi::{CString, c_char, c_void};
use frankenlibc_abi::malloc_abi as flm;
use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn sscanf(s: *const c_char, f: *const c_char, ...) -> i32;
    fn free(p: *mut c_void);
}

/// `%ms`/`%m[` (NUL-terminated alloc): compare (count, two strings).
fn alloc_str(eng: u8, inp: &str, fmt: &str) -> (i32, String, String) {
    let ci = CString::new(inp).unwrap();
    let cf = CString::new(fmt).unwrap();
    let mut p1: *mut c_char = std::ptr::null_mut();
    let mut p2: *mut c_char = std::ptr::null_mut();
    let r = if eng == 0 {
        unsafe { fl::sscanf(ci.as_ptr(), cf.as_ptr(), &mut p1, &mut p2) }
    } else {
        unsafe { sscanf(ci.as_ptr(), cf.as_ptr(), &mut p1, &mut p2) }
    };
    let s = |p: *mut c_char| {
        if p.is_null() {
            "<null>".to_string()
        } else {
            unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };
    let out = (r, s(p1), s(p2));
    for p in [p1, p2] {
        if !p.is_null() {
            if eng == 0 {
                unsafe { flm::free(p.cast()) };
            } else {
                unsafe { free(p.cast()) };
            }
        }
    }
    out
}

/// `%[N]c` (alloc or fixed): compare (count, the first `read` bytes).
fn char_bytes(eng: u8, inp: &str, fmt: &str, read: usize, alloc: bool) -> (i32, Vec<u8>) {
    let ci = CString::new(inp).unwrap();
    let cf = CString::new(fmt).unwrap();
    if alloc {
        let mut p: *mut c_char = std::ptr::null_mut();
        let r = if eng == 0 {
            unsafe { fl::sscanf(ci.as_ptr(), cf.as_ptr(), &mut p) }
        } else {
            unsafe { sscanf(ci.as_ptr(), cf.as_ptr(), &mut p) }
        };
        let bytes = if p.is_null() {
            vec![]
        } else {
            (0..read).map(|i| unsafe { *p.add(i) as u8 }).collect()
        };
        if !p.is_null() {
            if eng == 0 {
                unsafe { flm::free(p.cast()) };
            } else {
                unsafe { free(p.cast()) };
            }
        }
        (r, bytes)
    } else {
        let mut buf = [0u8; 16];
        let r = if eng == 0 {
            unsafe { fl::sscanf(ci.as_ptr(), cf.as_ptr(), buf.as_mut_ptr()) }
        } else {
            unsafe { sscanf(ci.as_ptr(), cf.as_ptr(), buf.as_mut_ptr()) }
        };
        (r, buf[..read].to_vec())
    }
}

#[test]
fn scanf_m_modifier_matches_glibc() {
    // %ms / %m[ allocation.
    for (inp, fmt) in [
        ("hello world", "%ms"),
        ("hello world", "%ms %ms"),
        ("  pad", "%ms"),
        ("abc123", "%m[a-z]"),
        ("12ab", "%m[0-9]"),
        ("xyz", "%2ms"),
        ("", "%ms"),
        ("onlyone", "%ms %ms"),
    ] {
        let a = alloc_str(0, inp, fmt);
        let b = alloc_str(1, inp, fmt);
        assert_eq!(a, b, "sscanf({inp:?}, {fmt:?}) [%ms] diverged: fl={a:?} glibc={b:?}");
    }

    // %mc allocation (no NUL; exactly the matched count).
    for (inp, fmt, read) in [("xyz", "%mc", 1), ("xyz", "%3mc", 3), ("ab", "%5mc", 2)] {
        let a = char_bytes(0, inp, fmt, read, true);
        let b = char_bytes(1, inp, fmt, read, true);
        assert_eq!(a, b, "sscanf({inp:?}, {fmt:?}) [%mc] diverged: fl={a:?} glibc={b:?}");
    }

    // Non-alloc %Nc reads what is available when width exceeds the input.
    for (inp, fmt, read) in [("ab", "%5c", 2), ("abcdef", "%3c", 3), ("ab", "%2c", 2), ("a", "%1c", 1)] {
        let a = char_bytes(0, inp, fmt, read, false);
        let b = char_bytes(1, inp, fmt, read, false);
        assert_eq!(a, b, "sscanf({inp:?}, {fmt:?}) [%Nc] diverged: fl={a:?} glibc={b:?}");
    }
}
