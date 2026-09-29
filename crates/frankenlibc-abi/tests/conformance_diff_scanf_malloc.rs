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

use frankenlibc_abi::malloc_abi as flm;
use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char, c_void};

unsafe extern "C" {
    fn sscanf(s: *const c_char, f: *const c_char, ...) -> i32;
    fn free(p: *mut c_void);
}

/// Marks an out-pointer the call must leave alone, so that "stored NULL" and
/// "untouched" are told apart.
const UNTOUCHED: *mut c_char = 1 as *mut c_char;

/// `%ms`/`%m[` (NUL-terminated alloc): compare (count, two strings).
///
/// Engines: 0 = fl's variadic `sscanf`, 2 = fl's `__isoc23_sscanf` -- what a
/// program built against glibc 2.38+ headers calls, and which reaches the
/// `va_list` store path through `vsscanf` (that path ignored `%m` and wrote the
/// token over the caller's pointer: fuser crashed) -- 1 = host glibc.
fn alloc_str(eng: u8, inp: &str, fmt: &str) -> (i32, String, String) {
    let ci = CString::new(inp).unwrap();
    let cf = CString::new(fmt).unwrap();
    let mut p1: *mut c_char = UNTOUCHED;
    let mut p2: *mut c_char = UNTOUCHED;
    let r = match eng {
        0 => unsafe { fl::sscanf(ci.as_ptr(), cf.as_ptr(), &mut p1, &mut p2) },
        2 => unsafe {
            frankenlibc_abi::isoc_abi::__isoc23_sscanf(ci.as_ptr(), cf.as_ptr(), &mut p1, &mut p2)
        },
        _ => unsafe { sscanf(ci.as_ptr(), cf.as_ptr(), &mut p1, &mut p2) },
    };
    let s = |p: *mut c_char| {
        if p == UNTOUCHED {
            "<untouched>".to_string()
        } else if p.is_null() {
            "<null>".to_string()
        } else {
            unsafe { std::ffi::CStr::from_ptr(p) }
                .to_string_lossy()
                .into_owned()
        }
    };
    let out = (r, s(p1), s(p2));
    for p in [p1, p2] {
        if !p.is_null() && p != UNTOUCHED {
            if eng != 1 {
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
        ("", "%*ms%ms"),
        ("key=value", "%m[^=]=%ms"),
        ("5 9", "%*d %m[a-z]"),
    ] {
        let b = alloc_str(1, inp, fmt);
        for eng in [0, 2] {
            let a = alloc_str(eng, inp, fmt);
            assert_eq!(
                a, b,
                "engine {eng} sscanf({inp:?}, {fmt:?}) [%ms] diverged: fl={a:?} glibc={b:?}"
            );
        }
    }

    // %mc allocation (no NUL; exactly the matched count).
    for (inp, fmt, read) in [("xyz", "%mc", 1), ("xyz", "%3mc", 3)] {
        let a = char_bytes(0, inp, fmt, read, true);
        let b = char_bytes(1, inp, fmt, read, true);
        assert_eq!(
            a, b,
            "sscanf({inp:?}, {fmt:?}) [%mc] diverged: fl={a:?} glibc={b:?}"
        );
    }

    // A WIDTH THE INPUT CANNOT SUPPLY IS A FAILURE, not a clamp: measured on
    // glibc 2.42, sscanf("ab", "%5mc") == -1 and sscanf("ab", "%5c") == -1, and
    // the conversion counts nothing. These rows assert the RETURN CODE only. The
    // destination buffer after a failed conversion is a different matter: glibc
    // leaves the characters it managed to read (`%5c` on "ab" leaves "ab" in the
    // caller's buffer) while fl leaves the buffer untouched, and POSIX specifies
    // neither, so comparing those bytes would pin an implementation detail rather
    // than a contract (bd-7ilguh).
    for (inp, fmt, alloc) in [("ab", "%5mc", true), ("ab", "%5c", false)] {
        let a = char_bytes(0, inp, fmt, 2, alloc).0;
        let b = char_bytes(1, inp, fmt, 2, alloc).0;
        assert_eq!(
            a, -1,
            "fl sscanf({inp:?}, {fmt:?}) must fail the conversion"
        );
        assert_eq!(
            a, b,
            "sscanf({inp:?}, {fmt:?}) [insufficient width] diverged: fl={a} glibc={b}"
        );
    }

    // Non-alloc %Nc with a width the input CAN supply reads exactly that many.
    for (inp, fmt, read) in [("abcdef", "%3c", 3), ("ab", "%2c", 2), ("a", "%1c", 1)] {
        let a = char_bytes(0, inp, fmt, read, false);
        let b = char_bytes(1, inp, fmt, read, false);
        assert_eq!(
            a, b,
            "sscanf({inp:?}, {fmt:?}) [%Nc] diverged: fl={a:?} glibc={b:?}"
        );
    }
}
