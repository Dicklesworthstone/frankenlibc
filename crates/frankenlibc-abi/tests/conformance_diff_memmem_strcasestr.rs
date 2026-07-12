#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc memmem/strcasestr oracle

//! Differential gate for memmem + strcasestr (bd-tjr4z7), neither of which had a
//! dedicated gate. memmem does a binary (length-bounded) substring search;
//! strcasestr does a case-insensitive NUL-terminated one. Both return a pointer
//! to the first match or NULL, and both return `haystack` for an empty needle.
//! For each scenario fl must return the same offset as host glibc. No mocks.

use std::ffi::{c_char, c_void};

unsafe extern "C" {
    fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *mut c_void;
    fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char;
}

fn off_v(ret: *mut c_void, base: *const u8) -> isize {
    if ret.is_null() {
        -1
    } else {
        (ret as isize) - (base as isize)
    }
}
fn off_c(ret: *mut c_char, base: *const u8) -> isize {
    if ret.is_null() {
        -1
    } else {
        (ret as isize) - (base as isize)
    }
}

#[test]
fn memmem_matches_glibc() {
    let hay = b"abcabcdabcde";
    // (needle, expected behaviour exercised)
    let needles: &[&[u8]] = &[
        b"abc",          // first match at 0
        b"abcd",         // match at 3
        b"abcde",        // match at 7
        b"cde",          // match near end
        b"xyz",          // absent
        b"",             // empty needle -> haystack
        b"abcdef",       // longer-than-any-suffix, absent
        b"a",            // single byte
        b"e",            // last byte
        b"abcabcdabcde", // whole haystack
    ];
    for n in needles {
        let rg = unsafe {
            memmem(
                hay.as_ptr() as *const c_void,
                hay.len(),
                n.as_ptr() as *const c_void,
                n.len(),
            )
        };
        let rf = unsafe {
            frankenlibc_abi::string_abi::memmem(
                hay.as_ptr() as *const c_void,
                hay.len(),
                n.as_ptr() as *const c_void,
                n.len(),
            )
        };
        assert_eq!(
            off_v(rf, hay.as_ptr()),
            off_v(rg, hay.as_ptr()),
            "memmem(needle={n:?})"
        );
    }
    // needle longer than haystack -> NULL in both.
    let big = b"abcabcdabcdeXX";
    let rg = unsafe {
        memmem(
            hay.as_ptr() as *const c_void,
            hay.len(),
            big.as_ptr() as *const c_void,
            big.len(),
        )
    };
    let rf = unsafe {
        frankenlibc_abi::string_abi::memmem(
            hay.as_ptr() as *const c_void,
            hay.len(),
            big.as_ptr() as *const c_void,
            big.len(),
        )
    };
    assert_eq!(
        off_v(rf, hay.as_ptr()),
        off_v(rg, hay.as_ptr()),
        "memmem(needle>haystack)"
    );
}

#[test]
fn strcasestr_matches_glibc() {
    let hay = c"The Quick BROWN fox QuIcK";
    let hay_bytes = hay.to_bytes();
    let needles = [
        c"quick", c"QUICK", c"brown", c"FOX", c"the", c"zzz", c"", c"Q", c"k",
    ];
    for n in needles {
        let rg = unsafe { strcasestr(hay.as_ptr(), n.as_ptr()) };
        let rf = unsafe { frankenlibc_abi::string_abi::strcasestr(hay.as_ptr(), n.as_ptr()) };
        assert_eq!(
            off_c(rf, hay_bytes.as_ptr()),
            off_c(rg, hay_bytes.as_ptr()),
            "strcasestr(needle={n:?})"
        );
    }
}
