#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc memrchr oracle

//! Differential gate for memrchr (bd-m46zox) — previously uncovered. memrchr
//! scans the first n bytes and returns a pointer to the LAST occurrence of byte
//! c, or NULL if absent. fl must return the same offset as host glibc across:
//! match at end/middle/start, multiple occurrences (last wins), no match, n=0,
//! and a NUL search byte. No mocks.

use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn memrchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void;
}

fn off(ret: *mut c_void, base: *const u8) -> isize {
    if ret.is_null() {
        -1
    } else {
        (ret as isize) - (base as isize)
    }
}

#[test]
fn memrchr_matches_glibc() {
    let hay: &[u8] = b"abcabcd\0ef";
    // (search byte, n)
    let cases: &[(u8, usize)] = &[
        (b'a', hay.len()), // last 'a' at idx 3
        (b'a', 3),         // within first 3 -> last 'a' at idx 0
        (b'd', hay.len()), // single 'd' at idx 6
        (b'e', hay.len()), // near end
        (b'f', hay.len()), // last byte
        (b'z', hay.len()), // absent
        (b'a', 0),         // n=0 -> NULL
        (0u8, hay.len()),  // NUL byte at idx 7
        (b'c', hay.len()), // last 'c' at idx 5
        (b'c', 4),         // within first 4 -> 'c' at idx 2
    ];
    for &(c, n) in cases {
        let g = unsafe { memrchr(hay.as_ptr() as *const c_void, c as c_int, n) };
        let f = unsafe {
            frankenlibc_abi::string_abi::memrchr(hay.as_ptr() as *const c_void, c as c_int, n)
        };
        assert_eq!(
            off(f, hay.as_ptr()),
            off(g, hay.as_ptr()),
            "memrchr(c={c}, n={n}): fl={} glibc={}",
            off(f, hay.as_ptr()),
            off(g, hay.as_ptr())
        );
    }
}
