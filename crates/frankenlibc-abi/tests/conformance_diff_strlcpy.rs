#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strlcpy/strlcat oracle (glibc >= 2.38)

//! Differential gate for strlcpy/strlcat (bd-0t2qbx). Both return the length of
//! the string they *tried* to create (strlcpy: strlen(src); strlcat:
//! min(strlen(dst),size)+strlen(src)) and NUL-terminate within `size` when
//! size>0. For each scenario fl must match host glibc on BOTH the return value
//! and the resulting buffer bytes. Host glibc 2.38+ exports these. No mocks.

use std::ffi::{c_char, c_void};

unsafe extern "C" {
    fn strlcpy(dst: *mut c_char, src: *const c_char, n: usize) -> usize;
    fn strlcat(dst: *mut c_char, src: *const c_char, n: usize) -> usize;
    fn memcpy(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void;
}

const FILL: u8 = 0x7e;

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

#[test]
fn strlcpy_matches_glibc() {
    // (src, size)
    let cases: &[(&str, usize)] = &[
        ("abc", 8),        // fits
        ("abcdefg", 8),    // exact fit (7 + NUL)
        ("abcdefgh", 8),   // truncates by one
        ("abcdefghij", 8), // truncates
        ("", 8),           // empty
        ("hello", 1),      // size 1 -> only NUL
        ("hello", 0),      // size 0 -> no write, ret strlen
        ("hello", 5),      // truncates (need 6)
    ];
    for &(src, size) in cases {
        let s = cstr(src);
        let mut gd = [FILL; 16];
        let mut fd = [FILL; 16];
        let rg = unsafe {
            strlcpy(
                gd.as_mut_ptr() as *mut c_char,
                s.as_ptr() as *const c_char,
                size,
            )
        };
        let rf = unsafe {
            frankenlibc_abi::string_abi::strlcpy(
                fd.as_mut_ptr() as *mut c_char,
                s.as_ptr() as *const c_char,
                size,
            )
        };
        assert_eq!(rf, rg, "strlcpy(src={src:?}, size={size}) return");
        assert_eq!(fd, gd, "strlcpy(src={src:?}, size={size}) buffer");
    }
}

#[test]
fn strlcat_matches_glibc() {
    // (initial dst prefix, src, size)
    let cases: &[(&str, &str, usize)] = &[
        ("ab", "cd", 8),       // fits -> "abcd"
        ("ab", "cdefghij", 8), // truncates
        ("abcdef", "gh", 8),   // exact fit
        ("abcdefg", "h", 8),   // truncates by one
        ("", "xyz", 8),        // empty dst
        ("abc", "", 8),        // empty src
        ("abcdefgh", "x", 8),  // dlen == size (no NUL within size): ret size+strlen(src)
        ("abc", "de", 2),      // size < dlen
    ];
    for &(pre, src, size) in cases {
        let s = cstr(src);
        // dst buffers pre-filled with the prefix (NUL-terminated) then FILL.
        let mut gd = [FILL; 24];
        let mut fd = [FILL; 24];
        let pre_c = cstr(pre);
        unsafe {
            memcpy(
                gd.as_mut_ptr() as *mut c_void,
                pre_c.as_ptr() as *const c_void,
                pre_c.len(),
            );
            memcpy(
                fd.as_mut_ptr() as *mut c_void,
                pre_c.as_ptr() as *const c_void,
                pre_c.len(),
            );
        }
        let rg = unsafe {
            strlcat(
                gd.as_mut_ptr() as *mut c_char,
                s.as_ptr() as *const c_char,
                size,
            )
        };
        let rf = unsafe {
            frankenlibc_abi::string_abi::strlcat(
                fd.as_mut_ptr() as *mut c_char,
                s.as_ptr() as *const c_char,
                size,
            )
        };
        assert_eq!(
            rf, rg,
            "strlcat(pre={pre:?}, src={src:?}, size={size}) return"
        );
        assert_eq!(
            fd, gd,
            "strlcat(pre={pre:?}, src={src:?}, size={size}) buffer"
        );
    }
}
