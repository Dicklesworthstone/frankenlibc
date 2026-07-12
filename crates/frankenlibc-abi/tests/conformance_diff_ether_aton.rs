//! Differential gate for ether_aton/ether_aton_r trailing-byte handling vs glibc.
//!
//! glibc stops after parsing six octets and does not require the string to end
//! there: a two-hex-digit sixth octet ignores any trailing bytes
//! ("01:02:03:04:05:06:07" -> "…:06"), and a single-digit sixth octet succeeds
//! only when the next byte is NUL or whitespace (glibc isspace, including \v) —
//! otherwise that byte is (mis)read as the second hex digit and rejected
//! ("…:6x" -> NULL, but "…:6 " -> OK, "…:6a" -> "…:6a"). fl previously demanded
//! the string end exactly at the sixth octet, so it returned NULL for all of
//! glibc's accepted trailing forms.
//!
//! fl is called via its Rust path; glibc via dlsym on libc.so.6 (bypassing fl's
//! no_mangle interposition). Both fill the 6-byte `struct ether_addr`.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type AtonRFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> *mut c_void;

fn glibc_aton_r(g: AtonRFn, s: &[u8]) -> Option<[u8; 6]> {
    // s must be NUL-terminated.
    let mut out = [0u8; 6];
    let r = unsafe { g(s.as_ptr() as *const c_char, out.as_mut_ptr() as *mut c_void) };
    if r.is_null() { None } else { Some(out) }
}
fn fl_aton_r(s: &[u8]) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let r =
        unsafe { fl::ether_aton_r(s.as_ptr() as *const c_char, out.as_mut_ptr() as *mut c_void) };
    if r.is_null() { None } else { Some(out) }
}

#[test]
fn ether_aton_trailing_matches_glibc() {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let gp = unsafe { dlsym(h, c"ether_aton_r".as_ptr()) };
    assert!(!gp.is_null(), "missing ether_aton_r");
    let g: AtonRFn = unsafe { core::mem::transmute(gp) };

    // NUL-terminated byte literals (each ends in \0).
    let inputs: &[&[u8]] = &[
        b"01:02:03:04:05:06\0",
        b"1:2:3:4:5:6\0",
        b"1:2:3:4:5:6 \0",         // trailing space
        b"1:2:3:4:5:6\t\0",        // tab
        b"1:2:3:4:5:6\x0b\0",      // vertical tab (glibc isspace, Rust not)
        b"1:2:3:4:5:6\n\0",        // newline
        b"01:02:03:04:05:06x\0",   // 2-digit last + junk -> OK
        b"1:2:3:4:5:6x\0",         // 1-digit last + non-hex junk -> NULL
        b"1:2:3:4:5:6a\0",         // 1-digit last + hex -> reads 6a
        b"01:02:03:04:05:06:07\0", // trailing :07 after 2-digit -> OK (…:06)
        b"1:2:3:4:5:6:\0",         // 1-digit + ':' -> NULL
        b"01:02:03:04:05:0\0",     // 1-digit last at end
        b"1:2:3:4:5:\0",           // missing last octet -> NULL
        b"1:2:3:4:5:6  junk\0",    // space then junk -> OK
        b"1:2:3:4:5\0",            // only 5 octets -> NULL
        b"gg:00:00:00:00:00\0",    // bad hex -> NULL
    ];

    let mut div = Vec::new();
    for s in inputs {
        let fv = fl_aton_r(s);
        let gv = glibc_aton_r(g, s);
        if fv != gv {
            let disp: String = s[..s.len() - 1].iter().map(|&b| b as char).collect();
            div.push(format!("{disp:?}: fl={fv:?} glibc={gv:?}"));
        }
    }
    assert!(
        div.is_empty(),
        "ether_aton divergences ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
