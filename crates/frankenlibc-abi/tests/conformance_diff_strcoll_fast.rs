#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Isomorphism gate for routing strcoll through the strcmp ABI fast path.
//! FrankenLibC uses the C/POSIX locale where collation order is byte order, so
//! strcoll == strcmp; the old wrapper scanned both operands' lengths and then
//! compared (a triple pass, ~4.4x slower than glibc strcoll on equal strings).
//! It now delegates to the fused single-pass SWAR/32-byte-SIMD strcmp (4.40x ->
//! 1.17x). 300000 random pairs (small alphabet so equal strings and shared
//! prefixes are frequent) agree with host glibc strcoll on the comparison sign.

use frankenlibc_abi::string_abi as fa;
use std::ffi::CString;
use std::os::raw::c_char;

unsafe extern "C" {
    fn strcoll(a: *const c_char, b: *const c_char) -> i32;
}

#[test]
fn strcoll_matches_glibc() {
    let mut seed: u64 = 0x71;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut div = 0u32;
    for _ in 0..300000 {
        let la = (rng() as usize) % 40;
        let lb = (rng() as usize) % 40;
        let a: Vec<u8> = (0..la).map(|_| ((rng() % 7) + b'a' as u64) as u8).collect();
        let mut b: Vec<u8> = if rng() & 1 == 0 {
            a.clone()
        } else {
            (0..lb).map(|_| ((rng() % 7) + b'a' as u64) as u8).collect()
        };
        if rng() & 3 == 0 && !b.is_empty() {
            let k = (rng() as usize) % b.len();
            b[k] = ((rng() % 7) + b'a' as u64) as u8;
        }
        let ca = CString::new(a).unwrap();
        let cb = CString::new(b).unwrap();
        let f = unsafe { fa::strcoll(ca.as_ptr(), cb.as_ptr()) }.signum();
        let g = unsafe { strcoll(ca.as_ptr(), cb.as_ptr()) }.signum();
        if f != g {
            div += 1;
            if div <= 8 {
                eprintln!("DIV a={ca:?} b={cb:?} f={f} g={g}");
            }
        }
    }
    assert_eq!(div, 0, "strcoll diverged from glibc in {div} cases");
}
