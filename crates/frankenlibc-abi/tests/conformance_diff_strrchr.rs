//! Differential gate for the public `strrchr` ABI after routing its scan through
//! the SWAR `scan_c_string_last_byte`. fl must agree with host glibc `strrchr`
//! for every target (incl. '\0', high-bit, absent), every NUL position, every
//! pointer alignment, and with multiple target occurrences (so the LAST match is
//! what matters), including occurrences on SWAR window boundaries.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::strrchr as fl_strrchr;
use std::os::raw::c_char;

#[test]
fn strrchr_matches_glibc() {
    let mut checked = 0u64;
    for align_off in 0usize..8 {
        for len in 0usize..140 {
            // Body over a small alphabet so targets recur (last-match is exercised);
            // never an early NUL.
            let body: Vec<u8> = (0..len)
                .map(|k| {
                    let b = b"ax\x80by\xffz"[k % 7];
                    if b == 0 { 0x61 } else { b }
                })
                .collect();
            let mut content = body.clone();
            content.push(0);
            content.extend([b'a', 0x80, b'z', 0xFF, b'x']); // post-NUL guard incl targets

            let mut backing: Vec<u64> = vec![0u64; (align_off + content.len()) / 8 + 2];
            let base = backing.as_mut_ptr().cast::<u8>();
            unsafe {
                for (k, &b) in content.iter().enumerate() {
                    *base.add(align_off + k) = b;
                }
            }
            let p = unsafe { base.add(align_off) } as *const c_char;

            for &t in &[b'a', b'x', b'y', b'z', b'b', 0x80u8, 0xFFu8, 0x00u8, 0x51u8] {
                let fl = unsafe { fl_strrchr(p, t as i32) };
                let gl = unsafe { libc::strrchr(p, t as i32) };
                let fl_off = if fl.is_null() {
                    None
                } else {
                    Some(fl as usize - p as usize)
                };
                let gl_off = if gl.is_null() {
                    None
                } else {
                    Some(gl as usize - p as usize)
                };
                assert_eq!(
                    fl_off, gl_off,
                    "strrchr align={align_off} len={len} target={t:#x}: fl={fl_off:?} gl={gl_off:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 9000, "corpus unexpectedly small: {checked}");
}
