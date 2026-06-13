//! Differential gate for the public `strchr` ABI after routing its scan through
//! the SWAR `scan_c_string_for_byte`. fl must agree with host glibc `strchr` for
//! every target byte (incl. '\0' and high-bit bytes), every NUL position, and
//! every pointer alignment — including targets that appear after vs before the
//! NUL and targets sitting exactly on a SWAR window boundary.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::strchr as fl_strchr;
use std::os::raw::c_char;

#[test]
fn strchr_matches_glibc() {
    let mut checked = 0u64;
    for align_off in 0usize..8 {
        for len in 0usize..130 {
            // Body bytes drawn from a small alphabet (so targets actually hit),
            // never an early NUL.
            let body: Vec<u8> = (0..len)
                .map(|k| {
                    let b = b"ab\x80cd\xffe"[k % 7];
                    if b == 0 { 0x61 } else { b }
                })
                .collect();
            let mut content = body.clone();
            content.push(0);
            content.extend([b'a', 0x80, b'z', 0xFF, b'b']); // post-NUL guard (incl targets)

            let mut backing: Vec<u64> = vec![0u64; (align_off + content.len()) / 8 + 2];
            let base = backing.as_mut_ptr().cast::<u8>();
            unsafe {
                for (k, &b) in content.iter().enumerate() {
                    *base.add(align_off + k) = b;
                }
            }
            let p = unsafe { base.add(align_off) } as *const c_char;

            // Targets: present bytes, absent byte, high-bit bytes, and NUL.
            for &t in &[
                b'a', b'b', b'c', b'd', b'e', b'z', 0x80u8, 0xFFu8, 0x00u8, 0x71u8,
            ] {
                let fl = unsafe { fl_strchr(p, t as i32) };
                let gl = unsafe { libc::strchr(p, t as i32) };
                // Compare as offsets from base (or both null).
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
                    "strchr align={align_off} len={len} target={t:#x}: fl={fl_off:?} gl={gl_off:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 9000, "corpus unexpectedly small: {checked}");
}
