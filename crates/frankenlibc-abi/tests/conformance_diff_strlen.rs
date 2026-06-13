//! Differential gate for the public `strlen`/`strnlen` ABI after routing their
//! NUL scans through the SWAR `scan_c_string`. fl must agree with host glibc
//! `strlen`/`strnlen` for every length, pointer alignment, and (for strnlen)
//! every bound straddling the terminator.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::{strlen as fl_strlen, strnlen as fl_strnlen};
use std::os::raw::c_char;

#[test]
fn strlen_strnlen_match_glibc() {
    let mut checked = 0u64;
    for align_off in 0usize..8 {
        for len in 0usize..260 {
            // Non-zero body (mix high-bit bytes to exercise the haszero lane), NUL,
            // then non-zero trailing guard so an overrun would change the answer.
            let mut content: Vec<u8> = (0..len)
                .map(|k| {
                    let b = (k as u8).wrapping_mul(91).wrapping_add(3);
                    if b == 0 { 0x80 } else { b }
                })
                .collect();
            content.push(0);
            content.extend([0xFF, 0x80, 0x41, 0xFF, 0x80, 0x01, 0xFF, 0x80]);

            // 8-aligned backing; place string at align_off.
            let mut backing: Vec<u64> = vec![0u64; (align_off + content.len()) / 8 + 2];
            let base = backing.as_mut_ptr().cast::<u8>();
            unsafe {
                for (k, &b) in content.iter().enumerate() {
                    *base.add(align_off + k) = b;
                }
            }
            let p = unsafe { base.add(align_off) } as *const c_char;

            // strlen.
            let fl = unsafe { fl_strlen(p) };
            let gl = unsafe { libc::strlen(p) };
            assert_eq!(
                fl, gl,
                "strlen align={align_off} len={len}: fl={fl} gl={gl}"
            );

            // strnlen over bounds straddling the terminator.
            for &bound in &[
                0usize,
                len.saturating_sub(1),
                len,
                len + 1,
                len + 8,
                len + 200,
            ] {
                let fln = unsafe { fl_strnlen(p, bound) };
                let gln = unsafe { libc::strnlen(p, bound) };
                assert_eq!(
                    fln, gln,
                    "strnlen align={align_off} len={len} bound={bound}: fl={fln} gl={gln}"
                );
                checked += 1;
            }
            checked += 1;
        }
    }
    assert!(checked > 12000, "corpus unexpectedly small: {checked}");
}
