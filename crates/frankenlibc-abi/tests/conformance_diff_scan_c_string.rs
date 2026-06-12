//! Isomorphism gate for the SWAR `scan_c_string` NUL scanner (behind
//! strcpy/stpcpy/strncat). The word-at-a-time scan must return exactly the same
//! `(index, found)` as a trivial byte-at-a-time reference for every NUL position,
//! every pointer alignment, and both bounded and unbounded modes — including the
//! cases where the NUL straddles a SWAR window boundary and where a high-bit
//! (>=0x80) byte sits next to the NUL (the haszero trick's false-positive lane).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::bench_scan_c_string;
use std::os::raw::c_char;

/// Byte-at-a-time reference: index of first NUL (or `limit`/end) and whether found.
fn reference(buf: &[u8], bound: Option<usize>) -> (usize, bool) {
    match bound {
        Some(limit) => {
            for (i, &b) in buf.iter().take(limit).enumerate() {
                if b == 0 {
                    return (i, true);
                }
            }
            (limit.min(buf.len()), false)
        }
        None => {
            for (i, &b) in buf.iter().enumerate() {
                if b == 0 {
                    return (i, true);
                }
            }
            (buf.len(), false) // unreachable for our NUL-terminated inputs
        }
    }
}

#[test]
fn scan_c_string_swar_matches_byte_reference() {
    let mut checked = 0u64;
    // Over-aligned backing so we can place the string at offsets 0..8.
    for align_off in 0usize..8 {
        for nul_pos in 0usize..200 {
            // Content: nul_pos non-zero bytes (mix in high-bit bytes adjacent to the
            // NUL to exercise the haszero false-positive lane), then the NUL, then
            // trailing garbage (also non-zero) so a wrong scan would overrun.
            let mut content: Vec<u8> = (0..nul_pos)
                .map(|k| {
                    let b = (k as u8).wrapping_mul(73).wrapping_add(1);
                    if b == 0 { 0xFF } else { b } // never an early NUL
                })
                .collect();
            content.push(0); // terminator
            content.extend([0x80u8, 0xFF, 0x01, 0x80, 0xFF, 0x7F, 0x80, 0xFF, 0x42]);

            // Place into an 8-aligned Vec<u64> backing at `align_off`.
            let mut backing: Vec<u64> = vec![0u64; (align_off + content.len()) / 8 + 2];
            let base = backing.as_mut_ptr().cast::<u8>();
            unsafe {
                for (k, &b) in content.iter().enumerate() {
                    *base.add(align_off + k) = b;
                }
            }
            let p = unsafe { base.add(align_off) } as *const c_char;

            // Unbounded.
            let got = unsafe { bench_scan_c_string(p, None) };
            let want = reference(&content, None);
            assert_eq!(got, want, "unbounded align={align_off} nul_pos={nul_pos}");

            // Bounded at several limits straddling the NUL.
            for &lim in &[0usize, nul_pos.saturating_sub(1), nul_pos, nul_pos + 1, nul_pos + 8] {
                let got_b = unsafe { bench_scan_c_string(p, Some(lim)) };
                let want_b = reference(&content, Some(lim));
                assert_eq!(
                    got_b, want_b,
                    "bounded align={align_off} nul_pos={nul_pos} limit={lim}"
                );
                checked += 1;
            }
            checked += 1;
        }
    }
    assert!(checked > 9000, "corpus unexpectedly small: {checked}");
}
