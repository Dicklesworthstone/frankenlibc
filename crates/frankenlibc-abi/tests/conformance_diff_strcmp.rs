//! Differential + page-safety gate for the public `strcmp`/`strncmp` ABI after
//! routing their compares through the SWAR, page-cross-guarded `scan_strcmp`.
//!
//! 1. fl must agree (in sign) with host glibc `strcmp`/`strncmp` across many
//!    string pairs (equal, prefix, single-byte diff at every position, shared and
//!    differing NULs, high-bit bytes, various alignments and lengths).
//! 2. The wide 8-byte reads must never fault past a NUL near a page boundary: a
//!    string is placed so its NUL is the last readable byte before an unmapped
//!    guard page, and strcmp/strncmp must complete without segfaulting.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::{strcmp as fl_strcmp, strncmp as fl_strncmp};
use std::os::raw::c_char;

fn sign(x: i32) -> i32 {
    x.signum()
}

#[test]
fn strcmp_strncmp_match_glibc() {
    let mut checked = 0u64;
    let alphabet = b"ab\x80c\xffd";
    for align1 in 0usize..8 {
        for align2 in 0usize..8 {
            for len in 0usize..70 {
                // Base string of `len` non-NUL bytes + NUL.
                let mut base: Vec<u8> = (0..len).map(|k| alphabet[k % alphabet.len()]).collect();
                base.push(0);

                // Variants of the second string: identical, and a single-byte
                // mutation at each position (including turning a byte into NUL).
                let mut variants: Vec<Vec<u8>> = vec![base.clone()];
                for pos in 0..base.len() {
                    for &nb in &[b'a', b'z', 0x80u8, 0xFFu8, 0u8] {
                        if base[pos] != nb {
                            let mut v = base.clone();
                            v[pos] = nb;
                            variants.push(v);
                        }
                    }
                }

                let mut b1 = vec![0u64; (align1 + base.len()) / 8 + 2];
                let p1base = b1.as_mut_ptr().cast::<u8>();
                unsafe {
                    for (k, &b) in base.iter().enumerate() {
                        *p1base.add(align1 + k) = b;
                    }
                }
                let p1 = unsafe { p1base.add(align1) } as *const c_char;

                for v in &variants {
                    let mut b2 = vec![0u64; (align2 + v.len() + 8) / 8 + 2];
                    let p2base = b2.as_mut_ptr().cast::<u8>();
                    unsafe {
                        for (k, &b) in v.iter().enumerate() {
                            *p2base.add(align2 + k) = b;
                        }
                    }
                    let p2 = unsafe { p2base.add(align2) } as *const c_char;

                    let fl = unsafe { fl_strcmp(p1, p2) };
                    let gl = unsafe { libc::strcmp(p1, p2) };
                    assert_eq!(
                        sign(fl),
                        sign(gl),
                        "strcmp a1={align1} a2={align2} len={len} base={base:?} v={v:?}: fl={fl} gl={gl}"
                    );

                    for &n in &[0usize, 1, len / 2, len, len + 1, len + 8] {
                        let fln = unsafe { fl_strncmp(p1, p2, n) };
                        let gln = unsafe { libc::strncmp(p1, p2, n) };
                        assert_eq!(
                            sign(fln),
                            sign(gln),
                            "strncmp a1={align1} a2={align2} len={len} n={n}: fl={fln} gl={gln}"
                        );
                        checked += 1;
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 100_000, "corpus unexpectedly small: {checked}");
}

/// Place a string so its NUL is the final byte before an unmapped guard page and
/// confirm the wide-read page guard prevents a fault.
#[test]
fn strcmp_does_not_overread_past_guard_page() {
    let page = 4096usize;
    unsafe {
        // Two adjacent pages; make the second PROT_NONE.
        let base = libc::mmap(
            std::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        let base = base.cast::<u8>();
        assert_eq!(
            libc::mprotect(base.add(page).cast(), page, libc::PROT_NONE),
            0,
            "mprotect failed"
        );

        // For NUL offsets in the last 16 bytes of page 1, the terminated string
        // sits flush against the guard page; any 8-byte over-read would fault.
        for nul_back in 1..=16usize {
            let start = base.add(page - nul_back);
            for k in 0..(nul_back - 1) {
                *start.add(k) = b'a';
            }
            *start.add(nul_back - 1) = 0; // NUL is the last byte of page 1.

            let other = b"aaaaaaaaaaaaaaaaaaaa\0".as_ptr().cast::<c_char>();
            let sp = start.cast::<c_char>();
            // Must not fault. Both directions + strncmp with an over-large n.
            let _ = fl_strcmp(sp, other);
            let _ = fl_strcmp(other, sp);
            let _ = fl_strncmp(sp, other, 4096);
            let _ = fl_strncmp(other, sp, 4096);
        }

        libc::munmap(base.cast(), page * 2);
    }
}
