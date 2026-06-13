//! Differential + page-safety gate for the public `wcscasecmp`/`wcsncasecmp` ABI
//! after routing their ASCII-folded compares through the portable-SIMD
//! `scan_wcscasecmp_simd`. fl must sign-match host glibc (C/POSIX locale) across
//! many wide-string pairs — equal-mod-ASCII-case, case-swaps, single-element
//! diffs, shared/early NUL, non-ASCII (unfolded) elements, alignments, lengths,
//! and n straddling the NUL — and the vector loads must not fault past a NUL
//! flush against an unmapped page.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi::{wcscasecmp as fl_wcscasecmp, wcsncasecmp as fl_wcsncasecmp};
use std::os::raw::c_int;

unsafe extern "C" {
    fn wcscasecmp(s1: *const u32, s2: *const u32) -> c_int;
    fn wcsncasecmp(s1: *const u32, s2: *const u32, n: usize) -> c_int;
}

fn sign(x: i32) -> i32 {
    x.signum()
}

// Mix uppercase/lowercase ASCII letters (foldable) with non-ASCII codepoints
// (NOT folded in C locale, incl. the >0x7F "would-be-letters" 0xC0.. range).
const ALPHABET: [u32; 8] = [
    b'A' as u32,
    b'z' as u32,
    b'M' as u32,
    b'q' as u32,
    0xC0,
    0x100,
    0x1_0041,
    0x7FFF_FFFF,
];

#[test]
fn wcscasecmp_wcsncasecmp_match_glibc() {
    let mut checked = 0u64;
    for align1 in 0usize..2 {
        for align2 in 0usize..2 {
            for len in 0usize..40 {
                let mut base: Vec<u32> = (0..len).map(|k| ALPHABET[k % ALPHABET.len()]).collect();
                base.push(0);

                let mut variants: Vec<Vec<u32>> = vec![base.clone()];
                // Flip ASCII-letter case in every position.
                let mut swapped = base.clone();
                for v in swapped.iter_mut() {
                    if (0x41..=0x5A).contains(v) || (0x61..=0x7A).contains(v) {
                        *v ^= 0x20;
                    }
                }
                variants.push(swapped);
                for pos in 0..base.len() {
                    for &nv in &[b'a' as u32, b'Z' as u32, 0xC0u32, 0x1_0061u32, 0u32] {
                        if base[pos] != nv {
                            let mut v = base.clone();
                            v[pos] = nv;
                            variants.push(v);
                        }
                    }
                }

                let mut b1 = vec![0u32; align1 + base.len() + 2];
                for (k, &c) in base.iter().enumerate() {
                    b1[align1 + k] = c;
                }
                let p1 = unsafe { b1.as_ptr().add(align1) };

                for v in &variants {
                    let mut b2 = vec![0u32; align2 + v.len() + 2];
                    for (k, &c) in v.iter().enumerate() {
                        b2[align2 + k] = c;
                    }
                    let p2 = unsafe { b2.as_ptr().add(align2) };

                    let fl = unsafe { fl_wcscasecmp(p1, p2) };
                    let gl = unsafe { wcscasecmp(p1, p2) };
                    assert_eq!(
                        sign(fl),
                        sign(gl),
                        "wcscasecmp len={len} base={base:?} v={v:?}: fl={fl} gl={gl}"
                    );

                    for &n in &[0usize, 1, len / 2, len, len + 1, len + 4] {
                        let fln = unsafe { fl_wcsncasecmp(p1, p2, n) };
                        let gln = unsafe { wcsncasecmp(p1, p2, n) };
                        assert_eq!(sign(fln), sign(gln), "wcsncasecmp len={len} n={n}");
                        checked += 1;
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 40_000, "corpus unexpectedly small: {checked}");
}

#[test]
fn wcscasecmp_does_not_overread_past_guard_page() {
    let page = 4096usize;
    let wchars = page / 4;
    unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        let base = base.cast::<u32>();
        assert_eq!(
            libc::mprotect(base.cast::<u8>().add(page).cast(), page, libc::PROT_NONE),
            0,
            "mprotect failed"
        );
        for back in 1..=10usize {
            let start = base.add(wchars - back);
            for k in 0..(back - 1) {
                *start.add(k) = b'A' as u32;
            }
            *start.add(back - 1) = 0;
            let mut other: [u32; 12] = [b'a' as u32; 12];
            other[11] = 0;
            let op = other.as_ptr();
            let _ = fl_wcscasecmp(start, op);
            let _ = fl_wcscasecmp(op, start);
            let _ = fl_wcsncasecmp(start, op, 4096);
            let _ = fl_wcsncasecmp(op, start, 4096);
        }
        libc::munmap(base.cast(), page * 2);
    }
}
