//! Differential + page-safety gate for the public `wcscmp`/`wcsncmp` ABI after
//! routing their compares through the fused u64-SWAR `scan_wcscmp` (two wchar_t
//! lanes per word). fl must sign-match host glibc across many wide-string pairs,
//! and the wide reads must not fault past a NUL flush against an unmapped page.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi::{wcscmp as fl_wcscmp, wcsncmp as fl_wcsncmp};
use std::os::raw::c_int;

unsafe extern "C" {
    fn wcscmp(s1: *const u32, s2: *const u32) -> c_int;
    fn wcsncmp(s1: *const u32, s2: *const u32, n: usize) -> c_int;
}

fn sign(x: i32) -> i32 {
    x.signum()
}

// wchar_t is i32 on Linux; mix in values that span the signed boundary and that
// land a zero only in one 32-bit lane of a u64 (exercising has_zero_u32_lane).
const ALPHABET: [u32; 6] = [b'a' as u32, b'Z' as u32, 0x100, 0x1_0000, 0x8000_0000, 0x7FFF_FFFF];

#[test]
fn wcscmp_wcsncmp_match_glibc() {
    let mut checked = 0u64;
    for align1 in 0usize..2 {
        for align2 in 0usize..2 {
            for len in 0usize..40 {
                let mut base: Vec<u32> = (0..len).map(|k| ALPHABET[k % ALPHABET.len()]).collect();
                base.push(0);

                let mut variants: Vec<Vec<u32>> = vec![base.clone()];
                for pos in 0..base.len() {
                    for &nv in &[b'a' as u32, b'z' as u32, 0x8000_0000u32, 0u32] {
                        if base[pos] != nv {
                            let mut v = base.clone();
                            v[pos] = nv;
                            variants.push(v);
                        }
                    }
                }

                // 8-byte (2-wchar) aligned backing; place at element offset align1/2.
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

                    let fl = unsafe { fl_wcscmp(p1, p2) };
                    let gl = unsafe { wcscmp(p1, p2) };
                    assert_eq!(sign(fl), sign(gl), "wcscmp len={len} base={base:?} v={v:?}");

                    for &n in &[0usize, 1, len / 2, len, len + 1, len + 4] {
                        let fln = unsafe { fl_wcsncmp(p1, p2, n) };
                        let gln = unsafe { wcsncmp(p1, p2, n) };
                        assert_eq!(sign(fln), sign(gln), "wcsncmp len={len} n={n}");
                        checked += 1;
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 50_000, "corpus unexpectedly small: {checked}");
}

#[test]
fn wcscmp_does_not_overread_past_guard_page() {
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
        // Place a NUL-terminated wide string whose NUL is the last wchar of page 1.
        for back in 1..=8usize {
            let start = base.add(wchars - back);
            for k in 0..(back - 1) {
                *start.add(k) = b'a' as u32;
            }
            *start.add(back - 1) = 0;
            let mut other: [u32; 12] = [b'a' as u32; 12];
            other[11] = 0;
            let op = other.as_ptr();
            let _ = fl_wcscmp(start, op);
            let _ = fl_wcscmp(op, start);
            let _ = fl_wcsncmp(start, op, 4096);
            let _ = fl_wcsncmp(op, start, 4096);
        }
        libc::munmap(base.cast(), page * 2);
    }
}
