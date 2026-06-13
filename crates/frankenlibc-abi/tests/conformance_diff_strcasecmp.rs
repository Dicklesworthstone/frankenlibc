//! Gate for the public `strcasecmp`/`strncasecmp` ABI after fusing their scans
//! into a single SWAR case-fold compare.
//!
//! 1. The branchless SWAR ASCII lowercase must equal `u8::to_ascii_lowercase` for
//!    EVERY byte value 0..=255 in EVERY lane position (carry-safety + C-locale:
//!    only `A`-`Z` fold, non-ASCII untouched).
//! 2. fl must agree (in sign) with host glibc `strcasecmp`/`strncasecmp` across
//!    many pairs (equal mod case, case-only diff, single-byte diff, shared/early
//!    NUL, high-bit bytes, alignments, lengths, strncasecmp n straddling len).
//! 3. The wide reads must not fault past a NUL flush against an unmapped page.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::{
    strcasecmp as fl_strcasecmp, strncasecmp as fl_strncasecmp, test_swar_ascii_lower,
};
use std::os::raw::c_char;

fn sign(x: i32) -> i32 {
    x.signum()
}

#[test]
fn swar_ascii_lower_matches_scalar_for_all_bytes_and_lanes() {
    for lane in 0..8 {
        for b in 0u16..=255 {
            let b = b as u8;
            let w = (b as u64) << (lane * 8);
            let folded = test_swar_ascii_lower(w);
            let got = ((folded >> (lane * 8)) & 0xFF) as u8;
            assert_eq!(
                got,
                b.to_ascii_lowercase(),
                "swar lower byte={b:#x} lane={lane}: got {got:#x}"
            );
            // Other lanes must be untouched (they were 0).
            let cleared = folded & !(0xFFu64 << (lane * 8));
            assert_eq!(
                cleared, 0,
                "swar lower leaked into other lanes for byte={b:#x} lane={lane}"
            );
        }
    }
    // A full mixed word.
    let w = u64::from_ne_bytes(*b"AbZ@[a1\xff");
    let got = test_swar_ascii_lower(w).to_ne_bytes();
    let want: Vec<u8> = b"AbZ@[a1\xff"
        .iter()
        .map(|c| c.to_ascii_lowercase())
        .collect();
    assert_eq!(&got[..], &want[..], "swar lower mixed word");
}

#[test]
fn strcasecmp_strncasecmp_match_glibc() {
    let mut checked = 0u64;
    let alphabet = b"aB\x80Cd\xffeF";
    for align1 in 0usize..8 {
        for align2 in 0usize..8 {
            for len in 0usize..68 {
                let mut base: Vec<u8> = (0..len).map(|k| alphabet[k % alphabet.len()]).collect();
                base.push(0);

                let mut variants: Vec<Vec<u8>> = vec![base.clone()];
                // Case-swap each letter; single-byte mutations.
                let mut swapped = base.clone();
                for b in swapped.iter_mut() {
                    if b.is_ascii_alphabetic() {
                        *b ^= 0x20;
                    }
                }
                variants.push(swapped);
                for pos in 0..base.len() {
                    for &nb in &[b'a', b'Z', 0x80u8, 0xFFu8, 0u8] {
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
                    let mut b2 = vec![0u64; (align2 + v.len()) / 8 + 2];
                    let p2base = b2.as_mut_ptr().cast::<u8>();
                    unsafe {
                        for (k, &b) in v.iter().enumerate() {
                            *p2base.add(align2 + k) = b;
                        }
                    }
                    let p2 = unsafe { p2base.add(align2) } as *const c_char;

                    let fl = unsafe { fl_strcasecmp(p1, p2) };
                    let gl = unsafe { libc::strcasecmp(p1, p2) };
                    assert_eq!(
                        sign(fl),
                        sign(gl),
                        "strcasecmp a1={align1} a2={align2} len={len} base={base:?} v={v:?}: fl={fl} gl={gl}"
                    );

                    for &n in &[0usize, 1, len / 2, len, len + 1, len + 8] {
                        let fln = unsafe { fl_strncasecmp(p1, p2, n) };
                        let gln = unsafe { libc::strncasecmp(p1, p2, n) };
                        assert_eq!(
                            sign(fln),
                            sign(gln),
                            "strncasecmp a1={align1} a2={align2} len={len} n={n}: fl={fln} gl={gln}"
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

#[test]
fn strcasecmp_does_not_overread_past_guard_page() {
    let page = 4096usize;
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
        let base = base.cast::<u8>();
        assert_eq!(
            libc::mprotect(base.add(page).cast(), page, libc::PROT_NONE),
            0,
            "mprotect failed"
        );
        for nul_back in 1..=16usize {
            let start = base.add(page - nul_back);
            for k in 0..(nul_back - 1) {
                *start.add(k) = b'A';
            }
            *start.add(nul_back - 1) = 0;
            let other = b"aaaaaaaaaaaaaaaaaaaa\0".as_ptr().cast::<c_char>();
            let sp = start.cast::<c_char>();
            let _ = fl_strcasecmp(sp, other);
            let _ = fl_strcasecmp(other, sp);
            let _ = fl_strncasecmp(sp, other, 4096);
            let _ = fl_strncasecmp(other, sp, 4096);
        }
        libc::munmap(base.cast(), page * 2);
    }
}
