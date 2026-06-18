#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc copy oracle + raw buffers

//! Differential + metamorphic harness for the copy/fill stragglers
//! (bd-99odcf): mempcpy / memccpy / strlcpy / strlcat. memcpy/memmove/memset/
//! stpcpy/stpncpy/strncpy had diff gates, but these four — each with subtle
//! return-value semantics (end pointer / sentinel pointer / would-be length /
//! truncation) — had NONE.
//!
//! For thousands of randomised inputs, fl must match host glibc on BOTH the
//! return value AND the resulting destination bytes (the whole buffer, so
//! untouched-tail behaviour is checked too). Plus metamorphic invariants on the
//! documented contracts. No mocks.

use std::ffi::{c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn mempcpy(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void;
        pub fn memccpy(d: *mut c_void, s: *const c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn strlcpy(d: *mut c_char, s: *const c_char, n: usize) -> usize;
        pub fn strlcat(d: *mut c_char, s: *const c_char, n: usize) -> usize;
    }
}
use frankenlibc_abi::string_abi as fl;

fn off(p: *const c_void, base: *const c_void) -> isize {
    if p.is_null() {
        -1
    } else {
        (p as isize) - (base as isize)
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
    fn byte(&mut self, alpha: u8) -> u8 {
        1 + (self.next() % (alpha as u64)) as u8
    }
}

const FILL: u8 = 0xAA; // sentinel for untouched destination bytes

#[test]
fn mempcpy_matches_glibc() {
    let mut rng = Rng(0x4D45_4D50_4350_5900);
    for _ in 0..6000 {
        let alpha = [2u8, 16, 255][rng.below(3)];
        let n = rng.below(64);
        let src: Vec<u8> = (0..n).map(|_| rng.byte(alpha)).collect();
        let cap = n + rng.below(8); // dst at least n
        let mut gd = vec![FILL; cap];
        let mut fd = vec![FILL; cap];
        let gr = unsafe { g::mempcpy(gd.as_mut_ptr().cast(), src.as_ptr().cast(), n) };
        let fr = unsafe { fl::mempcpy(fd.as_mut_ptr().cast(), src.as_ptr().cast(), n) };
        assert_eq!(
            off(fr, fd.as_ptr().cast()),
            off(gr, gd.as_ptr().cast()),
            "mempcpy return offset n={n}"
        );
        assert_eq!(fd, gd, "mempcpy content n={n}");
        // METAMORPHIC: returns dst+n; copied prefix == src; tail untouched.
        assert_eq!(off(fr, fd.as_ptr().cast()), n as isize, "mempcpy must return dst+n");
        assert_eq!(&fd[..n], &src[..], "mempcpy prefix");
        assert!(fd[n..].iter().all(|&b| b == FILL), "mempcpy tail untouched");
    }
}

#[test]
fn memccpy_matches_glibc() {
    let mut rng = Rng(0x4D45_4343_5059_0000);
    for _ in 0..6000 {
        let alpha = [2u8, 4, 16][rng.below(3)];
        let n = rng.below(64);
        let src: Vec<u8> = (0..n).map(|_| rng.byte(alpha)).collect();
        // sentinel byte: sometimes present in src, sometimes not.
        let c: c_int = if n > 0 && rng.below(2) == 0 {
            src[rng.below(n)] as c_int
        } else {
            rng.byte(alpha) as c_int
        };
        let cap = n + rng.below(8);
        let mut gd = vec![FILL; cap];
        let mut fd = vec![FILL; cap];
        let gr = unsafe { g::memccpy(gd.as_mut_ptr().cast(), src.as_ptr().cast(), c, n) };
        let fr = unsafe { fl::memccpy(fd.as_mut_ptr().cast(), src.as_ptr().cast(), c, n) };
        assert_eq!(
            off(fr, fd.as_ptr().cast()),
            off(gr, gd.as_ptr().cast()),
            "memccpy return offset n={n} c={c}"
        );
        assert_eq!(fd, gd, "memccpy content n={n} c={c} src={src:?}");
        // METAMORPHIC: if c at first index i, return == dst+i+1 and prefix copied;
        // else NULL and all n bytes copied.
        let found = src[..n].iter().position(|&b| b as c_int == c);
        match found {
            Some(i) => {
                assert_eq!(off(fr, fd.as_ptr().cast()), (i + 1) as isize, "memccpy stop+1");
                assert_eq!(&fd[..=i], &src[..=i], "memccpy copied through sentinel");
            }
            None => {
                assert!(fr.is_null(), "memccpy not-found -> NULL");
                assert_eq!(&fd[..n], &src[..n], "memccpy full copy when absent");
            }
        }
    }
}

#[test]
fn strlcpy_matches_glibc() {
    let mut rng = Rng(0x5354_524C_4350_0000);
    for _ in 0..6000 {
        let alpha = [2u8, 8][rng.below(2)];
        let slen = rng.below(40);
        let mut src: Vec<c_char> = (0..slen).map(|_| rng.byte(alpha) as c_char).collect();
        src.push(0);
        // size spans <, ==, > strlen(src)+1 and includes 0.
        let size = rng.below(45);
        let cap = size.max(1) + 4;
        let mut gd = vec![FILL as c_char; cap];
        let mut fd = vec![FILL as c_char; cap];
        let gr = unsafe { g::strlcpy(gd.as_mut_ptr(), src.as_ptr(), size) };
        let fr = unsafe { fl::strlcpy(fd.as_mut_ptr(), src.as_ptr(), size) };
        assert_eq!(fr, gr, "strlcpy return slen={slen} size={size}");
        assert_eq!(fd, gd, "strlcpy content slen={slen} size={size}");
        // METAMORPHIC: return is always strlen(src) regardless of size.
        assert_eq!(fr, slen, "strlcpy must return source length");
        if size > 0 {
            // dst is NUL-terminated within [0,size).
            let copied = slen.min(size - 1);
            assert_eq!(fd[copied], 0, "strlcpy NUL terminator at min(slen,size-1)");
        }
    }
}

#[test]
fn strlcat_matches_glibc() {
    let mut rng = Rng(0x5354_524C_4341_0000);
    for _ in 0..6000 {
        let alpha = [2u8, 8][rng.below(2)];
        let dlen = rng.below(20); // initial dst content length
        let slen = rng.below(30);
        let size = rng.below(60);
        let cap = size.max(dlen + 1) + 4;

        let init: Vec<u8> = (0..dlen).map(|_| rng.byte(alpha)).collect();
        let mut src: Vec<c_char> = (0..slen).map(|_| rng.byte(alpha) as c_char).collect();
        src.push(0);

        // Build identical pre-filled dst buffers (init string + NUL + sentinel).
        let mk_dst = || -> Vec<c_char> {
            let mut v = vec![FILL as c_char; cap];
            for (i, &b) in init.iter().enumerate() {
                v[i] = b as c_char;
            }
            if dlen < cap {
                v[dlen] = 0;
            }
            v
        };
        let mut gd = mk_dst();
        let mut fd = mk_dst();
        let gr = unsafe { g::strlcat(gd.as_mut_ptr(), src.as_ptr(), size) };
        let fr = unsafe { fl::strlcat(fd.as_mut_ptr(), src.as_ptr(), size) };
        assert_eq!(
            fr, gr,
            "strlcat return dlen={dlen} slen={slen} size={size}"
        );
        assert_eq!(
            fd, gd,
            "strlcat content dlen={dlen} slen={slen} size={size} init={init:?}"
        );
        // METAMORPHIC: return == min(dlen, size) + slen (BSD contract).
        assert_eq!(fr, dlen.min(size) + slen, "strlcat return formula");
    }
}
