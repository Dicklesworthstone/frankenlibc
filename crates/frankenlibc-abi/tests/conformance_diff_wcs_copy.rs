#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wide-copy oracle + raw buffers

//! Differential harness for the wide copy/fill family (bd-jkckh0):
//! wcscpy / wcsncpy / wcpcpy / wcpncpy / wmemcpy / wmemmove / wmemset /
//! wcscat / wcsncat — the wide analog of the narrow copy/fill functions, which
//! had ZERO committed coverage.
//!
//! For thousands of randomised inputs, fl must match host glibc on BOTH the
//! return pointer (as a wchar offset) AND the full destination buffer — so
//! NUL-padding (wcsncpy), the wcpncpy terminator-pointer rule, and overlapping
//! wmemmove are all checked. Astral-plane wchars (>0xFFFF) included. No mocks.

type Wc = libc::wchar_t; // i32

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn wcscpy(d: *mut Wc, s: *const Wc) -> *mut Wc;
        pub fn wcsncpy(d: *mut Wc, s: *const Wc, n: usize) -> *mut Wc;
        pub fn wcpcpy(d: *mut Wc, s: *const Wc) -> *mut Wc;
        pub fn wcpncpy(d: *mut Wc, s: *const Wc, n: usize) -> *mut Wc;
        pub fn wmemcpy(d: *mut Wc, s: *const Wc, n: usize) -> *mut Wc;
        pub fn wmemmove(d: *mut Wc, s: *const Wc, n: usize) -> *mut Wc;
        pub fn wmemset(d: *mut Wc, c: Wc, n: usize) -> *mut Wc;
        pub fn wcscat(d: *mut Wc, s: *const Wc) -> *mut Wc;
        pub fn wcsncat(d: *mut Wc, s: *const Wc, n: usize) -> *mut Wc;
    }
}
use frankenlibc_abi::wchar_abi as fl;

fn woff(p: *const Wc, base: *const Wc) -> isize {
    if p.is_null() {
        -1
    } else {
        ((p as isize) - (base as isize)) / std::mem::size_of::<Wc>() as isize
    }
}
#[inline]
fn u(p: *mut Wc) -> *mut u32 {
    p.cast()
}
#[inline]
fn uc(p: *const Wc) -> *const u32 {
    p.cast()
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
}

const FILL: Wc = 0x7F00_00AA; // distinctive untouched-byte sentinel

fn rand_wstr(rng: &mut Rng, max_len: usize, alpha: &[Wc]) -> Vec<Wc> {
    let len = rng.below(max_len + 1);
    let mut v: Vec<Wc> = (0..len).map(|_| alpha[rng.below(alpha.len())]).collect();
    v.push(0);
    v
}

#[test]
fn wcscpy_wcpcpy_match_glibc() {
    let mut rng = Rng(0x7743_5343_5059_0000);
    let alpha: Vec<Wc> = vec![1, 2, 3, 0x4E2D, 0x1_F600];
    for _ in 0..6000 {
        let src = rand_wstr(&mut rng, 40, &alpha);
        let cap = src.len() + rng.below(8);
        let mut gd = vec![FILL; cap];
        let mut fd = vec![FILL; cap];
        // wcscpy returns dst.
        let gr = unsafe { g::wcscpy(gd.as_mut_ptr(), src.as_ptr()) };
        let fr = unsafe { fl::wcscpy(u(fd.as_mut_ptr()), uc(src.as_ptr())) };
        assert_eq!(woff(fr.cast(), fd.as_ptr()), woff(gr, gd.as_ptr()), "wcscpy ret");
        assert_eq!(fd, gd, "wcscpy content src={src:?}");

        // wcpcpy returns dst + wcslen (pointer to the written NUL).
        let mut gd2 = vec![FILL; cap];
        let mut fd2 = vec![FILL; cap];
        let gr2 = unsafe { g::wcpcpy(gd2.as_mut_ptr(), src.as_ptr()) };
        let fr2 = unsafe { fl::wcpcpy(u(fd2.as_mut_ptr()), uc(src.as_ptr())) };
        assert_eq!(woff(fr2.cast(), fd2.as_ptr()), woff(gr2, gd2.as_ptr()), "wcpcpy ret");
        assert_eq!(fd2, gd2, "wcpcpy content");
        assert_eq!(
            woff(fr2.cast(), fd2.as_ptr()),
            (src.len() - 1) as isize,
            "wcpcpy must return dst+wcslen"
        );
    }
}

#[test]
fn wcsncpy_wcpncpy_match_glibc() {
    let mut rng = Rng(0x776E_6370_5900_0000);
    let alpha: Vec<Wc> = vec![1, 2, 3, 0x20AC];
    for _ in 0..6000 {
        let src = rand_wstr(&mut rng, 30, &alpha);
        let n = rng.below(36); // spans <, ==, > wcslen(src)
        let cap = n + rng.below(6) + 1;
        let mut gd = vec![FILL; cap];
        let mut fd = vec![FILL; cap];
        let gr = unsafe { g::wcsncpy(gd.as_mut_ptr(), src.as_ptr(), n) };
        let fr = unsafe { fl::wcsncpy(u(fd.as_mut_ptr()), uc(src.as_ptr()), n) };
        assert_eq!(woff(fr.cast(), fd.as_ptr()), woff(gr, gd.as_ptr()), "wcsncpy ret");
        assert_eq!(fd, gd, "wcsncpy content src={src:?} n={n}");

        let mut gd2 = vec![FILL; cap];
        let mut fd2 = vec![FILL; cap];
        let gr2 = unsafe { g::wcpncpy(gd2.as_mut_ptr(), src.as_ptr(), n) };
        let fr2 = unsafe { fl::wcpncpy(u(fd2.as_mut_ptr()), uc(src.as_ptr()), n) };
        assert_eq!(woff(fr2.cast(), fd2.as_ptr()), woff(gr2, gd2.as_ptr()), "wcpncpy ret n={n}");
        assert_eq!(fd2, gd2, "wcpncpy content src={src:?} n={n}");
    }
}

#[test]
fn wmemcpy_wmemset_match_glibc() {
    let mut rng = Rng(0x776D_656D_0000_0000);
    let alpha: Vec<Wc> = vec![1, 2, 0x10FFFF, 0, 0x4E2D];
    for _ in 0..6000 {
        let n = rng.below(64);
        let src: Vec<Wc> = (0..n).map(|_| alpha[rng.below(alpha.len())]).collect();
        let cap = n + rng.below(6);
        let mut gd = vec![FILL; cap];
        let mut fd = vec![FILL; cap];
        let gr = unsafe { g::wmemcpy(gd.as_mut_ptr(), src.as_ptr(), n) };
        let fr = unsafe { fl::wmemcpy(u(fd.as_mut_ptr()), uc(src.as_ptr()), n) };
        assert_eq!(woff(fr.cast(), fd.as_ptr()), woff(gr, gd.as_ptr()), "wmemcpy ret");
        assert_eq!(fd, gd, "wmemcpy content n={n}");

        // wmemset
        let c: Wc = alpha[rng.below(alpha.len())];
        let mut gs = vec![FILL; cap];
        let mut fs = vec![FILL; cap];
        let grs = unsafe { g::wmemset(gs.as_mut_ptr(), c, n) };
        let frs = unsafe { fl::wmemset(u(fs.as_mut_ptr()), c as u32, n) };
        assert_eq!(woff(frs.cast(), fs.as_ptr()), woff(grs, gs.as_ptr()), "wmemset ret");
        assert_eq!(fs, gs, "wmemset content n={n} c={c}");
        assert!(fs[..n].iter().all(|&w| w == c), "wmemset filled prefix");
    }
}

#[test]
fn wmemmove_overlap_matches_glibc() {
    let mut rng = Rng(0x776D_6F76_0000_0000);
    for _ in 0..6000 {
        let len = 8 + rng.below(40);
        let base: Vec<Wc> = (0..len).map(|i| (i as Wc) * 3 + 1).collect();
        let n = rng.below(len + 1);
        let so = rng.below(len - n + 1);
        let dom = rng.below(len - n + 1); // overlapping dst/src within one buffer
        let mut gb = base.clone();
        let mut fb = base.clone();
        let gr = unsafe {
            g::wmemmove(gb.as_mut_ptr().add(dom), gb.as_ptr().add(so), n)
        };
        let fr = unsafe {
            fl::wmemmove(u(fb.as_mut_ptr().add(dom)), uc(fb.as_ptr().add(so)), n)
        };
        assert_eq!(
            woff(fr.cast(), fb.as_ptr()),
            woff(gr, gb.as_ptr()),
            "wmemmove ret dom={dom} so={so} n={n}"
        );
        assert_eq!(fb, gb, "wmemmove overlap content dom={dom} so={so} n={n}");
    }
}

#[test]
fn wcscat_wcsncat_match_glibc() {
    let mut rng = Rng(0x7763_6174_0000_0000);
    let alpha: Vec<Wc> = vec![1, 2, 3, 0x1_0348];
    for _ in 0..6000 {
        let init = rand_wstr(&mut rng, 16, &alpha); // includes NUL
        let dlen = init.len() - 1;
        let src = rand_wstr(&mut rng, 24, &alpha);
        let slen = src.len() - 1;
        let cap = dlen + slen + 4;

        let mk = || -> Vec<Wc> {
            let mut v = vec![FILL; cap];
            v[..init.len()].copy_from_slice(&init);
            v
        };
        // wcscat
        let mut gd = mk();
        let mut fd = mk();
        let gr = unsafe { g::wcscat(gd.as_mut_ptr(), src.as_ptr()) };
        let fr = unsafe { fl::wcscat(u(fd.as_mut_ptr()), uc(src.as_ptr())) };
        assert_eq!(woff(fr.cast(), fd.as_ptr()), woff(gr, gd.as_ptr()), "wcscat ret");
        assert_eq!(fd, gd, "wcscat content init={init:?} src={src:?}");

        // wcsncat with n spanning <, ==, > slen
        let n = rng.below(slen + 4);
        let cap2 = dlen + n + 4;
        let mk2 = || -> Vec<Wc> {
            let mut v = vec![FILL; cap2];
            v[..init.len()].copy_from_slice(&init);
            v
        };
        let mut gd2 = mk2();
        let mut fd2 = mk2();
        let gr2 = unsafe { g::wcsncat(gd2.as_mut_ptr(), src.as_ptr(), n) };
        let fr2 = unsafe { fl::wcsncat(u(fd2.as_mut_ptr()), uc(src.as_ptr()), n) };
        assert_eq!(woff(fr2.cast(), fd2.as_ptr()), woff(gr2, gd2.as_ptr()), "wcsncat ret n={n}");
        assert_eq!(fd2, gd2, "wcsncat content init={init:?} src={src:?} n={n}");
    }
}
