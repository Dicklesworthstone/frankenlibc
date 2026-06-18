#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc string-search oracle + raw pointer math

//! Differential + metamorphic harness for the SIMD-optimised string-search
//! family (bd-7xqyx8). Before this, strchr/strrchr/strchrnul had individual
//! diff gates but strstr/memmem/memchr/strcasestr/strpbrk/strspn/strcspn/
//! rawmemchr had NONE, and nothing cross-checked the family for internal
//! consistency.
//!
//! Two layers, no mocks:
//!   1. DIFFERENTIAL — for thousands of randomised inputs (varied alignment,
//!      length, byte alphabet, needle presence/position, and the empty/NUL edge
//!      cases that stress SIMD tail handling), fl's result OFFSET must equal the
//!      host glibc result offset, byte-for-byte.
//!   2. METAMORPHIC — cross-consistency invariants that must hold regardless of
//!      the implementation (strchr vs memchr vs strchrnul; strstr vs memmem;
//!      rawmemchr vs memchr; strspn/strcspn complementarity).
//!
//! Bare `extern "C"` names resolve to host glibc in the test binary (fl's
//! symbols are not no_mangle in test builds); fl is reached via the crate path.

use std::ffi::{c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn strstr(h: *const c_char, n: *const c_char) -> *mut c_char;
        pub fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char;
        pub fn memmem(
            h: *const c_void,
            hl: usize,
            n: *const c_void,
            nl: usize,
        ) -> *mut c_void;
        pub fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strrchr(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strpbrk(s: *const c_char, a: *const c_char) -> *mut c_char;
        pub fn strspn(s: *const c_char, a: *const c_char) -> usize;
        pub fn strcspn(s: *const c_char, a: *const c_char) -> usize;
    }
}

use frankenlibc_abi::string_abi as fl;

/// Offset of `p` from `base`, or -1 if `p` is NULL. Both impls operate on the
/// same buffer, so equal offsets ⟺ identical results.
fn off(p: *const c_void, base: *const c_void) -> isize {
    if p.is_null() {
        -1
    } else {
        (p as isize) - (base as isize)
    }
}

/// Deterministic xorshift64* PRNG — reproducible, no external entropy.
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
    /// A byte drawn from a small alphabet of `alpha` distinct values (1..=255),
    /// so matches and repeats are frequent (stresses overlap/backtrack paths).
    fn byte(&mut self, alpha: u8) -> u8 {
        1 + (self.next() % (alpha as u64)) as u8
    }
}

/// Build a random NUL-terminated C string (no embedded NULs) plus its bytes.
fn rand_cstr(rng: &mut Rng, max_len: usize, alpha: u8) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    let mut v: Vec<u8> = (0..len).map(|_| rng.byte(alpha)).collect();
    v.push(0);
    v
}

/// Build a random byte buffer that MAY contain embedded NULs (for mem* funcs).
fn rand_bytes(rng: &mut Rng, max_len: usize, alpha: u8) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    (0..len)
        .map(|_| {
            // ~1/8 chance of an embedded NUL to exercise the mem* NUL handling.
            if rng.below(8) == 0 {
                0
            } else {
                rng.byte(alpha)
            }
        })
        .collect()
}

#[test]
fn strstr_memmem_strcasestr_match_glibc() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..6000 {
        let alpha = [2u8, 3, 5, 26][rng.below(4)];
        let hay = rand_cstr(&mut rng, 40, alpha);
        // Sometimes splice a copy of a haystack slice as the needle so it is
        // actually present at a known-ish position; sometimes fully random.
        let needle = if !hay.is_empty() && rng.below(2) == 0 && hay.len() > 1 {
            let hlen = hay.len() - 1; // exclude NUL
            let start = if hlen == 0 { 0 } else { rng.below(hlen) };
            let end = start + rng.below(hlen - start + 1);
            let mut n: Vec<u8> = hay[start..end].to_vec();
            n.push(0);
            n
        } else {
            rand_cstr(&mut rng, 6, alpha)
        };

        let g_ss = unsafe { g::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        let f_ss = unsafe { fl::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        assert_eq!(
            off(f_ss.cast(), hay.as_ptr().cast()),
            off(g_ss.cast(), hay.as_ptr().cast()),
            "strstr mismatch hay={hay:?} needle={needle:?}"
        );

        // strcasestr: same contract, ASCII-case-insensitive.
        let g_ci = unsafe { g::strcasestr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        let f_ci = unsafe { fl::strcasestr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        assert_eq!(
            off(f_ci.cast(), hay.as_ptr().cast()),
            off(g_ci.cast(), hay.as_ptr().cast()),
            "strcasestr mismatch hay={hay:?} needle={needle:?}"
        );

        // memmem over the byte bodies (excluding the NUL terminators).
        let hb = &hay[..hay.len().saturating_sub(1)];
        let nb = &needle[..needle.len().saturating_sub(1)];
        let g_mm = unsafe { g::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        let f_mm =
            unsafe { fl::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        assert_eq!(
            off(f_mm.cast(), hb.as_ptr().cast()),
            off(g_mm.cast(), hb.as_ptr().cast()),
            "memmem mismatch hay={hb:?} needle={nb:?}"
        );

        // METAMORPHIC: strstr presence ⟺ memmem presence at the same offset
        // (when the needle has no embedded NUL, which rand_cstr guarantees).
        assert_eq!(
            off(f_ss.cast(), hay.as_ptr().cast()),
            off(f_mm.cast(), hb.as_ptr().cast()),
            "strstr vs memmem disagree hay={hay:?} needle={needle:?}"
        );
    }
}

#[test]
fn memchr_strchr_family_match_glibc() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for _ in 0..6000 {
        let alpha = [2u8, 4, 16][rng.below(3)];
        let s = rand_cstr(&mut rng, 48, alpha);
        let slen = s.len() - 1; // strlen
        // Search byte: bias toward bytes present in s and the NUL.
        let c: c_int = match rng.below(4) {
            0 => 0,
            1 if slen > 0 => s[rng.below(slen)] as c_int,
            _ => rng.byte(alpha) as c_int,
        };

        // strchr vs glibc.
        let gc = unsafe { g::strchr(s.as_ptr().cast(), c) };
        let fc = unsafe { fl::strchr(s.as_ptr().cast(), c) };
        assert_eq!(
            off(fc.cast(), s.as_ptr().cast()),
            off(gc.cast(), s.as_ptr().cast()),
            "strchr mismatch s={s:?} c={c}"
        );

        // strrchr vs glibc.
        let gr = unsafe { g::strrchr(s.as_ptr().cast(), c) };
        let fr = unsafe { fl::strrchr(s.as_ptr().cast(), c) };
        assert_eq!(
            off(fr.cast(), s.as_ptr().cast()),
            off(gr.cast(), s.as_ptr().cast()),
            "strrchr mismatch s={s:?} c={c}"
        );

        // strchrnul vs glibc (never NULL: returns NUL terminator when absent).
        let gn = unsafe { g::strchrnul(s.as_ptr().cast(), c) };
        let fn_ = unsafe { fl::strchrnul(s.as_ptr().cast(), c) };
        assert_eq!(
            off(fn_.cast(), s.as_ptr().cast()),
            off(gn.cast(), s.as_ptr().cast()),
            "strchrnul mismatch s={s:?} c={c}"
        );

        // memchr over the body INCLUDING the terminator so the c==0 case can be
        // located (matches strchr's NUL-finding behaviour).
        let n = slen + 1;
        let gm = unsafe { g::memchr(s.as_ptr().cast(), c, n) };
        let fm = unsafe { fl::memchr(s.as_ptr().cast(), c, n) };
        assert_eq!(
            off(fm.cast(), s.as_ptr().cast()),
            off(gm.cast(), s.as_ptr().cast()),
            "memchr mismatch s={s:?} c={c} n={n}"
        );

        // METAMORPHIC invariants (fl internal consistency):
        // strchr(s,c) == memchr(s,c,strlen+1) for the byte c.
        assert_eq!(
            off(fc.cast(), s.as_ptr().cast()),
            off(fm.cast(), s.as_ptr().cast()),
            "strchr vs memchr disagree s={s:?} c={c}"
        );
        // strchrnul == strchr when found, else points at the NUL terminator.
        let chrnul_off = off(fn_.cast(), s.as_ptr().cast());
        if !fc.is_null() {
            assert_eq!(chrnul_off, off(fc.cast(), s.as_ptr().cast()));
        } else {
            assert_eq!(chrnul_off, slen as isize, "strchrnul must point at NUL");
        }
        // strchr(s,0) is always the terminator.
        if c == 0 {
            assert_eq!(off(fc.cast(), s.as_ptr().cast()), slen as isize);
        }
    }
}

#[test]
fn strpbrk_strspn_strcspn_match_glibc() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..6000 {
        let alpha = [2u8, 3, 8][rng.below(3)];
        let s = rand_cstr(&mut rng, 40, alpha);
        let set = rand_cstr(&mut rng, 6, alpha);

        let gp = unsafe { g::strpbrk(s.as_ptr().cast(), set.as_ptr().cast()) };
        let fp = unsafe { fl::strpbrk(s.as_ptr().cast(), set.as_ptr().cast()) };
        assert_eq!(
            off(fp.cast(), s.as_ptr().cast()),
            off(gp.cast(), s.as_ptr().cast()),
            "strpbrk mismatch s={s:?} set={set:?}"
        );

        let g_spn = unsafe { g::strspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        let f_spn = unsafe { fl::strspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        assert_eq!(f_spn, g_spn, "strspn mismatch s={s:?} set={set:?}");

        let g_csp = unsafe { g::strcspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        let f_csp = unsafe { fl::strcspn(s.as_ptr().cast(), set.as_ptr().cast()) };
        assert_eq!(f_csp, g_csp, "strcspn mismatch s={s:?} set={set:?}");

        // METAMORPHIC: the prefix of `s` of length strcspn(s,set) contains no
        // char of `set`, and the char at that index (if < strlen) IS in `set`
        // and equals strpbrk's hit.
        let slen = s.len() - 1;
        if f_csp < slen {
            assert_eq!(
                off(fp.cast(), s.as_ptr().cast()),
                f_csp as isize,
                "strpbrk must hit the first reject char (= strcspn index)"
            );
        } else {
            assert!(fp.is_null(), "no reject char -> strpbrk NULL");
        }
    }
}

#[test]
fn rawmemchr_matches_memchr_when_present() {
    // rawmemchr assumes the byte IS present; cross-check against memchr.
    let mut rng = Rng(0x0BAD_C0DE_1337_4242);
    for _ in 0..4000 {
        let alpha = [2u8, 5, 12][rng.below(3)];
        let mut buf = rand_bytes(&mut rng, 40, alpha);
        // Guarantee a sentinel byte is present by appending it.
        let c = rng.byte(alpha);
        buf.push(c);
        let n = buf.len();
        let fm = unsafe { fl::memchr(buf.as_ptr().cast(), c as c_int, n) };
        let fr = unsafe { fl::rawmemchr(buf.as_ptr().cast(), c as c_int) };
        assert_eq!(
            off(fr, buf.as_ptr().cast()),
            off(fm, buf.as_ptr().cast()),
            "rawmemchr vs memchr disagree buf={buf:?} c={c}"
        );
    }
}

#[test]
fn empty_and_edge_cases_match_glibc() {
    // Empty haystack, empty needle, needle longer than haystack, single byte.
    let cases: &[(&[u8], &[u8])] = &[
        (b"\0", b"\0"),       // both empty
        (b"abc\0", b"\0"),    // empty needle -> haystack
        (b"\0", b"x\0"),      // empty haystack, non-empty needle
        (b"abc\0", b"abcd\0"), // needle longer
        (b"aaaa\0", b"aa\0"), // overlapping repeats
        (b"abcabc\0", b"bca\0"),
        (b"x\0", b"x\0"),
    ];
    for (hay, needle) in cases {
        let g_ss = unsafe { g::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        let f_ss = unsafe { fl::strstr(hay.as_ptr().cast(), needle.as_ptr().cast()) };
        assert_eq!(
            off(f_ss.cast(), hay.as_ptr().cast()),
            off(g_ss.cast(), hay.as_ptr().cast()),
            "strstr edge mismatch hay={hay:?} needle={needle:?}"
        );
        let hb = &hay[..hay.len() - 1];
        let nb = &needle[..needle.len() - 1];
        let g_mm = unsafe { g::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        let f_mm =
            unsafe { fl::memmem(hb.as_ptr().cast(), hb.len(), nb.as_ptr().cast(), nb.len()) };
        assert_eq!(
            off(f_mm.cast(), hb.as_ptr().cast()),
            off(g_mm.cast(), hb.as_ptr().cast()),
            "memmem edge mismatch hay={hb:?} needle={nb:?}"
        );
    }
    // memchr with n==0 is always NULL.
    let buf = [1u8, 2, 3];
    assert!(unsafe { fl::memchr(buf.as_ptr().cast(), 1, 0) }.is_null());
    assert!(unsafe { g::memchr(buf.as_ptr().cast(), 1, 0) }.is_null());
}
