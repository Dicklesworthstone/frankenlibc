#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wide-string oracle + raw buffers

//! Differential + metamorphic harness for uncovered wide-char string fns
//! (bd-m2bbva). wcscmp/wcschr/wcsrchr/wcsspn/wcsstr/wcscasecmp had gates, but
//! the bounded/byte/search forms wcsncmp / wcsncasecmp / wcspbrk / wcscspn /
//! wmemchr / wcschrnul had NONE.
//!
//! No mocks: for thousands of randomised wide strings (small alphabets that
//! force matches/overlaps, ASCII letters for case-folding, and astral-plane
//! wchars beyond the BMP), fl's result must equal host glibc's — SIGN for the
//! ordered compares, OFFSET for the searches, exact value for wcscspn — plus
//! metamorphic invariants (antisymmetry, n==0 identity, wcspbrk⇔wcscspn,
//! wcschrnul⇔wmemchr).

use std::ffi::c_int;

type Wc = libc::wchar_t; // i32 on Linux

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn wcsncmp(a: *const Wc, b: *const Wc, n: usize) -> c_int;
        pub fn wcsncasecmp(a: *const Wc, b: *const Wc, n: usize) -> c_int;
        pub fn wcspbrk(s: *const Wc, set: *const Wc) -> *mut Wc;
        pub fn wcscspn(s: *const Wc, set: *const Wc) -> usize;
        pub fn wmemchr(s: *const Wc, c: Wc, n: usize) -> *mut Wc;
        pub fn wcschrnul(s: *const Wc, c: Wc) -> *mut Wc;
    }
}
use frankenlibc_abi::wchar_abi as fl;

fn sgn(x: c_int) -> i32 {
    x.signum()
}
/// Offset in wchar units from `base`, or -1 for NULL.
fn woff(p: *const Wc, base: *const Wc) -> isize {
    if p.is_null() {
        -1
    } else {
        ((p as isize) - (base as isize)) / std::mem::size_of::<Wc>() as isize
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
}

/// NUL-terminated wide string drawn from `alphabet`.
fn rand_wstr(rng: &mut Rng, max_len: usize, alphabet: &[Wc]) -> Vec<Wc> {
    let len = rng.below(max_len + 1);
    let mut v: Vec<Wc> = (0..len).map(|_| alphabet[rng.below(alphabet.len())]).collect();
    v.push(0);
    v
}

// Helpers to pass an i32 buffer to fl fns that take *const u32 (same repr).
#[inline]
fn u32p(p: *const Wc) -> *const u32 {
    p.cast()
}

#[test]
fn wcsncmp_wcsncasecmp_match_glibc() {
    let mut rng = Rng(0x57AB_1E00_DEAD_BEEF);
    // Alphabet mixes ASCII case pairs (for casefold), a couple BMP and astral.
    let alpha: Vec<Wc> = vec![
        b'a' as Wc, b'A' as Wc, b'b' as Wc, b'B' as Wc, b'z' as Wc, b'Z' as Wc,
        0x00E9, 0x4E2D, 0x1_0348,
    ];
    for _ in 0..8000 {
        let a = rand_wstr(&mut rng, 24, &alpha);
        let b = if rng.below(2) == 0 && a.len() > 1 {
            // share a prefix so length/n drives the result
            let k = rng.below(a.len() - 1);
            let mut v = a[..k].to_vec();
            for _ in 0..rng.below(4) {
                v.push(alpha[rng.below(alpha.len())]);
            }
            v.push(0);
            v
        } else {
            rand_wstr(&mut rng, 24, &alpha)
        };
        let n = rng.below(28);

        let gc = unsafe { g::wcsncmp(a.as_ptr(), b.as_ptr(), n) };
        let fc = unsafe { fl::wcsncmp(u32p(a.as_ptr()), u32p(b.as_ptr()), n) };
        assert_eq!(sgn(fc), sgn(gc), "wcsncmp sign a={a:?} b={b:?} n={n}: fl={fc} g={gc}");

        let gci = unsafe { g::wcsncasecmp(a.as_ptr(), b.as_ptr(), n) };
        let fci = unsafe { fl::wcsncasecmp(u32p(a.as_ptr()), u32p(b.as_ptr()), n) };
        assert_eq!(
            sgn(fci),
            sgn(gci),
            "wcsncasecmp sign a={a:?} b={b:?} n={n}: fl={fci} g={gci}"
        );

        // METAMORPHIC: antisymmetry + n==0 identity.
        let fc_rev = unsafe { fl::wcsncmp(u32p(b.as_ptr()), u32p(a.as_ptr()), n) };
        assert_eq!(sgn(fc), -sgn(fc_rev), "wcsncmp antisymmetry");
        assert_eq!(
            unsafe { fl::wcsncmp(u32p(a.as_ptr()), u32p(b.as_ptr()), 0) },
            0,
            "wcsncmp n==0 identity"
        );
    }
}

#[test]
fn wcspbrk_wcscspn_match_glibc() {
    let mut rng = Rng(0x1122_3344_5566_7788);
    let alpha: Vec<Wc> = vec![1, 2, 3, 0x4E2D, 0x1_0000];
    for _ in 0..8000 {
        let s = rand_wstr(&mut rng, 24, &alpha);
        let set = rand_wstr(&mut rng, 5, &alpha);

        let gp = unsafe { g::wcspbrk(s.as_ptr(), set.as_ptr()) };
        let fp = unsafe { fl::wcspbrk(u32p(s.as_ptr()), u32p(set.as_ptr())) };
        assert_eq!(
            woff(fp.cast(), s.as_ptr()),
            woff(gp, s.as_ptr()),
            "wcspbrk s={s:?} set={set:?}"
        );

        let gspn = unsafe { g::wcscspn(s.as_ptr(), set.as_ptr()) };
        let fspn = unsafe { fl::wcscspn(u32p(s.as_ptr()), u32p(set.as_ptr())) };
        assert_eq!(fspn, gspn, "wcscspn s={s:?} set={set:?}");

        // METAMORPHIC: wcspbrk hit index == wcscspn (first reject char), else NULL.
        let slen = s.len() - 1;
        if fspn < slen {
            assert_eq!(woff(fp.cast(), s.as_ptr()), fspn as isize, "wcspbrk==wcscspn idx");
        } else {
            assert!(fp.is_null(), "no reject -> wcspbrk NULL");
        }
    }
}

#[test]
fn wmemchr_wcschrnul_match_glibc() {
    let mut rng = Rng(0x99AA_BBCC_DDEE_FF00);
    let alpha: Vec<Wc> = vec![1, 2, 3, 4, 0x20AC, 0x1_F600];
    for _ in 0..8000 {
        let s = rand_wstr(&mut rng, 28, &alpha);
        let slen = s.len() - 1;
        // search wchar: bias to present, NUL, and absent.
        let c: Wc = match rng.below(4) {
            0 => 0,
            1 if slen > 0 => s[rng.below(slen)],
            _ => 0x7_FFFF, // very unlikely to be present
        };

        // wmemchr over body + terminator so c==0 is locatable.
        let n = slen + 1;
        let gm = unsafe { g::wmemchr(s.as_ptr(), c, n) };
        let fm = unsafe { fl::wmemchr(u32p(s.as_ptr()), c as u32, n) };
        assert_eq!(woff(fm.cast(), s.as_ptr()), woff(gm, s.as_ptr()), "wmemchr s={s:?} c={c}");

        // wcschrnul: never NULL; returns terminator when absent.
        let gn = unsafe { g::wcschrnul(s.as_ptr(), c) };
        let fnn = unsafe { fl::wcschrnul(s.as_ptr(), c) };
        assert_eq!(
            woff(fnn, s.as_ptr()),
            woff(gn, s.as_ptr()),
            "wcschrnul s={s:?} c={c}"
        );

        // METAMORPHIC: wcschrnul == wmemchr(strlen+1) when found, else terminator.
        let chrnul = woff(fnn, s.as_ptr());
        let memchr_off = woff(fm.cast(), s.as_ptr());
        if memchr_off >= 0 {
            assert_eq!(chrnul, memchr_off, "wcschrnul vs wmemchr disagree");
        } else {
            assert_eq!(chrnul, slen as isize, "wcschrnul must point at terminator");
        }
    }
}

#[test]
fn edge_cases_match_glibc() {
    let mk = |v: &[i32]| -> Vec<Wc> {
        let mut x: Vec<Wc> = v.to_vec();
        x.push(0);
        x
    };
    // (a, b, n) for wcsncmp; and (s, set) for wcspbrk/wcscspn.
    let a = mk(&[]);
    let b = mk(&[1]);
    assert_eq!(
        sgn(unsafe { fl::wcsncmp(u32p(a.as_ptr()), u32p(b.as_ptr()), 5) }),
        sgn(unsafe { g::wcsncmp(a.as_ptr(), b.as_ptr(), 5) }),
        "empty vs non-empty wcsncmp"
    );
    // astral-plane difference at the tail
    let a2 = mk(&[5, 5, 0x1_0000]);
    let b2 = mk(&[5, 5, 0x1_0001]);
    assert_eq!(
        sgn(unsafe { fl::wcsncmp(u32p(a2.as_ptr()), u32p(b2.as_ptr()), 3) }),
        sgn(unsafe { g::wcsncmp(a2.as_ptr(), b2.as_ptr(), 3) }),
        "astral tail wcsncmp"
    );
    // wcspbrk with empty set -> NULL; wcscspn -> strlen
    let s = mk(&[1, 2, 3]);
    let empty = mk(&[]);
    assert!(unsafe { fl::wcspbrk(u32p(s.as_ptr()), u32p(empty.as_ptr())) }.is_null());
    assert_eq!(unsafe { fl::wcscspn(u32p(s.as_ptr()), u32p(empty.as_ptr())) }, 3);
    // wmemchr n==0 -> NULL
    assert!(unsafe { fl::wmemchr(u32p(s.as_ptr()), 1, 0) }.is_null());
}
