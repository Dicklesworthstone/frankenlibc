#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc comparison oracle + raw buffers

//! Differential + metamorphic harness for the SIMD comparison family
//! (bd-pcbtt5). strcmp/strcasecmp/strcoll/wmemcmp had diff gates, but
//! memcmp/bcmp/strncmp/strncasecmp — the bounded/byte forms, all SIMD — had
//! NONE, and nothing checked the family's order-relation invariants.
//!
//! Two layers, no mocks:
//!   1. DIFFERENTIAL — for thousands of randomised buffer pairs (varied length,
//!      alignment, alphabet, and difference position — especially the LAST byte,
//!      which stresses the SIMD tail), fl's result SIGN must equal host glibc's.
//!      (C only specifies the sign of the ordered comparisons; bcmp is checked
//!      for zero/non-zero equality.)
//!   2. METAMORPHIC — antisymmetry, reflexivity, the n==0 identity, bcmp⇔memcmp
//!      zero-equivalence, transitivity of the induced order, and strncmp's
//!      agreement with strcmp for an unbounded length.

use std::ffi::{c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
        pub fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
        pub fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
        pub fn strncasecmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
        pub fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    }
}
use frankenlibc_abi::string_abi as fl;

fn sgn(x: c_int) -> i32 {
    x.signum()
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

/// A pair of equal-length byte buffers: identical, or differing at a chosen
/// position (biased toward the last byte to stress SIMD tail handling).
fn rand_pair(rng: &mut Rng, max_len: usize, alpha: u8) -> (Vec<u8>, Vec<u8>) {
    let len = rng.below(max_len + 1);
    let a: Vec<u8> = (0..len).map(|_| rng.byte(alpha)).collect();
    let mut b = a.clone();
    if len > 0 {
        match rng.below(4) {
            0 => {}                            // identical
            1 => {
                let i = len - 1; // last byte (tail)
                b[i] = b[i].wrapping_add(1).max(1);
            }
            _ => {
                let i = rng.below(len);
                b[i] = rng.byte(alpha);
            }
        }
    }
    (a, b)
}

fn rand_cstr(rng: &mut Rng, max_len: usize, alpha: u8) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    let mut v: Vec<u8> = (0..len).map(|_| rng.byte(alpha)).collect();
    v.push(0);
    v
}

#[test]
fn memcmp_bcmp_match_glibc() {
    let mut rng = Rng(0xA5A5_5A5A_C3C3_3C3C);
    for _ in 0..8000 {
        let alpha = [2u8, 3, 16, 255][rng.below(4)];
        let (a, b) = rand_pair(&mut rng, 48, alpha);
        let n = a.len();
        let gm = unsafe { g::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        let fm = unsafe { fl::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        assert_eq!(
            sgn(fm),
            sgn(gm),
            "memcmp sign mismatch a={a:?} b={b:?} n={n}: fl={fm} glibc={gm}"
        );

        // bcmp: zero iff equal (sign is irrelevant per POSIX).
        let gb = unsafe { g::bcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        let fb = unsafe { fl::bcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        assert_eq!(
            fb == 0,
            gb == 0,
            "bcmp zero-ness mismatch a={a:?} b={b:?} n={n}"
        );

        // METAMORPHIC (fl internal): antisymmetry, reflexivity, n==0, bcmp⇔memcmp.
        let fm_rev = unsafe { fl::memcmp(b.as_ptr().cast(), a.as_ptr().cast(), n) };
        assert_eq!(sgn(fm), -sgn(fm_rev), "memcmp antisymmetry a={a:?} b={b:?}");
        assert_eq!(
            unsafe { fl::memcmp(a.as_ptr().cast(), a.as_ptr().cast(), n) },
            0,
            "memcmp reflexivity"
        );
        assert_eq!(
            unsafe { fl::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 0) },
            0,
            "memcmp n==0 identity"
        );
        assert_eq!(
            (fb == 0),
            (fm == 0),
            "bcmp==0 must match memcmp==0 a={a:?} b={b:?}"
        );
    }
}

/// Large-buffer differential: stresses the AVX2 memcmp kernel's 128-byte
/// unrolled main loop, the 32-byte loop, and the overlapping tail window — none
/// of which `memcmp_bcmp_match_glibc` reaches (it caps at n=48). Difference is
/// planted at every kind of position: the last byte (tail), a 32-byte boundary,
/// deep inside an unrolled block, plus the all-equal case.
#[test]
fn memcmp_large_buffers_match_glibc() {
    let mut rng = Rng(0xDEAD_BEEF_1234_5678);
    for _ in 0..6000 {
        let alpha = [2u8, 16, 255][rng.below(3)];
        // Sizes that span the 32/128 boundaries and their neighbours.
        let len = [32usize, 33, 63, 64, 65, 96, 127, 128, 129, 160, 200, 255, 256, 257, 384, 512]
            [rng.below(16)];
        let a: Vec<u8> = (0..len).map(|_| rng.byte(alpha)).collect();
        let mut b = a.clone();
        match rng.below(5) {
            0 => {}                                   // identical
            1 => b[len - 1] = b[len - 1].wrapping_add(1).max(1), // tail
            2 => {
                let i = (len / 32) * 32; // last 32B boundary (or 0)
                let i = i.min(len - 1);
                b[i] = b[i].wrapping_add(1).max(1);
            }
            _ => {
                let i = rng.below(len);
                b[i] = rng.byte(alpha);
            }
        }
        let n = len;
        let gm = unsafe { g::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        let fm = unsafe { fl::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        assert_eq!(
            sgn(fm),
            sgn(gm),
            "large memcmp sign mismatch n={n} alpha={alpha}: fl={fm} glibc={gm}"
        );
        // Antisymmetry on the wide kernel.
        let fm_rev = unsafe { fl::memcmp(b.as_ptr().cast(), a.as_ptr().cast(), n) };
        assert_eq!(sgn(fm), -sgn(fm_rev), "large memcmp antisymmetry n={n}");
    }
}

#[test]
fn strncmp_strncasecmp_match_glibc() {
    let mut rng = Rng(0x0F0F_F0F0_1122_3344);
    for _ in 0..8000 {
        let alpha = [2u8, 4, 26][rng.below(3)];
        let a = rand_cstr(&mut rng, 40, alpha);
        // Sometimes share a prefix with `a` so comparisons hinge on length/n.
        let b = if rng.below(2) == 0 && a.len() > 1 {
            let k = rng.below(a.len()); // keep k bytes (may include NUL region)
            let mut v = a[..k.min(a.len() - 1)].to_vec();
            // optionally extend
            for _ in 0..rng.below(4) {
                v.push(rng.byte(alpha));
            }
            v.push(0);
            v
        } else {
            rand_cstr(&mut rng, 40, alpha)
        };
        let n = rng.below(45); // spans <, ==, > the string lengths

        let gs = unsafe { g::strncmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        let fs = unsafe { fl::strncmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        assert_eq!(
            sgn(fs),
            sgn(gs),
            "strncmp sign mismatch a={a:?} b={b:?} n={n}: fl={fs} glibc={gs}"
        );

        let gci = unsafe { g::strncasecmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        let fci = unsafe { fl::strncasecmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        assert_eq!(
            sgn(fci),
            sgn(gci),
            "strncasecmp sign mismatch a={a:?} b={b:?} n={n}: fl={fci} glibc={gci}"
        );

        // METAMORPHIC: n==0 -> 0; antisymmetry; unbounded strncmp == strcmp sign.
        assert_eq!(
            unsafe { fl::strncmp(a.as_ptr().cast(), b.as_ptr().cast(), 0) },
            0,
            "strncmp n==0 identity"
        );
        let fs_rev = unsafe { fl::strncmp(b.as_ptr().cast(), a.as_ptr().cast(), n) };
        assert_eq!(sgn(fs), -sgn(fs_rev), "strncmp antisymmetry");
        let big = usize::MAX;
        let f_full = unsafe { fl::strncmp(a.as_ptr().cast(), b.as_ptr().cast(), big) };
        let f_strcmp = unsafe { fl::strcmp(a.as_ptr().cast(), b.as_ptr().cast()) };
        // also confirm fl's strcmp matches glibc's strcmp sign here
        let g_strcmp = unsafe { g::strcmp(a.as_ptr().cast(), b.as_ptr().cast()) };
        assert_eq!(sgn(f_strcmp), sgn(g_strcmp), "strcmp sign vs glibc");
        assert_eq!(
            sgn(f_full),
            sgn(f_strcmp),
            "strncmp(SIZE_MAX) must equal strcmp a={a:?} b={b:?}"
        );
    }
}

#[test]
fn ordering_is_transitive() {
    // The order induced by memcmp on fixed-length buffers must be transitive.
    let mut rng = Rng(0x7777_3333_BBBB_1111);
    let n = 8usize;
    for _ in 0..4000 {
        let mk = |rng: &mut Rng| -> Vec<u8> { (0..n).map(|_| rng.byte(3)).collect() };
        let mut trip = [mk(&mut rng), mk(&mut rng), mk(&mut rng)];
        // sort by fl::memcmp, then assert pairwise order is consistent.
        trip.sort_by(|x, y| {
            unsafe { fl::memcmp(x.as_ptr().cast(), y.as_ptr().cast(), n) }.cmp(&0)
        });
        let c01 = unsafe { fl::memcmp(trip[0].as_ptr().cast(), trip[1].as_ptr().cast(), n) };
        let c12 = unsafe { fl::memcmp(trip[1].as_ptr().cast(), trip[2].as_ptr().cast(), n) };
        let c02 = unsafe { fl::memcmp(trip[0].as_ptr().cast(), trip[2].as_ptr().cast(), n) };
        assert!(c01 <= 0 && c12 <= 0, "post-sort order broken");
        // a<=b<=c implies a<=c.
        assert!(c02 <= 0, "transitivity violated: {trip:?}");
    }
}

#[test]
fn edge_cases_match_glibc() {
    // Identical buffers, single byte high-vs-low, full 0xFF vs 0x00.
    let pairs: &[(&[u8], &[u8])] = &[
        (&[], &[]),
        (&[0u8], &[0u8]),
        (&[0x00], &[0xFF]),
        (&[0xFF], &[0x00]),
        (&[1, 2, 3], &[1, 2, 3]),
        (&[1, 2, 3], &[1, 2, 4]),
        (&[1, 2, 4], &[1, 2, 3]),
        (&[0x80], &[0x7F]), // signed-vs-unsigned char trap
        (&[0x7F], &[0x80]),
    ];
    for (a, b) in pairs {
        let n = a.len();
        let gm = unsafe { g::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        let fm = unsafe { fl::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), n) };
        assert_eq!(
            sgn(fm),
            sgn(gm),
            "memcmp edge sign mismatch a={a:?} b={b:?}: fl={fm} glibc={gm}"
        );
    }
}
