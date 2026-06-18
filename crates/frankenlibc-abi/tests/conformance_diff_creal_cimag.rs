#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc creal/cimag oracle

//! Differential gate for creal/cimag/crealf/cimagf (bd-p7phur). The complex
//! transcendentals are fuzzed, but these component extractors were uncovered.
//! Trivial-looking, but the gate catches a re<->im swap or wrong-half read in
//! the SSE,SSE _Complex ABI, and verifies special parts (NaN/+/-inf/+/-0) pass
//! through exactly. creal(z)==z.re, cimag(z)==z.im, bit-for-bit NaN-aware vs
//! host glibc, double + float complex. No mocks.

use frankenlibc_abi::math_abi::{self as fl, CDoubleComplex as C, CFloatComplex as Cf};

unsafe extern "C" {
    fn creal(z: C) -> f64;
    fn cimag(z: C) -> f64;
    fn crealf(z: Cf) -> f32;
    fn cimagf(z: Cf) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const N: f64 = f64::NAN;
const I: f64 = f64::INFINITY;

// distinct re/im so a swap is detectable; plus special parts.
const PARTS: &[(f64, f64)] = &[
    (3.0, 4.0),
    (-3.0, 4.0),
    (3.0, -4.0),
    (0.0, -0.0),
    (-0.0, 0.0),
    (I, 2.0),
    (2.0, -I),
    (N, 5.0),
    (5.0, N),
    (I, N),
    (1.5e300, -2.5e-300),
];

#[test]
fn creal_cimag_match_glibc() {
    for &(re, im) in PARTS {
        let z = C { re, im };
        let gr = unsafe { creal(z) };
        let fr = unsafe { fl::creal(z) };
        assert!(same64(fr, gr), "creal({re:?},{im:?}): fl={fr:?} glibc={gr:?}");
        assert!(same64(fr, re), "creal must return re: got {fr:?} want {re:?}");
        let gi = unsafe { cimag(z) };
        let fi = unsafe { fl::cimag(z) };
        assert!(same64(fi, gi), "cimag({re:?},{im:?}): fl={fi:?} glibc={gi:?}");
        assert!(same64(fi, im), "cimag must return im: got {fi:?} want {im:?}");

        let (ref_, imf) = (re as f32, im as f32);
        let zf = Cf { re: ref_, im: imf };
        let grf = unsafe { crealf(zf) };
        let frf = unsafe { fl::crealf(zf) };
        assert!(same32(frf, grf), "crealf({ref_:?},{imf:?}): fl={frf:?} glibc={grf:?}");
        let gif = unsafe { cimagf(zf) };
        let fif = unsafe { fl::cimagf(zf) };
        assert!(same32(fif, gif), "cimagf({ref_:?},{imf:?}): fl={fif:?} glibc={gif:?}");
    }
}
