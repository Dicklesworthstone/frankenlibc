#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc atan2 oracle

//! Differential gate for f64 atan2/atan2f C99 (Annex F.10.1.4) special cases
//! (bd-mq6t14). f64 atan2 had only an f128 gate + two fl-internal basics — no
//! differential gate over the signed-zero / quadrant / infinity matrix, which
//! is the classic atan2 bug locus (the sign of a +/-0 argument selects between
//! +/-0 and +/-pi results). Bit-for-bit (NaN-aware, so +0 vs -0 is enforced)
//! against host glibc, atan2 + atan2f. No mocks.

unsafe extern "C" {
    fn atan2(y: f64, x: f64) -> f64;
    fn atan2f(y: f32, x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const N: f64 = f64::NAN;
const I: f64 = f64::INFINITY;
const P0: f64 = 0.0;
const M0: f64 = -0.0;

// (y, x) across the full sign/quadrant/inf matrix.
const CASES: &[(f64, f64)] = &[
    // signed-zero over signed-zero
    (P0, P0),
    (M0, P0),
    (P0, M0),
    (M0, M0),
    // signed-zero numerator, signed denominator
    (P0, 1.0),
    (M0, 1.0),
    (P0, -1.0),
    (M0, -1.0),
    // signed value over signed-zero -> +/- pi/2
    (1.0, P0),
    (-1.0, P0),
    (1.0, M0),
    (-1.0, M0),
    // finite over +/-inf -> +/-0 or +/-pi
    (1.0, I),
    (-1.0, I),
    (1.0, -I),
    (-1.0, -I),
    // +/-inf over finite -> +/- pi/2
    (I, 1.0),
    (-I, 1.0),
    (I, -1.0),
    (-I, -1.0),
    // inf over inf -> +/- pi/4 or +/- 3pi/4
    (I, I),
    (-I, I),
    (I, -I),
    (-I, -I),
    // NaN propagation
    (N, 1.0),
    (1.0, N),
    (N, N),
    // ordinary quadrants
    (1.0, 1.0),
    (1.0, -1.0),
    (-1.0, -1.0),
    (-1.0, 1.0),
    (0.5, 2.0),
];

#[test]
fn atan2_special_cases_match_glibc() {
    for &(y, x) in CASES {
        let g = unsafe { atan2(y, x) };
        let f = unsafe { frankenlibc_abi::math_abi::atan2(y, x) };
        assert!(
            same64(f, g),
            "atan2({y:?},{x:?}): fl={f:?} (bits {:#018x}) glibc={g:?} (bits {:#018x})",
            f.to_bits(),
            g.to_bits()
        );
    }
}

#[test]
fn atan2f_special_cases_match_glibc() {
    for &(y, x) in CASES {
        let (yf, xf) = (y as f32, x as f32);
        let g = unsafe { atan2f(yf, xf) };
        let f = unsafe { frankenlibc_abi::math_abi::atan2f(yf, xf) };
        assert!(same32(f, g), "atan2f({yf:?},{xf:?}): fl={f:?} glibc={g:?}");
    }
}
