#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc hypot oracle

//! Differential gate for f64 hypot/hypotf C99 (Annex F.10.4.3) special cases
//! (bd-nlwr1c). f64 hypot had only an errno test and fl-internal tests — no
//! differential special-value gate (the f128 variant did). Pins:
//!   hypot(+/-inf, y) == +inf for ANY y, INCLUDING NaN (inf overrides NaN)
//!   hypot(x, +/-inf) == +inf likewise
//!   hypot(NaN, finite) == NaN (and symmetric)
//!   hypot(+/-0, +/-0) == +0
//!   symmetry + sign-independence: hypot(x,y)==hypot(y,x)==hypot(|x|,|y|)
//!   no spurious overflow for large-but-representable results (scaling path)
//! fl must match host glibc bit-for-bit (NaN-aware), hypot + hypotf. No mocks.

unsafe extern "C" {
    fn hypot(x: f64, y: f64) -> f64;
    fn hypotf(x: f32, y: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const N: f64 = f64::NAN;
const I: f64 = f64::INFINITY;

const CASES: &[(f64, f64)] = &[
    // inf overrides NaN -> +inf
    (I, N),
    (N, I),
    (-I, N),
    (N, -I),
    (I, -I),
    // inf with finite -> +inf
    (I, 3.0),
    (-3.0, -I),
    // NaN with finite -> NaN
    (N, 3.0),
    (3.0, N),
    (N, N),
    // zeros
    (0.0, 0.0),
    (-0.0, 0.0),
    (-0.0, -0.0),
    // exact / sign-independence
    (3.0, 4.0),
    (-3.0, 4.0),
    (4.0, -3.0),
    (5.0, 12.0),
    // subnormal + scaling, no spurious overflow / underflow
    (1.0e308, 1.0e308),
    (1.5e308, 2.0e307),
    (5.0e-324, 5.0e-324),
    (0.0, 7.0),
];

#[test]
fn hypot_special_cases_match_glibc() {
    for &(x, y) in CASES {
        let g = unsafe { hypot(x, y) };
        let f = unsafe { frankenlibc_abi::math_abi::hypot(x, y) };
        assert!(same64(f, g), "hypot({x:?},{y:?}): fl={f:?} glibc={g:?}");
        // symmetry (fl-internal invariant)
        let fs = unsafe { frankenlibc_abi::math_abi::hypot(y, x) };
        assert!(
            same64(f, fs),
            "hypot symmetry ({x:?},{y:?}): {f:?} vs {fs:?}"
        );
    }
}

#[test]
fn hypotf_special_cases_match_glibc() {
    for &(x, y) in CASES {
        let (xf, yf) = (x as f32, y as f32);
        let g = unsafe { hypotf(xf, yf) };
        let f = unsafe { frankenlibc_abi::math_abi::hypotf(xf, yf) };
        assert!(same32(f, g), "hypotf({xf:?},{yf:?}): fl={f:?} glibc={g:?}");
    }
}
