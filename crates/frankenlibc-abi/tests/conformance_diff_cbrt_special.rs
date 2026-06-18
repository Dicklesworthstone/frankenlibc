#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cbrt oracle

//! Differential gate for f64 cbrt/cbrtf (bd-z6tlx1). f64 cbrt had only
//! fl-internal tests — no differential gate vs glibc (the f128 variant had
//! one). cbrt is distinctive: it is an ODD function with NO domain error on
//! negatives (unlike sqrt), preserves the sign of zero/infinity, and is exact
//! on perfect cubes. Pins: cbrt(+/-0)=+/-0, cbrt(+/-inf)=+/-inf, cbrt(NaN)=NaN,
//! exact perfect cubes (incl negative), the odd-function identity
//! cbrt(-x)==-cbrt(x), and irrational/scaled values bit-for-bit vs glibc.
//! cbrt + cbrtf. No mocks.

unsafe extern "C" {
    fn cbrt(x: f64) -> f64;
    fn cbrtf(x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const CASES: &[f64] = &[
    0.0,
    -0.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1.0,
    -1.0,
    8.0,
    -8.0,
    27.0,
    -27.0,
    64.0,
    1000.0,
    -1000.0,
    2.0,    // irrational result -> must match glibc rounding
    -2.0,
    0.125,
    0.5,
    1.0e300,
    -1.0e300,
    5.0e-324, // smallest subnormal
    1.234_567_89e-200,
];

#[test]
fn cbrt_special_cases_match_glibc() {
    for &x in CASES {
        let g = unsafe { cbrt(x) };
        let f = unsafe { frankenlibc_abi::math_abi::cbrt(x) };
        assert!(
            same64(f, g),
            "cbrt({x:?}): fl={f:?} (bits {:#018x}) glibc={g:?} (bits {:#018x})",
            f.to_bits(),
            g.to_bits()
        );
        // Odd-function identity (fl-internal): cbrt(-x) == -cbrt(x).
        if !x.is_nan() {
            let fneg = unsafe { frankenlibc_abi::math_abi::cbrt(-x) };
            assert!(same64(fneg, -f), "cbrt odd-function at {x:?}: cbrt(-x)={fneg:?} -cbrt(x)={:?}", -f);
        }
    }
}

#[test]
fn cbrtf_special_cases_match_glibc() {
    for &x in CASES {
        let xf = x as f32;
        let g = unsafe { cbrtf(xf) };
        let f = unsafe { frankenlibc_abi::math_abi::cbrtf(xf) };
        assert!(same32(f, g), "cbrtf({xf:?}): fl={f:?} glibc={g:?}");
    }
}
