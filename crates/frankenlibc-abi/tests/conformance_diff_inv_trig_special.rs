#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc atan/asin/acos oracle

//! Differential gate for atan/asin/acos (+f32) special VALUES (bd-4xb7wc).
//! atan (single-arg) had no differential coverage at all; asin/acos had only
//! the out-of-domain cases (fp_exceptions: acos(2)/asin(-2) -> NaN), not the
//! valid special values. Pins C99 F.10.1: atan(+/-0)=+/-0, atan(+/-inf)=+/-pi/2,
//! atan(NaN)=NaN; asin(+/-0)=+/-0, asin(+/-1)=+/-pi/2; acos(1)=+0, acos(-1)=pi,
//! acos(0)=pi/2; out-of-domain -> NaN; plus parity (atan/asin odd). Bit-for-bit
//! NaN-aware vs glibc. No mocks.

unsafe extern "C" {
    fn atan(x: f64) -> f64;
    fn asin(x: f64) -> f64;
    fn acos(x: f64) -> f64;
    fn atanf(x: f32) -> f32;
    fn asinf(x: f32) -> f32;
    fn acosf(x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

// atan accepts all reals; asin/acos only [-1,1] (others -> NaN).
const ATAN_CASES: &[f64] = &[
    0.0,
    -0.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1.0,
    -1.0,
    0.5,
    -0.5,
    1.0e300,
];
const ASIN_ACOS_CASES: &[f64] = &[
    0.0,
    -0.0,
    1.0,
    -1.0,
    0.5,
    -0.5,
    0.25,
    f64::NAN,
    2.0,
    -2.0,
    f64::INFINITY,
];

#[test]
fn atan_special_match_glibc() {
    for &x in ATAN_CASES {
        let g = unsafe { atan(x) };
        let f = unsafe { frankenlibc_abi::math_abi::atan(x) };
        assert!(same64(f, g), "atan({x:?}): fl={f:?} glibc={g:?}");
        if !x.is_nan() {
            let fneg = unsafe { frankenlibc_abi::math_abi::atan(-x) };
            assert!(same64(fneg, -f), "atan odd at {x:?}");
        }
        let gf = unsafe { atanf(x as f32) };
        let ff = unsafe { frankenlibc_abi::math_abi::atanf(x as f32) };
        assert!(
            same32(ff, gf),
            "atanf({:?}): fl={ff:?} glibc={gf:?}",
            x as f32
        );
    }
}

#[test]
fn asin_acos_special_match_glibc() {
    for &x in ASIN_ACOS_CASES {
        let gs = unsafe { asin(x) };
        let fs = unsafe { frankenlibc_abi::math_abi::asin(x) };
        assert!(same64(fs, gs), "asin({x:?}): fl={fs:?} glibc={gs:?}");
        let gc = unsafe { acos(x) };
        let fc = unsafe { frankenlibc_abi::math_abi::acos(x) };
        assert!(same64(fc, gc), "acos({x:?}): fl={fc:?} glibc={gc:?}");

        // asin is odd (fl-internal), where in-domain.
        if !x.is_nan() && x.abs() <= 1.0 {
            let fs_n = unsafe { frankenlibc_abi::math_abi::asin(-x) };
            assert!(same64(fs_n, -fs), "asin odd at {x:?}");
        }

        let xf = x as f32;
        let gsf = unsafe { asinf(xf) };
        let fsf = unsafe { frankenlibc_abi::math_abi::asinf(xf) };
        assert!(same32(fsf, gsf), "asinf({xf:?}): fl={fsf:?} glibc={gsf:?}");
        let gcf = unsafe { acosf(xf) };
        let fcf = unsafe { frankenlibc_abi::math_abi::acosf(xf) };
        assert!(same32(fcf, gcf), "acosf({xf:?}): fl={fcf:?} glibc={gcf:?}");
    }
}
