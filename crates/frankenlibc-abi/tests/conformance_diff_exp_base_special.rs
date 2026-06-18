#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc exp2/exp10 oracle

//! Differential gate for exp2/exp10/pow10 (+f32) special cases (bd-bgbrbc).
//! These base-2 / base-10 exponentials had no special-argument differential
//! coverage (exp2m1/exp10m1 are different functions). Pins the C99 F.10.3.x
//! cases: f(+/-0)=1, f(NaN)=NaN, f(+inf)=+inf, f(-inf)=+0, exact integer powers
//! (exp2(10)=1024, exp10(3)=1000), overflow -> +inf, underflow -> +0, and the
//! pow10==exp10 alias identity. Bit-for-bit NaN-aware vs host glibc. No mocks.

unsafe extern "C" {
    fn exp2(x: f64) -> f64;
    fn exp10(x: f64) -> f64;
    fn exp2f(x: f32) -> f32;
    fn exp10f(x: f32) -> f32;
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
    2.0,
    3.0,
    10.0,
    -10.0,
    0.5,
    1100.0,  // overflow -> +inf
    -1100.0, // underflow -> +0
    309.0,
];

#[test]
fn exp2_exp10_special_match_glibc() {
    for &x in CASES {
        let g2 = unsafe { exp2(x) };
        let f2 = unsafe { frankenlibc_abi::math_abi::exp2(x) };
        assert!(same64(f2, g2), "exp2({x:?}): fl={f2:?} glibc={g2:?}");

        let g10 = unsafe { exp10(x) };
        let f10 = unsafe { frankenlibc_abi::math_abi::exp10(x) };
        assert!(same64(f10, g10), "exp10({x:?}): fl={f10:?} glibc={g10:?}");

        // pow10 is an alias of exp10 (fl-internal identity).
        let fp10 = unsafe { frankenlibc_abi::math_abi::pow10(x) };
        assert!(same64(fp10, f10), "pow10==exp10 at {x:?}: {fp10:?} vs {f10:?}");
    }
}

#[test]
fn exp2f_exp10f_special_match_glibc() {
    for &x in CASES {
        let xf = x as f32;
        let g2 = unsafe { exp2f(xf) };
        let f2 = unsafe { frankenlibc_abi::math_abi::exp2f(xf) };
        assert!(same32(f2, g2), "exp2f({xf:?}): fl={f2:?} glibc={g2:?}");

        let g10 = unsafe { exp10f(xf) };
        let f10 = unsafe { frankenlibc_abi::math_abi::exp10f(xf) };
        assert!(same32(f10, g10), "exp10f({xf:?}): fl={f10:?} glibc={g10:?}");
    }
}
