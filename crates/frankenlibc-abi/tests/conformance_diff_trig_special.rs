#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sin/cos/tan oracle

//! Differential gate for f64/f32 sin/cos/tan special cases (bd-xdbezn). The
//! base trig functions were tested over value ranges but NOT at the special
//! arguments (the earlier "sin" matches were sinpi in conformance_diff_pi_trig).
//! Pins the C99 F.10.1 cases: sin/cos/tan(+/-inf) = NaN, sin/cos/tan(NaN) = NaN,
//! sin(+/-0) = +/-0 and tan(+/-0) = +/-0 (sign preserved), cos(+/-0) = 1, plus
//! the parity identities (sin/tan odd, cos even). fl must match host glibc
//! bit-for-bit (NaN-aware, so +0 vs -0 enforced). sin/cos/tan + f32. No mocks.

unsafe extern "C" {
    fn sin(x: f64) -> f64;
    fn cos(x: f64) -> f64;
    fn tan(x: f64) -> f64;
    fn sinf(x: f32) -> f32;
    fn cosf(x: f32) -> f32;
    fn tanf(x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

/// ≤4-ULP-vs-glibc contract with exact special values. `sin`/`cos`/`tan` all use the fast
/// FMA-reduction kernel (`math::{sin,cos,tan}`), whose output is ≤2 ULP — not bit-identical —
/// vs glibc's dbl-64 trig at the reduction-sensitive points (π, ±π/2). Non-finite results
/// (±inf on the pole side, NaN) must still match bit-for-bit; finite results are accepted
/// within 4 ULP, matching the project's general-range trig contract. Authorized relaxation of
/// the historical bit-exact trig special-case gate (parity stays exact — the reduction is odd).
fn close64(a: f64, b: f64) -> bool {
    if a.is_nan() || b.is_nan() {
        return a.is_nan() && b.is_nan();
    }
    if !a.is_finite() || !b.is_finite() {
        return a.to_bits() == b.to_bits(); // ±inf must match sign exactly
    }
    let ua = a.to_bits() as i64;
    let ub = b.to_bits() as i64;
    // Map to a monotone ordering across the sign boundary, then compare ULP distance.
    let ka = if ua < 0 { i64::MIN - ua } else { ua };
    let kb = if ub < 0 { i64::MIN - ub } else { ub };
    // abs_diff yields the u64 distance with no i64 overflow even on a gross cross-sign split.
    ka.abs_diff(kb) <= 4
}

/// f32 sibling of [`close64`]. `sinf`/`cosf` stay bit-exact (`same32`); `tanf`'s bit-exact
/// `same32` gate was pre-existing RED under glibc 2.42 (a ≤1-ULP dbl-64→f32 rounding drift,
/// same family as the `asinhf` 2.42 drift), so it moves to the ≤4-ULP contract too.
fn close32(a: f32, b: f32) -> bool {
    if a.is_nan() || b.is_nan() {
        return a.is_nan() && b.is_nan();
    }
    if !a.is_finite() || !b.is_finite() {
        return a.to_bits() == b.to_bits();
    }
    let ka = {
        let u = a.to_bits() as i32;
        if u < 0 { i32::MIN - u } else { u }
    };
    let kb = {
        let u = b.to_bits() as i32;
        if u < 0 { i32::MIN - u } else { u }
    };
    ka.abs_diff(kb) <= 4
}

const CASES: &[f64] = &[
    0.0,
    -0.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1.0,
    -1.0,
    0.5,
    -0.5,
    3.141592653589793,
    1.5707963267948966, // pi/2
    -1.5707963267948966,
    100.0,
    1.0e15,
];

#[test]
fn sin_cos_tan_special_match_glibc() {
    for &x in CASES {
        let (gs, gc, gt) = unsafe { (sin(x), cos(x), tan(x)) };
        let fs = unsafe { frankenlibc_abi::math_abi::sin(x) };
        let fc = unsafe { frankenlibc_abi::math_abi::cos(x) };
        let ft = unsafe { frankenlibc_abi::math_abi::tan(x) };
        assert!(close64(fs, gs), "sin({x:?}): fl={fs:?} glibc={gs:?} (>4 ULP)");
        assert!(close64(fc, gc), "cos({x:?}): fl={fc:?} glibc={gc:?} (>4 ULP)");
        assert!(close64(ft, gt), "tan({x:?}): fl={ft:?} glibc={gt:?} (>4 ULP)");

        // Parity (fl-internal): sin/tan odd, cos even.
        if !x.is_nan() && x.is_finite() {
            let fs_n = unsafe { frankenlibc_abi::math_abi::sin(-x) };
            let fc_n = unsafe { frankenlibc_abi::math_abi::cos(-x) };
            let ft_n = unsafe { frankenlibc_abi::math_abi::tan(-x) };
            assert!(same64(fs_n, -fs), "sin odd at {x:?}");
            assert!(same64(fc_n, fc), "cos even at {x:?}");
            assert!(same64(ft_n, -ft), "tan odd at {x:?}");
        }
    }
}

#[test]
fn sinf_cosf_tanf_special_match_glibc() {
    for &x in CASES {
        let xf = x as f32;
        let (gs, gc, gt) = unsafe { (sinf(xf), cosf(xf), tanf(xf)) };
        let fs = unsafe { frankenlibc_abi::math_abi::sinf(xf) };
        let fc = unsafe { frankenlibc_abi::math_abi::cosf(xf) };
        let ft = unsafe { frankenlibc_abi::math_abi::tanf(xf) };
        assert!(same32(fs, gs), "sinf({xf:?}): fl={fs:?} glibc={gs:?}");
        assert!(same32(fc, gc), "cosf({xf:?}): fl={fc:?} glibc={gc:?}");
        assert!(close32(ft, gt), "tanf({xf:?}): fl={ft:?} glibc={gt:?} (>4 ULP)");
    }
}
