#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc math oracle

//! Differential gate for the fused `exp2f` kernel (bd-fused-f32-exp-log-kernels).
//!
//! fl `exp2f` previously delegated wholesale to `libm::exp2f`. The lever routes
//! the normal-result interior (|x| < 126) through the fused single-pass kernel
//! shared with powf (`powf_exp2_inline`), which is glibc's `__ieee754_exp2f`
//! algorithm (0.5 ULP); overflow/underflow/subnormal/inf/nan defer to
//! `libm::exp2f`. This gate sweeps a dense interior grid and asserts agreement
//! within the 4-ULP glibc parity contract (it should be bit-exact since it is
//! glibc's algorithm), and checks the special/boundary inputs for exact parity.

mod g {
    unsafe extern "C" {
        pub fn exp2f(x: f32) -> f32;
    }
}
use frankenlibc_abi::math_abi as fl;

fn ulp_diff(a: f32, b: f32) -> u64 {
    if a == b || (a.is_nan() && b.is_nan()) {
        return 0;
    }
    if a.is_nan() || b.is_nan() || a.is_infinite() || b.is_infinite() {
        return u64::MAX;
    }
    let ai = a.to_bits() as i64;
    let bi = b.to_bits() as i64;
    let am = if ai < 0 { i64::MIN - ai } else { ai };
    let bm = if bi < 0 { i64::MIN - bi } else { bi };
    am.abs_diff(bm)
}

#[test]
fn exp2f_within_4_ulps_vs_glibc() {
    let mut worst = 0u64;
    let mut worst_desc = String::new();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0u64;

    // Dense interior sweep over [-125.9, 125.9]; fine step near 0 (the common
    // regime) plus the full normal range.
    let mut x = -125.9_f32;
    while x < 125.9 {
        let got = unsafe { fl::exp2f(x) };
        let want = unsafe { g::exp2f(x) };
        checked += 1;
        let u = ulp_diff(got, want);
        if u > worst {
            worst = u;
            worst_desc = format!("exp2f({x}) fl={got:?} glibc={want:?} ({u} ULP)");
        }
        if u > 4 {
            failures.push(format!("exp2f({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
        // Non-uniform step: dense in [-8, 8], coarser in the tails.
        x += if x.abs() < 8.0 { 0.0009 } else { 0.05 };
    }

    // Boundary / special inputs must match glibc exactly (these defer to libm).
    for &x in &[
        0.0f32,
        -0.0,
        1.0,
        -1.0,
        127.9,
        128.0,
        130.0,
        -126.0,
        -149.0,
        -150.0,
        -200.0,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ] {
        let got = unsafe { fl::exp2f(x) };
        let want = unsafe { g::exp2f(x) };
        if want.is_nan() {
            assert!(got.is_nan(), "exp2f({x}) fl={got:?} glibc=NaN");
        } else {
            assert_eq!(
                got, want,
                "exp2f({x}) boundary mismatch fl={got:?} glibc={want:?}"
            );
        }
    }

    assert!(
        failures.is_empty(),
        "{} exp2f inputs exceeded 4 ULP (of {checked}); worst {worst_desc}:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        checked > 10000,
        "expected a dense grid, only checked {checked}"
    );
    eprintln!("exp2f: {checked} inputs within 4 ULP, worst = {worst_desc}");
}
