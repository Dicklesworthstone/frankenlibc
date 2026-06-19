#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc math oracle

//! Differential gates for the fused `log2f` and `expf` kernels
//! (bd-fused-f32-exp-log-kernels). Both are ports of ARM optimized-routines
//! (glibc `__ieee754_log2f` / `__ieee754_expf`); they should be bit-exact to
//! glibc over their fast-path domains. Special/boundary inputs defer to libm and
//! are checked for exact parity.

mod g {
    unsafe extern "C" {
        pub fn log2f(x: f32) -> f32;
        pub fn expf(x: f32) -> f32;
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
fn log2f_within_4_ulps_vs_glibc() {
    let mut worst = 0u64;
    let mut worst_desc = String::new();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0u64;

    // Multiplicative sweep over the full positive normal range.
    let mut x = f32::MIN_POSITIVE;
    while x < f32::MAX / 2.0 {
        let got = unsafe { fl::log2f(x) };
        let want = unsafe { g::log2f(x) };
        checked += 1;
        let u = ulp_diff(got, want);
        if u > worst {
            worst = u;
            worst_desc = format!("log2f({x}) fl={got:?} glibc={want:?} ({u} ULP)");
        }
        if u > 4 {
            failures.push(format!("log2f({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
        x *= 1.0009;
    }
    // Dense sweep near 1.0 (the worst region for log).
    let mut x = 0.5_f32;
    while x < 2.0 {
        let got = unsafe { fl::log2f(x) };
        let want = unsafe { g::log2f(x) };
        checked += 1;
        let u = ulp_diff(got, want);
        if u > worst {
            worst = u;
            worst_desc = format!("log2f({x}) fl={got:?} glibc={want:?} ({u} ULP)");
        }
        if u > 4 {
            failures.push(format!("log2f({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
        x += 0.00007;
    }
    // Boundary / special inputs: exact parity (these defer to libm).
    for &x in &[
        0.0f32,
        -0.0,
        1.0,
        -1.0,
        -5.0,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ] {
        let got = unsafe { fl::log2f(x) };
        let want = unsafe { g::log2f(x) };
        if want.is_nan() {
            assert!(got.is_nan(), "log2f({x}) fl={got:?} glibc=NaN");
        } else {
            assert_eq!(got, want, "log2f({x}) mismatch fl={got:?} glibc={want:?}");
        }
    }
    assert!(
        failures.is_empty(),
        "{} log2f inputs > 4 ULP (of {checked}); worst {worst_desc}:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(checked > 20000, "expected dense grid, only {checked}");
    eprintln!("log2f: {checked} inputs within 4 ULP, worst = {worst_desc}");
}

#[test]
fn expf_within_4_ulps_vs_glibc() {
    let mut worst = 0u64;
    let mut worst_desc = String::new();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0u64;

    let mut x = -86.9_f32;
    while x < 86.9 {
        let got = unsafe { fl::expf(x) };
        let want = unsafe { g::expf(x) };
        checked += 1;
        let u = ulp_diff(got, want);
        if u > worst {
            worst = u;
            worst_desc = format!("expf({x}) fl={got:?} glibc={want:?} ({u} ULP)");
        }
        if u > 4 {
            failures.push(format!("expf({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
        x += if x.abs() < 6.0 { 0.0007 } else { 0.03 };
    }
    // Boundary / special inputs: exact parity.
    for &x in &[
        0.0f32,
        -0.0,
        88.0,
        89.0,
        100.0,
        -88.0,
        -103.0,
        -110.0,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ] {
        let got = unsafe { fl::expf(x) };
        let want = unsafe { g::expf(x) };
        if want.is_nan() {
            assert!(got.is_nan(), "expf({x}) fl={got:?} glibc=NaN");
        } else {
            assert_eq!(got, want, "expf({x}) mismatch fl={got:?} glibc={want:?}");
        }
    }
    assert!(
        failures.is_empty(),
        "{} expf inputs > 4 ULP (of {checked}); worst {worst_desc}:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(checked > 10000, "expected dense grid, only {checked}");
    eprintln!("expf: {checked} inputs within 4 ULP, worst = {worst_desc}");
}
