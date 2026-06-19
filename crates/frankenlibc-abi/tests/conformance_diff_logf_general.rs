#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc math oracle

//! Differential gate for the fused `logf` kernel (bd-fused-f32-exp-log-kernels).
//! Port of ARM optimized-routines `logf` (glibc `__ieee754_logf`); should be
//! bit-exact to glibc over the positive normal domain. Special/boundary inputs
//! defer to libm and are checked for exact parity.

mod g {
    unsafe extern "C" {
        pub fn logf(x: f32) -> f32;
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
fn logf_within_4_ulps_vs_glibc() {
    let mut worst = 0u64;
    let mut worst_desc = String::new();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0u64;

    // Multiplicative sweep over the full positive normal range.
    let mut x = f32::MIN_POSITIVE;
    while x < f32::MAX / 2.0 {
        let got = unsafe { fl::logf(x) };
        let want = unsafe { g::logf(x) };
        checked += 1;
        let u = ulp_diff(got, want);
        if u > worst {
            worst = u;
            worst_desc = format!("logf({x}) fl={got:?} glibc={want:?} ({u} ULP)");
        }
        if u > 4 {
            failures.push(format!("logf({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
        x *= 1.0009;
    }
    // Dense sweep near 1.0 (the cancellation-sensitive region for log).
    let mut x = 0.5_f32;
    while x < 2.0 {
        let got = unsafe { fl::logf(x) };
        let want = unsafe { g::logf(x) };
        checked += 1;
        let u = ulp_diff(got, want);
        if u > worst {
            worst = u;
            worst_desc = format!("logf({x}) fl={got:?} glibc={want:?} ({u} ULP)");
        }
        if u > 4 {
            failures.push(format!("logf({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
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
        let got = unsafe { fl::logf(x) };
        let want = unsafe { g::logf(x) };
        if want.is_nan() {
            assert!(got.is_nan(), "logf({x}) fl={got:?} glibc=NaN");
        } else {
            assert_eq!(got, want, "logf({x}) mismatch fl={got:?} glibc={want:?}");
        }
    }
    assert!(
        failures.is_empty(),
        "{} logf inputs > 4 ULP (of {checked}); worst {worst_desc}:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(checked > 20000, "expected dense grid, only {checked}");
    eprintln!("logf: {checked} inputs within 4 ULP, worst = {worst_desc}");
}
