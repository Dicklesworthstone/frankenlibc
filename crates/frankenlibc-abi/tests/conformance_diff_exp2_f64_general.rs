#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc math oracle

//! Differential gate for the fused f64 `exp2` kernel
//! (bd-fused-f64-pow-exp-log-kernels). fl's f64 `exp2` previously delegated
//! wholesale to `libm::exp2`. The lever routes the normal-result interior
//! through the ARM optimized-routines table kernel (glibc `__ieee754_exp2`,
//! 0.507 ULP); denormal-tiny/overflow/underflow/inf/nan defer to libm. The
//! kernel is glibc's own algorithm, so it should be bit-exact over the interior.

mod g {
    unsafe extern "C" {
        pub fn exp2(x: f64) -> f64;
    }
}
use frankenlibc_core::math::exp2 as fl_exp2;

fn ulp_diff(a: f64, b: f64) -> u64 {
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
fn exp2_f64_within_4_ulps_vs_glibc() {
    let mut worst = 0u64;
    let mut worst_desc = String::new();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0u64;

    // Dense interior sweep over (-1021.9, 1021.9); fine near 0, coarser in tails.
    let mut x = -1021.9_f64;
    while x < 1021.9 {
        let got = fl_exp2(x);
        let want = unsafe { g::exp2(x) };
        checked += 1;
        let u = ulp_diff(got, want);
        if u > worst {
            worst = u;
            worst_desc = format!("exp2({x}) fl={got:?} glibc={want:?} ({u} ULP)");
        }
        if u > 4 {
            failures.push(format!("exp2({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
        x += if x.abs() < 16.0 { 0.00031 } else { 0.017 };
    }

    // Boundary / special inputs: exact parity (these defer to libm).
    for &x in &[
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        1021.0,
        1022.0,
        1024.0,
        2000.0,
        -1022.0,
        -1074.0,
        -1100.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        1e-320,
    ] {
        let got = fl_exp2(x);
        let want = unsafe { g::exp2(x) };
        if want.is_nan() {
            assert!(got.is_nan(), "exp2({x}) fl={got:?} glibc=NaN");
        } else {
            assert_eq!(
                got, want,
                "exp2({x}) boundary mismatch fl={got:?} glibc={want:?}"
            );
        }
    }

    assert!(
        failures.is_empty(),
        "{} f64 exp2 inputs > 4 ULP (of {checked}); worst {worst_desc}:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(checked > 100000, "expected dense grid, only {checked}");
    eprintln!("f64 exp2: {checked} inputs within 4 ULP, worst = {worst_desc}");
}
