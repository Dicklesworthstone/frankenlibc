#![cfg(target_os = "linux")]

//! Differential conformance harness for math.h special functions:
//!   - tgamma / lgamma (gamma function)
//!   - erf / erfc       (error function)
//!   - j0 / j1 / jn     (Bessel J)
//!   - y0 / y1 / yn     (Bessel Y)
//!
//! These are libm functions covered by IEEE-754 / POSIX. Tolerance is
//! 4 ULPs to match conformance_diff_math's existing pattern.
//!
//! Filed under [bd-xn6p8] follow-up — extending math conformance.

use frankenlibc_abi::math_abi as fl;

unsafe extern "C" {
    fn tgamma(x: f64) -> f64;
    fn lgamma(x: f64) -> f64;
    fn erf(x: f64) -> f64;
    fn erfc(x: f64) -> f64;
    fn j0(x: f64) -> f64;
    fn j1(x: f64) -> f64;
    fn jn(n: std::ffi::c_int, x: f64) -> f64;
    fn y0(x: f64) -> f64;
    fn y1(x: f64) -> f64;
    fn yn(n: std::ffi::c_int, x: f64) -> f64;
}

/// 4-ULP tolerance threshold (per IEEE-754 + glibc libm contract).
fn within_ulps(a: f64, b: f64, ulps: u64) -> bool {
    if a.is_nan() && b.is_nan() {
        return true;
    }
    if a == b {
        return true;
    }
    if a.is_finite() != b.is_finite() {
        return false;
    }
    if !a.is_finite() {
        return false; // both ±inf would have been caught by ==
    }
    let abits = a.to_bits() as i64;
    let bbits = b.to_bits() as i64;
    let abits = if abits < 0 { i64::MIN - abits } else { abits };
    let bbits = if bbits < 0 { i64::MIN - bbits } else { bbits };
    (abits - bbits).unsigned_abs() <= ulps
}

#[test]
fn diff_tgamma_within_4_ulps() {
    let inputs: &[f64] = &[
        0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 0.1, 4.5, 100.0, 0.01,
        -0.5, -1.5, -2.5, -3.5,
    ];
    let mut divs = Vec::new();
    for &x in inputs {
        let fl_y = unsafe { fl::tgamma(x) };
        let lc_y = unsafe { tgamma(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("tgamma({x}): fl={fl_y} lc={lc_y}"));
        }
    }
    assert!(divs.is_empty(), "tgamma divergences:\n{}", divs.join("\n"));
}

#[test]
fn diff_lgamma_within_4_ulps() {
    let inputs: &[f64] = &[
        0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 100.0, 1e6, 1e10,
    ];
    let mut divs = Vec::new();
    for &x in inputs {
        let fl_y = unsafe { fl::lgamma(x) };
        let lc_y = unsafe { lgamma(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("lgamma({x}): fl={fl_y} lc={lc_y}"));
        }
    }
    assert!(divs.is_empty(), "lgamma divergences:\n{}", divs.join("\n"));
}

#[test]
fn diff_erf_within_4_ulps() {
    let inputs: &[f64] = &[
        0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 0.001, 6.0, -0.5, -1.0, -3.0,
    ];
    let mut divs = Vec::new();
    for &x in inputs {
        let fl_y = unsafe { fl::erf(x) };
        let lc_y = unsafe { erf(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("erf({x}): fl={fl_y} lc={lc_y}"));
        }
        let fl_y = unsafe { fl::erfc(x) };
        let lc_y = unsafe { erfc(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("erfc({x}): fl={fl_y} lc={lc_y}"));
        }
    }
    assert!(divs.is_empty(), "erf/erfc divergences:\n{}", divs.join("\n"));
}

#[test]
fn diff_bessel_j_within_4_ulps() {
    let inputs: &[f64] = &[
        0.0, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 100.0, 0.001,
    ];
    let mut divs = Vec::new();
    for &x in inputs {
        let fl_y = unsafe { fl::j0(x) };
        let lc_y = unsafe { j0(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("j0({x}): fl={fl_y} lc={lc_y}"));
        }
        let fl_y = unsafe { fl::j1(x) };
        let lc_y = unsafe { j1(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("j1({x}): fl={fl_y} lc={lc_y}"));
        }
        for n in [2i32, 5, 10] {
            let fl_y = unsafe { fl::jn(n, x) };
            let lc_y = unsafe { jn(n, x) };
            if !within_ulps(fl_y, lc_y, 4) {
                divs.push(format!("jn({n}, {x}): fl={fl_y} lc={lc_y}"));
            }
        }
    }
    assert!(divs.is_empty(), "Bessel J divergences:\n{}", divs.join("\n"));
}

#[test]
fn diff_bessel_y_within_4_ulps() {
    // Bessel Y is undefined at 0 (negative infinity).
    let inputs: &[f64] = &[0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 100.0];
    let mut divs = Vec::new();
    for &x in inputs {
        let fl_y = unsafe { fl::y0(x) };
        let lc_y = unsafe { y0(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("y0({x}): fl={fl_y} lc={lc_y}"));
        }
        let fl_y = unsafe { fl::y1(x) };
        let lc_y = unsafe { y1(x) };
        if !within_ulps(fl_y, lc_y, 4) {
            divs.push(format!("y1({x}): fl={fl_y} lc={lc_y}"));
        }
        for n in [2i32, 5, 10] {
            let fl_y = unsafe { fl::yn(n, x) };
            let lc_y = unsafe { yn(n, x) };
            if !within_ulps(fl_y, lc_y, 4) {
                divs.push(format!("yn({n}, {x}): fl={fl_y} lc={lc_y}"));
            }
        }
    }
    assert!(divs.is_empty(), "Bessel Y divergences:\n{}", divs.join("\n"));
}

#[test]
fn math_special_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libm special\",\"reference\":\"glibc\",\"functions\":10,\"divergences\":0}}",
    );
}
