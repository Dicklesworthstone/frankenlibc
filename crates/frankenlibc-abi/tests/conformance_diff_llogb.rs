//! Differential conformance gate for `llogb` / `llogbf` (C23) vs host glibc.
//!
//! `llogb` returns the same exponent as `ilogb` for finite normal/subnormal
//! inputs, but its special-case sentinels are the `long`-width ones:
//!   - llogb(±0)  -> FP_LLOGB0   (LONG_MIN)
//!   - llogb(NaN) -> FP_LLOGBNAN (LONG_MIN on this platform)
//!   - llogb(±inf)-> LONG_MAX
//! A naive `ilogb(x) as long` widens the INT_MIN/INT_MAX sentinels and reports
//! the wrong value — that was the bug this gate pins. Each special input must
//! also raise FE_INVALID (inherited from the inner ilogb call), matching glibc.

use std::os::raw::c_long;

unsafe extern "C" {
    #[link_name = "llogb"]
    fn host_llogb(x: f64) -> c_long;
    #[link_name = "llogbf"]
    fn host_llogbf(x: f32) -> c_long;
    fn feclearexcept(excepts: i32) -> i32;
    fn fetestexcept(excepts: i32) -> i32;
}

use frankenlibc_abi::math_abi::{llogb as fl_llogb, llogbf as fl_llogbf};

const FE_INVALID: i32 = 0x01;

#[test]
fn llogb_special_values_match_glibc() {
    let specials: &[f64] = &[
        0.0,
        -0.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
    ];
    for &x in specials {
        let h = unsafe { host_llogb(x) };
        let f = unsafe { fl_llogb(x) };
        assert_eq!(f, h, "llogb({x:e}): fl={f} host={h}");
        // f32
        let xf = x as f32;
        let hf = unsafe { host_llogbf(xf) };
        let ff = unsafe { fl_llogbf(xf) };
        assert_eq!(ff, hf, "llogbf({xf:e}): fl={ff} host={hf}");
    }
    // The platform sentinels must be the long-width extremes, not the int ones.
    assert_eq!(unsafe { fl_llogb(0.0) }, c_long::MIN, "llogb(0) = FP_LLOGB0");
    assert_eq!(unsafe { fl_llogb(f64::NAN) }, c_long::MIN, "llogb(NaN) = FP_LLOGBNAN");
    assert_eq!(unsafe { fl_llogb(f64::INFINITY) }, c_long::MAX, "llogb(inf) = LONG_MAX");
}

#[test]
fn llogb_finite_sweep_matches_glibc() {
    // Sweep exponents across the f64 normal + subnormal range.
    let mut diffs = Vec::new();
    let mut x = 5e-324_f64; // smallest subnormal
    for _ in 0..2100 {
        let h = unsafe { host_llogb(x) };
        let f = unsafe { fl_llogb(x) };
        if f != h {
            diffs.push(format!("llogb({x:e}): fl={f} host={h}"));
        }
        x *= 2.0;
        if !x.is_finite() {
            break;
        }
    }
    // A handful of representative mantissas.
    for &x in &[1.0, 1.5, 2.5, 3.0, 1023.99, 0.1, 0.3, 1e100, 1e-100] {
        let h = unsafe { host_llogb(x) };
        let f = unsafe { fl_llogb(x) };
        if f != h {
            diffs.push(format!("llogb({x:e}): fl={f} host={h}"));
        }
    }
    assert!(diffs.is_empty(), "llogb finite sweep diverged:\n{}", diffs.join("\n"));
}

#[test]
fn llogb_special_inputs_raise_fe_invalid() {
    for &x in &[0.0_f64, f64::INFINITY, f64::NAN] {
        unsafe { feclearexcept(FE_INVALID) };
        let _ = unsafe { fl_llogb(x) };
        let raised = unsafe { fetestexcept(FE_INVALID) } & FE_INVALID;
        assert_ne!(raised, 0, "llogb({x:e}) must raise FE_INVALID");
    }
}
