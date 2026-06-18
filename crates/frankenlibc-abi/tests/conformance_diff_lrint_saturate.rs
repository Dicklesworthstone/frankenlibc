#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc lrint/lround + fetestexcept oracle

//! Differential gate for lrint/llrint/lround/llround out-of-range behaviour
//! (bd-2ray6w). Existing gates cover in-range values and rounding modes, but
//! NOT the saturation path: for inf/NaN/huge inputs the rounded value is
//! outside i64, where C99 7.12.9.x leaves the RESULT VALUE unspecified but
//! mandates a domain/range error (FE_INVALID). So this gate compares the
//! FE_INVALID flag for ALL inputs, and the result VALUE only when glibc did not
//! raise FE_INVALID (i.e. the in-range case where the value is specified) —
//! deliberately not asserting the unspecified out-of-range result. No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn lrint(x: f64) -> i64;
    fn llrint(x: f64) -> i64;
    fn lround(x: f64) -> i64;
    fn llround(x: f64) -> i64;
    fn feclearexcept(excepts: c_int) -> c_int;
    fn fetestexcept(excepts: c_int) -> c_int;
}

const FE_INVALID: c_int = 0x01;

const CASES: &[f64] = &[
    // in-range (glibc raises no FE_INVALID): value must match
    0.0,
    -0.0,
    2.5,
    -2.5,
    0.5,
    -0.5,
    100.0,
    123.49,
    -123.51,
    9.0e18, // < i64::MAX (~9.22e18), in range
    // out-of-range / non-finite: only the FE_INVALID flag is compared
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1.0e300,
    -1.0e300,
    1.0e19, // > i64::MAX
];

fn check(label: &str, x: f64, flf: impl Fn(f64) -> i64, gf: unsafe extern "C" fn(f64) -> i64) {
    unsafe { feclearexcept(FE_INVALID) };
    let fv = flf(x);
    let f_inv = unsafe { fetestexcept(FE_INVALID) } & FE_INVALID;

    unsafe { feclearexcept(FE_INVALID) };
    let gv = unsafe { gf(x) };
    let g_inv = unsafe { fetestexcept(FE_INVALID) } & FE_INVALID;

    assert_eq!(f_inv, g_inv, "{label}({x:?}) FE_INVALID: fl={f_inv:#x} glibc={g_inv:#x}");
    // Result value is specified only when in range (glibc raised no FE_INVALID).
    if g_inv == 0 {
        assert_eq!(fv, gv, "{label}({x:?}) value: fl={fv} glibc={gv}");
    }
}

#[test]
fn lrint_family_saturation_matches_glibc() {
    use frankenlibc_abi::math_abi as m;
    for &x in CASES {
        check("lrint", x, |v| unsafe { m::lrint(v) }, lrint);
        check("llrint", x, |v| unsafe { m::llrint(v) }, llrint);
        check("lround", x, |v| unsafe { m::lround(v) }, lround);
        check("llround", x, |v| unsafe { m::llround(v) }, llround);
    }
}
