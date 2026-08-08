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
    // c_long is i64 on LP64, which is the only target this file compiles for.
    fn lrintf(x: f32) -> i64;
    fn llrintf(x: f32) -> i64;
    fn lroundf(x: f32) -> i64;
    fn llroundf(x: f32) -> i64;
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

    assert_eq!(
        f_inv, g_inv,
        "{label}({x:?}) FE_INVALID: fl={f_inv:#x} glibc={g_inv:#x}"
    );
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

fn check_f32(label: &str, x: f32, flf: impl Fn(f32) -> i64, gf: unsafe extern "C" fn(f32) -> i64) {
    unsafe { feclearexcept(FE_INVALID) };
    let fv = flf(x);
    let f_inv = unsafe { fetestexcept(FE_INVALID) } & FE_INVALID;

    unsafe { feclearexcept(FE_INVALID) };
    let gv = unsafe { gf(x) };
    let g_inv = unsafe { fetestexcept(FE_INVALID) } & FE_INVALID;

    assert_eq!(
        f_inv, g_inv,
        "{label}({x:?}) FE_INVALID: fl={f_inv:#x} glibc={g_inv:#x}"
    );
    if g_inv == 0 {
        assert_eq!(fv, gv, "{label}({x:?}) value: fl={fv} glibc={gv}");
    }
}

/// f32 siblings share `round_to_i64_x86` with the f64 family, but libm is
/// routinely asymmetric across widths, so a shared-helper fix is not evidence
/// that both widths behave — this arm is what makes it evidence.
///
/// Note the range boundary differs from the f64 cases: every finite f32 is far
/// below 2^63, so f32 CANNOT reach the out-of-range path by magnitude alone.
/// Only the non-finite inputs exercise saturation here, which is precisely why
/// an f64-only gate would not have covered these entry points.
#[test]
fn lrintf_family_saturation_matches_glibc() {
    use frankenlibc_abi::math_abi as m;
    const F32_CASES: &[f32] = &[
        // in-range: value must match
        0.0,
        -0.0,
        2.5,
        -2.5,
        0.5,
        -0.5,
        100.0,
        123.49,
        -123.51,
        // non-finite: only the FE_INVALID flag is compared
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
        f32::MAX,
        f32::MIN,
    ];
    for &x in F32_CASES {
        check_f32("lrintf", x, |v| unsafe { m::lrintf(v) }, lrintf);
        check_f32("llrintf", x, |v| unsafe { m::llrintf(v) }, llrintf);
        check_f32("lroundf", x, |v| unsafe { m::lroundf(v) }, lroundf);
        check_f32("llroundf", x, |v| unsafe { m::llroundf(v) }, llroundf);
    }
}
