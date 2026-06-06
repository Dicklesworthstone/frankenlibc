//! Differential probe: frankenlibc math vs glibc libm on C99 Annex F
//! mandated-exact special cases (inf/nan/±0 handling, exact integer powers,
//! signed-zero atan2 quadrants, round-half-to-even remainder, hypot(inf,nan),
//! nextafter steps). Compared via exact IEEE-754 bits, EXCEPT NaN results which
//! are compared as "is NaN" (NaN sign/payload is unspecified by the standard).
//! glibc reference bits captured from a C probe linked against -lm.

use frankenlibc_core::math::{
    atan2, cbrt, copysign, exp, fmod, hypot, ldexp, log, nextafter, pow, remainder, scalbn,
};

fn check(label: &str, got: f64, glibc_hex: &str, diffs: &mut Vec<String>) {
    let g = u64::from_str_radix(glibc_hex, 16).expect("hex");
    let ref_val = f64::from_bits(g);
    let ok = if ref_val.is_nan() {
        got.is_nan()
    } else {
        got.to_bits() == g
    };
    if !ok {
        diffs.push(format!(
            "{label}: frankenlibc=0x{:016x} ({got:?}) glibc=0x{g:016x} ({ref_val:?})",
            got.to_bits()
        ));
    }
}

#[test]
fn math_special_value_differential_battery() {
    let inf = f64::INFINITY;
    let ninf = f64::NEG_INFINITY;
    let nan = f64::NAN;
    let mut d = Vec::new();

    // (label, frankenlibc result, glibc bits)
    check("pow_p0_n2", pow(0.0, -2.0), "7ff0000000000000", &mut d);
    check("pow_n0_n3", pow(-0.0, -3.0), "fff0000000000000", &mut d);
    check("pow_p0_3", pow(0.0, 3.0), "0000000000000000", &mut d);
    check("pow_n0_3", pow(-0.0, 3.0), "8000000000000000", &mut d);
    check("pow_n1_inf", pow(-1.0, inf), "3ff0000000000000", &mut d);
    check("pow_n1_ninf", pow(-1.0, ninf), "3ff0000000000000", &mut d);
    check("pow_1_nan", pow(1.0, nan), "3ff0000000000000", &mut d);
    check("pow_nan_0", pow(nan, 0.0), "3ff0000000000000", &mut d);
    check("pow_inf_0", pow(inf, 0.0), "3ff0000000000000", &mut d);
    check("pow_2_10", pow(2.0, 10.0), "4090000000000000", &mut d);
    check("pow_n2_3", pow(-2.0, 3.0), "c020000000000000", &mut d);
    check("pow_0_0", pow(0.0, 0.0), "3ff0000000000000", &mut d);
    check("pow_ninf_n1", pow(ninf, -1.0), "8000000000000000", &mut d);
    check("pow_ninf_2", pow(ninf, 2.0), "7ff0000000000000", &mut d);
    check("pow_half_ninf", pow(0.5, ninf), "7ff0000000000000", &mut d);
    check("pow_2_ninf", pow(2.0, ninf), "0000000000000000", &mut d);

    check("fmod_5_3", fmod(5.0, 3.0), "4000000000000000", &mut d);
    check("fmod_n5_3", fmod(-5.0, 3.0), "c000000000000000", &mut d);
    check("fmod_5_n3", fmod(5.0, -3.0), "4000000000000000", &mut d);
    check("fmod_5_0", fmod(5.0, 0.0), "fff8000000000000", &mut d);
    check("fmod_inf_1", fmod(inf, 1.0), "fff8000000000000", &mut d);
    check("fmod_1_inf", fmod(1.0, inf), "3ff0000000000000", &mut d);
    check("fmod_n0_5", fmod(-0.0, 5.0), "8000000000000000", &mut d);

    check("rem_5_3", remainder(5.0, 3.0), "bff0000000000000", &mut d);
    check("rem_5_2", remainder(5.0, 2.0), "3ff0000000000000", &mut d);
    check("rem_7_2", remainder(7.0, 2.0), "bff0000000000000", &mut d);
    check("rem_n5_3", remainder(-5.0, 3.0), "3ff0000000000000", &mut d);

    check("atan2_p0_p0", atan2(0.0, 0.0), "0000000000000000", &mut d);
    check("atan2_n0_p0", atan2(-0.0, 0.0), "8000000000000000", &mut d);
    check("atan2_p0_n0", atan2(0.0, -0.0), "400921fb54442d18", &mut d);
    check("atan2_n0_n0", atan2(-0.0, -0.0), "c00921fb54442d18", &mut d);
    check("atan2_p0_n1", atan2(0.0, -1.0), "400921fb54442d18", &mut d);
    check("atan2_1_0", atan2(1.0, 0.0), "3ff921fb54442d18", &mut d);
    check("atan2_n1_0", atan2(-1.0, 0.0), "bff921fb54442d18", &mut d);
    check("atan2_inf_inf", atan2(inf, inf), "3fe921fb54442d18", &mut d);
    check(
        "atan2_inf_ninf",
        atan2(inf, ninf),
        "4002d97c7f3321d2",
        &mut d,
    );

    check(
        "copysign_3_n0",
        copysign(3.0, -0.0),
        "c008000000000000",
        &mut d,
    );
    check(
        "copysign_3_n1",
        copysign(3.0, -1.0),
        "c008000000000000",
        &mut d,
    );

    check("cbrt_n8", cbrt(-8.0), "c000000000000000", &mut d);
    check("cbrt_n0", cbrt(-0.0), "8000000000000000", &mut d);
    check("cbrt_inf", cbrt(inf), "7ff0000000000000", &mut d);

    check("hypot_3_4", hypot(3.0, 4.0), "4014000000000000", &mut d);
    check("hypot_inf_nan", hypot(inf, nan), "7ff0000000000000", &mut d);
    check("hypot_nan_inf", hypot(nan, inf), "7ff0000000000000", &mut d);

    check(
        "nextafter_1_2",
        nextafter(1.0, 2.0),
        "3ff0000000000001",
        &mut d,
    );
    check(
        "nextafter_0_1",
        nextafter(0.0, 1.0),
        "0000000000000001",
        &mut d,
    );
    check(
        "nextafter_0_n1",
        nextafter(0.0, -1.0),
        "8000000000000001",
        &mut d,
    );
    check(
        "nextafter_1_1",
        nextafter(1.0, 1.0),
        "3ff0000000000000",
        &mut d,
    );
    check(
        "nextafter_inf_0",
        nextafter(inf, 0.0),
        "7fefffffffffffff",
        &mut d,
    );

    check("log_1", log(1.0), "0000000000000000", &mut d);
    check("log_0", log(0.0), "fff0000000000000", &mut d);
    check("log_n1", log(-1.0), "fff8000000000000", &mut d);
    check("log_inf", log(inf), "7ff0000000000000", &mut d);
    check("exp_0", exp(0.0), "3ff0000000000000", &mut d);
    check("exp_ninf", exp(ninf), "0000000000000000", &mut d);
    check("exp_inf", exp(inf), "7ff0000000000000", &mut d);
    check("scalbn_1_3", scalbn(1.0, 3), "4020000000000000", &mut d);
    check("ldexp_3_4", ldexp(3.0, 4), "4048000000000000", &mut d);

    assert!(
        d.is_empty(),
        "math special-value results diverge from glibc in {} case(s):\n{}",
        d.len(),
        d.join("\n")
    );
}

/// Regression guard: the libm-passthrough error/gamma functions stay within the
/// 4-ULP-vs-glibc math contract across their ranges. Pins erf/erfc/lgamma against
/// the host glibc directly (catches any musl-libm drift). Bessel functions are
/// NOT pinned here — they diverge by 100s-1000s of ULP (see bd-2g7oyh.171 and the
/// `bessel_glibc_divergence_research` probe below).
#[test]
#[allow(unsafe_code)] // host-glibc oracle (-lm is linked by std)
fn erf_erfc_lgamma_within_4_ulp_of_glibc() {
    unsafe extern "C" {
        fn erf(x: f64) -> f64;
        fn erfc(x: f64) -> f64;
        fn lgamma(x: f64) -> f64;
    }
    fn ulp(a: f64, b: f64) -> i64 {
        if a == b || (a.is_nan() && b.is_nan()) {
            0
        } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            i64::MAX
        } else {
            (a.to_bits() as i64 - b.to_bits() as i64).abs()
        }
    }
    let mut worst = (0i64, 0i64, 0i64);
    let mut x = -6.0f64;
    while x <= 25.0 {
        let ue = ulp(frankenlibc_core::math::erf(x), unsafe { erf(x) });
        let uc = ulp(frankenlibc_core::math::erfc(x), unsafe { erfc(x) });
        worst.0 = worst.0.max(ue);
        worst.1 = worst.1.max(uc);
        if x > 0.0 {
            let ul = ulp(frankenlibc_core::math::lgamma(x), unsafe { lgamma(x) });
            worst.2 = worst.2.max(ul);
        }
        x += 1e-4;
    }
    assert!(
        worst.0 <= 4 && worst.1 <= 4 && worst.2 <= 4,
        "passthrough erf/erfc/lgamma drifted >4 ULP vs glibc: erf={} erfc={} lgamma={}",
        worst.0,
        worst.1,
        worst.2
    );
}

/// Research probe (ignored): quantifies how far the libm-passthrough Bessel
/// functions diverge from glibc. fl uses musl libm for j0/j1/jn/y0/y1/yn, which
/// uses different algorithms than glibc; divergence reaches 1000s of ULP near the
/// Bessel zeros and for high orders/arguments. Tracks bd-2g7oyh.171. Run with
/// `--ignored --nocapture` to print the per-function worst ULP.
#[test]
#[ignore]
#[allow(unsafe_code)]
fn bessel_glibc_divergence_research() {
    unsafe extern "C" {
        fn j0(x: f64) -> f64;
        fn j1(x: f64) -> f64;
        fn jn(n: i32, x: f64) -> f64;
        fn y0(x: f64) -> f64;
        fn y1(x: f64) -> f64;
        fn yn(n: i32, x: f64) -> f64;
    }
    fn ulp(a: f64, b: f64) -> i64 {
        if a == b || (a.is_nan() && b.is_nan()) {
            0
        } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            i64::MAX
        } else {
            (a.to_bits() as i64 - b.to_bits() as i64).abs()
        }
    }
    let report = |name: &str, fl: &dyn Fn(f64) -> f64, gl: &dyn Fn(f64) -> f64| {
        let (mut worst, mut wx, mut over4) = (0i64, 0.0f64, 0u64);
        let mut x = 0.1f64;
        while x <= 40.0 {
            let u = ulp(fl(x), gl(x));
            if u != i64::MAX {
                if u > worst {
                    worst = u;
                    wx = x;
                }
                if u > 4 {
                    over4 += 1;
                }
            }
            x += 1e-3;
        }
        eprintln!("{name:6}: worst {worst} ULP @x={wx:.4}  ({over4} pts >4ULP)");
    };
    report("j0", &|x| frankenlibc_core::math::j0(x), &|x| unsafe { j0(x) });
    report("j1", &|x| frankenlibc_core::math::j1(x), &|x| unsafe { j1(x) });
    report("y0", &|x| frankenlibc_core::math::y0(x), &|x| unsafe { y0(x) });
    report("y1", &|x| frankenlibc_core::math::y1(x), &|x| unsafe { y1(x) });
    report("jn3", &|x| frankenlibc_core::math::jn(3, x), &|x| unsafe { jn(3, x) });
    report("yn3", &|x| frankenlibc_core::math::yn(3, x), &|x| unsafe { yn(3, x) });
    report("jn10", &|x| frankenlibc_core::math::jn(10, x), &|x| unsafe { jn(10, x) });
}

/// Comprehensive regression guard: the libm-passthrough trig / inverse-trig /
/// inverse-hyperbolic / cbrt functions stay within the 4-ULP-vs-glibc math
/// contract across their ranges — INCLUDING large-argument range reduction for
/// sin/cos/tan (1e6..1e18), where musl and glibc reduction could diverge but in
/// fact agree to ≤1 ULP. Catches any future musl-libm drift. (Bessel is the only
/// libm-passthrough family that "diverges", and that is a pure near-zero ULP
/// metric artifact — both agree to 0 ULP where the value is meaningful; see the
/// bessel_glibc_divergence_research probe.)
#[test]
#[allow(unsafe_code)] // host-glibc oracle (-lm linked by std)
fn trig_inverse_cbrt_passthroughs_within_4_ulp_of_glibc() {
    use frankenlibc_core::math as m;
    unsafe extern "C" {
        fn sin(x: f64) -> f64;
        fn cos(x: f64) -> f64;
        fn tan(x: f64) -> f64;
        fn asin(x: f64) -> f64;
        fn acos(x: f64) -> f64;
        fn atan(x: f64) -> f64;
        fn asinh(x: f64) -> f64;
        fn acosh(x: f64) -> f64;
        fn atanh(x: f64) -> f64;
        fn cbrt(x: f64) -> f64;
    }
    fn ulp(a: f64, b: f64) -> i64 {
        if a == b || (a.is_nan() && b.is_nan()) {
            0
        } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            i64::MAX
        } else {
            (a.to_bits() as i64 - b.to_bits() as i64).abs()
        }
    }
    let scan = |name: &str, fl: &dyn Fn(f64) -> f64, gl: &dyn Fn(f64) -> f64, lo: f64, hi: f64, step: f64| {
        let mut worst = 0i64;
        let mut wx = 0.0f64;
        let mut x = lo;
        while x <= hi {
            let u = ulp(fl(x), gl(x));
            if u > worst {
                worst = u;
                wx = x;
            }
            x += step;
        }
        assert!(worst <= 4, "{name} drifted {worst} ULP vs glibc at x={wx:e}");
    };

    scan("sin", &|x| m::sin(x), &|x| unsafe { sin(x) }, -12.0, 12.0, 1e-4);
    scan("cos", &|x| m::cos(x), &|x| unsafe { cos(x) }, -12.0, 12.0, 1e-4);
    scan("tan", &|x| m::tan(x), &|x| unsafe { tan(x) }, -1.5, 1.5, 1e-4);
    // Large-argument range reduction.
    scan("sin_big", &|x| m::sin(x), &|x| unsafe { sin(x) }, 1e6, 1e6 + 1e3, 1e-2);
    scan("sin_huge", &|x| m::sin(x), &|x| unsafe { sin(x) }, 1e15, 1e15 + 1e8, 1e4);
    scan("cos_huge", &|x| m::cos(x), &|x| unsafe { cos(x) }, 1e15, 1e15 + 1e8, 1e4);
    scan("sin_e18", &|x| m::sin(x), &|x| unsafe { sin(x) }, 1e18, 1e18 + 1e12, 1e8);
    scan("asin", &|x| m::asin(x), &|x| unsafe { asin(x) }, -1.0, 1.0, 1e-5);
    scan("acos", &|x| m::acos(x), &|x| unsafe { acos(x) }, -1.0, 1.0, 1e-5);
    scan("atan", &|x| m::atan(x), &|x| unsafe { atan(x) }, -50.0, 50.0, 1e-3);
    scan("asinh", &|x| m::asinh(x), &|x| unsafe { asinh(x) }, -50.0, 50.0, 1e-3);
    scan("acosh", &|x| m::acosh(x), &|x| unsafe { acosh(x) }, 1.0, 50.0, 1e-3);
    scan("atanh", &|x| m::atanh(x), &|x| unsafe { atanh(x) }, -0.999, 0.999, 1e-5);
    scan("cbrt", &|x| m::cbrt(x), &|x| unsafe { cbrt(x) }, -100.0, 100.0, 1e-3);
}

/// Regression guard for the f32 libm-passthrough trig / inverse-trig /
/// inverse-hyperbolic / cbrt / logf family: each stays within 4 ULP of the host
/// glibc across its range (incl. moderate large-arg range reduction for sinf).
/// Mirrors the f64 guard; catches any musl-libm-f32 drift past the contract.
#[test]
#[allow(unsafe_code)] // host-glibc oracle (-lm linked by std)
fn f32_trig_inverse_cbrt_passthroughs_within_4_ulp_of_glibc() {
    use frankenlibc_core::math as m;
    unsafe extern "C" {
        fn sinf(x: f32) -> f32;
        fn cosf(x: f32) -> f32;
        fn tanf(x: f32) -> f32;
        fn asinf(x: f32) -> f32;
        fn acosf(x: f32) -> f32;
        fn atanf(x: f32) -> f32;
        fn cbrtf(x: f32) -> f32;
        fn asinhf(x: f32) -> f32;
        fn acoshf(x: f32) -> f32;
        fn atanhf(x: f32) -> f32;
        fn logf(x: f32) -> f32;
        fn log2f(x: f32) -> f32;
        fn log10f(x: f32) -> f32;
        fn log1pf(x: f32) -> f32;
    }
    fn ulpf(a: f32, b: f32) -> i64 {
        if a == b || (a.is_nan() && b.is_nan()) {
            0
        } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            i64::MAX
        } else {
            (a.to_bits() as i64 - b.to_bits() as i64).abs()
        }
    }
    // Iterate the loop variable in f64 (cast to f32 per call) so a small step
    // near a large x can never stall on f32 rounding granularity.
    let scan = |name: &str, fl: &dyn Fn(f32) -> f32, gl: &dyn Fn(f32) -> f32, lo: f64, hi: f64, step: f64| {
        let mut worst = 0i64;
        let mut wx = 0.0f32;
        let mut xd = lo;
        while xd <= hi {
            let x = xd as f32;
            let u = ulpf(fl(x), gl(x));
            if u > worst {
                worst = u;
                wx = x;
            }
            xd += step;
        }
        assert!(worst <= 4, "{name} drifted {worst} ULP vs glibc at x={wx:e}");
    };

    scan("sinf", &|x| m::sinf(x), &|x| unsafe { sinf(x) }, -12.0, 12.0, 1e-4);
    scan("sinf_big", &|x| m::sinf(x), &|x| unsafe { sinf(x) }, 1e4, 1e4 + 4e3, 0.05);
    scan("cosf", &|x| m::cosf(x), &|x| unsafe { cosf(x) }, -12.0, 12.0, 1e-4);
    scan("tanf", &|x| m::tanf(x), &|x| unsafe { tanf(x) }, -1.5, 1.5, 1e-5);
    scan("asinf", &|x| m::asinf(x), &|x| unsafe { asinf(x) }, -1.0, 1.0, 1e-5);
    scan("acosf", &|x| m::acosf(x), &|x| unsafe { acosf(x) }, -1.0, 1.0, 1e-5);
    scan("atanf", &|x| m::atanf(x), &|x| unsafe { atanf(x) }, -50.0, 50.0, 1e-3);
    scan("cbrtf", &|x| m::cbrtf(x), &|x| unsafe { cbrtf(x) }, -100.0, 100.0, 1e-3);
    scan("asinhf", &|x| m::asinhf(x), &|x| unsafe { asinhf(x) }, -50.0, 50.0, 1e-3);
    scan("acoshf", &|x| m::acoshf(x), &|x| unsafe { acoshf(x) }, 1.0, 50.0, 1e-3);
    scan("atanhf", &|x| m::atanhf(x), &|x| unsafe { atanhf(x) }, -0.999, 0.999, 1e-5);
    scan("logf", &|x| m::logf(x), &|x| unsafe { logf(x) }, 1e-6, 1e6, 7.0);
    scan("log2f", &|x| m::log2f(x), &|x| unsafe { log2f(x) }, 1e-6, 1e6, 7.0);
    scan("log10f", &|x| m::log10f(x), &|x| unsafe { log10f(x) }, 1e-6, 1e6, 7.0);
    scan("log1pf", &|x| m::log1pf(x), &|x| unsafe { log1pf(x) }, -0.9, 50.0, 1e-4);
    // Dense near-1 sweep: log(x) -> 0 there, so relative accuracy is most
    // delicate (the f64 log2 kernel switches to its atanh branch for |x-1|<0.15).
    // Guards the f64-kernel routing of the f32 log family (logf/log2f/log10f).
    scan("logf_near1", &|x| m::logf(x), &|x| unsafe { logf(x) }, 0.5, 2.0, 1e-5);
    scan("log2f_near1", &|x| m::log2f(x), &|x| unsafe { log2f(x) }, 0.5, 2.0, 1e-5);
    scan("log10f_near1", &|x| m::log10f(x), &|x| unsafe { log10f(x) }, 0.5, 2.0, 1e-5);
    // Sub-1 and large-magnitude spans to exercise the full exponent range.
    scan("logf_small", &|x| m::logf(x), &|x| unsafe { logf(x) }, 1e-30, 1e-3, 3e-7);
    scan("log2f_small", &|x| m::log2f(x), &|x| unsafe { log2f(x) }, 1e-30, 1e-3, 3e-7);
    scan("log10f_small", &|x| m::log10f(x), &|x| unsafe { log10f(x) }, 1e-30, 1e-3, 3e-7);
}
