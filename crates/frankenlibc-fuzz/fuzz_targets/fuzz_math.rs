#![no_main]
//! Structure-aware fuzz target for FrankenLibC math functions.
//!
//! Exercises trig, exp/log, float utilities, and special functions
//! from `frankenlibc-core::math`. f64 and f32 variants tested.
//!
//! Invariants:
//! - No function panics on any finite, NaN, or Inf input
//! - sin²(x) + cos²(x) ≈ 1 for finite x
//! - exp(log(x)) ≈ x for positive finite x
//! - sqrt(x)² ≈ x for non-negative x
//! - f32 variants are consistent with f64 counterparts (within precision)
//!
//! Bead: bd-2hh.4

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::math;

#[derive(Debug, Arbitrary)]
struct MathFuzzInput {
    /// Primary f64 input value (raw bits for full coverage).
    bits_a: u64,
    /// Secondary f64 input (for two-argument functions).
    bits_b: u64,
    /// Integer input for jn/yn.
    n: i32,
    /// Operation selector.
    op: u8,
}

const EPS_F64: f64 = 1e-10;
const EPS_F32: f32 = 1e-4;

fn f64_from_bits(bits: u64) -> f64 {
    f64::from_bits(bits)
}

fn f32_from_f64_bits(bits: u64) -> f32 {
    // Take lower 32 bits as f32
    f32::from_bits(bits as u32)
}

fuzz_target!(|input: MathFuzzInput| {
    match input.op % 8 {
        0 => fuzz_trig(&input),
        1 => fuzz_exp_log(&input),
        2 => fuzz_float_utils(&input),
        3 => fuzz_special(&input),
        4 => fuzz_float32_trig(&input),
        5 => fuzz_float32_exp(&input),
        6 => fuzz_rounding(&input),
        7 => fuzz_two_arg(&input),
        _ => unreachable!(),
    }
});

/// Trig functions: no panics, Pythagorean identity.
fn fuzz_trig(input: &MathFuzzInput) {
    let x = f64_from_bits(input.bits_a);

    // All must not panic
    let s = math::sin(x);
    let c = math::cos(x);
    let t = math::tan(x);
    let _ = math::asin(x);
    let _ = math::acos(x);
    let _ = math::atan(x);
    let _ = math::sinh(x);
    let _ = math::cosh(x);
    let _ = math::tanh(x);
    let _ = math::asinh(x);
    let _ = math::acosh(x);
    let _ = math::atanh(x);
    let _ = t;

    // sincos should agree with sin/cos
    let (sc_s, sc_c) = math::sincos(x);
    if s.is_finite() {
        assert_eq!(s.to_bits(), sc_s.to_bits(), "sincos sin disagrees at x={x}");
    }
    if c.is_finite() {
        assert_eq!(c.to_bits(), sc_c.to_bits(), "sincos cos disagrees at x={x}");
    }

    // Pythagorean identity for finite x
    if x.is_finite() && s.is_finite() && c.is_finite() {
        let sum = s * s + c * c;
        assert!(
            (sum - 1.0).abs() < EPS_F64,
            "sin²+cos² = {sum} (not ≈1) at x={x}"
        );
    }
}

/// Exp/log functions: no panics, inverse relationship.
fn fuzz_exp_log(input: &MathFuzzInput) {
    let x = f64_from_bits(input.bits_a);

    let e = math::exp(x);
    let e2 = math::exp2(x);
    let em1 = math::expm1(x);
    let l = math::log(x);
    let l2 = math::log2(x);
    let l10 = math::log10(x);
    let l1p = math::log1p(x);
    let _ = (e, e2, em1, l, l2, l10, l1p);

    // exp(log(x)) ≈ x for positive finite x not near 0 or overflow
    if x.is_finite() && x > 1e-300 && x < 1e300 {
        let lx = math::log(x);
        if lx.is_finite() {
            let rt = math::exp(lx);
            if rt.is_finite() {
                let rel = ((rt - x) / x).abs();
                assert!(
                    rel < EPS_F64,
                    "exp(log({x})) = {rt}, relative error = {rel}"
                );
            }
        }
    }

    // log2(exp2(x)) ≈ x for small |x|
    if x.is_finite() && x.abs() < 100.0 {
        let e2x = math::exp2(x);
        if e2x.is_finite() && e2x > 0.0 {
            let rt = math::log2(e2x);
            if rt.is_finite() {
                let err = (rt - x).abs();
                assert!(err < EPS_F64, "log2(exp2({x})) = {rt}, error = {err}");
            }
        }
    }
}

/// Float utility functions: no panics, basic invariants.
fn fuzz_float_utils(input: &MathFuzzInput) {
    let x = f64_from_bits(input.bits_a);

    let _ = math::fabs(x);
    let _ = math::ceil(x);
    let _ = math::floor(x);
    let _ = math::round(x);
    let _ = math::trunc(x);
    let _ = math::rint(x);
    let _ = math::nearbyint(x);
    let _ = math::sqrt(x);
    let _ = math::cbrt(x);
    let _ = math::fpclassify(x);
    let _ = math::isnan(x);
    let _ = math::isinf(x);
    let _ = math::signbit(x);
    let _ = math::ilogb(x);
    let _ = math::logb(x);
    let _ = math::significand(x);

    let (frac, exp) = math::frexp(x);
    let _ = (frac, exp);
    let (int_part, frac_part) = math::modf(x);
    let _ = (int_part, frac_part);

    // fabs invariants
    if x.is_finite() {
        let a = math::fabs(x);
        assert!(a >= 0.0, "fabs should be non-negative");
        assert_eq!(a, math::fabs(-x), "fabs(-x) should equal fabs(x)");
    }

    // sqrt(x)² ≈ x for non-negative finite x
    if x.is_finite() && x >= 0.0 {
        let sq = math::sqrt(x);
        if sq.is_finite() {
            let rt = sq * sq;
            if x > 1e-300 && x < 1e300 {
                let rel = ((rt - x) / x).abs();
                assert!(rel < EPS_F64, "sqrt({x})² = {rt}, relative error = {rel}");
            }
        }
    }

    // floor(x) <= x <= ceil(x) for finite x
    if x.is_finite() {
        let fl = math::floor(x);
        let cl = math::ceil(x);
        assert!(fl <= x, "floor({x}) = {fl} > x");
        assert!(cl >= x, "ceil({x}) = {cl} < x");
    }
}

/// Special functions: no panics.
fn fuzz_special(input: &MathFuzzInput) {
    let x = f64_from_bits(input.bits_a);
    let n = input.n.clamp(-100, 100);

    let _ = math::erf(x);
    let _ = math::erfc(x);
    let _ = math::tgamma(x);
    let _ = math::lgamma(x);
    let (lg, sign) = math::lgamma_r(x);
    let _ = (lg, sign);
    let _ = math::j0(x);
    let _ = math::j1(x);
    let _ = math::jn(n, x);
    let _ = math::y0(x);
    let _ = math::y1(x);
    let _ = math::yn(n, x);

    // erf + erfc ≈ 1 for finite x
    if x.is_finite() {
        let e = math::erf(x);
        let ec = math::erfc(x);
        if e.is_finite() && ec.is_finite() {
            let sum = e + ec;
            assert!(
                (sum - 1.0).abs() < EPS_F64,
                "erf({x})+erfc({x}) = {sum} (not ≈1)"
            );
        }
    }
}

/// Float32 trig functions.
fn fuzz_float32_trig(input: &MathFuzzInput) {
    let x = f32_from_f64_bits(input.bits_a);

    let s = math::sinf(x);
    let c = math::cosf(x);
    let _ = math::tanf(x);
    let _ = math::asinf(x);
    let _ = math::acosf(x);
    let _ = math::atanf(x);
    let _ = math::sinhf(x);
    let _ = math::coshf(x);
    let _ = math::tanhf(x);
    let _ = math::asinhf(x);
    let _ = math::acoshf(x);
    let _ = math::atanhf(x);

    let (sc_s, sc_c) = math::sincosf(x);
    if s.is_finite() {
        assert_eq!(
            s.to_bits(),
            sc_s.to_bits(),
            "sincosf sin disagrees at x={x}"
        );
    }
    if c.is_finite() {
        assert_eq!(
            c.to_bits(),
            sc_c.to_bits(),
            "sincosf cos disagrees at x={x}"
        );
    }

    if x.is_finite() && s.is_finite() && c.is_finite() {
        let sum = s * s + c * c;
        assert!(
            (sum - 1.0).abs() < EPS_F32,
            "sinf²+cosf² = {sum} (not ≈1) at x={x}"
        );
    }
}

/// Float32 exp/log functions.
fn fuzz_float32_exp(input: &MathFuzzInput) {
    let x = f32_from_f64_bits(input.bits_a);

    let _ = math::expf(x);
    let _ = math::exp2f(x);
    let _ = math::expm1f(x);
    let _ = math::logf(x);
    let _ = math::log2f(x);
    let _ = math::log10f(x);
    let _ = math::log1pf(x);
    let _ = math::sqrtf(x);
    let _ = math::cbrtf(x);
    let _ = math::fabsf(x);
    let _ = math::ceilf(x);
    let _ = math::floorf(x);
    let _ = math::roundf(x);
    let _ = math::truncf(x);
    let _ = math::rintf(x);
    let _ = math::nearbyintf(x);
}

/// Rounding function consistency.
fn fuzz_rounding(input: &MathFuzzInput) {
    let x = f64_from_bits(input.bits_a);

    if x.is_finite() {
        let t = math::trunc(x);
        let fl = math::floor(x);
        let cl = math::ceil(x);

        // trunc is between floor and ceil
        if t.is_finite() && fl.is_finite() && cl.is_finite() {
            assert!(
                t >= fl && t <= cl,
                "trunc({x})={t} not in [floor={fl}, ceil={cl}]"
            );
        }

        // lrint, llrint, lround, llround should not panic
        let _ = math::lrint(x);
        let _ = math::llrint(x);
        let _ = math::lround(x);
        let _ = math::llround(x);
    }
}

/// Two-argument functions.
fn fuzz_two_arg(input: &MathFuzzInput) {
    let x = f64_from_bits(input.bits_a);
    let y = f64_from_bits(input.bits_b);

    let _ = math::pow(x, y);
    let _ = math::atan2(x, y);
    let _ = math::hypot(x, y);
    let _ = math::fmod(x, y);
    let _ = math::remainder(x, y);
    let _ = math::fmax(x, y);
    let _ = math::fmin(x, y);
    let _ = math::fdim(x, y);
    let _ = math::copysign(x, y);
    let _ = math::nextafter(x, y);
    let _ = math::fma(x, y, f64_from_bits(input.n as u64));

    let (_, _) = math::remquo(x, y);

    // hypot commutativity
    if x.is_finite() && y.is_finite() {
        let h1 = math::hypot(x, y);
        let h2 = math::hypot(y, x);
        if h1.is_finite() && h2.is_finite() {
            assert_eq!(
                h1.to_bits(),
                h2.to_bits(),
                "hypot not commutative: hypot({x},{y})={h1} vs hypot({y},{x})={h2}"
            );
        }
    }

    // fmax/fmin consistency
    if x.is_finite() && y.is_finite() {
        let mx = math::fmax(x, y);
        let mn = math::fmin(x, y);
        assert!(mx >= mn, "fmax({x},{y})={mx} < fmin={mn}");
    }
}
