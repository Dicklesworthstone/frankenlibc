#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // calls fl math exports directly

//! Wiring gate for the C23 _Float32/_Float64 math aliases (bd-wjkcrg). On
//! x86-64 _Float32 == float and _Float64 == double, so every `<fn>f32` alias
//! must be bit-identical to `<fn>f`, and every `<fn>f64` alias bit-identical to
//! `<fn>`. These ~268 one-line aliases were untested; a mis-wired alias (a
//! copy-paste typo calling the wrong base, e.g. acoshf32 -> asinhf) would slip
//! through. This asserts alias(x) == base(x) bit-for-bit over a value grid.
//! No mocks — pure self-consistency of fl's own exports.

use frankenlibc_abi::math_abi as m;

type F32 = unsafe extern "C" fn(f32) -> f32;
type F64 = unsafe extern "C" fn(f64) -> f64;

#[test]
fn floatn_f32_aliases_match_base() {
    let pairs: &[(F32, F32, &str)] = &[
        (m::sinf32, m::sinf, "sin"),
        (m::cosf32, m::cosf, "cos"),
        (m::tanf32, m::tanf, "tan"),
        (m::asinf32, m::asinf, "asin"),
        (m::acosf32, m::acosf, "acos"),
        (m::atanf32, m::atanf, "atan"),
        (m::sinhf32, m::sinhf, "sinh"),
        (m::coshf32, m::coshf, "cosh"),
        (m::tanhf32, m::tanhf, "tanh"),
        (m::asinhf32, m::asinhf, "asinh"),
        (m::acoshf32, m::acoshf, "acosh"),
        (m::atanhf32, m::atanhf, "atanh"),
        (m::expf32, m::expf, "exp"),
        (m::exp2f32, m::exp2f, "exp2"),
        (m::expm1f32, m::expm1f, "expm1"),
        (m::logf32, m::logf, "log"),
        (m::log2f32, m::log2f, "log2"),
        (m::log10f32, m::log10f, "log10"),
        (m::log1pf32, m::log1pf, "log1p"),
        (m::sqrtf32, m::sqrtf, "sqrt"),
        (m::cbrtf32, m::cbrtf, "cbrt"),
        (m::fabsf32, m::fabsf, "fabs"),
        (m::ceilf32, m::ceilf, "ceil"),
        (m::floorf32, m::floorf, "floor"),
        (m::truncf32, m::truncf, "trunc"),
        (m::roundf32, m::roundf, "round"),
        (m::rintf32, m::rintf, "rint"),
        (m::nearbyintf32, m::nearbyintf, "nearbyint"),
        (m::erff32, m::erff, "erf"),
        (m::erfcf32, m::erfcf, "erfc"),
        (m::tgammaf32, m::tgammaf, "tgamma"),
        (m::lgammaf32, m::lgammaf, "lgamma"),
    ];
    let xs = [
        0.0f32, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, 3.14159, 100.0, -100.0, 1e-20, 1e20,
        f32::NAN, f32::INFINITY, f32::NEG_INFINITY,
    ];
    for &(alias, base, name) in pairs {
        for &x in &xs {
            let a = unsafe { alias(x) };
            let b = unsafe { base(x) };
            assert!(
                a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()),
                "{name}f32({x}) = {a} but {name}f({x}) = {b}"
            );
        }
    }
}

#[test]
fn floatn_f64_aliases_match_base() {
    let pairs: &[(F64, F64, &str)] = &[
        (m::sinf64, m::sin, "sin"),
        (m::cosf64, m::cos, "cos"),
        (m::tanf64, m::tan, "tan"),
        (m::asinf64, m::asin, "asin"),
        (m::acosf64, m::acos, "acos"),
        (m::atanf64, m::atan, "atan"),
        (m::sinhf64, m::sinh, "sinh"),
        (m::coshf64, m::cosh, "cosh"),
        (m::tanhf64, m::tanh, "tanh"),
        (m::asinhf64, m::asinh, "asinh"),
        (m::acoshf64, m::acosh, "acosh"),
        (m::atanhf64, m::atanh, "atanh"),
        (m::expf64, m::exp, "exp"),
        (m::exp2f64, m::exp2, "exp2"),
        (m::expm1f64, m::expm1, "expm1"),
        (m::logf64, m::log, "log"),
        (m::log2f64, m::log2, "log2"),
        (m::log10f64, m::log10, "log10"),
        (m::log1pf64, m::log1p, "log1p"),
        (m::sqrtf64, m::sqrt, "sqrt"),
        (m::cbrtf64, m::cbrt, "cbrt"),
        (m::fabsf64, m::fabs, "fabs"),
        (m::ceilf64, m::ceil, "ceil"),
        (m::floorf64, m::floor, "floor"),
        (m::truncf64, m::trunc, "trunc"),
        (m::roundf64, m::round, "round"),
        (m::erff64, m::erf, "erf"),
        (m::erfcf64, m::erfc, "erfc"),
        (m::tgammaf64, m::tgamma, "tgamma"),
        (m::lgammaf64, m::lgamma, "lgamma"),
    ];
    let xs = [
        0.0f64, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, 3.141592653589793, 100.0, -100.0, 1e-200,
        1e200, f64::NAN, f64::INFINITY, f64::NEG_INFINITY,
    ];
    for &(alias, base, name) in pairs {
        for &x in &xs {
            let a = unsafe { alias(x) };
            let b = unsafe { base(x) };
            assert!(
                a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()),
                "{name}f64({x}) = {a} but {name}({x}) = {b}"
            );
        }
    }
}
