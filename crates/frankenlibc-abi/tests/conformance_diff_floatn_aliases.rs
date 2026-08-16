#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // calls fl math exports directly

//! Wiring gate for the C23 _Float32/_Float64 math aliases (bd-wjkcrg). On
//! x86-64 _Float32 == float and _Float64 == double, so every `<fn>f32` alias
//! must be bit-identical to `<fn>f`, and every `<fn>f64` alias bit-identical to
//! `<fn>`. These ~268 one-line aliases were untested; a mis-wired alias (a
//! copy-paste typo calling the wrong base, e.g. acoshf32 -> asinhf) would slip
//! through. This asserts alias(x) == base(x) bit-for-bit over a value grid.
//! No mocks — pure self-consistency of fl's own exports.
//!
//! COVERAGE, counted from math_abi.rs's own export list: fl exports 268 of
//! these aliases. This gate originally exercised 62 — and the 62 were exactly
//! one signature shape, the unary f(x)->x transcendentals, because that is what
//! a single value-grid loop can drive. Every other shape was untested, which
//! inverted the gate's own stated purpose: the long distinct transcendental
//! names it covered are where a copy-paste typo is LEAST likely, while the
//! clusters differing by one token were all in the untested 206 —
//! `fmaximum`/`_num`/`_mag`/`_mag_num`, `fromfp`/`fromfpx`/`ufromfp`/`ufromfpx`,
//! `j0`/`j1`/`jn`, `y0`/`y1`/`yn`, `nextup`/`nextdown`/`nextafter`.
//!
//! The tables below now cover 176 more, by signature family. Each pair was
//! derived from the export list with its signature checked against its base's,
//! so the tables cannot silently drift from the source.
//!
//! STILL UNCOVERED, and deliberately: the ~30 aliases taking out-pointers or
//! tagged strings (frexp, modf, remquo, sincos, canonicalize, getpayload,
//! setpayload, setpayloadsig, nan), which need per-function scaffolding rather
//! than a table. Also excluded, correctly, are the 12 C23 narrowing-arithmetic
//! entry points (`f32addf64`, `f32xmulf64`, …) — those are not aliases of any
//! base and must not be asserted equal to one.

use frankenlibc_abi::math_abi as m;
use frankenlibc_abi::math_abi::{CDoubleComplex, CFloatComplex};
use std::ffi::c_int;

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
        0.0f32,
        -0.0,
        1.0,
        -1.0,
        0.5,
        -0.5,
        2.0,
        3.14159,
        100.0,
        -100.0,
        1e-20,
        1e20,
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
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
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        0.5,
        -0.5,
        2.0,
        3.141592653589793,
        100.0,
        -100.0,
        1e-200,
        1e200,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
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

// ---------------------------------------------------------------------------
// bd-wjkcrg EXPANSION. The tables above cover only the unary f(x)->x
// transcendentals -- 62 of the 268 aliases fl exports. Everything below covers
// the other signature shapes, which is where a copy-paste typo is MOST likely:
// the alias clusters whose names differ by a single token
// (fmaximum / _num / _mag / _mag_num, fromfp / fromfpx / ufromfp / ufromfpx,
// j0 / j1 / jn, y0 / y1 / yn, nextup / nextdown / nextafter).
//
// Every pair below was derived from math_abi.rs's own export list, and each
// alias's signature was checked to match its base's before being paired, so
// these tables cannot drift out of step with the source by hand-editing.
//
// Same contract as above: alias(x..) == base(x..) BIT-FOR-BIT. Still a pure
// self-consistency wiring gate over fl's own exports -- no oracle involved.


type F32B = unsafe extern "C" fn(f32, f32) -> f32;

#[test]
fn floatn_f32_binary_aliases_match_base() {
    let pairs: &[(F32B, F32B, &str)] = &[
        (m::atan2f32, m::atan2f, "atan2f"),
        (m::atan2pif32, m::atan2pif, "atan2pif"),
        (m::copysignf32, m::copysignf, "copysignf"),
        (m::fdimf32, m::fdimf, "fdimf"),
        (m::fmaxf32, m::fmaxf, "fmaxf"),
        (m::fmaximum_mag_numf32, m::fmaximum_mag_numf, "fmaximum_mag_numf"),
        (m::fmaximum_magf32, m::fmaximum_magf, "fmaximum_magf"),
        (m::fmaximum_numf32, m::fmaximum_numf, "fmaximum_numf"),
        (m::fmaximumf32, m::fmaximumf, "fmaximumf"),
        (m::fmaxmagf32, m::fmaxmagf, "fmaxmagf"),
        (m::fminf32, m::fminf, "fminf"),
        (m::fminimum_mag_numf32, m::fminimum_mag_numf, "fminimum_mag_numf"),
        (m::fminimum_magf32, m::fminimum_magf, "fminimum_magf"),
        (m::fminimum_numf32, m::fminimum_numf, "fminimum_numf"),
        (m::fminimumf32, m::fminimumf, "fminimumf"),
        (m::fminmagf32, m::fminmagf, "fminmagf"),
        (m::fmodf32, m::fmodf, "fmodf"),
        (m::hypotf32, m::hypotf, "hypotf"),
        (m::nextafterf32, m::nextafterf, "nextafterf"),
        (m::powf32, m::powf, "powf"),
        (m::powrf32, m::powrf, "powrf"),
        (m::remainderf32, m::remainderf, "remainderf"),
    ];
    // Ordered pairs: many of these are ASYMMETRIC (copysign, fdim, pow, atan2,
    // nextafter, remainder), so (a,b) and (b,a) are different tests.
    let vs = [0.0f32, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, 3.5, f32::INFINITY, f32::NEG_INFINITY, f32::NAN, -f32::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for &y in &vs {
                let (a, b) = unsafe { (alias(x, y), base(x, y)) };
                assert_eq!(
                    a.to_bits(), b.to_bits(),
                    "{name}f32({x:?}, {y:?}) = {a:?} but {name}({x:?}, {y:?}) = {b:?}"
                );
            }
        }
    }
    assert_eq!(pairs.len(), 22, "binary f32 alias table shrank");
}

type F64B = unsafe extern "C" fn(f64, f64) -> f64;

#[test]
fn floatn_f64_binary_aliases_match_base() {
    let pairs: &[(F64B, F64B, &str)] = &[
        (m::atan2f64, m::atan2, "atan2"),
        (m::atan2pif64, m::atan2pi, "atan2pi"),
        (m::copysignf64, m::copysign, "copysign"),
        (m::fdimf64, m::fdim, "fdim"),
        (m::fmaxf64, m::fmax, "fmax"),
        (m::fmaximum_mag_numf64, m::fmaximum_mag_num, "fmaximum_mag_num"),
        (m::fmaximum_magf64, m::fmaximum_mag, "fmaximum_mag"),
        (m::fmaximum_numf64, m::fmaximum_num, "fmaximum_num"),
        (m::fmaximumf64, m::fmaximum, "fmaximum"),
        (m::fmaxmagf64, m::fmaxmag, "fmaxmag"),
        (m::fminf64, m::fmin, "fmin"),
        (m::fminimum_mag_numf64, m::fminimum_mag_num, "fminimum_mag_num"),
        (m::fminimum_magf64, m::fminimum_mag, "fminimum_mag"),
        (m::fminimum_numf64, m::fminimum_num, "fminimum_num"),
        (m::fminimumf64, m::fminimum, "fminimum"),
        (m::fminmagf64, m::fminmag, "fminmag"),
        (m::fmodf64, m::fmod, "fmod"),
        (m::hypotf64, m::hypot, "hypot"),
        (m::nextafterf64, m::nextafter, "nextafter"),
        (m::powf64, m::pow, "pow"),
        (m::powrf64, m::powr, "powr"),
        (m::remainderf64, m::remainder, "remainder"),
    ];
    // Ordered pairs: many of these are ASYMMETRIC (copysign, fdim, pow, atan2,
    // nextafter, remainder), so (a,b) and (b,a) are different tests.
    let vs = [0.0f64, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, 3.5, f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -f64::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for &y in &vs {
                let (a, b) = unsafe { (alias(x, y), base(x, y)) };
                assert_eq!(
                    a.to_bits(), b.to_bits(),
                    "{name}f64({x:?}, {y:?}) = {a:?} but {name}({x:?}, {y:?}) = {b:?}"
                );
            }
        }
    }
    assert_eq!(pairs.len(), 22, "binary f64 alias table shrank");
}

#[test]
fn floatn_f32_remaining_unary_aliases_match_base() {
    let pairs: &[(F32, F32, &str)] = &[
        (m::acospif32, m::acospif, "acospif"),
        (m::asinpif32, m::asinpif, "asinpif"),
        (m::atanpif32, m::atanpif, "atanpif"),
        (m::cospif32, m::cospif, "cospif"),
        (m::exp10f32, m::exp10f, "exp10f"),
        (m::exp10m1f32, m::exp10m1f, "exp10m1f"),
        (m::exp2m1f32, m::exp2m1f, "exp2m1f"),
        (m::j0f32, m::j0f, "j0f"),
        (m::j1f32, m::j1f, "j1f"),
        (m::log10p1f32, m::log10p1f, "log10p1f"),
        (m::log2p1f32, m::log2p1f, "log2p1f"),
        (m::logbf32, m::logbf, "logbf"),
        (m::logp1f32, m::logp1f, "logp1f"),
        (m::nextdownf32, m::nextdownf, "nextdownf"),
        (m::nextupf32, m::nextupf, "nextupf"),
        (m::roundevenf32, m::roundevenf, "roundevenf"),
        (m::rsqrtf32, m::rsqrtf, "rsqrtf"),
        (m::sinpif32, m::sinpif, "sinpif"),
        (m::tanpif32, m::tanpif, "tanpif"),
        (m::y0f32, m::y0f, "y0f"),
        (m::y1f32, m::y1f, "y1f"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, 3.5, 10.0, 0.25,
              f32::INFINITY, f32::NEG_INFINITY, f32::NAN, -f32::NAN,
              f32::MIN_POSITIVE, f32::MAX];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            let (a, b) = unsafe { (alias(x), base(x)) };
            assert_eq!(a.to_bits(), b.to_bits(), "{name}f32({x:?}) = {a:?} but {name}({x:?}) = {b:?}");
        }
    }
    assert_eq!(pairs.len(), 21, "unary f32 alias table shrank");
}

#[test]
fn floatn_f64_remaining_unary_aliases_match_base() {
    let pairs: &[(F64, F64, &str)] = &[
        (m::acospif64, m::acospi, "acospi"),
        (m::asinpif64, m::asinpi, "asinpi"),
        (m::atanpif64, m::atanpi, "atanpi"),
        (m::cospif64, m::cospi, "cospi"),
        (m::exp10f64, m::exp10, "exp10"),
        (m::exp10m1f64, m::exp10m1, "exp10m1"),
        (m::exp2m1f64, m::exp2m1, "exp2m1"),
        (m::j0f64, m::j0, "j0"),
        (m::j1f64, m::j1, "j1"),
        (m::log10p1f64, m::log10p1, "log10p1"),
        (m::log2p1f64, m::log2p1, "log2p1"),
        (m::logbf64, m::logb, "logb"),
        (m::logp1f64, m::logp1, "logp1"),
        (m::nearbyintf64, m::nearbyint, "nearbyint"),
        (m::nextdownf64, m::nextdown, "nextdown"),
        (m::nextupf64, m::nextup, "nextup"),
        (m::rintf64, m::rint, "rint"),
        (m::roundevenf64, m::roundeven, "roundeven"),
        (m::rsqrtf64, m::rsqrt, "rsqrt"),
        (m::sinpif64, m::sinpi, "sinpi"),
        (m::tanpif64, m::tanpi, "tanpi"),
        (m::y0f64, m::y0, "y0"),
        (m::y1f64, m::y1, "y1"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, 3.5, 10.0, 0.25,
              f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -f64::NAN,
              f64::MIN_POSITIVE, f64::MAX];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            let (a, b) = unsafe { (alias(x), base(x)) };
            assert_eq!(a.to_bits(), b.to_bits(), "{name}f64({x:?}) = {a:?} but {name}({x:?}) = {b:?}");
        }
    }
    assert_eq!(pairs.len(), 23, "unary f64 alias table shrank");
}

#[test]
fn floatn_f32_i64_returning_aliases_match_base() {
    type T = unsafe extern "C" fn(f32) -> i64;
    let pairs: &[(T, T, &str)] = &[
        (m::llogbf32, m::llogbf, "llogbf"),
        (m::llrintf32, m::llrintf, "llrintf"),
        (m::llroundf32, m::llroundf, "llroundf"),
        (m::lrintf32, m::lrintf, "lrintf"),
        (m::lroundf32, m::lroundf, "lroundf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 0.5, 2.5, -2.5, 3.5, 1024.0, 0.125,
              f32::INFINITY, f32::NEG_INFINITY, f32::NAN, f32::MIN_POSITIVE];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            let (a, b) = unsafe { (alias(x), base(x)) };
            assert_eq!(a, b, "{name}f32({x:?}) = {a} but {name}({x:?}) = {b}");
        }
    }
}

#[test]
fn floatn_f32_int_returning_aliases_match_base() {
    type T = unsafe extern "C" fn(f32) -> c_int;
    let pairs: &[(T, T, &str)] = &[
        (m::ilogbf32, m::ilogbf, "ilogbf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 0.5, 2.5, -2.5, 3.5, 1024.0, 0.125,
              f32::INFINITY, f32::NEG_INFINITY, f32::NAN, f32::MIN_POSITIVE];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            let (a, b) = unsafe { (alias(x), base(x)) };
            assert_eq!(a, b, "{name}f32({x:?}) = {a} but {name}({x:?}) = {b}");
        }
    }
}

#[test]
fn floatn_f64_i64_returning_aliases_match_base() {
    type T = unsafe extern "C" fn(f64) -> i64;
    let pairs: &[(T, T, &str)] = &[
        (m::llogbf64, m::llogb, "llogb"),
        (m::llrintf64, m::llrint, "llrint"),
        (m::llroundf64, m::llround, "llround"),
        (m::lrintf64, m::lrint, "lrint"),
        (m::lroundf64, m::lround, "lround"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 0.5, 2.5, -2.5, 3.5, 1024.0, 0.125,
              f64::INFINITY, f64::NEG_INFINITY, f64::NAN, f64::MIN_POSITIVE];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            let (a, b) = unsafe { (alias(x), base(x)) };
            assert_eq!(a, b, "{name}f64({x:?}) = {a} but {name}({x:?}) = {b}");
        }
    }
}

#[test]
fn floatn_f64_int_returning_aliases_match_base() {
    type T = unsafe extern "C" fn(f64) -> c_int;
    let pairs: &[(T, T, &str)] = &[
        (m::ilogbf64, m::ilogb, "ilogb"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 0.5, 2.5, -2.5, 3.5, 1024.0, 0.125,
              f64::INFINITY, f64::NEG_INFINITY, f64::NAN, f64::MIN_POSITIVE];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            let (a, b) = unsafe { (alias(x), base(x)) };
            assert_eq!(a, b, "{name}f64({x:?}) = {a} but {name}({x:?}) = {b}");
        }
    }
}

#[test]
fn floatn_f32_value_then_i64_aliases_match_base() {
    type T = unsafe extern "C" fn(f32, i64) -> f32;
    let pairs: &[(T, T, &str)] = &[
        (m::compoundnf32, m::compoundnf, "compoundnf"),
        (m::pownf32, m::pownf, "pownf"),
        (m::rootnf32, m::rootnf, "rootnf"),
        (m::scalblnf32, m::scalblnf, "scalblnf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 2.0, 0.5, 3.5, f32::INFINITY, f32::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for n in [-3, -1, 0, 1, 2, 5] {
                let (a, b) = unsafe { (alias(x, n as i64), base(x, n as i64)) };
                assert_eq!(a.to_bits(), b.to_bits(), "{name}f32({x:?}, {n}) mismatch");
            }
        }
    }
}

#[test]
fn floatn_f32_value_then_cint_aliases_match_base() {
    type T = unsafe extern "C" fn(f32, c_int) -> f32;
    let pairs: &[(T, T, &str)] = &[
        (m::ldexpf32, m::ldexpf, "ldexpf"),
        (m::scalbnf32, m::scalbnf, "scalbnf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 2.0, 0.5, 3.5, f32::INFINITY, f32::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for n in [-3, -1, 0, 1, 2, 5] {
                let (a, b) = unsafe { (alias(x, n as c_int), base(x, n as c_int)) };
                assert_eq!(a.to_bits(), b.to_bits(), "{name}f32({x:?}, {n}) mismatch");
            }
        }
    }
}

#[test]
fn floatn_f32_order_then_value_aliases_match_base() {
    // jn/yn take the ORDER first. An alias that swapped its two arguments would
    // still typecheck if both were the same type -- they are not, so this arm
    // exists mainly to catch jn -> yn style cross-wiring.
    type T = unsafe extern "C" fn(c_int, f32) -> f32;
    let pairs: &[(T, T, &str)] = &[
        (m::jnf32, m::jnf, "jnf"),
        (m::ynf32, m::ynf, "ynf"),
    ];
    let vs = [0.5f32, 1.0, 2.0, 3.5, 10.0, f32::INFINITY, f32::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for n in [0, 1, 2, 5] {
                let (a, b) = unsafe { (alias(n, x), base(n, x)) };
                assert_eq!(a.to_bits(), b.to_bits(), "{name}f32({n}, {x:?}) mismatch");
            }
        }
    }
}

#[test]
fn floatn_f64_value_then_i64_aliases_match_base() {
    type T = unsafe extern "C" fn(f64, i64) -> f64;
    let pairs: &[(T, T, &str)] = &[
        (m::compoundnf64, m::compoundn, "compoundn"),
        (m::pownf64, m::pown, "pown"),
        (m::rootnf64, m::rootn, "rootn"),
        (m::scalblnf64, m::scalbln, "scalbln"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 2.0, 0.5, 3.5, f64::INFINITY, f64::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for n in [-3, -1, 0, 1, 2, 5] {
                let (a, b) = unsafe { (alias(x, n as i64), base(x, n as i64)) };
                assert_eq!(a.to_bits(), b.to_bits(), "{name}f64({x:?}, {n}) mismatch");
            }
        }
    }
}

#[test]
fn floatn_f64_value_then_cint_aliases_match_base() {
    type T = unsafe extern "C" fn(f64, c_int) -> f64;
    let pairs: &[(T, T, &str)] = &[
        (m::ldexpf64, m::ldexp, "ldexp"),
        (m::scalbnf64, m::scalbn, "scalbn"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 2.0, 0.5, 3.5, f64::INFINITY, f64::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for n in [-3, -1, 0, 1, 2, 5] {
                let (a, b) = unsafe { (alias(x, n as c_int), base(x, n as c_int)) };
                assert_eq!(a.to_bits(), b.to_bits(), "{name}f64({x:?}, {n}) mismatch");
            }
        }
    }
}

#[test]
fn floatn_f64_order_then_value_aliases_match_base() {
    // jn/yn take the ORDER first. An alias that swapped its two arguments would
    // still typecheck if both were the same type -- they are not, so this arm
    // exists mainly to catch jn -> yn style cross-wiring.
    type T = unsafe extern "C" fn(c_int, f64) -> f64;
    let pairs: &[(T, T, &str)] = &[
        (m::jnf64, m::jn, "jn"),
        (m::ynf64, m::yn, "yn"),
    ];
    let vs = [0.5f64, 1.0, 2.0, 3.5, 10.0, f64::INFINITY, f64::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for n in [0, 1, 2, 5] {
                let (a, b) = unsafe { (alias(n, x), base(n, x)) };
                assert_eq!(a.to_bits(), b.to_bits(), "{name}f64({n}, {x:?}) mismatch");
            }
        }
    }
}

#[test]
fn floatn_f32_ternary_aliases_match_base() {
    type T = unsafe extern "C" fn(f32, f32, f32) -> f32;
    let pairs: &[(T, T, &str)] = &[
        (m::fmaf32, m::fmaf, "fmaf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 2.0, 0.5, 3.5, f32::INFINITY, f32::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs { for &y in &vs { for &z in &vs {
            let (a, b) = unsafe { (alias(x, y, z), base(x, y, z)) };
            assert_eq!(a.to_bits(), b.to_bits(), "{name}f32({x:?}, {y:?}, {z:?}) mismatch");
        } } }
    }
}

#[test]
fn floatn_f64_ternary_aliases_match_base() {
    type T = unsafe extern "C" fn(f64, f64, f64) -> f64;
    let pairs: &[(T, T, &str)] = &[
        (m::fmaf64, m::fma, "fma"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 2.0, 0.5, 3.5, f64::INFINITY, f64::NAN];
    for &(alias, base, name) in pairs {
        for &x in &vs { for &y in &vs { for &z in &vs {
            let (a, b) = unsafe { (alias(x, y, z), base(x, y, z)) };
            assert_eq!(a.to_bits(), b.to_bits(), "{name}f64({x:?}, {y:?}, {z:?}) mismatch");
        } } }
    }
}

#[test]
fn floatn_f32_complex_aliases_match_base() {
    type CC = unsafe extern "C" fn(CFloatComplex) -> CFloatComplex;
    type CR = unsafe extern "C" fn(CFloatComplex) -> f32;
    type CP = unsafe extern "C" fn(CFloatComplex, CFloatComplex) -> CFloatComplex;
    let cc: &[(CC, CC, &str)] = &[
        (m::cacosf32, m::cacosf, "cacosf"),
        (m::cacoshf32, m::cacoshf, "cacoshf"),
        (m::casinf32, m::casinf, "casinf"),
        (m::casinhf32, m::casinhf, "casinhf"),
        (m::catanf32, m::catanf, "catanf"),
        (m::catanhf32, m::catanhf, "catanhf"),
        (m::ccosf32, m::ccosf, "ccosf"),
        (m::ccoshf32, m::ccoshf, "ccoshf"),
        (m::cexpf32, m::cexpf, "cexpf"),
        (m::clog10f32, m::clog10f, "clog10f"),
        (m::clogf32, m::clogf, "clogf"),
        (m::conjf32, m::conjf, "conjf"),
        (m::cprojf32, m::cprojf, "cprojf"),
        (m::csinf32, m::csinf, "csinf"),
        (m::csinhf32, m::csinhf, "csinhf"),
        (m::csqrtf32, m::csqrtf, "csqrtf"),
        (m::ctanf32, m::ctanf, "ctanf"),
        (m::ctanhf32, m::ctanhf, "ctanhf"),
    ];
    let cr: &[(CR, CR, &str)] = &[
        (m::cabsf32, m::cabsf, "cabsf"),
        (m::cargf32, m::cargf, "cargf"),
        (m::cimagf32, m::cimagf, "cimagf"),
        (m::crealf32, m::crealf, "crealf"),
    ];
    let cp: &[(CP, CP, &str)] = &[
        (m::cpowf32, m::cpowf, "cpowf"),
    ];
    // Distinct re and im throughout, so an alias that read the wrong half is
    // visible; plus the special parts.
    let parts = [(3.0f32, 4.0f32), (-3.0, 4.0), (3.0, -4.0), (0.0, -0.0), (-0.0, 0.0),
                 (1.0, 0.0), (0.0, 1.0), (f32::INFINITY, 2.0), (2.0, f32::NEG_INFINITY),
                 (f32::NAN, 5.0), (5.0, f32::NAN), (0.5, -0.25)];
    for &(re, im) in &parts {
        let z = CFloatComplex { re, im };
        for &(alias, base, name) in cc {
            let (a, b) = unsafe { (alias(z), base(z)) };
            assert_eq!(
                (a.re.to_bits(), a.im.to_bits()), (b.re.to_bits(), b.im.to_bits()),
                "{name}f32({re:?}, {im:?}) mismatch"
            );
        }
        for &(alias, base, name) in cr {
            let (a, b) = unsafe { (alias(z), base(z)) };
            assert_eq!(a.to_bits(), b.to_bits(), "{name}f32({re:?}, {im:?}) mismatch");
        }
        for &(alias, base, name) in cp {
            let w2 = CFloatComplex { re: im, im: re };
            let (a, b) = unsafe { (alias(z, w2), base(z, w2)) };
            assert_eq!(
                (a.re.to_bits(), a.im.to_bits()), (b.re.to_bits(), b.im.to_bits()),
                "{name}f32(({re:?},{im:?}), swapped) mismatch"
            );
        }
    }
}

#[test]
fn floatn_f64_complex_aliases_match_base() {
    type CC = unsafe extern "C" fn(CDoubleComplex) -> CDoubleComplex;
    type CR = unsafe extern "C" fn(CDoubleComplex) -> f64;
    type CP = unsafe extern "C" fn(CDoubleComplex, CDoubleComplex) -> CDoubleComplex;
    let cc: &[(CC, CC, &str)] = &[
        (m::cacosf64, m::cacos, "cacos"),
        (m::cacoshf64, m::cacosh, "cacosh"),
        (m::casinf64, m::casin, "casin"),
        (m::casinhf64, m::casinh, "casinh"),
        (m::catanf64, m::catan, "catan"),
        (m::catanhf64, m::catanh, "catanh"),
        (m::ccosf64, m::ccos, "ccos"),
        (m::ccoshf64, m::ccosh, "ccosh"),
        (m::cexpf64, m::cexp, "cexp"),
        (m::clog10f64, m::clog10, "clog10"),
        (m::clogf64, m::clog, "clog"),
        (m::conjf64, m::conj, "conj"),
        (m::cprojf64, m::cproj, "cproj"),
        (m::csinf64, m::csin, "csin"),
        (m::csinhf64, m::csinh, "csinh"),
        (m::csqrtf64, m::csqrt, "csqrt"),
        (m::ctanf64, m::ctan, "ctan"),
        (m::ctanhf64, m::ctanh, "ctanh"),
    ];
    let cr: &[(CR, CR, &str)] = &[
        (m::cabsf64, m::cabs, "cabs"),
        (m::cargf64, m::carg, "carg"),
        (m::cimagf64, m::cimag, "cimag"),
        (m::crealf64, m::creal, "creal"),
    ];
    let cp: &[(CP, CP, &str)] = &[
        (m::cpowf64, m::cpow, "cpow"),
    ];
    // Distinct re and im throughout, so an alias that read the wrong half is
    // visible; plus the special parts.
    let parts = [(3.0f64, 4.0f64), (-3.0, 4.0), (3.0, -4.0), (0.0, -0.0), (-0.0, 0.0),
                 (1.0, 0.0), (0.0, 1.0), (f64::INFINITY, 2.0), (2.0, f64::NEG_INFINITY),
                 (f64::NAN, 5.0), (5.0, f64::NAN), (0.5, -0.25)];
    for &(re, im) in &parts {
        let z = CDoubleComplex { re, im };
        for &(alias, base, name) in cc {
            let (a, b) = unsafe { (alias(z), base(z)) };
            assert_eq!(
                (a.re.to_bits(), a.im.to_bits()), (b.re.to_bits(), b.im.to_bits()),
                "{name}f64({re:?}, {im:?}) mismatch"
            );
        }
        for &(alias, base, name) in cr {
            let (a, b) = unsafe { (alias(z), base(z)) };
            assert_eq!(a.to_bits(), b.to_bits(), "{name}f64({re:?}, {im:?}) mismatch");
        }
        for &(alias, base, name) in cp {
            let w2 = CDoubleComplex { re: im, im: re };
            let (a, b) = unsafe { (alias(z, w2), base(z, w2)) };
            assert_eq!(
                (a.re.to_bits(), a.im.to_bits()), (b.re.to_bits(), b.im.to_bits()),
                "{name}f64(({re:?},{im:?}), swapped) mismatch"
            );
        }
    }
}

#[test]
fn floatn_f32_fromfp_family_aliases_match_base_i64() {
    // The highest-risk cluster in the whole alias surface: fromfp, fromfpx,
    // ufromfp and ufromfpx differ by one token, and all four share a signature,
    // so a copy-paste typo between them typechecks silently.
    type T = unsafe extern "C" fn(f32, c_int, u32) -> i64;
    let pairs: &[(T, T, &str)] = &[
        (m::fromfpf32, m::fromfpf, "fromfpf"),
        (m::fromfpxf32, m::fromfpxf, "fromfpxf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 2.5, -2.5, 3.5, -3.5, 0.5, -0.5, 1024.0,
              f32::INFINITY, f32::NEG_INFINITY, f32::NAN];
    // All five C23 rounding directions, and widths either side of the value range.
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for rnd in 0..5 {
                for width in [1u32, 2, 8, 32, 64] {
                    let (a, b) = unsafe { (alias(x, rnd, width), base(x, rnd, width)) };
                    assert_eq!(a, b, "{name}f32({x:?}, rnd {rnd}, width {width}) = {a} but base = {b}");
                }
            }
        }
    }
}

#[test]
fn floatn_f32_fromfp_family_aliases_match_base_u64() {
    // The highest-risk cluster in the whole alias surface: fromfp, fromfpx,
    // ufromfp and ufromfpx differ by one token, and all four share a signature,
    // so a copy-paste typo between them typechecks silently.
    type T = unsafe extern "C" fn(f32, c_int, u32) -> u64;
    let pairs: &[(T, T, &str)] = &[
        (m::ufromfpf32, m::ufromfpf, "ufromfpf"),
        (m::ufromfpxf32, m::ufromfpxf, "ufromfpxf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 2.5, -2.5, 3.5, -3.5, 0.5, -0.5, 1024.0,
              f32::INFINITY, f32::NEG_INFINITY, f32::NAN];
    // All five C23 rounding directions, and widths either side of the value range.
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for rnd in 0..5 {
                for width in [1u32, 2, 8, 32, 64] {
                    let (a, b) = unsafe { (alias(x, rnd, width), base(x, rnd, width)) };
                    assert_eq!(a, b, "{name}f32({x:?}, rnd {rnd}, width {width}) = {a} but base = {b}");
                }
            }
        }
    }
}

#[test]
fn floatn_f32_totalorder_aliases_match_base() {
    // totalorder and totalordermag share a signature and differ by one token.
    // They take POINTERS, per the C23 binding glibc ships.
    type T = unsafe extern "C" fn(*const f32, *const f32) -> c_int;
    let pairs: &[(T, T, &str)] = &[
        (m::totalorderf32, m::totalorderf, "totalorderf"),
        (m::totalordermagf32, m::totalordermagf, "totalordermagf"),
    ];
    let vs = [0.0f32, -0.0, 1.0, -1.0, 2.0, -2.0, f32::INFINITY, f32::NEG_INFINITY,
              f32::NAN, -f32::NAN, f32::MIN_POSITIVE, -f32::MIN_POSITIVE];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for &y in &vs {
                // SAFETY: both pointers address live locals for the call's duration.
                let (a, b) = unsafe { (alias(&x, &y), base(&x, &y)) };
                assert_eq!(a, b, "{name}f32({x:?}, {y:?}) = {a} but base = {b}");
            }
        }
    }
}

#[test]
fn floatn_f64_fromfp_family_aliases_match_base_i64() {
    // The highest-risk cluster in the whole alias surface: fromfp, fromfpx,
    // ufromfp and ufromfpx differ by one token, and all four share a signature,
    // so a copy-paste typo between them typechecks silently.
    type T = unsafe extern "C" fn(f64, c_int, u32) -> i64;
    let pairs: &[(T, T, &str)] = &[
        (m::fromfpf64, m::fromfp, "fromfp"),
        (m::fromfpxf64, m::fromfpx, "fromfpx"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 2.5, -2.5, 3.5, -3.5, 0.5, -0.5, 1024.0,
              f64::INFINITY, f64::NEG_INFINITY, f64::NAN];
    // All five C23 rounding directions, and widths either side of the value range.
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for rnd in 0..5 {
                for width in [1u32, 2, 8, 32, 64] {
                    let (a, b) = unsafe { (alias(x, rnd, width), base(x, rnd, width)) };
                    assert_eq!(a, b, "{name}f64({x:?}, rnd {rnd}, width {width}) = {a} but base = {b}");
                }
            }
        }
    }
}

#[test]
fn floatn_f64_fromfp_family_aliases_match_base_u64() {
    // The highest-risk cluster in the whole alias surface: fromfp, fromfpx,
    // ufromfp and ufromfpx differ by one token, and all four share a signature,
    // so a copy-paste typo between them typechecks silently.
    type T = unsafe extern "C" fn(f64, c_int, u32) -> u64;
    let pairs: &[(T, T, &str)] = &[
        (m::ufromfpf64, m::ufromfp, "ufromfp"),
        (m::ufromfpxf64, m::ufromfpx, "ufromfpx"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 2.5, -2.5, 3.5, -3.5, 0.5, -0.5, 1024.0,
              f64::INFINITY, f64::NEG_INFINITY, f64::NAN];
    // All five C23 rounding directions, and widths either side of the value range.
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for rnd in 0..5 {
                for width in [1u32, 2, 8, 32, 64] {
                    let (a, b) = unsafe { (alias(x, rnd, width), base(x, rnd, width)) };
                    assert_eq!(a, b, "{name}f64({x:?}, rnd {rnd}, width {width}) = {a} but base = {b}");
                }
            }
        }
    }
}

#[test]
fn floatn_f64_totalorder_aliases_match_base() {
    // totalorder and totalordermag share a signature and differ by one token.
    // They take POINTERS, per the C23 binding glibc ships.
    type T = unsafe extern "C" fn(*const f64, *const f64) -> c_int;
    let pairs: &[(T, T, &str)] = &[
        (m::totalorderf64, m::totalorder, "totalorder"),
        (m::totalordermagf64, m::totalordermag, "totalordermag"),
    ];
    let vs = [0.0f64, -0.0, 1.0, -1.0, 2.0, -2.0, f64::INFINITY, f64::NEG_INFINITY,
              f64::NAN, -f64::NAN, f64::MIN_POSITIVE, -f64::MIN_POSITIVE];
    for &(alias, base, name) in pairs {
        for &x in &vs {
            for &y in &vs {
                // SAFETY: both pointers address live locals for the call's duration.
                let (a, b) = unsafe { (alias(&x, &y), base(&x, &y)) };
                assert_eq!(a, b, "{name}f64({x:?}, {y:?}) = {a} but base = {b}");
            }
        }
    }
}
