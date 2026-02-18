//! ABI layer for `<math.h>` functions.
//!
//! These entrypoints feed the runtime math kernel (`ApiFamily::MathFenv`)
//! so numeric exceptional regimes (NaN/Inf/denormal patterns) participate
//! in the same strict/hardened control loop as memory and concurrency paths.

use std::ffi::c_int;

use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { crate::errno_abi::__errno_location() };
    unsafe { *p = val };
}

#[inline]
fn deny_fallback(mode: SafetyLevel) -> f64 {
    if mode.heals_enabled() { 0.0 } else { f64::NAN }
}

#[inline]
fn heal_non_finite(x: f64) -> f64 {
    if x.is_nan() {
        0.0
    } else if x.is_infinite() {
        if x.is_sign_negative() {
            f64::MIN
        } else {
            f64::MAX
        }
    } else {
        x
    }
}

#[inline]
fn set_domain_errno() {
    // SAFETY: `__errno_location` returns writable thread-local errno storage.
    unsafe { set_abi_errno(libc::EDOM) };
}

#[inline]
fn set_range_errno() {
    // SAFETY: `__errno_location` returns writable thread-local errno storage.
    unsafe { set_abi_errno(libc::ERANGE) };
}

#[inline]
fn is_integral_f64(x: f64) -> bool {
    x.is_finite() && x.fract() == 0.0
}

#[inline]
fn unary_entry(x: f64, base_cost_ns: u64, f: fn(f64) -> f64) -> f64 {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        x.to_bits() as usize,
        std::mem::size_of::<f64>(),
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::MathFenv, decision.profile, base_cost_ns, true);
        return deny_fallback(mode);
    }

    let raw = f(x);
    let adverse = x.is_finite() && !raw.is_finite();
    let out = if adverse
        && mode.heals_enabled()
        && matches!(decision.action, MembraneAction::Repair(_))
    {
        heal_non_finite(raw)
    } else {
        raw
    };

    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(base_cost_ns, std::mem::size_of::<f64>()),
        adverse,
    );
    out
}

#[inline]
fn binary_entry(x: f64, y: f64, base_cost_ns: u64, f: fn(f64, f64) -> f64) -> f64 {
    let mixed =
        (x.to_bits() as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize) ^ y.to_bits() as usize;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f64>() * 2,
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::MathFenv, decision.profile, base_cost_ns, true);
        return deny_fallback(mode);
    }

    let raw = f(x, y);
    let adverse = x.is_finite() && y.is_finite() && !raw.is_finite();
    let out = if adverse
        && mode.heals_enabled()
        && matches!(decision.action, MembraneAction::Repair(_))
    {
        heal_non_finite(raw)
    } else {
        raw
    };

    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(base_cost_ns, std::mem::size_of::<f64>() * 2),
        adverse,
    );
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sin(x: f64) -> f64 {
    unary_entry(x, 5, frankenlibc_core::math::sin)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cos(x: f64) -> f64 {
    unary_entry(x, 5, frankenlibc_core::math::cos)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tan(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::tan)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asin(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::asin);
    if x.is_finite() && x.abs() > 1.0 {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acos(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::acos);
    if x.is_finite() && x.abs() > 1.0 {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan(x: f64) -> f64 {
    unary_entry(x, 5, frankenlibc_core::math::atan)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2(y: f64, x: f64) -> f64 {
    binary_entry(y, x, 6, frankenlibc_core::math::atan2)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinh(x: f64) -> f64 {
    let out = unary_entry(x, 7, frankenlibc_core::math::sinh);
    if x.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosh(x: f64) -> f64 {
    let out = unary_entry(x, 7, frankenlibc_core::math::cosh);
    if x.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanh(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::tanh)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinh(x: f64) -> f64 {
    unary_entry(x, 7, frankenlibc_core::math::asinh)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosh(x: f64) -> f64 {
    let out = unary_entry(x, 7, frankenlibc_core::math::acosh);
    if x.is_finite() && x < 1.0 {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanh(x: f64) -> f64 {
    let out = unary_entry(x, 7, frankenlibc_core::math::atanh);
    if x.is_finite() {
        if x.abs() > 1.0 {
            set_domain_errno();
        } else if x.abs() == 1.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::exp);
    if x.is_finite() && (out.is_infinite() || out == 0.0) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::exp2);
    if x.is_finite() && (out.is_infinite() || out == 0.0) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::expm1);
    if x.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::log);
    if x.is_finite() {
        if x < 0.0 {
            set_domain_errno();
        } else if x == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::log2);
    if x.is_finite() {
        if x < 0.0 {
            set_domain_errno();
        } else if x == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::log10);
    if x.is_finite() {
        if x < 0.0 {
            set_domain_errno();
        } else if x == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1p(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::log1p);
    if x.is_finite() {
        if x < -1.0 {
            set_domain_errno();
        } else if x == -1.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pow(x: f64, y: f64) -> f64 {
    let out = binary_entry(x, y, 8, frankenlibc_core::math::pow);
    if x.is_finite() && y.is_finite() {
        if x == 0.0 && y < 0.0 {
            set_range_errno();
        } else if x < 0.0 && !is_integral_f64(y) {
            set_domain_errno();
        } else if out.is_infinite() || (out == 0.0 && x != 0.0) {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrt(x: f64) -> f64 {
    let out = unary_entry(x, 6, frankenlibc_core::math::sqrt);
    if x.is_finite() && x < 0.0 {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrt(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::cbrt)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypot(x: f64, y: f64) -> f64 {
    let out = binary_entry(x, y, 7, frankenlibc_core::math::hypot);
    if x.is_finite() && y.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysign(x: f64, y: f64) -> f64 {
    binary_entry(x, y, 4, frankenlibc_core::math::copysign)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabs(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::fabs)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceil(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::ceil)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floor(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::floor)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn round(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::round)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn trunc(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::trunc)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rint(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::rint)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmod(x: f64, y: f64) -> f64 {
    let out = binary_entry(x, y, 6, frankenlibc_core::math::fmod);
    if y == 0.0 || (x.is_infinite() && y.is_finite()) {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainder(x: f64, y: f64) -> f64 {
    let out = binary_entry(x, y, 6, frankenlibc_core::math::remainder);
    if y == 0.0 || (x.is_infinite() && y.is_finite()) {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erf(x: f64) -> f64 {
    unary_entry(x, 9, frankenlibc_core::math::erf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgamma(x: f64) -> f64 {
    let out = unary_entry(x, 11, frankenlibc_core::math::tgamma);
    if x.is_finite() {
        if x < 0.0 && is_integral_f64(x) {
            set_domain_errno();
        } else if x == 0.0 || out.is_infinite() || out == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgamma(x: f64) -> f64 {
    let out = unary_entry(x, 10, frankenlibc_core::math::lgamma);
    if x.is_finite() && (x == 0.0 || (x < 0.0 && is_integral_f64(x)) || out.is_infinite()) {
        set_range_errno();
    }
    out
}

// ---------------------------------------------------------------------------
// Complementary error function
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfc(x: f64) -> f64 {
    unary_entry(x, 9, frankenlibc_core::math::erfc)
}

// ---------------------------------------------------------------------------
// Rounding / conversion
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyint(x: f64) -> f64 {
    unary_entry(x, 3, frankenlibc_core::math::nearbyint)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrint(x: f64) -> i64 {
    frankenlibc_core::math::lrint(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrint(x: f64) -> i64 {
    frankenlibc_core::math::llrint(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lround(x: f64) -> i64 {
    frankenlibc_core::math::lround(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llround(x: f64) -> i64 {
    frankenlibc_core::math::llround(x)
}

// ---------------------------------------------------------------------------
// Float decomposition
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexp(x: f64, exp: c_int) -> f64 {
    frankenlibc_core::math::ldexp(x, exp)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexp(x: f64, exp: *mut c_int) -> f64 {
    let (mantissa, e) = frankenlibc_core::math::frexp(x);
    if !exp.is_null() {
        unsafe { *exp = e };
    }
    mantissa
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modf(x: f64, iptr: *mut f64) -> f64 {
    let (frac, int_part) = frankenlibc_core::math::modf(x);
    if !iptr.is_null() {
        unsafe { *iptr = int_part };
    }
    frac
}

// ---------------------------------------------------------------------------
// Min / max / dim / fma
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmin(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::fmin(x, y)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmax(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::fmax(x, y)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdim(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::fdim(x, y)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    let mixed = (x.to_bits() as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize)
        ^ y.to_bits() as usize
        ^ z.to_bits() as usize;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f64>() * 3,
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::MathFenv, decision.profile, 5, true);
        return deny_fallback(mode);
    }

    let raw = frankenlibc_core::math::fma(x, y, z);
    let adverse = x.is_finite() && y.is_finite() && z.is_finite() && !raw.is_finite();
    let out = if adverse
        && mode.heals_enabled()
        && matches!(decision.action, MembraneAction::Repair(_))
    {
        heal_non_finite(raw)
    } else {
        raw
    };

    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(5, std::mem::size_of::<f64>() * 3),
        adverse,
    );
    out
}

// ---------------------------------------------------------------------------
// Scaling / exponent extraction
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbn(x: f64, n: c_int) -> f64 {
    frankenlibc_core::math::scalbn(x, n)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbln(x: f64, n: i64) -> f64 {
    frankenlibc_core::math::scalbln(x, n)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafter(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::nextafter(x, y)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogb(x: f64) -> c_int {
    frankenlibc_core::math::ilogb(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logb(x: f64) -> f64 {
    frankenlibc_core::math::logb(x)
}

// ===========================================================================
// Single-precision (f32) functions
// ===========================================================================

#[inline]
fn unary_entry_f32(x: f32, base_cost_ns: u64, f: fn(f32) -> f32) -> f32 {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        x.to_bits() as usize,
        std::mem::size_of::<f32>(),
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::MathFenv, decision.profile, base_cost_ns, true);
        return if mode.heals_enabled() { 0.0 } else { f32::NAN };
    }

    let raw = f(x);
    let adverse = x.is_finite() && !raw.is_finite();
    let out = if adverse
        && mode.heals_enabled()
        && matches!(decision.action, MembraneAction::Repair(_))
    {
        if raw.is_nan() {
            0.0
        } else if raw.is_sign_negative() {
            f32::MIN
        } else {
            f32::MAX
        }
    } else {
        raw
    };

    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(base_cost_ns, std::mem::size_of::<f32>()),
        adverse,
    );
    out
}

#[inline]
fn binary_entry_f32(x: f32, y: f32, base_cost_ns: u64, f: fn(f32, f32) -> f32) -> f32 {
    let mixed =
        (x.to_bits() as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize) ^ y.to_bits() as usize;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f32>() * 2,
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::MathFenv, decision.profile, base_cost_ns, true);
        return if mode.heals_enabled() { 0.0 } else { f32::NAN };
    }

    let raw = f(x, y);
    let adverse = x.is_finite() && y.is_finite() && !raw.is_finite();
    let out = if adverse
        && mode.heals_enabled()
        && matches!(decision.action, MembraneAction::Repair(_))
    {
        if raw.is_nan() {
            0.0
        } else if raw.is_sign_negative() {
            f32::MIN
        } else {
            f32::MAX
        }
    } else {
        raw
    };

    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(base_cost_ns, std::mem::size_of::<f32>() * 2),
        adverse,
    );
    out
}

// --- Trigonometric f32 ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf(x: f32) -> f32 {
    unary_entry_f32(x, 5, frankenlibc_core::math::sinf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf(x: f32) -> f32 {
    unary_entry_f32(x, 5, frankenlibc_core::math::cosf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf(x: f32) -> f32 {
    unary_entry_f32(x, 5, frankenlibc_core::math::tanf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 5, frankenlibc_core::math::asinf);
    if x.is_finite() && !(-1.0..=1.0).contains(&x) {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 5, frankenlibc_core::math::acosf);
    if x.is_finite() && !(-1.0..=1.0).contains(&x) {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf(x: f32) -> f32 {
    unary_entry_f32(x, 5, frankenlibc_core::math::atanf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f(y: f32, x: f32) -> f32 {
    binary_entry_f32(y, x, 6, frankenlibc_core::math::atan2f)
}

// --- Exponential / logarithmic f32 ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 6, frankenlibc_core::math::expf);
    if x.is_finite() && (out.is_infinite() || out == 0.0) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 6, frankenlibc_core::math::logf);
    if x.is_finite() {
        if x < 0.0 {
            set_domain_errno();
        } else if x == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 6, frankenlibc_core::math::log2f);
    if x.is_finite() {
        if x < 0.0 {
            set_domain_errno();
        } else if x == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 6, frankenlibc_core::math::log10f);
    if x.is_finite() {
        if x < 0.0 {
            set_domain_errno();
        } else if x == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf(x: f32, y: f32) -> f32 {
    let out = binary_entry_f32(x, y, 7, frankenlibc_core::math::powf);
    if x.is_finite() && y.is_finite() {
        if x < 0.0 && y.fract() != 0.0 {
            set_domain_errno();
        } else if out.is_infinite()
            || (x == 0.0 && y < 0.0)
            || (out == 0.0 && y > 0.0 && x != 0.0)
        {
            set_range_errno();
        }
    }
    out
}

// --- Float utilities f32 ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 3, frankenlibc_core::math::sqrtf);
    if x.is_finite() && x < 0.0 {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf(x: f32) -> f32 {
    unary_entry_f32(x, 2, frankenlibc_core::math::fabsf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::ceilf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::floorf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::roundf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::truncf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    let out = binary_entry_f32(x, y, 6, frankenlibc_core::math::fmodf);
    if y == 0.0 || (x.is_infinite() && y.is_finite()) {
        set_domain_errno();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi_errno() -> i32 {
        // SAFETY: `__errno_location` returns valid thread-local storage for this thread.
        unsafe { *crate::errno_abi::__errno_location() }
    }

    fn set_errno_for_test(val: i32) {
        // SAFETY: test helper writes this thread's errno slot directly.
        unsafe { *crate::errno_abi::__errno_location() = val };
    }

    #[test]
    fn heal_non_finite_sanity() {
        assert_eq!(heal_non_finite(f64::NAN), 0.0);
        assert_eq!(heal_non_finite(f64::INFINITY), f64::MAX);
        assert_eq!(heal_non_finite(f64::NEG_INFINITY), f64::MIN);
        assert_eq!(heal_non_finite(3.0), 3.0);
    }

    #[test]
    fn asin_domain_sets_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { asin(2.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn acosh_less_than_one_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { acosh(0.5) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn atanh_out_of_domain_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { atanh(2.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn atanh_unity_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { atanh(1.0) };
        assert!(out.is_infinite() && out.is_sign_positive());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn sinh_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { sinh(1000.0) };
        assert!(out.is_infinite() && out.is_sign_positive());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn cosh_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { cosh(1000.0) };
        assert!(out.is_infinite() && out.is_sign_positive());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn tanh_finite_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { tanh(2.0) };
        assert!(out.is_finite());
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn asinh_finite_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { asinh(-2.0) };
        assert!(out.is_finite());
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn log_negative_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { log(-1.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn log_zero_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { log(0.0) };
        assert!(out.is_infinite() && out.is_sign_negative());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn log2_negative_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { log2(-1.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn log2_zero_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { log2(0.0) };
        assert!(out.is_infinite() && out.is_sign_negative());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn log1p_less_than_negative_one_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { log1p(-2.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn log1p_negative_one_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { log1p(-1.0) };
        assert!(out.is_infinite() && out.is_sign_negative());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn exp_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { exp(1000.0) };
        assert!(out.is_infinite() && out.is_sign_positive());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn exp_underflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { exp(-1000.0) };
        assert_eq!(out, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn exp2_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { exp2(1024.0) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn exp2_underflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { exp2(-1075.0) };
        assert_eq!(out, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn expm1_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { expm1(1000.0) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn expm1_regular_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { expm1(-1.0e-10) };
        assert!(out.is_finite());
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn fmod_divide_by_zero_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { fmod(1.0, 0.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn fmod_infinite_dividend_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { fmod(f64::INFINITY, 2.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn pow_negative_fractional_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { pow(-2.0, 0.5) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn pow_zero_negative_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { pow(0.0, -1.0) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn pow_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { pow(1.0e308, 2.0) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn pow_underflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { pow(1.0e-308, 2.0) };
        assert_eq!(out, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn sqrt_negative_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { sqrt(-1.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn sqrt_negative_zero_preserves_sign_and_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { sqrt(-0.0) };
        assert_eq!(out, -0.0);
        assert!(out.is_sign_negative());
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn cbrt_negative_value_no_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { cbrt(-8.0) };
        assert_eq!(out, -2.0);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn copysign_applies_sign_and_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { copysign(3.0, -0.0) };
        assert_eq!(out, -3.0);
        assert!(out.is_sign_negative());
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn trunc_finite_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { trunc(-2.9) };
        assert_eq!(out, -2.0);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn rint_finite_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { rint(2.0) };
        assert_eq!(out, 2.0);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn remainder_divide_by_zero_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { remainder(1.0, 0.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn remainder_infinite_dividend_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { remainder(f64::INFINITY, 2.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn hypot_finite_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { hypot(1.6e308, 1.6e308) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn tgamma_zero_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { tgamma(0.0) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn tgamma_negative_integer_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { tgamma(-1.0) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn lgamma_zero_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { lgamma(0.0) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn lgamma_negative_integer_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { lgamma(-1.0) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }
}
