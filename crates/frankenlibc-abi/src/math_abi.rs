//! ABI layer for `<math.h>` functions.
//!
//! These entrypoints feed the runtime math kernel (`ApiFamily::MathFenv`)
//! so numeric exceptional regimes (NaN/Inf/denormal patterns) participate
//! in the same strict/hardened control loop as memory and concurrency paths.

use std::ffi::c_int;
use std::os::raw::c_long;

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
fn scaling_range_error_f64(x: f64, out: f64) -> bool {
    x.is_finite() && x != 0.0 && (out.is_infinite() || out == 0.0)
}

#[inline]
fn scaling_range_error_f32(x: f32, out: f32) -> bool {
    x.is_finite() && x != 0.0 && (out.is_infinite() || out == 0.0)
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

/// Reentrant lgamma: returns lgamma(x) and writes sign to `*signgamp`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgamma_r(x: f64, signgamp: *mut c_int) -> f64 {
    let (val, sign) = frankenlibc_core::math::lgamma_r(x);
    if !signgamp.is_null() {
        // SAFETY: caller guarantees `signgamp` points to valid writable `int`.
        unsafe { *signgamp = sign };
    }
    if x.is_finite() && (x == 0.0 || (x < 0.0 && is_integral_f64(x)) || val.is_infinite()) {
        set_range_errno();
    }
    val
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
    let out = frankenlibc_core::math::ldexp(x, exp);
    if scaling_range_error_f64(x, out) {
        set_range_errno();
    }
    out
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
    let out = frankenlibc_core::math::scalbn(x, n);
    if scaling_range_error_f64(x, out) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbln(x: f64, n: i64) -> f64 {
    let out = frankenlibc_core::math::scalbln(x, n);
    if scaling_range_error_f64(x, out) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafter(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::nextafter(x, y)
}

/// C99 `nexttoward`: next representable f64 toward a long-double direction.
/// On x86_64 the `long double` parameter arrives as f64 in our LD_PRELOAD ABI.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nexttoward(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::nexttoward(x, y)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogb(x: f64) -> c_int {
    frankenlibc_core::math::ilogb(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logb(x: f64) -> f64 {
    frankenlibc_core::math::logb(x)
}

// ---------------------------------------------------------------------------
// remquo — remainder with quotient
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquo(x: f64, y: f64, quo: *mut c_int) -> f64 {
    let (rem, q) = frankenlibc_core::math::remquo(x, y);
    if !quo.is_null() {
        // SAFETY: caller guarantees `quo` points to valid writable `int`.
        unsafe { *quo = q };
    }
    if y == 0.0 || (x.is_infinite() && y.is_finite()) {
        set_domain_errno();
    }
    rem
}

// ---------------------------------------------------------------------------
// sincos — simultaneous sin + cos
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincos(x: f64, sin_out: *mut f64, cos_out: *mut f64) {
    let (s, c) = frankenlibc_core::math::sincos(x);
    if !sin_out.is_null() {
        // SAFETY: caller guarantees `sin_out` points to valid writable `double`.
        unsafe { *sin_out = s };
    }
    if !cos_out.is_null() {
        // SAFETY: caller guarantees `cos_out` points to valid writable `double`.
        unsafe { *cos_out = c };
    }
}

// ---------------------------------------------------------------------------
// nan — generate quiet NaN
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nan(_tagp: *const std::ffi::c_char) -> f64 {
    f64::NAN
}

// ---------------------------------------------------------------------------
// Bessel functions
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0(x: f64) -> f64 {
    unary_entry(x, 12, frankenlibc_core::math::j0)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1(x: f64) -> f64 {
    unary_entry(x, 12, frankenlibc_core::math::j1)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jn(n: c_int, x: f64) -> f64 {
    let mixed = (n as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize) ^ x.to_bits() as usize;
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f64>(),
        false,
        false,
        0,
    );
    let raw = frankenlibc_core::math::jn(n, x);
    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(15, std::mem::size_of::<f64>()),
        false,
    );
    raw
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0(x: f64) -> f64 {
    let out = unary_entry(x, 12, frankenlibc_core::math::y0);
    // y0(x) for x <= 0 is domain error
    if x <= 0.0 && x.is_finite() {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1(x: f64) -> f64 {
    let out = unary_entry(x, 12, frankenlibc_core::math::y1);
    if x <= 0.0 && x.is_finite() {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yn(n: c_int, x: f64) -> f64 {
    let mixed = (n as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize) ^ x.to_bits() as usize;
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f64>(),
        false,
        false,
        0,
    );
    let raw = frankenlibc_core::math::yn(n, x);
    if x <= 0.0 && x.is_finite() {
        set_domain_errno();
    }
    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(15, std::mem::size_of::<f64>()),
        false,
    );
    raw
}

// ---------------------------------------------------------------------------
// BSD/GNU compatibility functions
// ---------------------------------------------------------------------------

/// BSD `finite()` — returns non-zero if x is finite.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn finite(x: f64) -> c_int {
    frankenlibc_core::math::finite(x) as c_int
}

/// BSD `drem()` — alias for `remainder()`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn drem(x: f64, y: f64) -> f64 {
    let out = binary_entry(x, y, 6, frankenlibc_core::math::drem);
    if y == 0.0 || (x.is_infinite() && y.is_finite()) {
        set_domain_errno();
    }
    out
}

/// BSD `gamma()` — alias for `lgamma()`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gamma(x: f64) -> f64 {
    let out = unary_entry(x, 10, frankenlibc_core::math::gamma);
    if x.is_finite() && (x == 0.0 || (x < 0.0 && is_integral_f64(x)) || out.is_infinite()) {
        set_range_errno();
    }
    out
}

/// Extract significand scaled to [1, 2).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn significand(x: f64) -> f64 {
    frankenlibc_core::math::significand(x)
}

/// GNU `exp10()` — base-10 exponential.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10(x: f64) -> f64 {
    let out = unary_entry(x, 7, frankenlibc_core::math::exp10);
    if x.is_finite() && (out.is_infinite() || out == 0.0) {
        set_range_errno();
    }
    out
}

/// `pow10` is a GNU extension alias for `exp10`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pow10(x: f64) -> f64 {
    unsafe { exp10(x) }
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
        } else if out.is_infinite() || (x == 0.0 && y < 0.0) || (out == 0.0 && y > 0.0 && x != 0.0)
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

// --- Hyperbolic f32 ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 5, frankenlibc_core::math::sinhf);
    if x.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 5, frankenlibc_core::math::coshf);
    if x.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf(x: f32) -> f32 {
    unary_entry_f32(x, 5, frankenlibc_core::math::tanhf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf(x: f32) -> f32 {
    unary_entry_f32(x, 5, frankenlibc_core::math::asinhf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 5, frankenlibc_core::math::acoshf);
    if x.is_finite() && x < 1.0 {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 5, frankenlibc_core::math::atanhf);
    if x.is_finite() {
        if !(-1.0..=1.0).contains(&x) {
            set_domain_errno();
        } else if x == 1.0 || x == -1.0 {
            set_range_errno();
        }
    }
    out
}

// --- Exponential / logarithmic f32 (extended) ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 6, frankenlibc_core::math::exp2f);
    if x.is_finite() && (out.is_infinite() || out == 0.0) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 6, frankenlibc_core::math::expm1f);
    if x.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 6, frankenlibc_core::math::log1pf);
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
pub unsafe extern "C" fn logbf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 4, frankenlibc_core::math::logbf);
    if x == 0.0 {
        set_range_errno();
    }
    out
}

// --- Special functions f32 ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff(x: f32) -> f32 {
    unary_entry_f32(x, 8, frankenlibc_core::math::erff)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf(x: f32) -> f32 {
    unary_entry_f32(x, 8, frankenlibc_core::math::erfcf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 10, frankenlibc_core::math::tgammaf);
    if x.is_finite() {
        if x <= 0.0 && x == x.floor() {
            set_domain_errno();
        } else if out.is_infinite() || out == 0.0 {
            set_range_errno();
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 10, frankenlibc_core::math::lgammaf);
    if x.is_finite() && ((x <= 0.0 && x == x.floor()) || out.is_infinite()) {
        set_range_errno();
    }
    out
}

/// Reentrant lgammaf: returns lgammaf(x) and writes sign to `*signgamp`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf_r(x: f32, signgamp: *mut c_int) -> f32 {
    let (val, sign) = frankenlibc_core::math::lgammaf_r(x);
    if !signgamp.is_null() {
        // SAFETY: caller guarantees `signgamp` points to valid writable `int`.
        unsafe { *signgamp = sign };
    }
    if x.is_finite() {
        if x <= 0.0 && x == x.floor() {
            set_domain_errno();
        } else if val.is_infinite() {
            set_range_errno();
        }
    }
    val
}

// --- Float utilities f32 (extended) ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf(x: f32) -> f32 {
    unary_entry_f32(x, 4, frankenlibc_core::math::cbrtf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf(x: f32, y: f32) -> f32 {
    let out = binary_entry_f32(x, y, 5, frankenlibc_core::math::hypotf);
    if x.is_finite() && y.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf(x: f32, y: f32) -> f32 {
    binary_entry_f32(x, y, 2, frankenlibc_core::math::copysignf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf(x: f32, y: f32) -> f32 {
    binary_entry_f32(x, y, 3, frankenlibc_core::math::fdimf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf(x: f32, y: f32) -> f32 {
    binary_entry_f32(x, y, 2, frankenlibc_core::math::fmaxf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf(x: f32, y: f32) -> f32 {
    binary_entry_f32(x, y, 2, frankenlibc_core::math::fminf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    // fma is ternary — use the binary path with manual third arg folding.
    let mixed = (x.to_bits() as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize)
        ^ y.to_bits() as usize
        ^ z.to_bits() as usize;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f32>() * 3,
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::MathFenv, decision.profile, 5, true);
        return if mode.heals_enabled() { 0.0 } else { f32::NAN };
    }

    let raw = frankenlibc_core::math::fmaf(x, y, z);
    let adverse = x.is_finite() && y.is_finite() && z.is_finite() && !raw.is_finite();
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
        runtime_policy::scaled_cost(5, std::mem::size_of::<f32>() * 3),
        adverse,
    );
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf(x: f32, y: f32) -> f32 {
    let out = binary_entry_f32(x, y, 5, frankenlibc_core::math::remainderf);
    if y == 0.0 || (x.is_infinite() && y.is_finite()) {
        set_domain_errno();
    }
    out
}

// --- Rounding / integer conversion f32 ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::rintf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::nearbyintf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf(x: f32) -> c_long {
    frankenlibc_core::math::lrintf(x) as c_long
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf(x: f32) -> i64 {
    frankenlibc_core::math::llrintf(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf(x: f32) -> c_long {
    frankenlibc_core::math::lroundf(x) as c_long
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf(x: f32) -> i64 {
    frankenlibc_core::math::llroundf(x)
}

// --- Float decomposition f32 ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf(x: f32, exp: *mut c_int) -> f32 {
    let (mantissa, e) = frankenlibc_core::math::frexpf(x);
    if !exp.is_null() {
        unsafe { *exp = e };
    }
    mantissa
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf(x: f32, exp: c_int) -> f32 {
    let out = frankenlibc_core::math::ldexpf(x, exp);
    if scaling_range_error_f32(x, out) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff(x: f32, iptr: *mut f32) -> f32 {
    let (frac, int_part) = frankenlibc_core::math::modff(x);
    if !iptr.is_null() {
        unsafe { *iptr = int_part };
    }
    frac
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf(x: f32) -> c_int {
    frankenlibc_core::math::ilogbf(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf(x: f32, n: c_int) -> f32 {
    let out = frankenlibc_core::math::scalbnf(x, n);
    if scaling_range_error_f32(x, out) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf(x: f32, n: c_long) -> f32 {
    let out = frankenlibc_core::math::scalblnf(x, n);
    if scaling_range_error_f32(x, out) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf(x: f32, y: f32) -> f32 {
    binary_entry_f32(x, y, 3, frankenlibc_core::math::nextafterf)
}

/// C99 `nexttowardf`: next representable f32 toward a long-double direction.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nexttowardf(x: f32, y: f64) -> f32 {
    frankenlibc_core::math::nexttowardf(x, y)
}

// ---------------------------------------------------------------------------
// New f32 batch: remquof, sincosf, nanf, exp10f, Bessel f32
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof(x: f32, y: f32, quo: *mut c_int) -> f32 {
    let (rem, q) = frankenlibc_core::math::remquof(x, y);
    if !quo.is_null() {
        // SAFETY: caller guarantees `quo` points to valid writable `int`.
        unsafe { *quo = q };
    }
    if y == 0.0 || (x.is_infinite() && y.is_finite()) {
        set_domain_errno();
    }
    rem
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf(x: f32, sin_out: *mut f32, cos_out: *mut f32) {
    let (s, c) = frankenlibc_core::math::sincosf(x);
    if !sin_out.is_null() {
        // SAFETY: caller guarantees `sin_out` points to valid writable `float`.
        unsafe { *sin_out = s };
    }
    if !cos_out.is_null() {
        // SAFETY: caller guarantees `cos_out` points to valid writable `float`.
        unsafe { *cos_out = c };
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf(_tagp: *const std::ffi::c_char) -> f32 {
    f32::NAN
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 7, frankenlibc_core::math::exp10f);
    if x.is_finite() && (out.is_infinite() || out == 0.0) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f(x: f32) -> f32 {
    unary_entry_f32(x, 12, frankenlibc_core::math::j0f)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f(x: f32) -> f32 {
    unary_entry_f32(x, 12, frankenlibc_core::math::j1f)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf(n: c_int, x: f32) -> f32 {
    let mixed = (n as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize) ^ x.to_bits() as usize;
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f32>(),
        false,
        false,
        0,
    );
    let raw = frankenlibc_core::math::jnf(n, x);
    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(15, std::mem::size_of::<f32>()),
        false,
    );
    raw
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 12, frankenlibc_core::math::y0f);
    if x <= 0.0 && x.is_finite() {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 12, frankenlibc_core::math::y1f);
    if x <= 0.0 && x.is_finite() {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf(n: c_int, x: f32) -> f32 {
    let mixed = (n as usize).wrapping_mul(0x9e37_79b9_7f4a_7c15usize) ^ x.to_bits() as usize;
    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::MathFenv,
        mixed,
        std::mem::size_of::<f32>(),
        false,
        false,
        0,
    );
    let raw = frankenlibc_core::math::ynf(n, x);
    if x <= 0.0 && x.is_finite() {
        set_domain_errno();
    }
    runtime_policy::observe(
        ApiFamily::MathFenv,
        decision.profile,
        runtime_policy::scaled_cost(15, std::mem::size_of::<f32>()),
        false,
    );
    raw
}

// ---------------------------------------------------------------------------
// BSD/compat f32 variants: finitef, dremf, gammaf, significandf
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn finitef(x: f32) -> c_int {
    frankenlibc_core::math::finitef(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dremf(x: f32, y: f32) -> f32 {
    binary_entry_f32(x, y, 4, frankenlibc_core::math::dremf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gammaf(x: f32) -> f32 {
    let out = unary_entry_f32(x, 8, frankenlibc_core::math::gammaf);
    // lgamma poles at non-positive integers
    if x.is_finite() && x <= 0.0 && x.fract() == 0.0 {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn significandf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::significandf)
}

/// `pow10f` is a GNU extension alias for `exp10f`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pow10f(x: f32) -> f32 {
    unsafe { exp10f(x) }
}

// ---------------------------------------------------------------------------
// glibc internal classification functions (__fpclassify, __signbit, etc.)
// These are used by glibc's <math.h> macro infrastructure.
// ---------------------------------------------------------------------------

/// glibc `__fpclassify`: classify f64 (FP_NAN=0, FP_INFINITE=1, FP_ZERO=2, FP_SUBNORMAL=3, FP_NORMAL=4).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fpclassify(x: f64) -> c_int {
    frankenlibc_core::math::fpclassify(x)
}

/// glibc `__fpclassifyf`: classify f32.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fpclassifyf(x: f32) -> c_int {
    frankenlibc_core::math::fpclassifyf(x)
}

/// glibc `__signbit`: return non-zero if sign bit set (f64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __signbit(x: f64) -> c_int {
    frankenlibc_core::math::signbit(x)
}

/// glibc `__signbitf`: return non-zero if sign bit set (f32).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __signbitf(x: f32) -> c_int {
    frankenlibc_core::math::signbitf(x)
}

/// glibc `__isinf`: +1 for +Inf, -1 for -Inf, 0 otherwise (f64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isinf(x: f64) -> c_int {
    frankenlibc_core::math::isinf(x)
}

/// glibc `__isinff`: +1 for +Inf, -1 for -Inf, 0 otherwise (f32).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isinff(x: f32) -> c_int {
    frankenlibc_core::math::isinff(x)
}

/// glibc `__isnan`: non-zero if NaN (f64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isnan(x: f64) -> c_int {
    frankenlibc_core::math::isnan(x)
}

/// glibc `__isnanf`: non-zero if NaN (f32).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isnanf(x: f32) -> c_int {
    frankenlibc_core::math::isnanf(x)
}

/// glibc `__finite`: non-zero if neither infinite nor NaN (f64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __finite(x: f64) -> c_int {
    frankenlibc_core::math::finite(x)
}

/// glibc `__finitef`: non-zero if neither infinite nor NaN (f32).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __finitef(x: f32) -> c_int {
    frankenlibc_core::math::finitef(x)
}

// =========================================================================
// C99 <complex.h> functions
// =========================================================================
//
// The C ABI represents `double complex` as `{ double, double }` and
// `float complex` as `{ float, float }`.  On x86-64, complex return values
// are passed in SSE registers (xmm0 for real, xmm1 for imaginary).
//
// We use `#[repr(C)]` structs that match the glibc ABI exactly.

/// ABI-compatible `double complex`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CDoubleComplex {
    pub re: f64,
    pub im: f64,
}

/// ABI-compatible `float complex`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CFloatComplex {
    pub re: f32,
    pub im: f32,
}

/// ABI-compatible `long double complex` (approximated as f64 on x86-64 with
/// Rust, since Rust lacks native f128/f80 support).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CLongDoubleComplex {
    pub re: f64,
    pub im: f64,
}

// --- Internal complex arithmetic helpers ---

#[inline]
fn c_mul(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

#[inline]
fn c_div(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    let denom = b.0 * b.0 + b.1 * b.1;
    if denom == 0.0 {
        (f64::NAN, f64::NAN)
    } else {
        ((a.0 * b.0 + a.1 * b.1) / denom, (a.1 * b.0 - a.0 * b.1) / denom)
    }
}

#[inline]
fn c_exp(re: f64, im: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    let r = math::exp(re);
    (r * math::cos(im), r * math::sin(im))
}

#[inline]
fn c_log(re: f64, im: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    (math::log(math::hypot(re, im)), math::atan2(im, re))
}

#[inline]
fn c_sqrt(re: f64, im: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    if re == 0.0 && im == 0.0 {
        return (0.0, 0.0);
    }
    let r = math::hypot(re, im);
    let t = math::sqrt((r + math::fabs(re)) / 2.0);
    if re >= 0.0 {
        (t, im / (2.0 * t))
    } else if im >= 0.0 {
        (math::fabs(im) / (2.0 * t), t)
    } else {
        (math::fabs(im) / (2.0 * t), -t)
    }
}

// --- creal / cimag / conj / carg / cabs ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn creal(z: CDoubleComplex) -> f64 {
    z.re
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf(z: CFloatComplex) -> f32 {
    z.re
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn creall(z: CLongDoubleComplex) -> f64 {
    z.re
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimag(z: CDoubleComplex) -> f64 {
    z.im
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf(z: CFloatComplex) -> f32 {
    z.im
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagl(z: CLongDoubleComplex) -> f64 {
    z.im
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conj(z: CDoubleComplex) -> CDoubleComplex {
    CDoubleComplex { re: z.re, im: -z.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf(z: CFloatComplex) -> CFloatComplex {
    CFloatComplex { re: z.re, im: -z.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    CLongDoubleComplex { re: z.re, im: -z.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn carg(z: CDoubleComplex) -> f64 {
    frankenlibc_core::math::atan2(z.im, z.re)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf(z: CFloatComplex) -> f32 {
    frankenlibc_core::math::atan2f(z.im, z.re)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargl(z: CLongDoubleComplex) -> f64 {
    frankenlibc_core::math::atan2(z.im, z.re)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabs(z: CDoubleComplex) -> f64 {
    frankenlibc_core::math::hypot(z.re, z.im)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf(z: CFloatComplex) -> f32 {
    frankenlibc_core::math::hypotf(z.re, z.im)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsl(z: CLongDoubleComplex) -> f64 {
    frankenlibc_core::math::hypot(z.re, z.im)
}

// --- cproj (projection onto Riemann sphere) ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cproj(z: CDoubleComplex) -> CDoubleComplex {
    if z.re.is_infinite() || z.im.is_infinite() {
        CDoubleComplex { re: f64::INFINITY, im: f64::copysign(0.0, z.im) }
    } else {
        z
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf(z: CFloatComplex) -> CFloatComplex {
    if z.re.is_infinite() || z.im.is_infinite() {
        CFloatComplex { re: f32::INFINITY, im: f32::copysign(0.0, z.im) }
    } else {
        z
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    if z.re.is_infinite() || z.im.is_infinite() {
        CLongDoubleComplex { re: f64::INFINITY, im: f64::copysign(0.0, z.im) }
    } else {
        z
    }
}

// --- cexp / clog / csqrt ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexp(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_exp(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf(z: CFloatComplex) -> CFloatComplex {
    let (re, im) = c_exp(z.re as f64, z.im as f64);
    CFloatComplex { re: re as f32, im: im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let (re, im) = c_exp(z.re, z.im);
    CLongDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_log(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf(z: CFloatComplex) -> CFloatComplex {
    let (re, im) = c_log(z.re as f64, z.im as f64);
    CFloatComplex { re: re as f32, im: im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let (re, im) = c_log(z.re, z.im);
    CLongDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrt(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_sqrt(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf(z: CFloatComplex) -> CFloatComplex {
    let (re, im) = c_sqrt(z.re as f64, z.im as f64);
    CFloatComplex { re: re as f32, im: im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let (re, im) = c_sqrt(z.re, z.im);
    CLongDoubleComplex { re, im }
}

// --- cpow ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpow(base: CDoubleComplex, exp: CDoubleComplex) -> CDoubleComplex {
    // z^w = exp(w * log(z))
    let lz = c_log(base.re, base.im);
    let wl = c_mul((exp.re, exp.im), lz);
    let (re, im) = c_exp(wl.0, wl.1);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf(base: CFloatComplex, exp: CFloatComplex) -> CFloatComplex {
    let lz = c_log(base.re as f64, base.im as f64);
    let wl = c_mul((exp.re as f64, exp.im as f64), lz);
    let (re, im) = c_exp(wl.0, wl.1);
    CFloatComplex { re: re as f32, im: im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowl(base: CLongDoubleComplex, exp: CLongDoubleComplex) -> CLongDoubleComplex {
    let lz = c_log(base.re, base.im);
    let wl = c_mul((exp.re, exp.im), lz);
    let (re, im) = c_exp(wl.0, wl.1);
    CLongDoubleComplex { re, im }
}

// --- Trigonometric: csin, ccos, ctan ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csin(z: CDoubleComplex) -> CDoubleComplex {
    // sin(a+bi) = sin(a)cosh(b) + i*cos(a)sinh(b)
    CDoubleComplex {
        re: frankenlibc_core::math::sin(z.re) * frankenlibc_core::math::cosh(z.im),
        im: frankenlibc_core::math::cos(z.re) * frankenlibc_core::math::sinh(z.im),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { csin(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { csin(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccos(z: CDoubleComplex) -> CDoubleComplex {
    // cos(a+bi) = cos(a)cosh(b) - i*sin(a)sinh(b)
    CDoubleComplex {
        re: frankenlibc_core::math::cos(z.re) * frankenlibc_core::math::cosh(z.im),
        im: -frankenlibc_core::math::sin(z.re) * frankenlibc_core::math::sinh(z.im),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { ccos(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ccos(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctan(z: CDoubleComplex) -> CDoubleComplex {
    // tan(z) = sin(z) / cos(z)
    let s = unsafe { csin(z) };
    let c = unsafe { ccos(z) };
    let (re, im) = c_div((s.re, s.im), (c.re, c.im));
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { ctan(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ctan(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

// --- Hyperbolic: csinh, ccosh, ctanh ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinh(z: CDoubleComplex) -> CDoubleComplex {
    // sinh(a+bi) = sinh(a)cos(b) + i*cosh(a)sin(b)
    CDoubleComplex {
        re: frankenlibc_core::math::sinh(z.re) * frankenlibc_core::math::cos(z.im),
        im: frankenlibc_core::math::cosh(z.re) * frankenlibc_core::math::sin(z.im),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { csinh(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { csinh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosh(z: CDoubleComplex) -> CDoubleComplex {
    // cosh(a+bi) = cosh(a)cos(b) + i*sinh(a)sin(b)
    CDoubleComplex {
        re: frankenlibc_core::math::cosh(z.re) * frankenlibc_core::math::cos(z.im),
        im: frankenlibc_core::math::sinh(z.re) * frankenlibc_core::math::sin(z.im),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { ccosh(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ccosh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanh(z: CDoubleComplex) -> CDoubleComplex {
    // tanh(z) = sinh(z) / cosh(z)
    let s = unsafe { csinh(z) };
    let c = unsafe { ccosh(z) };
    let (re, im) = c_div((s.re, s.im), (c.re, c.im));
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { ctanh(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ctanh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

// --- Inverse trig: casin, cacos, catan ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casin(z: CDoubleComplex) -> CDoubleComplex {
    // asin(z) = -i * log(iz + sqrt(1 - z^2))
    let z2 = c_mul((z.re, z.im), (z.re, z.im));
    let one_minus_z2 = (1.0 - z2.0, -z2.1);
    let sq = c_sqrt(one_minus_z2.0, one_minus_z2.1);
    let iz = (-z.im, z.re); // i*z
    let arg = (iz.0 + sq.0, iz.1 + sq.1);
    let lg = c_log(arg.0, arg.1);
    // -i * lg = (lg.1, -lg.0)
    CDoubleComplex { re: lg.1, im: -lg.0 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { casin(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { casin(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacos(z: CDoubleComplex) -> CDoubleComplex {
    // acos(z) = pi/2 - asin(z)
    let as_ = unsafe { casin(z) };
    CDoubleComplex {
        re: std::f64::consts::FRAC_PI_2 - as_.re,
        im: -as_.im,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { cacos(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { cacos(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catan(z: CDoubleComplex) -> CDoubleComplex {
    // atan(z) = (i/2) * log((1-iz)/(1+iz))
    // where iz = (-im, re)
    let iz = (-z.im, z.re);
    let num = (1.0 - iz.0, -iz.1);       // 1 - iz
    let den = (1.0 + iz.0, iz.1);         // 1 + iz
    let ratio = c_div(num, den);
    let lg = c_log(ratio.0, ratio.1);
    // (i/2) * lg = (-lg.1/2, lg.0/2)
    CDoubleComplex { re: -lg.1 / 2.0, im: lg.0 / 2.0 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { catan(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { catan(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

// --- Inverse hyperbolic: casinh, cacosh, catanh ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinh(z: CDoubleComplex) -> CDoubleComplex {
    // asinh(z) = log(z + sqrt(z^2 + 1))
    let z2 = c_mul((z.re, z.im), (z.re, z.im));
    let z2p1 = (z2.0 + 1.0, z2.1);
    let sq = c_sqrt(z2p1.0, z2p1.1);
    let arg = (z.re + sq.0, z.im + sq.1);
    let (re, im) = c_log(arg.0, arg.1);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { casinh(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { casinh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosh(z: CDoubleComplex) -> CDoubleComplex {
    // acosh(z) = log(z + sqrt(z^2 - 1))
    let z2 = c_mul((z.re, z.im), (z.re, z.im));
    let z2m1 = (z2.0 - 1.0, z2.1);
    let sq = c_sqrt(z2m1.0, z2m1.1);
    let arg = (z.re + sq.0, z.im + sq.1);
    let (re, im) = c_log(arg.0, arg.1);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { cacosh(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { cacosh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanh(z: CDoubleComplex) -> CDoubleComplex {
    // atanh(z) = (1/2) * log((1+z)/(1-z))
    let num = (1.0 + z.re, z.im);
    let den = (1.0 - z.re, -z.im);
    let ratio = c_div(num, den);
    let lg = c_log(ratio.0, ratio.1);
    CDoubleComplex { re: lg.0 / 2.0, im: lg.1 / 2.0 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { catanh(CDoubleComplex { re: z.re as f64, im: z.im as f64 }) };
    CFloatComplex { re: r.re as f32, im: r.im as f32 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { catanh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
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
    fn acoshf_less_than_one_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { acoshf(0.5f32) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn atanhf_out_of_domain_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { atanhf(2.0f32) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn atanhf_unity_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { atanhf(1.0f32) };
        assert!(out.is_infinite() && out.is_sign_positive());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn tanhf_finite_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { tanhf(2.0f32) };
        assert!(out.is_finite());
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn asinhf_finite_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { asinhf(-2.0f32) };
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
    fn log1pf_less_than_negative_one_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { log1pf(-2.0f32) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn log1pf_negative_one_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { log1pf(-1.0f32) };
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
    fn exp2f_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { exp2f(200.0f32) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn exp2f_underflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { exp2f(-200.0f32) };
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
    fn cbrtf_negative_value_no_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { cbrtf(-8.0f32) };
        assert_eq!(out, -2.0f32);
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
    fn copysignf_applies_sign_and_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { copysignf(3.0f32, -0.0f32) };
        assert_eq!(out, -3.0f32);
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
    fn rintf_finite_value_leaves_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { rintf(2.0f32) };
        assert_eq!(out, 2.0f32);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn frexp_writes_exponent_and_accepts_null_pointer() {
        set_errno_for_test(0);
        let mut exp: c_int = 0;
        // SAFETY: valid exponent output pointer.
        let mantissa = unsafe { frexp(12.0, &mut exp as *mut c_int) };
        assert!((mantissa - 0.75).abs() < 1e-12);
        assert_eq!(exp, 4);
        assert_eq!(abi_errno(), 0);

        set_errno_for_test(0);
        // SAFETY: null pointer is tolerated by ABI wrapper.
        let mantissa_null = unsafe { frexp(12.0, std::ptr::null_mut()) };
        assert!((mantissa_null - 0.75).abs() < 1e-12);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn modf_writes_integer_part_and_accepts_null_pointer() {
        set_errno_for_test(0);
        let mut ipart: f64 = 0.0;
        // SAFETY: valid integer-part output pointer.
        let frac = unsafe { modf(3.75, &mut ipart as *mut f64) };
        assert!((frac - 0.75).abs() < 1e-12);
        assert!((ipart - 3.0).abs() < 1e-12);
        assert_eq!(abi_errno(), 0);

        set_errno_for_test(0);
        // SAFETY: null pointer is tolerated by ABI wrapper.
        let frac_null = unsafe { modf(3.75, std::ptr::null_mut()) };
        assert!((frac_null - 0.75).abs() < 1e-12);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn ldexp_range_behavior_sets_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 inputs.
        let overflow = unsafe { ldexp(1.0, 4096) };
        assert!(overflow.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);

        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 inputs.
        let underflow = unsafe { ldexp(1.0, -4096) };
        assert_eq!(underflow, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);

        set_errno_for_test(0);
        // SAFETY: zero input is valid and should not trigger ERANGE.
        let zero = unsafe { ldexp(0.0, 4096) };
        assert_eq!(zero, 0.0);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn scalbn_and_scalbln_range_behavior_sets_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 inputs.
        let overflow = unsafe { scalbn(1.0, 4096) };
        assert!(overflow.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);

        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 inputs.
        let underflow = unsafe { scalbln(1.0, -4096) };
        assert_eq!(underflow, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn f32_scaling_range_behavior_sets_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 inputs.
        let overflow = unsafe { ldexpf(1.0, 1024) };
        assert!(overflow.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);

        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 inputs.
        let underflow = unsafe { scalbnf(1.0, -1024) };
        assert_eq!(underflow, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);

        set_errno_for_test(0);
        // SAFETY: zero input is valid and should not trigger ERANGE.
        let zero = unsafe { scalblnf(0.0, 1024 as c_long) };
        assert_eq!(zero, 0.0);
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
    fn remainderf_divide_by_zero_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { remainderf(1.0f32, 0.0f32) };
        assert!(out.is_nan());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn remainderf_infinite_dividend_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { remainderf(f32::INFINITY, 2.0f32) };
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
    fn hypotf_finite_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { hypotf(f32::MAX, f32::MAX) };
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
    fn tgammaf_negative_integer_sets_domain_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { tgammaf(-1.0f32) };
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

    #[test]
    fn lgammaf_negative_integer_sets_range_errno() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { lgammaf(-1.0f32) };
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    // --- New math ABI tests ---

    #[test]
    fn remquo_basic_and_domain_error() {
        set_errno_for_test(0);
        let mut quo: c_int = 0;
        // SAFETY: ABI entrypoint with valid pointer to writable int.
        let rem = unsafe { remquo(10.0, 3.0, &mut quo as *mut c_int) };
        assert!((rem - 1.0).abs() < 1e-12);
        assert_eq!(quo & 0x7, 3 & 0x7);
        assert_eq!(abi_errno(), 0);

        // domain error: y == 0
        set_errno_for_test(0);
        let _ = unsafe { remquo(1.0, 0.0, std::ptr::null_mut()) };
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn sincos_basic() {
        let mut s: f64 = 0.0;
        let mut c: f64 = 0.0;
        // SAFETY: ABI entrypoint with valid pointers.
        unsafe { sincos(0.0, &mut s as *mut f64, &mut c as *mut f64) };
        assert!((s - 0.0).abs() < 1e-12);
        assert!((c - 1.0).abs() < 1e-12);
    }

    #[test]
    fn nan_returns_nan() {
        // SAFETY: null tagp is valid for nan().
        let v = unsafe { nan(std::ptr::null()) };
        assert!(v.is_nan());
    }

    #[test]
    fn j0_bessel_basic() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let v = unsafe { j0(0.0) };
        assert!((v - 1.0).abs() < 1e-12);
        assert_eq!(abi_errno(), 0);
    }

    #[test]
    fn y0_domain_error_at_zero() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let v = unsafe { y0(0.0) };
        assert!(v.is_infinite());
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn y0_domain_error_negative() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let _v = unsafe { y0(-1.0) };
        assert_eq!(abi_errno(), libc::EDOM);
    }

    #[test]
    fn finite_returns_correct_values() {
        // SAFETY: ABI entrypoint accepts plain f64 input.
        assert_eq!(unsafe { finite(1.0) }, 1);
        assert_eq!(unsafe { finite(f64::INFINITY) }, 0);
        assert_eq!(unsafe { finite(f64::NAN) }, 0);
    }

    #[test]
    fn drem_matches_remainder() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let d = unsafe { drem(5.3, 2.0) };
        let r = unsafe { remainder(5.3, 2.0) };
        assert_eq!(d, r);
    }

    #[test]
    fn exp10_basic_and_overflow() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let v = unsafe { exp10(1.0) };
        assert!((v - 10.0).abs() < 1e-10);
        assert_eq!(abi_errno(), 0);

        set_errno_for_test(0);
        let v2 = unsafe { exp10(1000.0) };
        assert!(v2.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn significand_basic() {
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let s = unsafe { significand(12.0) };
        assert!((s - 1.5).abs() < 1e-12);
    }

    #[test]
    fn gamma_matches_lgamma() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let g = unsafe { gamma(5.0) };
        let lg = unsafe { lgamma(5.0) };
        assert!((g - lg).abs() < 1e-12);
    }

    #[test]
    fn pow10_matches_exp10() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let p = unsafe { pow10(2.0) };
        let e = unsafe { exp10(2.0) };
        assert!((p - e).abs() < 1e-12);
        assert!((p - 100.0).abs() < 1e-10);
    }

    #[test]
    fn pow10f_matches_exp10f() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let p = unsafe { pow10f(2.0f32) };
        let e = unsafe { exp10f(2.0f32) };
        assert!((p - e).abs() < 1e-4);
        assert!((p - 100.0f32).abs() < 1e-2);
    }

    // -----------------------------------------------------------------------
    // lgamma_r / lgammaf_r tests
    // -----------------------------------------------------------------------

    #[test]
    fn lgamma_r_positive_sign_and_value() {
        set_errno_for_test(0);
        let mut sign: c_int = 0;
        // SAFETY: `sign` is valid writable int.
        let val = unsafe { lgamma_r(5.0, &mut sign as *mut c_int) };
        assert!((val - 24.0_f64.ln()).abs() < 1e-8);
        assert_eq!(sign, 1);
    }

    #[test]
    fn lgamma_r_negative_sign() {
        set_errno_for_test(0);
        let mut sign: c_int = 0;
        // SAFETY: `sign` is valid writable int.
        let _ = unsafe { lgamma_r(-0.5, &mut sign as *mut c_int) };
        assert_eq!(sign, -1);
    }

    #[test]
    fn lgamma_r_null_signgam_accepted() {
        set_errno_for_test(0);
        // SAFETY: null pointer should be tolerated.
        let val = unsafe { lgamma_r(5.0, std::ptr::null_mut()) };
        assert!((val - 24.0_f64.ln()).abs() < 1e-8);
    }

    #[test]
    fn lgamma_r_pole_sets_errno() {
        set_errno_for_test(0);
        // SAFETY: lgamma_r at zero should set ERANGE.
        let val = unsafe { lgamma_r(0.0, std::ptr::null_mut()) };
        assert!(val.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn lgammaf_r_positive_sign_and_value() {
        set_errno_for_test(0);
        let mut sign: c_int = 0;
        // SAFETY: `sign` is valid writable int.
        let val = unsafe { lgammaf_r(5.0f32, &mut sign as *mut c_int) };
        assert!((val - (24.0_f32).ln()).abs() < 1e-3);
        assert_eq!(sign, 1);
    }

    // -----------------------------------------------------------------------
    // nexttoward / nexttowardf tests
    // -----------------------------------------------------------------------

    #[test]
    fn nexttoward_steps_toward_target() {
        // SAFETY: ABI entrypoints accept plain float inputs.
        let up = unsafe { nexttoward(1.0, 2.0) };
        assert!(up > 1.0);
        assert!(up < 1.0 + 1e-15);
        let down = unsafe { nexttoward(1.0, 0.0) };
        assert!(down < 1.0);
        // Equal: returns x
        assert_eq!(unsafe { nexttoward(1.0, 1.0) }, 1.0);
    }

    #[test]
    fn nexttowardf_steps_and_propagates_nan() {
        // SAFETY: ABI entrypoints accept plain float inputs.
        let up = unsafe { nexttowardf(1.0f32, 2.0f64) };
        assert!(up > 1.0f32);
        assert!(unsafe { nexttowardf(f32::NAN, 1.0f64) }.is_nan());
    }

    // -----------------------------------------------------------------------
    // glibc classification internals tests
    // -----------------------------------------------------------------------

    #[test]
    fn fpclassify_classifies_all_categories() {
        // SAFETY: classification functions accept any float.
        unsafe {
            assert_eq!(__fpclassify(1.0), 4); // FP_NORMAL
            assert_eq!(__fpclassify(0.0), 2); // FP_ZERO
            assert_eq!(__fpclassify(f64::NAN), 0); // FP_NAN
            assert_eq!(__fpclassify(f64::INFINITY), 1); // FP_INFINITE
            assert_eq!(__fpclassify(5e-324), 3); // FP_SUBNORMAL
        }
    }

    #[test]
    fn fpclassifyf_classifies_all_categories() {
        // SAFETY: classification functions accept any float.
        unsafe {
            assert_eq!(__fpclassifyf(1.0f32), 4);
            assert_eq!(__fpclassifyf(0.0f32), 2);
            assert_eq!(__fpclassifyf(f32::NAN), 0);
            assert_eq!(__fpclassifyf(f32::INFINITY), 1);
            assert_eq!(__fpclassifyf(1e-45f32), 3);
        }
    }

    #[test]
    fn signbit_detects_sign() {
        // SAFETY: sign bit check accepts any float.
        unsafe {
            assert_eq!(__signbit(1.0), 0);
            assert_eq!(__signbit(-1.0), 1);
            assert_eq!(__signbit(-0.0), 1);
            assert_eq!(__signbitf(1.0f32), 0);
            assert_eq!(__signbitf(-1.0f32), 1);
        }
    }

    #[test]
    fn isinf_isnan_finite_checks() {
        // SAFETY: classification functions accept any float.
        unsafe {
            assert_eq!(__isinf(f64::INFINITY), 1);
            assert_eq!(__isinf(f64::NEG_INFINITY), -1);
            assert_eq!(__isinf(1.0), 0);
            assert_eq!(__isnan(f64::NAN), 1);
            assert_eq!(__isnan(1.0), 0);
            assert_eq!(__finite(1.0), 1);
            assert_eq!(__finite(f64::INFINITY), 0);
            assert_eq!(__finite(f64::NAN), 0);
        }
    }

    #[test]
    fn isinff_isnanf_finitef_checks() {
        // SAFETY: classification functions accept any float.
        unsafe {
            assert_eq!(__isinff(f32::INFINITY), 1);
            assert_eq!(__isinff(f32::NEG_INFINITY), -1);
            assert_eq!(__isinff(1.0f32), 0);
            assert_eq!(__isnanf(f32::NAN), 1);
            assert_eq!(__isnanf(1.0f32), 0);
            assert_eq!(__finitef(1.0f32), 1);
            assert_eq!(__finitef(f32::INFINITY), 0);
        }
    }

    // -----------------------------------------------------------------------
    // C99 complex math tests
    // -----------------------------------------------------------------------

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol || (a.is_nan() && b.is_nan())
    }

    #[test]
    fn creal_cimag_conj_basics() {
        unsafe {
            let z = CDoubleComplex { re: 3.0, im: 4.0 };
            assert_eq!(creal(z), 3.0);
            assert_eq!(cimag(z), 4.0);
            let c = conj(z);
            assert_eq!(c.re, 3.0);
            assert_eq!(c.im, -4.0);
        }
    }

    #[test]
    fn cabs_pythagorean() {
        unsafe {
            let z = CDoubleComplex { re: 3.0, im: 4.0 };
            assert!(approx(cabs(z), 5.0, 1e-10));
        }
    }

    #[test]
    fn carg_quadrants() {
        unsafe {
            let z1 = CDoubleComplex { re: 1.0, im: 0.0 };
            assert!(approx(carg(z1), 0.0, 1e-10));
            let z2 = CDoubleComplex { re: 0.0, im: 1.0 };
            assert!(approx(carg(z2), std::f64::consts::FRAC_PI_2, 1e-10));
        }
    }

    #[test]
    fn cexp_euler() {
        // e^(i*pi) = -1 + 0i
        unsafe {
            let z = CDoubleComplex { re: 0.0, im: std::f64::consts::PI };
            let r = cexp(z);
            assert!(approx(r.re, -1.0, 1e-10));
            assert!(approx(r.im, 0.0, 1e-10));
        }
    }

    #[test]
    fn clog_inverse_of_exp() {
        unsafe {
            let z = CDoubleComplex { re: 1.0, im: 2.0 };
            let e = cexp(z);
            let l = clog(e);
            assert!(approx(l.re, z.re, 1e-10));
            assert!(approx(l.im, z.im, 1e-10));
        }
    }

    #[test]
    fn csqrt_squares_back() {
        unsafe {
            let z = CDoubleComplex { re: -4.0, im: 0.0 };
            let s = csqrt(z);
            // sqrt(-4) = 2i
            assert!(approx(s.re, 0.0, 1e-10));
            assert!(approx(s.im, 2.0, 1e-10));
        }
    }

    #[test]
    fn cpow_integer_power() {
        unsafe {
            // (1+i)^2 = 2i
            let base = CDoubleComplex { re: 1.0, im: 1.0 };
            let exp = CDoubleComplex { re: 2.0, im: 0.0 };
            let r = cpow(base, exp);
            assert!(approx(r.re, 0.0, 1e-8));
            assert!(approx(r.im, 2.0, 1e-8));
        }
    }

    #[test]
    fn csin_ccos_pythagorean_identity() {
        // sin^2(z) + cos^2(z) = 1
        unsafe {
            let z = CDoubleComplex { re: 1.5, im: 0.75 };
            let s = csin(z);
            let c = ccos(z);
            let s2 = c_mul((s.re, s.im), (s.re, s.im));
            let c2 = c_mul((c.re, c.im), (c.re, c.im));
            assert!(approx(s2.0 + c2.0, 1.0, 1e-10));
            assert!(approx(s2.1 + c2.1, 0.0, 1e-10));
        }
    }

    #[test]
    fn ctan_equals_sin_over_cos() {
        unsafe {
            let z = CDoubleComplex { re: 0.5, im: 0.3 };
            let t = ctan(z);
            let s = csin(z);
            let c = ccos(z);
            let ratio = c_div((s.re, s.im), (c.re, c.im));
            assert!(approx(t.re, ratio.0, 1e-10));
            assert!(approx(t.im, ratio.1, 1e-10));
        }
    }

    #[test]
    fn csinh_ccosh_identity() {
        // cosh^2(z) - sinh^2(z) = 1
        unsafe {
            let z = CDoubleComplex { re: 1.0, im: 0.5 };
            let sh = csinh(z);
            let ch = ccosh(z);
            let sh2 = c_mul((sh.re, sh.im), (sh.re, sh.im));
            let ch2 = c_mul((ch.re, ch.im), (ch.re, ch.im));
            assert!(approx(ch2.0 - sh2.0, 1.0, 1e-10));
            assert!(approx(ch2.1 - sh2.1, 0.0, 1e-10));
        }
    }

    #[test]
    fn casin_cacos_sum_is_pi_over_2() {
        // asin(z) + acos(z) = pi/2
        unsafe {
            let z = CDoubleComplex { re: 0.5, im: 0.3 };
            let as_ = casin(z);
            let ac = cacos(z);
            assert!(approx(as_.re + ac.re, std::f64::consts::FRAC_PI_2, 1e-10));
            assert!(approx(as_.im + ac.im, 0.0, 1e-10));
        }
    }

    #[test]
    fn cproj_maps_infinity() {
        unsafe {
            let z = CDoubleComplex { re: f64::INFINITY, im: -3.0 };
            let p = cproj(z);
            assert_eq!(p.re, f64::INFINITY);
            assert!(p.im == 0.0 && p.im.is_sign_negative()); // -0.0
        }
    }

    #[test]
    fn complex_float_variants_consistent() {
        unsafe {
            let zd = CDoubleComplex { re: 1.0, im: 2.0 };
            let zf = CFloatComplex { re: 1.0f32, im: 2.0f32 };
            assert!(approx(cabsf(zf) as f64, cabs(zd), 1e-4));
            let sd = csin(zd);
            let sf = csinf(zf);
            assert!(approx(sf.re as f64, sd.re, 1e-4));
            assert!(approx(sf.im as f64, sd.im, 1e-4));
        }
    }

    #[test]
    fn casinh_cacosh_catanh_roundtrip() {
        unsafe {
            // asinh(sinh(z)) ~ z  for small z
            let z = CDoubleComplex { re: 0.5, im: 0.3 };
            let sh = csinh(z);
            let ash = casinh(sh);
            assert!(approx(ash.re, z.re, 1e-10));
            assert!(approx(ash.im, z.im, 1e-10));
        }
    }
}
