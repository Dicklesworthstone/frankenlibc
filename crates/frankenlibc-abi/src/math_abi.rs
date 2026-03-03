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

// =========================================================================
// C23 IEEE 754-2019 fmaximum / fminimum family
// =========================================================================
//
// IEEE 754-2019 min/max operations with strict NaN and signed-zero semantics.
// Width aliases: f32/f=f32, f64/(none)/f32x=f64, l/f64x/f128=f64 (Rust lacks f80/f128).

// --- Core implementations (f64) ---

/// IEEE 754-2019: NaN if either NaN; -0 < +0.
#[inline]
fn fmaximum_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    // -0 < +0
    if x == 0.0 && y == 0.0 {
        if x.is_sign_negative() && !y.is_sign_negative() {
            return y;
        }
        return x;
    }
    if x > y { x } else { y }
}

/// IEEE 754-2019: non-NaN wins; -0 < +0.
#[inline]
fn fmaximum_num_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() && y.is_nan() {
        return f64::NAN;
    }
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    if x == 0.0 && y == 0.0 {
        if x.is_sign_negative() && !y.is_sign_negative() {
            return y;
        }
        return x;
    }
    if x > y { x } else { y }
}

/// IEEE 754-2019: compare |x| vs |y|; NaN if either NaN.
#[inline]
fn fmaximum_mag_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    let ax = x.abs();
    let ay = y.abs();
    if ax > ay {
        x
    } else if ay > ax {
        y
    } else {
        fmaximum_impl(x, y)
    }
}

/// IEEE 754-2019: compare |x| vs |y|; non-NaN wins.
#[inline]
fn fmaximum_mag_num_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() && y.is_nan() {
        return f64::NAN;
    }
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    let ax = x.abs();
    let ay = y.abs();
    if ax > ay {
        x
    } else if ay > ax {
        y
    } else {
        fmaximum_num_impl(x, y)
    }
}

/// IEEE 754-2019: NaN if either NaN; -0 < +0.
#[inline]
fn fminimum_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    if x == 0.0 && y == 0.0 {
        if !x.is_sign_negative() && y.is_sign_negative() {
            return y;
        }
        return x;
    }
    if x < y { x } else { y }
}

/// IEEE 754-2019: non-NaN wins; -0 < +0.
#[inline]
fn fminimum_num_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() && y.is_nan() {
        return f64::NAN;
    }
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    if x == 0.0 && y == 0.0 {
        if !x.is_sign_negative() && y.is_sign_negative() {
            return y;
        }
        return x;
    }
    if x < y { x } else { y }
}

/// IEEE 754-2019: compare |x| vs |y|; NaN if either NaN.
#[inline]
fn fminimum_mag_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    let ax = x.abs();
    let ay = y.abs();
    if ax < ay {
        x
    } else if ay < ax {
        y
    } else {
        fminimum_impl(x, y)
    }
}

/// IEEE 754-2019: compare |x| vs |y|; non-NaN wins.
#[inline]
fn fminimum_mag_num_impl(x: f64, y: f64) -> f64 {
    if x.is_nan() && y.is_nan() {
        return f64::NAN;
    }
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    let ax = x.abs();
    let ay = y.abs();
    if ax < ay {
        x
    } else if ay < ax {
        y
    } else {
        fminimum_num_impl(x, y)
    }
}

// --- f32 core implementations ---

#[inline]
fn fmaximum_implf(x: f32, y: f32) -> f32 {
    fmaximum_impl(x as f64, y as f64) as f32
}
#[inline]
fn fmaximum_num_implf(x: f32, y: f32) -> f32 {
    fmaximum_num_impl(x as f64, y as f64) as f32
}
#[inline]
fn fmaximum_mag_implf(x: f32, y: f32) -> f32 {
    fmaximum_mag_impl(x as f64, y as f64) as f32
}
#[inline]
fn fmaximum_mag_num_implf(x: f32, y: f32) -> f32 {
    fmaximum_mag_num_impl(x as f64, y as f64) as f32
}
#[inline]
fn fminimum_implf(x: f32, y: f32) -> f32 {
    fminimum_impl(x as f64, y as f64) as f32
}
#[inline]
fn fminimum_num_implf(x: f32, y: f32) -> f32 {
    fminimum_num_impl(x as f64, y as f64) as f32
}
#[inline]
fn fminimum_mag_implf(x: f32, y: f32) -> f32 {
    fminimum_mag_impl(x as f64, y as f64) as f32
}
#[inline]
fn fminimum_mag_num_implf(x: f32, y: f32) -> f32 {
    fminimum_mag_num_impl(x as f64, y as f64) as f32
}

// --- fmaximum exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum(x: f64, y: f64) -> f64 { fmaximum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf(x: f32, y: f32) -> f32 { fmaximum_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximuml(x: f64, y: f64) -> f64 { fmaximum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf32(x: f32, y: f32) -> f32 { fmaximum_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf32x(x: f64, y: f64) -> f64 { fmaximum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf64(x: f64, y: f64) -> f64 { fmaximum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf64x(x: f64, y: f64) -> f64 { fmaximum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf128(x: f64, y: f64) -> f64 { fmaximum_impl(x, y) }

// --- fmaximum_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_num(x: f64, y: f64) -> f64 { fmaximum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf(x: f32, y: f32) -> f32 { fmaximum_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numl(x: f64, y: f64) -> f64 { fmaximum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf32(x: f32, y: f32) -> f32 { fmaximum_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf32x(x: f64, y: f64) -> f64 { fmaximum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf64(x: f64, y: f64) -> f64 { fmaximum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf64x(x: f64, y: f64) -> f64 { fmaximum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf128(x: f64, y: f64) -> f64 { fmaximum_num_impl(x, y) }

// --- fmaximum_mag exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag(x: f64, y: f64) -> f64 { fmaximum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf(x: f32, y: f32) -> f32 { fmaximum_mag_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magl(x: f64, y: f64) -> f64 { fmaximum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf32(x: f32, y: f32) -> f32 { fmaximum_mag_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf32x(x: f64, y: f64) -> f64 { fmaximum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf64(x: f64, y: f64) -> f64 { fmaximum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf64x(x: f64, y: f64) -> f64 { fmaximum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf128(x: f64, y: f64) -> f64 { fmaximum_mag_impl(x, y) }

// --- fmaximum_mag_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_num(x: f64, y: f64) -> f64 { fmaximum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf(x: f32, y: f32) -> f32 { fmaximum_mag_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numl(x: f64, y: f64) -> f64 { fmaximum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf32(x: f32, y: f32) -> f32 { fmaximum_mag_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf32x(x: f64, y: f64) -> f64 { fmaximum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf64(x: f64, y: f64) -> f64 { fmaximum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf64x(x: f64, y: f64) -> f64 { fmaximum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf128(x: f64, y: f64) -> f64 { fmaximum_mag_num_impl(x, y) }

// --- fminimum exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum(x: f64, y: f64) -> f64 { fminimum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf(x: f32, y: f32) -> f32 { fminimum_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimuml(x: f64, y: f64) -> f64 { fminimum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf32(x: f32, y: f32) -> f32 { fminimum_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf32x(x: f64, y: f64) -> f64 { fminimum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf64(x: f64, y: f64) -> f64 { fminimum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf64x(x: f64, y: f64) -> f64 { fminimum_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf128(x: f64, y: f64) -> f64 { fminimum_impl(x, y) }

// --- fminimum_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_num(x: f64, y: f64) -> f64 { fminimum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf(x: f32, y: f32) -> f32 { fminimum_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numl(x: f64, y: f64) -> f64 { fminimum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf32(x: f32, y: f32) -> f32 { fminimum_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf32x(x: f64, y: f64) -> f64 { fminimum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf64(x: f64, y: f64) -> f64 { fminimum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf64x(x: f64, y: f64) -> f64 { fminimum_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf128(x: f64, y: f64) -> f64 { fminimum_num_impl(x, y) }

// --- fminimum_mag exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag(x: f64, y: f64) -> f64 { fminimum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf(x: f32, y: f32) -> f32 { fminimum_mag_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magl(x: f64, y: f64) -> f64 { fminimum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf32(x: f32, y: f32) -> f32 { fminimum_mag_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf32x(x: f64, y: f64) -> f64 { fminimum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf64(x: f64, y: f64) -> f64 { fminimum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf64x(x: f64, y: f64) -> f64 { fminimum_mag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf128(x: f64, y: f64) -> f64 { fminimum_mag_impl(x, y) }

// --- fminimum_mag_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_num(x: f64, y: f64) -> f64 { fminimum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf(x: f32, y: f32) -> f32 { fminimum_mag_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numl(x: f64, y: f64) -> f64 { fminimum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf32(x: f32, y: f32) -> f32 { fminimum_mag_num_implf(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf32x(x: f64, y: f64) -> f64 { fminimum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf64(x: f64, y: f64) -> f64 { fminimum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf64x(x: f64, y: f64) -> f64 { fminimum_mag_num_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf128(x: f64, y: f64) -> f64 { fminimum_mag_num_impl(x, y) }

// =========================================================================
// C23 new math functions
// =========================================================================

// --- C23 Pi-trig functions ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospi(x: f64) -> f64 { let r = unsafe { acos(x) }; r / std::f64::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif(x: f32) -> f32 { let r = unsafe { acosf(x) }; r / std::f32::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospil(x: f64) -> f64 { unsafe { acospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif32(x: f32) -> f32 { unsafe { acospif(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif32x(x: f64) -> f64 { unsafe { acospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif64(x: f64) -> f64 { unsafe { acospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif64x(x: f64) -> f64 { unsafe { acospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif128(x: f64) -> f64 { unsafe { acospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpi(x: f64) -> f64 { let r = unsafe { asin(x) }; r / std::f64::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif(x: f32) -> f32 { let r = unsafe { asinf(x) }; r / std::f32::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpil(x: f64) -> f64 { unsafe { asinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif32(x: f32) -> f32 { unsafe { asinpif(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif32x(x: f64) -> f64 { unsafe { asinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif64(x: f64) -> f64 { unsafe { asinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif64x(x: f64) -> f64 { unsafe { asinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif128(x: f64) -> f64 { unsafe { asinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpi(x: f64) -> f64 { let r = unsafe { atan(x) }; r / std::f64::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif(x: f32) -> f32 { let r = unsafe { atanf(x) }; r / std::f32::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpil(x: f64) -> f64 { unsafe { atanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif32(x: f32) -> f32 { unsafe { atanpif(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif32x(x: f64) -> f64 { unsafe { atanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif64(x: f64) -> f64 { unsafe { atanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif64x(x: f64) -> f64 { unsafe { atanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif128(x: f64) -> f64 { unsafe { atanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pi(x: f64, y: f64) -> f64 { let r = unsafe { atan2(x, y) }; r / std::f64::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif(x: f32, y: f32) -> f32 { let r = unsafe { atan2f(x, y) }; r / std::f32::consts::PI }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pil(x: f64, y: f64) -> f64 { unsafe { atan2pi(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif32(x: f32, y: f32) -> f32 { unsafe { atan2pif(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif32x(x: f64, y: f64) -> f64 { unsafe { atan2pi(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif64(x: f64, y: f64) -> f64 { unsafe { atan2pi(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif64x(x: f64, y: f64) -> f64 { unsafe { atan2pi(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif128(x: f64, y: f64) -> f64 { unsafe { atan2pi(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospi(x: f64) -> f64 { unsafe { cos(x * std::f64::consts::PI) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif(x: f32) -> f32 { unsafe { cosf(x * std::f32::consts::PI) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospil(x: f64) -> f64 { unsafe { cospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif32(x: f32) -> f32 { unsafe { cospif(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif32x(x: f64) -> f64 { unsafe { cospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif64(x: f64) -> f64 { unsafe { cospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif64x(x: f64) -> f64 { unsafe { cospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif128(x: f64) -> f64 { unsafe { cospi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpi(x: f64) -> f64 { unsafe { sin(x * std::f64::consts::PI) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif(x: f32) -> f32 { unsafe { sinf(x * std::f32::consts::PI) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpil(x: f64) -> f64 { unsafe { sinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif32(x: f32) -> f32 { unsafe { sinpif(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif32x(x: f64) -> f64 { unsafe { sinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif64(x: f64) -> f64 { unsafe { sinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif64x(x: f64) -> f64 { unsafe { sinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif128(x: f64) -> f64 { unsafe { sinpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpi(x: f64) -> f64 { unsafe { tan(x * std::f64::consts::PI) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif(x: f32) -> f32 { unsafe { tanf(x * std::f32::consts::PI) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpil(x: f64) -> f64 { unsafe { tanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif32(x: f32) -> f32 { unsafe { tanpif(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif32x(x: f64) -> f64 { unsafe { tanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif64(x: f64) -> f64 { unsafe { tanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif64x(x: f64) -> f64 { unsafe { tanpi(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif128(x: f64) -> f64 { unsafe { tanpi(x) } }

// --- roundeven ---

fn roundeven_impl(x: f64) -> f64 {
    let r = x.round();
    if (x - r).abs() == 0.5 {
        let r2 = if x > 0.0 { x.floor() } else { x.ceil() };
        if (r2 as i64) % 2 == 0 { r2 } else { r }
    } else {
        r
    }
}
fn roundevenf_impl(x: f32) -> f32 {
    let r = x.round();
    if (x - r).abs() == 0.5f32 {
        let r2 = if x > 0.0f32 { x.floor() } else { x.ceil() };
        if (r2 as i32) % 2 == 0 { r2 } else { r }
    } else {
        r
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundeven(x: f64) -> f64 { roundeven_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf(x: f32) -> f32 { roundevenf_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenl(x: f64) -> f64 { unsafe { roundeven(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf32(x: f32) -> f32 { unsafe { roundevenf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf32x(x: f64) -> f64 { unsafe { roundeven(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf64(x: f64) -> f64 { unsafe { roundeven(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf64x(x: f64) -> f64 { unsafe { roundeven(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf128(x: f64) -> f64 { unsafe { roundeven(x) } }

// --- nextdown / nextup ---

fn nextdown_impl(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x == f64::NEG_INFINITY { return f64::NEG_INFINITY; }
    if x == 0.0 { return -f64::MIN_POSITIVE * f64::EPSILON; }
    let bits = x.to_bits();
    let next = if x > 0.0 { bits - 1 } else { bits + 1 };
    f64::from_bits(next)
}
fn nextdownf_impl(x: f32) -> f32 {
    if x.is_nan() { return x; }
    if x == f32::NEG_INFINITY { return f32::NEG_INFINITY; }
    if x == 0.0f32 { return -f32::MIN_POSITIVE * f32::EPSILON; }
    let bits = x.to_bits();
    let next = if x > 0.0f32 { bits - 1 } else { bits + 1 };
    f32::from_bits(next)
}
fn nextup_impl(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x == f64::INFINITY { return f64::INFINITY; }
    if x == 0.0 { return f64::MIN_POSITIVE * f64::EPSILON; }
    let bits = x.to_bits();
    let next = if x > 0.0 { bits + 1 } else { bits - 1 };
    f64::from_bits(next)
}
fn nextupf_impl(x: f32) -> f32 {
    if x.is_nan() { return x; }
    if x == f32::INFINITY { return f32::INFINITY; }
    if x == 0.0f32 { return f32::MIN_POSITIVE * f32::EPSILON; }
    let bits = x.to_bits();
    let next = if x > 0.0f32 { bits + 1 } else { bits - 1 };
    f32::from_bits(next)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdown(x: f64) -> f64 { nextdown_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf(x: f32) -> f32 { nextdownf_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownl(x: f64) -> f64 { unsafe { nextdown(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf32(x: f32) -> f32 { unsafe { nextdownf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf32x(x: f64) -> f64 { unsafe { nextdown(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf64(x: f64) -> f64 { unsafe { nextdown(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf64x(x: f64) -> f64 { unsafe { nextdown(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf128(x: f64) -> f64 { unsafe { nextdown(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextup(x: f64) -> f64 { nextup_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf(x: f32) -> f32 { nextupf_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupl(x: f64) -> f64 { unsafe { nextup(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf32(x: f32) -> f32 { unsafe { nextupf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf32x(x: f64) -> f64 { unsafe { nextup(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf64(x: f64) -> f64 { unsafe { nextup(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf64x(x: f64) -> f64 { unsafe { nextup(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf128(x: f64) -> f64 { unsafe { nextup(x) } }

// --- rsqrt (1/sqrt) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrt(x: f64) -> f64 { let s = unsafe { sqrt(x) }; 1.0 / s }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf(x: f32) -> f32 { let s = unsafe { sqrtf(x) }; 1.0f32 / s }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtl(x: f64) -> f64 { unsafe { rsqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf32(x: f32) -> f32 { unsafe { rsqrtf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf32x(x: f64) -> f64 { unsafe { rsqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf64(x: f64) -> f64 { unsafe { rsqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf64x(x: f64) -> f64 { unsafe { rsqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf128(x: f64) -> f64 { unsafe { rsqrt(x) } }

// --- llogb (long ilogb) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogb(x: f64) -> c_long { let r = unsafe { ilogb(x) }; r as c_long }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf(x: f32) -> c_long { let r = unsafe { ilogbf(x) }; r as c_long }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbl(x: f64) -> c_long { unsafe { llogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf32(x: f32) -> c_long { unsafe { llogbf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf32x(x: f64) -> c_long { unsafe { llogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf64(x: f64) -> c_long { unsafe { llogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf64x(x: f64) -> c_long { unsafe { llogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf128(x: f64) -> c_long { unsafe { llogb(x) } }

// --- logp1, log2p1, log10p1 (C23 aliases) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1(x: f64) -> f64 { unsafe { log1p(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f(x: f32) -> f32 { unsafe { log1pf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1l(x: f64) -> f64 { unsafe { logp1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f32(x: f32) -> f32 { unsafe { logp1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f32x(x: f64) -> f64 { unsafe { logp1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f64(x: f64) -> f64 { unsafe { logp1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f64x(x: f64) -> f64 { unsafe { logp1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f128(x: f64) -> f64 { unsafe { logp1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1(x: f64) -> f64 { let r = unsafe { log1p(x) }; r / std::f64::consts::LN_2 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f(x: f32) -> f32 { let r = unsafe { log1pf(x) }; r / std::f32::consts::LN_2 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1l(x: f64) -> f64 { unsafe { log2p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f32(x: f32) -> f32 { unsafe { log2p1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f32x(x: f64) -> f64 { unsafe { log2p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f64(x: f64) -> f64 { unsafe { log2p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f64x(x: f64) -> f64 { unsafe { log2p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f128(x: f64) -> f64 { unsafe { log2p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1(x: f64) -> f64 { let r = unsafe { log1p(x) }; r / std::f64::consts::LN_10 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f(x: f32) -> f32 { let r = unsafe { log1pf(x) }; r / std::f32::consts::LN_10 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1l(x: f64) -> f64 { unsafe { log10p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f32(x: f32) -> f32 { unsafe { log10p1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f32x(x: f64) -> f64 { unsafe { log10p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f64(x: f64) -> f64 { unsafe { log10p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f64x(x: f64) -> f64 { unsafe { log10p1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f128(x: f64) -> f64 { unsafe { log10p1(x) } }

// --- exp2m1, exp10m1 (C23) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1(x: f64) -> f64 { unsafe { expm1(x * std::f64::consts::LN_2) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f(x: f32) -> f32 { unsafe { expm1f(x * std::f32::consts::LN_2) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1l(x: f64) -> f64 { unsafe { exp2m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f32(x: f32) -> f32 { unsafe { exp2m1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f32x(x: f64) -> f64 { unsafe { exp2m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f64(x: f64) -> f64 { unsafe { exp2m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f64x(x: f64) -> f64 { unsafe { exp2m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f128(x: f64) -> f64 { unsafe { exp2m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1(x: f64) -> f64 { unsafe { expm1(x * std::f64::consts::LN_10) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f(x: f32) -> f32 { unsafe { expm1f(x * std::f32::consts::LN_10) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1l(x: f64) -> f64 { unsafe { exp10m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f32(x: f32) -> f32 { unsafe { exp10m1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f32x(x: f64) -> f64 { unsafe { exp10m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f64(x: f64) -> f64 { unsafe { exp10m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f64x(x: f64) -> f64 { unsafe { exp10m1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f128(x: f64) -> f64 { unsafe { exp10m1(x) } }

// --- compoundn ((1+x)^n) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundn(x: f64, n: i64) -> f64 { frankenlibc_core::math::pow(1.0 + x, n as f64) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf(x: f32, n: i64) -> f32 { frankenlibc_core::math::powf(1.0f32 + x, n as f32) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnl(x: f64, n: i64) -> f64 { unsafe { compoundn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf32(x: f32, n: i64) -> f32 { unsafe { compoundnf(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf32x(x: f64, n: i64) -> f64 { unsafe { compoundn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf64(x: f64, n: i64) -> f64 { unsafe { compoundn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf64x(x: f64, n: i64) -> f64 { unsafe { compoundn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf128(x: f64, n: i64) -> f64 { unsafe { compoundn(x, n) } }

// --- pown (x^n integer) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pown(x: f64, n: i64) -> f64 { frankenlibc_core::math::pow(x, n as f64) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf(x: f32, n: i64) -> f32 { frankenlibc_core::math::powf(x, n as f32) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownl(x: f64, n: i64) -> f64 { unsafe { pown(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf32(x: f32, n: i64) -> f32 { unsafe { pownf(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf32x(x: f64, n: i64) -> f64 { unsafe { pown(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf64(x: f64, n: i64) -> f64 { unsafe { pown(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf64x(x: f64, n: i64) -> f64 { unsafe { pown(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf128(x: f64, n: i64) -> f64 { unsafe { pown(x, n) } }

// --- powr (x^y for positive x) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powr(x: f64, y: f64) -> f64 { if x < 0.0 { f64::NAN } else { frankenlibc_core::math::pow(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf(x: f32, y: f32) -> f32 { if x < 0.0f32 { f32::NAN } else { frankenlibc_core::math::powf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrl(x: f64, y: f64) -> f64 { unsafe { powr(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf32(x: f32, y: f32) -> f32 { unsafe { powrf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf32x(x: f64, y: f64) -> f64 { unsafe { powr(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf64(x: f64, y: f64) -> f64 { unsafe { powr(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf64x(x: f64, y: f64) -> f64 { unsafe { powr(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf128(x: f64, y: f64) -> f64 { unsafe { powr(x, y) } }

// --- rootn (nth root) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootn(x: f64, n: i64) -> f64 { if n == 0 { return f64::NAN; } frankenlibc_core::math::pow(x, 1.0 / n as f64) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf(x: f32, n: i64) -> f32 { if n == 0 { return f32::NAN; } frankenlibc_core::math::powf(x, 1.0f32 / n as f32) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnl(x: f64, n: i64) -> f64 { unsafe { rootn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf32(x: f32, n: i64) -> f32 { unsafe { rootnf(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf32x(x: f64, n: i64) -> f64 { unsafe { rootn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf64(x: f64, n: i64) -> f64 { unsafe { rootn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf64x(x: f64, n: i64) -> f64 { unsafe { rootn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf128(x: f64, n: i64) -> f64 { unsafe { rootn(x, n) } }

// --- fmaxmag / fminmag (C23) ---

fn fmaxmag_impl(x: f64, y: f64) -> f64 {
    let ax = x.abs();
    let ay = y.abs();
    if ax > ay { x } else if ay > ax { y } else { unsafe { fmax(x, y) } }
}
fn fmaxmagf_impl(x: f32, y: f32) -> f32 {
    let ax = x.abs();
    let ay = y.abs();
    if ax > ay { x } else if ay > ax { y } else { unsafe { fmaxf(x, y) } }
}
fn fminmag_impl(x: f64, y: f64) -> f64 {
    let ax = x.abs();
    let ay = y.abs();
    if ax < ay { x } else if ay < ax { y } else { unsafe { fmin(x, y) } }
}
fn fminmagf_impl(x: f32, y: f32) -> f32 {
    let ax = x.abs();
    let ay = y.abs();
    if ax < ay { x } else if ay < ax { y } else { unsafe { fminf(x, y) } }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmag(x: f64, y: f64) -> f64 { fmaxmag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf(x: f32, y: f32) -> f32 { fmaxmagf_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagl(x: f64, y: f64) -> f64 { unsafe { fmaxmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf32(x: f32, y: f32) -> f32 { unsafe { fmaxmagf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf32x(x: f64, y: f64) -> f64 { unsafe { fmaxmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf64(x: f64, y: f64) -> f64 { unsafe { fmaxmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf64x(x: f64, y: f64) -> f64 { unsafe { fmaxmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf128(x: f64, y: f64) -> f64 { unsafe { fmaxmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmag(x: f64, y: f64) -> f64 { fminmag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf(x: f32, y: f32) -> f32 { fminmagf_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagl(x: f64, y: f64) -> f64 { unsafe { fminmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf32(x: f32, y: f32) -> f32 { unsafe { fminmagf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf32x(x: f64, y: f64) -> f64 { unsafe { fminmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf64(x: f64, y: f64) -> f64 { unsafe { fminmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf64x(x: f64, y: f64) -> f64 { unsafe { fminmag(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf128(x: f64, y: f64) -> f64 { unsafe { fminmag(x, y) } }

// --- totalorder / totalordermag (IEEE 754-2019) ---

fn totalorder_impl(x: *const f64, y: *const f64) -> c_int {
    let a = unsafe { *x };
    let b = unsafe { *y };
    let ai = a.to_bits() as i64;
    let bi = b.to_bits() as i64;
    // Convert sign-magnitude to monotonic ordering:
    // negative floats: flip magnitude bits (preserves sign, reverses magnitude order)
    // positive floats: leave as-is (already monotonically ordered)
    let a_tc = if ai < 0 { ai ^ i64::MAX } else { ai };
    let b_tc = if bi < 0 { bi ^ i64::MAX } else { bi };
    if a_tc <= b_tc { 1 } else { 0 }
}
fn totalorderf_impl(x: *const f32, y: *const f32) -> c_int {
    let a = unsafe { *x };
    let b = unsafe { *y };
    let ai = a.to_bits() as i32;
    let bi = b.to_bits() as i32;
    let a_tc = if ai < 0 { ai ^ i32::MAX } else { ai };
    let b_tc = if bi < 0 { bi ^ i32::MAX } else { bi };
    if a_tc <= b_tc { 1 } else { 0 }
}
fn totalordermag_impl(x: *const f64, y: *const f64) -> c_int {
    let a = unsafe { (*x).abs() };
    let b = unsafe { (*y).abs() };
    totalorder_impl(&a as *const f64, &b as *const f64)
}
fn totalordermagf_impl(x: *const f32, y: *const f32) -> c_int {
    let a = unsafe { (*x).abs() };
    let b = unsafe { (*y).abs() };
    totalorderf_impl(&a as *const f32, &b as *const f32)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorder(x: *const f64, y: *const f64) -> c_int { totalorder_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf(x: *const f32, y: *const f32) -> c_int { totalorderf_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderl(x: *const f64, y: *const f64) -> c_int { totalorder_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf32(x: *const f32, y: *const f32) -> c_int { totalorderf_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf32x(x: *const f64, y: *const f64) -> c_int { totalorder_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf64(x: *const f64, y: *const f64) -> c_int { totalorder_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf64x(x: *const f64, y: *const f64) -> c_int { totalorder_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf128(x: *const f64, y: *const f64) -> c_int { totalorder_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermag(x: *const f64, y: *const f64) -> c_int { totalordermag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf(x: *const f32, y: *const f32) -> c_int { totalordermagf_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagl(x: *const f64, y: *const f64) -> c_int { totalordermag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf32(x: *const f32, y: *const f32) -> c_int { totalordermagf_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf32x(x: *const f64, y: *const f64) -> c_int { totalordermag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf64(x: *const f64, y: *const f64) -> c_int { totalordermag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf64x(x: *const f64, y: *const f64) -> c_int { totalordermag_impl(x, y) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf128(x: *const f64, y: *const f64) -> c_int { totalordermag_impl(x, y) }

// --- canonicalize (C23 IEEE 754) ---

fn canonicalize_impl(cx: *mut f64, x: *const f64) -> c_int {
    let val = unsafe { *x };
    if !cx.is_null() { unsafe { *cx = val; } }
    if val.is_nan() { 1 } else { 0 }
}
fn canonicalizef_impl(cx: *mut f32, x: *const f32) -> c_int {
    let val = unsafe { *x };
    if !cx.is_null() { unsafe { *cx = val; } }
    if val.is_nan() { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize(cx: *mut f64, x: *const f64) -> c_int { canonicalize_impl(cx, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef(cx: *mut f32, x: *const f32) -> c_int { canonicalizef_impl(cx, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizel(cx: *mut f64, x: *const f64) -> c_int { canonicalize_impl(cx, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef32(cx: *mut f32, x: *const f32) -> c_int { canonicalizef_impl(cx, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef32x(cx: *mut f64, x: *const f64) -> c_int { canonicalize_impl(cx, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef64(cx: *mut f64, x: *const f64) -> c_int { canonicalize_impl(cx, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef64x(cx: *mut f64, x: *const f64) -> c_int { canonicalize_impl(cx, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef128(cx: *mut f64, x: *const f64) -> c_int { canonicalize_impl(cx, x) }

// --- getpayload / setpayload / setpayloadsig (C23) ---

fn getpayload_impl(x: *const f64) -> f64 {
    let val = unsafe { *x };
    if !val.is_nan() { return -1.0; }
    let bits = val.to_bits();
    (bits & 0x0007_FFFF_FFFF_FFFF) as f64
}
fn getpayloadf_impl(x: *const f32) -> f32 {
    let val = unsafe { *x };
    if !val.is_nan() { return -1.0f32; }
    let bits = val.to_bits();
    (bits & 0x003F_FFFF) as f32
}
fn setpayload_impl(res: *mut f64, payload: f64) -> c_int {
    let p = payload as u64;
    if payload < 0.0 || p >= (1u64 << 51) { return 1; }
    unsafe { *res = f64::from_bits(0x7FF8_0000_0000_0000 | p); }
    0
}
fn setpayloadf_impl(res: *mut f32, payload: f32) -> c_int {
    let p = payload as u32;
    if payload < 0.0f32 || p >= (1u32 << 22) { return 1; }
    unsafe { *res = f32::from_bits(0x7FC0_0000 | p); }
    0
}
fn setpayloadsig_impl(res: *mut f64, payload: f64) -> c_int {
    let p = payload as u64;
    if payload < 0.0 || p == 0 || p >= (1u64 << 51) { return 1; }
    unsafe { *res = f64::from_bits(0x7FF0_0000_0000_0000 | p); }
    0
}
fn setpayloadsigf_impl(res: *mut f32, payload: f32) -> c_int {
    let p = payload as u32;
    if payload < 0.0f32 || p == 0 || p >= (1u32 << 22) { return 1; }
    unsafe { *res = f32::from_bits(0x7F80_0000 | p); }
    0
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayload(x: *const f64) -> f64 { getpayload_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf(x: *const f32) -> f32 { getpayloadf_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadl(x: *const f64) -> f64 { getpayload_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf32(x: *const f32) -> f32 { getpayloadf_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf32x(x: *const f64) -> f64 { getpayload_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf64(x: *const f64) -> f64 { getpayload_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf64x(x: *const f64) -> f64 { getpayload_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf128(x: *const f64) -> f64 { getpayload_impl(x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayload(res: *mut f64, pl: f64) -> c_int { setpayload_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf(res: *mut f32, pl: f32) -> c_int { setpayloadf_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadl(res: *mut f64, pl: f64) -> c_int { setpayload_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf32(res: *mut f32, pl: f32) -> c_int { setpayloadf_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf32x(res: *mut f64, pl: f64) -> c_int { setpayload_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf64(res: *mut f64, pl: f64) -> c_int { setpayload_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf64x(res: *mut f64, pl: f64) -> c_int { setpayload_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf128(res: *mut f64, pl: f64) -> c_int { setpayload_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsig(res: *mut f64, pl: f64) -> c_int { setpayloadsig_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf(res: *mut f32, pl: f32) -> c_int { setpayloadsigf_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigl(res: *mut f64, pl: f64) -> c_int { setpayloadsig_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf32(res: *mut f32, pl: f32) -> c_int { setpayloadsigf_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf32x(res: *mut f64, pl: f64) -> c_int { setpayloadsig_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf64(res: *mut f64, pl: f64) -> c_int { setpayloadsig_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf64x(res: *mut f64, pl: f64) -> c_int { setpayloadsig_impl(res, pl) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf128(res: *mut f64, pl: f64) -> c_int { setpayloadsig_impl(res, pl) }

// --- fromfp / ufromfp / fromfpx / ufromfpx (C23) ---

#[allow(dead_code)]
const FP_INT_UPWARD: c_int = 0;
#[allow(dead_code)]
const FP_INT_DOWNWARD: c_int = 1;
#[allow(dead_code)]
const FP_INT_TOWARDZERO: c_int = 2;
#[allow(dead_code)]
const FP_INT_TONEARESTFROMZERO: c_int = 3;
#[allow(dead_code)]
const FP_INT_TONEAREST: c_int = 4;

fn fromfp_impl(x: f64, rnd: c_int, width: u32) -> f64 {
    if x.is_nan() || x.is_infinite() { return f64::NAN; }
    let r = match rnd {
        FP_INT_UPWARD => x.ceil(),
        FP_INT_DOWNWARD => x.floor(),
        FP_INT_TOWARDZERO => x.trunc(),
        FP_INT_TONEARESTFROMZERO => x.round(),
        _ => {
            let r = x.round();
            if (x - r).abs() == 0.5 { if (r as i64) % 2 != 0 { r - r.signum() } else { r } } else { r }
        }
    };
    if width == 0 || width > 64 { return f64::NAN; }
    let max = if width >= 64 { i64::MAX } else { (1i64 << (width - 1)) - 1 };
    let min = if width >= 64 { i64::MIN } else { -(1i64 << (width - 1)) };
    let ri = r as i64;
    if ri < min || ri > max { f64::NAN } else { r }
}
fn fromfpf_impl(x: f32, rnd: c_int, width: u32) -> f32 { fromfp_impl(x as f64, rnd, width) as f32 }
fn ufromfp_impl(x: f64, rnd: c_int, width: u32) -> f64 {
    if x.is_nan() || x.is_infinite() || x < 0.0 { return f64::NAN; }
    let r = fromfp_impl(x, rnd, 64);
    if r.is_nan() || r < 0.0 { return f64::NAN; }
    if width == 0 || width > 64 { return f64::NAN; }
    let max = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
    if (r as u64) > max { f64::NAN } else { r }
}
fn ufromfpf_impl(x: f32, rnd: c_int, width: u32) -> f32 { ufromfp_impl(x as f64, rnd, width) as f32 }

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfp(x: f64, rnd: c_int, width: u32) -> f64 { fromfp_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf(x: f32, rnd: c_int, width: u32) -> f32 { fromfpf_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpl(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf32(x: f32, rnd: c_int, width: u32) -> f32 { unsafe { fromfpf(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf32x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf64(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf64x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf128(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfp(x: f64, rnd: c_int, width: u32) -> f64 { ufromfp_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf(x: f32, rnd: c_int, width: u32) -> f32 { ufromfpf_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpl(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf32(x: f32, rnd: c_int, width: u32) -> f32 { unsafe { ufromfpf(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf32x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf64(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf64x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf128(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfp(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpx(x: f64, rnd: c_int, width: u32) -> f64 { fromfp_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf(x: f32, rnd: c_int, width: u32) -> f32 { fromfpf_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxl(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf32(x: f32, rnd: c_int, width: u32) -> f32 { unsafe { fromfpxf(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf32x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf64(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf64x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf128(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { fromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpx(x: f64, rnd: c_int, width: u32) -> f64 { ufromfp_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf(x: f32, rnd: c_int, width: u32) -> f32 { ufromfpf_impl(x, rnd, width) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxl(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf32(x: f32, rnd: c_int, width: u32) -> f32 { unsafe { ufromfpxf(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf32x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf64(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf64x(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfpx(x, rnd, width) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf128(x: f64, rnd: c_int, width: u32) -> f64 { unsafe { ufromfpx(x, rnd, width) } }

// --- clog10 (complex log base 10) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10(z: CDoubleComplex) -> CDoubleComplex { let r = unsafe { clog(z) }; let ln10 = std::f64::consts::LN_10; CDoubleComplex { re: r.re / ln10, im: r.im / ln10 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f(z: CFloatComplex) -> CFloatComplex { let r = unsafe { clogf(z) }; let ln10 = std::f32::consts::LN_10; CFloatComplex { re: r.re / ln10, im: r.im / ln10 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10l(z: CLongDoubleComplex) -> CLongDoubleComplex { let r = unsafe { clog10(CDoubleComplex { re: z.re, im: z.im }) }; CLongDoubleComplex { re: r.re, im: r.im } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clog10(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog10(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clog10f(z: CFloatComplex) -> CFloatComplex { unsafe { clog10f(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clog10l(z: CLongDoubleComplex) -> CLongDoubleComplex { unsafe { clog10l(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f32(z: CFloatComplex) -> CFloatComplex { unsafe { clog10f(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog10(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f64(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog10(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog10(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f128(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog10(z) } }

// --- lgamma*_r width variants ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammal_r(x: f64, signgamp: *mut c_int) -> f64 { unsafe { lgamma_r(x, signgamp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32_r(x: f32, signgamp: *mut c_int) -> f32 { unsafe { lgammaf_r(x, signgamp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32x_r(x: f64, signgamp: *mut c_int) -> f64 { unsafe { lgamma_r(x, signgamp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64_r(x: f64, signgamp: *mut c_int) -> f64 { unsafe { lgamma_r(x, signgamp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64x_r(x: f64, signgamp: *mut c_int) -> f64 { unsafe { lgamma_r(x, signgamp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf128_r(x: f64, signgamp: *mut c_int) -> f64 { unsafe { lgamma_r(x, signgamp) } }



// =========================================================================
// Long-double variants (forward to double)
// =========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshl(x: f64) -> f64 { unsafe { acosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosl(x: f64) -> f64 { unsafe { acos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhl(x: f64) -> f64 { unsafe { asinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinl(x: f64) -> f64 { unsafe { asin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhl(x: f64) -> f64 { unsafe { atanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanl(x: f64) -> f64 { unsafe { atan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtl(x: f64) -> f64 { unsafe { cbrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceill(x: f64) -> f64 { unsafe { ceil(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshl(x: f64) -> f64 { unsafe { cosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosl(x: f64) -> f64 { unsafe { cos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcl(x: f64) -> f64 { unsafe { erfc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfl(x: f64) -> f64 { unsafe { erf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10l(x: f64) -> f64 { unsafe { exp10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2l(x: f64) -> f64 { unsafe { exp2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expl(x: f64) -> f64 { unsafe { exp(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1l(x: f64) -> f64 { unsafe { expm1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsl(x: f64) -> f64 { unsafe { fabs(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorl(x: f64) -> f64 { unsafe { floor(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammal(x: f64) -> f64 { unsafe { lgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10l(x: f64) -> f64 { unsafe { log10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pl(x: f64) -> f64 { unsafe { log1p(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2l(x: f64) -> f64 { unsafe { log2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbl(x: f64) -> f64 { unsafe { logb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logl(x: f64) -> f64 { unsafe { log(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintl(x: f64) -> f64 { unsafe { nearbyint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintl(x: f64) -> f64 { unsafe { rint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundl(x: f64) -> f64 { unsafe { round(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhl(x: f64) -> f64 { unsafe { sinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinl(x: f64) -> f64 { unsafe { sin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtl(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhl(x: f64) -> f64 { unsafe { tanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanl(x: f64) -> f64 { unsafe { tan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammal(x: f64) -> f64 { unsafe { tgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncl(x: f64) -> f64 { unsafe { trunc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2l(x: f64, y: f64) -> f64 { unsafe { atan2(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdiml(x: f64, y: f64) -> f64 { unsafe { fdim(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxl(x: f64, y: f64) -> f64 { unsafe { fmax(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminl(x: f64, y: f64) -> f64 { unsafe { fmin(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodl(x: f64, y: f64) -> f64 { unsafe { fmod(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotl(x: f64, y: f64) -> f64 { unsafe { hypot(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterl(x: f64, y: f64) -> f64 { unsafe { nextafter(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powl(x: f64, y: f64) -> f64 { unsafe { pow(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderl(x: f64, y: f64) -> f64 { unsafe { remainder(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmal(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbl(x: f64) -> c_int { unsafe { ilogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintl(x: f64) -> c_long { unsafe { lrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundl(x: f64) -> c_long { unsafe { lround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintl(x: f64) -> i64 { unsafe { llrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundl(x: f64) -> i64 { unsafe { llround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnl(x: f64, n: c_long) -> f64 { unsafe { scalbln(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquol(x: f64, y: f64, quo: *mut c_int) -> f64 { unsafe { remquo(x, y, quo) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanl(tagp: *const std::ffi::c_char) -> f64 { unsafe { nan(tagp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nexttowardl(x: f64, y: f64) -> f64 { unsafe { nextafter(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnl(n: c_int, x: f64) -> f64 { unsafe { jn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0l(x: f64) -> f64 { unsafe { j0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1l(x: f64) -> f64 { unsafe { j1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynl(n: c_int, x: f64) -> f64 { unsafe { yn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0l(x: f64) -> f64 { unsafe { y0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1l(x: f64) -> f64 { unsafe { y1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pow10l(x: f64) -> f64 { unsafe { pow10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gammal(x: f64) -> f64 { unsafe { gamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dreml(x: f64, y: f64) -> f64 { unsafe { drem(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn significandl(x: f64) -> f64 { unsafe { significand(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosl(x: f64, s: *mut f64, c: *mut f64) { unsafe { sincos(x, s, c) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbl(x: f64, y: f64) -> f64 { frankenlibc_core::math::scalbn(x, y as i32) }

// =========================================================================
// C23 narrowing math functions
// =========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fadd(x: f64, y: f64) -> f32 { (x + y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn faddl(x: f64, y: f64) -> f32 { (x + y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdiv(x: f64, y: f64) -> f32 { (x / y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdivl(x: f64, y: f64) -> f32 { (x / y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmul(x: f64, y: f64) -> f32 { (x * y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmull(x: f64, y: f64) -> f32 { (x * y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsqrt(x: f64) -> f32 { let r = unsafe { sqrt(x) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsqrtl(x: f64) -> f32 { let r = unsafe { sqrt(x) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsub(x: f64, y: f64) -> f32 { (x - y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsubl(x: f64, y: f64) -> f32 { (x - y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ffma(x: f64, y: f64, z: f64) -> f32 { let r = unsafe { fma(x, y, z) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ffmal(x: f64, y: f64, z: f64) -> f32 { let r = unsafe { fma(x, y, z) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn daddl(x: f64, y: f64) -> f64 { x + y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ddivl(x: f64, y: f64) -> f64 { x / y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dmull(x: f64, y: f64) -> f64 { x * y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dsqrtl(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dsubl(x: f64, y: f64) -> f64 { x - y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dfmal(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }

// Type-generic narrowing operations
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf32x(x: f64, y: f64) -> f32 { (x + y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf64(x: f64, y: f64) -> f32 { (x + y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf64x(x: f64, y: f64) -> f32 { (x + y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf128(x: f64, y: f64) -> f32 { (x + y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xaddf64(x: f64, y: f64) -> f64 { x + y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xaddf64x(x: f64, y: f64) -> f64 { x + y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xaddf128(x: f64, y: f64) -> f64 { x + y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64addf64x(x: f64, y: f64) -> f64 { x + y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64addf128(x: f64, y: f64) -> f64 { x + y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xaddf128(x: f64, y: f64) -> f64 { x + y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf32x(x: f64, y: f64) -> f32 { (x / y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf64(x: f64, y: f64) -> f32 { (x / y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf64x(x: f64, y: f64) -> f32 { (x / y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf128(x: f64, y: f64) -> f32 { (x / y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xdivf64(x: f64, y: f64) -> f64 { x / y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xdivf64x(x: f64, y: f64) -> f64 { x / y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xdivf128(x: f64, y: f64) -> f64 { x / y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64divf64x(x: f64, y: f64) -> f64 { x / y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64divf128(x: f64, y: f64) -> f64 { x / y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xdivf128(x: f64, y: f64) -> f64 { x / y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf32x(x: f64, y: f64) -> f32 { (x * y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf64(x: f64, y: f64) -> f32 { (x * y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf64x(x: f64, y: f64) -> f32 { (x * y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf128(x: f64, y: f64) -> f32 { (x * y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xmulf64(x: f64, y: f64) -> f64 { x * y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xmulf64x(x: f64, y: f64) -> f64 { x * y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xmulf128(x: f64, y: f64) -> f64 { x * y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64mulf64x(x: f64, y: f64) -> f64 { x * y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64mulf128(x: f64, y: f64) -> f64 { x * y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xmulf128(x: f64, y: f64) -> f64 { x * y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf32x(x: f64) -> f32 { let r = unsafe { sqrt(x) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf64(x: f64) -> f32 { let r = unsafe { sqrt(x) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf64x(x: f64) -> f32 { let r = unsafe { sqrt(x) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf128(x: f64) -> f32 { let r = unsafe { sqrt(x) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsqrtf64(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsqrtf64x(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsqrtf128(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64sqrtf64x(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64sqrtf128(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xsqrtf128(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf32x(x: f64, y: f64) -> f32 { (x - y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf64(x: f64, y: f64) -> f32 { (x - y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf64x(x: f64, y: f64) -> f32 { (x - y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf128(x: f64, y: f64) -> f32 { (x - y) as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsubf64(x: f64, y: f64) -> f64 { x - y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsubf64x(x: f64, y: f64) -> f64 { x - y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsubf128(x: f64, y: f64) -> f64 { x - y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64subf64x(x: f64, y: f64) -> f64 { x - y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64subf128(x: f64, y: f64) -> f64 { x - y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xsubf128(x: f64, y: f64) -> f64 { x - y }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf32x(x: f64, y: f64, z: f64) -> f32 { let r = unsafe { fma(x, y, z) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf64(x: f64, y: f64, z: f64) -> f32 { let r = unsafe { fma(x, y, z) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf64x(x: f64, y: f64, z: f64) -> f32 { let r = unsafe { fma(x, y, z) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf128(x: f64, y: f64, z: f64) -> f32 { let r = unsafe { fma(x, y, z) }; r as f32 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xfmaf64(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xfmaf64x(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xfmaf128(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64fmaf64x(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64fmaf128(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xfmaf128(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }

// =========================================================================
// Internal glibc math helpers
// =========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fpclassifyl(x: f64) -> c_int { unsafe { __fpclassify(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iscanonicall(_x: f64) -> c_int { 1 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsig(x: f64, y: f64) -> c_int { if x == y { 1 } else { 0 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsigf(x: f32, y: f32) -> c_int { if x == y { 1 } else { 0 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsigl(x: f64, y: f64) -> c_int { if x == y { 1 } else { 0 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsigf128(x: f64, y: f64) -> c_int { if x == y { 1 } else { 0 } }

fn is_signaling_nan_f64(x: f64) -> bool {
    if !x.is_nan() { return false; }
    let bits = x.to_bits();
    (bits & 0x0008_0000_0000_0000) == 0 && (bits & 0x0007_FFFF_FFFF_FFFF) != 0
}
fn is_signaling_nan_f32(x: f32) -> bool {
    if !x.is_nan() { return false; }
    let bits = x.to_bits();
    (bits & 0x0040_0000) == 0 && (bits & 0x003F_FFFF) != 0
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignaling(x: f64) -> c_int { if is_signaling_nan_f64(x) { 1 } else { 0 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignalingf(x: f32) -> c_int { if is_signaling_nan_f32(x) { 1 } else { 0 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignalingl(x: f64) -> c_int { if is_signaling_nan_f64(x) { 1 } else { 0 } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignalingf128(x: f64) -> c_int { if is_signaling_nan_f64(x) { 1 } else { 0 } }

#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut signgam: c_int = 0;
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __signgam: c_int = 0;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn matherr(_exc: *mut std::ffi::c_void) -> c_int { 0 }

#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static _LIB_VERSION: c_int = 0;

// =========================================================================
// fenv extensions (glibc-specific) - delegate to host fenv
// =========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fedisableexcept(_excepts: c_int) -> c_int { -1 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feenableexcept(_excepts: c_int) -> c_int { -1 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetexcept() -> c_int { -1 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetexcept(_excepts: c_int) -> c_int { -1 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fetestexceptflag(_flagp: *const c_int, _excepts: c_int) -> c_int { -1 }

#[repr(C)]
pub struct FeMode {
    _data: [u8; 8],
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetmode(_modep: *mut FeMode) -> c_int { -1 }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetmode(_modep: *const FeMode) -> c_int { -1 }


// =========================================================================
// TS 18661 / C23 type-generic math width aliases
// =========================================================================
//
// Width mapping: f32→float, f32x→double, f64→double, f64x→f64, f128→f64
// On x86-64 we map long double and _Float128 to f64 (double precision).

// --- unary real (f64→f64, f32→f32) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf32(x: f32) -> f32 { unsafe { acosf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf32x(x: f64) -> f64 { unsafe { acos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf64(x: f64) -> f64 { unsafe { acos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf64x(x: f64) -> f64 { unsafe { acos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf128(x: f64) -> f64 { unsafe { acos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf32(x: f32) -> f32 { unsafe { acoshf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf32x(x: f64) -> f64 { unsafe { acosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf64(x: f64) -> f64 { unsafe { acosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf64x(x: f64) -> f64 { unsafe { acosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf128(x: f64) -> f64 { unsafe { acosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf32(x: f32) -> f32 { unsafe { asinf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf32x(x: f64) -> f64 { unsafe { asin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf64(x: f64) -> f64 { unsafe { asin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf64x(x: f64) -> f64 { unsafe { asin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf128(x: f64) -> f64 { unsafe { asin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf32(x: f32) -> f32 { unsafe { asinhf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf32x(x: f64) -> f64 { unsafe { asinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf64(x: f64) -> f64 { unsafe { asinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf64x(x: f64) -> f64 { unsafe { asinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf128(x: f64) -> f64 { unsafe { asinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf32(x: f32) -> f32 { unsafe { atanf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf32x(x: f64) -> f64 { unsafe { atan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf64(x: f64) -> f64 { unsafe { atan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf64x(x: f64) -> f64 { unsafe { atan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf128(x: f64) -> f64 { unsafe { atan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf32(x: f32) -> f32 { unsafe { atanhf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf32x(x: f64) -> f64 { unsafe { atanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf64(x: f64) -> f64 { unsafe { atanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf64x(x: f64) -> f64 { unsafe { atanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf128(x: f64) -> f64 { unsafe { atanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf32(x: f32) -> f32 { unsafe { cbrtf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf32x(x: f64) -> f64 { unsafe { cbrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf64(x: f64) -> f64 { unsafe { cbrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf64x(x: f64) -> f64 { unsafe { cbrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf128(x: f64) -> f64 { unsafe { cbrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf32(x: f32) -> f32 { unsafe { ceilf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf32x(x: f64) -> f64 { unsafe { ceil(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf64(x: f64) -> f64 { unsafe { ceil(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf64x(x: f64) -> f64 { unsafe { ceil(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf128(x: f64) -> f64 { unsafe { ceil(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf32(x: f32) -> f32 { unsafe { cosf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf32x(x: f64) -> f64 { unsafe { cos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf64(x: f64) -> f64 { unsafe { cos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf64x(x: f64) -> f64 { unsafe { cos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf128(x: f64) -> f64 { unsafe { cos(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf32(x: f32) -> f32 { unsafe { coshf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf32x(x: f64) -> f64 { unsafe { cosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf64(x: f64) -> f64 { unsafe { cosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf64x(x: f64) -> f64 { unsafe { cosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf128(x: f64) -> f64 { unsafe { cosh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff32(x: f32) -> f32 { unsafe { erff(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff32x(x: f64) -> f64 { unsafe { erf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff64(x: f64) -> f64 { unsafe { erf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff64x(x: f64) -> f64 { unsafe { erf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff128(x: f64) -> f64 { unsafe { erf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf32(x: f32) -> f32 { unsafe { erfcf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf32x(x: f64) -> f64 { unsafe { erfc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf64(x: f64) -> f64 { unsafe { erfc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf64x(x: f64) -> f64 { unsafe { erfc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf128(x: f64) -> f64 { unsafe { erfc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf32(x: f32) -> f32 { unsafe { expf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf32x(x: f64) -> f64 { unsafe { exp(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf64(x: f64) -> f64 { unsafe { exp(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf64x(x: f64) -> f64 { unsafe { exp(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf128(x: f64) -> f64 { unsafe { exp(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f32(x: f32) -> f32 { unsafe { exp10f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f32x(x: f64) -> f64 { unsafe { exp10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f64(x: f64) -> f64 { unsafe { exp10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f64x(x: f64) -> f64 { unsafe { exp10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f128(x: f64) -> f64 { unsafe { exp10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f32(x: f32) -> f32 { unsafe { exp2f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f32x(x: f64) -> f64 { unsafe { exp2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f64(x: f64) -> f64 { unsafe { exp2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f64x(x: f64) -> f64 { unsafe { exp2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f128(x: f64) -> f64 { unsafe { exp2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f32(x: f32) -> f32 { unsafe { expm1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f32x(x: f64) -> f64 { unsafe { expm1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f64(x: f64) -> f64 { unsafe { expm1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f64x(x: f64) -> f64 { unsafe { expm1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f128(x: f64) -> f64 { unsafe { expm1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf32(x: f32) -> f32 { unsafe { fabsf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf32x(x: f64) -> f64 { unsafe { fabs(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf64(x: f64) -> f64 { unsafe { fabs(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf64x(x: f64) -> f64 { unsafe { fabs(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf128(x: f64) -> f64 { unsafe { fabs(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf32(x: f32) -> f32 { unsafe { floorf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf32x(x: f64) -> f64 { unsafe { floor(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf64(x: f64) -> f64 { unsafe { floor(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf64x(x: f64) -> f64 { unsafe { floor(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf128(x: f64) -> f64 { unsafe { floor(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32(x: f32) -> f32 { unsafe { lgammaf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32x(x: f64) -> f64 { unsafe { lgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64(x: f64) -> f64 { unsafe { lgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64x(x: f64) -> f64 { unsafe { lgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf128(x: f64) -> f64 { unsafe { lgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf32(x: f32) -> f32 { unsafe { logf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf32x(x: f64) -> f64 { unsafe { log(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf64(x: f64) -> f64 { unsafe { log(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf64x(x: f64) -> f64 { unsafe { log(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf128(x: f64) -> f64 { unsafe { log(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f32(x: f32) -> f32 { unsafe { log10f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f32x(x: f64) -> f64 { unsafe { log10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f64(x: f64) -> f64 { unsafe { log10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f64x(x: f64) -> f64 { unsafe { log10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f128(x: f64) -> f64 { unsafe { log10(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf32(x: f32) -> f32 { unsafe { log1pf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf32x(x: f64) -> f64 { unsafe { log1p(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf64(x: f64) -> f64 { unsafe { log1p(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf64x(x: f64) -> f64 { unsafe { log1p(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf128(x: f64) -> f64 { unsafe { log1p(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f32(x: f32) -> f32 { unsafe { log2f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f32x(x: f64) -> f64 { unsafe { log2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f64(x: f64) -> f64 { unsafe { log2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f64x(x: f64) -> f64 { unsafe { log2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f128(x: f64) -> f64 { unsafe { log2(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf32(x: f32) -> f32 { unsafe { logbf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf32x(x: f64) -> f64 { unsafe { logb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf64(x: f64) -> f64 { unsafe { logb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf64x(x: f64) -> f64 { unsafe { logb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf128(x: f64) -> f64 { unsafe { logb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf32(x: f32) -> f32 { unsafe { nearbyintf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf32x(x: f64) -> f64 { unsafe { nearbyint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf64(x: f64) -> f64 { unsafe { nearbyint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf64x(x: f64) -> f64 { unsafe { nearbyint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf128(x: f64) -> f64 { unsafe { nearbyint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf32(x: f32) -> f32 { unsafe { rintf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf32x(x: f64) -> f64 { unsafe { rint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf64(x: f64) -> f64 { unsafe { rint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf64x(x: f64) -> f64 { unsafe { rint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf128(x: f64) -> f64 { unsafe { rint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf32(x: f32) -> f32 { unsafe { roundf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf32x(x: f64) -> f64 { unsafe { round(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf64(x: f64) -> f64 { unsafe { round(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf64x(x: f64) -> f64 { unsafe { round(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf128(x: f64) -> f64 { unsafe { round(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf32(x: f32) -> f32 { unsafe { sinf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf32x(x: f64) -> f64 { unsafe { sin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf64(x: f64) -> f64 { unsafe { sin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf64x(x: f64) -> f64 { unsafe { sin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf128(x: f64) -> f64 { unsafe { sin(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf32(x: f32) -> f32 { unsafe { sinhf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf32x(x: f64) -> f64 { unsafe { sinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf64(x: f64) -> f64 { unsafe { sinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf64x(x: f64) -> f64 { unsafe { sinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf128(x: f64) -> f64 { unsafe { sinh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf32(x: f32) -> f32 { unsafe { sqrtf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf32x(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf64(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf64x(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf128(x: f64) -> f64 { unsafe { sqrt(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf32(x: f32) -> f32 { unsafe { tanf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf32x(x: f64) -> f64 { unsafe { tan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf64(x: f64) -> f64 { unsafe { tan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf64x(x: f64) -> f64 { unsafe { tan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf128(x: f64) -> f64 { unsafe { tan(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf32(x: f32) -> f32 { unsafe { tanhf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf32x(x: f64) -> f64 { unsafe { tanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf64(x: f64) -> f64 { unsafe { tanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf64x(x: f64) -> f64 { unsafe { tanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf128(x: f64) -> f64 { unsafe { tanh(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf32(x: f32) -> f32 { unsafe { tgammaf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf32x(x: f64) -> f64 { unsafe { tgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf64(x: f64) -> f64 { unsafe { tgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf64x(x: f64) -> f64 { unsafe { tgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf128(x: f64) -> f64 { unsafe { tgamma(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf32(x: f32) -> f32 { unsafe { truncf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf32x(x: f64) -> f64 { unsafe { trunc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf64(x: f64) -> f64 { unsafe { trunc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf64x(x: f64) -> f64 { unsafe { trunc(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf128(x: f64) -> f64 { unsafe { trunc(x) } }

// --- binary real (f64,f64→f64, f32,f32→f32) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f32(x: f32, y: f32) -> f32 { unsafe { atan2f(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f32x(x: f64, y: f64) -> f64 { unsafe { atan2(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f64(x: f64, y: f64) -> f64 { unsafe { atan2(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f64x(x: f64, y: f64) -> f64 { unsafe { atan2(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f128(x: f64, y: f64) -> f64 { unsafe { atan2(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf32(x: f32, y: f32) -> f32 { unsafe { copysignf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf32x(x: f64, y: f64) -> f64 { unsafe { copysign(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf64(x: f64, y: f64) -> f64 { unsafe { copysign(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf64x(x: f64, y: f64) -> f64 { unsafe { copysign(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf128(x: f64, y: f64) -> f64 { unsafe { copysign(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf32(x: f32, y: f32) -> f32 { unsafe { fdimf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf32x(x: f64, y: f64) -> f64 { unsafe { fdim(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf64(x: f64, y: f64) -> f64 { unsafe { fdim(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf64x(x: f64, y: f64) -> f64 { unsafe { fdim(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf128(x: f64, y: f64) -> f64 { unsafe { fdim(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf32(x: f32, y: f32) -> f32 { unsafe { fmaxf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf32x(x: f64, y: f64) -> f64 { unsafe { fmax(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf64(x: f64, y: f64) -> f64 { unsafe { fmax(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf64x(x: f64, y: f64) -> f64 { unsafe { fmax(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf128(x: f64, y: f64) -> f64 { unsafe { fmax(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf32(x: f32, y: f32) -> f32 { unsafe { fminf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf32x(x: f64, y: f64) -> f64 { unsafe { fmin(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf64(x: f64, y: f64) -> f64 { unsafe { fmin(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf64x(x: f64, y: f64) -> f64 { unsafe { fmin(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf128(x: f64, y: f64) -> f64 { unsafe { fmin(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf32(x: f32, y: f32) -> f32 { unsafe { fmodf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf32x(x: f64, y: f64) -> f64 { unsafe { fmod(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf64(x: f64, y: f64) -> f64 { unsafe { fmod(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf64x(x: f64, y: f64) -> f64 { unsafe { fmod(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf128(x: f64, y: f64) -> f64 { unsafe { fmod(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf32(x: f32, y: f32) -> f32 { unsafe { hypotf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf32x(x: f64, y: f64) -> f64 { unsafe { hypot(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf64(x: f64, y: f64) -> f64 { unsafe { hypot(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf64x(x: f64, y: f64) -> f64 { unsafe { hypot(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf128(x: f64, y: f64) -> f64 { unsafe { hypot(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf32(x: f32, y: f32) -> f32 { unsafe { nextafterf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf32x(x: f64, y: f64) -> f64 { unsafe { nextafter(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf64(x: f64, y: f64) -> f64 { unsafe { nextafter(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf64x(x: f64, y: f64) -> f64 { unsafe { nextafter(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf128(x: f64, y: f64) -> f64 { unsafe { nextafter(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf32(x: f32, y: f32) -> f32 { unsafe { powf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf32x(x: f64, y: f64) -> f64 { unsafe { pow(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf64(x: f64, y: f64) -> f64 { unsafe { pow(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf64x(x: f64, y: f64) -> f64 { unsafe { pow(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf128(x: f64, y: f64) -> f64 { unsafe { pow(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf32(x: f32, y: f32) -> f32 { unsafe { remainderf(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf32x(x: f64, y: f64) -> f64 { unsafe { remainder(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf64(x: f64, y: f64) -> f64 { unsafe { remainder(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf64x(x: f64, y: f64) -> f64 { unsafe { remainder(x, y) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf128(x: f64, y: f64) -> f64 { unsafe { remainder(x, y) } }

// --- ternary real ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf32(x: f32, y: f32, z: f32) -> f32 { unsafe { fmaf(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf32x(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf64(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf64x(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf128(x: f64, y: f64, z: f64) -> f64 { unsafe { fma(x, y, z) } }

// --- unary → c_int ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf32(x: f32) -> c_int { unsafe { ilogbf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf32x(x: f64) -> c_int { unsafe { ilogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf64(x: f64) -> c_int { unsafe { ilogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf64x(x: f64) -> c_int { unsafe { ilogb(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf128(x: f64) -> c_int { unsafe { ilogb(x) } }

// --- unary → c_long ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf32(x: f32) -> c_long { unsafe { lrintf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf32x(x: f64) -> c_long { unsafe { lrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf64(x: f64) -> c_long { unsafe { lrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf64x(x: f64) -> c_long { unsafe { lrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf128(x: f64) -> c_long { unsafe { lrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf32(x: f32) -> c_long { unsafe { lroundf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf32x(x: f64) -> c_long { unsafe { lround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf64(x: f64) -> c_long { unsafe { lround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf64x(x: f64) -> c_long { unsafe { lround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf128(x: f64) -> c_long { unsafe { lround(x) } }

// --- unary → i64 ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf32(x: f32) -> i64 { unsafe { llrintf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf32x(x: f64) -> i64 { unsafe { llrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf64(x: f64) -> i64 { unsafe { llrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf64x(x: f64) -> i64 { unsafe { llrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf128(x: f64) -> i64 { unsafe { llrint(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf32(x: f32) -> i64 { unsafe { llroundf(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf32x(x: f64) -> i64 { unsafe { llround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf64(x: f64) -> i64 { unsafe { llround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf64x(x: f64) -> i64 { unsafe { llround(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf128(x: f64) -> i64 { unsafe { llround(x) } }

// --- frexp-like (f, *mut c_int → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf32(x: f32, exp: *mut c_int) -> f32 { unsafe { frexpf(x, exp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf32x(x: f64, exp: *mut c_int) -> f64 { unsafe { frexp(x, exp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf64(x: f64, exp: *mut c_int) -> f64 { unsafe { frexp(x, exp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf64x(x: f64, exp: *mut c_int) -> f64 { unsafe { frexp(x, exp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf128(x: f64, exp: *mut c_int) -> f64 { unsafe { frexp(x, exp) } }

// --- ldexp/scalbn-like (f, c_int → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf32(x: f32, n: c_int) -> f32 { unsafe { ldexpf(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf32x(x: f64, n: c_int) -> f64 { unsafe { ldexp(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf64(x: f64, n: c_int) -> f64 { unsafe { ldexp(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf64x(x: f64, n: c_int) -> f64 { unsafe { ldexp(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf128(x: f64, n: c_int) -> f64 { unsafe { ldexp(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf32(x: f32, n: c_int) -> f32 { unsafe { scalbnf(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf32x(x: f64, n: c_int) -> f64 { unsafe { scalbn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf64(x: f64, n: c_int) -> f64 { unsafe { scalbn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf64x(x: f64, n: c_int) -> f64 { unsafe { scalbn(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf128(x: f64, n: c_int) -> f64 { unsafe { scalbn(x, n) } }

// --- scalbln-like (f, c_long → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf32(x: f32, n: c_long) -> f32 { unsafe { scalblnf(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf32x(x: f64, n: c_long) -> f64 { unsafe { scalbln(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf64(x: f64, n: c_long) -> f64 { unsafe { scalbln(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf64x(x: f64, n: c_long) -> f64 { unsafe { scalbln(x, n) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf128(x: f64, n: c_long) -> f64 { unsafe { scalbln(x, n) } }

// --- modf-like (f, *mut f → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff32(x: f32, iptr: *mut f32) -> f32 { unsafe { modff(x, iptr) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff32x(x: f64, iptr: *mut f64) -> f64 { unsafe { modf(x, iptr) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff64(x: f64, iptr: *mut f64) -> f64 { unsafe { modf(x, iptr) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff64x(x: f64, iptr: *mut f64) -> f64 { unsafe { modf(x, iptr) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff128(x: f64, iptr: *mut f64) -> f64 { unsafe { modf(x, iptr) } }

// --- remquo-like (f, f, *mut c_int → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof32(x: f32, y: f32, quo: *mut c_int) -> f32 { unsafe { remquof(x, y, quo) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof32x(x: f64, y: f64, quo: *mut c_int) -> f64 { unsafe { remquo(x, y, quo) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof64(x: f64, y: f64, quo: *mut c_int) -> f64 { unsafe { remquo(x, y, quo) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof64x(x: f64, y: f64, quo: *mut c_int) -> f64 { unsafe { remquo(x, y, quo) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof128(x: f64, y: f64, quo: *mut c_int) -> f64 { unsafe { remquo(x, y, quo) } }

// --- sincos-like (f, *mut f, *mut f → void) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32(x: f32, s: *mut f32, c: *mut f32) { unsafe { sincosf(x, s, c) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32x(x: f64, s: *mut f64, c: *mut f64) { unsafe { sincos(x, s, c) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf64(x: f64, s: *mut f64, c: *mut f64) { unsafe { sincos(x, s, c) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf64x(x: f64, s: *mut f64, c: *mut f64) { unsafe { sincos(x, s, c) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf128(x: f64, s: *mut f64, c: *mut f64) { unsafe { sincos(x, s, c) } }

// --- nan-like (*const c_char → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf32(tagp: *const std::ffi::c_char) -> f32 { unsafe { nanf(tagp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf32x(tagp: *const std::ffi::c_char) -> f64 { unsafe { nan(tagp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf64(tagp: *const std::ffi::c_char) -> f64 { unsafe { nan(tagp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf64x(tagp: *const std::ffi::c_char) -> f64 { unsafe { nan(tagp) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf128(tagp: *const std::ffi::c_char) -> f64 { unsafe { nan(tagp) } }

// --- int-first (c_int, f → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf32(n: c_int, x: f32) -> f32 { unsafe { jnf(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf32x(n: c_int, x: f64) -> f64 { unsafe { jn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf64(n: c_int, x: f64) -> f64 { unsafe { jn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf64x(n: c_int, x: f64) -> f64 { unsafe { jn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf128(n: c_int, x: f64) -> f64 { unsafe { jn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf32(n: c_int, x: f32) -> f32 { unsafe { ynf(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf32x(n: c_int, x: f64) -> f64 { unsafe { yn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf64(n: c_int, x: f64) -> f64 { unsafe { yn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf64x(n: c_int, x: f64) -> f64 { unsafe { yn(n, x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf128(n: c_int, x: f64) -> f64 { unsafe { yn(n, x) } }

// --- Bessel no-int (f64→f64, f32→f32) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f32(x: f32) -> f32 { unsafe { j0f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f32x(x: f64) -> f64 { unsafe { j0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f64(x: f64) -> f64 { unsafe { j0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f64x(x: f64) -> f64 { unsafe { j0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f128(x: f64) -> f64 { unsafe { j0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f32(x: f32) -> f32 { unsafe { j1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f32x(x: f64) -> f64 { unsafe { j1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f64(x: f64) -> f64 { unsafe { j1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f64x(x: f64) -> f64 { unsafe { j1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f128(x: f64) -> f64 { unsafe { j1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f32(x: f32) -> f32 { unsafe { y0f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f32x(x: f64) -> f64 { unsafe { y0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f64(x: f64) -> f64 { unsafe { y0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f64x(x: f64) -> f64 { unsafe { y0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f128(x: f64) -> f64 { unsafe { y0(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f32(x: f32) -> f32 { unsafe { y1f(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f32x(x: f64) -> f64 { unsafe { y1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f64(x: f64) -> f64 { unsafe { y1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f64x(x: f64) -> f64 { unsafe { y1(x) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f128(x: f64) -> f64 { unsafe { y1(x) } }

// --- complex → real ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf32(z: CFloatComplex) -> f32 { unsafe { cabsf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf32x(z: CDoubleComplex) -> f64 { unsafe { cabs(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf64(z: CDoubleComplex) -> f64 { unsafe { cabs(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf64x(z: CDoubleComplex) -> f64 { unsafe { cabs(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf128(z: CDoubleComplex) -> f64 { unsafe { cabs(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf32(z: CFloatComplex) -> f32 { unsafe { cargf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf32x(z: CDoubleComplex) -> f64 { unsafe { carg(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf64(z: CDoubleComplex) -> f64 { unsafe { carg(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf64x(z: CDoubleComplex) -> f64 { unsafe { carg(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf128(z: CDoubleComplex) -> f64 { unsafe { carg(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf32(z: CFloatComplex) -> f32 { unsafe { cimagf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf32x(z: CDoubleComplex) -> f64 { unsafe { cimag(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf64(z: CDoubleComplex) -> f64 { unsafe { cimag(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf64x(z: CDoubleComplex) -> f64 { unsafe { cimag(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf128(z: CDoubleComplex) -> f64 { unsafe { cimag(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf32(z: CFloatComplex) -> f32 { unsafe { crealf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf32x(z: CDoubleComplex) -> f64 { unsafe { creal(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf64(z: CDoubleComplex) -> f64 { unsafe { creal(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf64x(z: CDoubleComplex) -> f64 { unsafe { creal(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf128(z: CDoubleComplex) -> f64 { unsafe { creal(z) } }

// --- complex → complex ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf32(z: CFloatComplex) -> CFloatComplex { unsafe { cacosf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf32(z: CFloatComplex) -> CFloatComplex { unsafe { cacoshf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { cacosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf32(z: CFloatComplex) -> CFloatComplex { unsafe { casinf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { casin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { casin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { casin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { casin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf32(z: CFloatComplex) -> CFloatComplex { unsafe { casinhf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { casinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { casinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { casinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { casinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf32(z: CFloatComplex) -> CFloatComplex { unsafe { catanf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { catan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { catan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { catan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { catan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf32(z: CFloatComplex) -> CFloatComplex { unsafe { catanhf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { catanh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { catanh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { catanh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { catanh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf32(z: CFloatComplex) -> CFloatComplex { unsafe { ccosf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccos(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf32(z: CFloatComplex) -> CFloatComplex { unsafe { ccoshf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { ccosh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf32(z: CFloatComplex) -> CFloatComplex { unsafe { cexpf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cexp(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { cexp(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cexp(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { cexp(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf32(z: CFloatComplex) -> CFloatComplex { unsafe { clogf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { clog(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf32(z: CFloatComplex) -> CFloatComplex { unsafe { conjf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { conj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { conj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { conj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { conj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf32(z: CFloatComplex) -> CFloatComplex { unsafe { cprojf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cproj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { cproj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { cproj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { cproj(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf32(z: CFloatComplex) -> CFloatComplex { unsafe { csinf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { csin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { csin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { csin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { csin(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf32(z: CFloatComplex) -> CFloatComplex { unsafe { csinhf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { csinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { csinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { csinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { csinh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf32(z: CFloatComplex) -> CFloatComplex { unsafe { csqrtf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { csqrt(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { csqrt(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { csqrt(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { csqrt(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf32(z: CFloatComplex) -> CFloatComplex { unsafe { ctanf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctan(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf32(z: CFloatComplex) -> CFloatComplex { unsafe { ctanhf(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf32x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctanh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf64(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctanh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf64x(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctanh(z) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf128(z: CDoubleComplex) -> CDoubleComplex { unsafe { ctanh(z) } }

// --- complex binary → complex ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf32(a: CFloatComplex, b: CFloatComplex) -> CFloatComplex { unsafe { cpowf(a, b) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf32x(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex { unsafe { cpow(a, b) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf64(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex { unsafe { cpow(a, b) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf64x(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex { unsafe { cpow(a, b) } }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf128(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex { unsafe { cpow(a, b) } }


// =========================================================================
// glibc __*_finite math aliases
// =========================================================================
//
// glibc exports __func_finite variants that assume finite input (gcc -ffinite-math-only).
// They forward to the regular math function since our implementations handle all cases.

macro_rules! finite_unary_f64 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f64) -> f64 { $target(x) }
    };
}

macro_rules! finite_unary_f32 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f32) -> f32 { $target(x) }
    };
}

macro_rules! finite_binary_f64 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f64, y: f64) -> f64 { $target(x, y) }
    };
}

macro_rules! finite_binary_f32 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f32, y: f32) -> f32 { $target(x, y) }
    };
}

// Unary f64 (double) _finite aliases
finite_unary_f64!(__acos_finite, frankenlibc_core::math::acos);
finite_unary_f64!(__acosh_finite, frankenlibc_core::math::acosh);
finite_unary_f64!(__asin_finite, frankenlibc_core::math::asin);
finite_unary_f64!(__atanh_finite, frankenlibc_core::math::atanh);
finite_unary_f64!(__cosh_finite, frankenlibc_core::math::cosh);
finite_unary_f64!(__exp_finite, frankenlibc_core::math::exp);
finite_unary_f64!(__exp2_finite, frankenlibc_core::math::exp2);
finite_unary_f64!(__exp10_finite, frankenlibc_core::math::exp10);
finite_unary_f64!(__log_finite, frankenlibc_core::math::log);
finite_unary_f64!(__log2_finite, frankenlibc_core::math::log2);
finite_unary_f64!(__log10_finite, frankenlibc_core::math::log10);
finite_unary_f64!(__sinh_finite, frankenlibc_core::math::sinh);
finite_unary_f64!(__sqrt_finite, frankenlibc_core::math::sqrt);
finite_unary_f64!(__j0_finite, frankenlibc_core::math::j0);
finite_unary_f64!(__j1_finite, frankenlibc_core::math::j1);
finite_unary_f64!(__y0_finite, frankenlibc_core::math::y0);
finite_unary_f64!(__y1_finite, frankenlibc_core::math::y1);

// Unary f32 (float) _finite aliases
finite_unary_f32!(__acosf_finite, frankenlibc_core::math::acosf);
finite_unary_f32!(__acoshf_finite, frankenlibc_core::math::acoshf);
finite_unary_f32!(__asinf_finite, frankenlibc_core::math::asinf);
finite_unary_f32!(__atanhf_finite, frankenlibc_core::math::atanhf);
finite_unary_f32!(__coshf_finite, frankenlibc_core::math::coshf);
finite_unary_f32!(__expf_finite, frankenlibc_core::math::expf);
finite_unary_f32!(__exp2f_finite, frankenlibc_core::math::exp2f);
finite_unary_f32!(__exp10f_finite, frankenlibc_core::math::exp10f);
finite_unary_f32!(__logf_finite, frankenlibc_core::math::logf);
finite_unary_f32!(__log2f_finite, frankenlibc_core::math::log2f);
finite_unary_f32!(__log10f_finite, frankenlibc_core::math::log10f);
finite_unary_f32!(__sinhf_finite, frankenlibc_core::math::sinhf);
finite_unary_f32!(__sqrtf_finite, frankenlibc_core::math::sqrtf);
finite_unary_f32!(__j0f_finite, frankenlibc_core::math::j0f);
finite_unary_f32!(__j1f_finite, frankenlibc_core::math::j1f);
finite_unary_f32!(__y0f_finite, frankenlibc_core::math::y0f);
finite_unary_f32!(__y1f_finite, frankenlibc_core::math::y1f);

// Long double _finite aliases (mapped to f64)
finite_unary_f64!(__acosl_finite, frankenlibc_core::math::acos);
finite_unary_f64!(__acoshl_finite, frankenlibc_core::math::acosh);
finite_unary_f64!(__asinl_finite, frankenlibc_core::math::asin);
finite_unary_f64!(__atanhl_finite, frankenlibc_core::math::atanh);
finite_unary_f64!(__coshl_finite, frankenlibc_core::math::cosh);
finite_unary_f64!(__expl_finite, frankenlibc_core::math::exp);
finite_unary_f64!(__exp2l_finite, frankenlibc_core::math::exp2);
finite_unary_f64!(__exp10l_finite, frankenlibc_core::math::exp10);
finite_unary_f64!(__logl_finite, frankenlibc_core::math::log);
finite_unary_f64!(__log2l_finite, frankenlibc_core::math::log2);
finite_unary_f64!(__log10l_finite, frankenlibc_core::math::log10);
finite_unary_f64!(__sinhl_finite, frankenlibc_core::math::sinh);
finite_unary_f64!(__sqrtl_finite, frankenlibc_core::math::sqrt);
finite_unary_f64!(__j0l_finite, frankenlibc_core::math::j0);
finite_unary_f64!(__j1l_finite, frankenlibc_core::math::j1);
finite_unary_f64!(__y0l_finite, frankenlibc_core::math::y0);
finite_unary_f64!(__y1l_finite, frankenlibc_core::math::y1);

// f128 _finite aliases (mapped to f64, Rust lacks f128)
finite_unary_f64!(__acosf128_finite, frankenlibc_core::math::acos);
finite_unary_f64!(__acoshf128_finite, frankenlibc_core::math::acosh);
finite_unary_f64!(__asinf128_finite, frankenlibc_core::math::asin);
finite_unary_f64!(__atanhf128_finite, frankenlibc_core::math::atanh);
finite_unary_f64!(__coshf128_finite, frankenlibc_core::math::cosh);
finite_unary_f64!(__expf128_finite, frankenlibc_core::math::exp);
finite_unary_f64!(__exp2f128_finite, frankenlibc_core::math::exp2);
finite_unary_f64!(__exp10f128_finite, frankenlibc_core::math::exp10);
finite_unary_f64!(__logf128_finite, frankenlibc_core::math::log);
finite_unary_f64!(__log2f128_finite, frankenlibc_core::math::log2);
finite_unary_f64!(__log10f128_finite, frankenlibc_core::math::log10);
finite_unary_f64!(__sinhf128_finite, frankenlibc_core::math::sinh);
finite_unary_f64!(__sqrtf128_finite, frankenlibc_core::math::sqrt);
finite_unary_f64!(__j0f128_finite, frankenlibc_core::math::j0);
finite_unary_f64!(__j1f128_finite, frankenlibc_core::math::j1);
finite_unary_f64!(__y0f128_finite, frankenlibc_core::math::y0);
finite_unary_f64!(__y1f128_finite, frankenlibc_core::math::y1);

// Binary f64 _finite aliases
finite_binary_f64!(__atan2_finite, frankenlibc_core::math::atan2);
finite_binary_f64!(__fmod_finite, frankenlibc_core::math::fmod);
finite_binary_f64!(__hypot_finite, frankenlibc_core::math::hypot);
finite_binary_f64!(__pow_finite, frankenlibc_core::math::pow);
finite_binary_f64!(__remainder_finite, frankenlibc_core::math::remainder);
// __scalb_finite: scalb(x, y) = x * 2^(int)y
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __scalb_finite(x: f64, y: f64) -> f64 { frankenlibc_core::math::scalbn(x, y as i32) }

// Binary f32 _finite aliases
finite_binary_f32!(__atan2f_finite, frankenlibc_core::math::atan2f);
finite_binary_f32!(__fmodf_finite, frankenlibc_core::math::fmodf);
finite_binary_f32!(__hypotf_finite, frankenlibc_core::math::hypotf);
finite_binary_f32!(__powf_finite, frankenlibc_core::math::powf);
finite_binary_f32!(__remainderf_finite, frankenlibc_core::math::remainderf);
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __scalbf_finite(x: f32, y: f32) -> f32 { frankenlibc_core::math::scalbnf(x, y as i32) }

// Binary long double _finite aliases
finite_binary_f64!(__atan2l_finite, frankenlibc_core::math::atan2);
finite_binary_f64!(__fmodl_finite, frankenlibc_core::math::fmod);
finite_binary_f64!(__hypotl_finite, frankenlibc_core::math::hypot);
finite_binary_f64!(__powl_finite, frankenlibc_core::math::pow);
finite_binary_f64!(__remainderl_finite, frankenlibc_core::math::remainder);
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __scalbl_finite(x: f64, y: f64) -> f64 { frankenlibc_core::math::scalbn(x, y as i32) }

// Binary f128 _finite aliases
finite_binary_f64!(__atan2f128_finite, frankenlibc_core::math::atan2);
finite_binary_f64!(__fmodf128_finite, frankenlibc_core::math::fmod);
finite_binary_f64!(__hypotf128_finite, frankenlibc_core::math::hypot);
finite_binary_f64!(__powf128_finite, frankenlibc_core::math::pow);
finite_binary_f64!(__remainderf128_finite, frankenlibc_core::math::remainder);

// jn/yn take (int, double) signature
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jn_finite(n: c_int, x: f64) -> f64 { frankenlibc_core::math::jn(n, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jnf_finite(n: c_int, x: f32) -> f32 { frankenlibc_core::math::jnf(n, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jnl_finite(n: c_int, x: f64) -> f64 { frankenlibc_core::math::jn(n, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jnf128_finite(n: c_int, x: f64) -> f64 { frankenlibc_core::math::jn(n, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __yn_finite(n: c_int, x: f64) -> f64 { frankenlibc_core::math::yn(n, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ynf_finite(n: c_int, x: f32) -> f32 { frankenlibc_core::math::ynf(n, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ynl_finite(n: c_int, x: f64) -> f64 { frankenlibc_core::math::yn(n, x) }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ynf128_finite(n: c_int, x: f64) -> f64 { frankenlibc_core::math::yn(n, x) }

// lgamma_r/gamma_r _finite aliases take (double, *int) -> double
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __lgamma_r_finite(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { crate::math_abi::lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __lgammaf_r_finite(x: f32, signgamp: *mut c_int) -> f32 {
    unsafe { crate::math_abi::lgammaf_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __lgammal_r_finite(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { crate::math_abi::lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __lgammaf128_r_finite(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { crate::math_abi::lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gamma_r_finite(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { crate::math_abi::lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gammaf_r_finite(x: f32, signgamp: *mut c_int) -> f32 {
    unsafe { crate::math_abi::lgammaf_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gammal_r_finite(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { crate::math_abi::lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gammaf128_r_finite(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { crate::math_abi::lgamma_r(x, signgamp) }
}

// __finite classification variants (f128)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __finitef128(x: f64) -> c_int {
    frankenlibc_core::math::finite(x)
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

    // -----------------------------------------------------------------------
    // C23 fmaximum / fminimum tests
    // -----------------------------------------------------------------------

    #[test]
    fn fmaximum_basic_ordering() {
        unsafe {
            assert_eq!(fmaximum(3.0, 5.0), 5.0);
            assert_eq!(fmaximum(-1.0, -2.0), -1.0);
            assert!(fmaximum(f64::NAN, 1.0).is_nan()); // NaN propagates
            assert!(fmaximum(1.0, f64::NAN).is_nan());
        }
    }

    #[test]
    fn fmaximum_signed_zero() {
        unsafe {
            // -0 < +0 per IEEE 754-2019
            let r = fmaximum(0.0, -0.0);
            assert_eq!(r, 0.0);
            assert!(!r.is_sign_negative());
            let r2 = fmaximum(-0.0, 0.0);
            assert_eq!(r2, 0.0);
            assert!(!r2.is_sign_negative());
        }
    }

    #[test]
    fn fmaximum_num_nan_handling() {
        unsafe {
            assert_eq!(fmaximum_num(f64::NAN, 1.0), 1.0);
            assert_eq!(fmaximum_num(1.0, f64::NAN), 1.0);
            assert!(fmaximum_num(f64::NAN, f64::NAN).is_nan());
        }
    }

    #[test]
    fn fmaximum_mag_by_absolute_value() {
        unsafe {
            assert_eq!(fmaximum_mag(3.0, -5.0), -5.0); // |-5| > |3|
            assert_eq!(fmaximum_mag(-1.0, 0.5), -1.0); // |-1| > |0.5|
        }
    }

    #[test]
    fn fminimum_basic_ordering() {
        unsafe {
            assert_eq!(fminimum(3.0, 5.0), 3.0);
            assert_eq!(fminimum(-1.0, -2.0), -2.0);
            assert!(fminimum(f64::NAN, 1.0).is_nan());
        }
    }

    #[test]
    fn fminimum_signed_zero() {
        unsafe {
            // -0 < +0 per IEEE 754-2019
            let r = fminimum(0.0, -0.0);
            assert_eq!(r, 0.0);
            assert!(r.is_sign_negative());
            let r2 = fminimum(-0.0, 0.0);
            assert_eq!(r2, 0.0);
            assert!(r2.is_sign_negative());
        }
    }

    #[test]
    fn fminimum_num_nan_handling() {
        unsafe {
            assert_eq!(fminimum_num(f64::NAN, 1.0), 1.0);
            assert_eq!(fminimum_num(1.0, f64::NAN), 1.0);
            assert!(fminimum_num(f64::NAN, f64::NAN).is_nan());
        }
    }

    #[test]
    fn fminimum_mag_by_absolute_value() {
        unsafe {
            assert_eq!(fminimum_mag(3.0, -5.0), 3.0); // |3| < |-5|
            assert_eq!(fminimum_mag(-1.0, 0.5), 0.5); // |0.5| < |-1|
        }
    }

    #[test]
    fn fmaximum_f32_variants_consistent() {
        unsafe {
            assert_eq!(fmaximumf(3.0f32, 5.0f32), 5.0f32);
            assert_eq!(fmaximumf32(3.0f32, 5.0f32), 5.0f32);
            assert!(fmaximumf(f32::NAN, 1.0f32).is_nan());
        }
    }
}
