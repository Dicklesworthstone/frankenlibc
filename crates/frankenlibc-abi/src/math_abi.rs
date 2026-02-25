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
    if x.is_finite() {
        if x <= 0.0 && x == x.floor() {
            set_domain_errno();
        } else if out.is_infinite() {
            set_range_errno();
        }
    }
    out
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
}
