//! ABI layer for `<math.h>` functions.
//!
//! These entrypoints feed the runtime math kernel (`ApiFamily::MathFenv`)
//! so numeric exceptional regimes (NaN/Inf/denormal patterns) participate
//! in the same strict/hardened control loop as memory and concurrency paths.

use std::ffi::c_int;
use std::os::raw::c_long;

use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

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

/// Unbiased base-2 exponent of a finite, nonzero binary128 value (its `logb`),
/// handling subnormals via the mantissa's leading-zero count. Caller guarantees
/// the value is finite and nonzero.
#[inline]
fn f128_unbiased_exp(bits: u128) -> i32 {
    let exp_field = ((bits >> 112) & 0x7fff) as i32;
    if exp_field == 0 {
        // Subnormal: value = mantissa * 2^-16494; the leading set bit fixes the
        // exponent. mantissa is a 112-bit value held in a u128.
        let mant = bits & ((1u128 << 112) - 1);
        -16367 - (mant.leading_zeros() as i32)
    } else {
        exp_field - 16383
    }
}

/// Round to integral, nearest-even — for `rintf128`. glibc's `__rintf128` rounds
/// to nearest-even REGARDLESS of the dynamic FP rounding mode (verified: under
/// FE_DOWNWARD, rintf128(1.5) is still 2.0), unlike nearbyint/lrint/llrint which
/// do honor the mode. We match that quirk.
fn round_f128_nearest(x: f128) -> f128 {
    x.round_ties_even()
}

/// Round to integral in the current FP rounding direction — for
/// nearbyint/lrint/llrint, which (unlike rintf128) honor the FE_* mode.
fn round_f128_current_mode(x: f128) -> f128 {
    // x86 FE_*: TONEAREST=0, DOWNWARD=0x400, UPWARD=0x800, TOWARDZERO=0xc00.
    match unsafe { crate::fenv_abi::fegetround() } {
        0x400 => x.floor(),
        0x800 => x.ceil(),
        0xc00 => x.trunc(),
        _ => x.round_ties_even(),
    }
}

/// Convert an already-integral binary128 to i64, saturating like glibc's
/// lround/lrint: NaN and positive overflow -> i64::MAX, negative overflow ->
/// i64::MIN (no errno; FE_INVALID only).
fn f128_to_i64_sat(r: f128) -> i64 {
    if r.is_nan() {
        i64::MAX
    } else {
        r as i64 // saturating float->int cast
    }
}

/// Round a binary128 to integral per a C23 `FP_INT_*` direction argument:
/// 0=UPWARD, 1=DOWNWARD, 2=TOWARDZERO, 3=TONEARESTFROMZERO (half away from zero),
/// 4=TONEAREST (half to even). Used by the fromfp family.
fn round_dir_f128(x: f128, rnd: c_int) -> f128 {
    match rnd {
        0 => x.ceil(),
        1 => x.floor(),
        2 => x.trunc(),
        3 => x.round(),
        _ => x.round_ties_even(),
    }
}

/// `fromfp`/`fromfpx` core for binary128 -> intmax_t. Rounds per `rnd`, then if
/// the result is out of the signed `width`-bit range (or x is non-finite),
/// raises EDOM and SATURATES (positive/NaN -> max, negative -> min), matching
/// glibc. (fromfpx additionally raises FE_INEXACT, which we leave to the FPU.)
fn fromfp_signed_f128(x: f128, rnd: c_int, width: u32) -> i64 {
    if width == 0 {
        // A 0-bit integer has no representable values: always a range error.
        unsafe { set_abi_errno(libc::EDOM) };
        return 0;
    }
    let smax: i64 = if width >= 64 {
        i64::MAX
    } else {
        (1i64 << (width - 1)) - 1
    };
    let smin: i64 = if width >= 64 {
        i64::MIN
    } else {
        -(1i64 << (width - 1))
    };
    if x.is_nan() {
        unsafe { set_abi_errno(libc::EDOM) };
        return smax;
    }
    let r = round_dir_f128(x, rnd);
    if r.is_infinite() {
        unsafe { set_abi_errno(libc::EDOM) };
        return if r > 0.0 { smax } else { smin };
    }
    if r > smax as f128 {
        unsafe { set_abi_errno(libc::EDOM) };
        return smax;
    }
    if r < smin as f128 {
        unsafe { set_abi_errno(libc::EDOM) };
        return smin;
    }
    r as i64
}

/// `ufromfp`/`ufromfpx` core for binary128 -> uintmax_t. Negative results clamp
/// to 0, overflow clamps to the unsigned `width`-bit max, both with EDOM.
fn fromfp_unsigned_f128(x: f128, rnd: c_int, width: u32) -> u64 {
    if width == 0 {
        // A 0-bit integer has no representable values: always a range error.
        unsafe { set_abi_errno(libc::EDOM) };
        return 0;
    }
    let umax: u64 = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    if x.is_nan() {
        unsafe { set_abi_errno(libc::EDOM) };
        return umax;
    }
    let r = round_dir_f128(x, rnd);
    if r.is_infinite() {
        unsafe { set_abi_errno(libc::EDOM) };
        return if r > 0.0 { umax } else { 0 };
    }
    if r < 0.0 {
        unsafe { set_abi_errno(libc::EDOM) };
        return 0;
    }
    if r > umax as f128 {
        unsafe { set_abi_errno(libc::EDOM) };
        return umax;
    }
    r as u64
}

/// nextafter/nexttoward range-error rule, matching glibc: ERANGE on overflow
/// (finite x -> infinite result) and on underflow (result subnormal-or-zero AND
/// magnitude decreased). nextafter(0, y) -> smallest subnormal is NOT an
/// underflow (magnitude increased from 0), so it sets no errno.
#[inline]
fn nextafter_range_error_f64(x: f64, r: f64) -> bool {
    if x.is_nan() || r.is_nan() {
        return false;
    }
    if x.is_finite() && r.is_infinite() {
        return true; // overflow
    }
    let sub_or_zero = r == 0.0 || r.abs() < f64::MIN_POSITIVE;
    sub_or_zero && r.abs() < x.abs() // underflow (magnitude decreased)
}

#[inline]
fn nextafter_range_error_f32(x: f32, r: f32) -> bool {
    if x.is_nan() || r.is_nan() {
        return false;
    }
    if x.is_finite() && r.is_infinite() {
        return true;
    }
    let sub_or_zero = r == 0.0 || r.abs() < f32::MIN_POSITIVE;
    sub_or_zero && r.abs() < x.abs()
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
    // Determine errno to set (if any) BEFORE returning, to ensure no
    // subsequent operation clobbers it.
    let errno_val = if x.is_finite() && y.is_finite() {
        if x == 0.0 && y < 0.0 {
            Some(libc::ERANGE)
        } else if x < 0.0 && !is_integral_f64(y) {
            Some(libc::EDOM)
        } else if out.is_infinite() || (out == 0.0 && x != 0.0) {
            Some(libc::ERANGE)
        } else {
            None
        }
    } else {
        None
    };
    if let Some(e) = errno_val {
        unsafe { set_abi_errno(e) };
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

/// Round to nearest integer, ties AWAY from zero (C `round`), in the integer
/// (bit) domain so it raises NO floating-point exceptions — matching glibc.
///
/// `frankenlibc_core::math::round` delegates to `libm::round`, whose `+0.5`
/// arithmetic spuriously raises FE_INEXACT on every non-integer argument;
/// glibc's `round` is an exact integral operation that raises nothing. We
/// override the kernel here (rather than in core) because the f32 sibling lives
/// in a core file currently reserved by another agent — keeping both kernels
/// together in the ABI layer is the conflict-free, symmetric home. Pinned by
/// `conformance_diff_round_exact_flags`.
fn round_exact(x: f64) -> f64 {
    let bits = x.to_bits();
    let sign = bits & 0x8000_0000_0000_0000;
    let e = ((bits >> 52) & 0x7ff) as i32;
    if e >= 1023 + 52 {
        // |x| >= 2^52 (and inf/NaN): already integral.
        return x;
    }
    if e < 1023 {
        // |x| < 1: ±0 (|x| < 0.5) or ±1 (|x| >= 0.5, ties away from zero).
        let mag = f64::from_bits(bits & 0x7fff_ffff_ffff_ffff);
        let r = if mag >= 0.5 { 1.0_f64 } else { 0.0_f64 };
        return f64::from_bits(r.to_bits() | sign);
    }
    let frac_bits = 1075 - e;
    let half = 1u64 << (frac_bits - 1);
    let frac_mask = (1u64 << frac_bits) - 1;
    let int_part = bits & !frac_mask;
    let out = if (bits & frac_mask) >= half {
        int_part + (1u64 << frac_bits)
    } else {
        int_part
    };
    f64::from_bits(out)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn round(x: f64) -> f64 {
    unary_entry(x, 4, round_exact)
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
    let had_inexact = exact_op_inexact_guard();
    let out = binary_entry(x, y, 6, frankenlibc_core::math::fmod);
    exact_op_clear_inexact(had_inexact);
    // glibc EDOM rule: x infinite OR y zero, with neither operand NaN. The old
    // guard missed fmod(±inf,±inf) and wrongly set EDOM for fmod(NaN, 0).
    if !x.is_nan() && !y.is_nan() && (x.is_infinite() || y == 0.0) {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainder(x: f64, y: f64) -> f64 {
    let had_inexact = exact_op_inexact_guard();
    let out = binary_entry(x, y, 6, frankenlibc_core::math::remainder);
    exact_op_clear_inexact(had_inexact);
    // glibc EDOM rule: x infinite OR y zero, neither operand NaN (see fmod).
    if !x.is_nan() && !y.is_nan() && (x.is_infinite() || y == 0.0) {
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
    // Compute via reentrant version to get sign, then update global signgam.
    let (_, sign) = frankenlibc_core::math::lgamma_r(x);
    unsafe {
        signgam = sign;
        __signgam = sign;
    }
    // Run through unary_entry for membrane accounting. lgamma computes
    // the same value as lgamma_r; the sign is a side-channel.
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

/// `nearbyint` rounds to integer in the CURRENT rounding mode but, unlike
/// `rint`, must NOT raise FE_INEXACT — that suppression is the sole difference
/// between the two. fl's kernel delegates to `libm::rint` (which honors the
/// mode for the value but raises FE_INEXACT), so we compute the value then
/// clear FE_INEXACT iff it was not already set before the call. Pre-existing
/// flags and any FE_INVALID (e.g. a signaling-NaN argument) are preserved.
/// Pinned by conformance_diff_nearbyint_flags.
fn nearbyint_no_inexact(x: f64) -> f64 {
    let had_inexact = unsafe { fetestexcept(FE_INEXACT_BIT) } & FE_INEXACT_BIT;
    let r = frankenlibc_core::math::nearbyint(x);
    if had_inexact == 0 {
        unsafe { feclearexcept(FE_INEXACT_BIT) };
    }
    r
}
fn nearbyintf_no_inexact(x: f32) -> f32 {
    let had_inexact = unsafe { fetestexcept(FE_INEXACT_BIT) } & FE_INEXACT_BIT;
    let r = frankenlibc_core::math::nearbyintf(x);
    if had_inexact == 0 {
        unsafe { feclearexcept(FE_INEXACT_BIT) };
    }
    r
}

/// fmod/remainder/remquo/drem are EXACT operations: they raise FE_INVALID on a
/// domain error (y == 0 or x infinite) but must NEVER raise FE_INEXACT. fl's
/// kernel/membrane can leave a spurious FE_INEXACT on the NaN-producing domain
/// path (glibc raises FE_INVALID only), so the wrappers snapshot FE_INEXACT on
/// entry and clear it iff it was not already set by the caller. Pinned by
/// conformance_diff_fmod_rem_flags.
#[inline]
fn exact_op_inexact_guard() -> c_int {
    let raised = unsafe { fetestexcept(FE_INEXACT_BIT) };
    raised & FE_INEXACT_BIT
}
#[inline]
fn exact_op_clear_inexact(had_inexact: c_int) {
    if had_inexact == 0 {
        unsafe { feclearexcept(FE_INEXACT_BIT) };
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyint(x: f64) -> f64 {
    unary_entry(x, 3, nearbyint_no_inexact)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrint(x: f64) -> i64 {
    frankenlibc_core::math::lrint(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrint(x: f64) -> i64 {
    frankenlibc_core::math::llrint(x)
}

/// Convert an already-integral `f64` to `i64` with glibc's x86 `cvtsd2si`
/// semantics: out-of-range / NaN yields the "integer indefinite" `i64::MIN`.
/// `r` is integral (produced by [`round_exact`]), so the cast raises no
/// FE_INEXACT, and the range guard means no out-of-range conversion is ever
/// attempted. Used by lround/llround/lroundf/llroundf so they stay exception-
/// free — C F.10.6.5 specifies the l*round family does NOT raise FE_INEXACT,
/// but `frankenlibc_core::math::lround` routes through `libm::round` whose
/// `+0.5` arithmetic spuriously raised it.
fn integral_f64_to_i64(r: f64) -> i64 {
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    if r.is_nan() || !(-TWO_POW_63..TWO_POW_63).contains(&r) {
        i64::MIN
    } else {
        r as i64
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lround(x: f64) -> i64 {
    integral_f64_to_i64(round_exact(x))
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llround(x: f64) -> i64 {
    integral_f64_to_i64(round_exact(x))
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
    // glibc's fmax lowers to the hardware MAXSD instruction, which on a signed-
    // zero tie (both operands ±0) returns the SECOND operand. libm's fmax
    // returns the first, so fmax(-0,+0) gave -0 where glibc gives +0. Mirror
    // the MAXSD tie-break. Pinned by conformance_diff_exact_unary_flags.
    if x == 0.0 && y == 0.0 {
        return y;
    }
    frankenlibc_core::math::fmax(x, y)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdim(x: f64, y: f64) -> f64 {
    let out = frankenlibc_core::math::fdim(x, y);
    // fdim overflow (finite inputs, infinite difference) is a range error.
    if x.is_finite() && y.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    // Strict mode fast path: skip runtime policy overhead entirely.
    if runtime_policy::strict_passthrough_active() {
        return frankenlibc_core::math::fma(x, y, z);
    }

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

#[inline]
pub(crate) fn scalb_svid_impl(x: f64, exp: f64) -> f64 {
    if x.is_nan() || exp.is_nan() {
        return x * exp;
    }
    if !exp.is_finite() {
        let out = if exp > 0.0 { x * exp } else { x / (-exp) };
        if out.is_nan() {
            set_domain_errno();
        }
        return out;
    }
    if exp != exp.trunc() {
        set_domain_errno();
        return core::hint::black_box(0.0_f64) / core::hint::black_box(-0.0_f64);
    }
    let n = if exp > 65000.0 {
        65000
    } else if exp < -65000.0 {
        -65000
    } else {
        exp as i32
    };
    let out = frankenlibc_core::math::scalbn(x, n);
    if scaling_range_error_f64(x, out) {
        set_range_errno();
    }
    out
}

#[inline]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn scalbf_svid_impl(x: f32, exp: f32) -> f32 {
    if x.is_nan() || exp.is_nan() {
        return x * exp;
    }
    if !exp.is_finite() {
        let out = if exp > 0.0 { x * exp } else { x / (-exp) };
        if out.is_nan() {
            set_domain_errno();
        }
        return out;
    }
    if exp != exp.trunc() {
        set_domain_errno();
        return core::hint::black_box(0.0_f32) / core::hint::black_box(-0.0_f32);
    }
    let n = if exp > 65000.0 {
        65000
    } else if exp < -65000.0 {
        -65000
    } else {
        exp as i32
    };
    let out = frankenlibc_core::math::scalbnf(x, n);
    if scaling_range_error_f32(x, out) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafter(x: f64, y: f64) -> f64 {
    let out = frankenlibc_core::math::nextafter(x, y);
    if nextafter_range_error_f64(x, out) {
        set_range_errno();
    }
    out
}

/// C99 `nexttoward`: next representable f64 toward a long-double direction.
/// Non-x86_64 builds use the Rust test-time f64 direction approximation.
#[cfg_attr(
    all(not(debug_assertions), not(target_arch = "x86_64")),
    unsafe(no_mangle)
)]
pub unsafe extern "C" fn nexttoward(x: f64, y: f64) -> f64 {
    let out = frankenlibc_core::math::nexttoward(x, y);
    if nextafter_range_error_f64(x, out) {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogb(x: f64) -> c_int {
    frankenlibc_core::math::ilogb(x)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logb(x: f64) -> f64 {
    // glibc raises the FE_DIVBYZERO flag for logb(0) (handled in core) but does
    // NOT set errno — leave errno untouched to match.
    frankenlibc_core::math::logb(x)
}

// ---------------------------------------------------------------------------
// remquo — remainder with quotient
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquo(x: f64, y: f64, quo: *mut c_int) -> f64 {
    let had_inexact = exact_op_inexact_guard();
    let (rem, q) = frankenlibc_core::math::remquo(x, y);
    exact_op_clear_inexact(had_inexact);
    if !quo.is_null() {
        // SAFETY: caller guarantees `quo` points to valid writable `int`.
        unsafe { *quo = q };
    }
    // Unlike fmod/remainder (SVID functions with an errno wrapper), C99 remquo
    // has NO errno wrapper in glibc: it sets errno on no input (only the
    // FE_INVALID flag for domain cases). fl previously set a spurious EDOM.
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
pub unsafe extern "C" fn nan(tagp: *const std::ffi::c_char) -> f64 {
    let tag: &[u8] = if tagp.is_null() {
        b""
    } else {
        // SAFETY: per the C contract `tagp` is a valid NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(tagp) }.to_bytes()
    };
    frankenlibc_core::math::nan(tag)
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
    if x == 0.0 {
        // Y_n(0) = -inf is a pole: glibc reports a range error (ERANGE), not a
        // domain error. Only x < 0 (Y undefined for negative reals) is EDOM.
        set_range_errno();
    } else if x < 0.0 && x.is_finite() {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1(x: f64) -> f64 {
    let out = unary_entry(x, 12, frankenlibc_core::math::y1);
    if x == 0.0 {
        // Y_n(0) = -inf is a pole: glibc reports a range error (ERANGE), not a
        // domain error. Only x < 0 (Y undefined for negative reals) is EDOM.
        set_range_errno();
    } else if x < 0.0 && x.is_finite() {
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
    if x == 0.0 {
        // Y_n(0) = -inf is a pole: glibc reports a range error (ERANGE), not a
        // domain error. Only x < 0 (Y undefined for negative reals) is EDOM.
        set_range_errno();
    } else if x < 0.0 && x.is_finite() {
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
    let had_inexact = exact_op_inexact_guard();
    let out = binary_entry(x, y, 6, frankenlibc_core::math::drem);
    exact_op_clear_inexact(had_inexact);
    // glibc EDOM rule for remainder: a genuine domain error (x infinite OR y
    // zero) with NEITHER operand NaN. The old guard both missed drem(±inf,±inf)
    // (it required y finite) and wrongly set EDOM for drem(NaN, 0) (a NaN
    // operand must leave errno at 0).
    if !x.is_nan() && !y.is_nan() && (x.is_infinite() || y == 0.0) {
        set_domain_errno();
    }
    out
}

/// BSD `gamma()` — alias for `lgamma()`. Like `lgamma`, it sets the global
/// `signgam` to the sign of Γ(x); fl previously left signgam stale.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gamma(x: f64) -> f64 {
    let (_, sign) = frankenlibc_core::math::lgamma_r(x);
    unsafe {
        signgam = sign;
        __signgam = sign;
    }
    let out = unary_entry(x, 10, frankenlibc_core::math::gamma);
    if x.is_finite() && (x == 0.0 || (x < 0.0 && is_integral_f64(x)) || out.is_infinite()) {
        set_range_errno();
    }
    out
}

/// Extract significand scaled to [1, 2).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn significand(x: f64) -> f64 {
    // significand(0) has no normalized mantissa: glibc reports EDOM.
    if x == 0.0 {
        set_domain_errno();
    }
    let out = frankenlibc_core::math::significand(x);
    // glibc significand(x) = scalbn(x, -ilogb(x)); ilogb(0/inf/NaN) raises
    // FE_INVALID, which propagates. fl's core leaves the flag unset, so re-raise
    // it on the cold path for the three special-input classes.
    if x == 0.0 || !x.is_finite() {
        pi_fn_raise_invalid_f64();
    }
    out
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
        } else if out.is_infinite() || (x == 0.0 && y < 0.0) || (out == 0.0 && x != 0.0) {
            // Range error: overflow (inf), pole at x==0 with y<0, or underflow
            // to zero. Mirrors f64 `pow`; the underflow case applies regardless
            // of the exponent's sign (an earlier `y > 0.0` guard wrongly skipped
            // negative-exponent underflow, e.g. powf(2, -200), which glibc flags).
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

/// f32 sibling of [`round_exact`]: ties away from zero, exception-free. See
/// that function for why the kernel lives in the ABI layer.
fn roundf_exact(x: f32) -> f32 {
    let bits = x.to_bits();
    let sign = bits & 0x8000_0000;
    let e = ((bits >> 23) & 0xff) as i32;
    if e >= 127 + 23 {
        return x;
    }
    if e < 127 {
        let mag = f32::from_bits(bits & 0x7fff_ffff);
        let r = if mag >= 0.5 { 1.0_f32 } else { 0.0_f32 };
        return f32::from_bits(r.to_bits() | sign);
    }
    let frac_bits = 150 - e;
    let half = 1u32 << (frac_bits - 1);
    let frac_mask = (1u32 << frac_bits) - 1;
    let int_part = bits & !frac_mask;
    let out = if (bits & frac_mask) >= half {
        int_part + (1u32 << frac_bits)
    } else {
        int_part
    };
    f32::from_bits(out)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf(x: f32) -> f32 {
    unary_entry_f32(x, 3, roundf_exact)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf(x: f32) -> f32 {
    unary_entry_f32(x, 3, frankenlibc_core::math::truncf)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    let had_inexact = exact_op_inexact_guard();
    let out = binary_entry_f32(x, y, 6, frankenlibc_core::math::fmodf);
    exact_op_clear_inexact(had_inexact);
    // Same glibc EDOM rule as fmod (see fmod for the two prior-guard bugs).
    if !x.is_nan() && !y.is_nan() && (x.is_infinite() || y == 0.0) {
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
    // glibc does not set errno for logbf(0) (only the FE_DIVBYZERO flag).
    unary_entry_f32(x, 4, frankenlibc_core::math::logbf)
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
        if x < 0.0 && x == x.floor() {
            set_domain_errno(); // negative integer: domain error
        } else if x == 0.0 || out.is_infinite() || out == 0.0 {
            set_range_errno(); // zero or overflow/underflow: range error
        }
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf(x: f32) -> f32 {
    // Compute via reentrant version to get sign, then update global signgam.
    let (_, sign) = frankenlibc_core::math::lgammaf_r(x);
    unsafe {
        signgam = sign;
        __signgam = sign;
    }
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
    let out = binary_entry_f32(x, y, 3, frankenlibc_core::math::fdimf);
    // fdim overflow (finite inputs, infinite difference) is a range error.
    if x.is_finite() && y.is_finite() && out.is_infinite() {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf(x: f32, y: f32) -> f32 {
    // glibc fmaxf lowers to MAXSS: a signed-zero tie returns the SECOND operand
    // (see fmax). libm's fmaxf returns the first.
    if x == 0.0 && y == 0.0 {
        return y;
    }
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
    let had_inexact = exact_op_inexact_guard();
    let out = binary_entry_f32(x, y, 5, frankenlibc_core::math::remainderf);
    exact_op_clear_inexact(had_inexact);
    // Same glibc EDOM rule as fmod/remainder.
    if !x.is_nan() && !y.is_nan() && (x.is_infinite() || y == 0.0) {
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
    unary_entry_f32(x, 3, nearbyintf_no_inexact)
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
    integral_f64_to_i64(roundf_exact(x) as f64) as c_long
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf(x: f32) -> i64 {
    integral_f64_to_i64(roundf_exact(x) as f64)
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
    let out = binary_entry_f32(x, y, 3, frankenlibc_core::math::nextafterf);
    if nextafter_range_error_f32(x, out) {
        set_range_errno();
    }
    out
}

/// C99 `nexttowardf`: next representable f32 toward a long-double direction.
#[cfg_attr(
    all(not(debug_assertions), not(target_arch = "x86_64")),
    unsafe(no_mangle)
)]
pub unsafe extern "C" fn nexttowardf(x: f32, y: f64) -> f32 {
    let out = frankenlibc_core::math::nexttowardf(x, y);
    if nextafter_range_error_f32(x, out) {
        set_range_errno();
    }
    out
}

#[cfg(all(target_arch = "x86_64", any(not(debug_assertions), test)))]
core::arch::global_asm!(
    ".global nexttoward",
    ".type nexttoward, @function",
    "nexttoward:",
    "  lea rdi, [rsp + 8]",
    "  jmp __frankenlibc_nexttoward_x86_64",
    ".size nexttoward, .-nexttoward",
    ".global nexttowardf",
    ".type nexttowardf, @function",
    "nexttowardf:",
    "  lea rdi, [rsp + 8]",
    "  jmp __frankenlibc_nexttowardf_x86_64",
    ".size nexttowardf, .-nexttowardf",
    ".global nexttowardl",
    ".type nexttowardl, @function",
    "nexttowardl:",
    "  sub rsp, 24",
    "  lea rdi, [rsp + 32]",
    "  lea rsi, [rsp + 48]",
    "  mov rdx, rsp",
    "  call __frankenlibc_nexttowardl_x86_64",
    "  fld tbyte ptr [rsp]",
    "  add rsp, 24",
    "  ret",
    ".size nexttowardl, .-nexttowardl",
);

#[cfg(all(target_arch = "x86_64", any(not(debug_assertions), test)))]
unsafe fn read_x87_long_double_arg(slot: *const u8) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    // SAFETY: x86_64 SysV passes `long double` arguments in 16-byte stack
    // slots. The assembly shims pass the address of that caller-provided slot.
    unsafe { std::ptr::copy_nonoverlapping(slot, bytes.as_mut_ptr(), bytes.len()) };
    bytes
}

#[cfg(all(target_arch = "x86_64", any(not(debug_assertions), test)))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __frankenlibc_nexttoward_x86_64(x: f64, y: *const u8) -> f64 {
    // SAFETY: `y` points at the x86_64 SysV stack slot for the `long double`
    // direction argument.
    let y = unsafe { read_x87_long_double_arg(y) };
    frankenlibc_core::math::nexttoward_long_double_bits(x, y)
}

#[cfg(all(target_arch = "x86_64", any(not(debug_assertions), test)))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __frankenlibc_nexttowardf_x86_64(x: f32, y: *const u8) -> f32 {
    // SAFETY: `y` points at the x86_64 SysV stack slot for the `long double`
    // direction argument.
    let y = unsafe { read_x87_long_double_arg(y) };
    frankenlibc_core::math::nexttowardf_long_double_bits(x, y)
}

#[cfg(all(target_arch = "x86_64", any(not(debug_assertions), test)))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __frankenlibc_nexttowardl_x86_64(
    x: *const u8,
    y: *const u8,
    out: *mut u8,
) {
    // SAFETY: `x` and `y` point at x86_64 SysV stack slots for `long double`
    // arguments. `out` points at the assembly wrapper's 16-byte return slot.
    let x = unsafe { read_x87_long_double_arg(x) };
    let y = unsafe { read_x87_long_double_arg(y) };
    let result = frankenlibc_core::math::nexttowardl_long_double_bits(x, y);
    // SAFETY: `out` points to a 16-byte writable stack slot owned by the
    // assembly wrapper.
    unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out, result.len()) };
}

// ---------------------------------------------------------------------------
// New f32 batch: remquof, sincosf, nanf, exp10f, Bessel f32
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof(x: f32, y: f32, quo: *mut c_int) -> f32 {
    let had_inexact = exact_op_inexact_guard();
    let (rem, q) = frankenlibc_core::math::remquof(x, y);
    exact_op_clear_inexact(had_inexact);
    if !quo.is_null() {
        // SAFETY: caller guarantees `quo` points to valid writable `int`.
        unsafe { *quo = q };
    }
    // C99 remquof has no errno wrapper in glibc (see remquo).
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
pub unsafe extern "C" fn nanf(tagp: *const std::ffi::c_char) -> f32 {
    let tag: &[u8] = if tagp.is_null() {
        b""
    } else {
        // SAFETY: per the C contract `tagp` is a valid NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(tagp) }.to_bytes()
    };
    frankenlibc_core::math::nanf(tag)
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
    if x == 0.0 {
        // Y_n(0) = -inf is a pole: glibc reports a range error (ERANGE), not a
        // domain error. Only x < 0 (Y undefined for negative reals) is EDOM.
        set_range_errno();
    } else if x < 0.0 && x.is_finite() {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f(x: f32) -> f32 {
    let out = unary_entry_f32(x, 12, frankenlibc_core::math::y1f);
    if x == 0.0 {
        // Y_n(0) = -inf is a pole: glibc reports a range error (ERANGE), not a
        // domain error. Only x < 0 (Y undefined for negative reals) is EDOM.
        set_range_errno();
    } else if x < 0.0 && x.is_finite() {
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
    if x == 0.0 {
        // Y_n(0) = -inf is a pole: glibc reports a range error (ERANGE), not a
        // domain error. Only x < 0 (Y undefined for negative reals) is EDOM.
        set_range_errno();
    } else if x < 0.0 && x.is_finite() {
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
    let had_inexact = exact_op_inexact_guard();
    let out = binary_entry_f32(x, y, 4, frankenlibc_core::math::dremf);
    exact_op_clear_inexact(had_inexact);
    // Same glibc EDOM rule as drem; dremf previously set no errno at all.
    if !x.is_nan() && !y.is_nan() && (x.is_infinite() || y == 0.0) {
        set_domain_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gammaf(x: f32) -> f32 {
    // BSD gammaf aliases lgammaf: set the global signgam to sign of Γ(x).
    let (_, sign) = frankenlibc_core::math::lgammaf_r(x);
    unsafe {
        signgam = sign;
        __signgam = sign;
    }
    let out = unary_entry_f32(x, 8, frankenlibc_core::math::gammaf);
    // lgamma poles at non-positive integers
    if x.is_finite() && x <= 0.0 && x.fract() == 0.0 {
        set_range_errno();
    }
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn significandf(x: f32) -> f32 {
    // significand(0) has no normalized mantissa: glibc reports EDOM.
    if x == 0.0 {
        set_domain_errno();
    }
    let out = unary_entry_f32(x, 3, frankenlibc_core::math::significandf);
    // ilogbf(0/inf/NaN) raises FE_INVALID inside glibc's significandf; mirror it.
    // glibc's f32 path additionally raises FE_INEXACT on ±inf (the scalbnf scale
    // of an infinite operand), unlike the f64 significand path.
    if x == 0.0 || !x.is_finite() {
        pi_fn_raise_invalid_f32();
        if x.is_infinite() {
            raise_inexact_f64();
        }
    }
    out
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

/// ABI-compatible `_Complex _Float128` (verified to match the C ABI: a 32-byte
/// repr(C) struct of two f128 passes/returns identically to glibc's type).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CFloat128Complex {
    pub re: f128,
    pub im: f128,
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

// Only used by the trig self-consistency tests now that catan/catanh use the
// closed-form c_atanh.
#[cfg(test)]
#[inline]
fn c_div(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    let denom = b.0 * b.0 + b.1 * b.1;
    if denom == 0.0 {
        (f64::NAN, f64::NAN)
    } else {
        (
            (a.0 * b.0 + a.1 * b.1) / denom,
            (a.1 * b.0 - a.0 * b.1) / denom,
        )
    }
}

/// Real threshold past which `exp` overflows; above it the complex exp /
/// hyperbolic functions scale through `e^x = (e^(x/2))^2` so a finite result
/// with a small trig factor is not lost to a spurious infinity. glibc's
/// `s_cexp`/`s_csinh` use the same `(DBL_MAX_EXP - 1) * ln 2 ~ 709` cutoff.
const CL_OVF_T: f64 = 709.0;

/// `(e^|x|/2 * cos y, e^|x|/2 * sin y)` for `|x|` past the overflow threshold,
/// where `sinh(|x|) == cosh(|x|) == e^|x|/2` to full f64 precision. The split
/// `e^|x| = h*h` (`h = e^(|x|/2)`, well in range) keeps the trig-scaled result
/// finite when it should be; only `e^|x|/2 - t_float` style single-step scaling
/// would lose precision (see bd-2g7oyh.241). Caller applies the odd-fn sign.
#[inline]
fn cl_half_exp_scaled(arx: f64, ix: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    let h = math::exp(arx * 0.5);
    let hh = h * 0.5;
    ((math::cos(ix) * hh) * h, (math::sin(ix) * hh) * h)
}

/// glibc-faithful complex `cexp`. The naive `e^x*cos y + i e^x*sin y` gives
/// `inf*0 = NaN` whenever `e^x` overflows while a trig factor is exactly zero
/// (notably `y == 0`); this adds the C99 Annex G special values.
#[inline]
fn c_exp(re: f64, im: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    if re.is_finite() {
        if im.is_finite() {
            if im == 0.0 {
                // cexp(x + i*0) = e^x + i*0 (imag keeps the sign of iy; e^x > 0,
                // sin(±0) = ±0, so the product would be inf*0 = NaN for large x).
                return (math::exp(re), im);
            }
            if re > CL_OVF_T {
                // e^re overflows; split e^re = h*h (h = e^(re/2)) so a finite
                // result with a small trig factor survives.
                let h = math::exp(re * 0.5);
                return ((math::cos(im) * h) * h, (math::sin(im) * h) * h);
            }
            let r = math::exp(re);
            return (r * math::cos(im), r * math::sin(im));
        }
        // im is inf or NaN, re finite: cexp(x + i*(inf|NaN)) = NaN + i*NaN.
        return (f64::NAN, f64::NAN);
    }
    if re.is_infinite() {
        if re < 0.0 {
            // e^-inf = +0; 0 * (cos y + i sin y).
            if im == 0.0 {
                return (0.0, im);
            }
            if im.is_finite() {
                return (
                    f64::copysign(0.0, math::cos(im)),
                    f64::copysign(0.0, math::sin(im)),
                );
            }
            // cexp(-inf + i*(inf|NaN)) = +0 +- i*0 (imag keeps the sign of iy).
            return (0.0, f64::copysign(0.0, im));
        }
        // e^+inf = +inf.
        if im == 0.0 {
            return (re, im);
        }
        if im.is_finite() {
            return (
                f64::copysign(f64::INFINITY, math::cos(im)),
                f64::copysign(f64::INFINITY, math::sin(im)),
            );
        }
        // cexp(+inf + i*(inf|NaN)) = +inf + i*NaN.
        return (f64::INFINITY, f64::NAN);
    }
    // re is NaN.
    (f64::NAN, if im == 0.0 { im } else { f64::NAN })
}

/// Knuth's error-free transform: returns `(s, e)` with `s = fl(a + b)` and
/// `a + b = s + e` exactly (no overflow). Used to accumulate `re^2 + im^2 - 1`
/// without losing the small residual to cancellation.
#[inline]
fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    let bp = s - a;
    let ap = s - bp;
    let e = (a - ap) + (b - bp);
    (s, e)
}

#[inline]
fn c_log(re: f64, im: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    let im_out = math::atan2(im, re);
    // Real part = 0.5*ln(re^2 + im^2). `ln(hypot(re,im))` loses almost all
    // precision when |z| ~ 1 (the log is near zero, so forming hypot then
    // taking its log cancels catastrophically). Mirror glibc's log1p-based
    // clog: take the larger magnitude `ax`, and when it is near 1 evaluate
    //   0.5 * log1p((ax-1)*(ax+1) + ay^2)
    // which builds re^2 + im^2 - 1 with no subtractive cancellation; otherwise
    //   ln(ax) + 0.5 * log1p((ay/ax)^2)
    // where ln(ax) is safely bounded away from zero. Infinities keep the old
    // hypot semantics (|z| = inf -> real part +inf).
    let mut ax = math::fabs(re);
    let mut ay = math::fabs(im);
    if ax < ay {
        core::mem::swap(&mut ax, &mut ay);
    }
    let re_out = if re.is_infinite() || im.is_infinite() {
        f64::INFINITY
    } else if ax == 0.0 {
        f64::NEG_INFINITY
    } else if (0.5..=2.0).contains(&ax) {
        // |z| may be ~1, where ln collapses to near zero. Form re^2 + im^2 - 1
        // to near-correct rounding so the residual survives even when the two
        // squares nearly cancel against 1 (z near the unit circle at ~45deg,
        // where ax^2 and ay^2 cancel and ax^2 - 1 is no longer exact). Each
        // `mul_add` recovers the exact rounding error of a square, and the
        // dominant terms {ax^2, ay^2, -1} are accumulated with error-free
        // Knuth 2Sum so only log1p's own rounding remains.
        let rr = ax * ax;
        let rr_err = ax.mul_add(ax, -rr);
        let ii = ay * ay;
        let ii_err = ay.mul_add(ay, -ii);
        // 2Sum(rr, -1), then 2Sum(., ii); fold residuals into the low word.
        let (p, e1) = two_sum(rr, -1.0);
        let (d_hi, e2) = two_sum(p, ii);
        let d = d_hi + (e1 + e2 + rr_err + ii_err);
        0.5 * math::log1p(d)
    } else {
        let t = ay / ax;
        math::log(ax) + 0.5 * math::log1p(t * t)
    };
    (re_out, im_out)
}

#[inline]
fn c_sqrt(re: f64, im: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    // glibc-faithful csqrt (C99 Annex G): exact special values first, then the
    // cancellation-avoiding general formula. The imaginary sign is carried by
    // `copysign(.., im)` so the negative-real-axis branch cut respects signed
    // zero (a bare `im >= 0.0` would mis-route `im == -0.0` to the +root).
    if re.is_nan() || im.is_nan() || re.is_infinite() || im.is_infinite() {
        // csqrt(x +- i*inf) = +inf +- i*inf for ANY x (including NaN).
        if im.is_infinite() {
            return (f64::INFINITY, im);
        }
        if re.is_infinite() {
            if re < 0.0 {
                // csqrt(-inf + i*y) = (+0, copysign(inf, y)) for finite y, and
                // csqrt(-inf + i*NaN) = NaN +- i*inf (Annex G: imag is +-inf).
                let r = if im.is_nan() { f64::NAN } else { 0.0 };
                return (r, f64::copysign(f64::INFINITY, im));
            }
            // csqrt(+inf + i*y) = (+inf, copysign(0, y)); +inf + i*NaN => +inf + i*NaN.
            let i = if im.is_nan() {
                f64::NAN
            } else {
                f64::copysign(0.0, im)
            };
            return (re, i);
        }
        // Exactly one operand is NaN (neither infinite).
        return (f64::NAN, f64::NAN);
    }
    // Finite operands.
    if im == 0.0 {
        if re < 0.0 {
            return (0.0, f64::copysign(math::sqrt(-re), im));
        }
        // `fabs` forces +0 for a -0 real input (sqrt(-0.0) would keep the sign).
        return (math::fabs(math::sqrt(re)), f64::copysign(0.0, im));
    }
    if re == 0.0 {
        let r = math::sqrt(0.5 * math::fabs(im));
        return (r, f64::copysign(r, im));
    }
    // Both parts nonzero and finite. Use the identity 2*Re*Im = Im(z) to avoid
    // cancellation in `d -+ re`.
    let d = math::hypot(re, im);
    let (r, s) = if re > 0.0 {
        let rr = math::sqrt(0.5 * (d + re));
        (rr, 0.5 * (im / rr))
    } else {
        let ss = math::sqrt(0.5 * (d - re));
        (math::fabs(0.5 * (im / ss)), ss)
    };
    (r, f64::copysign(s, im))
}

/// glibc-faithful complex `ctanh` (used directly and, via the `-i*tanh(iz)`
/// identity, by `ctan`). The naive `csinh/ccosh` then `c_div` forms `inf/inf`
/// for large real parts and yields NaN; this uses the cancellation- and
/// overflow-stable identity
///   tanh(x+iy) = (sinh x cosh x + i sin y cos y) / (sinh^2 x + cos^2 y)
/// whose denominator scales with the numerator, plus the C99 Annex G special
/// values.
#[inline]
fn c_tanh(rx: f64, ix: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    if !rx.is_finite() || !ix.is_finite() {
        if rx.is_infinite() {
            // tanh(+-inf + iy): real -> +-1; imag -> +-0 (sign from sin*cos of a
            // finite y with |y|>1, else from y itself).
            let re = f64::copysign(1.0, rx);
            let im = if ix.is_finite() && math::fabs(ix) > 1.0 {
                f64::copysign(0.0, math::sin(ix) * math::cos(ix))
            } else {
                f64::copysign(0.0, ix)
            };
            return (re, im);
        }
        // rx is NaN here (not infinite). tanh(NaN + i0) = NaN + i0; otherwise
        // (rx==0 ? 0 : NaN) + iNaN.
        if ix == 0.0 {
            return (rx, ix);
        }
        let re = if rx == 0.0 { rx } else { f64::NAN };
        return (re, f64::NAN);
    }
    // Finite operands. For |x| past the overflow threshold sinh/cosh would
    // overflow, but tanh has already saturated: real = +-1, imag -> +-0.
    const T: f64 = 354.0; // floor((DBL_MAX_EXP-1)*ln2/2)
    let sinix = math::sin(ix);
    let cosix = math::cos(ix);
    if math::fabs(rx) > T {
        let re = f64::copysign(1.0, rx);
        let im = 4.0 * sinix * cosix * math::exp(-2.0 * math::fabs(rx));
        return (re, im);
    }
    let sinhrx = math::sinh(rx);
    let coshrx = math::cosh(rx);
    let den = sinhrx * sinhrx + cosix * cosix;
    (sinhrx * coshrx / den, sinix * cosix / den)
}

/// glibc-faithful complex `catanh` (and, via `catan(z) = -i*atanh(iz)`, the base
/// for the inverse-tangent variant). The naive `0.5*clog((1+z)/(1-z))` mishandles
/// the branch cuts (sign of the real/imag part along `(-inf,-1]` and `[1,inf)`)
/// and leaves rounding noise where the result is exactly real or imaginary. This
/// uses the cancellation-free closed form
///   Re = 0.25 * log1p(4x / ((1-x)^2 + y^2))
///   Im = 0.5  * atan2(2y, (1-x)(1+x) - y^2)
/// whose `log1p`/`atan2` carry the correct branch-cut signs, plus the large-|z|
/// limit `atanh(z) ~ 1/z + i*sign(y)*pi/2` and the C99 Annex G special values.
#[inline]
fn c_atanh(x: f64, y: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    use std::f64::consts::FRAC_PI_2;

    if x.is_nan() || y.is_nan() || x.is_infinite() || y.is_infinite() {
        if y.is_infinite() {
            // atanh(x +- i*inf) = copysign(0, x) +- i*pi/2 (any x incl nan/inf).
            return (f64::copysign(0.0, x), f64::copysign(FRAC_PI_2, y));
        }
        if x.is_infinite() {
            // atanh(+-inf + iy) = copysign(0, x) + i*(NaN or copysign(pi/2, y)).
            let im = if y.is_nan() {
                f64::NAN
            } else {
                f64::copysign(FRAC_PI_2, y)
            };
            return (f64::copysign(0.0, x), im);
        }
        // Exactly one of x, y is NaN (no infinities).
        if x.is_nan() {
            return (f64::NAN, f64::NAN);
        }
        // y is NaN, x finite: atanh(+-0 + iNaN) = +-0 + iNaN, else NaN + iNaN.
        return (if x == 0.0 { x } else { f64::NAN }, f64::NAN);
    }
    if x == 0.0 && y == 0.0 {
        // atanh(+-0 +- i0) = z.
        return (x, y);
    }
    // Large |z|: atanh(z) -> 1/z, so Re -> x/(x^2+y^2) (formed without overflow)
    // and Im -> sign(y)*pi/2.
    const LARGE: f64 = 9.486_832_980_505_138e153; // ~ sqrt(DBL_MAX) / 2
    if math::fabs(x) >= LARGE || math::fabs(y) >= LARGE {
        let (ax, ay) = (math::fabs(x), math::fabs(y));
        let re = if ax >= ay {
            let r = ay / ax;
            (1.0 / ax) / (1.0 + r * r)
        } else {
            let r = ax / ay;
            (r / ay) / (1.0 + r * r)
        };
        return (f64::copysign(re, x), f64::copysign(FRAC_PI_2, y));
    }
    // Re = 0.25*log(((1+x)^2+y^2)/((1-x)^2+y^2)). `log1p(4x/den)` is accurate
    // everywhere except near the z=-1 branch point, where `4x/den -> -1` (the
    // numerator `(1+x)^2+y^2` collapses). There — and only there — switch to
    // `log(num) - log(den)`, whose two magnitudes are well separated (no
    // cancellation); elsewhere that difference would itself cancel (e.g. large
    // |y|, where num ~ den), so log1p is kept.
    let den = (1.0 - x) * (1.0 - x) + y * y;
    let num = (1.0 + x) * (1.0 + x) + y * y;
    let re = if num < 0.5 * den {
        0.25 * (math::log(num) - math::log(den))
    } else {
        0.25 * math::log1p(4.0 * x / den)
    };
    let im = 0.5 * math::atan2(2.0 * y, (1.0 - x) * (1.0 + x) - y * y);
    (re, im)
}

/// Hull-Fairgrieve-Tang principal-branch complex arcsine for `x, y >= 0` finite.
/// Returns `(Re, Im)` of `asin(x + iy)` with both >= 0; callers apply the
/// odd-function signs (`Re` odd in x, `Im` odd in y). This is the algorithm glibc
/// and Boost use to keep a few ULP across the `[1,inf)` / `(-inf,-1]` cuts where
/// the naive `-i*clog(iz + csqrt(1-z^2))` flips signs and loses precision.
#[inline]
fn hft_asin(x: f64, y: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    const A_CROSSOVER: f64 = 1.5;
    const B_CROSSOVER: f64 = 0.6417;
    let xp1 = x + 1.0;
    let xm1 = x - 1.0;
    let r = math::hypot(xp1, y); // |z + 1|
    let s = math::hypot(xm1, y); // |z - 1|
    let a = 0.5 * (r + s); // >= 1
    let b = x / a; // = sin(Re), |b| <= 1

    let re = if b <= B_CROSSOVER {
        math::asin(b)
    } else {
        let apx = a + x;
        if x <= 1.0 {
            math::atan(x / math::sqrt(0.5 * apx * (y * y / (r + xp1) + (s - xm1))))
        } else {
            math::atan(x / (y * math::sqrt(0.5 * (apx / (r + xp1) + apx / (s + xm1)))))
        }
    };

    let im = if a <= A_CROSSOVER {
        // Im = log1p(am1 + sqrt(am1*(a+1))) with am1 = a - 1 formed accurately.
        let am1 = if x < 1.0 {
            0.5 * (y * y / (r + xp1) + y * y / (s + (1.0 - x)))
        } else {
            0.5 * (y * y / (r + xp1) + (s + xm1))
        };
        math::log1p(am1 + math::sqrt(am1 * (a + 1.0)))
    } else {
        // = log(a + sqrt(a^2 - 1)); acosh avoids overflow of a^2 for large |z|.
        math::acosh(a)
    };

    (re, im)
}

/// glibc-faithful complex `casinh` (and the base for `casin`, `cacos`, `cacosh`
/// via the standard identities). Finite values use the HFT arcsine; the inf/nan
/// corners are the C99 Annex G special values.
#[inline]
fn c_asinh(x: f64, y: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    use std::f64::consts::{FRAC_PI_2, FRAC_PI_4};

    if !x.is_finite() || !y.is_finite() {
        if x.is_nan() {
            if y == 0.0 {
                return (f64::NAN, y); // asinh(NaN + i0) = NaN + i0
            }
            if y.is_infinite() {
                return (f64::copysign(f64::INFINITY, x), f64::NAN); // (+-inf, NaN)
            }
            return (f64::NAN, f64::NAN);
        }
        if x.is_infinite() {
            if y.is_nan() {
                return (x, f64::NAN); // asinh(+-inf + iNaN) = +-inf + iNaN
            }
            if y.is_infinite() {
                return (x, f64::copysign(FRAC_PI_4, y)); // (+-inf, +-pi/4)
            }
            return (x, f64::copysign(0.0, y)); // asinh(+-inf + iy) = +-inf + i0
        }
        // x finite, y is inf or NaN.
        if y.is_infinite() {
            return (f64::copysign(f64::INFINITY, x), f64::copysign(FRAC_PI_2, y));
        }
        // y is NaN, x finite: host glibc returns (NaN, NaN) for all x (incl +-0).
        return (f64::NAN, f64::NAN);
    }
    // Finite. asinh(z) = -i*asin(iz); with the HFT arcsine of (|y|, |x|) this is
    // (copysign(Im, x), copysign(Re, y)).
    let (hr, hi) = hft_asin(math::fabs(y), math::fabs(x));
    (f64::copysign(hi, x), f64::copysign(hr, y))
}

/// Hull-Fairgrieve-Tang principal-branch complex arccosine for `x, y >= 0`
/// finite. Returns `(Re in [0, pi/2], Im >= 0)`. Same intermediates as
/// `hft_asin`, but the real part is `acos(b)` / `atan(D/x)` — computed directly
/// so `cacos` near `z = 1` keeps its tiny real part instead of losing it to the
/// `pi/2 - asin` cancellation.
#[inline]
fn hft_acos(x: f64, y: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    const A_CROSSOVER: f64 = 1.5;
    const B_CROSSOVER: f64 = 0.6417;
    let xp1 = x + 1.0;
    let xm1 = x - 1.0;
    let r = math::hypot(xp1, y);
    let s = math::hypot(xm1, y);
    let a = 0.5 * (r + s);
    let b = x / a;

    let re = if b <= B_CROSSOVER {
        math::acos(b)
    } else {
        let apx = a + x;
        if x <= 1.0 {
            math::atan(math::sqrt(0.5 * apx * (y * y / (r + xp1) + (s - xm1))) / x)
        } else {
            math::atan(y * math::sqrt(0.5 * (apx / (r + xp1) + apx / (s + xm1))) / x)
        }
    };

    let im = if a <= A_CROSSOVER {
        let am1 = if x < 1.0 {
            0.5 * (y * y / (r + xp1) + y * y / (s + (1.0 - x)))
        } else {
            0.5 * (y * y / (r + xp1) + (s + xm1))
        };
        math::log1p(am1 + math::sqrt(am1 * (a + 1.0)))
    } else {
        math::acosh(a)
    };

    (re, im)
}

/// glibc-faithful complex `cacos` (and the base for `cacosh`). Finite values use
/// the HFT arccosine; non-finite inputs have no cancellation, so they fall back
/// to `pi/2 - casin`. `Re in [0, pi]` (reflected for negative real part), and
/// `Im` has the opposite sign to `y`.
#[inline]
fn c_acos(x: f64, y: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    use std::f64::consts::{FRAC_PI_2, PI};
    if !x.is_finite() || !y.is_finite() {
        let (p, q) = c_asinh(-y, x); // casin(z) = (q, -p)
        return (FRAC_PI_2 - q, p);
    }
    let (hr, hi) = hft_acos(math::fabs(x), math::fabs(y));
    let re = if x.is_sign_negative() { PI - hr } else { hr };
    (re, f64::copysign(hi, -y))
}

/// glibc-faithful complex `csinh` (and, via `csin(z) = -i*csinh(iz)`, the base
/// for the trig variant). The naive `sinh(x)cos(y) + i cosh(x)sin(y)` yields
/// `inf*0 = NaN` whenever a hyperbolic factor overflows while a trig factor is
/// exactly zero (notably `y == 0`); this adds the C99 Annex G special values.
#[inline]
fn c_sinh(rx: f64, ix: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    if rx.is_finite() {
        if ix.is_finite() {
            if ix == 0.0 {
                // csinh(x + i*0) = sinh(x) + i*0 (imag keeps the sign of iy).
                return (math::sinh(rx), ix);
            }
            let arx = math::fabs(rx);
            if arx > CL_OVF_T {
                // sinh(|x|) == cosh(|x|) == e^|x|/2 here; sinh is odd in x.
                let (rc, rs) = cl_half_exp_scaled(arx, ix);
                let re = if rx.is_sign_negative() { -rc } else { rc };
                return (re, rs);
            }
            return (
                math::sinh(rx) * math::cos(ix),
                math::cosh(rx) * math::sin(ix),
            );
        }
        // ix is inf or NaN, rx finite.
        if rx == 0.0 {
            // csinh(+-0 + i*(inf|NaN)) = +-0 + i*NaN.
            return (rx, f64::NAN);
        }
        return (f64::NAN, f64::NAN);
    }
    if rx.is_infinite() {
        if ix == 0.0 {
            // csinh(+-inf + i*0) = +-inf + i*0.
            return (rx, ix);
        }
        if ix.is_finite() {
            // csinh(+-inf + iy): real = sinh(rx)cos y (sign = sign(rx)^sign cos),
            // imag = cosh(rx)sin y (cosh>0, so sign = sign sin).
            let re = f64::copysign(f64::INFINITY, math::cos(ix) * f64::copysign(1.0, rx));
            let im = f64::copysign(f64::INFINITY, math::sin(ix));
            return (re, im);
        }
        // csinh(+-inf + i*(inf|NaN)) = inf + i*NaN (glibc fixes the sign +inf).
        return (f64::INFINITY, f64::NAN);
    }
    // rx is NaN.
    (f64::NAN, if ix == 0.0 { ix } else { f64::NAN })
}

/// glibc-faithful complex `ccosh` (base for `ccos(z) = ccosh(iz)`). Same
/// `inf*0 = NaN` hazard as `csinh`; cosh is even in x and sinh is odd, so the
/// imaginary zero at `y == 0` carries `sign(x) ^ sign(iy)`.
#[inline]
fn c_cosh(rx: f64, ix: f64) -> (f64, f64) {
    use frankenlibc_core::math;
    if rx.is_finite() {
        if ix.is_finite() {
            if ix == 0.0 {
                // ccosh(x + i*0) = cosh(x) + i*(sinh(x)*0); zero sign is
                // sign(x) ^ sign(iy).
                let neg = rx.is_sign_negative() ^ ix.is_sign_negative();
                return (math::cosh(rx), if neg { -0.0 } else { 0.0 });
            }
            let arx = math::fabs(rx);
            if arx > CL_OVF_T {
                // cosh(|x|) == sinh(|x|) == e^|x|/2 here; sinh (imag) is odd in x.
                let (rc, rs) = cl_half_exp_scaled(arx, ix);
                let im = if rx.is_sign_negative() { -rs } else { rs };
                return (rc, im);
            }
            return (
                math::cosh(rx) * math::cos(ix),
                math::sinh(rx) * math::sin(ix),
            );
        }
        // ix is inf or NaN, rx finite.
        if rx == 0.0 {
            // ccosh(+-0 + i*(inf|NaN)) = NaN + i*0 (glibc fixes the sign +0).
            return (f64::NAN, 0.0);
        }
        return (f64::NAN, f64::NAN);
    }
    if rx.is_infinite() {
        if ix == 0.0 {
            // ccosh(+-inf + i*0) = +inf + i*0 with sign(x) ^ sign(iy).
            let neg = rx.is_sign_negative() ^ ix.is_sign_negative();
            return (f64::INFINITY, if neg { -0.0 } else { 0.0 });
        }
        if ix.is_finite() {
            // ccosh(+-inf + iy) = +inf*cos y + i*+-inf*sin y.
            let re = f64::copysign(f64::INFINITY, math::cos(ix));
            let im = f64::copysign(f64::INFINITY, math::sin(ix) * f64::copysign(1.0, rx));
            return (re, im);
        }
        // ccosh(+-inf + i*(inf|NaN)) = +inf + i*NaN.
        return (f64::INFINITY, f64::NAN);
    }
    // rx is NaN.
    (
        f64::NAN,
        if ix == 0.0 {
            f64::copysign(0.0, ix)
        } else {
            f64::NAN
        },
    )
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
    CDoubleComplex {
        re: z.re,
        im: -z.im,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf(z: CFloatComplex) -> CFloatComplex {
    CFloatComplex {
        re: z.re,
        im: -z.im,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    CLongDoubleComplex {
        re: z.re,
        im: -z.im,
    }
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
        CDoubleComplex {
            re: f64::INFINITY,
            im: f64::copysign(0.0, z.im),
        }
    } else {
        z
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf(z: CFloatComplex) -> CFloatComplex {
    if z.re.is_infinite() || z.im.is_infinite() {
        CFloatComplex {
            re: f32::INFINITY,
            im: f32::copysign(0.0, z.im),
        }
    } else {
        z
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    if z.re.is_infinite() || z.im.is_infinite() {
        CLongDoubleComplex {
            re: f64::INFINITY,
            im: f64::copysign(0.0, z.im),
        }
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
    CFloatComplex {
        re: re as f32,
        im: im as f32,
    }
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
    CFloatComplex {
        re: re as f32,
        im: im as f32,
    }
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
    CFloatComplex {
        re: re as f32,
        im: im as f32,
    }
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
    CFloatComplex {
        re: re as f32,
        im: im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowl(
    base: CLongDoubleComplex,
    exp: CLongDoubleComplex,
) -> CLongDoubleComplex {
    let lz = c_log(base.re, base.im);
    let wl = c_mul((exp.re, exp.im), lz);
    let (re, im) = c_exp(wl.0, wl.1);
    CLongDoubleComplex { re, im }
}

// --- Trigonometric: csin, ccos, ctan ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csin(z: CDoubleComplex) -> CDoubleComplex {
    // sin(z) = -i*sinh(iz); iz = (-im, re), sinh gives (p, q) and
    // -i*(p + qi) = (q, -p). Inherits c_sinh's Annex G special values and the
    // overflow scaling for large |Im z| (= large real arg of sinh).
    let (p, q) = c_sinh(-z.im, z.re);
    CDoubleComplex { re: q, im: -p }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        csin(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { csin(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccos(z: CDoubleComplex) -> CDoubleComplex {
    // cos(z) = cosh(iz); iz = (-im, re). Inherits c_cosh's Annex G special
    // values and overflow scaling for large |Im z|.
    let (re, im) = c_cosh(-z.im, z.re);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        ccos(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ccos(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctan(z: CDoubleComplex) -> CDoubleComplex {
    // tan(z) = -i * tanh(iz); with iz = (-im, re), tanh gives (p, q) and
    // -i*(p + qi) = (q, -p). This inherits ctanh's overflow-stable formula and
    // Annex G special-value handling along the imaginary axis.
    let (p, q) = c_tanh(-z.im, z.re);
    CDoubleComplex { re: q, im: -p }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        ctan(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ctan(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

// --- Hyperbolic: csinh, ccosh, ctanh ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinh(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_sinh(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        csinh(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { csinh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosh(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_cosh(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        ccosh(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ccosh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanh(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_tanh(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        ctanh(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { ctanh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

// --- Inverse trig: casin, cacos, catan ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casin(z: CDoubleComplex) -> CDoubleComplex {
    // asin(z) = -i*asinh(iz); iz = (-im, re), asinh gives (p, q) and
    // -i*(p + qi) = (q, -p). Inherits c_asinh's branch cuts and special values.
    let (p, q) = c_asinh(-z.im, z.re);
    CDoubleComplex { re: q, im: -p }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        casin(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { casin(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacos(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_acos(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        cacos(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { cacos(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catan(z: CDoubleComplex) -> CDoubleComplex {
    // atan(z) = -i*atanh(iz); iz = (-im, re), atanh gives (p, q) and
    // -i*(p + qi) = (q, -p). Inherits c_atanh's branch cuts and special values.
    let (p, q) = c_atanh(-z.im, z.re);
    CDoubleComplex { re: q, im: -p }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        catan(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { catan(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

// --- Inverse hyperbolic: casinh, cacosh, catanh ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinh(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_asinh(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        casinh(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { casinh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosh(z: CDoubleComplex) -> CDoubleComplex {
    // acosh(z) = +-i*acos(z), with the sign chosen so Re(acosh) >= 0. With
    // acos(z) = (rc, ic): if Im(acos) is negative take i*acos = (-ic, rc), else
    // -i*acos = (ic, -rc); either way Re = |ic| >= 0. Use the sign bit (not
    // `ic <= 0`) so the +-0 imaginary axis routes to the correct branch.
    let c = unsafe { cacos(z) };
    if c.im.is_sign_negative() || c.im.is_nan() {
        CDoubleComplex {
            re: -c.im,
            im: c.re,
        }
    } else {
        CDoubleComplex {
            re: c.im,
            im: -c.re,
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        cacosh(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshl(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { cacosh(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanh(z: CDoubleComplex) -> CDoubleComplex {
    let (re, im) = c_atanh(z.re, z.im);
    CDoubleComplex { re, im }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe {
        catanh(CDoubleComplex {
            re: z.re as f64,
            im: z.im as f64,
        })
    };
    CFloatComplex {
        re: r.re as f32,
        im: r.im as f32,
    }
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
pub unsafe extern "C" fn fmaximum(x: f64, y: f64) -> f64 {
    fmaximum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf(x: f32, y: f32) -> f32 {
    fmaximum_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximuml(x: f64, y: f64) -> f64 {
    fmaximum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf32(x: f32, y: f32) -> f32 {
    fmaximum_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf32x(x: f64, y: f64) -> f64 {
    fmaximum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf64(x: f64, y: f64) -> f64 {
    fmaximum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf64x(x: f64, y: f64) -> f64 {
    fmaximum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximumf128(x: f128, y: f128) -> f128 {
    // C23 fmaximum = IEEE-754-2019 maximum: NaN-propagating, +0 > -0.
    x.maximum(y)
}

// --- fmaximum_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_num(x: f64, y: f64) -> f64 {
    fmaximum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf(x: f32, y: f32) -> f32 {
    fmaximum_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numl(x: f64, y: f64) -> f64 {
    fmaximum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf32(x: f32, y: f32) -> f32 {
    fmaximum_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf32x(x: f64, y: f64) -> f64 {
    fmaximum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf64(x: f64, y: f64) -> f64 {
    fmaximum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf64x(x: f64, y: f64) -> f64 {
    fmaximum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_numf128(x: f128, y: f128) -> f128 {
    // C23 fmaximum_num: like fmaximum but a NaN operand is ignored.
    if x.is_nan() {
        y
    } else if y.is_nan() {
        x
    } else {
        x.maximum(y)
    }
}

// --- fmaximum_mag exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag(x: f64, y: f64) -> f64 {
    fmaximum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf(x: f32, y: f32) -> f32 {
    fmaximum_mag_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magl(x: f64, y: f64) -> f64 {
    fmaximum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf32(x: f32, y: f32) -> f32 {
    fmaximum_mag_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf32x(x: f64, y: f64) -> f64 {
    fmaximum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf64(x: f64, y: f64) -> f64 {
    fmaximum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf64x(x: f64, y: f64) -> f64 {
    fmaximum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_magf128(x: f128, y: f128) -> f128 {
    // Greater magnitude; NaN propagates; equal magnitude defers to fmaximum.
    if x.is_nan() || y.is_nan() {
        return x.maximum(y);
    }
    let (ax, ay) = (x.abs(), y.abs());
    if ax > ay {
        x
    } else if ay > ax {
        y
    } else {
        x.maximum(y)
    }
}

// --- fmaximum_mag_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_num(x: f64, y: f64) -> f64 {
    fmaximum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf(x: f32, y: f32) -> f32 {
    fmaximum_mag_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numl(x: f64, y: f64) -> f64 {
    fmaximum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf32(x: f32, y: f32) -> f32 {
    fmaximum_mag_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf32x(x: f64, y: f64) -> f64 {
    fmaximum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf64(x: f64, y: f64) -> f64 {
    fmaximum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf64x(x: f64, y: f64) -> f64 {
    fmaximum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaximum_mag_numf128(x: f128, y: f128) -> f128 {
    // Greater magnitude, NaN ignored; equal magnitude defers to fmaximum_num.
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    let (ax, ay) = (x.abs(), y.abs());
    if ax > ay {
        x
    } else if ay > ax {
        y
    } else {
        x.maximum(y)
    }
}

// --- fminimum exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum(x: f64, y: f64) -> f64 {
    fminimum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf(x: f32, y: f32) -> f32 {
    fminimum_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimuml(x: f64, y: f64) -> f64 {
    fminimum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf32(x: f32, y: f32) -> f32 {
    fminimum_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf32x(x: f64, y: f64) -> f64 {
    fminimum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf64(x: f64, y: f64) -> f64 {
    fminimum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf64x(x: f64, y: f64) -> f64 {
    fminimum_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimumf128(x: f128, y: f128) -> f128 {
    // C23 fminimum = IEEE-754-2019 minimum: NaN-propagating, -0 < +0.
    x.minimum(y)
}

// --- fminimum_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_num(x: f64, y: f64) -> f64 {
    fminimum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf(x: f32, y: f32) -> f32 {
    fminimum_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numl(x: f64, y: f64) -> f64 {
    fminimum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf32(x: f32, y: f32) -> f32 {
    fminimum_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf32x(x: f64, y: f64) -> f64 {
    fminimum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf64(x: f64, y: f64) -> f64 {
    fminimum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf64x(x: f64, y: f64) -> f64 {
    fminimum_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_numf128(x: f128, y: f128) -> f128 {
    // C23 fminimum_num: like fminimum but a NaN operand is ignored.
    if x.is_nan() {
        y
    } else if y.is_nan() {
        x
    } else {
        x.minimum(y)
    }
}

// --- fminimum_mag exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag(x: f64, y: f64) -> f64 {
    fminimum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf(x: f32, y: f32) -> f32 {
    fminimum_mag_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magl(x: f64, y: f64) -> f64 {
    fminimum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf32(x: f32, y: f32) -> f32 {
    fminimum_mag_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf32x(x: f64, y: f64) -> f64 {
    fminimum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf64(x: f64, y: f64) -> f64 {
    fminimum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf64x(x: f64, y: f64) -> f64 {
    fminimum_mag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_magf128(x: f128, y: f128) -> f128 {
    // Lesser magnitude; NaN propagates; equal magnitude defers to fminimum.
    if x.is_nan() || y.is_nan() {
        return x.minimum(y);
    }
    let (ax, ay) = (x.abs(), y.abs());
    if ax < ay {
        x
    } else if ay < ax {
        y
    } else {
        x.minimum(y)
    }
}

// --- fminimum_mag_num exports ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_num(x: f64, y: f64) -> f64 {
    fminimum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf(x: f32, y: f32) -> f32 {
    fminimum_mag_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numl(x: f64, y: f64) -> f64 {
    fminimum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf32(x: f32, y: f32) -> f32 {
    fminimum_mag_num_implf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf32x(x: f64, y: f64) -> f64 {
    fminimum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf64(x: f64, y: f64) -> f64 {
    fminimum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf64x(x: f64, y: f64) -> f64 {
    fminimum_mag_num_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminimum_mag_numf128(x: f128, y: f128) -> f128 {
    // Lesser magnitude, NaN ignored; equal magnitude defers to fminimum_num.
    if x.is_nan() {
        return y;
    }
    if y.is_nan() {
        return x;
    }
    let (ax, ay) = (x.abs(), y.abs());
    if ax < ay {
        x
    } else if ay < ax {
        y
    } else {
        x.minimum(y)
    }
}

// =========================================================================
// C23 new math functions
// =========================================================================

// --- C23 Pi-trig functions ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospi(x: f64) -> f64 {
    let r = unsafe { acos(x) };
    r / std::f64::consts::PI
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif(x: f32) -> f32 {
    // glibc's acospif computes in double precision and rounds once:
    // round_to_f32(acos((double)x) / pi). Doing the f32 division directly
    // (acosf(x) / pi_f32) loses 1-2 ULP vs glibc; routing through the f64
    // acospi is byte-exact (verified 0 ULP over a 20k-point sweep).
    unsafe { acospi(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospil(x: f64) -> f64 {
    unsafe { acospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif32(x: f32) -> f32 {
    unsafe { acospif(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif32x(x: f64) -> f64 {
    unsafe { acospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif64(x: f64) -> f64 {
    unsafe { acospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif64x(x: f64) -> f64 {
    unsafe { acospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acospif128(x: f128) -> f128 {
    // glibc s_acospi_template: acos(x)/pi, EDOM if |x|>1, clamp to [.,1].
    const PI: f128 = 3.141592653589793238462643383279502884f128;
    if x.abs() > 1.0 {
        set_domain_errno();
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    }
    let ret = acos_f128(x) / PI;
    if ret > 1.0 { 1.0 } else { ret }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpi(x: f64) -> f64 {
    let r = unsafe { asin(x) };
    r / std::f64::consts::PI
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif(x: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact); the direct
    // f32 form asinf(x)/pi_f32 loses up to 2 ULP.
    unsafe { asinpi(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpil(x: f64) -> f64 {
    unsafe { asinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif32(x: f32) -> f32 {
    unsafe { asinpif(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif32x(x: f64) -> f64 {
    unsafe { asinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif64(x: f64) -> f64 {
    unsafe { asinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif64x(x: f64) -> f64 {
    unsafe { asinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinpif128(x: f128) -> f128 {
    // glibc s_asinpi_template: EDOM if |x|>1, else asin(x)/pi, clamp to ±0.5.
    const PI: f128 = 3.141592653589793238462643383279502884f128;
    if !(x.abs() <= 1.0) {
        if x.is_nan() {
            return (x - x) / (x - x); // propagate input NaN
        }
        set_domain_errno();
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    }
    let ret = asin_f128(x) / PI;
    if x != 0.0 && ret == 0.0 {
        set_range_errno();
    }
    if ret.abs() > 0.5 { (0.5f128).copysign(ret) } else { ret }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpi(x: f64) -> f64 {
    let r = unsafe { atan(x) };
    r / std::f64::consts::PI
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif(x: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact); the direct
    // f32 form atanf(x)/pi_f32 loses up to 2 ULP.
    unsafe { atanpi(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpil(x: f64) -> f64 {
    unsafe { atanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif32(x: f32) -> f32 {
    unsafe { atanpif(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif32x(x: f64) -> f64 {
    unsafe { atanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif64(x: f64) -> f64 {
    unsafe { atanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif64x(x: f64) -> f64 {
    unsafe { atanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanpif128(x: f128) -> f128 {
    // glibc s_atanpi_template: atan(x)/pi, ERANGE on nonzero→0 underflow, ±0.5 clamp.
    const PI: f128 = 3.141592653589793238462643383279502884f128;
    let ret = atan_f128(x) / PI;
    if x != 0.0 && ret == 0.0 {
        set_range_errno();
    }
    if ret.abs() > 0.5 { (0.5f128).copysign(ret) } else { ret }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pi(x: f64, y: f64) -> f64 {
    let r = unsafe { atan2(x, y) };
    r / std::f64::consts::PI
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif(x: f32, y: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact); the direct
    // f32 form atan2f(x,y)/pi_f32 loses up to 2 ULP.
    unsafe { atan2pi(x as f64, y as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pil(x: f64, y: f64) -> f64 {
    unsafe { atan2pi(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif32(x: f32, y: f32) -> f32 {
    unsafe { atan2pif(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif32x(x: f64, y: f64) -> f64 {
    unsafe { atan2pi(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif64(x: f64, y: f64) -> f64 {
    unsafe { atan2pi(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif64x(x: f64, y: f64) -> f64 {
    unsafe { atan2pi(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2pif128(y: f128, x: f128) -> f128 {
    // glibc s_atan2pi_template: atan2(y,x)/pi, ERANGE underflow, ±1 clamp.
    const PI: f128 = 3.141592653589793238462643383279502884f128;
    let ret = atan2_f128(y, x) / PI;
    if ret == 0.0 && y != 0.0 && x.is_finite() {
        set_range_errno();
    }
    if ret.abs() > 1.0 { (1.0f128).copysign(ret) } else { ret }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
/// Re-raise FE_INVALID on the cold pi-function domain path (x = ±inf).
#[inline]
fn pi_fn_raise_invalid_f64() {
    let _ = core::hint::black_box(core::hint::black_box(0.0_f64) / core::hint::black_box(0.0_f64));
}
#[inline]
fn pi_fn_raise_invalid_f32() {
    let _ = core::hint::black_box(core::hint::black_box(0.0_f32) / core::hint::black_box(0.0_f32));
}

// C23 pi-scaled trig: sinpi(x)=sin(pi*x), cospi(x)=cos(pi*x), tanpi(x)=tan(pi*x),
// computed via the exact identity f(n+r) with n=round(x), r=x-n in [-0.5,0.5]
// (exact by Sterbenz for |x|<2^53). This yields EXACT results at integer and
// half-integer arguments (sinpi(1)=+0, cospi(0.5)=+0, tanpi(0.5)=+inf) and
// stays correct for huge arguments where the naive sin(x*PI) loses all
// precision. |x|>=2^53 is always an even integer: sinpi=±0, cospi=1, tanpi=±0.
pub unsafe extern "C" fn cospi(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x.is_infinite() {
        pi_fn_raise_invalid_f64();
        return f64::NAN;
    }
    if x.abs() >= 9007199254740992.0 {
        return 1.0; // even integer → cos(pi*even)=+1
    }
    let n = x.round();
    let r = x - n;
    let n_odd = (n as i64) & 1 != 0;
    if r == 0.0 {
        return if n_odd { -1.0 } else { 1.0 };
    }
    if r == 0.5 || r == -0.5 {
        return 0.0; // cos at odd multiple of pi/2 is +0
    }
    let c = frankenlibc_core::math::cos(r * std::f64::consts::PI);
    if n_odd { -c } else { c }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif(x: f32) -> f32 {
    // glibc computes cospif in double precision and rounds once. Doing the
    // arg-reduction in f32 loses enormous ULP near cospi's zeros (x = k+0.5),
    // where cosf amplifies the f32 `r*pi` rounding error (up to ~28000 ULP).
    // Routing through the f64 cospi is byte-exact vs glibc (0 ULP over a
    // 400k-point sweep), and the f64 path handles NaN/inf/large-x identically.
    unsafe { cospi(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospil(x: f64) -> f64 {
    unsafe { cospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif32(x: f32) -> f32 {
    unsafe { cospif(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif32x(x: f64) -> f64 {
    unsafe { cospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif64(x: f64) -> f64 {
    unsafe { cospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif64x(x: f64) -> f64 {
    unsafe { cospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cospif128(x: f64) -> f64 {
    unsafe { cospi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpi(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x.is_infinite() {
        pi_fn_raise_invalid_f64();
        return f64::NAN;
    }
    if x.abs() >= 9007199254740992.0 {
        // even integer → sin(pi*even)=±0 with sign of x
        return if x.is_sign_negative() { -0.0 } else { 0.0 };
    }
    let n = x.round();
    let r = x - n;
    let n_odd = (n as i64) & 1 != 0;
    if r == 0.0 {
        return if x.is_sign_negative() { -0.0 } else { 0.0 };
    }
    if r == 0.5 || r == -0.5 {
        let m = if r > 0.0 { 1.0 } else { -1.0 };
        return if n_odd { -m } else { m };
    }
    let s = frankenlibc_core::math::sin(r * std::f64::consts::PI);
    if n_odd { -s } else { s }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif(x: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact, 0 ULP); the
    // direct f32 arg-reduction is up to ~1 ULP off. The f64 sinpi handles
    // NaN/inf (FE_INVALID)/large-x and signed-zero identically.
    unsafe { sinpi(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpil(x: f64) -> f64 {
    unsafe { sinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif32(x: f32) -> f32 {
    unsafe { sinpif(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif32x(x: f64) -> f64 {
    unsafe { sinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif64(x: f64) -> f64 {
    unsafe { sinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif64x(x: f64) -> f64 {
    unsafe { sinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinpif128(x: f64) -> f64 {
    unsafe { sinpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpi(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x.is_infinite() {
        pi_fn_raise_invalid_f64();
        return f64::NAN;
    }
    // tanpi = sinpi/cospi: the (-1)^n factors cancel, the half-integer pole
    // becomes ±1/±0 (auto-raising FE_DIVBYZERO → ±inf), and the integer zero
    // becomes ±0/±1 with the correct sign.
    let s = unsafe { sinpi(x) };
    let c = unsafe { cospi(x) };
    s / c
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif(x: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact, 0 ULP); the
    // direct f32 path loses huge ULP near tanpi's poles. The f64 tanpi raises
    // FE_DIVBYZERO at the poles and FE_INVALID on inf.
    unsafe { tanpi(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpil(x: f64) -> f64 {
    unsafe { tanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif32(x: f32) -> f32 {
    unsafe { tanpif(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif32x(x: f64) -> f64 {
    unsafe { tanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif64(x: f64) -> f64 {
    unsafe { tanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif64x(x: f64) -> f64 {
    unsafe { tanpi(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanpif128(x: f64) -> f64 {
    unsafe { tanpi(x) }
}

// --- roundeven ---

// Round to nearest integer, ties to EVEN, implemented purely in the integer
// (bit) domain. Unlike a float-arithmetic formulation (x.round() + tie fixup +
// `as i64` casts), this raises NO floating-point exceptions: glibc's roundeven
// is the IEEE roundToIntegralTiesToEven operation, which never signals
// FE_INEXACT (even on non-integers) nor FE_INVALID (on infinities). The earlier
// implementation produced bit-exact results but spuriously raised FE_INEXACT on
// every non-integer and FE_INVALID on ±inf (the float->int cast), diverging from
// glibc's exception-free contract.
fn roundeven_impl(x: f64) -> f64 {
    let bits = x.to_bits();
    let sign = bits & 0x8000_0000_0000_0000;
    let e = ((bits >> 52) & 0x7ff) as i32;
    // |x| >= 2^52 (and inf/NaN): already integral, return unchanged.
    if e >= 1023 + 52 {
        return x;
    }
    // |x| < 1: result is ±0 (|x| <= 0.5, ties-to-even rounds 0.5 to 0) or ±1.
    if e < 1023 {
        let mag = f64::from_bits(bits & 0x7fff_ffff_ffff_ffff);
        let r = if mag > 0.5 { 1.0_f64 } else { 0.0_f64 };
        return f64::from_bits(r.to_bits() | sign);
    }
    // 1 <= |x| < 2^52: split mantissa into integer/fractional bits.
    let frac_bits = 1075 - e; // 1..=52 fractional mantissa bits
    let half = 1u64 << (frac_bits - 1);
    let frac_mask = (1u64 << frac_bits) - 1;
    let int_part = bits & !frac_mask;
    let frac = bits & frac_mask;
    // Round up when above the halfway point, or exactly halfway with an odd
    // integer (ties to even). Integer add carries naturally into the exponent.
    let round_up = frac > half || (frac == half && (int_part & (1u64 << frac_bits)) != 0);
    let out = if round_up {
        int_part + (1u64 << frac_bits)
    } else {
        int_part
    };
    f64::from_bits(out)
}
fn roundevenf_impl(x: f32) -> f32 {
    let bits = x.to_bits();
    let sign = bits & 0x8000_0000;
    let e = ((bits >> 23) & 0xff) as i32;
    // |x| >= 2^23 (and inf/NaN): already integral.
    if e >= 127 + 23 {
        return x;
    }
    // |x| < 1: ±0 or ±1.
    if e < 127 {
        let mag = f32::from_bits(bits & 0x7fff_ffff);
        let r = if mag > 0.5 { 1.0_f32 } else { 0.0_f32 };
        return f32::from_bits(r.to_bits() | sign);
    }
    let frac_bits = 150 - e; // 1..=23 fractional mantissa bits
    let half = 1u32 << (frac_bits - 1);
    let frac_mask = (1u32 << frac_bits) - 1;
    let int_part = bits & !frac_mask;
    let frac = bits & frac_mask;
    let round_up = frac > half || (frac == half && (int_part & (1u32 << frac_bits)) != 0);
    let out = if round_up {
        int_part + (1u32 << frac_bits)
    } else {
        int_part
    };
    f32::from_bits(out)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundeven(x: f64) -> f64 {
    roundeven_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf(x: f32) -> f32 {
    roundevenf_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenl(x: f64) -> f64 {
    unsafe { roundeven(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf32(x: f32) -> f32 {
    unsafe { roundevenf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf32x(x: f64) -> f64 {
    unsafe { roundeven(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf64(x: f64) -> f64 {
    unsafe { roundeven(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf64x(x: f64) -> f64 {
    unsafe { roundeven(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundevenf128(x: f128) -> f128 {
    x.round_ties_even()
}

// --- nextdown / nextup ---

fn nextdown_impl(x: f64) -> f64 {
    let xb = x.to_bits();
    if (xb & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000 && (xb & 0x000f_ffff_ffff_ffff) != 0 {
        return f64::from_bits(xb | 0x0008_0000_0000_0000); // quiet a signaling NaN
    }
    if x == f64::NEG_INFINITY {
        return f64::NEG_INFINITY;
    }
    if x == 0.0 {
        return -f64::MIN_POSITIVE * f64::EPSILON;
    }
    let bits = x.to_bits();
    let next = if x > 0.0 { bits - 1 } else { bits + 1 };
    f64::from_bits(next)
}
fn nextdownf_impl(x: f32) -> f32 {
    let xb = x.to_bits();
    if (xb & 0x7f80_0000) == 0x7f80_0000 && (xb & 0x007f_ffff) != 0 {
        return f32::from_bits(xb | 0x0040_0000); // quiet a signaling NaN
    }
    if x == f32::NEG_INFINITY {
        return f32::NEG_INFINITY;
    }
    if x == 0.0f32 {
        return -f32::MIN_POSITIVE * f32::EPSILON;
    }
    let bits = x.to_bits();
    let next = if x > 0.0f32 { bits - 1 } else { bits + 1 };
    f32::from_bits(next)
}
fn nextup_impl(x: f64) -> f64 {
    let xb = x.to_bits();
    if (xb & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000 && (xb & 0x000f_ffff_ffff_ffff) != 0 {
        return f64::from_bits(xb | 0x0008_0000_0000_0000); // quiet a signaling NaN
    }
    if x == f64::INFINITY {
        return f64::INFINITY;
    }
    if x == 0.0 {
        return f64::MIN_POSITIVE * f64::EPSILON;
    }
    let bits = x.to_bits();
    let next = if x > 0.0 { bits + 1 } else { bits - 1 };
    f64::from_bits(next)
}
fn nextupf_impl(x: f32) -> f32 {
    let xb = x.to_bits();
    if (xb & 0x7f80_0000) == 0x7f80_0000 && (xb & 0x007f_ffff) != 0 {
        return f32::from_bits(xb | 0x0040_0000); // quiet a signaling NaN
    }
    if x == f32::INFINITY {
        return f32::INFINITY;
    }
    if x == 0.0f32 {
        return f32::MIN_POSITIVE * f32::EPSILON;
    }
    let bits = x.to_bits();
    let next = if x > 0.0f32 { bits + 1 } else { bits - 1 };
    f32::from_bits(next)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdown(x: f64) -> f64 {
    nextdown_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf(x: f32) -> f32 {
    nextdownf_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownl(x: f64) -> f64 {
    unsafe { nextdown(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf32(x: f32) -> f32 {
    unsafe { nextdownf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf32x(x: f64) -> f64 {
    unsafe { nextdown(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf64(x: f64) -> f64 {
    unsafe { nextdown(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf64x(x: f64) -> f64 {
    unsafe { nextdown(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextdownf128(x: f128) -> f128 {
    x.next_down()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextup(x: f64) -> f64 {
    nextup_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf(x: f32) -> f32 {
    nextupf_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupl(x: f64) -> f64 {
    unsafe { nextup(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf32(x: f32) -> f32 {
    unsafe { nextupf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf32x(x: f64) -> f64 {
    unsafe { nextup(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf64(x: f64) -> f64 {
    unsafe { nextup(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf64x(x: f64) -> f64 {
    unsafe { nextup(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextupf128(x: f128) -> f128 {
    x.next_up()
}

// --- rsqrt (1/sqrt) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrt(x: f64) -> f64 {
    let s = unsafe { sqrt(x) };
    1.0 / s
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf(x: f32) -> f32 {
    let s = unsafe { sqrtf(x) };
    1.0f32 / s
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtl(x: f64) -> f64 {
    unsafe { rsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf32(x: f32) -> f32 {
    unsafe { rsqrtf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf32x(x: f64) -> f64 {
    unsafe { rsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf64(x: f64) -> f64 {
    unsafe { rsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf64x(x: f64) -> f64 {
    unsafe { rsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rsqrtf128(x: f128) -> f128 {
    // glibc s_rsqrt: errno on islessequal(x,0) (false for NaN), then 1/sqrt(x).
    if x <= 0.0 {
        if x < 0.0 {
            set_domain_errno();
            // sqrtl(negative) is the canonical NEGATIVE qNaN on glibc; 1/that
            // propagates the same NaN. (Rust's f128 sqrt yields a +qNaN, so we
            // produce glibc's bit pattern explicitly.)
            return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
        }
        set_range_errno();
    }
    1.0 / x.sqrt()
}

// --- llogb (long ilogb) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogb(x: f64) -> c_long {
    // `llogb` shares `ilogb`'s exponent result for finite normal/subnormal
    // inputs, but its special-case sentinels are the `long` variants, not the
    // `int` ones: glibc returns FP_LLOGB0 (LONG_MIN) for 0, FP_LLOGBNAN
    // (LONG_MIN) for NaN, and LONG_MAX for infinity — whereas a plain
    // `ilogb(x) as c_long` would widen INT_MIN/INT_MAX and report the wrong
    // sentinel. ilogb already raised FE_INVALID for these inputs.
    map_ilogb_to_llogb(unsafe { ilogb(x) })
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf(x: f32) -> c_long {
    map_ilogb_to_llogb(unsafe { ilogbf(x) })
}

/// Widen an `ilogb` result to the `llogb` return type, translating the
/// `int`-width special sentinels (FP_ILOGB0/FP_ILOGBNAN = INT_MIN, infinity =
/// INT_MAX) to their `long`-width counterparts. Finite exponents (|e| <= 16383
/// even for long double) are far from the i32 extremes, so only the sentinels
/// are remapped.
#[inline]
fn map_ilogb_to_llogb(r: c_int) -> c_long {
    match r {
        c_int::MIN => c_long::MIN, // FP_ILOGB0 / FP_ILOGBNAN -> FP_LLOGB0 / FP_LLOGBNAN
        c_int::MAX => c_long::MAX, // infinity
        other => other as c_long,
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbl(x: f64) -> c_long {
    unsafe { llogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf32(x: f32) -> c_long {
    unsafe { llogbf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf32x(x: f64) -> c_long {
    unsafe { llogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf64(x: f64) -> c_long {
    unsafe { llogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf64x(x: f64) -> c_long {
    unsafe { llogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llogbf128(x: f128) -> c_long {
    let bits = x.to_bits();
    let exp_field = (bits >> 112) & 0x7fff;
    let mant = bits & ((1u128 << 112) - 1);
    if exp_field == 0x7fff {
        unsafe { set_abi_errno(libc::EDOM) };
        return if mant == 0 { c_long::MAX } else { c_long::MIN }; // inf, nan (FP_LLOGBNAN)
    }
    if exp_field == 0 && mant == 0 {
        unsafe { set_abi_errno(libc::EDOM) };
        return c_long::MIN; // FP_LLOGB0
    }
    f128_unbiased_exp(bits) as c_long
}

// --- logp1, log2p1, log10p1 (C23 aliases) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1(x: f64) -> f64 {
    unsafe { log1p(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f(x: f32) -> f32 {
    unsafe { log1pf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1l(x: f64) -> f64 {
    unsafe { logp1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f32(x: f32) -> f32 {
    unsafe { logp1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f32x(x: f64) -> f64 {
    unsafe { logp1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f64(x: f64) -> f64 {
    unsafe { logp1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f64x(x: f64) -> f64 {
    unsafe { logp1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logp1f128(x: f128) -> f128 {
    // C23 logp1 is an exact alias of log1p.
    let r = log1pl_f128(x);
    if x == -1.0 {
        set_range_errno();
    } else if x < -1.0 {
        set_domain_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1(x: f64) -> f64 {
    let r = unsafe { log1p(x) };
    r / std::f64::consts::LN_2
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f(x: f32) -> f32 {
    // glibc computes in double + rounds once; the f32 path (log1pf(x)/LN_2_f32)
    // is ~2 ULP off. Routing through f64 log2p1 is byte-exact (0 ULP).
    unsafe { log2p1(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1l(x: f64) -> f64 {
    unsafe { log2p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f32(x: f32) -> f32 {
    unsafe { log2p1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f32x(x: f64) -> f64 {
    unsafe { log2p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f64(x: f64) -> f64 {
    unsafe { log2p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f64x(x: f64) -> f64 {
    unsafe { log2p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2p1f128(x: f128) -> f128 {
    // glibc s_log2p1_template: log2(e)·log1p(x), linear near 0.
    const LOG2E: f128 = 1.442695040888963407359924681001892137f128;
    if x <= -1.0 {
        if x == -1.0 {
            set_range_errno();
        } else {
            set_domain_errno();
        }
    }
    if x.abs() < f128::from_bits(16269u128 << 112) {
        return LOG2E * x; // |x| < EPSILON/4 = 2^-114
    }
    LOG2E * log1pl_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1(x: f64) -> f64 {
    let r = unsafe { log1p(x) };
    r / std::f64::consts::LN_10
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f(x: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact); the f32 path
    // (log1pf(x)/LN_10_f32) is ~2 ULP off.
    unsafe { log10p1(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1l(x: f64) -> f64 {
    unsafe { log10p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f32(x: f32) -> f32 {
    unsafe { log10p1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f32x(x: f64) -> f64 {
    unsafe { log10p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f64(x: f64) -> f64 {
    unsafe { log10p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f64x(x: f64) -> f64 {
    unsafe { log10p1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10p1f128(x: f128) -> f128 {
    // glibc s_log10p1_template: log10(e)·log1p(x), linear near 0.
    const LOG10E: f128 = 0.434294481903251827651128918916605082f128;
    if x <= -1.0 {
        if x == -1.0 {
            set_range_errno();
        } else {
            set_domain_errno();
        }
    }
    if x.abs() < f128::from_bits(16269u128 << 112) {
        let ret = LOG10E * x; // |x| < EPSILON/4
        if x != 0.0 && ret == 0.0 {
            set_range_errno();
        }
        return ret;
    }
    LOG10E * log1pl_f128(x)
}

// --- exp2m1, exp10m1 (C23) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1(x: f64) -> f64 {
    // C23 2^x - 1. The naive expm1(x*LN_2) amplifies the LN_2 round-off in the
    // argument reduction by the exponential, diverging from glibc by hundreds of
    // ULP for large |x| (e.g. 703 ULP at x~956). Away from 0, 2^x is far from 1 so
    // exp2(x) - 1 is benign and tracks glibc's correctly-rounded exp2 to 0 ULP;
    // only inside |x| < 1 (where 1 is within an ULP of the result) is expm1 needed
    // to avoid catastrophic cancellation. NaN/inf flow through exp2 unchanged.
    if x.abs() < 1.0 {
        unsafe { expm1(x * std::f64::consts::LN_2) }
    } else {
        unsafe { exp2(x) - 1.0 }
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f(x: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact); the f32
    // split path is ~2 ULP off. The f64 exp2m1 keeps the C23 overflow/underflow
    // and clamping semantics.
    unsafe { exp2m1(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1l(x: f64) -> f64 {
    unsafe { exp2m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f32(x: f32) -> f32 {
    unsafe { exp2m1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f32x(x: f64) -> f64 {
    unsafe { exp2m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f64(x: f64) -> f64 {
    unsafe { exp2m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f64x(x: f64) -> f64 {
    unsafe { exp2m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2m1f128(x: f64) -> f64 {
    unsafe { exp2m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1(x: f64) -> f64 {
    // C23 10^x - 1. Same argument-reduction hazard as exp2m1 (naive form diverges
    // ~1080 ULP at x~301). exp10(x) - 1 matches glibc to 0 ULP for |x| >= 0.5;
    // inside that band expm1(x*LN_10) avoids the near-1 cancellation.
    if x.abs() < 0.5 {
        unsafe { expm1(x * std::f64::consts::LN_10) }
    } else {
        unsafe { exp10(x) - 1.0 }
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f(x: f32) -> f32 {
    // Compute in double + round once, matching glibc (byte-exact); the f32
    // split path is ~3 ULP off.
    unsafe { exp10m1(x as f64) as f32 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1l(x: f64) -> f64 {
    unsafe { exp10m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f32(x: f32) -> f32 {
    unsafe { exp10m1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f32x(x: f64) -> f64 {
    unsafe { exp10m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f64(x: f64) -> f64 {
    unsafe { exp10m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f64x(x: f64) -> f64 {
    unsafe { exp10m1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10m1f128(x: f128) -> f128 {
    // glibc s_exp10m1_template: small |x| via expm1(ln10·x), large via exp10.
    const M_LN10: f128 = 2.302585092994045684017991454684364208f128;
    if x >= -0.5 && x <= 0.5 {
        expm1l_f128(M_LN10 * x)
    } else if x > 39.0 {
        // M_MANT_DIG/3 + 2 = 113/3 + 2 = 39
        let ret = exp10l_f128(x);
        if !ret.is_finite() && x.is_finite() {
            set_range_errno();
        }
        ret
    } else if x < -39.0 {
        -1.0
    } else {
        exp10l_f128(x) - 1.0
    }
}

// --- compoundn ((1+x)^n) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundn(x: f64, n: i64) -> f64 {
    // C23 7.12.7.1: compoundn(x, n) = (1+x)^n is defined only for x >= -1;
    // x < -1 is a domain error (NaN + FE_INVALID). For x >= -1, pow already
    // gives the exact contract: pow(anything,0)=1 (incl NaN/inf), pow(0,n<0)=
    // inf+DBZ, NaN propagation.
    if x < -1.0 {
        pi_fn_raise_invalid_f64();
        return f64::NAN;
    }
    frankenlibc_core::math::pow(1.0 + x, n as f64)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf(x: f32, n: i64) -> f32 {
    if x < -1.0 {
        pi_fn_raise_invalid_f32();
        return f32::NAN;
    }
    frankenlibc_core::math::powf(1.0f32 + x, n as f32)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnl(x: f64, n: i64) -> f64 {
    unsafe { compoundn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf32(x: f32, n: i64) -> f32 {
    unsafe { compoundnf(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf32x(x: f64, n: i64) -> f64 {
    unsafe { compoundn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf64(x: f64, n: i64) -> f64 {
    unsafe { compoundn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf64x(x: f64, n: i64) -> f64 {
    unsafe { compoundn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn compoundnf128(x: f64, n: i64) -> f64 {
    unsafe { compoundn(x, n) }
}

// --- pown (x^n integer) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pown(x: f64, n: i64) -> f64 {
    frankenlibc_core::math::pow(x, n as f64)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf(x: f32, n: i64) -> f32 {
    frankenlibc_core::math::powf(x, n as f32)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownl(x: f64, n: i64) -> f64 {
    unsafe { pown(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf32(x: f32, n: i64) -> f32 {
    unsafe { pownf(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf32x(x: f64, n: i64) -> f64 {
    unsafe { pown(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf64(x: f64, n: i64) -> f64 {
    unsafe { pown(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf64x(x: f64, n: i64) -> f64 {
    unsafe { pown(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pownf128(x: f64, n: i64) -> f64 {
    unsafe { pown(x, n) }
}

// --- powr (x^y for positive x) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powr(x: f64, y: f64) -> f64 {
    // C23 7.12.7.2: powr(x, y) = exp(y*log(x)), defined for x >= 0. Unlike pow,
    // powr propagates NaN in BOTH args (powr(NaN,0)=NaN, not 1) and the
    // indeterminate forms 0^0, inf^0, 1^±inf are domain errors (NaN+INVALID).
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    if x < 0.0 {
        pi_fn_raise_invalid_f64();
        return f64::NAN;
    }
    if (x == 0.0 && y == 0.0) || (x.is_infinite() && y == 0.0) || (x == 1.0 && y.is_infinite()) {
        pi_fn_raise_invalid_f64();
        return f64::NAN;
    }
    frankenlibc_core::math::pow(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf(x: f32, y: f32) -> f32 {
    if x.is_nan() || y.is_nan() {
        return f32::NAN;
    }
    if x < 0.0f32 {
        pi_fn_raise_invalid_f32();
        return f32::NAN;
    }
    if (x == 0.0 && y == 0.0) || (x.is_infinite() && y == 0.0) || (x == 1.0 && y.is_infinite()) {
        pi_fn_raise_invalid_f32();
        return f32::NAN;
    }
    frankenlibc_core::math::powf(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrl(x: f64, y: f64) -> f64 {
    unsafe { powr(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf32(x: f32, y: f32) -> f32 {
    unsafe { powrf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf32x(x: f64, y: f64) -> f64 {
    unsafe { powr(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf64(x: f64, y: f64) -> f64 {
    unsafe { powr(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf64x(x: f64, y: f64) -> f64 {
    unsafe { powr(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powrf128(x: f64, y: f64) -> f64 {
    unsafe { powr(x, y) }
}

// --- rootn (nth root) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootn(x: f64, n: i64) -> f64 {
    // C23 7.12.7.4: rootn(x, n) = x^(1/n). Naive pow(x, 1/n) is wrong for
    // negative x with ODD n (the real n-th root exists, e.g. rootn(-8,3)=-2,
    // but pow(-8, 0.333…)=NaN). Handle the sign explicitly.
    if n == 0 {
        pi_fn_raise_invalid_f64(); // rootn(x,0) is a domain error
        return f64::NAN;
    }
    if x.is_nan() {
        return x;
    }
    if x < 0.0 {
        if n & 1 == 0 {
            pi_fn_raise_invalid_f64(); // even root of a negative is undefined
            return f64::NAN;
        }
        return -frankenlibc_core::math::pow(-x, 1.0 / n as f64);
    }
    let r = frankenlibc_core::math::pow(x, 1.0 / n as f64);
    // pow(-0.0, +/-frac) loses the sign for an odd root; restore it.
    if x == 0.0 && (n & 1 != 0) {
        r.copysign(x)
    } else {
        r
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf(x: f32, n: i64) -> f32 {
    if n == 0 {
        pi_fn_raise_invalid_f32();
        return f32::NAN;
    }
    if x.is_nan() {
        return x;
    }
    if x < 0.0 {
        if n & 1 == 0 {
            pi_fn_raise_invalid_f32();
            return f32::NAN;
        }
        return -frankenlibc_core::math::powf(-x, 1.0f32 / n as f32);
    }
    let r = frankenlibc_core::math::powf(x, 1.0f32 / n as f32);
    if x == 0.0 && (n & 1 != 0) {
        r.copysign(x)
    } else {
        r
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnl(x: f64, n: i64) -> f64 {
    unsafe { rootn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf32(x: f32, n: i64) -> f32 {
    unsafe { rootnf(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf32x(x: f64, n: i64) -> f64 {
    unsafe { rootn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf64(x: f64, n: i64) -> f64 {
    unsafe { rootn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf64x(x: f64, n: i64) -> f64 {
    unsafe { rootn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rootnf128(x: f64, n: i64) -> f64 {
    unsafe { rootn(x, n) }
}

// --- fmaxmag / fminmag (C23) ---

// glibc fmaxmag/fminmag: the non-NaN argument wins when one is NaN, and on an
// equal-magnitude tie the result is the larger/smaller VALUE — `if x > y`, NOT
// fmax. fmax(+0,-0) yields +0, but glibc fmaxmag(+0,-0) is -0 (`+0 > -0` is
// false, so it returns y). Using fmax/fmin here was a signed-zero parity bug.
fn fmaxmag_impl(x: f64, y: f64) -> f64 {
    let ax = x.abs();
    let ay = y.abs();
    if ax > ay || ay.is_nan() {
        x
    } else if ay > ax || ax.is_nan() {
        y
    } else if x > y {
        x
    } else {
        y
    }
}
fn fmaxmagf_impl(x: f32, y: f32) -> f32 {
    let ax = x.abs();
    let ay = y.abs();
    if ax > ay || ay.is_nan() {
        x
    } else if ay > ax || ax.is_nan() {
        y
    } else if x > y {
        x
    } else {
        y
    }
}
fn fminmag_impl(x: f64, y: f64) -> f64 {
    let ax = x.abs();
    let ay = y.abs();
    if ax < ay || ay.is_nan() {
        x
    } else if ay < ax || ax.is_nan() {
        y
    } else if x < y {
        x
    } else {
        y
    }
}
fn fminmagf_impl(x: f32, y: f32) -> f32 {
    let ax = x.abs();
    let ay = y.abs();
    if ax < ay || ay.is_nan() {
        x
    } else if ay < ax || ax.is_nan() {
        y
    } else if x < y {
        x
    } else {
        y
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmag(x: f64, y: f64) -> f64 {
    fmaxmag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf(x: f32, y: f32) -> f32 {
    fmaxmagf_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagl(x: f64, y: f64) -> f64 {
    unsafe { fmaxmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf32(x: f32, y: f32) -> f32 {
    unsafe { fmaxmagf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf32x(x: f64, y: f64) -> f64 {
    unsafe { fmaxmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf64(x: f64, y: f64) -> f64 {
    unsafe { fmaxmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf64x(x: f64, y: f64) -> f64 {
    unsafe { fmaxmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxmagf128(x: f128, y: f128) -> f128 {
    // Greater magnitude; equal magnitude or a NaN operand defers to fmax.
    if x.is_nan() {
        return if y.is_nan() { x } else { y };
    }
    if y.is_nan() {
        return x;
    }
    let (ax, ay) = (x.abs(), y.abs());
    if ax > ay {
        x
    } else if ay > ax {
        y
    } else if x > y {
        x
    } else {
        y
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmag(x: f64, y: f64) -> f64 {
    fminmag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf(x: f32, y: f32) -> f32 {
    fminmagf_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagl(x: f64, y: f64) -> f64 {
    unsafe { fminmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf32(x: f32, y: f32) -> f32 {
    unsafe { fminmagf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf32x(x: f64, y: f64) -> f64 {
    unsafe { fminmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf64(x: f64, y: f64) -> f64 {
    unsafe { fminmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf64x(x: f64, y: f64) -> f64 {
    unsafe { fminmag(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminmagf128(x: f128, y: f128) -> f128 {
    // Lesser magnitude; equal magnitude or a NaN operand defers to fmin.
    if x.is_nan() {
        return if y.is_nan() { x } else { y };
    }
    if y.is_nan() {
        return x;
    }
    let (ax, ay) = (x.abs(), y.abs());
    if ax < ay {
        x
    } else if ay < ax {
        y
    } else if x < y {
        x
    } else {
        y
    }
}

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
pub unsafe extern "C" fn totalorder(x: *const f64, y: *const f64) -> c_int {
    totalorder_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf(x: *const f32, y: *const f32) -> c_int {
    totalorderf_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderl(x: *const f64, y: *const f64) -> c_int {
    totalorder_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf32(x: *const f32, y: *const f32) -> c_int {
    totalorderf_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf32x(x: *const f64, y: *const f64) -> c_int {
    totalorder_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf64(x: *const f64, y: *const f64) -> c_int {
    totalorder_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf64x(x: *const f64, y: *const f64) -> c_int {
    totalorder_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf128(x: *const f64, y: *const f64) -> c_int {
    totalorder_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermag(x: *const f64, y: *const f64) -> c_int {
    totalordermag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf(x: *const f32, y: *const f32) -> c_int {
    totalordermagf_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagl(x: *const f64, y: *const f64) -> c_int {
    totalordermag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf32(x: *const f32, y: *const f32) -> c_int {
    totalordermagf_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf32x(x: *const f64, y: *const f64) -> c_int {
    totalordermag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf64(x: *const f64, y: *const f64) -> c_int {
    totalordermag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf64x(x: *const f64, y: *const f64) -> c_int {
    totalordermag_impl(x, y)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf128(x: *const f64, y: *const f64) -> c_int {
    totalordermag_impl(x, y)
}

// --- canonicalize (C23 IEEE 754) ---

fn canonicalize_impl(cx: *mut f64, x: *const f64) -> c_int {
    // Every IEEE binary64 value is canonical, so canonicalize always succeeds
    // (returns 0). The only transformation glibc applies is quieting a
    // signaling NaN (set the mantissa MSB) — preserving sign and payload.
    let mut bits = unsafe { *x }.to_bits();
    let is_nan = (bits & 0x7ff0_0000_0000_0000) == 0x7ff0_0000_0000_0000
        && (bits & 0x000f_ffff_ffff_ffff) != 0;
    if is_nan {
        bits |= 0x0008_0000_0000_0000; // quiet bit
    }
    if !cx.is_null() {
        unsafe {
            *cx = f64::from_bits(bits);
        }
    }
    0
}
fn canonicalizef_impl(cx: *mut f32, x: *const f32) -> c_int {
    let mut bits = unsafe { *x }.to_bits();
    let is_nan = (bits & 0x7f80_0000) == 0x7f80_0000 && (bits & 0x007f_ffff) != 0;
    if is_nan {
        bits |= 0x0040_0000; // quiet bit
    }
    if !cx.is_null() {
        unsafe {
            *cx = f32::from_bits(bits);
        }
    }
    0
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize(cx: *mut f64, x: *const f64) -> c_int {
    canonicalize_impl(cx, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef(cx: *mut f32, x: *const f32) -> c_int {
    canonicalizef_impl(cx, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizel(cx: *mut f64, x: *const f64) -> c_int {
    canonicalize_impl(cx, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef32(cx: *mut f32, x: *const f32) -> c_int {
    canonicalizef_impl(cx, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef32x(cx: *mut f64, x: *const f64) -> c_int {
    canonicalize_impl(cx, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef64(cx: *mut f64, x: *const f64) -> c_int {
    canonicalize_impl(cx, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef64x(cx: *mut f64, x: *const f64) -> c_int {
    canonicalize_impl(cx, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef128(cx: *mut f64, x: *const f64) -> c_int {
    canonicalize_impl(cx, x)
}

// --- getpayload / setpayload / setpayloadsig (C23) ---

fn getpayload_impl(x: *const f64) -> f64 {
    let val = unsafe { *x };
    if !val.is_nan() {
        return -1.0;
    }
    let bits = val.to_bits();
    (bits & 0x0007_FFFF_FFFF_FFFF) as f64
}
fn getpayloadf_impl(x: *const f32) -> f32 {
    let val = unsafe { *x };
    if !val.is_nan() {
        return -1.0f32;
    }
    let bits = val.to_bits();
    (bits & 0x003F_FFFF) as f32
}
// C23 setpayload/setpayloadsig: the payload must be a non-negative INTEGER in
// range. A non-integer (1.5), NaN, inf or out-of-range value fails (returns 1)
// and sets *res to +0 — glibc does NOT truncate (the old `payload as u64`
// silently accepted 1.5 as 1 and never zeroed *res). setpayloadsig additionally
// requires payload >= 1 (payload 0 would yield an infinity, not an sNaN).
fn setpayload_impl(res: *mut f64, payload: f64) -> c_int {
    if (0.0..2_251_799_813_685_248.0).contains(&payload) && payload == payload.trunc() {
        unsafe {
            *res = f64::from_bits(0x7FF8_0000_0000_0000 | payload as u64);
        }
        0
    } else {
        unsafe { *res = 0.0 };
        1
    }
}
fn setpayloadf_impl(res: *mut f32, payload: f32) -> c_int {
    if (0.0..4_194_304.0).contains(&payload) && payload == payload.trunc() {
        unsafe {
            *res = f32::from_bits(0x7FC0_0000 | payload as u32);
        }
        0
    } else {
        unsafe { *res = 0.0 };
        1
    }
}
fn setpayloadsig_impl(res: *mut f64, payload: f64) -> c_int {
    if (1.0..2_251_799_813_685_248.0).contains(&payload) && payload == payload.trunc() {
        unsafe {
            *res = f64::from_bits(0x7FF0_0000_0000_0000 | payload as u64);
        }
        0
    } else {
        unsafe { *res = 0.0 };
        1
    }
}
fn setpayloadsigf_impl(res: *mut f32, payload: f32) -> c_int {
    if (1.0..4_194_304.0).contains(&payload) && payload == payload.trunc() {
        unsafe {
            *res = f32::from_bits(0x7F80_0000 | payload as u32);
        }
        0
    } else {
        unsafe { *res = 0.0 };
        1
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayload(x: *const f64) -> f64 {
    getpayload_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf(x: *const f32) -> f32 {
    getpayloadf_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadl(x: *const f64) -> f64 {
    getpayload_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf32(x: *const f32) -> f32 {
    getpayloadf_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf32x(x: *const f64) -> f64 {
    getpayload_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf64(x: *const f64) -> f64 {
    getpayload_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf64x(x: *const f64) -> f64 {
    getpayload_impl(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf128(x: *const f128) -> f128 {
    let bits = unsafe { (*x).to_bits() };
    let exp = (bits >> 112) & 0x7fff;
    let mant = bits & ((1u128 << 112) - 1);
    if exp == 0x7fff && mant != 0 {
        // NaN: payload is the significand bits below the quiet bit (bit 111).
        (mant & ((1u128 << 111) - 1)) as f128
    } else {
        -1.0
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayload(res: *mut f64, pl: f64) -> c_int {
    setpayload_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf(res: *mut f32, pl: f32) -> c_int {
    setpayloadf_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadl(res: *mut f64, pl: f64) -> c_int {
    setpayload_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf32(res: *mut f32, pl: f32) -> c_int {
    setpayloadf_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf32x(res: *mut f64, pl: f64) -> c_int {
    setpayload_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf64(res: *mut f64, pl: f64) -> c_int {
    setpayload_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf64x(res: *mut f64, pl: f64) -> c_int {
    setpayload_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf128(res: *mut f128, pl: f128) -> c_int {
    // Quiet NaN with payload pl (an integer in [0, 2^111)); else *res = +0, rc 1.
    let two111 = f128::from_bits((111u128 + 16383) << 112);
    if pl.is_finite() && pl >= 0.0 && pl == pl.trunc() && pl < two111 {
        let payload = pl as u128;
        unsafe { *res = f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111) | payload) };
        0
    } else {
        unsafe { *res = 0.0 };
        1
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsig(res: *mut f64, pl: f64) -> c_int {
    setpayloadsig_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf(res: *mut f32, pl: f32) -> c_int {
    setpayloadsigf_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigl(res: *mut f64, pl: f64) -> c_int {
    setpayloadsig_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf32(res: *mut f32, pl: f32) -> c_int {
    setpayloadsigf_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf32x(res: *mut f64, pl: f64) -> c_int {
    setpayloadsig_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf64(res: *mut f64, pl: f64) -> c_int {
    setpayloadsig_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf64x(res: *mut f64, pl: f64) -> c_int {
    setpayloadsig_impl(res, pl)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf128(res: *mut f128, pl: f128) -> c_int {
    // Signaling NaN with payload pl (an integer in [1, 2^111) — must be nonzero
    // so the result is a NaN, not infinity); else *res = +0, rc 1.
    let two111 = f128::from_bits((111u128 + 16383) << 112);
    if pl.is_finite() && pl >= 1.0 && pl == pl.trunc() && pl < two111 {
        let payload = pl as u128;
        unsafe { *res = f128::from_bits((0x7fff_u128 << 112) | payload) };
        0
    } else {
        unsafe { *res = 0.0 };
        1
    }
}

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

/// Raise FE_INEXACT via a safe force_eval (1/3 is inexact). Used by the
/// fromfpx/ufromfpx variants when the kept (in-range) result differs from x.
#[inline]
#[allow(dead_code)]
fn raise_inexact_f64() {
    let _ = core::hint::black_box(core::hint::black_box(1.0_f64) / core::hint::black_box(3.0_f64));
}

/// 2^n for n in 0..=64, exact and FE-flag-free (bit construction). `2f64.powi(n)`
/// with a runtime n lowers to a libm pow call that raises FE_INEXACT even though
/// 2^n is exact, which would pollute fromfp's flag contract.
#[inline]
fn pow2_exact(n: u32) -> f64 {
    f64::from_bits((1023u64 + n as u64) << 52)
}

/// Round in the requested FP_INT direction WITHOUT raising FP exceptions.
/// `fromfp` must raise only FE_INVALID (the *x variants add FE_INEXACT
/// explicitly), so the rounding itself must be flag-free. ceil/floor/trunc
/// lower to suppress-precision roundsd; round-half-away/even are built from
/// trunc + exact integer arithmetic (x - trunc(x) is exact; adding ±1 to an
/// integer-valued f64 is exact). `f64::round` is NOT used: it raises INEXACT.
#[inline]
fn fromfp_round(x: f64, rnd: c_int) -> f64 {
    match rnd {
        FP_INT_UPWARD => x.ceil(),
        FP_INT_DOWNWARD => x.floor(),
        FP_INT_TOWARDZERO => x.trunc(),
        FP_INT_TONEARESTFROMZERO => {
            let t = x.trunc();
            if (x - t).abs() >= 0.5 {
                t + x.signum()
            } else {
                t
            }
        }
        _ => {
            // FP_INT_TONEAREST: round half to even.
            let t = x.trunc();
            let af = (x - t).abs();
            if af < 0.5 {
                t
            } else if af > 0.5 {
                t + x.signum()
            } else if (t as i64) % 2 == 0 {
                t // tie: t already even
            } else {
                t + x.signum()
            }
        }
    }
}

/// Shared core for fromfp/fromfpx. Matches glibc: round x in the requested
/// direction to a signed integer of `width` bits; NaN/±inf and out-of-range
/// results raise FE_INVALID and return glibc's clamp (max for NaN/+inf/overflow,
/// min for -inf/underflow). With `inexact`, also raise FE_INEXACT when the kept
/// result differs from x (the fromfpx variant).
const FE_INVALID_BIT: c_int = 0x01;
const FE_INEXACT_BIT: c_int = 0x20;

unsafe extern "C" {
    fn feraiseexcept(excepts: c_int) -> c_int;
    fn feclearexcept(excepts: c_int) -> c_int;
    fn fetestexcept(excepts: c_int) -> c_int;
}

/// Set the FP exception state for the fromfp family to EXACTLY the caller's
/// pre-existing flags plus `want` (FE_INVALID/FE_INEXACT). The decision logic
/// itself performs FP arithmetic (rounding, 2^w construction) that can raise
/// spurious flags; computing the intended flags as pure booleans and then
/// stamping them here makes the contract exact regardless.
#[inline]
fn fromfp_set_flags(entry: c_int, want: c_int) {
    unsafe {
        feclearexcept(FE_INVALID_BIT | FE_INEXACT_BIT);
        let f = (entry & (FE_INVALID_BIT | FE_INEXACT_BIT)) | want;
        if f != 0 {
            feraiseexcept(f);
        }
    }
}

fn fromfp_core(x: f64, rnd: c_int, width: u32, inexact: bool) -> i64 {
    let entry = unsafe { fetestexcept(FE_INVALID_BIT | FE_INEXACT_BIT) };
    let w = width.min(64);
    if w == 0 {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return 0;
    }
    // Signed `width`-bit target range [min, max] = [-2^(w-1), 2^(w-1)-1], held
    // as exact integers (no float rounding of the bound — that was the old bug:
    // the f64 model clamped a width-64 overflow to 2^63 with a spurious
    // FE_INEXACT, where glibc returns exactly 2^63-1 with FE_INVALID only).
    let max: i64 = if w == 64 {
        i64::MAX
    } else {
        (1i64 << (w - 1)) - 1
    };
    let min: i64 = if w == 64 {
        i64::MIN
    } else {
        -(1i64 << (w - 1))
    };
    // 2^(w-1) as an exact f64 — the first out-of-range high value, used only to
    // classify the (integer-valued) rounded result, never as the return value.
    let thresh_hi = pow2_exact(w - 1);

    if x.is_nan() {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return max;
    }
    if x.is_infinite() {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return if x > 0.0 { max } else { min };
    }
    let r = fromfp_round(x, rnd); // exact integer-valued f64, raises no flags
    if r >= thresh_hi {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return max;
    }
    if r < -thresh_hi {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return min;
    }
    // In range: r is an integer-valued f64 in [min, max] (|r| < 2^63), so the
    // cast is exact. fromfpx (inexact=true) reports FE_INEXACT when rounding
    // changed the value; fromfp (inexact=false) never does. The float->int cast
    // (cvttsd2si) can itself raise a spurious FE_INEXACT, so it must run BEFORE
    // the final flag stamp — fromfp_set_flags clears and re-raises the exact set.
    let inx = if inexact && r != x { FE_INEXACT_BIT } else { 0 };
    let result = r as i64;
    fromfp_set_flags(entry, inx);
    result
}

/// Shared core for ufromfp/ufromfpx. Unsigned range [0, 2^width-1]; negatives
/// that round into range are valid (e.g. ufromfp(-0.4, UPWARD) = 0). Returns the
/// rounded value as a `uintmax_t`, matching glibc.
fn ufromfp_core(x: f64, rnd: c_int, width: u32, inexact: bool) -> u64 {
    let entry = unsafe { fetestexcept(FE_INVALID_BIT | FE_INEXACT_BIT) };
    let w = width.min(64);
    if w == 0 {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return 0;
    }
    let max: u64 = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
    let thresh_hi = pow2_exact(w); // 2^w as exact f64 — first out-of-range value

    if x.is_nan() {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return max;
    }
    if x.is_infinite() {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return if x > 0.0 { max } else { 0 };
    }
    let r = fromfp_round(x, rnd);
    if r >= thresh_hi {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return max;
    }
    if r < 0.0 {
        fromfp_set_flags(entry, FE_INVALID_BIT);
        return 0;
    }
    // In range: r is an integer-valued f64 in [0, 2^64), cast is exact. The
    // cvttsd2usi cast can raise a spurious FE_INEXACT, so cast BEFORE stamping.
    let inx = if inexact && r != x { FE_INEXACT_BIT } else { 0 };
    let result = r as u64;
    fromfp_set_flags(entry, inx);
    result
}

fn fromfp_impl(x: f64, rnd: c_int, width: u32) -> i64 {
    fromfp_core(x, rnd, width, false)
}
fn fromfpx_impl(x: f64, rnd: c_int, width: u32) -> i64 {
    fromfp_core(x, rnd, width, true)
}
// f32 input widens to f64 losslessly, so the rounding/clamp is identical.
fn fromfpf_impl(x: f32, rnd: c_int, width: u32) -> i64 {
    fromfp_core(x as f64, rnd, width, false)
}
fn fromfpxf_impl(x: f32, rnd: c_int, width: u32) -> i64 {
    fromfp_core(x as f64, rnd, width, true)
}
fn ufromfp_impl(x: f64, rnd: c_int, width: u32) -> u64 {
    ufromfp_core(x, rnd, width, false)
}
fn ufromfpx_impl(x: f64, rnd: c_int, width: u32) -> u64 {
    ufromfp_core(x, rnd, width, true)
}
fn ufromfpf_impl(x: f32, rnd: c_int, width: u32) -> u64 {
    ufromfp_core(x as f64, rnd, width, false)
}
fn ufromfpxf_impl(x: f32, rnd: c_int, width: u32) -> u64 {
    ufromfp_core(x as f64, rnd, width, true)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfp(x: f64, rnd: c_int, width: u32) -> i64 {
    fromfp_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf(x: f32, rnd: c_int, width: u32) -> i64 {
    fromfpf_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpl(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf32(x: f32, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfpf(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf32x(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf64(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf64x(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpf128(x: f128, rnd: c_int, width: u32) -> i64 {
    fromfp_signed_f128(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfp(x: f64, rnd: c_int, width: u32) -> u64 {
    ufromfp_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf(x: f32, rnd: c_int, width: u32) -> u64 {
    ufromfpf_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpl(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf32(x: f32, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfpf(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf32x(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf64(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf64x(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfp(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpf128(x: f128, rnd: c_int, width: u32) -> u64 {
    fromfp_unsigned_f128(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpx(x: f64, rnd: c_int, width: u32) -> i64 {
    fromfpx_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf(x: f32, rnd: c_int, width: u32) -> i64 {
    fromfpxf_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxl(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf32(x: f32, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfpxf(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf32x(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf64(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf64x(x: f64, rnd: c_int, width: u32) -> i64 {
    unsafe { fromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fromfpxf128(x: f128, rnd: c_int, width: u32) -> i64 {
    // Same value/errno as fromfp; the distinguishing FE_INEXACT flag is omitted.
    fromfp_signed_f128(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpx(x: f64, rnd: c_int, width: u32) -> u64 {
    ufromfpx_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf(x: f32, rnd: c_int, width: u32) -> u64 {
    ufromfpxf_impl(x, rnd, width)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxl(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf32(x: f32, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfpxf(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf32x(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf64(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf64x(x: f64, rnd: c_int, width: u32) -> u64 {
    unsafe { ufromfpx(x, rnd, width) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ufromfpxf128(x: f128, rnd: c_int, width: u32) -> u64 {
    // Same value/errno as ufromfp; FE_INEXACT flag omitted.
    fromfp_unsigned_f128(x, rnd, width)
}

// --- clog10 (complex log base 10) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10(z: CDoubleComplex) -> CDoubleComplex {
    let r = unsafe { clog(z) };
    let ln10 = std::f64::consts::LN_10;
    CDoubleComplex {
        re: r.re / ln10,
        im: r.im / ln10,
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f(z: CFloatComplex) -> CFloatComplex {
    let r = unsafe { clogf(z) };
    let ln10 = std::f32::consts::LN_10;
    CFloatComplex {
        re: r.re / ln10,
        im: r.im / ln10,
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10l(z: CLongDoubleComplex) -> CLongDoubleComplex {
    let r = unsafe { clog10(CDoubleComplex { re: z.re, im: z.im }) };
    CLongDoubleComplex { re: r.re, im: r.im }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clog10(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog10(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clog10f(z: CFloatComplex) -> CFloatComplex {
    unsafe { clog10f(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __clog10l(z: CLongDoubleComplex) -> CLongDoubleComplex {
    unsafe { clog10l(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f32(z: CFloatComplex) -> CFloatComplex {
    unsafe { clog10f(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog10(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog10(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog10(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clog10f128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog10(z) }
}

// --- lgamma*_r width variants ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammal_r(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32_r(x: f32, signgamp: *mut c_int) -> f32 {
    unsafe { lgammaf_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32x_r(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64_r(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64x_r(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { lgamma_r(x, signgamp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf128_r(x: f64, signgamp: *mut c_int) -> f64 {
    unsafe { lgamma_r(x, signgamp) }
}

// =========================================================================
// Long-double variants (forward to double)
// =========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshl(x: f64) -> f64 {
    unsafe { acosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosl(x: f64) -> f64 {
    unsafe { acos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhl(x: f64) -> f64 {
    unsafe { asinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinl(x: f64) -> f64 {
    unsafe { asin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhl(x: f64) -> f64 {
    unsafe { atanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanl(x: f64) -> f64 {
    unsafe { atan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtl(x: f64) -> f64 {
    unsafe { cbrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceill(x: f64) -> f64 {
    unsafe { ceil(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshl(x: f64) -> f64 {
    unsafe { cosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosl(x: f64) -> f64 {
    unsafe { cos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcl(x: f64) -> f64 {
    unsafe { erfc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfl(x: f64) -> f64 {
    unsafe { erf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10l(x: f64) -> f64 {
    unsafe { exp10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2l(x: f64) -> f64 {
    unsafe { exp2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expl(x: f64) -> f64 {
    unsafe { exp(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1l(x: f64) -> f64 {
    unsafe { expm1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsl(x: f64) -> f64 {
    unsafe { fabs(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorl(x: f64) -> f64 {
    unsafe { floor(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammal(x: f64) -> f64 {
    unsafe { lgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10l(x: f64) -> f64 {
    unsafe { log10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pl(x: f64) -> f64 {
    unsafe { log1p(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2l(x: f64) -> f64 {
    unsafe { log2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbl(x: f64) -> f64 {
    unsafe { logb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logl(x: f64) -> f64 {
    unsafe { log(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintl(x: f64) -> f64 {
    unsafe { nearbyint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintl(x: f64) -> f64 {
    unsafe { rint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundl(x: f64) -> f64 {
    unsafe { round(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhl(x: f64) -> f64 {
    unsafe { sinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinl(x: f64) -> f64 {
    unsafe { sin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtl(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhl(x: f64) -> f64 {
    unsafe { tanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanl(x: f64) -> f64 {
    unsafe { tan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammal(x: f64) -> f64 {
    unsafe { tgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncl(x: f64) -> f64 {
    unsafe { trunc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2l(x: f64, y: f64) -> f64 {
    unsafe { atan2(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdiml(x: f64, y: f64) -> f64 {
    unsafe { fdim(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxl(x: f64, y: f64) -> f64 {
    unsafe { fmax(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminl(x: f64, y: f64) -> f64 {
    unsafe { fmin(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodl(x: f64, y: f64) -> f64 {
    unsafe { fmod(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotl(x: f64, y: f64) -> f64 {
    unsafe { hypot(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterl(x: f64, y: f64) -> f64 {
    unsafe { nextafter(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powl(x: f64, y: f64) -> f64 {
    unsafe { pow(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderl(x: f64, y: f64) -> f64 {
    unsafe { remainder(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmal(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbl(x: f64) -> c_int {
    unsafe { ilogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintl(x: f64) -> c_long {
    unsafe { lrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundl(x: f64) -> c_long {
    unsafe { lround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintl(x: f64) -> i64 {
    unsafe { llrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundl(x: f64) -> i64 {
    unsafe { llround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnl(x: f64, n: c_long) -> f64 {
    unsafe { scalbln(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquol(x: f64, y: f64, quo: *mut c_int) -> f64 {
    unsafe { remquo(x, y, quo) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanl(tagp: *const std::ffi::c_char) -> f64 {
    unsafe { nan(tagp) }
}
#[cfg_attr(
    all(not(debug_assertions), not(target_arch = "x86_64")),
    unsafe(no_mangle)
)]
pub unsafe extern "C" fn nexttowardl(x: f64, y: f64) -> f64 {
    unsafe { nextafter(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnl(n: c_int, x: f64) -> f64 {
    unsafe { jn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0l(x: f64) -> f64 {
    unsafe { j0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1l(x: f64) -> f64 {
    unsafe { j1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynl(n: c_int, x: f64) -> f64 {
    unsafe { yn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0l(x: f64) -> f64 {
    unsafe { y0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1l(x: f64) -> f64 {
    unsafe { y1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pow10l(x: f64) -> f64 {
    unsafe { pow10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gammal(x: f64) -> f64 {
    unsafe { gamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dreml(x: f64, y: f64) -> f64 {
    unsafe { drem(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn significandl(x: f64) -> f64 {
    unsafe { significand(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosl(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbl(x: f64, y: f64) -> f64 {
    // Same public SVID semantics as `scalb`: non-integer exponents report
    // EDOM+FE_INVALID, and finite integer overflow/underflow reports ERANGE.
    scalb_svid_impl(x, y)
}

// =========================================================================
// C23 narrowing math functions
// =========================================================================

/// Boldo–Melquiond round-to-odd: `(x OP y) as f32` double-rounds (round the
/// exact result to f64, then to f32), which disagrees with the C23 contract of
/// a SINGLE correct rounding to f32 — e.g. fadd(1+2^-24, 2^-53) double-rounds
/// to 1.0 but the correctly-rounded f32 is 1.0000001. Given the f64
/// round-to-nearest result `t` and the SIGN of the exact residual (E - t)
/// carried in `resid` (resid == 0 ⟺ E is exactly t), nudge `t` to an
/// odd-significand f64 toward the residual before the f32 cast. Since f64 has
/// 53 > 2*24+1 bits, round-to-odd-to-f64 then round-to-nearest-to-f32 equals
/// the single correctly-rounded f32 of E.
#[inline]
fn narrow_round_odd(t: f64, resid: f64) -> f32 {
    if !t.is_finite() || resid == 0.0 {
        return t as f32;
    }
    let ro = if t.to_bits() & 1 == 1 {
        t // already odd: it is the round-to-odd value
    } else {
        let dir = if resid > 0.0 {
            f64::INFINITY
        } else {
            f64::NEG_INFINITY
        };
        frankenlibc_core::math::nextafter(t, dir)
    };
    ro as f32
}

/// Round-to-odd for binary128: given the round-to-nearest f128 result `t` and
/// the exact residual `resid` (sign of E - t; resid==0 ⟺ E is exactly t), nudge
/// `t` to an odd-significand f128 on E's side. Casting the result to f64 or f32
/// then gives the single correctly-rounded narrow value — f128's 113 bits
/// exceed 2·53+2, so the otherwise-double rounding (f128→f64/f32 cast) is
/// defeated. This is the wide-operand analogue of `narrow_round_odd`, used by
/// the C23 `fN{op}f128` narrowing functions.
#[inline]
fn narrow_round_odd_f128(t: f128, resid: f128) -> f128 {
    if !t.is_finite() || resid == 0.0 {
        return t;
    }
    if t == 0.0 {
        // Underflow to zero: the round-to-odd value is the smallest subnormal
        // toward E (sign matches the residual; +0/-0 are consistent with it).
        let sign = if resid < 0.0 { 1u128 << 127 } else { 0 };
        return f128::from_bits(sign | 1);
    }
    if t.to_bits() & 1 == 1 {
        return t; // already odd
    }
    // Step one ULP toward E. Toward +inf raises the bit pattern for positive t
    // and lowers it for negative t (the format is monotone in bits per sign).
    let bits = t.to_bits();
    let positive = bits >> 127 == 0;
    let toward_pos = resid > 0.0;
    let nb = if toward_pos == positive { bits + 1 } else { bits - 1 };
    f128::from_bits(nb)
}

/// On x86_64/glibc an invalid operation on non-NaN operands yields the
/// canonical NEGATIVE qNaN (0xffff8…), whereas Rust's f128 software arithmetic
/// yields a positive qNaN. When `r` is NaN but no operand was NaN (a freshly
/// raised invalid op), return glibc's negative qNaN; otherwise pass `r` through
/// unchanged (NaN-propagation and finite/inf results are already correct).
#[inline]
fn fixup_invalid_nan_f128(r: f128, operand_nan: bool) -> f128 {
    if r.is_nan() && !operand_nan {
        f128::from_bits((0xffff_u128 << 112) | (1u128 << 111))
    } else {
        r
    }
}

// C23 narrowing from binary128 operands: compute the operation in f128 (one
// correct rounding to f128), recover the exact residual, then round-to-odd so
// the f64/f32 cast lands on the single correctly-rounded narrow result.
#[inline]
fn nadd_ro_f128(x: f128, y: f128) -> f128 {
    let s = x + y;
    if s.is_nan() {
        return fixup_invalid_nan_f128(s, x.is_nan() || y.is_nan());
    }
    let bb = s - x; // 2Sum (Knuth): exact residual of x+y
    let resid = (x - (s - bb)) + (y - bb);
    narrow_round_odd_f128(s, resid)
}
#[inline]
fn nsub_ro_f128(x: f128, y: f128) -> f128 {
    let ny = -y;
    let s = x + ny;
    if s.is_nan() {
        return fixup_invalid_nan_f128(s, x.is_nan() || y.is_nan());
    }
    let bb = s - x;
    let resid = (x - (s - bb)) + (ny - bb);
    narrow_round_odd_f128(s, resid)
}
#[inline]
fn nmul_ro_f128(x: f128, y: f128) -> f128 {
    let p = x * y;
    if !p.is_finite() {
        // overflow/NaN in f128 ⇒ also overflow/NaN narrowed
        return fixup_invalid_nan_f128(p, x.is_nan() || y.is_nan());
    }
    let resid = x.mul_add(y, -p); // exact x*y - p
    narrow_round_odd_f128(p, resid)
}
#[inline]
fn ndiv_ro_f128(x: f128, y: f128) -> f128 {
    let q = x / y;
    if !q.is_finite() || q == 0.0 {
        return fixup_invalid_nan_f128(q, x.is_nan() || y.is_nan());
    }
    let r = (-q).mul_add(y, x); // x - q*y, exact residual numerator
    if !r.is_finite() {
        return q;
    }
    // sign(E - q) = sign(r / y) = sign(r) * sign(y)
    let resid = if r == 0.0 {
        0.0
    } else if (r > 0.0) == (y > 0.0) {
        1.0
    } else {
        -1.0
    };
    narrow_round_odd_f128(q, resid)
}
#[inline]
fn nsqrt_ro_f128(x: f128) -> f128 {
    let s = x.sqrt();
    if !s.is_finite() || s == 0.0 {
        return fixup_invalid_nan_f128(s, x.is_nan());
    }
    let r = (-s).mul_add(s, x); // x - s^2; sign(E - s) = sign(r) since s>0
    narrow_round_odd_f128(s, r)
}
#[inline]
fn nfma_ro_f128(x: f128, y: f128, z: f128) -> f128 {
    // 0·inf (either order) is an invalid operation: x86/glibc yield the
    // canonical NEGATIVE qNaN regardless of the addend z.
    if (x == 0.0 && y.is_infinite()) || (x.is_infinite() && y == 0.0) {
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    }
    let r = x.mul_add(y, z); // correctly-rounded f128 fma
    if !r.is_finite() {
        return fixup_invalid_nan_f128(r, x.is_nan() || y.is_nan() || z.is_nan());
    }
    let u1 = x * y;
    if !u1.is_finite() {
        return r;
    }
    // ErrFma (Boldo–Muller): exact x*y+z = r + e1 + e2.
    let u2 = x.mul_add(y, -u1); // exact x*y - u1
    let a1 = z + u2;
    let bz = a1 - z;
    let a2 = (z - (a1 - bz)) + (u2 - bz);
    let b1 = u1 + a1;
    let bu = b1 - u1;
    let b2 = (u1 - (b1 - bu)) + (a1 - bu);
    let gamma = (b1 - r) + b2;
    let e1 = gamma + a2;
    let e2 = a2 - (e1 - gamma);
    let mut resid = if e1 != 0.0 { e1 } else { e2 };
    // When x·y underflows f128 entirely (flushed to 0) but is mathematically
    // nonzero, the ErrFma above loses it — yet its sign still tips a round-to-
    // odd tie (exact result exactly on a narrow midpoint). Restore that sign.
    if resid == 0.0 && u1 == 0.0 && x != 0.0 && y != 0.0 && x.is_finite() && y.is_finite() {
        resid = if (x > 0.0) == (y > 0.0) {
            f128::MIN_POSITIVE
        } else {
            -f128::MIN_POSITIVE
        };
    }
    narrow_round_odd_f128(r, resid)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fadd(x: f64, y: f64) -> f32 {
    let s = x + y;
    let bb = s - x; // 2Sum (Knuth): exact residual of x+y
    let resid = (x - (s - bb)) + (y - bb);
    narrow_round_odd(s, resid)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn faddl(x: f64, y: f64) -> f32 {
    unsafe { fadd(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdiv(x: f64, y: f64) -> f32 {
    let q = x / y;
    // Exact / non-finite results need no round-to-odd. q == 0 (incl finite/±inf
    // and true underflow below f64 range) is exact-to-f32; the fma residual
    // would also be NaN for a ±inf divisor (0*inf), so guard it.
    if !q.is_finite() || q == 0.0 {
        return q as f32;
    }
    let r = frankenlibc_core::math::fma(-q, y, x); // x - q*y, exact residual numerator
    if !r.is_finite() {
        return q as f32;
    }
    // sign(E - q) = sign(r / y) = sign(r) * sign(y)
    let resid = if r == 0.0 {
        0.0
    } else if (r > 0.0) == (y > 0.0) {
        1.0
    } else {
        -1.0
    };
    narrow_round_odd(q, resid)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdivl(x: f64, y: f64) -> f32 {
    unsafe { fdiv(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmul(x: f64, y: f64) -> f32 {
    let p = x * y;
    let resid = frankenlibc_core::math::fma(x, y, -p); // exact x*y - p
    narrow_round_odd(p, resid)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmull(x: f64, y: f64) -> f32 {
    unsafe { fmul(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsqrt(x: f64) -> f32 {
    let s = frankenlibc_core::math::sqrt(x);
    if !s.is_finite() || s == 0.0 {
        return s as f32;
    }
    let r = frankenlibc_core::math::fma(-s, s, x); // x - s^2; sign(E - s) = sign(r) since s>0
    narrow_round_odd(s, r)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsqrtl(x: f64) -> f32 {
    unsafe { fsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsub(x: f64, y: f64) -> f32 {
    let ny = -y;
    let s = x + ny;
    let bb = s - x; // 2Sum residual of x-y
    let resid = (x - (s - bb)) + (ny - bb);
    narrow_round_odd(s, resid)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsubl(x: f64, y: f64) -> f32 {
    unsafe { fsub(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ffma(x: f64, y: f64, z: f64) -> f32 {
    use frankenlibc_core::math::fma as fma64;
    // C23 ffma: round the EXACT x*y+z a SINGLE time to f32. `fma(x,y,z) as f32`
    // double-rounds. Recover the sign of the exact residual via Boldo–Muller
    // ErrFma, then apply round-to-odd (see narrow_round_odd).
    let r = fma64(x, y, z);
    if !r.is_finite() {
        return r as f32;
    }
    // 2Prod: x*y = u1 + u2 exact (u1 finite here, since r is finite).
    let u1 = x * y;
    let u2 = fma64(x, y, -u1);
    // 2Sum(z, u2) = (a1, a2)
    let a1 = z + u2;
    let bz = a1 - z;
    let a2 = (z - (a1 - bz)) + (u2 - bz);
    // 2Sum(u1, a1) = (b1, b2)
    let b1 = u1 + a1;
    let bu = b1 - u1;
    let b2 = (u1 - (b1 - bu)) + (a1 - bu);
    let gamma = (b1 - r) + b2;
    // FastTwoSum(gamma, a2) = (e1, e2): exact x*y+z = r + e1 + e2.
    let e1 = gamma + a2;
    let e2 = a2 - (e1 - gamma);
    let resid = if e1 != 0.0 { e1 } else { e2 };
    narrow_round_odd(r, resid)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ffmal(x: f64, y: f64, z: f64) -> f32 {
    unsafe { ffma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn daddl(x: f64, y: f64) -> f64 {
    x + y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ddivl(x: f64, y: f64) -> f64 {
    x / y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dmull(x: f64, y: f64) -> f64 {
    x * y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dsqrtl(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dsubl(x: f64, y: f64) -> f64 {
    x - y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dfmal(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}

// Type-generic narrowing operations
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf32x(x: f64, y: f64) -> f32 {
    // _Float32x is `double` on x86_64, so this equals f32addf64/fadd; route
    // through fadd for correct single rounding.
    unsafe { fadd(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf64(x: f64, y: f64) -> f32 {
    // Identical operation to `fadd` (f32 = round(x+y)). Route through it so this
    // explicit-width spelling gets the correct single rounding (round-to-odd),
    // not the double-rounding `(x+y) as f32`.
    unsafe { fadd(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf64x(x: f64, y: f64) -> f32 {
    // _Float64x is f64 in fl, so this is the same op as f32addf64/fadd; route
    // through fadd for correct single rounding (not double-rounding).
    unsafe { fadd(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32addf128(x: f128, y: f128) -> f32 {
    nadd_ro_f128(x, y) as f32
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xaddf64(x: f64, y: f64) -> f64 {
    x + y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xaddf64x(x: f64, y: f64) -> f64 {
    x + y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xaddf128(x: f128, y: f128) -> f64 {
    // _Float32x is `double` (f64) on x86_64.
    nadd_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64addf64x(x: f64, y: f64) -> f64 {
    x + y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64addf128(x: f128, y: f128) -> f64 {
    nadd_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xaddf128(x: f64, y: f64) -> f64 {
    x + y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf32x(x: f64, y: f64) -> f32 {
    unsafe { fdiv(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf64(x: f64, y: f64) -> f32 {
    // Route through `fdiv` for correct single rounding (round-to-odd).
    unsafe { fdiv(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf64x(x: f64, y: f64) -> f32 {
    unsafe { fdiv(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32divf128(x: f128, y: f128) -> f32 {
    ndiv_ro_f128(x, y) as f32
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xdivf64(x: f64, y: f64) -> f64 {
    x / y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xdivf64x(x: f64, y: f64) -> f64 {
    x / y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xdivf128(x: f128, y: f128) -> f64 {
    ndiv_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64divf64x(x: f64, y: f64) -> f64 {
    x / y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64divf128(x: f128, y: f128) -> f64 {
    ndiv_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xdivf128(x: f64, y: f64) -> f64 {
    x / y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf32x(x: f64, y: f64) -> f32 {
    unsafe { fmul(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf64(x: f64, y: f64) -> f32 {
    // Route through `fmul` for correct single rounding (round-to-odd).
    unsafe { fmul(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf64x(x: f64, y: f64) -> f32 {
    unsafe { fmul(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32mulf128(x: f128, y: f128) -> f32 {
    nmul_ro_f128(x, y) as f32
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xmulf64(x: f64, y: f64) -> f64 {
    x * y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xmulf64x(x: f64, y: f64) -> f64 {
    x * y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xmulf128(x: f128, y: f128) -> f64 {
    nmul_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64mulf64x(x: f64, y: f64) -> f64 {
    x * y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64mulf128(x: f128, y: f128) -> f64 {
    nmul_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xmulf128(x: f64, y: f64) -> f64 {
    x * y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf32x(x: f64) -> f32 {
    unsafe { fsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf64(x: f64) -> f32 {
    // Route through `fsqrt` for correct single rounding (round-to-odd).
    unsafe { fsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf64x(x: f64) -> f32 {
    unsafe { fsqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32sqrtf128(x: f128) -> f32 {
    nsqrt_ro_f128(x) as f32
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsqrtf64(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsqrtf64x(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsqrtf128(x: f128) -> f64 {
    nsqrt_ro_f128(x) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64sqrtf64x(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64sqrtf128(x: f128) -> f64 {
    nsqrt_ro_f128(x) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xsqrtf128(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf32x(x: f64, y: f64) -> f32 {
    unsafe { fsub(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf64(x: f64, y: f64) -> f32 {
    // Route through `fsub` for correct single rounding (round-to-odd).
    unsafe { fsub(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf64x(x: f64, y: f64) -> f32 {
    unsafe { fsub(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32subf128(x: f128, y: f128) -> f32 {
    nsub_ro_f128(x, y) as f32
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsubf64(x: f64, y: f64) -> f64 {
    x - y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsubf64x(x: f64, y: f64) -> f64 {
    x - y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xsubf128(x: f128, y: f128) -> f64 {
    nsub_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64subf64x(x: f64, y: f64) -> f64 {
    x - y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64subf128(x: f128, y: f128) -> f64 {
    nsub_ro_f128(x, y) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xsubf128(x: f64, y: f64) -> f64 {
    x - y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf32x(x: f64, y: f64, z: f64) -> f32 {
    unsafe { ffma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf64(x: f64, y: f64, z: f64) -> f32 {
    // Route through `ffma` for correct single rounding (round-to-odd).
    unsafe { ffma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf64x(x: f64, y: f64, z: f64) -> f32 {
    unsafe { ffma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32fmaf128(x: f128, y: f128, z: f128) -> f32 {
    nfma_ro_f128(x, y, z) as f32
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xfmaf64(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xfmaf64x(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f32xfmaf128(x: f128, y: f128, z: f128) -> f64 {
    nfma_ro_f128(x, y, z) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64fmaf64x(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64fmaf128(x: f128, y: f128, z: f128) -> f64 {
    nfma_ro_f128(x, y, z) as f64
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn f64xfmaf128(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}

// =========================================================================
// Internal glibc math helpers
// =========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fpclassifyl(x: f64) -> c_int {
    unsafe { __fpclassify(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iscanonicall(_x: f64) -> c_int {
    1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsig(x: f64, y: f64) -> c_int {
    if x == y { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsigf(x: f32, y: f32) -> c_int {
    if x == y { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsigl(x: f64, y: f64) -> c_int {
    if x == y { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iseqsigf128(x: f128, y: f128) -> c_int {
    // Signaling equality: a NaN operand is a domain error (EDOM + FE_INVALID).
    if x.is_nan() || y.is_nan() {
        unsafe { set_abi_errno(libc::EDOM) };
        return 0;
    }
    (x == y) as c_int
}

fn is_signaling_nan_f64(x: f64) -> bool {
    if !x.is_nan() {
        return false;
    }
    let bits = x.to_bits();
    (bits & 0x0008_0000_0000_0000) == 0 && (bits & 0x0007_FFFF_FFFF_FFFF) != 0
}
fn is_signaling_nan_f32(x: f32) -> bool {
    if !x.is_nan() {
        return false;
    }
    let bits = x.to_bits();
    (bits & 0x0040_0000) == 0 && (bits & 0x003F_FFFF) != 0
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignaling(x: f64) -> c_int {
    if is_signaling_nan_f64(x) { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignalingf(x: f32) -> c_int {
    if is_signaling_nan_f32(x) { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignalingl(x: f64) -> c_int {
    if is_signaling_nan_f64(x) { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __issignalingf128(x: f128) -> c_int {
    // Signaling NaN: max exponent, nonzero mantissa, quiet bit (bit 111) clear.
    let b = x.to_bits();
    let exp = (b >> 112) & 0x7fff;
    let mant = b & ((1u128 << 112) - 1);
    (exp == 0x7fff && mant != 0 && (mant >> 111) & 1 == 0) as c_int
}

#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut signgam: c_int = 0;
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __signgam: c_int = 0;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn matherr(_exc: *mut std::ffi::c_void) -> c_int {
    0
}

#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static _LIB_VERSION: c_int = 0;

// =========================================================================
// fenv extensions (glibc-specific) - delegate to host fenv
// =========================================================================

// fedisableexcept / feenableexcept / fegetexcept / fesetexcept /
// fetestexceptflag / fegetmode / fesetmode are implemented in fenv_abi.rs
// (real MXCSR/x87 manipulation).

// =========================================================================
// TS 18661 / C23 type-generic math width aliases
// =========================================================================
//
// Width mapping: f32→float, f32x→double, f64→double, f64x→f64, f128→f64
// On x86-64 we map long double and _Float128 to f64 (double precision).

// --- unary real (f64→f64, f32→f32) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf32(x: f32) -> f32 {
    unsafe { acosf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf32x(x: f64) -> f64 {
    unsafe { acos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf64(x: f64) -> f64 {
    unsafe { acos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf64x(x: f64) -> f64 {
    unsafe { acos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acosf128(x: f128) -> f128 {
    acos_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf32(x: f32) -> f32 {
    unsafe { acoshf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf32x(x: f64) -> f64 {
    unsafe { acosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf64(x: f64) -> f64 {
    unsafe { acosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf64x(x: f64) -> f64 {
    unsafe { acosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acoshf128(x: f128) -> f128 {
    // glibc acosh wrapper: EDOM for x<1 (genuine NaN inputs carry no errno).
    if x < 1.0 {
        set_domain_errno();
    }
    acoshl_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf32(x: f32) -> f32 {
    unsafe { asinf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf32x(x: f64) -> f64 {
    unsafe { asin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf64(x: f64) -> f64 {
    unsafe { asin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf64x(x: f64) -> f64 {
    unsafe { asin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinf128(x: f128) -> f128 {
    asin_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf32(x: f32) -> f32 {
    unsafe { asinhf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf32x(x: f64) -> f64 {
    unsafe { asinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf64(x: f64) -> f64 {
    unsafe { asinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf64x(x: f64) -> f64 {
    unsafe { asinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asinhf128(x: f128) -> f128 {
    asinhl_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf32(x: f32) -> f32 {
    unsafe { atanf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf32x(x: f64) -> f64 {
    unsafe { atan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf64(x: f64) -> f64 {
    unsafe { atan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf64x(x: f64) -> f64 {
    unsafe { atan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanf128(x: f128) -> f128 {
    atan_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf32(x: f32) -> f32 {
    unsafe { atanhf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf32x(x: f64) -> f64 {
    unsafe { atanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf64(x: f64) -> f64 {
    unsafe { atanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf64x(x: f64) -> f64 {
    unsafe { atanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atanhf128(x: f128) -> f128 {
    // glibc atanh wrapper: ERANGE pole at |x|==1, EDOM for |x|>1.
    let ax = x.abs();
    if ax == 1.0 {
        set_range_errno();
    } else if ax > 1.0 {
        set_domain_errno();
    }
    atanhl_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf32(x: f32) -> f32 {
    unsafe { cbrtf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf32x(x: f64) -> f64 {
    unsafe { cbrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf64(x: f64) -> f64 {
    unsafe { cbrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf64x(x: f64) -> f64 {
    unsafe { cbrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbrtf128(x: f128) -> f128 {
    cbrt_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf32(x: f32) -> f32 {
    unsafe { ceilf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf32x(x: f64) -> f64 {
    unsafe { ceil(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf64(x: f64) -> f64 {
    unsafe { ceil(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf64x(x: f64) -> f64 {
    unsafe { ceil(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ceilf128(x: f128) -> f128 {
    x.ceil()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf32(x: f32) -> f32 {
    unsafe { cosf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf32x(x: f64) -> f64 {
    unsafe { cos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf64(x: f64) -> f64 {
    unsafe { cos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf64x(x: f64) -> f64 {
    unsafe { cos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cosf128(x: f64) -> f64 {
    unsafe { cos(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf32(x: f32) -> f32 {
    unsafe { coshf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf32x(x: f64) -> f64 {
    unsafe { cosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf64(x: f64) -> f64 {
    unsafe { cosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf64x(x: f64) -> f64 {
    unsafe { cosh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn coshf128(x: f128) -> f128 {
    let r = coshl_f128(x);
    if x.is_finite() && r.is_infinite() {
        set_range_errno(); // overflow
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff32(x: f32) -> f32 {
    unsafe { erff(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff32x(x: f64) -> f64 {
    unsafe { erf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff64(x: f64) -> f64 {
    unsafe { erf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff64x(x: f64) -> f64 {
    unsafe { erf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erff128(x: f64) -> f64 {
    unsafe { erf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf32(x: f32) -> f32 {
    unsafe { erfcf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf32x(x: f64) -> f64 {
    unsafe { erfc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf64(x: f64) -> f64 {
    unsafe { erfc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf64x(x: f64) -> f64 {
    unsafe { erfc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erfcf128(x: f64) -> f64 {
    unsafe { erfc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf32(x: f32) -> f32 {
    unsafe { expf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf32x(x: f64) -> f64 {
    unsafe { exp(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf64(x: f64) -> f64 {
    unsafe { exp(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf64x(x: f64) -> f64 {
    unsafe { exp(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expf128(x: f128) -> f128 {
    let r = expl_f128(x);
    // glibc's exp wrapper: ERANGE on overflow (finite x → inf) / underflow
    // (finite x → 0). x == -inf → 0 legitimately (x not finite, no errno).
    if x.is_finite() && (r.is_infinite() || r == 0.0) {
        set_range_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f32(x: f32) -> f32 {
    unsafe { exp10f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f32x(x: f64) -> f64 {
    unsafe { exp10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f64(x: f64) -> f64 {
    unsafe { exp10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f64x(x: f64) -> f64 {
    unsafe { exp10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp10f128(x: f128) -> f128 {
    let r = exp10l_f128(x);
    if x.is_finite() && (r.is_infinite() || r == 0.0) {
        set_range_errno(); // overflow / underflow
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f32(x: f32) -> f32 {
    unsafe { exp2f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f32x(x: f64) -> f64 {
    unsafe { exp2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f64(x: f64) -> f64 {
    unsafe { exp2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f64x(x: f64) -> f64 {
    unsafe { exp2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exp2f128(x: f64) -> f64 {
    unsafe { exp2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f32(x: f32) -> f32 {
    unsafe { expm1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f32x(x: f64) -> f64 {
    unsafe { expm1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f64(x: f64) -> f64 {
    unsafe { expm1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f64x(x: f64) -> f64 {
    unsafe { expm1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expm1f128(x: f128) -> f128 {
    let r = expm1l_f128(x);
    if x.is_finite() && r.is_infinite() {
        set_range_errno(); // overflow
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf32(x: f32) -> f32 {
    unsafe { fabsf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf32x(x: f64) -> f64 {
    unsafe { fabs(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf64(x: f64) -> f64 {
    unsafe { fabs(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf64x(x: f64) -> f64 {
    unsafe { fabs(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fabsf128(x: f128) -> f128 {
    f128::from_bits(x.to_bits() & !(1u128 << 127))
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf32(x: f32) -> f32 {
    unsafe { floorf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf32x(x: f64) -> f64 {
    unsafe { floor(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf64(x: f64) -> f64 {
    unsafe { floor(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf64x(x: f64) -> f64 {
    unsafe { floor(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn floorf128(x: f128) -> f128 {
    x.floor()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32(x: f32) -> f32 {
    unsafe { lgammaf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf32x(x: f64) -> f64 {
    unsafe { lgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64(x: f64) -> f64 {
    unsafe { lgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf64x(x: f64) -> f64 {
    unsafe { lgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf128(x: f64) -> f64 {
    unsafe { lgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf32(x: f32) -> f32 {
    unsafe { logf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf32x(x: f64) -> f64 {
    unsafe { log(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf64(x: f64) -> f64 {
    unsafe { log(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf64x(x: f64) -> f64 {
    unsafe { log(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logf128(x: f128) -> f128 {
    let r = logl_f128(x);
    // glibc log wrapper: pole error ERANGE at 0, domain error EDOM for x<0.
    if x == 0.0 {
        set_range_errno();
    } else if x < 0.0 {
        set_domain_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f32(x: f32) -> f32 {
    unsafe { log10f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f32x(x: f64) -> f64 {
    unsafe { log10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f64(x: f64) -> f64 {
    unsafe { log10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f64x(x: f64) -> f64 {
    unsafe { log10(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log10f128(x: f128) -> f128 {
    let r = log10l_f128(x);
    if x == 0.0 {
        set_range_errno(); // pole
    } else if x < 0.0 {
        set_domain_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf32(x: f32) -> f32 {
    unsafe { log1pf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf32x(x: f64) -> f64 {
    unsafe { log1p(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf64(x: f64) -> f64 {
    unsafe { log1p(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf64x(x: f64) -> f64 {
    unsafe { log1p(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log1pf128(x: f128) -> f128 {
    let r = log1pl_f128(x);
    // glibc log1p wrapper: ERANGE pole at x==-1, EDOM for x<-1.
    if x == -1.0 {
        set_range_errno();
    } else if x < -1.0 {
        set_domain_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f32(x: f32) -> f32 {
    unsafe { log2f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f32x(x: f64) -> f64 {
    unsafe { log2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f64(x: f64) -> f64 {
    unsafe { log2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f64x(x: f64) -> f64 {
    unsafe { log2(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn log2f128(x: f128) -> f128 {
    let r = log2l_f128(x);
    if x == 0.0 {
        set_range_errno(); // pole
    } else if x < 0.0 {
        set_domain_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf32(x: f32) -> f32 {
    unsafe { logbf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf32x(x: f64) -> f64 {
    unsafe { logb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf64(x: f64) -> f64 {
    unsafe { logb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf64x(x: f64) -> f64 {
    unsafe { logb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logbf128(x: f128) -> f128 {
    let bits = x.to_bits();
    let exp_field = (bits >> 112) & 0x7fff;
    let mant = bits & ((1u128 << 112) - 1);
    if exp_field == 0x7fff {
        return if mant == 0 { x.abs() } else { x }; // inf -> +inf, nan -> nan
    }
    if exp_field == 0 && mant == 0 {
        return f128::from_bits(0xffff_u128 << 112); // logb(0) = -inf
    }
    f128_unbiased_exp(bits) as f128
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf32(x: f32) -> f32 {
    unsafe { nearbyintf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf32x(x: f64) -> f64 {
    unsafe { nearbyint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf64(x: f64) -> f64 {
    unsafe { nearbyint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf64x(x: f64) -> f64 {
    unsafe { nearbyint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nearbyintf128(x: f128) -> f128 {
    round_f128_current_mode(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf32(x: f32) -> f32 {
    unsafe { rintf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf32x(x: f64) -> f64 {
    unsafe { rint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf64(x: f64) -> f64 {
    unsafe { rint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf64x(x: f64) -> f64 {
    unsafe { rint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rintf128(x: f128) -> f128 {
    round_f128_nearest(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf32(x: f32) -> f32 {
    unsafe { roundf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf32x(x: f64) -> f64 {
    unsafe { round(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf64(x: f64) -> f64 {
    unsafe { round(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf64x(x: f64) -> f64 {
    unsafe { round(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn roundf128(x: f128) -> f128 {
    x.round()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf32(x: f32) -> f32 {
    unsafe { sinf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf32x(x: f64) -> f64 {
    unsafe { sin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf64(x: f64) -> f64 {
    unsafe { sin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf64x(x: f64) -> f64 {
    unsafe { sin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinf128(x: f64) -> f64 {
    unsafe { sin(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf32(x: f32) -> f32 {
    unsafe { sinhf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf32x(x: f64) -> f64 {
    unsafe { sinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf64(x: f64) -> f64 {
    unsafe { sinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf64x(x: f64) -> f64 {
    unsafe { sinh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sinhf128(x: f128) -> f128 {
    let r = sinhl_f128(x);
    if x.is_finite() && r.is_infinite() {
        set_range_errno(); // overflow
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf32(x: f32) -> f32 {
    unsafe { sqrtf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf32x(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf64(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf64x(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sqrtf128(x: f128) -> f128 {
    // The f128 sqrt intrinsic is IEEE correctly-rounded (byte-exact vs glibc).
    x.sqrt()
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf32(x: f32) -> f32 {
    unsafe { tanf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf32x(x: f64) -> f64 {
    unsafe { tan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf64(x: f64) -> f64 {
    unsafe { tan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf64x(x: f64) -> f64 {
    unsafe { tan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanf128(x: f64) -> f64 {
    unsafe { tan(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf32(x: f32) -> f32 {
    unsafe { tanhf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf32x(x: f64) -> f64 {
    unsafe { tanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf64(x: f64) -> f64 {
    unsafe { tanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf64x(x: f64) -> f64 {
    unsafe { tanh(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tanhf128(x: f128) -> f128 {
    tanhl_f128(x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf32(x: f32) -> f32 {
    unsafe { tgammaf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf32x(x: f64) -> f64 {
    unsafe { tgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf64(x: f64) -> f64 {
    unsafe { tgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf64x(x: f64) -> f64 {
    unsafe { tgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgammaf128(x: f64) -> f64 {
    unsafe { tgamma(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf32(x: f32) -> f32 {
    unsafe { truncf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf32x(x: f64) -> f64 {
    unsafe { trunc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf64(x: f64) -> f64 {
    unsafe { trunc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf64x(x: f64) -> f64 {
    unsafe { trunc(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncf128(x: f128) -> f128 {
    x.trunc()
}

// --- binary real (f64,f64→f64, f32,f32→f32) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f32(x: f32, y: f32) -> f32 {
    unsafe { atan2f(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f32x(x: f64, y: f64) -> f64 {
    unsafe { atan2(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f64(x: f64, y: f64) -> f64 {
    unsafe { atan2(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f64x(x: f64, y: f64) -> f64 {
    unsafe { atan2(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atan2f128(y: f128, x: f128) -> f128 {
    atan2_f128(y, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf32(x: f32, y: f32) -> f32 {
    unsafe { copysignf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf32x(x: f64, y: f64) -> f64 {
    unsafe { copysign(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf64(x: f64, y: f64) -> f64 {
    unsafe { copysign(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf64x(x: f64, y: f64) -> f64 {
    unsafe { copysign(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignf128(x: f128, y: f128) -> f128 {
    let sign = y.to_bits() & (1u128 << 127);
    f128::from_bits((x.to_bits() & !(1u128 << 127)) | sign)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf32(x: f32, y: f32) -> f32 {
    unsafe { fdimf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf32x(x: f64, y: f64) -> f64 {
    unsafe { fdim(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf64(x: f64, y: f64) -> f64 {
    unsafe { fdim(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf64x(x: f64, y: f64) -> f64 {
    unsafe { fdim(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdimf128(x: f128, y: f128) -> f128 {
    if x.is_nan() || y.is_nan() {
        return x + y; // NaN propagation
    }
    if x > y {
        let d = x - y;
        if d.is_infinite() && x.is_finite() && y.is_finite() {
            set_range_errno();
        }
        d
    } else {
        0.0
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf32(x: f32, y: f32) -> f32 {
    unsafe { fmaxf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf32x(x: f64, y: f64) -> f64 {
    unsafe { fmax(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf64(x: f64, y: f64) -> f64 {
    unsafe { fmax(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf64x(x: f64, y: f64) -> f64 {
    unsafe { fmax(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaxf128(x: f128, y: f128) -> f128 {
    // glibc: isgreaterequal(x,y) ? x : y (returns the first arg on a ±0 tie,
    // unlike Rust's .max() which prefers +0).
    if x.is_nan() {
        y
    } else if y.is_nan() {
        x
    } else if x < y {
        y
    } else {
        x
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf32(x: f32, y: f32) -> f32 {
    unsafe { fminf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf32x(x: f64, y: f64) -> f64 {
    unsafe { fmin(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf64(x: f64, y: f64) -> f64 {
    unsafe { fmin(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf64x(x: f64, y: f64) -> f64 {
    unsafe { fmin(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fminf128(x: f128, y: f128) -> f128 {
    // glibc: x < y ? x : y (returns the second arg on a ±0 tie).
    if x.is_nan() {
        y
    } else if y.is_nan() || x < y {
        x
    } else {
        y
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf32(x: f32, y: f32) -> f32 {
    unsafe { fmodf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf32x(x: f64, y: f64) -> f64 {
    unsafe { fmod(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf64(x: f64, y: f64) -> f64 {
    unsafe { fmod(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf64x(x: f64, y: f64) -> f64 {
    unsafe { fmod(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmodf128(x: f128, y: f128) -> f128 {
    // The f128 `%` operator is the IEEE fmod (exact remainder); glibc fmod sets
    // no errno (FE_INVALID only) for the nan-producing cases, matching this.
    x % y
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf32(x: f32, y: f32) -> f32 {
    unsafe { hypotf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf32x(x: f64, y: f64) -> f64 {
    unsafe { hypot(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf64(x: f64, y: f64) -> f64 {
    unsafe { hypot(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf64x(x: f64, y: f64) -> f64 {
    unsafe { hypot(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hypotf128(x: f128, y: f128) -> f128 {
    let r = hypot_f128(x, y);
    // glibc's hypot wrapper sets ERANGE when finite operands overflow to inf.
    if r.is_infinite() && x.is_finite() && y.is_finite() {
        set_range_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf32(x: f32, y: f32) -> f32 {
    unsafe { nextafterf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf32x(x: f64, y: f64) -> f64 {
    unsafe { nextafter(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf64(x: f64, y: f64) -> f64 {
    unsafe { nextafter(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf64x(x: f64, y: f64) -> f64 {
    unsafe { nextafter(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nextafterf128(x: f128, y: f128) -> f128 {
    if x.is_nan() || y.is_nan() {
        return x + y;
    }
    if x == y {
        return y;
    }
    let r = if x < y { x.next_up() } else { x.next_down() };
    // glibc raises ERANGE when the result's exponent field is 0 (subnormal or
    // zero) or it overflowed a finite x to infinity.
    let r_exp = (r.to_bits() >> 112) & 0x7fff;
    if (x.is_finite() && r.is_infinite()) || (r_exp == 0 && x != 0.0) {
        set_range_errno();
    }
    r
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf32(x: f32, y: f32) -> f32 {
    unsafe { powf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf32x(x: f64, y: f64) -> f64 {
    unsafe { pow(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf64(x: f64, y: f64) -> f64 {
    unsafe { pow(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf64x(x: f64, y: f64) -> f64 {
    unsafe { pow(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn powf128(x: f64, y: f64) -> f64 {
    unsafe { pow(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf32(x: f32, y: f32) -> f32 {
    unsafe { remainderf(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf32x(x: f64, y: f64) -> f64 {
    unsafe { remainder(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf64(x: f64, y: f64) -> f64 {
    unsafe { remainder(x, y) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf64x(x: f64, y: f64) -> f64 {
    unsafe { remainder(x, y) }
}
/// IEEE remainder for binary128: x - n*y where n = round-to-nearest-even(x/y).
/// Exact (built from fmod + an exact tie-break), no rounding.
fn remainder_f128(x: f128, y: f128) -> f128 {
    let ax = x.abs();
    let ay = y.abs();
    let mut r = ax % ay; // fmod: r in [0, ay)
    let two_r = r + r; // exact (no overflow: r < ay)
    if two_r > ay {
        r -= ay;
    } else if two_r == ay {
        // Tie -> round to even quotient. The quotient n is even iff
        // fmod(ax, 2*ay) < ay (mod-2y keeps the low quotient bit).
        let two_ay = ay + ay;
        if ax % two_ay >= ay {
            r -= ay;
        }
    }
    if x.is_sign_negative() {
        -r
    } else {
        r
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remainderf128(x: f128, y: f128) -> f128 {
    let ax = x.abs();
    let ay = y.abs();
    if x.is_nan() || y.is_nan() {
        return x + y; // NaN propagation, no errno
    }
    if ay == 0.0 || ax.is_infinite() {
        unsafe { set_abi_errno(libc::EDOM) };
        // glibc returns a negative quiet NaN for the domain error.
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    }
    remainder_f128(x, y)
}

// --- ternary real ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf32(x: f32, y: f32, z: f32) -> f32 {
    unsafe { fmaf(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf32x(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf64(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf64x(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmaf128(x: f128, y: f128, z: f128) -> f128 {
    // The f128 fused-multiply-add intrinsic is IEEE correctly-rounded.
    x.mul_add(y, z)
}

// --- unary → c_int ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf32(x: f32) -> c_int {
    unsafe { ilogbf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf32x(x: f64) -> c_int {
    unsafe { ilogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf64(x: f64) -> c_int {
    unsafe { ilogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf64x(x: f64) -> c_int {
    unsafe { ilogb(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ilogbf128(x: f128) -> c_int {
    let bits = x.to_bits();
    let exp_field = (bits >> 112) & 0x7fff;
    let mant = bits & ((1u128 << 112) - 1);
    if exp_field == 0x7fff {
        unsafe { set_abi_errno(libc::EDOM) };
        return if mant == 0 { c_int::MAX } else { c_int::MIN }; // inf -> INT_MAX, nan -> FP_ILOGBNAN
    }
    if exp_field == 0 && mant == 0 {
        unsafe { set_abi_errno(libc::EDOM) };
        return c_int::MIN; // FP_ILOGB0
    }
    f128_unbiased_exp(bits)
}

// --- unary → c_long ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf32(x: f32) -> c_long {
    unsafe { lrintf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf32x(x: f64) -> c_long {
    unsafe { lrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf64(x: f64) -> c_long {
    unsafe { lrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf64x(x: f64) -> c_long {
    unsafe { lrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrintf128(x: f128) -> c_long {
    f128_to_i64_sat(round_f128_current_mode(x))
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf32(x: f32) -> c_long {
    unsafe { lroundf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf32x(x: f64) -> c_long {
    unsafe { lround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf64(x: f64) -> c_long {
    unsafe { lround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf64x(x: f64) -> c_long {
    unsafe { lround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lroundf128(x: f128) -> c_long {
    f128_to_i64_sat(x.round())
}

// --- unary → i64 ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf32(x: f32) -> i64 {
    unsafe { llrintf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf32x(x: f64) -> i64 {
    unsafe { llrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf64(x: f64) -> i64 {
    unsafe { llrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf64x(x: f64) -> i64 {
    unsafe { llrint(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llrintf128(x: f128) -> i64 {
    f128_to_i64_sat(round_f128_current_mode(x))
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf32(x: f32) -> i64 {
    unsafe { llroundf(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf32x(x: f64) -> i64 {
    unsafe { llround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf64(x: f64) -> i64 {
    unsafe { llround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf64x(x: f64) -> i64 {
    unsafe { llround(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llroundf128(x: f128) -> i64 {
    f128_to_i64_sat(x.round())
}

// --- frexp-like (f, *mut c_int → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf32(x: f32, exp: *mut c_int) -> f32 {
    unsafe { frexpf(x, exp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf32x(x: f64, exp: *mut c_int) -> f64 {
    unsafe { frexp(x, exp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf64(x: f64, exp: *mut c_int) -> f64 {
    unsafe { frexp(x, exp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf64x(x: f64, exp: *mut c_int) -> f64 {
    unsafe { frexp(x, exp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf128(x: f128, exp: *mut c_int) -> f128 {
    let bits = x.to_bits();
    let e = ((bits >> 112) & 0x7fff) as i32;
    if e == 0x7fff || x == 0.0 {
        // inf / nan / signed zero: *exp = 0, value unchanged.
        unsafe { *exp = 0 };
        return x;
    }
    let (norm_bits, base_exp) = if e == 0 {
        // Subnormal: renormalize via x * 2^113, then back out the 113.
        let xn = x * f128::from_bits((113u128 + 16383) << 112);
        (xn.to_bits(), ((xn.to_bits() >> 112) & 0x7fff) as i32 - 113)
    } else {
        (bits, e)
    };
    unsafe { *exp = base_exp - 16382 };
    // Mantissa in [0.5, 1): force the exponent field to 0x3FFE.
    f128::from_bits((norm_bits & !(0x7fffu128 << 112)) | (0x3FFEu128 << 112))
}

// --- ldexp/scalbn-like (f, c_int → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf32(x: f32, n: c_int) -> f32 {
    unsafe { ldexpf(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf32x(x: f64, n: c_int) -> f64 {
    unsafe { ldexp(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf64(x: f64, n: c_int) -> f64 {
    unsafe { ldexp(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf64x(x: f64, n: c_int) -> f64 {
    unsafe { ldexp(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpf128(x: f128, n: c_int) -> f128 {
    scalbn_f128(x, n as i64)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf32(x: f32, n: c_int) -> f32 {
    unsafe { scalbnf(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf32x(x: f64, n: c_int) -> f64 {
    unsafe { scalbn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf64(x: f64, n: c_int) -> f64 {
    unsafe { scalbn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf64x(x: f64, n: c_int) -> f64 {
    unsafe { scalbn(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnf128(x: f128, n: c_int) -> f128 {
    scalbn_f128(x, n as i64)
}

/// x * 2^n for binary128, via glibc's staged FP-multiply (so the FPU performs
/// the single correct rounding for subnormal/overflow results), then ERANGE on
/// an inf or zero result coming from a finite nonzero x.
fn scalbn_f128(x: f128, n: i64) -> f128 {
    let p_big = f128::from_bits(0x7ffe_u128 << 112); // 2^16383
    let p_min = f128::from_bits(1u128 << 112); // 2^-16382 (smallest normal)
    let p_renorm = f128::from_bits((113u128 + 16383) << 112); // 2^113
    let orig_nonzero_finite = x != 0.0 && x.is_finite();
    let mut x = x;
    let mut n = n;
    if n > 16383 {
        x *= p_big;
        n -= 16383;
        if n > 16383 {
            x *= p_big;
            n -= 16383;
            if n > 16383 {
                n = 16383;
            }
        }
    } else if n < -16382 {
        x *= p_min * p_renorm;
        n += 16382 - 113;
        if n < -16382 {
            x *= p_min * p_renorm;
            n += 16382 - 113;
            if n < -16382 {
                n = -16382;
            }
        }
    }
    let scale = f128::from_bits(((n + 16383) as u128) << 112);
    let r = x * scale;
    // glibc range error: overflow to inf, or a nonzero value flushed to zero.
    if orig_nonzero_finite && (r.is_infinite() || r == 0.0) {
        set_range_errno();
    }
    r
}

/// Cube root for binary128 — verbatim port of glibc's ldbl-128 `__cbrtl`
/// (Cephes/Moshier, sysdeps/ieee754/ldbl-128/s_cbrtl.c): extract power of two
/// with frexp, a degree-5 polynomial on the mantissa in [0.5,1), multiply by
/// cbrt(2^{e mod 3}), reapply the exponent with ldexp, then three Newton
/// iterations `x -= (x - z/x²)/3`. Uses only IEEE-correctly-rounded f128
/// `+ - * /` plus exact frexp/ldexp, so it is byte-exact vs glibc cbrtf128.
fn cbrt_f128(x: f128) -> f128 {
    const CBRT2: f128 = 1.259921049894873164767210607278228350570251f128;
    const CBRT4: f128 = 1.587401051968199474751705639272308260391493f128;
    const CBRT2I: f128 = 0.7937005259840997373758528196361541301957467f128;
    const CBRT4I: f128 = 0.6299605249474365823836053036391141752851257f128;
    const THIRD: f128 = 0.3333333333333333333333333333333333333333f128;

    if !x.is_finite() {
        return x + x;
    }
    if x == 0.0 {
        return x; // preserves the sign of zero
    }
    let (mut x, sign) = if x > 0.0 { (x, 1) } else { (-x, -1) };
    let z = x;

    // frexp: split into mantissa in [0.5,1) and a power-of-two exponent e.
    let mut e: i32;
    {
        let bits = x.to_bits();
        let ef = ((bits >> 112) & 0x7fff) as i32;
        let (norm_bits, base_exp) = if ef == 0 {
            let xn = x * f128::from_bits((113u128 + 16383) << 112); // *2^113
            (xn.to_bits(), ((xn.to_bits() >> 112) & 0x7fff) as i32 - 113)
        } else {
            (bits, ef)
        };
        e = base_exp - 16382;
        x = f128::from_bits((norm_bits & !(0x7fffu128 << 112)) | (0x3FFEu128 << 112));
    }

    // Approximate cube root of the mantissa, peak relative error 1.2e-6.
    x = ((((1.3584464340920900529734e-1f128 * x
        - 6.3986917220457538402318e-1f128) * x
        + 1.2875551670318751538055e0f128) * x
        - 1.4897083391357284957891e0f128) * x
        + 1.3304961236013647092521e0f128) * x
        + 3.7568280825958912391243e-1f128;

    // exponent divided by 3, scaling the mantissa by cbrt(2^rem).
    let rem;
    if e >= 0 {
        rem = e % 3;
        e /= 3;
        if rem == 1 {
            x *= CBRT2;
        } else if rem == 2 {
            x *= CBRT4;
        }
    } else {
        e = -e;
        rem = e % 3;
        e /= 3;
        if rem == 1 {
            x *= CBRT2I;
        } else if rem == 2 {
            x *= CBRT4I;
        }
        e = -e;
    }

    x = scalbn_f128(x, e as i64);

    // Newton iteration, three times.
    x -= (x - (z / (x * x))) * THIRD;
    x -= (x - (z / (x * x))) * THIRD;
    x -= (x - (z / (x * x))) * THIRD;

    if sign < 0 { -x } else { x }
}

/// True iff `x` is a signaling NaN (binary128): NaN with the quiet bit clear.
fn is_signaling_f128(x: f128) -> bool {
    let b = x.to_bits();
    (b >> 112) & 0x7fff == 0x7fff
        && (b & ((1u128 << 112) - 1)) != 0
        && (b & (1u128 << 111)) == 0
}

/// Borges' "MyHypot3" correction kernel (arXiv:1904.09481). Inputs must be
/// pre-adjusted so ax >= ay >= 0 and squaring ax, ay, (ax-ay) neither overflows
/// nor underflows. Uses f128 sqrt + correctly-rounded `+ - * /`.
fn hypot_kernel_f128(ax: f128, ay: f128) -> f128 {
    let mut h = (ax * ax + ay * ay).sqrt();
    let (t1, t2);
    if h <= 2.0 * ay {
        let delta = h - ay;
        t1 = ax * (2.0 * delta - ax);
        t2 = (delta - 2.0 * (ax - ay)) * delta;
    } else {
        let delta = h - ax;
        t1 = 2.0 * delta * (ax - 2.0 * ay);
        t2 = (4.0 * delta - ay) * ay + delta * delta;
    }
    h -= (t1 + t2) / (2.0 * h);
    h
}

/// Euclidean distance for binary128 — verbatim port of glibc's ldbl-128
/// `__ieee754_hypotl` (Borges' MyHypot3): scale huge/tiny/widely-varying
/// operands into a safe range, run the correction kernel, unscale. Byte-exact
/// vs glibc; does NOT set errno (the finite alias — the errno wrapper layers on
/// top in `hypotf128`).
fn hypot_f128(x: f128, y: f128) -> f128 {
    let scale = f128::from_bits(8080u128 << 112); // 2^-8303
    let large_val = f128::from_bits((24574u128 << 112) | 0x6a09_e667_f3bc_c908_b2fb_1366_ea95); // 0x1.6a09e667f3bcc908b2fb1366ea95p+8191
    let tiny_val = f128::from_bits(8192u128 << 112); // 2^-8191
    let eps = f128::from_bits(16269u128 << 112); // 2^-114

    if !x.is_finite() || !y.is_finite() {
        if (x.is_infinite() || y.is_infinite()) && !is_signaling_f128(x) && !is_signaling_f128(y) {
            return f128::INFINITY;
        }
        return x + y;
    }

    let x = x.abs();
    let y = y.abs();
    let ax = if x < y { y } else { x };
    let ay = if x < y { x } else { y };

    // ax huge: scale both down.
    if ax > large_val {
        if ay <= ax * eps {
            return ax + ay;
        }
        return hypot_kernel_f128(ax * scale, ay * scale) / scale;
    }
    // ay tiny: scale both up.
    if ay < tiny_val {
        if ax >= ay / eps {
            return ax + ay;
        }
        return hypot_kernel_f128(ax / scale, ay / scale) * scale;
    }
    // Common case.
    if ay <= ax * eps {
        return ax + ay;
    }
    hypot_kernel_f128(ax, ay)
}

/// arctan(k/8) for k = 0..=82, plus pi/2 at index 83 — glibc ldbl-128 table.
#[rustfmt::skip]
static ATAN_TBL_F128: [f128; 84] = [
    0.0000000000000000000000000000000000000000E0f128,
    1.2435499454676143503135484916387102557317E-1f128,
    2.4497866312686415417208248121127581091414E-1f128,
    3.5877067027057222039592006392646049977698E-1f128,
    4.6364760900080611621425623146121440202854E-1f128,
    5.5859931534356243597150821640166127034645E-1f128,
    6.4350110879328438680280922871732263804151E-1f128,
    7.1882999962162450541701415152590465395142E-1f128,
    7.8539816339744830961566084581987572104929E-1f128,
    8.4415398611317100251784414827164750652594E-1f128,
    8.9605538457134395617480071802993782702458E-1f128,
    9.4200004037946366473793717053459358607166E-1f128,
    9.8279372324732906798571061101466601449688E-1f128,
    1.0191413442663497346383429170230636487744E0f128,
    1.0516502125483736674598673120862998296302E0f128,
    1.0808390005411683108871567292171998202703E0f128,
    1.1071487177940905030170654601785370400700E0f128,
    1.1309537439791604464709335155363278047493E0f128,
    1.1525719972156675180401498626127513797495E0f128,
    1.1722738811284763866005949441337046149712E0f128,
    1.1902899496825317329277337748293183376012E0f128,
    1.2068173702852525303955115800565576303133E0f128,
    1.2220253232109896370417417439225704908830E0f128,
    1.2360594894780819419094519711090786987027E0f128,
    1.2490457723982544258299170772810901230778E0f128,
    1.2610933822524404193139408812473357720101E0f128,
    1.2722973952087173412961937498224804940684E0f128,
    1.2827408797442707473628852511364955306249E0f128,
    1.2924966677897852679030914214070816845853E0f128,
    1.3016288340091961438047858503666855921414E0f128,
    1.3101939350475556342564376891719053122733E0f128,
    1.3182420510168370498593302023271362531155E0f128,
    1.3258176636680324650592392104284756311844E0f128,
    1.3329603993374458675538498697331558093700E0f128,
    1.3397056595989995393283037525895557411039E0f128,
    1.3460851583802539310489409282517796256512E0f128,
    1.3521273809209546571891479413898128509842E0f128,
    1.3578579772154994751124898859640585287459E0f128,
    1.3633001003596939542892985278250991189943E0f128,
    1.3684746984165928776366381936948529556191E0f128,
    1.3734007669450158608612719264449611486510E0f128,
    1.3780955681325110444536609641291551522494E0f128,
    1.3825748214901258580599674177685685125566E0f128,
    1.3868528702577214543289381097042486034883E0f128,
    1.3909428270024183486427686943836432060856E0f128,
    1.3948567013423687823948122092044222644895E0f128,
    1.3986055122719575950126700816114282335732E0f128,
    1.4021993871854670105330304794336492676944E0f128,
    1.4056476493802697809521934019958079881002E0f128,
    1.4089588955564736949699075250792569287156E0f128,
    1.4121410646084952153676136718584891599630E0f128,
    1.4152014988178669079462550975833894394929E0f128,
    1.4181469983996314594038603039700989523716E0f128,
    1.4209838702219992566633046424614466661176E0f128,
    1.4237179714064941189018190466107297503086E0f128,
    1.4263547484202526397918060597281265695725E0f128,
    1.4288992721907326964184700745371983590908E0f128,
    1.4313562697035588982240194668401779312122E0f128,
    1.4337301524847089866404719096698873648610E0f128,
    1.4360250423171655234964275337155008780675E0f128,
    1.4382447944982225979614042479354815855386E0f128,
    1.4403930189057632173997301031392126865694E0f128,
    1.4424730991091018200252920599377292525125E0f128,
    1.4444882097316563655148453598508037025938E0f128,
    1.4464413322481351841999668424758804165254E0f128,
    1.4483352693775551917970437843145232637695E0f128,
    1.4501726582147939000905940595923466567576E0f128,
    1.4519559822271314199339700039142990228105E0f128,
    1.4536875822280323362423034480994649820285E0f128,
    1.4553696664279718992423082296859928222270E0f128,
    1.4570043196511885530074841089245667532358E0f128,
    1.4585935117976422128825857356750737658039E0f128,
    1.4601391056210009726721818194296893361233E0f128,
    1.4616428638860188872060496086383008594310E0f128,
    1.4631064559620759326975975316301202111560E0f128,
    1.4645314639038178118428450961503371619177E0f128,
    1.4659193880646627234129855241049975398470E0f128,
    1.4672716522843522691530527207287398276197E0f128,
    1.4685896086876430842559640450619880951144E0f128,
    1.4698745421276027686510391411132998919794E0f128,
    1.4711276743037345918528755717617308518553E0f128,
    1.4723501675822635384916444186631899205983E0f128,
    1.4735431285433308455179928682541563973416E0f128,
    1.5707963267948966192313216916397514420986E0f128,
];

/// Arctangent for binary128 — verbatim port of glibc's ldbl-128 Cephes/Moshier
/// `__atanl` (sysdeps/ieee754/ldbl-128/s_atanl.c). Range-reduce x into a table
/// cell arctan(k/8), reduce the residual with the arctan subtraction identity
/// `t = (x - k/8)/(1 + x·k/8)`, evaluate a rational `t + t³·p(t²)/q(t²)`, and
/// add back the table value. Fully self-contained (no other transcendental),
/// only f128 `+ - * /`, so byte-exact vs glibc.
fn atan_f128(x: f128) -> f128 {
    const P0: f128 = -4.283708356338736809269381409828726405572E1f128;
    const P1: f128 = -8.636132499244548540964557273544599863825E1f128;
    const P2: f128 = -5.713554848244551350855604111031839613216E1f128;
    const P3: f128 = -1.371405711877433266573835355036413750118E1f128;
    const P4: f128 = -8.638214309119210906997318946650189640184E-1f128;
    const Q0: f128 = 1.285112506901621042780814422948906537959E2f128;
    const Q1: f128 = 3.361907253914337187957855834229672347089E2f128;
    const Q2: f128 = 3.180448303864130128268191635189365331680E2f128;
    const Q3: f128 = 1.307244136980865800160844625025280344686E2f128;
    const Q4: f128 = 2.173623741810414221251136181221172551416E1f128;

    let bits = x.to_bits();
    let w0 = (bits >> 96) as u32;
    let sign = w0 & 0x8000_0000 != 0;
    let k0 = w0 & 0x7fff_ffff;

    // NaN / Infinity.
    if k0 >= 0x7fff_0000 {
        if x.is_nan() {
            return x + x;
        }
        return if sign { -ATAN_TBL_F128[83] } else { ATAN_TBL_F128[83] };
    }
    // |x| < 2^-58: atan(x) == x to full precision.
    if k0 <= 0x3fc5_0000 {
        return x;
    }
    // |x| > 2^115: saturate to +/- pi/2.
    if k0 >= 0x4072_0000 {
        return if sign { -ATAN_TBL_F128[83] } else { ATAN_TBL_F128[83] };
    }

    let x = if sign { -x } else { x };
    let (k, t) = if k0 >= 0x4002_4800 {
        // |x| >= 10.25: t = -1/x, table cell pi/2.
        (83usize, -1.0 / x)
    } else {
        // Index of nearest table element (asymmetric round per fdlibm).
        let ki = (8.0 * x + 0.25) as i32;
        let u = 0.125 * (ki as f128);
        (ki as usize, (x - u) / (1.0 + x * u))
    };

    let u = t * t;
    let p = ((((P4 * u) + P3) * u + P2) * u + P1) * u + P0;
    let q = ((((u + Q4) * u + Q3) * u + Q2) * u + Q1) * u + Q0;
    let u = t * u * p / q + t;
    let u = ATAN_TBL_F128[k] + u;
    if sign { -u } else { u }
}

/// Two-argument arctangent for binary128 — verbatim port of glibc's ldbl-128
/// `__ieee754_atan2l` (sysdeps/ieee754/ldbl-128/e_atan2l.c). All the IEEE
/// special cases, then quadrant placement of `__atanl(|y/x|)`. Depends only on
/// the byte-exact `atan_f128` plus algebraic f128 ops, so it is byte-exact.
fn atan2_f128(y: f128, x: f128) -> f128 {
    const TINY: f128 = 1.0e-4900f128;
    const PI_O_4: f128 = 7.85398163397448309615660845819875699e-01f128;
    const PI_O_2: f128 = 1.57079632679489661923132169163975140e+00f128;
    const PI: f128 = 3.14159265358979323846264338327950280e+00f128;
    const PI_LO: f128 = 8.67181013012378102479704402604335225e-35f128;
    let zero = 0.0f128;

    let xb = x.to_bits();
    let yb = y.to_bits();
    let hx = (xb >> 64) as i64;
    let lx = xb as u64;
    let hy = (yb >> 64) as i64;
    let ly = yb as u64;
    let ix = hx & 0x7fff_ffff_ffff_ffff;
    let iy = hy & 0x7fff_ffff_ffff_ffff;

    // x or y is NaN.
    if (ix as u64 | ((lx | lx.wrapping_neg()) >> 63)) > 0x7fff_0000_0000_0000
        || (iy as u64 | ((ly | ly.wrapping_neg()) >> 63)) > 0x7fff_0000_0000_0000
    {
        return x + y;
    }
    if hx == 0x3fff_0000_0000_0000 && lx == 0 {
        return atan_f128(y); // x == 1.0
    }
    let m = ((hy >> 63) & 1) | ((hx >> 62) & 2); // 2*sign(x)+sign(y)

    // y == 0.
    if iy == 0 && ly == 0 {
        return match m {
            0 | 1 => y,         // atan(+-0,+anything) = +-0
            2 => PI + TINY,     // atan(+0,-anything) = pi
            _ => -PI - TINY,    // atan(-0,-anything) = -pi
        };
    }
    // x == 0.
    if ix == 0 && lx == 0 {
        return if hy < 0 { -PI_O_2 - TINY } else { PI_O_2 + TINY };
    }
    // x is INF.
    if ix == 0x7fff_0000_0000_0000 {
        if iy == 0x7fff_0000_0000_0000 {
            return match m {
                0 => PI_O_4 + TINY,
                1 => -PI_O_4 - TINY,
                2 => 3.0 * PI_O_4 + TINY,
                _ => -3.0 * PI_O_4 - TINY,
            };
        }
        return match m {
            0 => zero,
            1 => -zero,
            2 => PI + TINY,
            _ => -PI - TINY,
        };
    }
    // y is INF.
    if iy == 0x7fff_0000_0000_0000 {
        return if hy < 0 { -PI_O_2 - TINY } else { PI_O_2 + TINY };
    }

    // Compute y/x.
    let k = (iy - ix) >> 48;
    let z = if k > 120 {
        PI_O_2 + 0.5 * PI_LO // |y/x| > 2^120
    } else if hx < 0 && k < -120 {
        zero // |y|/x < -2^120
    } else {
        atan_f128((y / x).abs())
    };
    match m {
        0 => z,                                                  // atan(+,+)
        1 => f128::from_bits(z.to_bits() ^ (1u128 << 127)),      // atan(-,+) = -z
        2 => PI - (z - PI_LO),                                   // atan(+,-)
        _ => (z - PI_LO) - PI,                                   // atan(-,-)
    }
}

/// Arcsine for binary128 — verbatim port of glibc's ldbl-128 Sun/fdlibm
/// `__ieee754_asinl` (e_asinl.c). Three rational approximations by range
/// (|x|<0.5 via pS/qS, [0.5625±] via rS/sS, |x|>=0.625 via sqrt((1-|x|)/2) +
/// pS/qS with a hi/lo split of the sqrt). Self-contained (only sqrtl +
/// algebraic f128 ops); polynomials written as sequential Horner statements
/// that reproduce glibc's exact mul-then-add operation order, so byte-exact.
#[allow(clippy::excessive_precision)]
fn asin_f128(x: f128) -> f128 {
    const PIO2_HI: f128 = 1.5707963267948966192313216916397514420986f128;
    const PIO2_LO: f128 = 4.3359050650618905123985220130216759843812E-35f128;
    const PIO4_HI: f128 = 7.8539816339744830961566084581987569936977E-1f128;
    const PS0: f128 = -8.358099012470680544198472400254596543711E2f128;
    const PS1: f128 = 3.674973957689619490312782828051860366493E3f128;
    const PS2: f128 = -6.730729094812979665807581609853656623219E3f128;
    const PS3: f128 = 6.643843795209060298375552684423454077633E3f128;
    const PS4: f128 = -3.817341990928606692235481812252049415993E3f128;
    const PS5: f128 = 1.284635388402653715636722822195716476156E3f128;
    const PS6: f128 = -2.410736125231549204856567737329112037867E2f128;
    const PS7: f128 = 2.219191969382402856557594215833622156220E1f128;
    const PS8: f128 = -7.249056260830627156600112195061001036533E-1f128;
    const PS9: f128 = 1.055923570937755300061509030361395604448E-3f128;
    const QS0: f128 = -5.014859407482408326519083440151745519205E3f128;
    const QS1: f128 = 2.430653047950480068881028451580393430537E4f128;
    const QS2: f128 = -4.997904737193653607449250593976069726962E4f128;
    const QS3: f128 = 5.675712336110456923807959930107347511086E4f128;
    const QS4: f128 = -3.881523118339661268482937768522572588022E4f128;
    const QS5: f128 = 1.634202194895541569749717032234510811216E4f128;
    const QS6: f128 = -4.151452662440709301601820849901296953752E3f128;
    const QS7: f128 = 5.956050864057192019085175976175695342168E2f128;
    const QS8: f128 = -4.175375777334867025769346564600396877176E1f128;
    const RS0: f128 = -5.619049346208901520945464704848780243887E0f128;
    const RS1: f128 = 4.460504162777731472539175700169871920352E1f128;
    const RS2: f128 = -1.317669505315409261479577040530751477488E2f128;
    const RS3: f128 = 1.626532582423661989632442410808596009227E2f128;
    const RS4: f128 = -3.144806644195158614904369445440583873264E1f128;
    const RS5: f128 = -9.806674443470740708765165604769099559553E1f128;
    const RS6: f128 = 5.708468492052010816555762842394927806920E1f128;
    const RS7: f128 = 1.396540499232262112248553357962639431922E1f128;
    const RS8: f128 = -1.126243289311910363001762058295832610344E1f128;
    const RS9: f128 = -4.956179821329901954211277873774472383512E-1f128;
    const RS10: f128 = 3.313227657082367169241333738391762525780E-1f128;
    const SS0: f128 = -4.645814742084009935700221277307007679325E0f128;
    const SS1: f128 = 3.879074822457694323970438316317961918430E1f128;
    const SS2: f128 = -1.221986588013474694623973554726201001066E2f128;
    const SS3: f128 = 1.658821150347718105012079876756201905822E2f128;
    const SS4: f128 = -4.804379630977558197953176474426239748977E1f128;
    const SS5: f128 = -1.004296417397316948114344573811562952793E2f128;
    const SS6: f128 = 7.530281592861320234941101403870010111138E1f128;
    const SS7: f128 = 1.270735595411673647119592092304357226607E1f128;
    const SS8: f128 = -1.815144839646376500705105967064792930282E1f128;
    const SS9: f128 = -7.821597334910963922204235247786840828217E-2f128;
    const ASINR5625: f128 = 5.9740641664535021430381036628424864397707E-1f128;

    let xb = x.to_bits();
    let w0 = (xb >> 96) as u32;
    let neg = w0 & 0x8000_0000 != 0;
    let ix = w0 & 0x7fff_ffff;
    let absx = f128::from_bits(xb & !(1u128 << 127)); // |x|

    if ix >= 0x3fff_0000 {
        // |x| >= 1
        if ix == 0x3fff_0000 && (xb & ((1u128 << 96) - 1)) == 0 {
            return x * PIO2_HI + x * PIO2_LO; // asin(±1) = ±pi/2
        }
        if x.is_nan() {
            return (x - x) / (x - x); // propagate the input NaN
        }
        // asin(|x|>1): glibc's (x-x)/(x-x) is the canonical NEGATIVE qNaN on x86.
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    }

    let mut flag = false;
    let t;
    if ix < 0x3ffe_0000 {
        // |x| < 0.5
        if ix < 0x3fc6_0000 {
            return x; // |x| < 2^-57: asin(x) == x
        }
        t = x * x;
        flag = true;
    } else if ix < 0x3ffe_4000 {
        // |x| < 0.625: asin(0.5625 + tt) = asinr5625 + tt·rS(tt)/sS(tt)
        let tt = absx - 0.5625;
        let mut p = RS10 * tt + RS9;
        p = p * tt + RS8;
        p = p * tt + RS7;
        p = p * tt + RS6;
        p = p * tt + RS5;
        p = p * tt + RS4;
        p = p * tt + RS3;
        p = p * tt + RS2;
        p = p * tt + RS1;
        p = p * tt + RS0;
        p = p * tt;
        let mut q = tt + SS9;
        q = q * tt + SS8;
        q = q * tt + SS7;
        q = q * tt + SS6;
        q = q * tt + SS5;
        q = q * tt + SS4;
        q = q * tt + SS3;
        q = q * tt + SS2;
        q = q * tt + SS1;
        q = q * tt + SS0;
        let r = ASINR5625 + p / q;
        return if neg { -r } else { r };
    } else {
        // 1 > |x| >= 0.625
        let w = 1.0 - absx;
        t = w * 0.5;
    }

    // pS/qS rational on t.
    let mut p = PS9 * t + PS8;
    p = p * t + PS7;
    p = p * t + PS6;
    p = p * t + PS5;
    p = p * t + PS4;
    p = p * t + PS3;
    p = p * t + PS2;
    p = p * t + PS1;
    p = p * t + PS0;
    p = p * t;
    let mut q = t + QS8;
    q = q * t + QS7;
    q = q * t + QS6;
    q = q * t + QS5;
    q = q * t + QS4;
    q = q * t + QS3;
    q = q * t + QS2;
    q = q * t + QS1;
    q = q * t + QS0;

    if flag {
        let w = p / q;
        return x + x * w;
    }

    let s = t.sqrt();
    let tres;
    if ix >= 0x3ffe_f333 {
        // |x| > 0.975
        let w = p / q;
        tres = PIO2_HI - (2.0 * (s + s * w) - PIO2_LO);
    } else {
        // hi/lo split of s: clear the low 64 mantissa bits.
        let w = f128::from_bits(s.to_bits() & (!0u128 << 64));
        let c = (t - w * w) / (s + w);
        let r = p / q;
        let pp = 2.0 * s * r - (PIO2_LO - 2.0 * c);
        let qq = PIO4_HI - 2.0 * w;
        tres = PIO4_HI - (pp - qq);
    }
    if neg { -tres } else { tres }
}

/// Arccosine for binary128 — verbatim port of glibc's ldbl-128 `__ieee754_acosl`
/// (e_acosl.c). Five range branches: |x|<2^-113 → pi/2; |x|<0.4375 via
/// pS/qS (acos = pi/2 - asin); [0.4375±] via P/Q; [0.5625±] via rS/sS (acos-
/// specific signs); |x|>=0.625 via acos = 2·asin(sqrt((1-|x|)/2)) with an
/// extended-precision sqrt correction. Self-contained (only sqrtl + algebraic
/// f128); sequential-Horner polynomials reproduce glibc's op order → byte-exact.
#[allow(clippy::excessive_precision)]
fn acos_f128(x: f128) -> f128 {
    const PIO2_HI: f128 = 1.5707963267948966192313216916397514420986f128;
    const PIO2_LO: f128 = 4.3359050650618905123985220130216759843812E-35f128;
    const RS0: f128 = 5.619049346208901520945464704848780243887E0f128;
    const RS1: f128 = -4.460504162777731472539175700169871920352E1f128;
    const RS2: f128 = 1.317669505315409261479577040530751477488E2f128;
    const RS3: f128 = -1.626532582423661989632442410808596009227E2f128;
    const RS4: f128 = 3.144806644195158614904369445440583873264E1f128;
    const RS5: f128 = 9.806674443470740708765165604769099559553E1f128;
    const RS6: f128 = -5.708468492052010816555762842394927806920E1f128;
    const RS7: f128 = -1.396540499232262112248553357962639431922E1f128;
    const RS8: f128 = 1.126243289311910363001762058295832610344E1f128;
    const RS9: f128 = 4.956179821329901954211277873774472383512E-1f128;
    const RS10: f128 = -3.313227657082367169241333738391762525780E-1f128;
    const SS0: f128 = -4.645814742084009935700221277307007679325E0f128;
    const SS1: f128 = 3.879074822457694323970438316317961918430E1f128;
    const SS2: f128 = -1.221986588013474694623973554726201001066E2f128;
    const SS3: f128 = 1.658821150347718105012079876756201905822E2f128;
    const SS4: f128 = -4.804379630977558197953176474426239748977E1f128;
    const SS5: f128 = -1.004296417397316948114344573811562952793E2f128;
    const SS6: f128 = 7.530281592861320234941101403870010111138E1f128;
    const SS7: f128 = 1.270735595411673647119592092304357226607E1f128;
    const SS8: f128 = -1.815144839646376500705105967064792930282E1f128;
    const SS9: f128 = -7.821597334910963922204235247786840828217E-2f128;
    const ACOSR5625: f128 = 9.7338991014954640492751132535550279812151E-1f128;
    const PIMACOSR5625: f128 = 2.1682027434402468335351320579240000860757E0f128;
    const P0: f128 = 2.177690192235413635229046633751390484892E0f128;
    const P1: f128 = -2.848698225706605746657192566166142909573E1f128;
    const P2: f128 = 1.040076477655245590871244795403659880304E2f128;
    const P3: f128 = -1.400087608918906358323551402881238180553E2f128;
    const P4: f128 = 2.221047917671449176051896400503615543757E1f128;
    const P5: f128 = 9.643714856395587663736110523917499638702E1f128;
    const P6: f128 = -5.158406639829833829027457284942389079196E1f128;
    const P7: f128 = -1.578651828337585944715290382181219741813E1f128;
    const P8: f128 = 1.093632715903802870546857764647931045906E1f128;
    const P9: f128 = 5.448925479898460003048760932274085300103E-1f128;
    const P10: f128 = -3.315886001095605268470690485170092986337E-1f128;
    const Q0: f128 = -1.958219113487162405143608843774587557016E0f128;
    const Q1: f128 = 2.614577866876185080678907676023269360520E1f128;
    const Q2: f128 = -9.990858606464150981009763389881793660938E1f128;
    const Q3: f128 = 1.443958741356995763628660823395334281596E2f128;
    const Q4: f128 = -3.206441012484232867657763518369723873129E1f128;
    const Q5: f128 = -1.048560885341833443564920145642588991492E2f128;
    const Q6: f128 = 6.745883931909770880159915641984874746358E1f128;
    const Q7: f128 = 1.806809656342804436118449982647641392951E1f128;
    const Q8: f128 = -1.770150690652438294290020775359580915464E1f128;
    const Q9: f128 = -5.659156469628629327045433069052560211164E-1f128;
    const ACOSR4375: f128 = 1.1179797320499710475919903296900511518755E0f128;
    const PIMACOSR4375: f128 = 2.0236129215398221908706530535894517323217E0f128;
    const PS0: f128 = -8.358099012470680544198472400254596543711E2f128;
    const PS1: f128 = 3.674973957689619490312782828051860366493E3f128;
    const PS2: f128 = -6.730729094812979665807581609853656623219E3f128;
    const PS3: f128 = 6.643843795209060298375552684423454077633E3f128;
    const PS4: f128 = -3.817341990928606692235481812252049415993E3f128;
    const PS5: f128 = 1.284635388402653715636722822195716476156E3f128;
    const PS6: f128 = -2.410736125231549204856567737329112037867E2f128;
    const PS7: f128 = 2.219191969382402856557594215833622156220E1f128;
    const PS8: f128 = -7.249056260830627156600112195061001036533E-1f128;
    const PS9: f128 = 1.055923570937755300061509030361395604448E-3f128;
    const QS0: f128 = -5.014859407482408326519083440151745519205E3f128;
    const QS1: f128 = 2.430653047950480068881028451580393430537E4f128;
    const QS2: f128 = -4.997904737193653607449250593976069726962E4f128;
    const QS3: f128 = 5.675712336110456923807959930107347511086E4f128;
    const QS4: f128 = -3.881523118339661268482937768522572588022E4f128;
    const QS5: f128 = 1.634202194895541569749717032234510811216E4f128;
    const QS6: f128 = -4.151452662440709301601820849901296953752E3f128;
    const QS7: f128 = 5.956050864057192019085175976175695342168E2f128;
    const QS8: f128 = -4.175375777334867025769346564600396877176E1f128;

    let xb = x.to_bits();
    let w0 = (xb >> 96) as u32;
    let neg = w0 & 0x8000_0000 != 0;
    let ix = w0 & 0x7fff_ffff;
    let absx = f128::from_bits(xb & !(1u128 << 127)); // |x|

    if ix >= 0x3fff_0000 {
        // |x| >= 1
        if ix == 0x3fff_0000 && (xb & ((1u128 << 96) - 1)) == 0 {
            // |x| == 1
            return if !neg { 0.0 } else { 2.0 * PIO2_HI + 2.0 * PIO2_LO }; // acos(1)=0 / acos(-1)=pi
        }
        if x.is_nan() {
            return (x - x) / (x - x);
        }
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111)); // acos(|x|>1) NaN
    }

    if ix < 0x3ffe_0000 {
        // |x| < 0.5
        if ix < 0x3f8e_0000 {
            return PIO2_HI + PIO2_LO; // |x| < 2^-113
        }
        if ix < 0x3ffd_e000 {
            // |x| < 0.4375 — acos via asin(x).
            let z = x * x;
            let mut p = PS9 * z + PS8;
            p = p * z + PS7;
            p = p * z + PS6;
            p = p * z + PS5;
            p = p * z + PS4;
            p = p * z + PS3;
            p = p * z + PS2;
            p = p * z + PS1;
            p = p * z + PS0;
            p = p * z;
            let mut q = z + QS8;
            q = q * z + QS7;
            q = q * z + QS6;
            q = q * z + QS5;
            q = q * z + QS4;
            q = q * z + QS3;
            q = q * z + QS2;
            q = q * z + QS1;
            q = q * z + QS0;
            let r = x + x * p / q;
            return PIO2_HI - (r - PIO2_LO);
        }
        // 0.4375 <= |x| < 0.5 via P/Q.
        let t = absx - 0.4375;
        let mut p = P10 * t + P9;
        p = p * t + P8;
        p = p * t + P7;
        p = p * t + P6;
        p = p * t + P5;
        p = p * t + P4;
        p = p * t + P3;
        p = p * t + P2;
        p = p * t + P1;
        p = p * t + P0;
        p = p * t;
        let mut q = t + Q9;
        q = q * t + Q8;
        q = q * t + Q7;
        q = q * t + Q6;
        q = q * t + Q5;
        q = q * t + Q4;
        q = q * t + Q3;
        q = q * t + Q2;
        q = q * t + Q1;
        q = q * t + Q0;
        let r = p / q;
        return if neg { PIMACOSR4375 - r } else { ACOSR4375 + r };
    }

    if ix < 0x3ffe_4000 {
        // |x| < 0.625 via rS/sS.
        let t = absx - 0.5625;
        let mut p = RS10 * t + RS9;
        p = p * t + RS8;
        p = p * t + RS7;
        p = p * t + RS6;
        p = p * t + RS5;
        p = p * t + RS4;
        p = p * t + RS3;
        p = p * t + RS2;
        p = p * t + RS1;
        p = p * t + RS0;
        p = p * t;
        let mut q = t + SS9;
        q = q * t + SS8;
        q = q * t + SS7;
        q = q * t + SS6;
        q = q * t + SS5;
        q = q * t + SS4;
        q = q * t + SS3;
        q = q * t + SS2;
        q = q * t + SS1;
        q = q * t + SS0;
        let pq = p / q;
        return if neg { PIMACOSR5625 - pq } else { ACOSR5625 + pq };
    }

    // |x| >= 0.625 via acos = 2·asin(sqrt((1-|x|)/2)).
    let z = (1.0 - absx) * 0.5;
    let s = z.sqrt();
    // Extended-precision sqrt correction (split f1 = high 64 bits of s).
    let f1 = f128::from_bits(s.to_bits() & (!0u128 << 64));
    let f2 = s - f1;
    let mut w = z - f1 * f1;
    w = w - 2.0 * f1 * f2;
    w = w - f2 * f2;
    w = w / (2.0 * s);
    let mut p = PS9 * z + PS8;
    p = p * z + PS7;
    p = p * z + PS6;
    p = p * z + PS5;
    p = p * z + PS4;
    p = p * z + PS3;
    p = p * z + PS2;
    p = p * z + PS1;
    p = p * z + PS0;
    p = p * z;
    let mut q = z + QS8;
    q = q * z + QS7;
    q = q * z + QS6;
    q = q * z + QS5;
    q = q * z + QS4;
    q = q * z + QS3;
    q = q * z + QS2;
    q = q * z + QS1;
    q = q * z + QS0;
    let r = s + (w + s * p / q);
    let w2 = if neg { PIO2_HI + (PIO2_LO - r) } else { r };
    2.0 * w2
}

/// `logtbl[k] = ln(t) - (t-1)` for t = 0.5 + (k+26)/128, k = 0..=91 — glibc
/// ldbl-128 e_logl.c lookup table. Index 38 is exactly 0 (the `ZERO` anchor).
#[rustfmt::skip]
static LOG_TBL_F128: [f128; 92] = [
    -5.5345593589352099112142921677820359632418E-2f128,
    -5.2108257402767124761784665198737642086148E-2f128,
    -4.8991686870576856279407775480686721935120E-2f128,
    -4.5993270766361228596215288742353061431071E-2f128,
    -4.3110481649613269682442058976885699556950E-2f128,
    -4.0340872319076331310838085093194799765520E-2f128,
    -3.7682072451780927439219005993827431503510E-2f128,
    -3.5131785416234343803903228503274262719586E-2f128,
    -3.2687785249045246292687241862699949178831E-2f128,
    -3.0347913785027239068190798397055267411813E-2f128,
    -2.8110077931525797884641940838507561326298E-2f128,
    -2.5972247078357715036426583294246819637618E-2f128,
    -2.3932450635346084858612873953407168217307E-2f128,
    -2.1988775689981395152022535153795155900240E-2f128,
    -2.0139364778244501615441044267387667496733E-2f128,
    -1.8382413762093794819267536615342902718324E-2f128,
    -1.6716169807550022358923589720001638093023E-2f128,
    -1.5138929457710992616226033183958974965355E-2f128,
    -1.3649036795397472900424896523305726435029E-2f128,
    -1.2244881690473465543308397998034325468152E-2f128,
    -1.0924898127200937840689817557742469105693E-2f128,
    -9.6875626072830301572839422532631079809328E-3f128,
    -8.5313926245226231463436209313499745894157E-3f128,
    -7.4549452072765973384933565912143044991706E-3f128,
    -6.4568155251217050991200599386801665681310E-3f128,
    -5.5356355563671005131126851708522185605193E-3f128,
    -4.6900728132525199028885749289712348829878E-3f128,
    -3.9188291218610470766469347968659624282519E-3f128,
    -3.2206394539524058873423550293617843896540E-3f128,
    -2.5942708080877805657374888909297113032132E-3f128,
    -2.0385211375711716729239156839929281289086E-3f128,
    -1.5522183228760777967376942769773768850872E-3f128,
    -1.1342191863606077520036253234446621373191E-3f128,
    -7.8340854719967065861624024730268350459991E-4f128,
    -4.9869831458030115699628274852562992756174E-4f128,
    -2.7902661731604211834685052867305795169688E-4f128,
    -1.2335696813916860754951146082826952093496E-4f128,
    -3.0677461025892873184042490943581654591817E-5f128,
    0.0000000000000000000000000000000000000000E0f128,
    -3.0359557945051052537099938863236321874198E-5f128,
    -1.2081346403474584914595395755316412213151E-4f128,
    -2.7044071846562177120083903771008342059094E-4f128,
    -4.7834133324631162897179240322783590830326E-4f128,
    -7.4363569786340080624467487620270965403695E-4f128,
    -1.0654639687057968333207323853366578860679E-3f128,
    -1.4429854811877171341298062134712230604279E-3f128,
    -1.8753781835651574193938679595797367137975E-3f128,
    -2.3618380914922506054347222273705859653658E-3f128,
    -2.9015787624124743013946600163375853631299E-3f128,
    -3.4938307889254087318399313316921940859043E-3f128,
    -4.1378413103128673800485306215154712148146E-3f128,
    -4.8328735414488877044289435125365629849599E-3f128,
    -5.5782063183564351739381962360253116934243E-3f128,
    -6.3731336597098858051938306767880719015261E-3f128,
    -7.2169643436165454612058905294782949315193E-3f128,
    -8.1090214990427641365934846191367315083867E-3f128,
    -9.0486422112807274112838713105168375482480E-3f128,
    -1.0035177140880864314674126398350812606841E-2f128,
    -1.1067990155502102718064936259435676477423E-2f128,
    -1.2146457974158024928196575103115488672416E-2f128,
    -1.3269969823361415906628825374158424754308E-2f128,
    -1.4437927104692837124388550722759686270765E-2f128,
    -1.5649743073340777659901053944852735064621E-2f128,
    -1.6904842527181702880599758489058031645317E-2f128,
    -1.8202661505988007336096407340750378994209E-2f128,
    -1.9542647000370545390701192438691126552961E-2f128,
    -2.0924256670080119637427928803038530924742E-2f128,
    -2.2346958571309108496179613803760727786257E-2f128,
    -2.3810230892650362330447187267648486279460E-2f128,
    -2.5313561699385640380910474255652501521033E-2f128,
    -2.6856448685790244233704909690165496625399E-2f128,
    -2.8438398935154170008519274953860128449036E-2f128,
    -3.0058928687233090922411781058956589863039E-2f128,
    -3.1717563112854831855692484086486099896614E-2f128,
    -3.3413836095418743219397234253475252001090E-2f128,
    -3.5147290019036555862676702093393332533702E-2f128,
    -3.6917475563073933027920505457688955423688E-2f128,
    -3.8723951502862058660874073462456610731178E-2f128,
    -4.0566284516358241168330505467000838017425E-2f128,
    -4.2444048996543693813649967076598766917965E-2f128,
    -4.4356826869355401653098777649745233339196E-2f128,
    -4.6304207416957323121106944474331029996141E-2f128,
    -4.8285787106164123613318093945035804818364E-2f128,
    -5.0301169421838218987124461766244507342648E-2f128,
    -5.2349964705088137924875459464622098310997E-2f128,
    -5.4431789996103111613753440311680967840214E-2f128,
    -5.6546268881465384189752786409400404404794E-2f128,
    -5.8693031345788023909329239565012647817664E-2f128,
    -6.0871713627532018185577188079210189048340E-2f128,
    -6.3081958078862169742820420185833800925568E-2f128,
    -6.5323413029406789694910800219643791556918E-2f128,
    -6.7595732653791419081537811574227049288168E-2f128,
];

/// Natural log for binary128 — verbatim port of glibc's ldbl-128
/// `__ieee754_logl` (e_logl.c, Cody & Waite): frexp to [0.703125,1.40625),
/// pick a table point t = 0.5+(k+26)/128, write log(u) = log(t) + log(1+z) with
/// z = (u-t)/t, sum a degree-15 series for log(1+z) plus the tabulated
/// log(t)-(t-1) and e·ln2 (split ln2a+ln2b). A near-1 interval skips the table
/// to dodge cancellation. Self-contained (only frexp + algebraic f128 ops), so
/// byte-exact. Builds the table argument t via direct exponent-field bits.
#[allow(clippy::excessive_precision)]
fn logl_f128(x: f128) -> f128 {
    const L3: f128 = 3.333333333333333333333333333333336096926E-1f128;
    const L4: f128 = -2.499999999999999999999999999486853077002E-1f128;
    const L5: f128 = 1.999999999999999999999999998515277861905E-1f128;
    const L6: f128 = -1.666666666666666666666798448356171665678E-1f128;
    const L7: f128 = 1.428571428571428571428808945895490721564E-1f128;
    const L8: f128 = -1.249999999999999987884655626377588149000E-1f128;
    const L9: f128 = 1.111111111111111093947834982832456459186E-1f128;
    const L10: f128 = -1.000000000000532974938900317952530453248E-1f128;
    const L11: f128 = 9.090909090915566247008015301349979892689E-2f128;
    const L12: f128 = -8.333333211818065121250921925397567745734E-2f128;
    const L13: f128 = 7.692307559897661630807048686258659316091E-2f128;
    const L14: f128 = -7.144242754190814657241902218399056829264E-2f128;
    const L15: f128 = 6.668057591071739754844678883223432347481E-2f128;
    const LN2A: f128 = 6.93145751953125e-1f128;
    const LN2B: f128 = 1.4286068203094172321214581765680755001344E-6f128;

    let xb = x.to_bits();
    let w0 = (xb >> 96) as u32;
    let k0 = w0 & 0x7fff_ffff;
    // log(0) = -inf.
    if k0 == 0 && (xb & ((1u128 << 96) - 1)) == 0 {
        return -0.5 / 0.0;
    }
    // log(x<0) = NaN (negative qNaN on x86; genuine NaN inputs propagate).
    if w0 & 0x8000_0000 != 0 {
        if x.is_nan() {
            return x + x;
        }
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    }
    // log(+inf) = +inf; log(+nan) = nan.
    if k0 >= 0x7fff_0000 {
        return x + x;
    }

    // frexp: mantissa in [0.5,1), exponent e.
    let bits = x.to_bits();
    let ef = ((bits >> 112) & 0x7fff) as i32;
    let (u_frexp, mut e) = if ef == 0 {
        let xn = x * f128::from_bits((113u128 + 16383) << 112);
        let efn = ((xn.to_bits() >> 112) & 0x7fff) as i32;
        (
            f128::from_bits((xn.to_bits() & !(0x7fff_u128 << 112)) | (0x3FFE_u128 << 112)),
            efn - 113 - 16382,
        )
    } else {
        (
            f128::from_bits((bits & !(0x7fff_u128 << 112)) | (0x3FFE_u128 << 112)),
            ef - 16382,
        )
    };

    let ub0 = u_frexp.to_bits();
    let m = ((ub0 >> 96) as u32 & 0xffff) | 0x10000;
    let mut k: i32;
    let t;
    let u_val;
    if m < 0x16800 {
        k = ((m - 0xff00) >> 9) as i32;
        t = f128::from_bits(((0x3fff_0000u32.wrapping_add((k as u32) << 9)) as u128) << 96);
        u_val = f128::from_bits(ub0 + (0x10000u128 << 96)); // w0 += 0x10000
        e -= 1;
        k += 64;
    } else {
        k = ((m - 0xfe00) >> 10) as i32;
        t = f128::from_bits(((0x3ffe_0000u32.wrapping_add((k as u32) << 10)) as u128) << 96);
        u_val = u_frexp;
    }

    let z;
    let mut tval = t;
    let mut kk = k;
    let mut ee = e;
    if x <= 1.0078125 && x >= 0.9921875 {
        if x == 1.0 {
            return 0.0;
        }
        z = x - 1.0;
        kk = 64;
        tval = 1.0;
        ee = 0;
    } else {
        z = (u_val - t) / t;
    }

    let w = z * z;
    let mut y = L15 * z + L14;
    y = y * z + L13;
    y = y * z + L12;
    y = y * z + L11;
    y = y * z + L10;
    y = y * z + L9;
    y = y * z + L8;
    y = y * z + L7;
    y = y * z + L6;
    y = y * z + L5;
    y = y * z + L4;
    y = y * z + L3;
    y = y * z * w; // (poly) * z * w
    y -= 0.5 * w;
    y += (ee as f128) * LN2B;
    y += z;
    y += LOG_TBL_F128[(kk - 26) as usize];
    y += tval - 1.0;
    y += (ee as f128) * LN2A;
    y
}

/// Add `k` to the 15-bit biased exponent field of a binary128, matching glibc's
/// `ieee.exponent += k` bitfield arithmetic (wraps mod 2^15). Callers keep the
/// result in the normal range (the `unsafe`/scale split in expl guarantees it).
#[inline]
fn add_exp_field_f128(v: f128, k: i32) -> f128 {
    let bits = v.to_bits();
    let exp = ((bits >> 112) & 0x7fff) as i32;
    let new_exp = ((exp + k) as u32 & 0x7fff) as u128;
    f128::from_bits((bits & !(0x7fff_u128 << 112)) | (new_exp << 112))
}

/// e^x for binary128 — verbatim port of glibc's ldbl-128 `__ieee754_expl`
/// (e_expl.c): reduce x = n·ln2 + (arg1 table) + (arg2 table) + r with two
/// 256/32768-spaced tables (t_expl.h), evaluate a degree-7 Chebyshev poly for
/// e^r-1, recombine 2^n · e^(arg1) · e^(arg2) via direct exponent-field adds.
/// The fenv save/restore (round-to-nearest, exception hold) is omitted: the
/// default environment is already round-to-nearest and only the value is gated.
/// Uses only algebraic f128 ops + the table, so byte-exact in default rounding.
#[allow(clippy::excessive_precision)]
fn expl_f128(x: f128) -> f128 {
    use crate::expl_table::{EXPL_TABLE, T_EXPL_ARG1, T_EXPL_ARG2, T_EXPL_RES1, T_EXPL_RES2};
    const HIMARK: f128 = 11356.523406294143949491931077970765f128;
    const LOMARK: f128 = -11433.4627433362978788372438434526231f128;
    const THREEP96: f128 = 237684487542793012780631851008.0f128;
    const THREEP103: f128 = 30423614405477505635920876929024.0f128;
    const THREEP111: f128 = 7788445287802241442795744493830144.0f128;
    const M_1_LN2: f128 = 1.44269504088896340735992468100189204f128;
    const M_LN2_0: f128 = 0.693147180559945309417232121457981864f128;
    const M_LN2_1: f128 = -1.94704509238074995158795957333327386E-31f128;
    const TINY: f128 = 1.0e-4900f128;
    const TWO16383: f128 = 5.94865747678615882542879663314003565E+4931f128;
    const TWO8: f128 = 256.0f128;
    const TWO15: f128 = 32768.0f128;
    const P1: f128 = 0.5f128;
    const P2: f128 = 1.66666666666666666666666666666666683E-01f128;
    const P3: f128 = 4.16666666666666666666654902320001674E-02f128;
    const P4: f128 = 8.33333333333333333333314659767198461E-03f128;
    const P5: f128 = 1.38888888889899438565058018857254025E-03f128;
    const P6: f128 = 1.98412698413981650382436541785404286E-04f128;

    if x < HIMARK && x > LOMARK {
        // Calculate n.
        let mut n = x * M_1_LN2 + THREEP111;
        n -= THREEP111;
        let mut x = x - n * M_LN2_0;
        let mut xl = n * M_LN2_1;

        // Calculate t/256, then tval1.
        let mut t = x + THREEP103;
        t -= THREEP103;
        let tval1 = (t * TWO8) as i32;
        x -= EXPL_TABLE[(T_EXPL_ARG1 as i32 + 2 * tval1) as usize];
        xl -= EXPL_TABLE[(T_EXPL_ARG1 as i32 + 2 * tval1 + 1) as usize];

        // Calculate t/32768, then tval2.
        t = x + THREEP96;
        t -= THREEP96;
        let tval2 = (t * TWO15) as i32;
        x -= EXPL_TABLE[(T_EXPL_ARG2 as i32 + 2 * tval2) as usize];
        xl -= EXPL_TABLE[(T_EXPL_ARG2 as i32 + 2 * tval2 + 1) as usize];

        x += xl;

        // ex2 = 2^n_0 · e^(arg1) · e^(arg2).
        let mut ex2 = EXPL_TABLE[(T_EXPL_RES1 as i32 + tval1) as usize]
            * EXPL_TABLE[(T_EXPL_RES2 as i32 + tval2) as usize];
        let n_i = n as i32;
        // 'unsafe_n' is true iff n_1 != 0 (i.e. |n| would overflow a single add).
        let unsafe_n = n_i.abs() >= 15000;
        let shift = if unsafe_n { 1 } else { 0 };
        ex2 = add_exp_field_f128(ex2, n_i >> shift);
        // scale = 2^n_1.
        let scale = add_exp_field_f128(1.0, n_i - (n_i >> shift));

        // Degree-7 Chebyshev poly for e^x2 - 1.
        let x22 = x + x * x * (P1 + x * (P2 + x * (P3 + x * (P4 + x * (P5 + x * P6)))));

        let result = x22 * ex2 + ex2;
        if !unsafe_n {
            result
        } else {
            result * scale // math_check_force_underflow_nonneg: flag only
        }
    } else if x < HIMARK {
        // x <= lomark (incl -inf).
        if x.is_infinite() {
            0.0 // e^-inf = 0
        } else {
            TINY * TINY // underflow
        }
    } else {
        // x >= himark, or x is NaN/+inf: overflow / propagate.
        TWO16383 * x
    }
}

/// e^x - 1 for binary128 — verbatim port of glibc's ldbl-128 `__expm1l`
/// (s_expm1l.c, Cephes): for x>=64 plain expl; else reduce x = ln2·(k+r) and
/// evaluate exp(r)-1 via a P/Q rational, then 2^k·(qx+1)-1. Self-contained given
/// the byte-exact expl_f128; only algebraic f128 ops otherwise → byte-exact.
#[allow(clippy::excessive_precision)]
fn expm1l_f128(x: f128) -> f128 {
    const P0: f128 = 2.943520915569954073888921213330863757240E8f128;
    const P1: f128 = -5.722847283900608941516165725053359168840E7f128;
    const P2: f128 = 8.944630806357575461578107295909719817253E6f128;
    const P3: f128 = -7.212432713558031519943281748462837065308E5f128;
    const P4: f128 = 4.578962475841642634225390068461943438441E4f128;
    const P5: f128 = -1.716772506388927649032068540558788106762E3f128;
    const P6: f128 = 4.401308817383362136048032038528753151144E1f128;
    const P7: f128 = -4.888737542888633647784737721812546636240E-1f128;
    const Q0: f128 = 1.766112549341972444333352727998584753865E9f128;
    const Q1: f128 = -7.848989743695296475743081255027098295771E8f128;
    const Q2: f128 = 1.615869009634292424463780387327037251069E8f128;
    const Q3: f128 = -2.019684072836541751428967854947019415698E7f128;
    const Q4: f128 = 1.682912729190313538934190635536631941751E6f128;
    const Q5: f128 = -9.615511549171441430850103489315371768998E4f128;
    const Q6: f128 = 3.697714952261803935521187272204485251835E3f128;
    const Q7: f128 = -8.802340681794263968892934703309274564037E1f128;
    const C1: f128 = 6.93145751953125E-1f128;
    const C2: f128 = 1.428606820309417232121458176568075500134E-6f128;
    const MINARG: f128 = -7.9018778583833765273564461846232128760607E1f128;
    const BIG: f128 = 1e4932f128;

    let xb = x.to_bits();
    let w0 = (xb >> 96) as u32;
    let sign = w0 & 0x8000_0000 != 0;
    let ix = w0 & 0x7fff_ffff;

    // Positive and exp large: exp(x)-1 == exp(x) in f128.
    if !sign && ix >= 0x4006_0000 {
        return expl_f128(x);
    }
    // inf / NaN (positive inf already handled above, so this is -inf or NaN).
    if ix >= 0x7fff_0000 {
        if (xb & ((1u128 << 112) - 1)) == 0 {
            return -1.0; // expm1(-inf) = -1
        }
        return x + x; // NaN
    }
    // expm1(±0) = ±0.
    if ix == 0 && (xb & ((1u128 << 112) - 1)) == 0 {
        return x;
    }
    // Very negative: result -> -1.
    if x < MINARG {
        return 4.0 / BIG - 1.0;
    }
    // Tiny: expm1(x) == x.
    if x.abs() < f128::from_bits(16270u128 << 112) {
        return x; // |x| < 2^-113
    }

    // Reduce x = ln2 (k + remainder), |remainder| <= 1/2.
    let ln2 = C1 + C2;
    let pf = (0.5 + x / ln2).floor();
    let k = pf as i32;
    let mut xr = x - pf * C1;
    xr -= pf * C2;

    // exp(remainder ln2) - 1 via P/Q.
    let mut px = P7 * xr + P6;
    px = px * xr + P5;
    px = px * xr + P4;
    px = px * xr + P3;
    px = px * xr + P2;
    px = px * xr + P1;
    px = px * xr + P0;
    px *= xr;
    let mut qx = xr + Q7;
    qx = qx * xr + Q6;
    qx = qx * xr + Q5;
    qx = qx * xr + Q4;
    qx = qx * xr + Q3;
    qx = qx * xr + Q2;
    qx = qx * xr + Q1;
    qx = qx * xr + Q0;
    let xx = xr * xr;
    let qx = xr + (0.5 * xx + xx * px / qx);

    // exp(x)-1 = 2^k (qx+1) - 1 = 2^k qx + 2^k - 1.
    let p2k = scalbn_f128(1.0, k as i64);
    p2k * qx + (p2k - 1.0)
}

/// Hyperbolic cosine for binary128 — verbatim port of glibc ldbl-128
/// `__ieee754_coshl` (e_coshl.c): range-split cosh via expm1l (small) / expl
/// (mid/large) / expl(x/2)² (near overflow). Built on byte-exact expm1l_f128 +
/// expl_f128 → byte-exact. Overflow returns +inf.
#[allow(clippy::excessive_precision)]
fn coshl_f128(x: f128) -> f128 {
    const HUGE: f128 = 1.0e4900f128;
    const OVF_THRESH: f128 = 1.1357216553474703894801348310092223067821E4f128;
    let xb = x.to_bits();
    let ex = (xb >> 96) as u32 & 0x7fff_ffff;
    let absx = f128::from_bits(xb & !(1u128 << 127));
    if ex >= 0x7fff_0000 {
        return x * x; // |x| for ±inf/NaN
    }
    if ex < 0x3ffd_62e4 {
        if ex < 0x3fb8_0000 {
            return 1.0; // cosh(tiny) = 1
        }
        let t = expm1l_f128(absx);
        let w = 1.0 + t;
        return 1.0 + (t * t) / (w + w);
    }
    if ex < 0x4004_4000 {
        let t = expl_f128(absx);
        return 0.5 * t + 0.5 / t;
    }
    if ex <= 0x400c_62e3 {
        return 0.5 * expl_f128(absx);
    }
    if absx <= OVF_THRESH {
        let w = expl_f128(0.5 * absx);
        let t = 0.5 * w;
        return t * w;
    }
    HUGE * HUGE // overflow
}

/// Hyperbolic sine for binary128 — verbatim port of glibc ldbl-128
/// `__ieee754_sinhl` (e_sinhl.c): sign·0.5·range-split via expm1l / expl. Built
/// on byte-exact expm1l_f128 + expl_f128 → byte-exact. Overflow returns ±inf.
#[allow(clippy::excessive_precision)]
fn sinhl_f128(x: f128) -> f128 {
    const SHUGE: f128 = 1.0e4931f128;
    const OVF_THRESH: f128 = 1.1357216553474703894801348310092223067821E4f128;
    let xb = x.to_bits();
    let jx = (xb >> 96) as u32;
    let ix = jx & 0x7fff_ffff;
    if ix >= 0x7fff_0000 {
        return x + x; // inf/nan
    }
    let h: f128 = if jx & 0x8000_0000 != 0 { -0.5 } else { 0.5 };
    let absx = f128::from_bits(xb & !(1u128 << 127));
    if ix <= 0x4004_4000 {
        if ix < 0x3fc6_0000 {
            return x; // sinh(tiny) = x (shuge + x > 1 always holds)
        }
        let t = expm1l_f128(absx);
        if ix < 0x3fff_0000 {
            return h * (2.0 * t - t * t / (t + 1.0));
        }
        return h * (t + t / (t + 1.0));
    }
    if ix <= 0x400c_62e3 {
        return h * expl_f128(absx);
    }
    if absx <= OVF_THRESH {
        let w = expl_f128(0.5 * absx);
        let t = h * w;
        return t * w;
    }
    x * SHUGE // overflow
}

/// Hyperbolic tangent for binary128 — verbatim port of glibc ldbl-128 `__tanhl`
/// (s_tanhl.c): tanh via expm1l(±2|x|), saturating to ±1 for |x|>=40. Built on
/// byte-exact expm1l_f128 → byte-exact. No errno (tanh never over/underflows to
/// a range error).
#[allow(clippy::excessive_precision)]
fn tanhl_f128(x: f128) -> f128 {
    const TINY: f128 = 1.0e-4900f128;
    let xb = x.to_bits();
    let jx = (xb >> 96) as u32;
    let ix = jx & 0x7fff_ffff;
    let neg = jx & 0x8000_0000 != 0;

    if ix >= 0x7fff_0000 {
        // tanh(±inf) = ±1; tanh(NaN) = NaN.
        return if neg { 1.0 / x - 1.0 } else { 1.0 / x + 1.0 };
    }

    let z;
    if ix < 0x4004_4000 {
        if x == 0.0 {
            return x; // ±0
        }
        if ix < 0x3fc6_0000 {
            return x * (1.0 + TINY); // |x| < 2^-57
        }
        let absx = f128::from_bits(xb & !(1u128 << 127));
        if ix >= 0x3fff_0000 {
            let t = expm1l_f128(2.0 * absx);
            z = 1.0 - 2.0 / (t + 2.0);
        } else {
            let t = expm1l_f128(-2.0 * absx);
            z = -t / (t + 2.0);
        }
    } else {
        z = 1.0 - TINY; // |x| > 40 → ±1
    }
    if neg { -z } else { z }
}

/// log(1+x) for binary128 — verbatim port of glibc's ldbl-128 `__log1pl`
/// (s_log1pl.c, Cephes): for |e|>2 the z=2(x-1)/(x+1) form with the R/S
/// rational, otherwise log(1+x)=x-.5x²+x³·P(x)/Q(x). Self-contained (frexp +
/// algebraic f128 ops) → byte-exact. Sequential-Horner polynomials.
#[allow(clippy::excessive_precision)]
fn log1pl_f128(xm1: f128) -> f128 {
    const P12: f128 = 1.538612243596254322971797716843006400388E-6f128;
    const P11: f128 = 4.998469661968096229986658302195402690910E-1f128;
    const P10: f128 = 2.321125933898420063925789532045674660756E1f128;
    const P9: f128 = 4.114517881637811823002128927449878962058E2f128;
    const P8: f128 = 3.824952356185897735160588078446136783779E3f128;
    const P7: f128 = 2.128857716871515081352991964243375186031E4f128;
    const P6: f128 = 7.594356839258970405033155585486712125861E4f128;
    const P5: f128 = 1.797628303815655343403735250238293741397E5f128;
    const P4: f128 = 2.854829159639697837788887080758954924001E5f128;
    const P3: f128 = 3.007007295140399532324943111654767187848E5f128;
    const P2: f128 = 2.014652742082537582487669938141683759923E5f128;
    const P1: f128 = 7.771154681358524243729929227226708890930E4f128;
    const P0: f128 = 1.313572404063446165910279910527789794488E4f128;
    const Q11: f128 = 4.839208193348159620282142911143429644326E1f128;
    const Q10: f128 = 9.104928120962988414618126155557301584078E2f128;
    const Q9: f128 = 9.147150349299596453976674231612674085381E3f128;
    const Q8: f128 = 5.605842085972455027590989944010492125825E4f128;
    const Q7: f128 = 2.248234257620569139969141618556349415120E5f128;
    const Q6: f128 = 6.132189329546557743179177159925690841200E5f128;
    const Q5: f128 = 1.158019977462989115839826904108208787040E6f128;
    const Q4: f128 = 1.514882452993549494932585972882995548426E6f128;
    const Q3: f128 = 1.347518538384329112529391120390701166528E6f128;
    const Q2: f128 = 7.777690340007566932935753241556479363645E5f128;
    const Q1: f128 = 2.626900195321832660448791748036714883242E5f128;
    const Q0: f128 = 3.940717212190338497730839731583397586124E4f128;
    const R5: f128 = -8.828896441624934385266096344596648080902E-1f128;
    const R4: f128 = 8.057002716646055371965756206836056074715E1f128;
    const R3: f128 = -2.024301798136027039250415126250455056397E3f128;
    const R2: f128 = 2.048819892795278657810231591630928516206E4f128;
    const R1: f128 = -8.977257995689735303686582344659576526998E4f128;
    const R0: f128 = 1.418134209872192732479751274970992665513E5f128;
    const S5: f128 = -1.186359407982897997337150403816839480438E2f128;
    const S4: f128 = 3.998526750980007367835804959888064681098E3f128;
    const S3: f128 = -5.748542087379434595104154610899551484314E4f128;
    const S2: f128 = 4.001557694070773974936904547424676279307E5f128;
    const S1: f128 = -1.332535117259762928288745111081235577029E6f128;
    const S0: f128 = 1.701761051846631278975701529965589676574E6f128;
    const C1: f128 = 6.93145751953125E-1f128;
    const C2: f128 = 1.428606820309417232121458176568075500134E-6f128;
    const SQRTH: f128 = 0.7071067811865475244008443621048490392848f128;

    let xb = xm1.to_bits();
    let hx = (xb >> 96) as u32;
    if (hx & 0x7fff_ffff) >= 0x7fff_0000 {
        // +inf→+inf, NaN→NaN; -inf→NaN (glibc's -inf+inf is the negative qNaN).
        if xm1.is_infinite() && (hx & 0x8000_0000) != 0 {
            return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
        }
        return xm1 + xm1.abs();
    }
    if (hx & 0x7fff_ffff) == 0 && (xb & ((1u128 << 96) - 1)) == 0 {
        return xm1; // ±0
    }
    if (hx & 0x7fff_ffff) < 0x3f8e_0000 {
        return xm1; // tiny: (int)xm1 == 0
    }

    let mut x = if xm1 >= f128::from_bits(16496u128 << 112) { xm1 } else { xm1 + 1.0 };
    if x <= 0.0 {
        if x == 0.0 {
            return -1.0 / 0.0; // log1p(-1) = -inf
        }
        // x < -1 → NaN (glibc's 0/(x-x) is the canonical NEGATIVE qNaN on x86).
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    }

    // frexp x (>0) into [0.5,1).
    let bits = x.to_bits();
    let ef = ((bits >> 112) & 0x7fff) as i32;
    let mut e;
    if ef == 0 {
        let xn = x * f128::from_bits((113u128 + 16383) << 112);
        e = ((xn.to_bits() >> 112) & 0x7fff) as i32 - 113 - 16382;
        x = f128::from_bits((xn.to_bits() & !(0x7fff_u128 << 112)) | (0x3FFE_u128 << 112));
    } else {
        e = ef - 16382;
        x = f128::from_bits((bits & !(0x7fff_u128 << 112)) | (0x3FFE_u128 << 112));
    }

    if e > 2 || e < -2 {
        let y;
        let zz;
        if x < SQRTH {
            e -= 1;
            let z = x - 0.5;
            y = 0.5 * z + 0.5;
            zz = z;
        } else {
            let mut z = x - 0.5;
            z -= 0.5;
            y = 0.5 * x + 0.5;
            zz = z;
        }
        let xr = zz / y;
        let z = xr * xr;
        let mut r = R5 * z + R4;
        r = r * z + R3;
        r = r * z + R2;
        r = r * z + R1;
        r = r * z + R0;
        let mut s = z + S5;
        s = s * z + S4;
        s = s * z + S3;
        s = s * z + S2;
        s = s * z + S1;
        s = s * z + S0;
        let mut zr = xr * (z * r / s);
        zr += (e as f128) * C2;
        zr += xr;
        zr += (e as f128) * C1;
        return zr;
    }

    // log(1+x) = x - .5x^2 + x^3 P(x)/Q(x).
    let xr = if x < SQRTH {
        e -= 1;
        if e != 0 { 2.0 * x - 1.0 } else { xm1 }
    } else if e != 0 {
        x - 1.0
    } else {
        xm1
    };
    let z = xr * xr;
    let mut r = P12 * xr + P11;
    r = r * xr + P10;
    r = r * xr + P9;
    r = r * xr + P8;
    r = r * xr + P7;
    r = r * xr + P6;
    r = r * xr + P5;
    r = r * xr + P4;
    r = r * xr + P3;
    r = r * xr + P2;
    r = r * xr + P1;
    r = r * xr + P0;
    let mut s = xr + Q11;
    s = s * xr + Q10;
    s = s * xr + Q9;
    s = s * xr + Q8;
    s = s * xr + Q7;
    s = s * xr + Q6;
    s = s * xr + Q5;
    s = s * xr + Q4;
    s = s * xr + Q3;
    s = s * xr + Q2;
    s = s * xr + Q1;
    s = s * xr + Q0;
    let mut y = xr * (z * r / s);
    y += (e as f128) * C2;
    let mut zr = y - 0.5 * z;
    zr += xr;
    zr += (e as f128) * C1;
    zr
}

/// Shared Cephes log coefficients (glibc ldbl-128 e_log2l.c / e_log10l.c):
/// ln(1+x) = x - x²/2 + x³·P(x)/Q(x) and log(x) = z + z³·R(z²)/S(z²). Ascending
/// index = ascending power; Q,S are monic (implicit leading 1).
#[rustfmt::skip]
static LOGB_P: [f128; 13] = [
    1.313572404063446165910279910527789794488E4f128,
    7.771154681358524243729929227226708890930E4f128,
    2.014652742082537582487669938141683759923E5f128,
    3.007007295140399532324943111654767187848E5f128,
    2.854829159639697837788887080758954924001E5f128,
    1.797628303815655343403735250238293741397E5f128,
    7.594356839258970405033155585486712125861E4f128,
    2.128857716871515081352991964243375186031E4f128,
    3.824952356185897735160588078446136783779E3f128,
    4.114517881637811823002128927449878962058E2f128,
    2.321125933898420063925789532045674660756E1f128,
    4.998469661968096229986658302195402690910E-1f128,
    1.538612243596254322971797716843006400388E-6f128,
];
#[rustfmt::skip]
static LOGB_Q: [f128; 12] = [
    3.940717212190338497730839731583397586124E4f128,
    2.626900195321832660448791748036714883242E5f128,
    7.777690340007566932935753241556479363645E5f128,
    1.347518538384329112529391120390701166528E6f128,
    1.514882452993549494932585972882995548426E6f128,
    1.158019977462989115839826904108208787040E6f128,
    6.132189329546557743179177159925690841200E5f128,
    2.248234257620569139969141618556349415120E5f128,
    5.605842085972455027590989944010492125825E4f128,
    9.147150349299596453976674231612674085381E3f128,
    9.104928120962988414618126155557301584078E2f128,
    4.839208193348159620282142911143429644326E1f128,
];
#[rustfmt::skip]
static LOGB_R: [f128; 6] = [
    1.418134209872192732479751274970992665513E5f128,
    -8.977257995689735303686582344659576526998E4f128,
    2.048819892795278657810231591630928516206E4f128,
    -2.024301798136027039250415126250455056397E3f128,
    8.057002716646055371965756206836056074715E1f128,
    -8.828896441624934385266096344596648080902E-1f128,
];
#[rustfmt::skip]
static LOGB_S: [f128; 6] = [
    1.701761051846631278975701529965589676574E6f128,
    -1.332535117259762928288745111081235577029E6f128,
    4.001557694070773974936904547424676279307E5f128,
    -5.748542087379434595104154610899551484314E4f128,
    3.998526750980007367835804959888064681098E3f128,
    -1.186359407982897997337150403816839480438E2f128,
];

/// Horner: p[n]·xⁿ + … + p[0]. Matches glibc's `neval`.
#[inline]
fn neval_f128(x: f128, p: &[f128]) -> f128 {
    let n = p.len() - 1;
    let mut y = p[n];
    for i in (0..n).rev() {
        y = y * x + p[i];
    }
    y
}
/// Monic Horner: xⁿ⁺¹ + p[n]·xⁿ + … + p[0]. Matches glibc's `deval`.
#[inline]
fn deval_f128(x: f128, p: &[f128]) -> f128 {
    let n = p.len() - 1;
    let mut y = x + p[n];
    for i in (0..n).rev() {
        y = y * x + p[i];
    }
    y
}

/// Shared Cephes log reduction (glibc ldbl-128 e_log2l/e_log10l): handle the
/// IEEE special cases, then frexp + the R/S (|e|>2) or P/Q form. Returns
/// Err(special-value) for 0/neg/inf/NaN/1, else Ok((y, xm, e)) — the reduced
/// log of the fraction `y`, the reduced argument `xm`, and the binary exponent
/// `e`, which each `logN` then combines with its own base constants.
#[allow(clippy::excessive_precision)]
fn cephes_log_reduce_f128(x: f128) -> Result<(f128, f128, i32), f128> {
    const SQRTH: f128 = 7.071067811865475244008443621048490392848359E-1f128;
    let bits = x.to_bits();
    let hx = (bits >> 64) as i64;
    let lx = bits as u64;
    if (hx & 0x7fff_ffff_ffff_ffff) == 0 && lx == 0 {
        return Err(-1.0 / x.abs()); // logN(±0) = -inf
    }
    if hx < 0 {
        if x.is_nan() {
            return Err((x - x) / (x - x));
        }
        return Err(f128::from_bits((0xffff_u128 << 112) | (1u128 << 111))); // x<0 NaN
    }
    if hx >= 0x7fff_0000_0000_0000 {
        return Err(x + x); // +inf / NaN
    }
    if x == 1.0 {
        return Err(0.0);
    }

    // frexp into [0.5,1).
    let xb = x.to_bits();
    let ef = ((xb >> 112) & 0x7fff) as i32;
    let mut e;
    let mut xm;
    if ef == 0 {
        let xn = x * f128::from_bits((113u128 + 16383) << 112);
        e = ((xn.to_bits() >> 112) & 0x7fff) as i32 - 113 - 16382;
        xm = f128::from_bits((xn.to_bits() & !(0x7fff_u128 << 112)) | (0x3FFE_u128 << 112));
    } else {
        e = ef - 16382;
        xm = f128::from_bits((xb & !(0x7fff_u128 << 112)) | (0x3FFE_u128 << 112));
    }

    let y;
    if e > 2 || e < -2 {
        let yy;
        if xm < SQRTH {
            e -= 1;
            let z = xm - 0.5;
            yy = 0.5 * z + 0.5;
            xm = z / yy;
        } else {
            let mut z = xm - 0.5;
            z -= 0.5;
            yy = 0.5 * xm + 0.5;
            xm = z / yy;
        }
        let z = xm * xm;
        y = xm * (z * neval_f128(z, &LOGB_R) / deval_f128(z, &LOGB_S));
    } else {
        if xm < SQRTH {
            e -= 1;
            xm = 2.0 * xm - 1.0;
        } else {
            xm -= 1.0;
        }
        let z = xm * xm;
        let yy = xm * (z * neval_f128(xm, &LOGB_P) / deval_f128(xm, &LOGB_Q));
        y = yy - 0.5 * z;
    }
    Ok((y, xm, e))
}

/// log2 for binary128 — glibc ldbl-128 `__ieee754_log2l`: combine via
/// LOG2EA = log2(e)-1 plus the integer exponent. Byte-exact.
#[allow(clippy::excessive_precision)]
fn log2l_f128(x: f128) -> f128 {
    const LOG2EA: f128 = 4.4269504088896340735992468100189213742664595E-1f128;
    let (y, xm, e) = match cephes_log_reduce_f128(x) {
        Ok(t) => t,
        Err(v) => return v,
    };
    let mut z = y * LOG2EA;
    z += xm * LOG2EA;
    z += y;
    z += xm;
    z += e as f128;
    z
}

/// log10 for binary128 — glibc ldbl-128 `__ieee754_log10l`: combine via
/// log10(e) split (L10EA+L10EB) and log10(2) split (L102A+L102B). Byte-exact.
#[allow(clippy::excessive_precision)]
fn log10l_f128(x: f128) -> f128 {
    const L102A: f128 = 0.3125f128;
    const L102B: f128 = -1.14700043360188047862611052755069732318101185E-2f128;
    const L10EA: f128 = 0.5f128;
    const L10EB: f128 = -6.570551809674817234887108108339491770560299E-2f128;
    let (y, xm, e) = match cephes_log_reduce_f128(x) {
        Ok(t) => t,
        Err(v) => return v,
    };
    let ef = e as f128;
    let mut z = y * L10EB;
    z += xm * L10EB;
    z += ef * L102B;
    z += y * L10EA;
    z += xm * L10EA;
    z += ef * L102A;
    z
}

/// Inverse hyperbolic tangent for binary128 — port of glibc `__ieee754_atanhl`
/// (e_atanhl.c): atanh via 0.5·log1p. Built on byte-exact log1pl_f128 →
/// byte-exact. ±1 is a pole (±inf), |x|>1 is NaN (negative qNaN on x86).
#[allow(clippy::excessive_precision)]
fn atanhl_f128(x: f128) -> f128 {
    let xb = x.to_bits();
    let jx = (xb >> 96) as u32;
    let ix = jx & 0x7fff_ffff;
    let absx = f128::from_bits(xb & !(1u128 << 127));
    if ix >= 0x3fff_0000 {
        if absx == 1.0 {
            return x / 0.0; // atanh(±1) = ±inf
        }
        if x.is_nan() {
            return (x - x) / (x - x);
        }
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111)); // |x|>1 NaN
    }
    if ix < 0x3fc6_0000 {
        return x; // |x| < 2^-57
    }
    let t = if ix < 0x3ffe_0000 {
        let t2 = absx + absx;
        0.5 * log1pl_f128(t2 + t2 * absx / (1.0 - absx))
    } else {
        0.5 * log1pl_f128((absx + absx) / (1.0 - absx))
    };
    if jx & 0x8000_0000 != 0 { -t } else { t }
}

/// Inverse hyperbolic cosine for binary128 — port of glibc `__ieee754_acoshl`
/// (e_acoshl.c): logl(2x) for huge, logl/log1pl mid forms with sqrtl. Built on
/// byte-exact logl_f128 + log1pl_f128 → byte-exact. x<1 is NaN (EDOM).
#[allow(clippy::excessive_precision)]
fn acoshl_f128(x: f128) -> f128 {
    const LN2: f128 = 0.6931471805599453094172321214581766f128;
    let bits = x.to_bits();
    let hx = (bits >> 64) as i64;
    let lx = bits as u64;
    if hx < 0x3fff_0000_0000_0000 {
        // x < 1 (incl negatives); NaN inputs propagate, else negative qNaN.
        if x.is_nan() {
            return (x - x) / (x - x);
        }
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111));
    } else if hx >= 0x4035_0000_0000_0000 {
        if hx >= 0x7fff_0000_0000_0000 {
            return x + x; // inf/NaN
        }
        return logl_f128(x) + LN2; // acosh(huge) = log(2x)
    } else if hx == 0x3fff_0000_0000_0000 && lx == 0 {
        return 0.0; // acosh(1) = 0
    } else if hx > 0x4000_0000_0000_0000 {
        let t = x * x;
        logl_f128(2.0 * x - 1.0 / (x + (t - 1.0).sqrt()))
    } else {
        let t = x - 1.0;
        log1pl_f128(t + (2.0 * t + t * t).sqrt())
    }
}

/// Inverse hyperbolic sine for binary128 — port of glibc `__asinhl`
/// (s_asinhl.c): logl(2x)+ln2 for huge, logl/log1pl mid forms with sqrtl. Built
/// on byte-exact logl_f128 + log1pl_f128 → byte-exact. No errno (entire-domain).
#[allow(clippy::excessive_precision)]
fn asinhl_f128(x: f128) -> f128 {
    const LN2: f128 = 6.931471805599453094172321214581765681e-1f128;
    let xb = x.to_bits();
    let sign = (xb >> 96) as u32;
    let ix = sign & 0x7fff_ffff;
    if ix == 0x7fff_0000 {
        return x + x; // inf/NaN
    }
    if ix < 0x3fc7_0000 {
        return x; // |x| < 2^-56
    }
    let absx = f128::from_bits(xb & !(1u128 << 127));
    let w = if ix > 0x4035_0000 {
        logl_f128(absx) + LN2 // |x| > 2^54
    } else if ix > 0x4000_0000 {
        let t = absx;
        logl_f128(2.0 * t + 1.0 / ((x * x + 1.0).sqrt() + t)) // 2 < |x| <= 2^54
    } else {
        let t = x * x;
        log1pl_f128(absx + t / (1.0 + (1.0 + t).sqrt())) // |x| <= 2
    };
    if sign & 0x8000_0000 != 0 { -w } else { w }
}

/// 10^x for binary128 — verbatim port of glibc's ldbl-128 `__ieee754_exp10l`
/// (e_exp10l.c): split arg into hi/lo (clearing the low 57 mantissa bits), form
/// arg·ln(10) in extended precision, and return expl(hi)·expl(lo). Built on the
/// byte-exact expl_f128 → byte-exact. The two ln(10)-split constants are the
/// exact f128 values of glibc's hex-float literals.
#[allow(clippy::excessive_precision)]
fn exp10l_f128(arg: f128) -> f128 {
    // log10_high = 0x2.4d763776aaa2bp0, log10_low = 0x5.ba95b58ae0b4c28a38a3fb3e7698p-60
    let log10_high = f128::from_bits(0x400026bb1bbb55515800000000000000u128);
    let log10_low = f128::from_bits(0x3fc56ea56d62b82d30a28e28fecf9da6u128);
    const M_LN10: f128 = 2.302585092994045684017991454684364208f128;

    if !arg.is_finite() {
        return expl_f128(arg); // inf→+inf (or 0 via expl(-inf)), NaN→NaN
    }
    if arg < -4974.0 {
        return f128::MIN_POSITIVE * f128::MIN_POSITIVE; // underflow → 0
    }
    if arg > 4933.0 {
        return f128::MAX * f128::MAX; // overflow → inf
    }
    if arg.abs() < f128::from_bits(16267u128 << 112) {
        return 1.0; // |arg| < 2^-116
    }

    let arg_high = f128::from_bits(arg.to_bits() & ((!0u128 << 64) | 0xfe00_0000_0000_0000));
    let arg_low = arg - arg_high;
    let exp_high = arg_high * log10_high;
    let exp_low = arg_high * log10_low + arg_low * M_LN10;
    expl_f128(exp_high) * expl_f128(exp_low)
}

// --- scalbln-like (f, c_long → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf32(x: f32, n: c_long) -> f32 {
    unsafe { scalblnf(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf32x(x: f64, n: c_long) -> f64 {
    unsafe { scalbln(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf64(x: f64, n: c_long) -> f64 {
    unsafe { scalbln(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf64x(x: f64, n: c_long) -> f64 {
    unsafe { scalbln(x, n) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalblnf128(x: f128, n: c_long) -> f128 {
    scalbn_f128(x, n)
}

// --- modf-like (f, *mut f → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff32(x: f32, iptr: *mut f32) -> f32 {
    unsafe { modff(x, iptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff32x(x: f64, iptr: *mut f64) -> f64 {
    unsafe { modf(x, iptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff64(x: f64, iptr: *mut f64) -> f64 {
    unsafe { modf(x, iptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff64x(x: f64, iptr: *mut f64) -> f64 {
    unsafe { modf(x, iptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modff128(x: f128, iptr: *mut f128) -> f128 {
    if x.is_nan() {
        unsafe { *iptr = x };
        return x;
    }
    if x.is_infinite() {
        unsafe { *iptr = x };
        return f128::from_bits(x.to_bits() & (1u128 << 127)); // signed zero
    }
    let t = x.trunc();
    unsafe { *iptr = t };
    // The fractional part carries x's sign (so -0 for negative whole numbers).
    (x - t).copysign(x)
}

// --- remquo-like (f, f, *mut c_int → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof32(x: f32, y: f32, quo: *mut c_int) -> f32 {
    unsafe { remquof(x, y, quo) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof32x(x: f64, y: f64, quo: *mut c_int) -> f64 {
    unsafe { remquo(x, y, quo) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof64(x: f64, y: f64, quo: *mut c_int) -> f64 {
    unsafe { remquo(x, y, quo) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof64x(x: f64, y: f64, quo: *mut c_int) -> f64 {
    unsafe { remquo(x, y, quo) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remquof128(x: f128, y: f128, quo: *mut c_int) -> f128 {
    let ax = x.abs();
    let ay = y.abs();
    // Domain / NaN cases: glibc leaves *quo untouched and sets no errno.
    if x.is_nan() || y.is_nan() {
        return x + y;
    }
    if ay == 0.0 || ax.is_infinite() {
        return f128::from_bits((0xffff_u128 << 112) | (1u128 << 111)); // negative qNaN
    }
    // Low quotient bits = floor(fmod(ax, 8*ay)/ay) (<=7 exact subtractions),
    // then round-to-nearest-even adjustment, with the sign of x/y. (8*ay may
    // overflow to inf, but then ax/ay < 8 so the loop still runs < 8 times.)
    let mut m = ax % (ay * 8.0f128);
    let mut qt: i32 = 0;
    while m >= ay {
        m -= ay;
        qt += 1;
    }
    let two_r = m + m; // m is now fmod(ax, ay)
    let round_up = two_r > ay || (two_r == ay && (qt & 1) == 1);
    // glibc keeps the low 3 quotient bits then adds the round-up carry WITHOUT
    // re-masking, so the stored value can be 8 (or -8).
    let n_mod8 = if round_up { qt + 1 } else { qt };
    let neg_q = x.is_sign_negative() != y.is_sign_negative();
    unsafe { *quo = if neg_q { -n_mod8 } else { n_mod8 } };
    remainder_f128(x, y)
}

// --- sincos-like (f, *mut f, *mut f → void) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32(x: f32, s: *mut f32, c: *mut f32) {
    unsafe { sincosf(x, s, c) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32x(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf64(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf64x(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf128(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}

// --- nan-like (*const c_char → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf32(tagp: *const std::ffi::c_char) -> f32 {
    unsafe { nanf(tagp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf32x(tagp: *const std::ffi::c_char) -> f64 {
    unsafe { nan(tagp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf64(tagp: *const std::ffi::c_char) -> f64 {
    unsafe { nan(tagp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf64x(tagp: *const std::ffi::c_char) -> f64 {
    unsafe { nan(tagp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nanf128(tagp: *const std::ffi::c_char) -> f128 {
    // Quiet NaN whose payload is the base-0 integer parsed from `tagp` (stopping
    // at the first invalid digit; empty/NULL/invalid -> payload 0).
    let mut payload: u128 = 0;
    if !tagp.is_null() {
        let mut seq: Vec<u8> = Vec::new();
        let mut p = tagp.cast::<u8>();
        for _ in 0..128 {
            let c = unsafe { *p };
            if c == 0 {
                break;
            }
            seq.push(c);
            p = unsafe { p.add(1) };
        }
        let (base, digits): (u128, &[u8]) =
            if seq.len() >= 2 && seq[0] == b'0' && (seq[1] | 0x20) == b'x' {
                (16, &seq[2..])
            } else if seq.len() > 1 && seq[0] == b'0' {
                (8, &seq[1..])
            } else {
                (10, &seq[..])
            };
        // glibc requires the ENTIRE tag to be a valid integer; any invalid char
        // (or an empty digit sequence) yields payload 0, not a parsed prefix.
        let mut val: u128 = 0;
        let mut valid = !digits.is_empty();
        for &c in digits {
            match (c as char).to_digit(base as u32) {
                Some(d) => val = val.wrapping_mul(base).wrapping_add(d as u128),
                None => {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            payload = val;
        }
    }
    f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111) | (payload & ((1u128 << 111) - 1)))
}

// --- int-first (c_int, f → f) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf32(n: c_int, x: f32) -> f32 {
    unsafe { jnf(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf32x(n: c_int, x: f64) -> f64 {
    unsafe { jn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf64(n: c_int, x: f64) -> f64 {
    unsafe { jn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf64x(n: c_int, x: f64) -> f64 {
    unsafe { jn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jnf128(n: c_int, x: f64) -> f64 {
    unsafe { jn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf32(n: c_int, x: f32) -> f32 {
    unsafe { ynf(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf32x(n: c_int, x: f64) -> f64 {
    unsafe { yn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf64(n: c_int, x: f64) -> f64 {
    unsafe { yn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf64x(n: c_int, x: f64) -> f64 {
    unsafe { yn(n, x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ynf128(n: c_int, x: f64) -> f64 {
    unsafe { yn(n, x) }
}

// --- Bessel no-int (f64→f64, f32→f32) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f32(x: f32) -> f32 {
    unsafe { j0f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f32x(x: f64) -> f64 {
    unsafe { j0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f64(x: f64) -> f64 {
    unsafe { j0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f64x(x: f64) -> f64 {
    unsafe { j0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j0f128(x: f64) -> f64 {
    unsafe { j0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f32(x: f32) -> f32 {
    unsafe { j1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f32x(x: f64) -> f64 {
    unsafe { j1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f64(x: f64) -> f64 {
    unsafe { j1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f64x(x: f64) -> f64 {
    unsafe { j1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn j1f128(x: f64) -> f64 {
    unsafe { j1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f32(x: f32) -> f32 {
    unsafe { y0f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f32x(x: f64) -> f64 {
    unsafe { y0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f64(x: f64) -> f64 {
    unsafe { y0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f64x(x: f64) -> f64 {
    unsafe { y0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y0f128(x: f64) -> f64 {
    unsafe { y0(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f32(x: f32) -> f32 {
    unsafe { y1f(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f32x(x: f64) -> f64 {
    unsafe { y1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f64(x: f64) -> f64 {
    unsafe { y1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f64x(x: f64) -> f64 {
    unsafe { y1(x) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn y1f128(x: f64) -> f64 {
    unsafe { y1(x) }
}

// --- complex → real ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf32(z: CFloatComplex) -> f32 {
    unsafe { cabsf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf32x(z: CDoubleComplex) -> f64 {
    unsafe { cabs(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf64(z: CDoubleComplex) -> f64 {
    unsafe { cabs(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf64x(z: CDoubleComplex) -> f64 {
    unsafe { cabs(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cabsf128(z: CFloat128Complex) -> f128 {
    // cabs delegates to the finite hypot alias (no errno).
    hypot_f128(z.re, z.im)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf32(z: CFloatComplex) -> f32 {
    unsafe { cargf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf32x(z: CDoubleComplex) -> f64 {
    unsafe { carg(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf64(z: CDoubleComplex) -> f64 {
    unsafe { carg(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf64x(z: CDoubleComplex) -> f64 {
    unsafe { carg(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cargf128(z: CDoubleComplex) -> f64 {
    unsafe { carg(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf32(z: CFloatComplex) -> f32 {
    unsafe { cimagf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf32x(z: CDoubleComplex) -> f64 {
    unsafe { cimag(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf64(z: CDoubleComplex) -> f64 {
    unsafe { cimag(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf64x(z: CDoubleComplex) -> f64 {
    unsafe { cimag(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cimagf128(z: CFloat128Complex) -> f128 {
    z.im
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf32(z: CFloatComplex) -> f32 {
    unsafe { crealf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf32x(z: CDoubleComplex) -> f64 {
    unsafe { creal(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf64(z: CDoubleComplex) -> f64 {
    unsafe { creal(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf64x(z: CDoubleComplex) -> f64 {
    unsafe { creal(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crealf128(z: CFloat128Complex) -> f128 {
    z.re
}

// --- complex → complex ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { cacosf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacosf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { cacoshf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cacoshf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cacosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { casinf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { casinhf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn casinhf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { casinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { catanf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { catanhf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catanh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catanh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catanh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catanhf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { catanh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { ccosf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccosf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccos(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { ccoshf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ccoshf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ccosh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { cexpf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cexp(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cexp(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cexp(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cexpf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cexp(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { clogf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clogf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { clog(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { conjf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { conj(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { conj(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { conj(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn conjf128(z: CFloat128Complex) -> CFloat128Complex {
    // Negate the imaginary part (flip its sign bit, so NaN/inf signs flip too).
    CFloat128Complex { re: z.re, im: f128::from_bits(z.im.to_bits() ^ (1u128 << 127)) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { cprojf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cproj(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cproj(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { cproj(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cprojf128(z: CFloat128Complex) -> CFloat128Complex {
    // Projection onto the Riemann sphere: if either part is infinite, the result
    // is (+inf, copysign(0, im)); otherwise z is unchanged.
    if z.re.is_infinite() || z.im.is_infinite() {
        let im0 = f128::from_bits(z.im.to_bits() & (1u128 << 127)); // signed zero
        CFloat128Complex { re: f128::from_bits(0x7fff_u128 << 112), im: im0 }
    } else {
        z
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { csinf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csin(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { csinhf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csinhf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csinh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { csqrtf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csqrt(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csqrt(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csqrt(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn csqrtf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { csqrt(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { ctanf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctan(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf32(z: CFloatComplex) -> CFloatComplex {
    unsafe { ctanhf(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf32x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctanh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf64(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctanh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf64x(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctanh(z) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctanhf128(z: CDoubleComplex) -> CDoubleComplex {
    unsafe { ctanh(z) }
}

// --- complex binary → complex ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf32(a: CFloatComplex, b: CFloatComplex) -> CFloatComplex {
    unsafe { cpowf(a, b) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf32x(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex {
    unsafe { cpow(a, b) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf64(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex {
    unsafe { cpow(a, b) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf64x(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex {
    unsafe { cpow(a, b) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cpowf128(a: CDoubleComplex, b: CDoubleComplex) -> CDoubleComplex {
    unsafe { cpow(a, b) }
}

// =========================================================================
// glibc __*_finite math aliases
// =========================================================================
//
// glibc exports __func_finite variants that assume finite input (gcc -ffinite-math-only).
// They forward to the regular math function since our implementations handle all cases.

macro_rules! finite_unary_f64 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f64) -> f64 {
            $target(x)
        }
    };
}

macro_rules! finite_unary_f32 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f32) -> f32 {
            $target(x)
        }
    };
}

macro_rules! finite_binary_f64 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f64, y: f64) -> f64 {
            $target(x, y)
        }
    };
}

macro_rules! finite_binary_f32 {
    ($name:ident, $target:path) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: f32, y: f32) -> f32 {
            $target(x, y)
        }
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
pub unsafe extern "C" fn __scalb_finite(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::scalbn(x, y as i32)
}

// Binary f32 _finite aliases
finite_binary_f32!(__atan2f_finite, frankenlibc_core::math::atan2f);
finite_binary_f32!(__fmodf_finite, frankenlibc_core::math::fmodf);
finite_binary_f32!(__hypotf_finite, frankenlibc_core::math::hypotf);
finite_binary_f32!(__powf_finite, frankenlibc_core::math::powf);
finite_binary_f32!(__remainderf_finite, frankenlibc_core::math::remainderf);
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __scalbf_finite(x: f32, y: f32) -> f32 {
    frankenlibc_core::math::scalbnf(x, y as i32)
}

// Binary long double _finite aliases
finite_binary_f64!(__atan2l_finite, frankenlibc_core::math::atan2);
finite_binary_f64!(__fmodl_finite, frankenlibc_core::math::fmod);
finite_binary_f64!(__hypotl_finite, frankenlibc_core::math::hypot);
finite_binary_f64!(__powl_finite, frankenlibc_core::math::pow);
finite_binary_f64!(__remainderl_finite, frankenlibc_core::math::remainder);
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __scalbl_finite(x: f64, y: f64) -> f64 {
    frankenlibc_core::math::scalbn(x, y as i32)
}

// Binary f128 _finite aliases
finite_binary_f64!(__atan2f128_finite, frankenlibc_core::math::atan2);
finite_binary_f64!(__fmodf128_finite, frankenlibc_core::math::fmod);
finite_binary_f64!(__hypotf128_finite, frankenlibc_core::math::hypot);
finite_binary_f64!(__powf128_finite, frankenlibc_core::math::pow);
finite_binary_f64!(__remainderf128_finite, frankenlibc_core::math::remainder);

// jn/yn take (int, double) signature
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jn_finite(n: c_int, x: f64) -> f64 {
    frankenlibc_core::math::jn(n, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jnf_finite(n: c_int, x: f32) -> f32 {
    frankenlibc_core::math::jnf(n, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jnl_finite(n: c_int, x: f64) -> f64 {
    frankenlibc_core::math::jn(n, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __jnf128_finite(n: c_int, x: f64) -> f64 {
    frankenlibc_core::math::jn(n, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __yn_finite(n: c_int, x: f64) -> f64 {
    frankenlibc_core::math::yn(n, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ynf_finite(n: c_int, x: f32) -> f32 {
    frankenlibc_core::math::ynf(n, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ynl_finite(n: c_int, x: f64) -> f64 {
    frankenlibc_core::math::yn(n, x)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ynf128_finite(n: c_int, x: f64) -> f64 {
    frankenlibc_core::math::yn(n, x)
}

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
pub unsafe extern "C" fn __finitef128(x: f128) -> c_int {
    (((x.to_bits() >> 112) & 0x7fff) != 0x7fff) as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    const X87_INTEGER_BIT: u64 = 1u64 << 63;
    const X87_EXP_BIAS: u16 = 16_383;

    fn x87_pack(negative: bool, exponent_bits: u16, significand: u64) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        let sign_exp = exponent_bits | if negative { 0x8000 } else { 0 };
        bytes[..8].copy_from_slice(&significand.to_le_bytes());
        bytes[8..10].copy_from_slice(&sign_exp.to_le_bytes());
        bytes
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn call_nexttoward_symbol_with_x87_arg(x: f64, y: [u8; 16]) -> f64 {
        let out: f64;
        // SAFETY: The inline call builds the x86_64 SysV stack slot expected
        // for a `long double` second argument, calls the exported assembly
        // shim, and restores the stack pointer before returning to Rust.
        unsafe {
            std::arch::asm!(
                "sub rsp, 16",
                "mov rax, qword ptr [{y_ptr}]",
                "mov qword ptr [rsp], rax",
                "mov rax, qword ptr [{y_ptr} + 8]",
                "mov qword ptr [rsp + 8], rax",
                "call nexttoward",
                "add rsp, 16",
                y_ptr = in(reg) y.as_ptr(),
                inout("xmm0") x => out,
                clobber_abi("C"),
            );
        }
        out
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn call_nexttowardf_symbol_with_x87_arg(x: f32, y: [u8; 16]) -> f32 {
        let out: f32;
        // SAFETY: The inline call builds the x86_64 SysV stack slot expected
        // for a `long double` second argument, calls the exported assembly
        // shim, and restores the stack pointer before returning to Rust.
        unsafe {
            std::arch::asm!(
                "sub rsp, 16",
                "mov rax, qword ptr [{y_ptr}]",
                "mov qword ptr [rsp], rax",
                "mov rax, qword ptr [{y_ptr} + 8]",
                "mov qword ptr [rsp + 8], rax",
                "call nexttowardf",
                "add rsp, 16",
                y_ptr = in(reg) y.as_ptr(),
                inout("xmm0") x => out,
                clobber_abi("C"),
            );
        }
        out
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn call_nexttowardl_symbol_with_x87_args(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        // SAFETY: The inline call builds the two x86_64 SysV stack slots
        // expected for `long double` arguments, calls the exported assembly
        // shim, stores the x87 `st(0)` result into `out`, and restores the
        // stack pointer before returning to Rust.
        unsafe {
            std::arch::asm!(
                "sub rsp, 48",
                "mov qword ptr [rsp + 32], rdx",
                "mov rax, qword ptr [rdi]",
                "mov qword ptr [rsp], rax",
                "mov rax, qword ptr [rdi + 8]",
                "mov qword ptr [rsp + 8], rax",
                "mov rax, qword ptr [rsi]",
                "mov qword ptr [rsp + 16], rax",
                "mov rax, qword ptr [rsi + 8]",
                "mov qword ptr [rsp + 24], rax",
                "call nexttowardl",
                "mov rax, qword ptr [rsp + 32]",
                "fstp tbyte ptr [rax]",
                "add rsp, 48",
                in("rdi") x.as_ptr(),
                in("rsi") y.as_ptr(),
                in("rdx") out.as_mut_ptr(),
                clobber_abi("C"),
            );
        }
        out
    }

    fn abi_errno() -> i32 {
        // SAFETY: `__errno_location` returns valid thread-local storage for this thread.
        // Use volatile read to match the volatile write in set_abi_errno,
        // preventing the LTO optimizer from reordering or eliminating accesses.
        unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) }
    }

    fn set_errno_for_test(val: i32) {
        // SAFETY: test helper writes this thread's errno slot directly.
        unsafe { std::ptr::write_volatile(crate::errno_abi::__errno_location(), val) };
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
        let x = std::hint::black_box(0.0_f64);
        let y = std::hint::black_box(-1.0_f64);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { pow(x, y) };
        std::hint::black_box(out);
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn pow_overflow_sets_range_errno() {
        set_errno_for_test(0);
        // Use black_box to prevent the optimizer from constant-folding the
        // pow call or eliminating the errno side effect.
        let x = std::hint::black_box(1.0e308_f64);
        let y = std::hint::black_box(2.0_f64);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { pow(x, y) };
        std::hint::black_box(out);
        assert!(out.is_infinite());
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn pow_underflow_sets_range_errno() {
        set_errno_for_test(0);
        let x = std::hint::black_box(1.0e-308_f64);
        let y = std::hint::black_box(2.0_f64);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let out = unsafe { pow(x, y) };
        std::hint::black_box(out);
        assert_eq!(out, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn powf_underflow_negative_exponent_sets_range_errno() {
        // Regression: powf's underflow branch used to require `y > 0.0`, which
        // wrongly skipped negative-exponent underflow. glibc flags ERANGE for
        // powf(2, -200) -> 0 (matches f64 pow).
        set_errno_for_test(0);
        let x = std::hint::black_box(2.0_f32);
        let y = std::hint::black_box(-200.0_f32);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { powf(x, y) };
        std::hint::black_box(out);
        assert_eq!(out, 0.0);
        assert_eq!(abi_errno(), libc::ERANGE);
    }

    #[test]
    fn powf_underflow_positive_exponent_sets_range_errno() {
        set_errno_for_test(0);
        let x = std::hint::black_box(0.5_f32);
        let y = std::hint::black_box(200.0_f32);
        // SAFETY: ABI entrypoint accepts plain f32 input.
        let out = unsafe { powf(x, y) };
        std::hint::black_box(out);
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
    fn y0_range_error_at_zero() {
        set_errno_for_test(0);
        // SAFETY: ABI entrypoint accepts plain f64 input.
        let v = unsafe { y0(0.0) };
        assert!(v.is_infinite());
        // Y0(0) = -inf is a pole: glibc reports a RANGE error (ERANGE), not a
        // domain error. Only x < 0 (Y undefined for negative reals) is EDOM.
        assert_eq!(abi_errno(), libc::ERANGE);
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn nexttoward_x86_64_symbol_reads_stack_long_double_direction() {
        let one_plus_tiny = x87_pack(false, X87_EXP_BIAS, X87_INTEGER_BIT | 1);
        let one_minus_tiny = x87_pack(false, X87_EXP_BIAS - 1, u64::MAX);

        // SAFETY: The helper constructs the C ABI long-double stack slot.
        let up = unsafe { call_nexttoward_symbol_with_x87_arg(1.0, one_plus_tiny) };
        // SAFETY: The helper constructs the C ABI long-double stack slot.
        let down = unsafe { call_nexttoward_symbol_with_x87_arg(1.0, one_minus_tiny) };

        assert_eq!(up, frankenlibc_core::math::nextafter(1.0, f64::INFINITY));
        assert_eq!(
            down,
            frankenlibc_core::math::nextafter(1.0, f64::NEG_INFINITY)
        );
    }

    #[test]
    fn nexttowardf_steps_and_propagates_nan() {
        // SAFETY: ABI entrypoints accept plain float inputs.
        let up = unsafe { nexttowardf(1.0f32, 2.0f64) };
        assert!(up > 1.0f32);
        assert!(unsafe { nexttowardf(f32::NAN, 1.0f64) }.is_nan());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn nexttowardf_x86_64_symbol_reads_stack_long_double_direction() {
        let one_plus_tiny = x87_pack(false, X87_EXP_BIAS, X87_INTEGER_BIT | 1);

        // SAFETY: The helper constructs the C ABI long-double stack slot.
        let up = unsafe { call_nexttowardf_symbol_with_x87_arg(1.0, one_plus_tiny) };

        assert_eq!(up, frankenlibc_core::math::nextafterf(1.0, f32::INFINITY));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn nexttowardl_x86_64_symbol_returns_x87_long_double_result() {
        let one = x87_pack(false, X87_EXP_BIAS, X87_INTEGER_BIT);
        let one_plus_one_ulp = x87_pack(false, X87_EXP_BIAS, X87_INTEGER_BIT | 1);
        let one_plus_two_ulps = x87_pack(false, X87_EXP_BIAS, X87_INTEGER_BIT | 2);

        // SAFETY: The helper constructs the C ABI long-double stack slots and
        // stores the x87 long-double return value.
        let up = unsafe { call_nexttowardl_symbol_with_x87_args(one, one_plus_two_ulps) };
        // SAFETY: The helper constructs the C ABI long-double stack slots and
        // stores the x87 long-double return value.
        let down = unsafe { call_nexttowardl_symbol_with_x87_args(one_plus_one_ulp, one) };

        assert_eq!(up, one_plus_one_ulp);
        assert_eq!(down, one);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn nexttowardl_x86_64_symbol_preserves_zero_sign_direction() {
        let positive_zero = x87_pack(false, 0, 0);
        let negative_zero = x87_pack(true, 0, 0);
        let negative_min = x87_pack(true, 0, 1);

        // SAFETY: The helper constructs the C ABI long-double stack slots and
        // stores the x87 long-double return value.
        let toward_negative =
            unsafe { call_nexttowardl_symbol_with_x87_args(positive_zero, negative_min) };
        // SAFETY: The helper constructs the C ABI long-double stack slots and
        // stores the x87 long-double return value.
        let equal_negative_zero =
            unsafe { call_nexttowardl_symbol_with_x87_args(positive_zero, negative_zero) };

        assert_eq!(toward_negative, negative_min);
        assert_eq!(equal_negative_zero, negative_zero);
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
            let z = CDoubleComplex {
                re: 0.0,
                im: std::f64::consts::PI,
            };
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
            let z = CDoubleComplex {
                re: f64::INFINITY,
                im: -3.0,
            };
            let p = cproj(z);
            assert_eq!(p.re, f64::INFINITY);
            assert!(p.im == 0.0 && p.im.is_sign_negative()); // -0.0
        }
    }

    #[test]
    fn complex_float_variants_consistent() {
        unsafe {
            let zd = CDoubleComplex { re: 1.0, im: 2.0 };
            let zf = CFloatComplex {
                re: 1.0f32,
                im: 2.0f32,
            };
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
