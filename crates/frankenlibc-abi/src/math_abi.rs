//! ABI layer for `<math.h>` functions.
//!
//! These entrypoints feed the runtime math kernel (`ApiFamily::MathFenv`)
//! so numeric exceptional regimes (NaN/Inf/denormal patterns) participate
//! in the same strict/hardened control loop as memory and concurrency paths.

use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sin(x: f64) -> f64 {
    unary_entry(x, 5, frankenlibc_core::math::sin)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cos(x: f64) -> f64 {
    unary_entry(x, 5, frankenlibc_core::math::cos)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tan(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::tan)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn asin(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::asin)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn acos(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::acos)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn atan(x: f64) -> f64 {
    unary_entry(x, 5, frankenlibc_core::math::atan)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn atan2(y: f64, x: f64) -> f64 {
    binary_entry(y, x, 6, frankenlibc_core::math::atan2)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn exp(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::exp)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn log(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::log)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn log10(x: f64) -> f64 {
    unary_entry(x, 6, frankenlibc_core::math::log10)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pow(x: f64, y: f64) -> f64 {
    binary_entry(x, y, 8, frankenlibc_core::math::pow)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fabs(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::fabs)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ceil(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::ceil)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn floor(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::floor)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn round(x: f64) -> f64 {
    unary_entry(x, 4, frankenlibc_core::math::round)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmod(x: f64, y: f64) -> f64 {
    binary_entry(x, y, 6, frankenlibc_core::math::fmod)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn erf(x: f64) -> f64 {
    unary_entry(x, 9, frankenlibc_core::math::erf)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tgamma(x: f64) -> f64 {
    unary_entry(x, 11, frankenlibc_core::math::tgamma)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lgamma(x: f64) -> f64 {
    unary_entry(x, 10, frankenlibc_core::math::lgamma)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heal_non_finite_sanity() {
        assert_eq!(heal_non_finite(f64::NAN), 0.0);
        assert_eq!(heal_non_finite(f64::INFINITY), f64::MAX);
        assert_eq!(heal_non_finite(f64::NEG_INFINITY), f64::MIN);
        assert_eq!(heal_non_finite(3.0), 3.0);
    }
}
