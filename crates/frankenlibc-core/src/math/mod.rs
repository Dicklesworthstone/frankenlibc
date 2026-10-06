//! Mathematical functions.
//!
//! Implements `<math.h>` functions: trigonometric, exponential/logarithmic,
//! special functions, and floating-point utilities.

/// Declares a hot math kernel that is compiled twice and chosen per call by
/// the CPU it runs on (bd-rc0923-epic-eeuy4f.13).
///
/// The shipped library is built for baseline x86-64, where every `mul_add`
/// lowers to a call of the exported `fma` and `floor`/`round`/`trunc` to calls
/// of their exported functions. `fn name(..) => body;` emits `name`, which
/// runs a twin of `body` compiled with AVX2 and FMA enabled -- the code the
/// x86-64-v3 build gave it -- when the CPU has both, and the baseline `body`
/// otherwise. `body` must be `#[inline(always)]`, and so must every helper on
/// its fast path, or that helper stays baseline code inside the twin. The
/// results are identical: `mul_add` is exactly rounded either way, and the
/// twin contracts nothing the source does not spell out. The check is a test
/// of the CPUID bits `std` caches after the first call; a build that already
/// targets AVX2 and FMA compiles the twin out and calls `body` directly.
macro_rules! avx2_fma_dispatch {
    ($(#[$attr:meta])* $vis:vis fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty => $body:ident;) => {
        $(#[$attr])*
        #[allow(unsafe_code)]
        $vis fn $name($($arg: $ty),*) -> $ret {
            #[cfg(all(
                target_arch = "x86_64",
                not(all(target_feature = "avx2", target_feature = "fma"))
            ))]
            {
                #[target_feature(enable = "avx2,fma")]
                fn avx2_fma_twin($($arg: $ty),*) -> $ret {
                    $body($($arg),*)
                }
                if std::arch::is_x86_feature_detected!("avx2")
                    && std::arch::is_x86_feature_detected!("fma")
                {
                    // SAFETY: the CPU supports AVX2 and FMA, checked just above.
                    return unsafe { avx2_fma_twin($($arg),*) };
                }
            }
            $body($($arg),*)
        }
    };
}
pub(crate) use avx2_fma_dispatch;

/// Whether this process can exercise the AVX2+FMA twins at all: false on a CPU
/// without both, and in a build that already targets them (the twins are then
/// compiled out and the dispatcher is the body).
#[cfg(test)]
pub(crate) fn avx2_fma_twins_active() -> bool {
    #[cfg(all(
        target_arch = "x86_64",
        not(all(target_feature = "avx2", target_feature = "fma"))
    ))]
    {
        std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("fma")
    }
    #[cfg(not(all(
        target_arch = "x86_64",
        not(all(target_feature = "avx2", target_feature = "fma"))
    )))]
    {
        false
    }
}

/// Inputs for the twin-versus-body checks: IEEE specials, subnormals, a dense
/// interior band, and random bit patterns over the whole range.
#[cfg(test)]
pub(crate) fn avx2_fma_dispatch_inputs(lo: f64, hi: f64) -> Vec<f64> {
    let mut v = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        2.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::from_bits(0x000f_ffff_ffff_ffff),
        f64::MAX,
        -f64::MAX,
    ];
    let mut s = 0x2545_f491_4f6c_dd1du64;
    for i in 0..200_000 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.push(if i % 2 == 0 {
            f64::from_bits(s)
        } else {
            lo + (hi - lo) * ((s >> 11) as f64 / (1u64 << 53) as f64)
        });
    }
    v
}

/// Asserts that a kernel declared through `avx2_fma_dispatch!` returns the same
/// bits through its dispatcher -- the AVX2+FMA twin, on a CPU with both -- as
/// its body compiled for this build's baseline (bd-rc0923-epic-eeuy4f.13).
#[cfg(test)]
pub(crate) fn assert_dispatch_matches_body(
    name: &str,
    inputs: &[f64],
    dispatched: impl Fn(f64) -> f64,
    body: impl Fn(f64) -> f64,
) {
    if !avx2_fma_twins_active() {
        eprintln!("{name}: AVX2+FMA twin not exercised (CPU lacks it, or the build targets it)");
    }
    for &x in inputs {
        let (got, want) = (dispatched(x), body(x));
        assert!(
            got.to_bits() == want.to_bits() || (got.is_nan() && want.is_nan()),
            "{name}({x:e} / {:#x}): dispatched {got:e} != body {want:e} (twins active: {})",
            x.to_bits(),
            avx2_fma_twins_active()
        );
    }
}

mod coremath;
mod erf_data;
mod gamma_data;
pub mod exp;
pub mod float;
pub mod float32;
pub mod fromfp;
mod log2_data;
mod log_data;
pub mod special;
pub mod trig;
mod trig_data;

pub use exp::{exp, exp2, expm1, log, log1p, log2, log10, pow};
pub use float::{
    FP_INFINITE, FP_NAN, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, cbrt, ceil, copysign, drem, exp10, fabs,
    fdim, finite, floor, fma, fmax, fmin, fmod, fpclassify, frexp, gamma, hypot, ilogb, isinf,
    isnan, ldexp, llrint, llround, logb, lrint, lround, modf, nan, nearbyint, nextafter,
    nexttoward, nexttoward_long_double_bits, nexttowardf_long_double_bits,
    nexttowardl_long_double_bits, remainder, remquo, rint, round, scalbln, scalbn, signbit,
    significand, sincos, sqrt, trunc,
};
pub use float32::{
    acosf, acoshf, asinf, asinhf, atan2f, atanf, atanhf, cbrtf, ceilf, copysignf, cosf, coshf,
    dremf, erfcf, erff, exp2f, exp10f, expf, expm1f, fabsf, fdimf, finitef, floorf, fmaf, fmaxf,
    fminf, fmodf, fpclassifyf, frexpf, gammaf, hypotf, ilogbf, isinff, isnanf, j0f, j1f, jnf,
    ldexpf, lgammaf, lgammaf_r, llrintf, llroundf, log1pf, log2f, log10f, logbf, logf, lrintf,
    lroundf, modff, nanf, nearbyintf, nextafterf, nexttowardf, powf, remainderf, remquof, rintf,
    roundf, scalblnf, scalbnf, signbitf, significandf, sincosf, sinf, sinhf, sqrtf, tanf, tanhf,
    tgammaf, truncf, y0f, y1f, ynf,
};
pub use special::{erf, erfc, j0, j1, jn, lgamma, lgamma_r, tgamma, y0, y1, yn};
pub use trig::{acos, acosh, asin, asinh, atan, atan2, atanh, cos, cosh, sin, sinh, tan, tanh};
