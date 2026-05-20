//! Mathematical functions.
//!
//! Implements `<math.h>` functions: trigonometric, exponential/logarithmic,
//! special functions, and floating-point utilities.

pub mod exp;
pub mod float;
pub mod float32;
pub mod special;
pub mod trig;

pub use exp::{exp, exp2, expm1, log, log1p, log2, log10, pow};
pub use float::{
    FP_INFINITE, FP_NAN, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, cbrt, ceil, copysign, drem, exp10, fabs,
    fdim, finite, floor, fma, fmax, fmin, fmod, fpclassify, frexp, gamma, hypot, ilogb, isinf,
    isnan, ldexp, llrint, llround, logb, lrint, lround, modf, nan, nearbyint, nextafter,
    nexttoward, nexttoward_long_double_bits, nexttowardf_long_double_bits, remainder, remquo, rint,
    round, scalbln, scalbn, signbit, significand, sincos, sqrt, trunc,
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
