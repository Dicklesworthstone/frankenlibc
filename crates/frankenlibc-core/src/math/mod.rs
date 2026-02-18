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
    cbrt, ceil, copysign, fabs, fdim, floor, fma, fmax, fmin, fmod, frexp, hypot, ilogb, ldexp,
    llrint, llround, logb, lrint, lround, modf, nearbyint, nextafter, remainder, rint, round,
    scalbln, scalbn, sqrt, trunc,
};
pub use float32::{
    acosf, acoshf, asinf, asinhf, atan2f, atanf, atanhf, cbrtf, ceilf, copysignf, cosf, coshf,
    erfcf, erff, exp2f, expf, expm1f, fabsf, fdimf, floorf, fmaf, fmaxf, fminf, fmodf, frexpf,
    hypotf, ilogbf, ldexpf, lgammaf, llrintf, llroundf, log1pf, log2f, log10f, logbf, logf,
    lrintf, lroundf, modff, nearbyintf, nextafterf, powf, remainderf, rintf, roundf, scalblnf,
    scalbnf, sinf, sinhf, sqrtf, tanhf, tanf, tgammaf, truncf,
};
pub use special::{erf, erfc, lgamma, tgamma};
pub use trig::{acos, acosh, asin, asinh, atan, atan2, atanh, cos, cosh, sin, sinh, tan, tanh};
