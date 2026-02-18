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
    acosf, asinf, atan2f, atanf, ceilf, cosf, expf, fabsf, floorf, fmodf, log2f, log10f, logf,
    powf, roundf, sinf, sqrtf, tanf, truncf,
};
pub use special::{erf, erfc, lgamma, tgamma};
pub use trig::{acos, acosh, asin, asinh, atan, atan2, atanh, cos, cosh, sin, sinh, tan, tanh};
