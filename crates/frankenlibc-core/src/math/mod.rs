//! Mathematical functions.
//!
//! Implements `<math.h>` functions: trigonometric, exponential/logarithmic,
//! special functions, and floating-point utilities.

pub mod exp;
pub mod float;
pub mod special;
pub mod trig;

pub use exp::{exp, exp2, expm1, log, log1p, log2, log10, pow};
pub use float::{
    cbrt, ceil, copysign, fabs, floor, fmod, hypot, remainder, rint, round, sqrt, trunc,
};
pub use special::{erf, lgamma, tgamma};
pub use trig::{acos, acosh, asin, asinh, atan, atan2, atanh, cos, cosh, sin, sinh, tan, tanh};
