//! Floating-point utility functions.

use core::cmp::Ordering;

#[inline]
pub fn fabs(x: f64) -> f64 {
    libm::fabs(x)
}

#[inline]
pub fn ceil(x: f64) -> f64 {
    libm::ceil(x)
}

#[inline]
pub fn floor(x: f64) -> f64 {
    libm::floor(x)
}

#[inline]
pub fn round(x: f64) -> f64 {
    libm::round(x)
}

#[inline]
pub fn trunc(x: f64) -> f64 {
    libm::trunc(x)
}

#[inline]
pub fn rint(x: f64) -> f64 {
    libm::rint(x)
}

#[inline]
pub fn fmod(x: f64, y: f64) -> f64 {
    libm::fmod(x, y)
}

#[inline]
pub fn remainder(x: f64, y: f64) -> f64 {
    libm::remainder(x, y)
}

#[inline]
pub fn copysign(x: f64, y: f64) -> f64 {
    libm::copysign(x, y)
}

#[inline]
pub fn sqrt(x: f64) -> f64 {
    libm::sqrt(x)
}

#[inline]
pub fn cbrt(x: f64) -> f64 {
    libm::cbrt(x)
}

#[inline]
pub fn hypot(x: f64, y: f64) -> f64 {
    libm::hypot(x, y)
}

/// Round to nearest integer without raising inexact exception.
///
/// Uses banker's rounding (round to even on ties), matching rint semantics.
#[inline]
pub fn nearbyint(x: f64) -> f64 {
    libm::rint(x)
}

/// Round to nearest integer, return as `i64`.
#[inline]
pub fn lrint(x: f64) -> i64 {
    libm::rint(x) as i64
}

/// Round to nearest integer, return as `i64`.
#[inline]
pub fn llrint(x: f64) -> i64 {
    libm::rint(x) as i64
}

/// Round to nearest integer (away from zero), return as `i64`.
#[inline]
pub fn lround(x: f64) -> i64 {
    libm::round(x) as i64
}

/// Round to nearest integer (away from zero), return as `i64`.
#[inline]
pub fn llround(x: f64) -> i64 {
    libm::round(x) as i64
}

/// Multiply `x` by 2^`exp`.
#[inline]
pub fn ldexp(x: f64, exp: i32) -> f64 {
    libm::ldexp(x, exp)
}

/// Extract mantissa and exponent: `x = m * 2^exp`, `0.5 <= |m| < 1.0`.
#[inline]
pub fn frexp(x: f64) -> (f64, i32) {
    libm::frexp(x)
}

/// Split `x` into integer and fractional parts.
#[inline]
pub fn modf(x: f64) -> (f64, f64) {
    libm::modf(x)
}

/// Return the minimum of two values, respecting NaN semantics.
#[inline]
pub fn fmin(x: f64, y: f64) -> f64 {
    libm::fmin(x, y)
}

/// Return the maximum of two values, respecting NaN semantics.
#[inline]
pub fn fmax(x: f64, y: f64) -> f64 {
    libm::fmax(x, y)
}

/// Positive difference: `max(x - y, 0)`.
#[inline]
pub fn fdim(x: f64, y: f64) -> f64 {
    libm::fdim(x, y)
}

/// Fused multiply-add: `x * y + z` with single rounding.
#[inline]
pub fn fma(x: f64, y: f64, z: f64) -> f64 {
    libm::fma(x, y, z)
}

/// Scale `x` by `2^n`.
#[inline]
pub fn scalbn(x: f64, n: i32) -> f64 {
    libm::scalbn(x, n)
}

/// Scale `x` by `2^n` (long exponent variant).
#[inline]
pub fn scalbln(x: f64, n: i64) -> f64 {
    // libm doesn't have scalbln directly; delegate via ldexp with clamping
    let exp = n.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    libm::ldexp(x, exp)
}

/// Return the next representable float after `x` toward `y`.
#[inline]
pub fn nextafter(x: f64, y: f64) -> f64 {
    libm::nextafter(x, y)
}

/// Return the next representable `f64` after `x` toward `y` (long double direction).
///
/// This is the Rust test-time fallback for call sites that already normalized
/// the direction to `f64`. x86_64 ABI exports use
/// [`nexttoward_long_double_bits`] so 80-bit-only direction differences are not
/// lost before the comparison.
#[inline]
pub fn nexttoward(x: f64, y: f64) -> f64 {
    libm::nextafter(x, y)
}

const X87_EXTENDED_LEN: usize = 16;
const X87_INTEGER_BIT: u64 = 1u64 << 63;
const X87_EXP_BIAS: i32 = 16_383;
const X87_EXP_INF_NAN: u16 = 0x7fff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BinaryFinite {
    negative: bool,
    significand: u64,
    exponent: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinaryClass {
    Nan,
    Infinite { negative: bool },
    Zero { negative: bool },
    Finite(BinaryFinite),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct X87Finite {
    negative: bool,
    exponent_bits: u16,
    significand: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum X87Class {
    Nan,
    Infinite { negative: bool },
    Zero { negative: bool },
    Finite(X87Finite),
}

fn x87_pack(negative: bool, exponent_bits: u16, significand: u64) -> [u8; X87_EXTENDED_LEN] {
    let mut bytes = [0u8; X87_EXTENDED_LEN];
    let sign_exp = exponent_bits | if negative { 0x8000 } else { 0 };
    bytes[..8].copy_from_slice(&significand.to_le_bytes());
    bytes[8..10].copy_from_slice(&sign_exp.to_le_bytes());
    bytes
}

fn x87_classify(bytes: [u8; X87_EXTENDED_LEN]) -> X87Class {
    let significand = u64::from_le_bytes(bytes[..8].try_into().expect("fixed x87 significand"));
    let sign_exp = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed x87 exponent"));
    let negative = sign_exp & 0x8000 != 0;
    let exponent_bits = sign_exp & 0x7fff;

    if exponent_bits == X87_EXP_INF_NAN {
        let fraction = significand & !X87_INTEGER_BIT;
        return if significand & X87_INTEGER_BIT != 0 && fraction == 0 {
            X87Class::Infinite { negative }
        } else {
            X87Class::Nan
        };
    }
    if significand == 0 {
        return X87Class::Zero { negative };
    }
    if exponent_bits != 0 && significand & X87_INTEGER_BIT == 0 {
        return X87Class::Nan;
    }

    X87Class::Finite(X87Finite {
        negative,
        exponent_bits,
        significand,
    })
}

fn x87_to_binary(class: X87Class) -> BinaryClass {
    match class {
        X87Class::Nan => BinaryClass::Nan,
        X87Class::Infinite { negative } => BinaryClass::Infinite { negative },
        X87Class::Zero { negative } => BinaryClass::Zero { negative },
        X87Class::Finite(finite) => {
            let unbiased = if finite.exponent_bits == 0 {
                1 - X87_EXP_BIAS
            } else {
                i32::from(finite.exponent_bits) - X87_EXP_BIAS
            };
            BinaryClass::Finite(BinaryFinite {
                negative: finite.negative,
                significand: finite.significand,
                exponent: unbiased - 63,
            })
        }
    }
}

fn f64_to_binary(x: f64) -> BinaryClass {
    let bits = x.to_bits();
    let negative = bits >> 63 != 0;
    let exponent_bits = ((bits >> 52) & 0x7ff) as u16;
    let fraction = bits & ((1u64 << 52) - 1);

    if exponent_bits == 0x7ff {
        return if fraction == 0 {
            BinaryClass::Infinite { negative }
        } else {
            BinaryClass::Nan
        };
    }
    if exponent_bits == 0 && fraction == 0 {
        return BinaryClass::Zero { negative };
    }
    let (significand, exponent) = if exponent_bits == 0 {
        (fraction, -1022 - 52)
    } else {
        (
            (1u64 << 52) | fraction,
            i32::from(exponent_bits) - 1023 - 52,
        )
    };
    BinaryClass::Finite(BinaryFinite {
        negative,
        significand,
        exponent,
    })
}

fn f32_to_binary(x: f32) -> BinaryClass {
    let bits = x.to_bits();
    let negative = bits >> 31 != 0;
    let exponent_bits = ((bits >> 23) & 0xff) as u16;
    let fraction = u64::from(bits & ((1u32 << 23) - 1));

    if exponent_bits == 0xff {
        return if fraction == 0 {
            BinaryClass::Infinite { negative }
        } else {
            BinaryClass::Nan
        };
    }
    if exponent_bits == 0 && fraction == 0 {
        return BinaryClass::Zero { negative };
    }
    let (significand, exponent) = if exponent_bits == 0 {
        (fraction, -126 - 23)
    } else {
        ((1u64 << 23) | fraction, i32::from(exponent_bits) - 127 - 23)
    };
    BinaryClass::Finite(BinaryFinite {
        negative,
        significand,
        exponent,
    })
}

fn cmp_positive_finite_magnitude(a: BinaryFinite, b: BinaryFinite) -> Ordering {
    let a_bits = 64 - a.significand.leading_zeros() as i32;
    let b_bits = 64 - b.significand.leading_zeros() as i32;
    let a_top = a.exponent + a_bits - 1;
    let b_top = b.exponent + b_bits - 1;
    if a_top != b_top {
        return a_top.cmp(&b_top);
    }

    match a.exponent.cmp(&b.exponent) {
        Ordering::Equal => a.significand.cmp(&b.significand),
        Ordering::Less => {
            let shift = (b.exponent - a.exponent) as u32;
            (a.significand as u128).cmp(&((b.significand as u128) << shift))
        }
        Ordering::Greater => {
            let shift = (a.exponent - b.exponent) as u32;
            ((a.significand as u128) << shift).cmp(&(b.significand as u128))
        }
    }
}

fn cmp_binary_finite(a: BinaryFinite, b: BinaryFinite) -> Ordering {
    if a.negative != b.negative {
        return if a.negative {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }

    let magnitude = cmp_positive_finite_magnitude(a, b);
    if a.negative {
        magnitude.reverse()
    } else {
        magnitude
    }
}

fn cmp_binary(a: BinaryClass, b: BinaryClass) -> Option<Ordering> {
    match (a, b) {
        (BinaryClass::Nan, _) | (_, BinaryClass::Nan) => None,
        (BinaryClass::Zero { .. }, BinaryClass::Zero { .. }) => Some(Ordering::Equal),
        (BinaryClass::Infinite { negative: an }, BinaryClass::Infinite { negative: bn }) => {
            Some(match (an, bn) {
                (true, true) | (false, false) => Ordering::Equal,
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
            })
        }
        (BinaryClass::Infinite { negative }, _) => Some(if negative {
            Ordering::Less
        } else {
            Ordering::Greater
        }),
        (_, BinaryClass::Infinite { negative }) => Some(if negative {
            Ordering::Greater
        } else {
            Ordering::Less
        }),
        (BinaryClass::Zero { .. }, BinaryClass::Finite(finite)) => Some(if finite.negative {
            Ordering::Greater
        } else {
            Ordering::Less
        }),
        (BinaryClass::Finite(finite), BinaryClass::Zero { .. }) => Some(if finite.negative {
            Ordering::Less
        } else {
            Ordering::Greater
        }),
        (BinaryClass::Finite(a), BinaryClass::Finite(b)) => Some(cmp_binary_finite(a, b)),
    }
}

fn equal_x87_zero_f64(y: X87Class, fallback: f64) -> f64 {
    match y {
        X87Class::Zero { negative } => {
            if negative {
                -0.0
            } else {
                0.0
            }
        }
        _ => fallback,
    }
}

fn equal_x87_zero_f32(y: X87Class, fallback: f32) -> f32 {
    match y {
        X87Class::Zero { negative } => {
            if negative {
                -0.0
            } else {
                0.0
            }
        }
        _ => fallback,
    }
}

fn x87_zero(negative: bool) -> [u8; X87_EXTENDED_LEN] {
    x87_pack(negative, 0, 0)
}

fn x87_infinity(negative: bool) -> [u8; X87_EXTENDED_LEN] {
    x87_pack(negative, X87_EXP_INF_NAN, X87_INTEGER_BIT)
}

fn x87_min_subnormal(negative: bool) -> [u8; X87_EXTENDED_LEN] {
    x87_pack(negative, 0, 1)
}

fn x87_max_finite(negative: bool) -> [u8; X87_EXTENDED_LEN] {
    x87_pack(negative, X87_EXP_INF_NAN - 1, u64::MAX)
}

fn x87_next_greater_magnitude(finite: X87Finite) -> [u8; X87_EXTENDED_LEN] {
    if finite.exponent_bits == 0 {
        if finite.significand < X87_INTEGER_BIT - 1 {
            return x87_pack(finite.negative, 0, finite.significand + 1);
        }
        return x87_pack(finite.negative, 1, X87_INTEGER_BIT);
    }

    if finite.exponent_bits == X87_EXP_INF_NAN - 1 && finite.significand == u64::MAX {
        return x87_infinity(finite.negative);
    }

    if finite.significand < u64::MAX {
        return x87_pack(
            finite.negative,
            finite.exponent_bits,
            finite.significand + 1,
        );
    }

    x87_pack(finite.negative, finite.exponent_bits + 1, X87_INTEGER_BIT)
}

fn x87_next_smaller_magnitude(finite: X87Finite) -> [u8; X87_EXTENDED_LEN] {
    if finite.exponent_bits == 0 {
        if finite.significand <= 1 {
            return x87_zero(finite.negative);
        }
        return x87_pack(finite.negative, 0, finite.significand - 1);
    }

    if finite.significand > X87_INTEGER_BIT {
        return x87_pack(
            finite.negative,
            finite.exponent_bits,
            finite.significand - 1,
        );
    }

    if finite.exponent_bits == 1 {
        return x87_pack(finite.negative, 0, X87_INTEGER_BIT - 1);
    }

    x87_pack(finite.negative, finite.exponent_bits - 1, u64::MAX)
}

fn x87_next_up(class: X87Class) -> [u8; X87_EXTENDED_LEN] {
    match class {
        X87Class::Nan => x87_pack(false, X87_EXP_INF_NAN, X87_INTEGER_BIT | 1),
        X87Class::Infinite { negative: true } => x87_max_finite(true),
        X87Class::Infinite { negative: false } => x87_infinity(false),
        X87Class::Zero { .. } => x87_min_subnormal(false),
        X87Class::Finite(finite) if finite.negative => x87_next_smaller_magnitude(finite),
        X87Class::Finite(finite) => x87_next_greater_magnitude(finite),
    }
}

fn x87_next_down(class: X87Class) -> [u8; X87_EXTENDED_LEN] {
    match class {
        X87Class::Nan => x87_pack(false, X87_EXP_INF_NAN, X87_INTEGER_BIT | 1),
        X87Class::Infinite { negative: true } => x87_infinity(true),
        X87Class::Infinite { negative: false } => x87_max_finite(false),
        X87Class::Zero { .. } => x87_min_subnormal(true),
        X87Class::Finite(finite) if finite.negative => x87_next_greater_magnitude(finite),
        X87Class::Finite(finite) => x87_next_smaller_magnitude(finite),
    }
}

/// Return the next representable `f64` after `x` toward an x86 80-bit
/// `long double` direction slot.
#[inline]
pub fn nexttoward_long_double_bits(x: f64, y: [u8; X87_EXTENDED_LEN]) -> f64 {
    let y_class = x87_classify(y);
    let Some(order) = cmp_binary(f64_to_binary(x), x87_to_binary(y_class)) else {
        return f64::NAN;
    };
    match order {
        Ordering::Less => libm::nextafter(x, f64::INFINITY),
        Ordering::Equal => equal_x87_zero_f64(y_class, x),
        Ordering::Greater => libm::nextafter(x, f64::NEG_INFINITY),
    }
}

/// Return the next representable `f32` after `x` toward an x86 80-bit
/// `long double` direction slot.
#[inline]
pub fn nexttowardf_long_double_bits(x: f32, y: [u8; X87_EXTENDED_LEN]) -> f32 {
    let y_class = x87_classify(y);
    let Some(order) = cmp_binary(f32_to_binary(x), x87_to_binary(y_class)) else {
        return f32::NAN;
    };
    match order {
        Ordering::Less => libm::nextafterf(x, f32::INFINITY),
        Ordering::Equal => equal_x87_zero_f32(y_class, x),
        Ordering::Greater => libm::nextafterf(x, f32::NEG_INFINITY),
    }
}

/// Return the next representable x86 80-bit `long double` after `x` toward
/// `y`, with both operands and the result represented as their 16-byte SysV
/// stack slots.
#[inline]
pub fn nexttowardl_long_double_bits(
    x: [u8; X87_EXTENDED_LEN],
    y: [u8; X87_EXTENDED_LEN],
) -> [u8; X87_EXTENDED_LEN] {
    let x_class = x87_classify(x);
    let y_class = x87_classify(y);
    if matches!(x_class, X87Class::Nan) {
        return x;
    }
    if matches!(y_class, X87Class::Nan) {
        return y;
    }

    let Some(order) = cmp_binary(x87_to_binary(x_class), x87_to_binary(y_class)) else {
        return x87_pack(false, X87_EXP_INF_NAN, X87_INTEGER_BIT | 1);
    };

    match order {
        Ordering::Less => x87_next_up(x_class),
        Ordering::Equal => y,
        Ordering::Greater => x87_next_down(x_class),
    }
}

/// Extract unbiased exponent as `i32` (FP_ILOGBNAN / FP_ILOGB0 for special values).
#[inline]
pub fn ilogb(x: f64) -> i32 {
    libm::ilogb(x)
}

/// Extract unbiased exponent as `f64`.
#[inline]
pub fn logb(x: f64) -> f64 {
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return f64::INFINITY;
    }
    if x.is_nan() {
        return x;
    }
    libm::ilogb(x) as f64
}

/// IEEE remainder with quotient: `x - n*y` where `n` is the integer nearest `x/y`.
/// Returns `(remainder, quotient_low_bits)` where quotient retains at least 3 low bits.
#[inline]
pub fn remquo(x: f64, y: f64) -> (f64, i32) {
    libm::remquo(x, y)
}

/// Compute sine and cosine simultaneously.
/// Returns `(sin(x), cos(x))`.
#[inline]
pub fn sincos(x: f64) -> (f64, f64) {
    libm::sincos(x)
}

/// Parse a `nan()` tag string into a mantissa payload, matching glibc:
/// the tag is read as a base-0 integer (`0x` hex, leading `0` octal, else
/// decimal) and is only used when it consumes the *entire* tag; any other
/// tag (empty, non-numeric, trailing junk) yields a payload of 0.
fn nan_payload(tag: &[u8]) -> u64 {
    if tag.is_empty() {
        return 0;
    }
    let (digits, base): (&[u8], u64) =
        if let Some(rest) = tag.strip_prefix(b"0x").or_else(|| tag.strip_prefix(b"0X")) {
            (rest, 16)
        } else if tag.len() > 1 && tag[0] == b'0' {
            (&tag[1..], 8)
        } else {
            (tag, 10)
        };
    if digits.is_empty() {
        return 0;
    }
    let mut acc: u64 = 0;
    for &b in digits {
        let d = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return 0, // non-numeric tail → glibc uses payload 0
        };
        if d >= base {
            return 0;
        }
        acc = acc.wrapping_mul(base).wrapping_add(d);
    }
    acc
}

/// Generate a quiet NaN, encoding the `tag` payload like C `nan(tagp)`
/// (equivalent to `strtod("NAN(tag)", NULL)`): `nan(b"1")` yields the bit
/// pattern `0x7ff8000000000001`, distinct from `nan(b"")`.
#[inline]
pub fn nan(tag: &[u8]) -> f64 {
    // Quiet NaN: exponent all-ones + the quiet bit (mantissa bit 51).
    const QUIET_NAN: u64 = 0x7ff8_0000_0000_0000;
    // The tag payload occupies mantissa bits 0..=50.
    const PAYLOAD_MASK: u64 = 0x0007_ffff_ffff_ffff;
    f64::from_bits(QUIET_NAN | (nan_payload(tag) & PAYLOAD_MASK))
}

/// BSD/SUSv2 `finite()`: returns non-zero if `x` is neither infinite nor NaN.
#[inline]
pub fn finite(x: f64) -> i32 {
    if x.is_finite() { 1 } else { 0 }
}

/// BSD `drem()` — alias for `remainder()`.
#[inline]
pub fn drem(x: f64, y: f64) -> f64 {
    remainder(x, y)
}

/// BSD `gamma()` — alias for `lgamma()`.
/// In glibc, `gamma` is equivalent to `lgamma` (the log of the absolute value
/// of the Gamma function).
#[inline]
pub fn gamma(x: f64) -> f64 {
    libm::lgamma(x)
}

/// Extract the significand (mantissa) of `x` scaled to `[1, 2)`.
///
/// Returns `x * 2^(-ilogb(x))`, or equivalently `scalbn(x, -ilogb(x))`.
#[inline]
pub fn significand(x: f64) -> f64 {
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return x;
    }
    let e = libm::ilogb(x);
    libm::scalbn(x, -e)
}

/// GNU extension: base-10 exponential `10^x`.
#[inline]
pub fn exp10(x: f64) -> f64 {
    // Integer exponents in [-22, 22] yield powers of ten that are exactly
    // representable in f64; `powi` returns them exactly. `exp(x * ln10)`
    // double-rounds (the product and the exp each round), so e.g. exp10(3)
    // would come out as 1000.0000000000007 — glibc returns exactly 1000.0.
    if x.is_finite() && x == x.trunc() && (-22.0..=22.0).contains(&x) {
        return 10.0_f64.powi(x as i32);
    }
    // 10^x = exp(x * ln(10)) for non-integer / out-of-range exponents.
    libm::exp(x * core::f64::consts::LN_10)
}

// ---------------------------------------------------------------------------
// IEEE 754 classification helpers (glibc __fpclassify, __signbit, etc.)
// ---------------------------------------------------------------------------

/// FP_NAN, FP_INFINITE, FP_ZERO, FP_SUBNORMAL, FP_NORMAL constants
/// matching glibc's <math.h> definitions.
pub const FP_NAN: i32 = 0;
pub const FP_INFINITE: i32 = 1;
pub const FP_ZERO: i32 = 2;
pub const FP_SUBNORMAL: i32 = 3;
pub const FP_NORMAL: i32 = 4;

/// Classify a double-precision float (glibc `__fpclassify`).
#[inline]
pub fn fpclassify(x: f64) -> i32 {
    if x.is_nan() {
        FP_NAN
    } else if x.is_infinite() {
        FP_INFINITE
    } else if x == 0.0 {
        FP_ZERO
    } else if x.is_subnormal() {
        FP_SUBNORMAL
    } else {
        FP_NORMAL
    }
}

/// Return non-zero if sign bit is set (glibc `__signbit`).
#[inline]
pub fn signbit(x: f64) -> i32 {
    if x.is_sign_negative() { 1 } else { 0 }
}

/// Return non-zero if `x` is infinite (glibc `__isinf`).
///
/// Returns +1 for +Inf, -1 for -Inf, 0 otherwise.
#[inline]
pub fn isinf(x: f64) -> i32 {
    if x == f64::INFINITY {
        1
    } else if x == f64::NEG_INFINITY {
        -1
    } else {
        0
    }
}

/// Return non-zero if `x` is NaN (glibc `__isnan`).
#[inline]
pub fn isnan(x: f64) -> i32 {
    if x.is_nan() { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_sanity() {
        assert_eq!(fabs(-3.5), 3.5);
        assert_eq!(ceil(2.1), 3.0);
        assert_eq!(floor(2.9), 2.0);
        assert_eq!(round(2.5), 3.0);
        assert_eq!(trunc(-2.9), -2.0);
        assert_eq!(rint(2.0), 2.0);
        assert!((fmod(5.5, 2.0) - 1.5).abs() < 1e-12);
        assert!((remainder(5.3, 2.0) + 0.7).abs() < 1e-12);
        let signed = copysign(3.0, -0.0);
        assert_eq!(signed, -3.0);
        assert!(signed.is_sign_negative());
        assert_eq!(sqrt(9.0), 3.0);
        assert_eq!(cbrt(27.0), 3.0);
        assert_eq!(cbrt(-8.0), -2.0);
        assert!((hypot(3.0, 4.0) - 5.0).abs() < 1e-12);
    }

    #[test]
    fn test_nearbyint() {
        assert_eq!(nearbyint(2.3), 2.0);
        assert_eq!(nearbyint(2.7), 3.0);
        assert_eq!(nearbyint(-2.5), -2.0); // banker's rounding
    }

    #[test]
    fn test_lrint_llrint() {
        assert_eq!(lrint(2.7), 3);
        assert_eq!(lrint(-2.3), -2);
        assert_eq!(llrint(2.7), 3);
        assert_eq!(llrint(-2.3), -2);
    }

    #[test]
    fn test_lround_llround() {
        assert_eq!(lround(2.5), 3);
        assert_eq!(lround(-2.5), -3);
        assert_eq!(llround(2.5), 3);
        assert_eq!(llround(-2.5), -3);
    }

    #[test]
    fn test_ldexp() {
        assert_eq!(ldexp(1.0, 10), 1024.0);
        assert_eq!(ldexp(3.0, 2), 12.0);
    }

    #[test]
    fn test_frexp() {
        let (m, e) = frexp(12.0);
        assert!((m - 0.75).abs() < 1e-12);
        assert_eq!(e, 4);
    }

    #[test]
    fn test_modf() {
        let (frac, int) = modf(3.75);
        assert!((int - 3.0).abs() < 1e-12);
        assert!((frac - 0.75).abs() < 1e-12);
    }

    #[test]
    fn test_fmin_fmax() {
        assert_eq!(fmin(2.0, 3.0), 2.0);
        assert_eq!(fmax(2.0, 3.0), 3.0);
        // NaN semantics: fmin/fmax return the non-NaN arg
        assert_eq!(fmin(f64::NAN, 3.0), 3.0);
        assert_eq!(fmax(f64::NAN, 3.0), 3.0);
    }

    #[test]
    fn test_fdim() {
        assert_eq!(fdim(4.0, 2.0), 2.0);
        assert_eq!(fdim(2.0, 4.0), 0.0);
    }

    #[test]
    fn test_fma() {
        assert!((fma(2.0, 3.0, 4.0) - 10.0).abs() < 1e-12);
    }

    #[test]
    fn test_scalbn() {
        assert_eq!(scalbn(1.0, 10), 1024.0);
        assert_eq!(scalbln(1.0, 10), 1024.0);
    }

    #[test]
    fn test_nextafter() {
        let next = nextafter(1.0, 2.0);
        assert!(next > 1.0);
        assert!(next < 1.0 + 1e-15);
    }

    #[test]
    fn test_nexttoward() {
        // nexttoward behaves like nextafter for f64 direction
        let nt = nexttoward(1.0, 2.0);
        let na = nextafter(1.0, 2.0);
        assert_eq!(nt, na);
        // Equal values: return x unchanged
        assert_eq!(nexttoward(1.0, 1.0), 1.0);
        // NaN propagation
        assert!(nexttoward(f64::NAN, 1.0).is_nan());
        assert!(nexttoward(1.0, f64::NAN).is_nan());
        // Step toward negative
        let down = nexttoward(1.0, 0.0);
        assert!(down < 1.0);
    }

    #[test]
    fn test_nexttoward_long_double_bits_preserves_sub_f64_direction() {
        let one_plus_tiny = x87_pack(false, X87_EXP_BIAS as u16, X87_INTEGER_BIT | 1);
        let one_minus_tiny = x87_pack(false, (X87_EXP_BIAS - 1) as u16, u64::MAX);

        assert_eq!(
            nexttoward_long_double_bits(1.0, one_plus_tiny),
            nextafter(1.0, f64::INFINITY)
        );
        assert_eq!(
            nexttoward_long_double_bits(1.0, one_minus_tiny),
            nextafter(1.0, f64::NEG_INFINITY)
        );
        assert_eq!(
            nexttowardf_long_double_bits(1.0, one_plus_tiny),
            libm::nextafterf(1.0, f32::INFINITY)
        );
    }

    #[test]
    fn test_nexttoward_long_double_bits_preserves_signed_zero_equality() {
        let negative_zero = x87_pack(true, 0, 0);
        assert_eq!(
            nexttoward_long_double_bits(0.0, negative_zero).to_bits(),
            (-0.0f64).to_bits()
        );
        assert_eq!(
            nexttowardf_long_double_bits(0.0, negative_zero).to_bits(),
            (-0.0f32).to_bits()
        );
    }

    #[test]
    fn test_nexttowardl_long_double_bits_steps_extended_precision() {
        let one = x87_pack(false, X87_EXP_BIAS as u16, X87_INTEGER_BIT);
        let one_plus_one_ulp = x87_pack(false, X87_EXP_BIAS as u16, X87_INTEGER_BIT | 1);
        let one_plus_two_ulps = x87_pack(false, X87_EXP_BIAS as u16, X87_INTEGER_BIT | 2);

        assert_eq!(
            nexttowardl_long_double_bits(one, one_plus_two_ulps),
            one_plus_one_ulp
        );
        assert_eq!(nexttowardl_long_double_bits(one_plus_one_ulp, one), one);
    }

    #[test]
    fn test_nexttowardl_long_double_bits_preserves_zero_sign_direction() {
        let positive_zero = x87_pack(false, 0, 0);
        let negative_zero = x87_pack(true, 0, 0);
        let positive_min = x87_pack(false, 0, 1);
        let negative_min = x87_pack(true, 0, 1);

        assert_eq!(
            nexttowardl_long_double_bits(positive_zero, positive_min),
            positive_min
        );
        assert_eq!(
            nexttowardl_long_double_bits(positive_zero, negative_min),
            negative_min
        );
        assert_eq!(
            nexttowardl_long_double_bits(positive_zero, negative_zero),
            negative_zero
        );
    }

    #[test]
    fn test_ilogb_logb() {
        assert_eq!(ilogb(8.0), 3);
        assert_eq!(logb(8.0), 3.0);
        assert_eq!(ilogb(1.0), 0);
    }

    #[test]
    fn test_remquo() {
        let (rem, quo) = remquo(10.0, 3.0);
        // 10 / 3 ~ 3.333, nearest integer = 3, remainder = 10 - 3*3 = 1
        assert!((rem - 1.0).abs() < 1e-12);
        assert_eq!(quo & 0x7, 3 & 0x7);
    }

    #[test]
    fn test_sincos() {
        let (s, c) = sincos(0.0);
        assert!((s - 0.0).abs() < 1e-12);
        assert!((c - 1.0).abs() < 1e-12);
        let (s2, c2) = sincos(core::f64::consts::FRAC_PI_2);
        assert!((s2 - 1.0).abs() < 1e-12);
        assert!(c2.abs() < 1e-12);
    }

    #[test]
    fn test_nan() {
        assert!(nan(b"").is_nan());
        assert!(nan(b"1").is_nan());
        // The tag payload is encoded into the low mantissa bits (glibc parity).
        assert_eq!(nan(b"").to_bits(), 0x7ff8_0000_0000_0000);
        assert_eq!(nan(b"1").to_bits(), 0x7ff8_0000_0000_0001);
        assert_eq!(nan(b"255").to_bits(), 0x7ff8_0000_0000_00ff);
        assert_eq!(nan(b"0x1ff").to_bits(), 0x7ff8_0000_0000_01ff);
        assert_eq!(nan(b"010").to_bits(), 0x7ff8_0000_0000_0008); // octal
        // Non-numeric or malformed tags fall back to a zero payload.
        assert_eq!(nan(b"abc").to_bits(), 0x7ff8_0000_0000_0000);
        assert_eq!(nan(b"12x").to_bits(), 0x7ff8_0000_0000_0000);
    }

    #[test]
    fn test_finite_fn() {
        assert_eq!(finite(1.0), 1);
        assert_eq!(finite(f64::INFINITY), 0);
        assert_eq!(finite(f64::NEG_INFINITY), 0);
        assert_eq!(finite(f64::NAN), 0);
        assert_eq!(finite(0.0), 1);
    }

    #[test]
    fn test_drem() {
        // drem is alias for remainder
        let r1 = drem(5.3, 2.0);
        let r2 = remainder(5.3, 2.0);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_gamma_alias() {
        // gamma() is alias for lgamma()
        assert!((gamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
    }

    #[test]
    fn test_significand() {
        // significand(x) = x * 2^(-ilogb(x)), result in [1, 2)
        let s = significand(12.0);
        assert!((s - 1.5).abs() < 1e-12); // 12 = 1.5 * 2^3
        assert_eq!(significand(0.0), 0.0);
        assert!(significand(f64::NAN).is_nan());
        assert!(significand(f64::INFINITY).is_infinite());
    }

    #[test]
    fn test_exp10() {
        // Integer exponents yield exact powers of ten (glibc parity) — not
        // the double-rounded 1000.0000000000007 that exp(x*ln10) produces.
        assert_eq!(exp10(0.0), 1.0);
        assert_eq!(exp10(1.0), 10.0);
        assert_eq!(exp10(2.0), 100.0);
        assert_eq!(exp10(3.0), 1000.0);
        assert_eq!(exp10(22.0), 1e22);
        assert_eq!(exp10(-1.0), 0.1);
        assert_eq!(exp10(-3.0), 0.001);
        // Non-integer exponents take the transcendental path.
        assert!((exp10(0.5) - 10.0_f64.sqrt()).abs() < 1e-12);
        // Out-of-fast-path-range integers still behave sanely.
        assert!(exp10(400.0).is_infinite());
        assert_eq!(exp10(-400.0), 0.0);
    }

    #[test]
    fn test_fpclassify() {
        assert_eq!(fpclassify(1.0), FP_NORMAL);
        assert_eq!(fpclassify(0.0), FP_ZERO);
        assert_eq!(fpclassify(-0.0), FP_ZERO);
        assert_eq!(fpclassify(f64::INFINITY), FP_INFINITE);
        assert_eq!(fpclassify(f64::NEG_INFINITY), FP_INFINITE);
        assert_eq!(fpclassify(f64::NAN), FP_NAN);
        assert_eq!(fpclassify(5e-324), FP_SUBNORMAL); // smallest positive subnormal
    }

    #[test]
    fn test_signbit() {
        assert_eq!(signbit(1.0), 0);
        assert_eq!(signbit(-1.0), 1);
        assert_eq!(signbit(0.0), 0);
        assert_eq!(signbit(-0.0), 1);
        assert_eq!(signbit(f64::INFINITY), 0);
        assert_eq!(signbit(f64::NEG_INFINITY), 1);
    }

    #[test]
    fn test_isinf() {
        assert_eq!(isinf(f64::INFINITY), 1);
        assert_eq!(isinf(f64::NEG_INFINITY), -1);
        assert_eq!(isinf(0.0), 0);
        assert_eq!(isinf(f64::NAN), 0);
        assert_eq!(isinf(1.0), 0);
    }

    #[test]
    fn test_isnan() {
        assert_eq!(isnan(f64::NAN), 1);
        assert_eq!(isnan(0.0), 0);
        assert_eq!(isnan(f64::INFINITY), 0);
        assert_eq!(isnan(1.0), 0);
    }

    #[test]
    fn test_pow_ieee_special_cases() {
        use crate::math::pow;
        // IEEE 754 special cases for pow
        assert_eq!(pow(0.0, 0.0), 1.0);
        assert_eq!(pow(-1.0, f64::INFINITY), 1.0);
        assert_eq!(pow(-1.0, f64::NEG_INFINITY), 1.0);
        assert_eq!(pow(1.0, f64::NAN), 1.0);
        assert_eq!(pow(f64::NAN, 0.0), 1.0);
        // Basic sanity
        assert!((pow(2.0, 10.0) - 1024.0).abs() < 1e-12);
        assert!((pow(10.0, -1.0) - 0.1).abs() < 1e-12);
    }

    #[test]
    fn test_hypot_ieee_special_cases() {
        // hypot(inf, x) = inf even if x is NaN
        assert_eq!(hypot(f64::INFINITY, f64::NAN), f64::INFINITY);
        assert_eq!(hypot(f64::NAN, f64::INFINITY), f64::INFINITY);
        assert_eq!(hypot(f64::NEG_INFINITY, f64::NAN), f64::INFINITY);
        // hypot with finite NaN returns NaN
        assert!(hypot(f64::NAN, 1.0).is_nan());
        assert!(hypot(1.0, f64::NAN).is_nan());
        // Basic sanity
        assert!((hypot(3.0, 4.0) - 5.0).abs() < 1e-12);
    }

    #[test]
    fn test_rint_bankers_rounding() {
        // Banker's rounding (round to even on ties)
        assert_eq!(rint(0.5), 0.0); // 0.5 rounds to 0 (even)
        assert_eq!(rint(1.5), 2.0); // 1.5 rounds to 2 (even)
        assert_eq!(rint(2.5), 2.0); // 2.5 rounds to 2 (even)
        assert_eq!(rint(3.5), 4.0); // 3.5 rounds to 4 (even)
        assert_eq!(rint(-0.5), -0.0); // -0.5 rounds to -0 (even)
        assert_eq!(rint(-1.5), -2.0); // -1.5 rounds to -2 (even)
    }

    // ===== glibc parity tests =====
    // Verified against glibc via scripts/c_probes/probe_math_edge.c

    #[test]
    fn glibc_round_ties_to_away() {
        // round() ties to away from zero, not to even
        assert_eq!(round(2.5), 3.0);
        assert_eq!(round(-2.5), -3.0);
        assert_eq!(round(2.4), 2.0);
        assert_eq!(round(-2.4), -2.0);
    }

    #[test]
    fn glibc_floor_ceil_negative() {
        // floor(-3.7) = -4.0, ceil(-3.3) = -3.0
        assert_eq!(floor(3.7), 3.0);
        assert_eq!(floor(-3.7), -4.0);
        assert_eq!(ceil(3.3), 4.0);
        assert_eq!(ceil(-3.3), -3.0);
    }

    #[test]
    fn glibc_trunc_toward_zero() {
        // trunc always toward zero
        assert_eq!(trunc(3.7), 3.0);
        assert_eq!(trunc(-3.7), -3.0);
    }

    #[test]
    fn glibc_fabs_clears_sign_bit() {
        assert_eq!(fabs(-3.14), 3.14);
        assert_eq!(fabs(3.14), 3.14);
        // fabs(-0.0) = 0.0 (sign bit cleared)
        assert_eq!(fabs(-0.0), 0.0);
        assert_eq!(signbit(fabs(-0.0)), 0);
    }

    #[test]
    fn glibc_sqrt_negative_is_nan() {
        assert!(sqrt(-1.0).is_nan());
    }

    #[test]
    fn glibc_cbrt_handles_negative() {
        // cbrt(-8.0) = -2.0 (unlike sqrt)
        assert!((cbrt(8.0) - 2.0).abs() < 1e-12);
        assert!((cbrt(-8.0) - (-2.0)).abs() < 1e-12);
        assert_eq!(cbrt(0.0), 0.0);
    }

    #[test]
    fn glibc_copysign_transfers_sign() {
        assert_eq!(copysign(3.0, -1.0), -3.0);
        assert_eq!(copysign(-3.0, 1.0), 3.0);
    }

    #[test]
    fn glibc_signbit_negative_zero() {
        // signbit(-0.0) = 1
        assert_eq!(signbit(-0.0), 1);
        assert_eq!(signbit(0.0), 0);
        assert_eq!(signbit(f64::NEG_INFINITY), 1);
    }

    #[test]
    fn glibc_isinf_returns_sign() {
        // isinf(INFINITY) = 1, isinf(-INFINITY) = -1
        assert_eq!(isinf(f64::INFINITY), 1);
        assert_eq!(isinf(f64::NEG_INFINITY), -1);
        assert_eq!(isinf(0.0), 0);
        assert_eq!(isinf(f64::NAN), 0);
    }

    #[test]
    fn glibc_fmod_sign_follows_dividend() {
        // fmod(-5.0, 3.0) = -2.0 (sign follows dividend)
        assert!((fmod(5.0, 3.0) - 2.0).abs() < 1e-12);
        assert!((fmod(-5.0, 3.0) - (-2.0)).abs() < 1e-12);
    }

    #[test]
    fn glibc_hypot_inf_dominates_nan() {
        // hypot(INFINITY, NAN) = INFINITY
        assert_eq!(hypot(f64::INFINITY, f64::NAN), f64::INFINITY);
        assert_eq!(hypot(f64::NAN, f64::INFINITY), f64::INFINITY);
    }
}
