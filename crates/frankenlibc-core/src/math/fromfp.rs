//! C23 floating-return `fromfp` rounding, without floating-point side effects.
//!
//! Unlike the older TS 18661 integer-return ABI, the result is not limited by
//! `intmax_t`. Work on the representation so rounding neither consults the
//! ambient fenv nor accidentally raises FE_INEXACT (the ABI layer owns flags).
//! Contract: GNU C Library manual 2.43, "Rounding Functions" / ISO C23 fromfp.

/// Supported storage formats; x87 padding above bit 79 is ignored.
#[derive(Clone, Copy, Debug)]
pub enum Format {
    Binary32,
    Binary64,
    Binary128,
    Extended80,
}

/// An integral floating representation, or a quiet NaN on a domain error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rounded {
    pub bits: u128,
    pub invalid: bool,
    /// True only for an in-range result differing numerically from the input.
    pub inexact: bool,
}

/// Round to the signed/unsigned integer range of `width` bits, retaining the
/// input floating format. Directions are FP_INT_UPWARD=0, DOWNWARD=1,
/// TOWARDZERO=2, TONEARESTFROMZERO=3 and TONEAREST=4.
/// Invalid direction arguments are rejected rather than silently using fenv.
pub fn round_to_width(
    bits: u128,
    format: Format,
    direction: i32,
    width: u32,
    unsigned: bool,
) -> Rounded {
    let (bits, fraction_bits, exponent_bits) = match format {
        Format::Binary32 => (bits & u128::from(u32::MAX), 23, 8),
        Format::Binary64 => (bits & u128::from(u64::MAX), 52, 11),
        Format::Binary128 => (bits, 112, 15),
        Format::Extended80 => {
            let exponent = (bits >> 64) & 0x7fff;
            let integer_bit = (bits >> 63) & 1;
            if exponent != 0 && integer_bit == 0 {
                // x87 unnormal/pseudo-special encodings are not numbers.
                return Rounded {
                    bits: (0x7fffu128 << 64) | (3u128 << 62),
                    invalid: true,
                    inexact: false,
                };
            }
            // Every binary80 value embeds exactly in binary128. Canonicalize
            // pseudo-denormals: exponent 0 with J=1 denotes exponent 1.
            let exponent = if exponent == 0 { integer_bit } else { exponent };
            let fraction = bits & ((1u128 << 63) - 1);
            let binary128 = ((bits >> 79) & 1) << 127 | exponent << 112 | fraction << 49;
            let mut result = round_binary(binary128, 112, 15, direction, width, unsigned);
            let exponent = (result.bits >> 112) & 0x7fff;
            result.bits = ((result.bits >> 127) << 79)
                | (exponent << 64)
                | (u128::from(exponent != 0) << 63)
                | ((result.bits & ((1u128 << 112) - 1)) >> 49);
            return result;
        }
    };
    round_binary(bits, fraction_bits, exponent_bits, direction, width, unsigned)
}

fn round_binary(
    bits: u128,
    fraction_bits: u32,
    exponent_bits: u32,
    direction: i32,
    width: u32,
    unsigned: bool,
) -> Rounded {
    let exponent_mask = (1u128 << exponent_bits) - 1;
    let fraction_mask = (1u128 << fraction_bits) - 1;
    let sign = bits & (1u128 << (fraction_bits + exponent_bits));
    let magnitude = bits ^ sign;
    let exponent = (magnitude >> fraction_bits) & exponent_mask;
    let bias = (1i32 << (exponent_bits - 1)) - 1;
    let invalid = || Rounded {
        bits: (exponent_mask << fraction_bits) | (1u128 << (fraction_bits - 1)),
        invalid: true,
        inexact: false,
    };
    if exponent == exponent_mask || width == 0 || !(0..=4).contains(&direction) {
        return invalid();
    }
    if magnitude == 0 {
        return Rounded { bits, invalid: false, inexact: false };
    }
    let power = if exponent == 0 { 1 - bias } else { exponent as i32 - bias };
    let rounded;
    let inexact;
    if power < 0 {
        let away = match direction {
            0 => sign == 0,
            1 => sign != 0,
            2 => false,
            3 => power == -1,
            4 => power == -1 && (magnitude & fraction_mask) != 0,
            _ => unreachable!(),
        };
        rounded = if away { (bias as u128) << fraction_bits } else { 0 };
        inexact = true;
    } else if power < fraction_bits as i32 {
        let shift = fraction_bits - power as u32;
        let unit = 1u128 << shift;
        let fraction = magnitude & (unit - 1);
        let truncated = magnitude & !(unit - 1);
        let half = unit >> 1;
        let away = fraction != 0 && match direction {
            0 => sign == 0,
            1 => sign != 0,
            2 => false,
            3 => fraction >= half,
            // At power=0 the unit bit is the implicit leading 1, not
            // necessarily bit 0 of the biased exponent field.
            4 => fraction > half || (fraction == half
                && (power == 0 || (truncated & unit) != 0)),
            _ => unreachable!(),
        };
        rounded = truncated + if away { unit } else { 0 };
        inexact = fraction != 0;
    } else {
        rounded = magnitude;
        inexact = false;
    }
    if rounded != 0 {
        let power = ((rounded >> fraction_bits) & exponent_mask) as i32 - bias;
        let limit = if unsigned { width } else { width - 1 };
        if (unsigned && sign != 0)
            || power as u32 > limit
            || (power as u32 == limit
                && (unsigned || sign == 0 || rounded & fraction_mask != 0))
        {
            return invalid();
        }
    }
    Rounded { bits: rounded | sign, invalid: false, inexact }
}

#[cfg(test)]
mod tests {
    use super::{Format, Rounded, round_to_width};

    fn round(x: f64, dir: i32, width: u32, unsigned: bool) -> Rounded {
        round_to_width(u128::from(x.to_bits()), Format::Binary64, dir, width, unsigned)
    }

    #[test]
    fn all_directions_and_ties() {
        let cases = [
            (7.5, [8.0, 7.0, 7.0, 8.0, 8.0]),
            (6.5, [7.0, 6.0, 6.0, 7.0, 6.0]),
            (-7.5, [-7.0, -8.0, -7.0, -8.0, -8.0]),
            (-6.5, [-6.0, -7.0, -6.0, -7.0, -6.0]),
            (1.5, [2.0, 1.0, 1.0, 2.0, 2.0]),
            (0.5, [1.0, 0.0, 0.0, 1.0, 0.0]),
        ];
        for (input, outputs) in cases {
            for (dir, expected) in outputs.into_iter().enumerate() {
                let result = round(input, dir as i32, 16, false);
                assert!(!result.invalid);
                assert!(result.inexact);
                assert_eq!(f64::from_bits(result.bits as u64), expected);
            }
        }
    }

    #[test]
    fn signed_and_unsigned_width_boundaries() {
        for width in 1..=64 {
            let bound = f64::from_bits(u64::from(1023 + width - 1) << 52);
            assert!(!round(-bound, 2, width, false).invalid);
            assert!(round(bound, 2, width, false).invalid);
            assert!(!round(bound, 2, width, true).invalid);
            assert!(round(-bound, 2, width, true).invalid);
        }
        assert!(round(127.5, 4, 8, false).invalid);
        assert!(!round(127.5, 2, 8, false).invalid);
        assert!(!round(-128.5, 4, 8, false).invalid);
        assert!(round(-128.5, 3, 8, false).invalid);
        assert!(!round(-0.25, 2, 1, true).invalid);
        assert!(round(-0.25, 1, 1, true).invalid);
    }

    #[test]
    fn arbitrary_width_does_not_saturate_at_intmax() {
        let big = f64::from_bits((1023 + 100) << 52);
        assert_eq!(round(big, 4, 102, false).bits, u128::from(big.to_bits()));
        assert!(round(big, 4, 100, true).invalid);
        assert!(!round(f64::MAX, 4, u32::MAX, false).invalid);
        let big128 = (16383u128 + 16000) << 112 | 123;
        let result = round_to_width(big128, Format::Binary128, 4, 16002, false);
        assert_eq!(result, Rounded { bits: big128, invalid: false, inexact: false });
    }

    #[test]
    fn invalid_and_exact_results_never_request_inexact() {
        for x in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            let r = round(x, 2, 64, false);
            assert!(r.invalid && !r.inexact);
            assert!(f64::from_bits(r.bits as u64).is_nan());
        }
        assert!(round(0.0, 2, 0, false).invalid);
        assert!(round(1.25, 5, 8, false).invalid);
        assert!(!round(2.0, 2, 8, false).inexact);
        assert!(!round(127.5, 4, 8, false).inexact);
        assert_eq!(round(-0.0, 4, 8, true).bits, u128::from((-0.0f64).to_bits()));
    }

    #[test]
    fn subnormals_round_without_float_operations() {
        for (format, sign, one) in [
            (Format::Binary32, 1u128 << 31, 127u128 << 23),
            (Format::Binary64, 1u128 << 63, 1023u128 << 52),
            (Format::Binary128, 1u128 << 127, 16383u128 << 112),
        ] {
            assert_eq!(round_to_width(1, format, 0, 2, false).bits, one);
            assert_eq!(round_to_width(1 | sign, format, 1, 2, false).bits, one | sign);
            assert_eq!(round_to_width(1, format, 4, 2, false).bits, 0);
        }
    }

    #[test]
    fn binary80_preserves_precision_and_rejects_unnormals() {
        let one = (16383u128 << 64) | (1u128 << 63);
        let one_and_half = one | (1u128 << 62);
        let two = (16384u128 << 64) | (1u128 << 63);
        assert_eq!(round_to_width(one_and_half, Format::Extended80, 4, 3, false).bits, two);
        assert_eq!(round_to_width(one, Format::Extended80, 4, 3, false).bits, one);
        assert!(round_to_width(16383u128 << 64, Format::Extended80, 4, 3, false).invalid);
        // The least pseudo-denormal and its canonical encoding denote the
        // same tiny positive value, and upward rounding must produce one.
        assert_eq!(round_to_width(1u128 << 63, Format::Extended80, 0, 3, false).bits, one);
        let big = ((16383u128 + 63) << 64) | (1u128 << 63) | 1;
        assert_eq!(round_to_width(big, Format::Extended80, 4, 65, false).bits, big);
    }
}
