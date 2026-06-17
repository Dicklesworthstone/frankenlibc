//! Exact decimal expansion of IEEE-754 binary128 (`_Float128`) values.
//!
//! A binary128 value is a dyadic rational `m · 2^E`, which therefore has a
//! *finite* exact decimal expansion. This module produces that exact
//! significand-digit string and its base-10 exponent with **no rounding**,
//! using a minimal big-integer. It is the foundation for a byte-exact
//! `strfromf128` formatter (bd-trosmi): the rounding and `%a/%e/%f/%g` format
//! assembly are layered on top of this exact decomposition by the caller.
//!
//! The exported function takes the raw 128-bit pattern (`u128`) rather than a
//! `f128`, so it needs no nightly `f128` feature and can be unit-tested against
//! exact reference values independent of argument-passing ABI concerns.

/// A minimal big unsigned integer: base-2^32, little-endian limbs, with no
/// trailing zero limbs (the value zero is the empty limb vector).
#[derive(Clone)]
struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    fn from_u128(mut v: u128) -> Self {
        let mut limbs = Vec::new();
        while v != 0 {
            limbs.push((v & 0xffff_ffff) as u32);
            v >>= 32;
        }
        BigUint { limbs }
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// `self << bits`.
    fn shl_bits(mut self, bits: u32) -> Self {
        if self.is_zero() || bits == 0 {
            return self;
        }
        let word_shift = (bits / 32) as usize;
        let bit_shift = bits % 32;
        let mut out = vec![0u32; word_shift];
        if bit_shift == 0 {
            out.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0u64;
            for &l in &self.limbs {
                let cur = ((l as u64) << bit_shift) | carry;
                out.push((cur & 0xffff_ffff) as u32);
                carry = cur >> 32;
            }
            if carry != 0 {
                out.push(carry as u32);
            }
        }
        self.limbs = out;
        self.normalize();
        self
    }

    /// `self *= x` for a small (< 2^32) multiplier.
    fn mul_small(&mut self, x: u32) {
        if x == 0 {
            self.limbs.clear();
            return;
        }
        if self.is_zero() {
            return;
        }
        let mut carry = 0u64;
        for l in self.limbs.iter_mut() {
            let cur = (*l as u64) * (x as u64) + carry;
            *l = (cur & 0xffff_ffff) as u32;
            carry = cur >> 32;
        }
        if carry != 0 {
            self.limbs.push(carry as u32);
        }
    }

    /// `self *= 5^k`, multiplying in 5^13 chunks (5^13 = 1_220_703_125 < 2^32).
    fn mul_pow5(mut self, k: u32) -> Self {
        let mut rem = k;
        while rem >= 13 {
            self.mul_small(1_220_703_125);
            rem -= 13;
        }
        if rem > 0 {
            self.mul_small(5u32.pow(rem));
        }
        self
    }

    /// Divide `self` by `d` in place; return the remainder.
    fn divmod_small(&mut self, d: u32) -> u32 {
        let mut rem = 0u64;
        for l in self.limbs.iter_mut().rev() {
            let cur = (rem << 32) | (*l as u64);
            *l = (cur / d as u64) as u32;
            rem = cur % d as u64;
        }
        self.normalize();
        rem as u32
    }

    /// Exact decimal digits, most-significant first, no leading zeros.
    fn into_decimal_digits(mut self) -> Vec<u8> {
        if self.is_zero() {
            return vec![b'0'];
        }
        // Extract base-10^9 chunks, least-significant first.
        let mut chunks: Vec<u32> = Vec::new();
        while !self.is_zero() {
            chunks.push(self.divmod_small(1_000_000_000));
        }
        let mut out = Vec::new();
        let last = chunks.len() - 1;
        out.extend_from_slice(chunks[last].to_string().as_bytes());
        for i in (0..last).rev() {
            // Each lower chunk is exactly 9 digits, zero-padded.
            let g = chunks[i];
            let mut div = 100_000_000;
            while div != 0 {
                out.push(b'0' + ((g / div) % 10) as u8);
                div /= 10;
            }
        }
        out
    }
}

/// Classification and exact decimal significand of a binary128 value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum F128Class {
    Zero {
        negative: bool,
    },
    Infinity {
        negative: bool,
    },
    Nan {
        negative: bool,
        quiet: bool,
        payload: u128,
    },
    /// Finite nonzero. The exact magnitude equals
    /// `(digits as a decimal integer) · 10^exp10`. `digits` are ASCII `b'0'..=b'9'`,
    /// most-significant first, with no leading and no trailing zeros.
    Finite {
        negative: bool,
        digits: Vec<u8>,
        exp10: i32,
    },
}

const BIAS: i32 = 16383;
const MANT_BITS: i32 = 112;

/// Decompose the raw 128-bit pattern of an IEEE-754 binary128 value into its
/// classification and (for finite values) exact decimal significand.
pub fn classify_binary128(bits: u128) -> F128Class {
    let negative = (bits >> 127) & 1 == 1;
    let exp_field = ((bits >> 112) & 0x7fff) as i32;
    let mantissa = bits & ((1u128 << 112) - 1);

    if exp_field == 0x7fff {
        if mantissa == 0 {
            return F128Class::Infinity { negative };
        }
        let quiet = (mantissa >> 111) & 1 == 1;
        let payload = mantissa & ((1u128 << 111) - 1);
        return F128Class::Nan { negative, quiet, payload };
    }

    // Significand integer `m` and binary exponent `e` such that value = m · 2^e.
    let (m, e): (u128, i32) = if exp_field == 0 {
        if mantissa == 0 {
            return F128Class::Zero { negative };
        }
        // Subnormal: no implicit leading bit, exponent fixed at 1 - BIAS.
        (mantissa, 1 - BIAS - MANT_BITS)
    } else {
        // Normal: implicit leading 1.
        ((1u128 << 112) | mantissa, exp_field - BIAS - MANT_BITS)
    };

    // value = m · 2^e. Build an integer N and exp10 with value = N · 10^exp10:
    //   e >= 0:  N = m << e,        exp10 = 0
    //   e <  0:  N = m · 5^(-e),    exp10 = e   (since 2^e = 5^(-e) · 10^e)
    let (big, mut exp10) = if e >= 0 {
        (BigUint::from_u128(m).shl_bits(e as u32), 0i32)
    } else {
        (BigUint::from_u128(m).mul_pow5((-e) as u32), e)
    };

    let mut digits = big.into_decimal_digits();
    // Normalize to the canonical significand: strip trailing zeros into exp10.
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
        exp10 += 1;
    }
    F128Class::Finite { negative, digits, exp10 }
}

/// Round a canonical significand (`digits`, `exp10`) — where the value equals
/// `(digits as integer) · 10^exp10` — to at most `max_sig` significant decimal
/// digits using round-half-to-even, returning a new canonical `(digits, exp10)`
/// (trailing zeros stripped). `max_sig` must be >= 1.
///
/// This is the rounding primitive shared by the `%e`/`%g` conversions; `%f`
/// rounding to a fixed number of fractional places maps onto it by choosing
/// `max_sig` from the value's magnitude.
pub fn round_to_sig_digits(digits: &[u8], exp10: i32, max_sig: usize) -> (Vec<u8>, i32) {
    let n = digits.len();
    if max_sig == 0 || n <= max_sig {
        return (digits.to_vec(), exp10);
    }
    let dropped = n - max_sig;
    let mut kept: Vec<u8> = digits[..max_sig].to_vec();
    let round_digit = digits[max_sig];
    let round_up = if round_digit > b'5' {
        true
    } else if round_digit < b'5' {
        false
    } else if digits[max_sig + 1..].iter().any(|&d| d != b'0') {
        true
    } else {
        // Exact tie: round to even (round up iff the last kept digit is odd).
        (kept[max_sig - 1] - b'0') % 2 == 1
    };
    let mut new_exp10 = exp10 + dropped as i32;
    if round_up {
        let mut i = max_sig;
        loop {
            if i == 0 {
                // Carry out of the most-significant digit: 99..9 -> 100..0.
                // Keep `max_sig` significant digits by dropping the new trailing
                // zero and bumping the exponent.
                kept.insert(0, b'1');
                kept.pop();
                new_exp10 += 1;
                break;
            }
            i -= 1;
            if kept[i] == b'9' {
                kept[i] = b'0';
            } else {
                kept[i] += 1;
                break;
            }
        }
    }
    while kept.len() > 1 && kept.last() == Some(&b'0') {
        kept.pop();
        new_exp10 += 1;
    }
    (kept, new_exp10)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(sign: u128, ef: u128, m: u128) -> u128 {
        (sign << 127) | (ef << 112) | m
    }

    fn finite(b: u128) -> (bool, String, i32) {
        match classify_binary128(b) {
            F128Class::Finite { negative, digits, exp10 } => {
                (negative, String::from_utf8(digits).unwrap(), exp10)
            }
            other => panic!("expected finite, got {other:?}"),
        }
    }

    #[test]
    fn exact_simple_values() {
        assert_eq!(finite(bits(0, 0x3FFF, 0)), (false, "1".into(), 0)); // 1.0
        assert_eq!(finite(bits(0, 0x4000, 0)), (false, "2".into(), 0)); // 2.0
        assert_eq!(finite(bits(0, 0x3FFE, 0)), (false, "5".into(), -1)); // 0.5
        assert_eq!(finite(bits(0, 0x3FFD, 0)), (false, "25".into(), -2)); // 0.25
        assert_eq!(finite(bits(0, 0x4000, 1 << 111)), (false, "3".into(), 0)); // 3.0
        assert_eq!(finite(bits(0, 0x4002, 1 << 110)), (false, "1".into(), 1)); // 10.0
        assert_eq!(finite(bits(1, 0x3FFF, 0)), (true, "1".into(), 0)); // -1.0
    }

    #[test]
    fn exact_tiny_normal_2_pow_minus_120() {
        let (neg, d, e) = finite(bits(0, 0x3F87, 0));
        assert!(!neg);
        assert_eq!(
            d,
            "752316384526264005099991383822237233803945956334136013765601092018187046051025390625"
        );
        assert_eq!(e, -120);
    }

    #[test]
    fn exact_smallest_subnormal_2_pow_minus_16494() {
        let (neg, d, e) = finite(bits(0, 0, 1));
        assert!(!neg);
        assert_eq!(d.len(), 11529);
        assert!(d.starts_with("64751751194380251109"));
        assert!(d.ends_with("41301822662353515625"));
        assert_eq!(e, -16494);
    }

    fn round(d: &str, exp10: i32, max_sig: usize) -> (String, i32) {
        let (r, e) = round_to_sig_digits(d.as_bytes(), exp10, max_sig);
        (String::from_utf8(r).unwrap(), e)
    }

    #[test]
    fn rounds_half_to_even() {
        // No rounding needed.
        assert_eq!(round("12345", 0, 5), ("12345".into(), 0));
        assert_eq!(round("12345", 0, 9), ("12345".into(), 0));
        // > 5 rounds up.
        assert_eq!(round("126", 0, 2), ("13".into(), 1));
        // < 5 truncates.
        assert_eq!(round("124", 0, 2), ("12".into(), 1));
        // Exact tie, last kept digit even -> stay; odd -> up.
        assert_eq!(round("125", 0, 2), ("12".into(), 1)); // 12 even
        assert_eq!(round("135", 0, 2), ("14".into(), 1)); // 13 odd -> 14
        // Tie with trailing nonzero -> always up.
        assert_eq!(round("1251", 0, 2), ("13".into(), 2));
        // Carry out of all-nines, with trailing-zero strip.
        assert_eq!(round("999500", 0, 3), ("1".into(), 6)); // -> 1_000_000
        assert_eq!(round("9996", 0, 3), ("1".into(), 4)); // 1000 -> 1e4
        // exp10 is preserved/offset, not assumed zero.
        assert_eq!(round("1999", -3, 1), ("2".into(), 0)); // 1.999 -> 2
    }

    #[test]
    fn classifies_specials() {
        assert_eq!(classify_binary128(bits(0, 0x7FFF, 0)), F128Class::Infinity { negative: false });
        assert_eq!(classify_binary128(bits(1, 0x7FFF, 0)), F128Class::Infinity { negative: true });
        assert_eq!(classify_binary128(bits(0, 0, 0)), F128Class::Zero { negative: false });
        assert_eq!(classify_binary128(bits(1, 0, 0)), F128Class::Zero { negative: true });
        match classify_binary128(bits(0, 0x7FFF, 1 << 111)) {
            F128Class::Nan { quiet, negative, .. } => {
                assert!(quiet);
                assert!(!negative);
            }
            o => panic!("expected quiet NaN, got {o:?}"),
        }
        match classify_binary128(bits(0, 0x7FFF, 1)) {
            F128Class::Nan { quiet, payload, .. } => {
                assert!(!quiet);
                assert_eq!(payload, 1);
            }
            o => panic!("expected signaling NaN, got {o:?}"),
        }
    }
}
