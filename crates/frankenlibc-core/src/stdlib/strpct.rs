//! NetBSD libutil percentage formatters: `strpct` / `strspct`.
//!
//! Render `100 * num / denom` into a byte string with the
//! requested number of fractional digits, using integer math
//! throughout (no floats — both for portability across no-float
//! contexts and to avoid platform-specific rounding surprises).

/// Render the unsigned percentage `100 * num / denom` rounded to
/// `precision` fractional digits. Returns the rendered bytes
/// (without trailing NUL).
///
/// `denom == 0` yields `"0"` (or `"0.000…0"` with `precision`
/// trailing zeros), matching NetBSD's defensive convention.
///
/// Internally widens to `u128` so multiplication by `100 *
/// 10^precision` doesn't overflow the inputs' native width.
pub fn format_percent_unsigned(num: u128, denom: u128, precision: usize) -> Vec<u8> {
    if denom == 0 {
        return zero_with_precision(precision);
    }
    // `precision` is bounded only by what the caller passes; cap
    // to a sane limit so the 10^precision computation doesn't
    // silently saturate. 39 keeps us inside `u128::MAX`.
    let prec = precision.min(38);
    let scale: u128 = 10u128.pow(prec as u32);
    let numerator = 100u128.saturating_mul(num).saturating_mul(scale);
    let half = denom / 2;
    let quotient = numerator.saturating_add(half) / denom;
    format_with_decimal(quotient, prec)
}

/// Render the signed percentage `100 * num / denom`. The result is
/// negative iff `num` and `denom` differ in sign.
pub fn format_percent_signed(num: i128, denom: i128, precision: usize) -> Vec<u8> {
    let sign_negative = (num < 0) ^ (denom < 0);
    let abs_num = num.unsigned_abs();
    let abs_denom = denom.unsigned_abs();
    let body = format_percent_unsigned(abs_num, abs_denom, precision);
    // Suppress the negative sign when the rendered value is "0"
    // (or "0.000…0") so callers don't see "-0".
    if sign_negative && !is_all_zeros(&body) {
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(b'-');
        out.extend_from_slice(&body);
        out
    } else {
        body
    }
}

fn zero_with_precision(precision: usize) -> Vec<u8> {
    if precision == 0 {
        return b"0".to_vec();
    }
    let prec = precision.min(38);
    let mut out = Vec::with_capacity(prec + 2);
    out.extend_from_slice(b"0.");
    out.extend(std::iter::repeat_n(b'0', prec));
    out
}

fn is_all_zeros(s: &[u8]) -> bool {
    s.iter().all(|&b| b == b'0' || b == b'.')
}

fn format_with_decimal(quotient: u128, precision: usize) -> Vec<u8> {
    let mut digits = quotient.to_string();
    if precision == 0 {
        return digits.into_bytes();
    }
    // Pad with leading zeros so we have at least `precision + 1`
    // digits; the leading group becomes the integer part (which
    // is always at least one digit).
    while digits.len() <= precision {
        digits.insert(0, '0');
    }
    let split = digits.len() - precision;
    let int_part = &digits[..split];
    let frac_part = &digits[split..];
    let mut out = Vec::with_capacity(int_part.len() + 1 + frac_part.len());
    out.extend_from_slice(int_part.as_bytes());
    out.push(b'.');
    out.extend_from_slice(frac_part.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_percent_no_precision() {
        assert_eq!(format_percent_unsigned(33, 100, 0), b"33".to_vec());
        assert_eq!(format_percent_unsigned(50, 200, 0), b"25".to_vec());
        assert_eq!(format_percent_unsigned(100, 100, 0), b"100".to_vec());
    }

    #[test]
    fn fractional_precision_rounds_to_nearest() {
        // 1/3 = 33.333... → "33.33" at precision 2
        assert_eq!(format_percent_unsigned(1, 3, 2), b"33.33".to_vec());
        // 2/3 = 66.666... → "66.67" at precision 2 (rounds up)
        assert_eq!(format_percent_unsigned(2, 3, 2), b"66.67".to_vec());
    }

    #[test]
    fn precision_pads_with_zeros() {
        assert_eq!(format_percent_unsigned(33, 100, 2), b"33.00".to_vec());
        assert_eq!(format_percent_unsigned(1, 100, 4), b"1.0000".to_vec());
    }

    #[test]
    fn small_values_get_leading_zero() {
        // 1/1000 = 0.1% → "0.10" at precision 2
        assert_eq!(format_percent_unsigned(1, 1000, 2), b"0.10".to_vec());
        // 1/200 = 0.5% → "0.50"
        assert_eq!(format_percent_unsigned(1, 200, 2), b"0.50".to_vec());
    }

    #[test]
    fn denom_zero_returns_zero_string() {
        assert_eq!(format_percent_unsigned(0, 0, 0), b"0".to_vec());
        assert_eq!(format_percent_unsigned(5, 0, 0), b"0".to_vec());
        assert_eq!(format_percent_unsigned(5, 0, 3), b"0.000".to_vec());
    }

    #[test]
    fn signed_percent_negative_when_num_or_denom_negative() {
        assert_eq!(format_percent_signed(-1, 4, 0), b"-25".to_vec());
        assert_eq!(format_percent_signed(1, -4, 0), b"-25".to_vec());
        assert_eq!(format_percent_signed(-1, -4, 0), b"25".to_vec());
    }

    #[test]
    fn signed_percent_zero_does_not_get_minus_sign() {
        assert_eq!(format_percent_signed(-0, 1, 0), b"0".to_vec());
        assert_eq!(format_percent_signed(0, -1, 0), b"0".to_vec());
        assert_eq!(format_percent_signed(0, 0, 0), b"0".to_vec());
        assert_eq!(format_percent_signed(0, -1, 2), b"0.00".to_vec());
    }

    #[test]
    fn signed_percent_zero_with_precision_is_padded() {
        assert_eq!(format_percent_signed(-1, 100, 2), b"-1.00".to_vec());
        assert_eq!(format_percent_signed(-25, 100, 2), b"-25.00".to_vec());
    }

    #[test]
    fn percent_at_or_above_100() {
        assert_eq!(format_percent_unsigned(150, 100, 1), b"150.0".to_vec());
        assert_eq!(format_percent_unsigned(999, 1000, 0), b"100".to_vec());
        assert_eq!(format_percent_unsigned(999, 1000, 1), b"99.9".to_vec());
    }

    #[test]
    fn precision_capped_to_avoid_overflow() {
        // Pathological precisions don't panic; the result is
        // well-formed (non-empty bytes containing a decimal
        // point), even if the saturating arithmetic produces a
        // numerically meaningless quotient.
        let out = format_percent_unsigned(1, 7, 100);
        assert!(!out.is_empty());
        assert!(out.contains(&b'.'));
    }

    #[test]
    fn precision_38_rounds_one_seventh_correctly() {
        // The largest precision before saturation kicks in for
        // num=1 / denom=7 is around 36; precision=10 fits with
        // headroom and exercises the rounding code.
        let out = format_percent_unsigned(1, 7, 10);
        // 100/7 = 14.2857142857... → rounded at 10 digits =
        // "14.2857142857" (exact since the 11th digit is 1).
        assert_eq!(out, b"14.2857142857".to_vec());
    }
}
