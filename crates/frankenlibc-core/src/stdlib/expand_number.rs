//! FreeBSD libutil `expand_number` — parse a human-readable size
//! string with optional decimal fraction ("1.5K") into a `uint64_t`.
//!
//! Pure-safe Rust port. The C ABI shim in
//! `frankenlibc-abi::stdlib_abi` handles raw-pointer plumbing and
//! maps [`ExpandError`] into the errno values that FreeBSD
//! `expand_number(3)` documents (EINVAL / ERANGE).
//!
//! ## Semantics (FreeBSD expand_number(3))
//!
//! - Optional leading ASCII whitespace.
//! - One or more decimal digits — **non-negative only** (the result
//!   is `uint64_t`).
//! - Optional `.` followed by one or more decimal digits (fractional
//!   part).
//! - Optional one-character suffix from `{k, K, m, M, g, G, t, T,
//!   p, P, e, E}` mapping to `1024^k`. Unlike NetBSD
//!   `dehumanize_number`, FreeBSD `expand_number` does **not**
//!   recognize `b/B` and will reject it as `Invalid`.
//! - The fractional part is multiplied by the suffix multiplier
//!   using integer arithmetic — `1.5K` becomes `1024 + ⌊5·1024/10⌋
//!   = 1536`, exactly matching libbsd's reference.
//! - A bare fractional value with no suffix is rejected as
//!   `Invalid` (FreeBSD requires a suffix when a decimal point is
//!   present, since otherwise the fractional bytes have nothing to
//!   scale into).
//! - Trailing garbage past the suffix is rejected as `Invalid`.

/// Reasons [`parse`] rejects an input. Maps 1:1 to the errno values
/// the abi shim publishes through `*errno_location()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpandError {
    /// Empty input, missing digits, unknown suffix, trailing garbage,
    /// negative sign, or fraction without suffix. FreeBSD reports
    /// this as `EINVAL`.
    Invalid,
    /// Numeric overflow during accumulation or the suffix multiply.
    /// FreeBSD reports this as `ERANGE`.
    Overflow,
}

/// Parse `input` into a `u64`. Returns `Ok(value)` iff the bytes
/// match the FreeBSD expand_number grammar AND fit in `u64`.
pub fn parse(input: &[u8]) -> Result<u64, ExpandError> {
    let mut i = 0usize;

    // Leading whitespace.
    while i < input.len() && is_ascii_whitespace(input[i]) {
        i += 1;
    }

    // Reject explicit signs — FreeBSD expand_number is non-negative.
    if i < input.len() && (input[i] == b'-' || input[i] == b'+') {
        return Err(ExpandError::Invalid);
    }

    // Integer part: at least one digit required.
    if i >= input.len() || !input[i].is_ascii_digit() {
        return Err(ExpandError::Invalid);
    }
    let mut whole: u64 = 0;
    while i < input.len() && input[i].is_ascii_digit() {
        let d = (input[i] - b'0') as u64;
        whole = whole
            .checked_mul(10)
            .and_then(|v| v.checked_add(d))
            .ok_or(ExpandError::Overflow)?;
        i += 1;
    }

    // Optional fractional part.
    let mut frac_value: u64 = 0;
    let mut frac_pow10: u64 = 1;
    let mut had_fraction = false;
    if i < input.len() && input[i] == b'.' {
        had_fraction = true;
        i += 1;
        // At least one fractional digit required after a `.`.
        if i >= input.len() || !input[i].is_ascii_digit() {
            return Err(ExpandError::Invalid);
        }
        while i < input.len() && input[i].is_ascii_digit() {
            let d = (input[i] - b'0') as u64;
            // Bound the fractional accumulator: more than 19 digits
            // can't fit in u64 (10^19 > u64::MAX). Anything past
            // that is silently truncated, mirroring libbsd.
            if let (Some(new_pow), Some(new_value)) = (
                frac_pow10.checked_mul(10),
                frac_value.checked_mul(10).and_then(|v| v.checked_add(d)),
            ) {
                frac_pow10 = new_pow;
                frac_value = new_value;
            }
            i += 1;
        }
    }

    // Suffix is required when a fractional part is present (otherwise
    // the fraction has no integer scale to round into).
    let multiplier: u64 = if i == input.len() {
        if had_fraction {
            return Err(ExpandError::Invalid);
        }
        1
    } else if i + 1 == input.len() {
        match input[i] {
            b'k' | b'K' => 1024,
            b'm' | b'M' => 1024 * 1024,
            b'g' | b'G' => 1024 * 1024 * 1024,
            b't' | b'T' => 1024u64.pow(4),
            b'p' | b'P' => 1024u64.pow(5),
            b'e' | b'E' => 1024u64.pow(6),
            _ => return Err(ExpandError::Invalid),
        }
    } else {
        return Err(ExpandError::Invalid);
    };

    // Combine: whole*multiplier + ⌊frac_value * multiplier / frac_pow10⌋.
    let scaled_whole = whole.checked_mul(multiplier).ok_or(ExpandError::Overflow)?;
    let scaled_frac = if had_fraction {
        // The intermediate `frac_value * multiplier` can exceed u64
        // even when the final ⌊·/frac_pow10⌋ comfortably fits — for
        // very long fractional accumulators (frac_value ≈ 10^19,
        // multiplier ≥ 1024). Promote to u128 just for this divide
        // so we don't spuriously report Overflow on inputs whose
        // result is well-defined.
        let prod = (frac_value as u128) * (multiplier as u128);
        let scaled = prod / (frac_pow10 as u128);
        if scaled > u64::MAX as u128 {
            return Err(ExpandError::Overflow);
        }
        scaled as u64
    } else {
        0
    };
    scaled_whole
        .checked_add(scaled_frac)
        .ok_or(ExpandError::Overflow)
}

#[inline]
fn is_ascii_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- happy path ----

    #[test]
    fn parses_plain_decimal() {
        assert_eq!(parse(b"42"), Ok(42));
        assert_eq!(parse(b"0"), Ok(0));
    }

    #[test]
    fn parses_with_kilo_suffix() {
        assert_eq!(parse(b"1k"), Ok(1024));
        assert_eq!(parse(b"4K"), Ok(4096));
    }

    #[test]
    fn parses_fractional_with_suffix() {
        // 1.5K = 1024 + ⌊5·1024/10⌋ = 1024 + 512 = 1536.
        assert_eq!(parse(b"1.5K"), Ok(1536));
        // 0.5G = 0 + ⌊5·1024^3/10⌋ = 536870912.
        assert_eq!(parse(b"0.5G"), Ok(1024 * 1024 * 1024 / 2));
        // 2.25M = 2*1024^2 + ⌊25·1024^2/100⌋
        let expected = 2 * 1024u64 * 1024 + (25 * 1024u64 * 1024) / 100;
        assert_eq!(parse(b"2.25M"), Ok(expected));
    }

    #[test]
    fn skips_leading_whitespace() {
        assert_eq!(parse(b"  42K"), Ok(42 * 1024));
        assert_eq!(parse(b"\t\n  3M"), Ok(3 * 1024 * 1024));
    }

    #[test]
    fn parses_all_suffixes() {
        let cases: &[(&[u8], u64)] = &[
            (b"1k", 1024),
            (b"1K", 1024),
            (b"1m", 1024 * 1024),
            (b"1M", 1024 * 1024),
            (b"1g", 1024 * 1024 * 1024),
            (b"1G", 1024 * 1024 * 1024),
            (b"1t", 1024u64.pow(4)),
            (b"1T", 1024u64.pow(4)),
            (b"1p", 1024u64.pow(5)),
            (b"1P", 1024u64.pow(5)),
            (b"1e", 1024u64.pow(6)),
            (b"1E", 1024u64.pow(6)),
        ];
        for (input, expected) in cases {
            assert_eq!(parse(input), Ok(*expected), "input {input:?}");
        }
    }

    // ---- invalid input ----

    #[test]
    fn empty_input_is_invalid() {
        assert_eq!(parse(b""), Err(ExpandError::Invalid));
    }

    #[test]
    fn whitespace_only_is_invalid() {
        assert_eq!(parse(b"   \t"), Err(ExpandError::Invalid));
    }

    #[test]
    fn negative_is_invalid() {
        // expand_number is unsigned; reject `-` outright.
        assert_eq!(parse(b"-1k"), Err(ExpandError::Invalid));
        assert_eq!(parse(b"-0"), Err(ExpandError::Invalid));
    }

    #[test]
    fn explicit_positive_sign_is_invalid() {
        // FreeBSD expand_number doesn't accept the explicit `+` sign.
        assert_eq!(parse(b"+42"), Err(ExpandError::Invalid));
    }

    #[test]
    fn unknown_suffix_is_invalid() {
        assert_eq!(parse(b"42x"), Err(ExpandError::Invalid));
        // FreeBSD expand_number does NOT recognize `b/B` (unlike
        // NetBSD dehumanize_number).
        assert_eq!(parse(b"42b"), Err(ExpandError::Invalid));
        assert_eq!(parse(b"42B"), Err(ExpandError::Invalid));
    }

    #[test]
    fn trailing_garbage_is_invalid() {
        assert_eq!(parse(b"42kb"), Err(ExpandError::Invalid));
        assert_eq!(parse(b"42K "), Err(ExpandError::Invalid));
        assert_eq!(parse(b"42M5"), Err(ExpandError::Invalid));
    }

    #[test]
    fn fraction_without_digits_is_invalid() {
        assert_eq!(parse(b"42."), Err(ExpandError::Invalid));
        assert_eq!(parse(b"42.K"), Err(ExpandError::Invalid));
    }

    #[test]
    fn integer_part_required() {
        // Bare ".5K" is not accepted — FreeBSD requires the integer part.
        assert_eq!(parse(b".5K"), Err(ExpandError::Invalid));
    }

    #[test]
    fn fraction_without_suffix_is_invalid() {
        // Without a suffix, the fractional part has no integer scale
        // to land in. FreeBSD documents this as malformed.
        assert_eq!(parse(b"1.5"), Err(ExpandError::Invalid));
        assert_eq!(parse(b"42.0"), Err(ExpandError::Invalid));
    }

    #[test]
    fn embedded_whitespace_is_invalid() {
        assert_eq!(parse(b"42 K"), Err(ExpandError::Invalid));
        assert_eq!(parse(b"4 2"), Err(ExpandError::Invalid));
    }

    #[test]
    fn hex_prefix_is_invalid() {
        assert_eq!(parse(b"0x10"), Err(ExpandError::Invalid));
    }

    // ---- overflow ----

    #[test]
    fn integer_part_overflow_returns_overflow() {
        assert_eq!(
            parse(b"99999999999999999999999"),
            Err(ExpandError::Overflow)
        );
    }

    #[test]
    fn suffix_multiply_overflow_returns_overflow() {
        // u64::MAX * 1024 overflows.
        let s = format!("{}k", u64::MAX);
        assert_eq!(parse(s.as_bytes()), Err(ExpandError::Overflow));
    }

    #[test]
    fn just_over_u64_max_with_suffix() {
        // 16 * 1024^6 = 2^64 — overflows u64::MAX (2^64 - 1).
        assert_eq!(parse(b"16E"), Err(ExpandError::Overflow));
    }

    // ---- edge cases ----

    #[test]
    fn zero_with_suffix_is_zero() {
        assert_eq!(parse(b"0k"), Ok(0));
        assert_eq!(parse(b"0E"), Ok(0));
    }

    #[test]
    fn fraction_truncates_toward_zero() {
        // 1.999K = 1024 + ⌊999·1024/1000⌋ = 1024 + 1022 = 2046
        // (NOT 2047 — integer division truncates).
        assert_eq!(parse(b"1.999K"), Ok(1024 + 999 * 1024 / 1000));
    }

    #[test]
    fn very_long_fraction_is_truncated_silently() {
        // More than 19 fractional digits; we silently stop
        // accumulating past the u64 precision boundary. The input
        // 1.5555...K (forty 5s) approaches 1.5555... × 1024 ≈ 1592.8,
        // so the integer-truncated result lands at 1592. Allow ±1
        // for any future precision tweak that doesn't change the
        // semantic.
        let mut s = String::from("1.");
        s.push_str(&"5".repeat(40));
        s.push('K');
        let r = parse(s.as_bytes()).unwrap();
        assert!((1591..=1593).contains(&r), "got {r}");
    }

    #[test]
    fn big_value_exact() {
        // u64::MAX itself fits without a suffix.
        let s = format!("{}", u64::MAX);
        assert_eq!(parse(s.as_bytes()), Ok(u64::MAX));
    }

    #[test]
    fn just_under_overflow_with_suffix() {
        // 15 * 1024^6 = 17293822569102704640, below u64::MAX.
        assert_eq!(parse(b"15E"), Ok(15 * 1024u64.pow(6)));
    }
}
