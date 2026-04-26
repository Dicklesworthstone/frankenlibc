//! NetBSD libutil `dehumanize_number` — parse a human-readable size
//! string ("1K", "4M", "2G") into an `int64_t`.
//!
//! Pure-safe Rust port of the byte-level logic. The C ABI shim in
//! `frankenlibc-abi::stdlib_abi` handles raw-pointer plumbing and
//! maps [`DehumanizeError`] into the errno values that NetBSD
//! `dehumanize_number(3)` documents.
//!
//! ## Semantics (NetBSD dehumanize_number(3))
//!
//! - Skip leading ASCII whitespace.
//! - Optional `+` or `-` sign.
//! - One or more decimal digits — **no** decimal point, no fractional
//!   suffixes (this is the "pure integer" cousin of FreeBSD's
//!   `expand_number`, which we'd ship separately).
//! - Optional **one-character** suffix from the set
//!   `{b, B, k, K, m, M, g, G, t, T, p, P, e, E}` mapping to
//!   `1024^k` (with `b`/`B` = `1`).
//! - Trailing garbage past the suffix is rejected as `Invalid`.
//! - Arithmetic overflow during the multiplier promotion is reported
//!   as `Overflow` (NetBSD reports `ERANGE`).

/// Reasons [`parse`] rejects an input. Maps 1:1 to the errno values
/// the abi shim publishes through `*errno_location()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DehumanizeError {
    /// Empty input, missing digits, unknown suffix, or trailing garbage.
    /// NetBSD reports this as `EINVAL`.
    Invalid,
    /// Numeric overflow during accumulation or the suffix multiply.
    /// NetBSD reports this as `ERANGE`.
    Overflow,
}

/// Parse `input` into an `i64`. Returns `Ok(value)` iff every byte
/// (after the optional sign and whitespace) is a decimal digit
/// followed by an optional one-character size suffix AND the
/// resulting value fits in `i64`. On error, returns the matching
/// [`DehumanizeError`].
pub fn parse(input: &[u8]) -> Result<i64, DehumanizeError> {
    let mut i = 0usize;

    // Leading whitespace.
    while i < input.len() && is_ascii_whitespace(input[i]) {
        i += 1;
    }

    // Optional sign.
    let negative = if i < input.len() && input[i] == b'-' {
        i += 1;
        true
    } else if i < input.len() && input[i] == b'+' {
        i += 1;
        false
    } else {
        false
    };

    // Must have at least one digit.
    if i >= input.len() || !input[i].is_ascii_digit() {
        return Err(DehumanizeError::Invalid);
    }

    // Accumulate digits with overflow short-circuit. We accumulate as
    // u64 so the suffix multiply has full headroom; sign is applied
    // at the very end.
    let mut value: u64 = 0;
    while i < input.len() && input[i].is_ascii_digit() {
        let d = (input[i] - b'0') as u64;
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(d))
            .ok_or(DehumanizeError::Overflow)?;
        i += 1;
    }

    // Optional one-char suffix.
    let multiplier: u64 = if i == input.len() {
        1
    } else if i + 1 == input.len() {
        match input[i] {
            b'b' | b'B' => 1,
            b'k' | b'K' => 1024,
            b'm' | b'M' => 1024 * 1024,
            b'g' | b'G' => 1024 * 1024 * 1024,
            b't' | b'T' => 1024u64.pow(4),
            b'p' | b'P' => 1024u64.pow(5),
            b'e' | b'E' => 1024u64.pow(6),
            _ => return Err(DehumanizeError::Invalid),
        }
    } else {
        // Anything past one suffix char is garbage.
        return Err(DehumanizeError::Invalid);
    };

    let scaled = value
        .checked_mul(multiplier)
        .ok_or(DehumanizeError::Overflow)?;

    if negative {
        // Special-case `i64::MIN`: its absolute value (2^63) doesn't
        // fit in i64, but `i64::MIN` itself does — handle it
        // explicitly so we don't reject the canonical extreme.
        if scaled == (i64::MAX as u64) + 1 {
            return Ok(i64::MIN);
        }
        if scaled > i64::MAX as u64 {
            return Err(DehumanizeError::Overflow);
        }
        Ok(-(scaled as i64))
    } else {
        if scaled > i64::MAX as u64 {
            return Err(DehumanizeError::Overflow);
        }
        Ok(scaled as i64)
    }
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
    fn parses_negative() {
        assert_eq!(parse(b"-100"), Ok(-100));
        assert_eq!(parse(b"-1"), Ok(-1));
    }

    #[test]
    fn parses_explicit_positive_sign() {
        assert_eq!(parse(b"+42"), Ok(42));
    }

    #[test]
    fn skips_leading_whitespace() {
        assert_eq!(parse(b"  42"), Ok(42));
        assert_eq!(parse(b"\t\n  -5"), Ok(-5));
    }

    // ---- size suffixes ----

    #[test]
    fn b_suffix_is_one() {
        assert_eq!(parse(b"42b"), Ok(42));
        assert_eq!(parse(b"42B"), Ok(42));
    }

    #[test]
    fn k_suffix() {
        assert_eq!(parse(b"1k"), Ok(1024));
        assert_eq!(parse(b"4K"), Ok(4096));
    }

    #[test]
    fn m_suffix() {
        assert_eq!(parse(b"1m"), Ok(1024 * 1024));
        assert_eq!(parse(b"2M"), Ok(2 * 1024 * 1024));
    }

    #[test]
    fn g_suffix() {
        assert_eq!(parse(b"1g"), Ok(1024 * 1024 * 1024));
        assert_eq!(parse(b"4G"), Ok(4 * 1024 * 1024 * 1024));
    }

    #[test]
    fn t_suffix() {
        assert_eq!(parse(b"1t"), Ok(1024i64.pow(4)));
    }

    #[test]
    fn p_suffix() {
        assert_eq!(parse(b"1p"), Ok(1024i64.pow(5)));
    }

    #[test]
    fn e_suffix() {
        // 1024^6 = 2^60 — fits in i64.
        assert_eq!(parse(b"1e"), Ok(1024i64.pow(6)));
    }

    #[test]
    fn negative_with_suffix() {
        assert_eq!(parse(b"-1k"), Ok(-1024));
        assert_eq!(parse(b"-2M"), Ok(-2 * 1024 * 1024));
    }

    // ---- invalid input ----

    #[test]
    fn empty_input_is_invalid() {
        assert_eq!(parse(b""), Err(DehumanizeError::Invalid));
    }

    #[test]
    fn whitespace_only_is_invalid() {
        assert_eq!(parse(b"   \t\n"), Err(DehumanizeError::Invalid));
    }

    #[test]
    fn sign_only_is_invalid() {
        assert_eq!(parse(b"-"), Err(DehumanizeError::Invalid));
        assert_eq!(parse(b"+"), Err(DehumanizeError::Invalid));
    }

    #[test]
    fn unknown_suffix_is_invalid() {
        assert_eq!(parse(b"42x"), Err(DehumanizeError::Invalid));
        assert_eq!(parse(b"42z"), Err(DehumanizeError::Invalid));
        assert_eq!(parse(b"42!"), Err(DehumanizeError::Invalid));
    }

    #[test]
    fn trailing_garbage_after_suffix_is_invalid() {
        assert_eq!(parse(b"42kb"), Err(DehumanizeError::Invalid));
        assert_eq!(parse(b"42K "), Err(DehumanizeError::Invalid));
        assert_eq!(parse(b"42M42"), Err(DehumanizeError::Invalid));
    }

    #[test]
    fn decimal_point_is_invalid() {
        // dehumanize_number is integer-only, unlike expand_number.
        assert_eq!(parse(b"1.5K"), Err(DehumanizeError::Invalid));
        assert_eq!(parse(b"1.0"), Err(DehumanizeError::Invalid));
    }

    #[test]
    fn hex_prefix_is_invalid() {
        // Decimal only; "0x10" parses "0" then trailing garbage "x10".
        assert_eq!(parse(b"0x10"), Err(DehumanizeError::Invalid));
    }

    #[test]
    fn embedded_whitespace_is_invalid() {
        assert_eq!(parse(b"42 K"), Err(DehumanizeError::Invalid));
        assert_eq!(parse(b"4 2"), Err(DehumanizeError::Invalid));
    }

    // ---- overflow ----

    #[test]
    fn digit_overflow_returns_overflow() {
        // Way past i64::MAX as a raw decimal accumulator.
        assert_eq!(
            parse(b"99999999999999999999999"),
            Err(DehumanizeError::Overflow)
        );
    }

    #[test]
    fn suffix_multiply_overflow_returns_overflow() {
        // 9223372036854775807 * 1024 overflows u64.
        let s = format!("{}k", i64::MAX);
        assert_eq!(parse(s.as_bytes()), Err(DehumanizeError::Overflow));
    }

    #[test]
    fn just_over_i64_max_with_suffix_overflows() {
        // 2 ** 60 = 1024^6 — exactly representable.
        // But 2 ** 60 * 8 = 9223372036854775808 = i64::MAX + 1, which
        // overflows i64.
        assert_eq!(parse(b"8e"), Err(DehumanizeError::Overflow));
    }

    #[test]
    fn negative_i64_min_is_special_cased() {
        // i64::MIN's absolute value is 2^63, which is > i64::MAX.
        // We accept this canonical extreme.
        assert_eq!(parse(b"-9223372036854775808"), Ok(i64::MIN));
    }

    #[test]
    fn negative_overflow_returns_overflow() {
        // -(i64::MAX + 2) is unrepresentable.
        assert_eq!(
            parse(b"-9223372036854775809"),
            Err(DehumanizeError::Overflow)
        );
    }

    // ---- edge cases ----

    #[test]
    fn zero_with_suffix_is_zero() {
        assert_eq!(parse(b"0k"), Ok(0));
        assert_eq!(parse(b"0E"), Ok(0));
    }

    #[test]
    fn leading_zeros_parse_as_decimal() {
        // No octal recognition (NetBSD dehumanize is decimal-only).
        assert_eq!(parse(b"010"), Ok(10));
        assert_eq!(parse(b"007k"), Ok(7 * 1024));
    }

    #[test]
    fn big_positive_under_max() {
        let s = format!("{}", i64::MAX);
        assert_eq!(parse(s.as_bytes()), Ok(i64::MAX));
    }
}
