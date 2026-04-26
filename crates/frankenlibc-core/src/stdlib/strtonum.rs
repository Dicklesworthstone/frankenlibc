//! OpenBSD `strtonum` — bounded decimal integer parser.
//!
//! Pure-safe Rust port of the OpenBSD libc primitive used by `sshd`,
//! `pf`, `bgpd`, and other utilities that want a safer alternative to
//! `strtoll(3)`. The C ABI shim in `frankenlibc-abi::stdlib_abi`
//! handles the raw-pointer plumbing and maps [`StrtonumError`] back
//! into the canonical static error strings that OpenBSD documents.
//!
//! ## Semantics (OpenBSD strtonum(3))
//!
//! - Skips leading ASCII whitespace.
//! - Accepts an optional `+` or `-` sign.
//! - Parses one or more decimal digits — **no** hex / octal / binary
//!   prefixes are honoured (this is the whole point of strtonum vs.
//!   strtoll).
//! - The parsed value must fit in `[minval, maxval]`. If the caller
//!   passes `minval > maxval`, the error is `InvalidRange`.
//! - On overflow during accumulation we short-circuit to `TooLarge`
//!   (positive overflow) or `TooSmall` (negative overflow) rather
//!   than wrapping silently.
//! - Trailing non-digit garbage (after the digit run) makes the entire
//!   parse `Invalid` — strtonum is intentionally stricter than
//!   strtoll, which would silently stop at the first invalid byte.

/// Reasons `parse` rejects an input. Maps 1:1 to the error-string
/// categories OpenBSD `strtonum` reports through `*errstr`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrtonumError {
    /// `nptr` was empty, contained no digits, or had trailing garbage.
    Invalid,
    /// The parsed value is below `minval`.
    TooSmall,
    /// The parsed value is above `maxval`.
    TooLarge,
    /// `minval > maxval` — the caller-supplied range is malformed.
    InvalidRange,
}

impl StrtonumError {
    /// The OpenBSD canonical error string the abi shim returns through
    /// `*errstr`. These exact byte strings are what callers check
    /// against (`if (errstr != NULL) ...`).
    pub fn message(self) -> &'static [u8] {
        match self {
            Self::Invalid => b"invalid",
            Self::TooSmall => b"too small",
            Self::TooLarge => b"too large",
            Self::InvalidRange => b"invalid",
        }
    }
}

/// Parse `input` as a decimal `i64` constrained to `[minval, maxval]`.
///
/// Returns `Ok(value)` iff every byte of `input` (after the optional
/// leading sign and whitespace) is a decimal digit AND the resulting
/// value is in range. On error, returns the matching
/// [`StrtonumError`] variant.
pub fn parse(input: &[u8], minval: i64, maxval: i64) -> Result<i64, StrtonumError> {
    if minval > maxval {
        return Err(StrtonumError::InvalidRange);
    }

    let mut i = 0usize;

    // Leading ASCII whitespace.
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
    let digit_start = i;
    if i >= input.len() || !input[i].is_ascii_digit() {
        return Err(StrtonumError::Invalid);
    }

    // Accumulate digits with overflow short-circuit.
    let mut value: i64 = 0;
    while i < input.len() && input[i].is_ascii_digit() {
        let d = (input[i] - b'0') as i64;
        if negative {
            // value = value * 10 - d, watching for i64::MIN overflow.
            value = match value.checked_mul(10).and_then(|v| v.checked_sub(d)) {
                Some(v) => v,
                None => {
                    // Skip remaining digits to confirm the rest of the
                    // input is well-formed numerically before reporting
                    // — we still want to call out trailing garbage as
                    // Invalid rather than TooSmall.
                    i += 1;
                    while i < input.len() && input[i].is_ascii_digit() {
                        i += 1;
                    }
                    return finalize(input, i, StrtonumError::TooSmall);
                }
            };
        } else {
            value = match value.checked_mul(10).and_then(|v| v.checked_add(d)) {
                Some(v) => v,
                None => {
                    i += 1;
                    while i < input.len() && input[i].is_ascii_digit() {
                        i += 1;
                    }
                    return finalize(input, i, StrtonumError::TooLarge);
                }
            };
        }
        i += 1;
    }

    // Reject trailing non-digit bytes (no embedded whitespace, no
    // suffix). digit_start is unused but documents intent.
    let _ = digit_start;
    if i != input.len() {
        return Err(StrtonumError::Invalid);
    }

    if value < minval {
        Err(StrtonumError::TooSmall)
    } else if value > maxval {
        Err(StrtonumError::TooLarge)
    } else {
        Ok(value)
    }
}

/// Helper: after an overflow short-circuit we've consumed the entire
/// digit run. If there's still trailing garbage, the canonical error
/// is `Invalid` regardless of the overflow direction.
fn finalize(input: &[u8], i: usize, overflow_err: StrtonumError) -> Result<i64, StrtonumError> {
    if i != input.len() {
        Err(StrtonumError::Invalid)
    } else {
        Err(overflow_err)
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
    fn parses_simple_decimal() {
        assert_eq!(parse(b"42", 0, 100), Ok(42));
        assert_eq!(parse(b"0", 0, 100), Ok(0));
        assert_eq!(parse(b"100", 0, 100), Ok(100));
    }

    #[test]
    fn parses_negative() {
        assert_eq!(parse(b"-5", -10, 10), Ok(-5));
        assert_eq!(parse(b"-100", -100, 100), Ok(-100));
    }

    #[test]
    fn parses_explicit_positive_sign() {
        assert_eq!(parse(b"+42", 0, 100), Ok(42));
        assert_eq!(parse(b"+0", -1, 1), Ok(0));
    }

    #[test]
    fn skips_leading_whitespace() {
        assert_eq!(parse(b"  42", 0, 100), Ok(42));
        assert_eq!(parse(b"\t\n  -5", -10, 10), Ok(-5));
        assert_eq!(parse(b"\x0b\x0c+1", 0, 10), Ok(1));
    }

    #[test]
    fn parses_at_minval_boundary() {
        assert_eq!(parse(b"-100", -100, 100), Ok(-100));
        assert_eq!(parse(b"0", 0, 100), Ok(0));
    }

    #[test]
    fn parses_at_maxval_boundary() {
        assert_eq!(parse(b"100", 0, 100), Ok(100));
    }

    #[test]
    fn parses_full_i64_range() {
        assert_eq!(
            parse(b"9223372036854775807", i64::MIN, i64::MAX),
            Ok(i64::MAX)
        );
        assert_eq!(
            parse(b"-9223372036854775808", i64::MIN, i64::MAX),
            Ok(i64::MIN)
        );
    }

    // ---- range errors ----

    #[test]
    fn too_small_below_minval() {
        assert_eq!(parse(b"5", 10, 20), Err(StrtonumError::TooSmall));
        assert_eq!(parse(b"-1", 0, 100), Err(StrtonumError::TooSmall));
    }

    #[test]
    fn too_large_above_maxval() {
        assert_eq!(parse(b"50", 0, 10), Err(StrtonumError::TooLarge));
        assert_eq!(parse(b"101", -100, 100), Err(StrtonumError::TooLarge));
    }

    #[test]
    fn invalid_range_when_min_above_max() {
        assert_eq!(parse(b"5", 10, 0), Err(StrtonumError::InvalidRange));
        // Even a parseable input fails fast on bad range.
        assert_eq!(parse(b"42", 1000, 100), Err(StrtonumError::InvalidRange));
    }

    // ---- invalid input ----

    #[test]
    fn invalid_empty_input() {
        assert_eq!(parse(b"", 0, 100), Err(StrtonumError::Invalid));
    }

    #[test]
    fn invalid_only_whitespace() {
        assert_eq!(parse(b"   \t\n", 0, 100), Err(StrtonumError::Invalid));
    }

    #[test]
    fn invalid_only_sign() {
        assert_eq!(parse(b"-", -10, 10), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"+", 0, 10), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"  -", -10, 10), Err(StrtonumError::Invalid));
    }

    #[test]
    fn invalid_trailing_garbage() {
        // strtonum is strict: any non-digit byte after the digit run
        // makes the parse Invalid. (strtoll would happily stop at the
        // first non-digit and report success.)
        assert_eq!(parse(b"42x", 0, 100), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"42 ", 0, 100), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"42.0", 0, 100), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"42abc", 0, 100), Err(StrtonumError::Invalid));
    }

    #[test]
    fn invalid_hex_prefix_is_invalid() {
        // No 0x recognition — the 'x' is trailing garbage after "0".
        assert_eq!(parse(b"0x10", 0, 100), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"0X1", 0, 100), Err(StrtonumError::Invalid));
    }

    #[test]
    fn invalid_octal_is_just_decimal() {
        // Leading zero is not an octal prefix — "010" parses as decimal 10.
        assert_eq!(parse(b"010", 0, 100), Ok(10));
        assert_eq!(parse(b"0007", 0, 100), Ok(7));
    }

    #[test]
    fn invalid_letter_first() {
        assert_eq!(parse(b"abc", 0, 100), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"a42", 0, 100), Err(StrtonumError::Invalid));
    }

    #[test]
    fn invalid_double_sign() {
        assert_eq!(parse(b"--5", -10, 10), Err(StrtonumError::Invalid));
        assert_eq!(parse(b"+-5", -10, 10), Err(StrtonumError::Invalid));
    }

    // ---- overflow handling ----

    #[test]
    fn positive_overflow_returns_too_large() {
        // 1 followed by 20 zeros far exceeds i64::MAX.
        assert_eq!(
            parse(b"100000000000000000000", i64::MIN, i64::MAX),
            Err(StrtonumError::TooLarge)
        );
        // Also overflows even if maxval is huge — overflow is detected
        // during accumulation before we reach the range check.
        assert_eq!(
            parse(b"99999999999999999999", 0, i64::MAX),
            Err(StrtonumError::TooLarge)
        );
    }

    #[test]
    fn negative_overflow_returns_too_small() {
        assert_eq!(
            parse(b"-100000000000000000000", i64::MIN, i64::MAX),
            Err(StrtonumError::TooSmall)
        );
    }

    #[test]
    fn overflow_with_trailing_garbage_is_still_invalid() {
        // Garbage takes precedence over overflow per OpenBSD semantics:
        // strtonum reports the parse as Invalid because the byte
        // sequence is malformed end-to-end.
        assert_eq!(
            parse(b"100000000000000000000x", i64::MIN, i64::MAX),
            Err(StrtonumError::Invalid)
        );
    }

    #[test]
    fn just_under_overflow_succeeds() {
        // i64::MAX - 1 must parse cleanly.
        let s = format!("{}", i64::MAX - 1);
        assert_eq!(parse(s.as_bytes(), i64::MIN, i64::MAX), Ok(i64::MAX - 1));
    }

    #[test]
    fn just_under_negative_overflow_succeeds() {
        let s = format!("{}", i64::MIN + 1);
        assert_eq!(parse(s.as_bytes(), i64::MIN, i64::MAX), Ok(i64::MIN + 1));
    }

    // ---- error message strings (OpenBSD canonical) ----

    #[test]
    fn error_messages_match_openbsd_strings() {
        assert_eq!(StrtonumError::Invalid.message(), b"invalid");
        assert_eq!(StrtonumError::TooSmall.message(), b"too small");
        assert_eq!(StrtonumError::TooLarge.message(), b"too large");
        assert_eq!(StrtonumError::InvalidRange.message(), b"invalid");
    }

    #[test]
    fn invalid_range_uses_invalid_message() {
        // OpenBSD does not have a separate string for caller-supplied
        // bad range — it folds it into "invalid".
        assert_eq!(parse(b"42", 100, 0).unwrap_err().message(), b"invalid");
    }
}
