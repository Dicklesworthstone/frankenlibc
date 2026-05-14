//! Pidfile decimal parser/formatter.
//!
//! Pure-safe Rust port of the byte-slice logic that previously lived
//! inline in `crates/frankenlibc-abi/src/stdlib_abi.rs` to back
//! the FreeBSD-compat `pidfile_open` / `pidfile_write` / `pidfile_read`
//! family.
//!
//! The parser is *strict-no-trailing-junk*: a newline, space, or any
//! non-digit byte after the digit run yields `None`. This is
//! deliberately different from `strtol`, which would accept a partial
//! parse and report the trailing offset via `endptr`. The pidfile
//! format records exactly the decimal PID bytes with no terminator —
//! callers expect parse failure on any deviation.
//!
//! The formatter renders a signed decimal value into a caller-owned
//! buffer and returns the number of bytes written. The caller is
//! responsible for choosing a buffer large enough; 24 bytes is
//! sufficient for any `i64` (max length: `-9223372036854775808` =
//! 20 bytes).

/// Parse a strict decimal PID from a byte slice.
///
/// Accepts: optional leading ASCII whitespace, optional `+` / `-`
/// sign, one-or-more ASCII digits, and *nothing else*. Returns `None`
/// if the digit run is empty, the consumed prefix does not exhaust
/// the input, or the value falls outside the `i32` range (Linux
/// pid_t).
///
/// # Examples
///
/// ```
/// use frankenlibc_core::stdlib::pidfile::parse_decimal_pid;
///
/// assert_eq!(parse_decimal_pid(b"42"), Some(42));
/// assert_eq!(parse_decimal_pid(b"  +42"), Some(42));
/// assert_eq!(parse_decimal_pid(b"-1"), Some(-1));
/// assert_eq!(parse_decimal_pid(b"42\n"), None);  // trailing newline rejected
/// assert_eq!(parse_decimal_pid(b""), None);
/// assert_eq!(parse_decimal_pid(b"abc"), None);
/// ```
pub fn parse_decimal_pid(input: &[u8]) -> Option<i32> {
    let mut i = 0usize;
    while i < input.len() && input[i].is_ascii_whitespace() {
        i += 1;
    }
    let negative = if i < input.len() && (input[i] == b'+' || input[i] == b'-') {
        let is_negative = input[i] == b'-';
        i += 1;
        is_negative
    } else {
        false
    };

    let start = i;
    let mut value: i64 = 0;
    while i < input.len() && input[i].is_ascii_digit() {
        value = value
            .checked_mul(10)?
            .checked_add((input[i] - b'0') as i64)?;
        i += 1;
    }
    if i == start || i != input.len() {
        return None;
    }
    let value = if negative {
        value.checked_neg()?
    } else {
        value
    };
    if value < i32::MIN as i64 || value > i32::MAX as i64 {
        return None;
    }
    Some(value as i32)
}

/// Render a signed decimal PID into a caller-owned byte buffer.
///
/// Returns the number of bytes written. The caller is responsible
/// for sizing `out` (24 bytes is always sufficient for any `i64`).
/// If `out` is shorter than the rendered length, the rendering is
/// truncated and a partial count is returned — callers that require
/// exact rendering must size the buffer ahead of time.
///
/// # Examples
///
/// ```
/// use frankenlibc_core::stdlib::pidfile::render_pid_decimal;
///
/// let mut buf = [0u8; 24];
/// let n = render_pid_decimal(42, &mut buf);
/// assert_eq!(&buf[..n], b"42");
///
/// let n = render_pid_decimal(0, &mut buf);
/// assert_eq!(&buf[..n], b"0");
/// ```
pub fn render_pid_decimal(pid: i64, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 24];
    let mut len = 0usize;
    // Cast through u64 preserves the bit pattern. The historical
    // FreeBSD render emits the unsigned interpretation of negative
    // PIDs, which is what our existing pidfile_write callers expect;
    // any future refactor that wants a signed render with a leading
    // '-' should add a separate signed path rather than perturb this
    // one.
    let mut v = pid as u64;
    if v == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while v > 0 {
            tmp[len] = b'0' + (v % 10) as u8;
            len += 1;
            v /= 10;
        }
    }
    let mut o = 0usize;
    for i in 0..len {
        if o >= out.len() {
            break;
        }
        out[o] = tmp[len - 1 - i];
        o += 1;
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_decimal() {
        assert_eq!(parse_decimal_pid(b"0"), Some(0));
        assert_eq!(parse_decimal_pid(b"1"), Some(1));
        assert_eq!(parse_decimal_pid(b"42"), Some(42));
        assert_eq!(parse_decimal_pid(b"123456"), Some(123456));
    }

    #[test]
    fn parse_skips_leading_whitespace() {
        assert_eq!(parse_decimal_pid(b"   42"), Some(42));
        assert_eq!(parse_decimal_pid(b"\t42"), Some(42));
        assert_eq!(parse_decimal_pid(b"\n42"), Some(42));
    }

    #[test]
    fn parse_handles_optional_sign() {
        assert_eq!(parse_decimal_pid(b"+42"), Some(42));
        assert_eq!(parse_decimal_pid(b"-1"), Some(-1));
        assert_eq!(parse_decimal_pid(b"-99999"), Some(-99999));
    }

    #[test]
    fn parse_leading_zero_padding_preserves_value() {
        for (plain, padded) in [
            (b"0".as_slice(), b"0000".as_slice()),
            (b"42".as_slice(), b"00042".as_slice()),
            (b"+42".as_slice(), b"+00042".as_slice()),
            (b"-42".as_slice(), b"-00042".as_slice()),
            (b"2147483647".as_slice(), b"0002147483647".as_slice()),
        ] {
            assert_eq!(parse_decimal_pid(plain), parse_decimal_pid(padded));
        }
    }

    #[test]
    fn parse_rejects_trailing_junk() {
        assert_eq!(parse_decimal_pid(b"42\n"), None);
        assert_eq!(parse_decimal_pid(b"42 "), None);
        assert_eq!(parse_decimal_pid(b"42a"), None);
        assert_eq!(parse_decimal_pid(b"42 trailing"), None);
    }

    #[test]
    fn parse_rejects_any_non_digit_after_valid_pid() {
        for valid in [
            b"0".as_slice(),
            b"+42".as_slice(),
            b"-42".as_slice(),
            b"2147483647".as_slice(),
        ] {
            for suffix in *b"\0\n\t a," {
                let mut candidate = valid.to_vec();
                candidate.push(suffix);
                assert_eq!(parse_decimal_pid(&candidate), None, "{candidate:?}");
            }
        }
    }

    #[test]
    fn parse_rejects_no_digits() {
        assert_eq!(parse_decimal_pid(b""), None);
        assert_eq!(parse_decimal_pid(b" "), None);
        assert_eq!(parse_decimal_pid(b"+"), None);
        assert_eq!(parse_decimal_pid(b"-"), None);
        assert_eq!(parse_decimal_pid(b"abc"), None);
    }

    #[test]
    fn parse_rejects_out_of_range() {
        assert_eq!(parse_decimal_pid(b"2147483647"), Some(i32::MAX));
        assert_eq!(parse_decimal_pid(b"2147483648"), None); // i32::MAX + 1
        assert_eq!(parse_decimal_pid(b"-2147483648"), Some(i32::MIN));
        assert_eq!(parse_decimal_pid(b"-2147483649"), None); // i32::MIN - 1
        assert_eq!(parse_decimal_pid(b"99999999999999999999"), None); // overflows i64
    }

    #[test]
    fn render_zero() {
        let mut buf = [0u8; 24];
        let n = render_pid_decimal(0, &mut buf);
        assert_eq!(&buf[..n], b"0");
    }

    #[test]
    fn render_positive() {
        let mut buf = [0u8; 24];
        let n = render_pid_decimal(42, &mut buf);
        assert_eq!(&buf[..n], b"42");

        let n = render_pid_decimal(123456, &mut buf);
        assert_eq!(&buf[..n], b"123456");

        let n = render_pid_decimal(i32::MAX as i64, &mut buf);
        assert_eq!(&buf[..n], b"2147483647");
    }

    #[test]
    fn render_does_not_overflow_buffer() {
        // 2147483647 = 10 bytes; provide only 5 — must not panic and
        // must report partial length.
        let mut buf = [0u8; 5];
        let n = render_pid_decimal(2147483647, &mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"21474");
    }

    #[test]
    fn truncated_render_is_prefix_of_full_render() {
        for pid in [0i64, 1, 42, i32::MAX as i64, i64::MAX, i64::MIN] {
            let mut full = [0u8; 24];
            let full_len = render_pid_decimal(pid, &mut full);

            for prefix_len in 0..full_len {
                let mut truncated = vec![0u8; prefix_len];
                let written = render_pid_decimal(pid, &mut truncated);
                assert_eq!(written, prefix_len);
                assert_eq!(&truncated[..written], &full[..prefix_len]);
            }
        }
    }

    #[test]
    fn round_trip_through_render_and_parse() {
        for pid in [0i32, 1, 42, 9999, 100_000, i32::MAX, -1, -99, i32::MIN + 1] {
            let mut buf = [0u8; 24];
            let n = render_pid_decimal(pid as i64, &mut buf);
            let parsed = parse_decimal_pid(&buf[..n]);
            // Note: the renderer emits the unsigned bit pattern of
            // negative inputs; only non-negative values round-trip
            // through the strict parser. This documents the
            // historical FreeBSD pidfile semantics — pidfile_write
            // never writes negative PIDs.
            if pid >= 0 {
                assert_eq!(parsed, Some(pid), "round-trip failed for pid={pid}");
            }
        }
    }
}
