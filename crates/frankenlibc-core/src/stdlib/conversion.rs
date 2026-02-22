//! Numeric conversion functions (atoi, atol, strtol, strtoul).

/// Result of a string-to-number conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionStatus {
    Success,
    Overflow,
    Underflow,
    InvalidBase,
}

// ----------------------------------------------------------------------------
// Concrete Implementations
// ----------------------------------------------------------------------------

pub fn atoi(s: &[u8]) -> i32 {
    let (val, _, _) = strtol_impl(s, 10);
    val as i32
}

pub fn atol(s: &[u8]) -> i64 {
    let (val, _, _) = strtol_impl(s, 10);
    val
}

pub fn atoll(s: &[u8]) -> i64 {
    atol(s)
}

/// Helper for strtol: returns (value, consumed_bytes, status)
pub fn strtol_impl(s: &[u8], base: i32) -> (i64, usize, ConversionStatus) {
    let mut i = 0;
    let len = s.len();

    while i < len && s[i].is_ascii_whitespace() {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' {
        negative = true;
        i += 1;
    } else if s[i] == b'+' {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;

    // Check for "0x" or "0X" prefix
    let has_0x_prefix = i + 1 < len && s[i] == b'0' && (s[i + 1] == b'x' || s[i + 1] == b'X');

    if base == 0 {
        if has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit() {
            effective_base = 16;
            i += 2;
        } else if i < len && s[i] == b'0' {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if base == 16 && has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit() {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let abs_max = if negative {
        9_223_372_036_854_775_808u64
    } else {
        9_223_372_036_854_775_807u64
    };
    let cutoff = abs_max / effective_base;
    let cutlim = abs_max % effective_base;

    let mut acc: u64 = 0;
    let mut any_digits = false;
    let mut overflow = false;

    while i < len {
        let c = s[i];
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'z' => c - b'a' + 10,
            b'A'..=b'Z' => c - b'A' + 10,
            _ => break,
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;

        if overflow {
            i += 1;
            continue;
        }

        if acc > cutoff || (acc == cutoff && (digit as u64) > cutlim) {
            overflow = true;
        } else {
            acc = acc * effective_base + (digit as u64);
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }

    if overflow {
        if negative {
            return (i64::MIN, i, ConversionStatus::Underflow);
        } else {
            return (i64::MAX, i, ConversionStatus::Overflow);
        }
    }

    let val = if negative {
        (acc as i64).wrapping_neg()
    } else {
        acc as i64
    };

    (val, i, ConversionStatus::Success)
}

pub fn strtol(s: &[u8], base: i32) -> (i64, usize) {
    let (val, len, _) = strtol_impl(s, base);
    (val, len)
}

/// Helper for strtoll
pub fn strtoll_impl(s: &[u8], base: i32) -> (i64, usize, ConversionStatus) {
    strtol_impl(s, base)
}

pub fn strtoll(s: &[u8], base: i32) -> (i64, usize) {
    strtol(s, base)
}

/// Helper for strtoimax
pub fn strtoimax_impl(s: &[u8], base: i32) -> (i64, usize, ConversionStatus) {
    strtol_impl(s, base)
}

pub fn strtoimax(s: &[u8], base: i32) -> (i64, usize) {
    strtol(s, base)
}

/// Helper for strtoul
pub fn strtoul_impl(s: &[u8], base: i32) -> (u64, usize, ConversionStatus) {
    let mut i = 0;
    let len = s.len();

    while i < len && s[i].is_ascii_whitespace() {
        i += 1;
    }
    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut negative = false;
    if s[i] == b'-' {
        negative = true;
        i += 1;
    } else if s[i] == b'+' {
        i += 1;
    }

    if i == len {
        return (0, 0, ConversionStatus::Success);
    }

    let mut effective_base = base as u64;

    // Check for "0x" or "0X" prefix
    let has_0x_prefix = i + 1 < len && s[i] == b'0' && (s[i + 1] == b'x' || s[i + 1] == b'X');

    if base == 0 {
        if has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit() {
            effective_base = 16;
            i += 2;
        } else if i < len && s[i] == b'0' {
            effective_base = 8;
        } else {
            effective_base = 10;
        }
    } else if base == 16 && has_0x_prefix && i + 2 < len && s[i + 2].is_ascii_hexdigit() {
        i += 2;
    }

    if !(2..=36).contains(&effective_base) {
        return (0, 0, ConversionStatus::InvalidBase);
    }

    let cutoff = u64::MAX / effective_base;
    let cutlim = u64::MAX % effective_base;

    let mut acc: u64 = 0;
    let mut any_digits = false;
    let mut overflow = false;

    while i < len {
        let c = s[i];
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'z' => c - b'a' + 10,
            b'A'..=b'Z' => c - b'A' + 10,
            _ => break,
        };
        if (digit as u64) >= effective_base {
            break;
        }

        any_digits = true;
        if overflow {
            i += 1;
            continue;
        }

        if acc > cutoff || (acc == cutoff && (digit as u64) > cutlim) {
            overflow = true;
        } else {
            acc = acc * effective_base + (digit as u64);
        }
        i += 1;
    }

    if !any_digits {
        return (0, 0, ConversionStatus::Success);
    }

    if overflow {
        return (u64::MAX, i, ConversionStatus::Overflow);
    }

    let val = if negative { acc.wrapping_neg() } else { acc };

    (val, i, ConversionStatus::Success)
}

pub fn strtoul(s: &[u8], base: i32) -> (u64, usize) {
    let (val, len, _) = strtoul_impl(s, base);
    (val, len)
}

/// Helper for strtoull
pub fn strtoull_impl(s: &[u8], base: i32) -> (u64, usize, ConversionStatus) {
    strtoul_impl(s, base)
}

pub fn strtoull(s: &[u8], base: i32) -> (u64, usize) {
    strtoul(s, base)
}

/// Helper for strtoumax
pub fn strtoumax_impl(s: &[u8], base: i32) -> (u64, usize, ConversionStatus) {
    strtoul_impl(s, base)
}

pub fn strtoumax(s: &[u8], base: i32) -> (u64, usize) {
    strtoul(s, base)
}

// ---------------------------------------------------------------------------
// Floating-point conversion
// ---------------------------------------------------------------------------

/// Parses a floating-point number from a NUL-terminated byte slice.
///
/// Returns `(value, bytes_consumed)`. On failure, returns `(0.0, 0)`.
pub fn strtod_impl(s: &[u8]) -> (f64, usize) {
    let len = crate::string::strlen(s);
    let slice = &s[..len];

    let mut i = 0;
    while i < slice.len() && slice[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= slice.len() {
        return (0.0, 0);
    }

    // Try to parse using core::str::parse on the valid ASCII portion.
    // Collect chars that could be part of a float.
    let start = i;
    if i < slice.len() && (slice[i] == b'+' || slice[i] == b'-') {
        i += 1;
    }

    // Check for "inf", "infinity", "nan" (case-insensitive)
    if i + 3 <= slice.len() {
        let word = &slice[i..i + 3];
        if word.eq_ignore_ascii_case(b"inf") {
            i += 3;
            if i + 5 <= slice.len() && slice[i..i + 5].eq_ignore_ascii_case(b"inity") {
                i += 5;
            }
            let sign: f64 = if start < slice.len() && slice[start] == b'-' {
                -1.0
            } else {
                1.0
            };
            return (sign * f64::INFINITY, i);
        }
        if word.eq_ignore_ascii_case(b"nan") {
            i += 3;
            return (f64::NAN, i);
        }
    }

    // Check for hex float (0x...)
    // Note: Rust's core::str::parse::<f64>() does not support hex floats.
    // A complete C99 strtod implementation would require a custom hex float parser.
    // For now, we will parse the prefix, but `parse::<f64>()` will fail and return 0.0.
    let is_hex =
        i + 1 < slice.len() && slice[i] == b'0' && (slice[i + 1] == b'x' || slice[i + 1] == b'X');
    if is_hex {
        i += 2;
    }

    // Consume digits, decimal point, exponent.
    let mut has_digits = false;
    while i < slice.len() && (slice[i].is_ascii_digit() || (is_hex && slice[i].is_ascii_hexdigit()))
    {
        has_digits = true;
        i += 1;
    }
    if i < slice.len() && slice[i] == b'.' {
        i += 1;
        while i < slice.len()
            && (slice[i].is_ascii_digit() || (is_hex && slice[i].is_ascii_hexdigit()))
        {
            has_digits = true;
            i += 1;
        }
    }
    if !has_digits {
        return (0.0, 0);
    }
    // Exponent
    if i < slice.len() {
        let exp_char = if is_hex { b'p' } else { b'e' };
        if slice[i].to_ascii_lowercase() == exp_char {
            i += 1;
            if i < slice.len() && (slice[i] == b'+' || slice[i] == b'-') {
                i += 1;
            }
            while i < slice.len() && slice[i].is_ascii_digit() {
                i += 1;
            }
        }
    }

    let num_str = core::str::from_utf8(&slice[start..i]).unwrap_or("");
    match num_str.parse::<f64>() {
        Ok(val) => (val, i),
        Err(_) => (0.0, 0),
    }
}

/// C `strtod` -- parse double from string, returns (value, bytes_consumed).
pub fn strtod(s: &[u8]) -> (f64, usize) {
    strtod_impl(s)
}

/// C `strtof` -- parse float from string, returns (value, bytes_consumed).
pub fn strtof(s: &[u8]) -> (f32, usize) {
    let (val, consumed) = strtod_impl(s);
    (val as f32, consumed)
}

/// C `atof` -- equivalent to `strtod(s, NULL)`.
pub fn atof(s: &[u8]) -> f64 {
    strtod_impl(s).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_atoi_basic() {
        assert_eq!(atoi(b"42"), 42);
        assert_eq!(atoi(b"-42"), -42);
        assert_eq!(atoi(b"   123"), 123);
    }

    #[test]
    fn test_atoll_aliases_atol() {
        assert_eq!(atoll(b"9223372036854775807"), i64::MAX);
        assert_eq!(atoll(b"-9223372036854775808"), i64::MIN);
    }

    #[test]
    fn test_strtol_base10() {
        let (val, len) = strtol(b"123456", 10);
        assert_eq!(val, 123456);
        assert_eq!(len, 6);
    }

    #[test]
    fn test_strtoimax_aliases_strtol() {
        let (val, len) = strtoimax(b"-9223372036854775808", 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtoll_aliases_strtol() {
        let (val, len) = strtoll(b"-9223372036854775808", 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtol_base16() {
        let (val, len) = strtol(b"0xFF", 16);
        assert_eq!(val, 255);
        assert_eq!(len, 4);

        let (val, len) = strtol(b"FF", 16);
        assert_eq!(val, 255);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_strtol_auto_base() {
        let (val, _) = strtol(b"0x10", 0);
        assert_eq!(val, 16);
        let (val, _) = strtol(b"010", 0);
        assert_eq!(val, 8);
        let (val, _) = strtol(b"10", 0);
        assert_eq!(val, 10);
    }

    #[test]
    fn test_strtol_overflow() {
        let max = i64::MAX;
        let s = format!("{}", max);
        let (val, _, status) = strtol_impl(s.as_bytes(), 10);
        assert_eq!(val, max);
        assert_eq!(status, ConversionStatus::Success);

        let s_over = "9223372036854775808"; // MAX + 1
        let (val, _, status) = strtol_impl(s_over.as_bytes(), 10);
        assert_eq!(val, i64::MAX);
        assert_eq!(status, ConversionStatus::Overflow);

        let min = i64::MIN;
        let s_min = format!("{}", min);
        let (val, _, status) = strtol_impl(s_min.as_bytes(), 10);
        assert_eq!(val, min);
        assert_eq!(status, ConversionStatus::Success);

        let s_under = "-9223372036854775809"; // MIN - 1
        let (val, _, status) = strtol_impl(s_under.as_bytes(), 10);
        assert_eq!(val, i64::MIN);
        assert_eq!(status, ConversionStatus::Underflow);
    }

    #[test]
    fn test_strtoul_overflow() {
        let max = u64::MAX;
        let s = format!("{}", max);
        let (val, _, status) = strtoul_impl(s.as_bytes(), 10);
        assert_eq!(val, max);
        assert_eq!(status, ConversionStatus::Success);

        let s_over = "18446744073709551616"; // MAX + 1
        let (val, _, status) = strtoul_impl(s_over.as_bytes(), 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(status, ConversionStatus::Overflow);
    }

    #[test]
    fn test_strtoumax_aliases_strtoul() {
        let (val, len) = strtoumax(b"18446744073709551615", 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtoull_aliases_strtoul() {
        let (val, len) = strtoull(b"18446744073709551615", 10);
        assert_eq!(val, u64::MAX);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_strtol_0x_edge_cases() {
        // "0xz" base 0 -> parses "0", stops at 'x'
        // expected: 0, len 1.
        let (val, len) = strtol(b"0xz", 0);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "0xz" base 16 -> parses "0", stops at 'x'
        let (val, len) = strtol(b"0xz", 16);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "0x" base 0 -> parses "0", stops at 'x'
        let (val, len) = strtol(b"0x", 0);
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        // "0x1" base 0 -> parses "0x1" (16)
        let (val, len) = strtol(b"0x1", 0);
        assert_eq!(val, 1);
        assert_eq!(len, 3);
    }

    #[test]
    fn test_atof_basic() {
        assert!((atof(b"3.25\0") - 3.25).abs() < 1e-10);
        assert!((atof(b"-42.5\0") - (-42.5)).abs() < 1e-10);
        assert_eq!(atof(b"0\0"), 0.0);
    }

    #[test]
    fn test_strtod_basic() {
        let (val, consumed) = strtod(b"123.456abc\0");
        assert!((val - 123.456).abs() < 1e-10);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_whitespace() {
        let (val, consumed) = strtod(b"  42.0\0");
        assert!((val - 42.0).abs() < 1e-10);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_strtod_infinity() {
        let (val, consumed) = strtod(b"inf\0");
        assert!(val.is_infinite() && val > 0.0);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_strtod_nan() {
        let (val, _) = strtod(b"nan\0");
        assert!(val.is_nan());
    }

    #[test]
    fn test_strtof_basic() {
        let (val, consumed) = strtof(b"3.25\0");
        assert!((val - 3.25_f32).abs() < 1e-5);
        assert_eq!(consumed, 4);
    }

    proptest! {
        #[test]
        fn prop_strtol_round_trips_all_i64_values(value in any::<i64>()) {
            let text = value.to_string();
            let (parsed, consumed, status) = strtol_impl(text.as_bytes(), 10);
            prop_assert_eq!(parsed, value);
            prop_assert_eq!(consumed, text.len());
            prop_assert_eq!(status, ConversionStatus::Success);
        }

        #[test]
        fn prop_strtoul_round_trips_all_u64_values(value in any::<u64>()) {
            let text = value.to_string();
            let (parsed, consumed, status) = strtoul_impl(text.as_bytes(), 10);
            prop_assert_eq!(parsed, value);
            prop_assert_eq!(consumed, text.len());
            prop_assert_eq!(status, ConversionStatus::Success);
        }

        #[test]
        fn prop_invalid_bases_are_rejected(
            raw in any::<i32>(),
            input in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let is_valid = raw == 0 || (2..=36).contains(&raw);
            prop_assume!(!is_valid);

            let mut idx = 0usize;
            while idx < input.len() && input[idx].is_ascii_whitespace() {
                idx += 1;
            }
            if idx < input.len() && (input[idx] == b'+' || input[idx] == b'-') {
                idx += 1;
            }
            // strto* implementations return Success before base validation when
            // no parseable body remains after whitespace/sign consumption.
            prop_assume!(idx < input.len());

            let (_, _, status_signed) = strtol_impl(&input, raw);
            let (_, _, status_unsigned) = strtoul_impl(&input, raw);

            prop_assert_eq!(status_signed, ConversionStatus::InvalidBase);
            prop_assert_eq!(status_unsigned, ConversionStatus::InvalidBase);
        }
    }
}
