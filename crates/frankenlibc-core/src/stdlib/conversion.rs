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
    // POSIX SUSv4: atoi(str) ≡ (int) strtol(str, NULL, 10). The cast
    // on 2's-complement targets (all supported archs) is a
    // truncation, not a saturating clamp. The earlier clamp-to-
    // INT_MAX logic diverged from glibc's observable behavior on
    // overflow and tripped fuzz_stdlib's atoi-vs-strtol parity
    // assertion (bd-ie8zc). C standard leaves overflow UB; POSIX
    // pins it down to the (int)long_val cast result.
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

/// Convert a single ASCII hex digit to its numeric value (0-15).
/// Caller must ensure `c.is_ascii_hexdigit()`.
fn hex_digit_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

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
        let special_sign: f64 = if start < slice.len() && slice[start] == b'-' {
            -1.0
        } else {
            1.0
        };
        if word.eq_ignore_ascii_case(b"inf") {
            i += 3;
            if i + 5 <= slice.len() && slice[i..i + 5].eq_ignore_ascii_case(b"inity") {
                i += 5;
            }
            return (special_sign * f64::INFINITY, i);
        }
        if word.eq_ignore_ascii_case(b"nan") {
            i += 3;
            // Preserve sign bit: -NaN and +NaN are distinct per IEEE 754.
            // Cannot use `special_sign * NAN` — IEEE 754 §6.3 says the sign
            // of a NaN result from arithmetic is undefined.  Use direct bit
            // manipulation to set the sign bit reliably.
            let nan = if special_sign < 0.0 {
                f64::from_bits(f64::NAN.to_bits() | (1u64 << 63))
            } else {
                f64::NAN
            };
            return (nan, i);
        }
    }

    // Check for hex float (0x...)
    let is_hex =
        i + 1 < slice.len() && slice[i] == b'0' && (slice[i + 1] == b'x' || slice[i + 1] == b'X');

    if is_hex {
        // Parse hex floating-point: [sign] 0x hex_significand [p binary_exponent]
        // sign was already consumed; `start` marks where sign (or first digit) began.
        let negative = start < slice.len() && slice[start] == b'-';
        i += 2; // skip "0x" / "0X"

        // Parse integer part of hex significand
        let mut significand: f64 = 0.0;
        let mut has_digits = false;

        while i < slice.len() && slice[i].is_ascii_hexdigit() {
            has_digits = true;
            significand = significand * 16.0 + hex_digit_val(slice[i]) as f64;
            i += 1;
        }

        // Parse fractional part
        let mut frac_hex_digits: i32 = 0;
        if i < slice.len() && slice[i] == b'.' {
            i += 1;
            while i < slice.len() && slice[i].is_ascii_hexdigit() {
                has_digits = true;
                frac_hex_digits = frac_hex_digits.saturating_add(1);
                significand = significand * 16.0 + hex_digit_val(slice[i]) as f64;
                i += 1;
            }
        }

        if !has_digits {
            // No hex digits after "0x" — the "0" before "x" is a valid
            // decimal number. Rewind past the 'x'/'X' so the consumed
            // count covers only the leading '0' (and any sign/whitespace).
            // i was advanced by 2 for "0x", so i-1 points at the 'x'.
            return (0.0, i - 1);
        }

        // Parse binary exponent (p/P followed by optional sign and decimal digits)
        let mut bin_exp: i32 = 0;
        if i < slice.len() && (slice[i] == b'p' || slice[i] == b'P') {
            i += 1;
            let mut exp_neg = false;
            if i < slice.len() && slice[i] == b'+' {
                i += 1;
            } else if i < slice.len() && slice[i] == b'-' {
                exp_neg = true;
                i += 1;
            }
            while i < slice.len() && slice[i].is_ascii_digit() {
                bin_exp = bin_exp
                    .saturating_mul(10)
                    .saturating_add((slice[i] - b'0') as i32);
                i += 1;
            }
            if exp_neg {
                bin_exp = -bin_exp;
            }
        }

        // Each hex fractional digit shifts by 4 binary positions, so adjust.
        // result = significand * 2^(bin_exp - 4 * frac_hex_digits)
        let effective_exp = bin_exp.saturating_sub(frac_hex_digits.saturating_mul(4));
        let val = libm::ldexp(significand, effective_exp);

        let val = if negative { -val } else { val };
        return (val, i);
    }

    // Decimal float path
    // Consume digits, decimal point, exponent.
    let mut has_digits = false;
    while i < slice.len() && slice[i].is_ascii_digit() {
        has_digits = true;
        i += 1;
    }
    if i < slice.len() && slice[i] == b'.' {
        i += 1;
        while i < slice.len() && slice[i].is_ascii_digit() {
            has_digits = true;
            i += 1;
        }
    }
    if !has_digits {
        return (0.0, 0);
    }
    // Exponent
    if i < slice.len() && (slice[i] == b'e' || slice[i] == b'E') {
        let saved_i = i;
        i += 1;
        if i < slice.len() && (slice[i] == b'+' || slice[i] == b'-') {
            i += 1;
        }
        let mut has_exp_digits = false;
        while i < slice.len() && slice[i].is_ascii_digit() {
            has_exp_digits = true;
            i += 1;
        }
        if !has_exp_digits {
            i = saved_i;
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
    use proptest::test_runner::Config as ProptestConfig;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

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
        // Positive NaN: sign bit should be clear.
        assert_eq!(val.to_bits() >> 63, 0, "plain nan should be positive");
    }

    #[test]
    fn test_strtod_negative_nan() {
        let (val, consumed) = strtod(b"-nan\0");
        assert!(val.is_nan());
        assert_eq!(consumed, 4);
        // Negative NaN: sign bit must be set (IEEE 754 sign-bit semantics).
        assert_eq!(val.to_bits() >> 63, 1, "-nan must have sign bit set");
    }

    #[test]
    fn test_strtof_basic() {
        let (val, consumed) = strtof(b"3.25\0");
        assert!((val - 3.25_f32).abs() < 1e-5);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_strtod_hex_float_basic() {
        // 0x1p0 = 1.0 * 2^0 = 1.0
        let (val, consumed) = strtod(b"0x1p0\0");
        assert_eq!(val, 1.0);
        assert_eq!(consumed, 5);

        // 0x1p1 = 1.0 * 2^1 = 2.0
        let (val, consumed) = strtod(b"0x1p1\0");
        assert_eq!(val, 2.0);
        assert_eq!(consumed, 5);

        // 0x1p-3 = 1.0 * 2^-3 = 0.125
        let (val, consumed) = strtod(b"0x1p-3\0");
        assert_eq!(val, 0.125);
        assert_eq!(consumed, 6);

        // 0xAp0 = 10.0
        let (val, _) = strtod(b"0xAp0\0");
        assert_eq!(val, 10.0);
    }

    #[test]
    fn test_strtod_hex_float_fractional() {
        // 0x1.0p0 = 1.0
        let (val, consumed) = strtod(b"0x1.0p0\0");
        assert_eq!(val, 1.0);
        assert_eq!(consumed, 7);

        // 0x1.8p0 = 1.5 (0x1 = 1, .8 = 8/16 = 0.5)
        let (val, _) = strtod(b"0x1.8p0\0");
        assert_eq!(val, 1.5);

        // 0x1.fp10 = (1 + 15/16) * 2^10 = 1.9375 * 1024 = 1984.0
        let (val, consumed) = strtod(b"0x1.fp10\0");
        assert_eq!(val, 1984.0);
        assert_eq!(consumed, 8);

        // 0xA.Bp5 = (10 + 11/16) * 2^5 = 10.6875 * 32 = 342.0
        let (val, consumed) = strtod(b"0xA.Bp5\0");
        assert_eq!(val, 342.0);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_hex_float_negative() {
        // -0x1.0p0 = -1.0
        let (val, consumed) = strtod(b"-0x1.0p0\0");
        assert_eq!(val, -1.0);
        assert_eq!(consumed, 8);

        // -0x1.fp10 = -1984.0
        let (val, _) = strtod(b"-0x1.fp10\0");
        assert_eq!(val, -1984.0);
    }

    #[test]
    fn test_strtod_hex_float_no_exponent() {
        // 0xff = 255.0 (no p exponent, binary exponent defaults to 0)
        let (val, consumed) = strtod(b"0xff\0");
        assert_eq!(val, 255.0);
        assert_eq!(consumed, 4);

        // 0x1.8 = 1.5
        let (val, consumed) = strtod(b"0x1.8\0");
        assert_eq!(val, 1.5);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_strtod_hex_float_uppercase() {
        // 0X1P10 = 1024.0
        let (val, consumed) = strtod(b"0X1P10\0");
        assert_eq!(val, 1024.0);
        assert_eq!(consumed, 6);

        // 0X1.FP10 = 1984.0
        let (val, _) = strtod(b"0X1.FP10\0");
        assert_eq!(val, 1984.0);
    }

    #[test]
    fn test_strtod_hex_float_trailing_chars() {
        // "0x1.8p1xyz" should parse "0x1.8p1" = 3.0, consumed = 7
        let (val, consumed) = strtod(b"0x1.8p1xyz\0");
        assert_eq!(val, 3.0);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_hex_float_with_leading_whitespace() {
        let (val, consumed) = strtod(b"  0x1p2\0");
        assert_eq!(val, 4.0);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_strtod_0x_without_hex_digits_parses_zero() {
        // "0x" with no hex digits: the '0' is a valid decimal number.
        // Per C standard, strtod should parse '0' and leave endptr at 'x'.
        let (val, consumed) = strtod(b"0x\0");
        assert_eq!(val, 0.0);
        assert_eq!(consumed, 1, "should consume only the '0', not the 'x'");
    }

    #[test]
    fn test_strtod_0x_trailing_non_hex() {
        let (val, consumed) = strtod(b"0xGHI\0");
        assert_eq!(val, 0.0);
        assert_eq!(consumed, 1, "no hex digits after 0x → parse '0' only");
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

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
