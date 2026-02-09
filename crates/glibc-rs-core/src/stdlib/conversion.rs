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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atoi_basic() {
        assert_eq!(atoi(b"42"), 42);
        assert_eq!(atoi(b"-42"), -42);
        assert_eq!(atoi(b"   123"), 123);
    }

    #[test]
    fn test_strtol_base10() {
        let (val, len) = strtol(b"123456", 10);
        assert_eq!(val, 123456);
        assert_eq!(len, 6);
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
}
