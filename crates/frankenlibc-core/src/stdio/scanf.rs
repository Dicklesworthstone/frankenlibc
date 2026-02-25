//! scanf format string parser and input scanner.
//!
//! Clean-room spec-first implementation of POSIX scanf format parsing.
//! Parses format directives and scans typed values from byte input.
//!
//! Reference: POSIX.1-2024 fscanf, ISO C11 7.21.6.2
//!
//! The engine returns a `Vec<ScanValue>` for each successfully scanned
//! non-suppressed conversion. The ABI layer writes these values through
//! the caller's va_list pointers.

use super::printf::LengthMod;

// ---------------------------------------------------------------------------
// Scan value types
// ---------------------------------------------------------------------------

/// A successfully scanned value from input.
#[derive(Debug, Clone)]
pub enum ScanValue {
    SignedInt(i64),
    UnsignedInt(u64),
    Float(f64),
    Char(Vec<u8>),
    String(Vec<u8>),
    CharsConsumed(usize),
    Pointer(usize),
}

// ---------------------------------------------------------------------------
// Scan spec types
// ---------------------------------------------------------------------------

/// A parsed scanf format directive.
#[derive(Debug, Clone)]
pub enum ScanDirective {
    /// Literal byte(s) to match.
    Literal(u8),
    /// Whitespace directive: skip zero or more whitespace chars.
    Whitespace,
    /// A conversion specifier.
    Spec(Box<ScanSpec>),
}

/// A parsed scanf conversion specifier.
#[derive(Debug, Clone)]
pub struct ScanSpec {
    pub suppress: bool,
    pub width: Option<usize>,
    pub length: LengthMod,
    pub conversion: u8,
    pub scanset: Option<ScanSet>,
}

/// Character set for %[...] specifier.
#[derive(Debug, Clone)]
pub struct ScanSet {
    pub negated: bool,
    pub chars: [bool; 256],
}

// ---------------------------------------------------------------------------
// Format string parser
// ---------------------------------------------------------------------------

/// Parse a scanf format string into a list of directives.
pub fn parse_scanf_format(fmt: &[u8]) -> Vec<ScanDirective> {
    let mut directives = Vec::new();
    let mut i = 0;

    while i < fmt.len() {
        if fmt[i] == 0 {
            break;
        }

        if fmt[i] == b'%' {
            i += 1;
            if i >= fmt.len() || fmt[i] == 0 {
                break;
            }
            if fmt[i] == b'%' {
                directives.push(ScanDirective::Literal(b'%'));
                i += 1;
                continue;
            }

            // Parse conversion specifier.
            let mut spec = ScanSpec {
                suppress: false,
                width: None,
                length: LengthMod::None,
                conversion: 0,
                scanset: None,
            };

            // Assignment suppression.
            if i < fmt.len() && fmt[i] == b'*' {
                spec.suppress = true;
                i += 1;
            }

            // Width.
            let mut w: usize = 0;
            let mut has_width = false;
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                w = w
                    .saturating_mul(10)
                    .saturating_add((fmt[i] - b'0') as usize);
                has_width = true;
                i += 1;
            }
            if has_width {
                spec.width = Some(w);
            }

            // Length modifier.
            if i < fmt.len() {
                match fmt[i] {
                    b'h' => {
                        i += 1;
                        if i < fmt.len() && fmt[i] == b'h' {
                            spec.length = LengthMod::Hh;
                            i += 1;
                        } else {
                            spec.length = LengthMod::H;
                        }
                    }
                    b'l' => {
                        i += 1;
                        if i < fmt.len() && fmt[i] == b'l' {
                            spec.length = LengthMod::Ll;
                            i += 1;
                        } else {
                            spec.length = LengthMod::L;
                        }
                    }
                    b'j' => {
                        spec.length = LengthMod::J;
                        i += 1;
                    }
                    b'z' => {
                        spec.length = LengthMod::Z;
                        i += 1;
                    }
                    b't' => {
                        spec.length = LengthMod::T;
                        i += 1;
                    }
                    b'L' => {
                        spec.length = LengthMod::BigL;
                        i += 1;
                    }
                    _ => {}
                }
            }

            // Conversion specifier.
            if i >= fmt.len() {
                break;
            }

            if fmt[i] == b'[' {
                // Parse scanset.
                i += 1;
                let mut negated = false;
                if i < fmt.len() && fmt[i] == b'^' {
                    negated = true;
                    i += 1;
                }
                let mut chars = [false; 256];
                // First char after [ or [^ can be ']'.
                if i < fmt.len() && fmt[i] == b']' {
                    chars[b']' as usize] = true;
                    i += 1;
                }
                while i < fmt.len() && fmt[i] != b']' && fmt[i] != 0 {
                    let c = fmt[i];
                    // Range: a-z.
                    if i + 2 < fmt.len() && fmt[i + 1] == b'-' && fmt[i + 2] != b']' {
                        let lo = c;
                        let hi = fmt[i + 2];
                        if lo <= hi {
                            for ch in lo..=hi {
                                chars[ch as usize] = true;
                            }
                        }
                        i += 3;
                    } else {
                        chars[c as usize] = true;
                        i += 1;
                    }
                }
                if i < fmt.len() && fmt[i] == b']' {
                    i += 1;
                }
                spec.conversion = b'[';
                spec.scanset = Some(ScanSet { negated, chars });
            } else {
                spec.conversion = fmt[i];
                i += 1;
            }

            directives.push(ScanDirective::Spec(Box::new(spec)));
        } else if fmt[i].is_ascii_whitespace() {
            directives.push(ScanDirective::Whitespace);
            i += 1;
            // Consume additional whitespace in format.
            while i < fmt.len() && fmt[i].is_ascii_whitespace() {
                i += 1;
            }
        } else {
            directives.push(ScanDirective::Literal(fmt[i]));
            i += 1;
        }
    }

    directives
}

// ---------------------------------------------------------------------------
// Input scanner
// ---------------------------------------------------------------------------

/// Scan result from the engine.
pub struct ScanResult {
    /// Successfully scanned non-suppressed values.
    pub values: Vec<ScanValue>,
    /// Number of successful assignments.
    pub count: i32,
    /// Total input bytes consumed.
    pub consumed: usize,
    /// Whether any input was consumed before matching failure.
    pub input_failure: bool,
}

/// Scan input according to parsed directives.
pub fn scan_input(input: &[u8], directives: &[ScanDirective]) -> ScanResult {
    let mut pos = 0;
    let mut values = Vec::new();
    let mut count: i32 = 0;
    let mut input_failure = true; // true until first successful read

    for dir in directives {
        match dir {
            ScanDirective::Whitespace => {
                // Skip whitespace in input.
                while pos < input.len() && input[pos].is_ascii_whitespace() {
                    pos += 1;
                }
            }
            ScanDirective::Literal(expected) => {
                if pos >= input.len() {
                    return ScanResult {
                        values,
                        count,
                        consumed: pos,
                        input_failure,
                    };
                }
                if input[pos] != *expected {
                    return ScanResult {
                        values,
                        count,
                        consumed: pos,
                        input_failure: false,
                    };
                }
                pos += 1;
            }
            ScanDirective::Spec(spec) => {
                let result = scan_one(input, pos, spec);
                match result {
                    None => {
                        // Matching failure or input exhaustion.
                        return ScanResult {
                            values,
                            count,
                            consumed: pos,
                            input_failure: pos >= input.len() && count == 0,
                        };
                    }
                    Some((val, new_pos)) => {
                        input_failure = false;
                        pos = new_pos;
                        if !spec.suppress
                            && let Some(v) = val
                        {
                            values.push(v);
                            count += 1;
                        }
                    }
                }
            }
        }
    }

    ScanResult {
        values,
        count,
        consumed: pos,
        input_failure,
    }
}

/// Scan a single conversion specifier.
/// Returns `None` on matching failure.
/// Returns `Some((value, new_pos))` on success. `value` is `None` for %n.
fn scan_one(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    match spec.conversion {
        b'd' => scan_int(input, pos, spec, 10, true),
        b'i' => scan_int_auto(input, pos, spec),
        b'u' => scan_int(input, pos, spec, 10, false),
        b'o' => scan_int(input, pos, spec, 8, false),
        b'x' | b'X' => scan_int(input, pos, spec, 16, false),
        b'f' | b'e' | b'g' | b'a' | b'E' | b'G' | b'A' | b'F' => scan_float(input, pos, spec),
        b'c' => scan_char(input, pos, spec),
        b's' => scan_string(input, pos, spec),
        b'[' => scan_scanset(input, pos, spec),
        b'n' => Some((Some(ScanValue::CharsConsumed(pos)), pos)),
        b'p' => scan_pointer(input, pos, spec),
        _ => None,
    }
}

/// Skip leading whitespace. Returns new position.
fn skip_ws(input: &[u8], mut pos: usize) -> usize {
    while pos < input.len() && input[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

/// Effective width: explicit or unlimited.
fn effective_width(spec: &ScanSpec, default: usize) -> usize {
    spec.width.unwrap_or(default)
}

/// Scan an integer with specified base. If `signed`, allow leading +/-.
fn scan_int(
    input: &[u8],
    pos: usize,
    spec: &ScanSpec,
    base: u32,
    signed: bool,
) -> Option<(Option<ScanValue>, usize)> {
    let pos = skip_ws(input, pos);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);
    let mut i = pos;
    let mut chars_read = 0usize;

    // Sign.
    let negative = if signed && i < input.len() && chars_read < max_chars {
        if input[i] == b'-' {
            i += 1;
            chars_read += 1;
            true
        } else if input[i] == b'+' {
            i += 1;
            chars_read += 1;
            false
        } else {
            false
        }
    } else if i < input.len() && chars_read < max_chars && input[i] == b'+' {
        i += 1;
        chars_read += 1;
        false
    } else {
        false
    };

    // Optional 0x/0X prefix for hex.
    if base == 16
        && i + 1 < input.len()
        && chars_read + 2 <= max_chars
        && input[i] == b'0'
        && (input[i + 1] == b'x' || input[i + 1] == b'X')
    {
        i += 2;
        chars_read += 2;
    }

    // Digits.
    let mut val: u64 = 0;
    let mut any_digit = false;
    while i < input.len() && chars_read < max_chars {
        let d = match digit_value(input[i], base) {
            Some(d) => d,
            None => break,
        };
        any_digit = true;
        val = val.wrapping_mul(base as u64).wrapping_add(d as u64);
        i += 1;
        chars_read += 1;
    }

    if !any_digit {
        return None;
    }

    let value = if signed {
        let signed_val = if negative { -(val as i64) } else { val as i64 };
        ScanValue::SignedInt(signed_val)
    } else {
        ScanValue::UnsignedInt(val)
    };

    Some((Some(value), i))
}

/// Scan integer with auto-detected base (%i: 0x=hex, 0=octal, else decimal).
fn scan_int_auto(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = skip_ws(input, pos);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);
    let mut i = pos;
    let mut chars_read = 0usize;

    // Sign.
    let negative = if i < input.len() && chars_read < max_chars {
        if input[i] == b'-' {
            i += 1;
            chars_read += 1;
            true
        } else if input[i] == b'+' {
            i += 1;
            chars_read += 1;
            false
        } else {
            false
        }
    } else {
        false
    };

    // Detect base.
    let base = if i < input.len() && chars_read < max_chars && input[i] == b'0' {
        if i + 1 < input.len()
            && chars_read + 1 < max_chars
            && (input[i + 1] == b'x' || input[i + 1] == b'X')
        {
            i += 2;
            chars_read += 2;
            16u32
        } else {
            8u32
            // Don't consume the '0' yet — it's a valid octal digit.
        }
    } else {
        10u32
    };

    // Digits.
    let mut val: u64 = 0;
    let mut any_digit = false;
    while i < input.len() && chars_read < max_chars {
        let d = match digit_value(input[i], base) {
            Some(d) => d,
            None => break,
        };
        any_digit = true;
        val = val.wrapping_mul(base as u64).wrapping_add(d as u64);
        i += 1;
        chars_read += 1;
    }

    if !any_digit {
        // For 0x with no hex digits, the '0' itself is a valid result.
        if base == 16 && i >= 2 && chars_read >= 2 {
            // Back up past the 'x'.
            return Some((Some(ScanValue::SignedInt(0)), i - 1));
        }
        return None;
    }

    let signed_val = if negative { -(val as i64) } else { val as i64 };

    Some((Some(ScanValue::SignedInt(signed_val)), i))
}

/// Convert a byte to a digit in the given base, or None.
fn digit_value(b: u8, base: u32) -> Option<u32> {
    let val = match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'a'..=b'f' => (b - b'a' + 10) as u32,
        b'A'..=b'F' => (b - b'A' + 10) as u32,
        _ => return None,
    };
    if val < base { Some(val) } else { None }
}

/// Scan a floating-point number.
fn scan_float(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = skip_ws(input, pos);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);
    let mut i = pos;
    let mut chars_read = 0usize;
    let mut buf = Vec::with_capacity(64);

    // Sign.
    if i < input.len() && chars_read < max_chars && (input[i] == b'+' || input[i] == b'-') {
        buf.push(input[i]);
        i += 1;
        chars_read += 1;
    }

    // Check for inf/infinity/nan.
    let remaining = &input[i..];
    if chars_read + 3 <= max_chars {
        if remaining.len() >= 3 && remaining[..3].eq_ignore_ascii_case(b"inf") {
            buf.extend_from_slice(b"inf");
            i += 3;
            chars_read += 3;
            if remaining.len() >= 8
                && chars_read + 5 <= max_chars
                && remaining[..8].eq_ignore_ascii_case(b"infinity")
            {
                i += 5;
            }
            let val: f64 = if buf.starts_with(b"-") {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            };
            return Some((Some(ScanValue::Float(val)), i));
        }
        if remaining.len() >= 3 && remaining[..3].eq_ignore_ascii_case(b"nan") {
            i += 3;
            return Some((Some(ScanValue::Float(f64::NAN)), i));
        }
    }

    // Digits, decimal point, exponent.
    let mut any_digit = false;
    while i < input.len() && chars_read < max_chars {
        let c = input[i];
        if c.is_ascii_digit() {
            any_digit = true;
            buf.push(c);
        } else if c == b'.' {
            buf.push(c);
        } else if (c == b'e' || c == b'E') && any_digit {
            buf.push(c);
            i += 1;
            chars_read += 1;
            // Optional exponent sign.
            if i < input.len() && chars_read < max_chars && (input[i] == b'+' || input[i] == b'-') {
                buf.push(input[i]);
                i += 1;
                chars_read += 1;
            }
            // Exponent digits.
            while i < input.len() && chars_read < max_chars && input[i].is_ascii_digit() {
                buf.push(input[i]);
                i += 1;
                chars_read += 1;
            }
            break;
        } else {
            break;
        }
        i += 1;
        chars_read += 1;
    }

    if !any_digit {
        return None;
    }

    // Parse the collected float string.
    let s = core::str::from_utf8(&buf).ok()?;
    let val: f64 = s.parse().ok()?;

    Some((Some(ScanValue::Float(val)), i))
}

/// Scan character(s) (%c). No whitespace skip. Width = number of chars.
fn scan_char(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    // %c does NOT skip whitespace.
    let n = spec.width.unwrap_or(1);
    if pos + n > input.len() {
        return None;
    }
    let chars = input[pos..pos + n].to_vec();
    Some((Some(ScanValue::Char(chars)), pos + n))
}

/// Scan a string (%s). Skips whitespace, then reads non-whitespace.
fn scan_string(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = skip_ws(input, pos);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);
    let mut i = pos;
    let mut chars_read = 0usize;
    let mut buf = Vec::new();

    while i < input.len() && chars_read < max_chars && !input[i].is_ascii_whitespace() {
        buf.push(input[i]);
        i += 1;
        chars_read += 1;
    }

    if buf.is_empty() {
        return None;
    }

    Some((Some(ScanValue::String(buf)), i))
}

/// Scan a scanset (%[...]). No whitespace skip.
fn scan_scanset(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let scanset = spec.scanset.as_ref()?;
    let max_chars = effective_width(spec, usize::MAX);
    let mut i = pos;
    let mut chars_read = 0usize;
    let mut buf = Vec::new();

    while i < input.len() && chars_read < max_chars {
        let c = input[i];
        let in_set = scanset.chars[c as usize];
        let accept = if scanset.negated { !in_set } else { in_set };
        if !accept {
            break;
        }
        buf.push(c);
        i += 1;
        chars_read += 1;
    }

    if buf.is_empty() {
        return None;
    }

    Some((Some(ScanValue::String(buf)), i))
}

/// Scan a pointer (%p). Expects 0xHEX or (nil).
fn scan_pointer(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = skip_ws(input, pos);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);

    // Check for "(nil)".
    if input[pos..].starts_with(b"(nil)") && max_chars >= 5 {
        return Some((Some(ScanValue::Pointer(0)), pos + 5));
    }

    // Expect 0x prefix.
    if pos + 2 > input.len()
        || input[pos] != b'0'
        || (input[pos + 1] != b'x' && input[pos + 1] != b'X')
    {
        return None;
    }

    let mut i = pos + 2;
    let mut chars_read = 2usize;
    let mut val: usize = 0;
    let mut any_digit = false;

    while i < input.len() && chars_read < max_chars {
        let d = match digit_value(input[i], 16) {
            Some(d) => d,
            None => break,
        };
        any_digit = true;
        val = val.wrapping_mul(16).wrapping_add(d as usize);
        i += 1;
        chars_read += 1;
    }

    if !any_digit {
        return None;
    }

    Some((Some(ScanValue::Pointer(val)), i))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_format() {
        let dirs = parse_scanf_format(b"%d %s");
        assert_eq!(dirs.len(), 3); // %d, whitespace, %s
    }

    #[test]
    fn test_parse_percent_escape() {
        let dirs = parse_scanf_format(b"%%");
        assert_eq!(dirs.len(), 1);
        assert!(matches!(dirs[0], ScanDirective::Literal(b'%')));
    }

    #[test]
    fn test_parse_scanset() {
        let dirs = parse_scanf_format(b"%[abc]");
        assert_eq!(dirs.len(), 1);
        if let ScanDirective::Spec(ref s) = dirs[0] {
            assert_eq!(s.conversion, b'[');
            let ss = s.scanset.as_ref().unwrap();
            assert!(!ss.negated);
            assert!(ss.chars[b'a' as usize]);
            assert!(ss.chars[b'b' as usize]);
            assert!(ss.chars[b'c' as usize]);
            assert!(!ss.chars[b'd' as usize]);
        } else {
            panic!("expected Spec");
        }
    }

    #[test]
    fn test_parse_negated_scanset() {
        let dirs = parse_scanf_format(b"%[^abc]");
        if let ScanDirective::Spec(ref s) = dirs[0] {
            let ss = s.scanset.as_ref().unwrap();
            assert!(ss.negated);
            assert!(ss.chars[b'a' as usize]);
        } else {
            panic!("expected Spec");
        }
    }

    #[test]
    fn test_parse_width_and_suppress() {
        let dirs = parse_scanf_format(b"%*5d");
        if let ScanDirective::Spec(ref s) = dirs[0] {
            assert!(s.suppress);
            assert_eq!(s.width, Some(5));
            assert_eq!(s.conversion, b'd');
        } else {
            panic!("expected Spec");
        }
    }

    #[test]
    fn test_parse_length_modifiers() {
        let dirs = parse_scanf_format(b"%ld %hhu %lld %zu");
        let specs: Vec<_> = dirs
            .iter()
            .filter_map(|d| {
                if let ScanDirective::Spec(s) = d {
                    Some(s)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(specs.len(), 4);
        assert!(matches!(specs[0].length, LengthMod::L));
        assert!(matches!(specs[1].length, LengthMod::Hh));
        assert!(matches!(specs[2].length, LengthMod::Ll));
        assert!(matches!(specs[3].length, LengthMod::Z));
    }

    #[test]
    fn test_scan_int_decimal() {
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"42", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(42)));
    }

    #[test]
    fn test_scan_int_negative() {
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"-123", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(-123)));
    }

    #[test]
    fn test_scan_unsigned() {
        let dirs = parse_scanf_format(b"%u");
        let result = scan_input(b"999", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::UnsignedInt(999)));
    }

    #[test]
    fn test_scan_hex() {
        let dirs = parse_scanf_format(b"%x");
        let result = scan_input(b"0xFF", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::UnsignedInt(255)));
    }

    #[test]
    fn test_scan_octal() {
        let dirs = parse_scanf_format(b"%o");
        let result = scan_input(b"77", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::UnsignedInt(63)));
    }

    #[test]
    fn test_scan_auto_int_hex() {
        let dirs = parse_scanf_format(b"%i");
        let result = scan_input(b"0x1a", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(26)));
    }

    #[test]
    fn test_scan_auto_int_octal() {
        let dirs = parse_scanf_format(b"%i");
        let result = scan_input(b"010", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(8)));
    }

    #[test]
    fn test_scan_string() {
        let dirs = parse_scanf_format(b"%s");
        let result = scan_input(b"hello world", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::String(ref s) = result.values[0] {
            assert_eq!(s, b"hello");
        } else {
            panic!("expected String");
        }
    }

    #[test]
    fn test_scan_char() {
        let dirs = parse_scanf_format(b"%c");
        let result = scan_input(b"A", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Char(ref c) = result.values[0] {
            assert_eq!(c, b"A");
        } else {
            panic!("expected Char");
        }
    }

    #[test]
    fn test_scan_multi_char() {
        let dirs = parse_scanf_format(b"%3c");
        let result = scan_input(b"ABC", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Char(ref c) = result.values[0] {
            assert_eq!(c, b"ABC");
        } else {
            panic!("expected Char");
        }
    }

    #[test]
    fn test_scan_float() {
        let dirs = parse_scanf_format(b"%f");
        let result = scan_input(b"3.25", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 3.25).abs() < 1e-10);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_float_scientific() {
        let dirs = parse_scanf_format(b"%e");
        let result = scan_input(b"1.5e2", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 150.0).abs() < 1e-10);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_multiple() {
        let dirs = parse_scanf_format(b"%d %d %d");
        let result = scan_input(b"1 2 3", &dirs);
        assert_eq!(result.count, 3);
        assert!(matches!(result.values[0], ScanValue::SignedInt(1)));
        assert!(matches!(result.values[1], ScanValue::SignedInt(2)));
        assert!(matches!(result.values[2], ScanValue::SignedInt(3)));
    }

    #[test]
    fn test_scan_suppress() {
        let dirs = parse_scanf_format(b"%*d %d");
        let result = scan_input(b"10 20", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(20)));
    }

    #[test]
    fn test_scan_width_limit() {
        let dirs = parse_scanf_format(b"%2d%2d");
        let result = scan_input(b"1234", &dirs);
        assert_eq!(result.count, 2);
        assert!(matches!(result.values[0], ScanValue::SignedInt(12)));
        assert!(matches!(result.values[1], ScanValue::SignedInt(34)));
    }

    #[test]
    fn test_scan_scanset() {
        let dirs = parse_scanf_format(b"%[a-z]");
        let result = scan_input(b"hello123", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::String(ref s) = result.values[0] {
            assert_eq!(s, b"hello");
        } else {
            panic!("expected String");
        }
    }

    #[test]
    fn test_scan_negated_scanset() {
        let dirs = parse_scanf_format(b"%[^\n]");
        let result = scan_input(b"hello world\n", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::String(ref s) = result.values[0] {
            assert_eq!(s, b"hello world");
        } else {
            panic!("expected String");
        }
    }

    #[test]
    fn test_scan_n() {
        let dirs = parse_scanf_format(b"%d%n");
        let result = scan_input(b"42", &dirs);
        assert_eq!(result.count, 2);
        assert!(matches!(result.values[0], ScanValue::SignedInt(42)));
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(2)));
    }

    #[test]
    fn test_scan_literal_matching() {
        let dirs = parse_scanf_format(b"x=%d");
        let result = scan_input(b"x=42", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(42)));
    }

    #[test]
    fn test_scan_literal_mismatch() {
        let dirs = parse_scanf_format(b"x=%d");
        let result = scan_input(b"y=42", &dirs);
        assert_eq!(result.count, 0);
    }

    #[test]
    fn test_scan_pointer() {
        let dirs = parse_scanf_format(b"%p");
        let result = scan_input(b"0xdeadbeef", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::Pointer(0xdeadbeef)));
    }

    #[test]
    fn test_scan_empty_input() {
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"", &dirs);
        assert_eq!(result.count, 0);
        assert!(result.input_failure);
    }

    #[test]
    fn test_scan_string_with_width() {
        let dirs = parse_scanf_format(b"%5s");
        let result = scan_input(b"helloworld", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::String(ref s) = result.values[0] {
            assert_eq!(s, b"hello");
        } else {
            panic!("expected String");
        }
    }

    #[test]
    fn test_scan_mixed_types() {
        let dirs = parse_scanf_format(b"%s %d %f");
        let result = scan_input(b"test 42 3.25", &dirs);
        assert_eq!(result.count, 3);
        if let ScanValue::String(ref s) = result.values[0] {
            assert_eq!(s, b"test");
        }
        assert!(matches!(result.values[1], ScanValue::SignedInt(42)));
        if let ScanValue::Float(v) = result.values[2] {
            assert!((v - 3.25).abs() < 1e-10);
        }
    }

    #[test]
    fn test_scan_inf_nan() {
        let dirs = parse_scanf_format(b"%f");
        let result = scan_input(b"inf", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!(v.is_infinite() && v > 0.0);
        }

        let result2 = scan_input(b"nan", &dirs);
        assert_eq!(result2.count, 1);
        if let ScanValue::Float(v) = result2.values[0] {
            assert!(v.is_nan());
        }
    }
}
