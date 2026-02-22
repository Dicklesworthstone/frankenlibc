//! printf formatting engine.
//!
//! Clean-room spec-first implementation of the POSIX printf format string
//! interpreter. Parses format directives and renders typed arguments to
//! byte buffers with full width/precision/flag support.
//!
//! Reference: POSIX.1-2024 fprintf, ISO C11 7.21.6.1
//!
//! Design invariant: all formatting is bounded — no allocation can grow
//! unboundedly from a single format specifier. Maximum expansion per
//! specifier is `width + precision + 64` bytes (sign + prefix + digits).

// ---------------------------------------------------------------------------
// Format spec types
// ---------------------------------------------------------------------------

/// Flags parsed from a printf format directive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FormatFlags {
    pub left_justify: bool, // '-'
    pub force_sign: bool,   // '+'
    pub space_sign: bool,   // ' '
    pub alt_form: bool,     // '#'
    pub zero_pad: bool,     // '0'
}

/// Width specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    None,
    Fixed(usize),
    FromArg, // '*'
}

/// Precision specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precision {
    None,
    Fixed(usize),
    FromArg, // '.*'
}

/// Length modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthMod {
    None,
    Hh,   // 'hh'
    H,    // 'h'
    L,    // 'l'
    Ll,   // 'll'
    Z,    // 'z'
    T,    // 't'
    J,    // 'j'
    BigL, // 'L'
}

/// A parsed printf format specifier.
#[derive(Debug, Clone)]
pub struct FormatSpec {
    pub flags: FormatFlags,
    pub width: Width,
    pub precision: Precision,
    pub length: LengthMod,
    pub conversion: u8,
}

// ---------------------------------------------------------------------------
// Format argument types (for safe rendering)
// ---------------------------------------------------------------------------

/// Typed argument value for safe formatting.
///
/// String arguments are handled out-of-band (as byte slices) since they
/// cannot be owned by this fixed-size enum.
#[derive(Debug, Clone, Copy)]
pub enum FormatArg {
    SignedInt(i64),
    UnsignedInt(u64),
    Float(f64),
    Char(u8),
    Pointer(usize),
}

// ---------------------------------------------------------------------------
// Segment: parsed pieces of a format string
// ---------------------------------------------------------------------------

/// A segment of a parsed format string.
#[derive(Debug, Clone)]
pub enum FormatSegment<'a> {
    /// Literal bytes to emit verbatim.
    Literal(&'a [u8]),
    /// A `%%` escape (emit a single '%').
    Percent,
    /// A conversion specifier requiring an argument.
    Spec(FormatSpec),
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a single format specifier starting after the '%' character.
///
/// `fmt` points to the first byte AFTER '%'. Returns `(spec, bytes_consumed)`
/// where `bytes_consumed` counts from `fmt[0]`. Returns `None` if malformed.
pub fn parse_format_spec(fmt: &[u8]) -> Option<(FormatSpec, usize)> {
    let mut pos = 0;
    let len = fmt.len();

    // --- flags ---
    let mut flags = FormatFlags::default();
    while pos < len {
        match fmt[pos] {
            b'-' => flags.left_justify = true,
            b'+' => flags.force_sign = true,
            b' ' => flags.space_sign = true,
            b'#' => flags.alt_form = true,
            b'0' => flags.zero_pad = true,
            _ => break,
        }
        pos += 1;
    }
    // POSIX: '+' overrides ' '; '-' overrides '0'.
    if flags.force_sign {
        flags.space_sign = false;
    }
    if flags.left_justify {
        flags.zero_pad = false;
    }

    // --- width ---
    let width = if pos < len && fmt[pos] == b'*' {
        pos += 1;
        Width::FromArg
    } else {
        let start = pos;
        while pos < len && fmt[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos > start {
            Width::Fixed(parse_decimal(&fmt[start..pos]))
        } else {
            Width::None
        }
    };

    // --- precision ---
    let precision = if pos < len && fmt[pos] == b'.' {
        pos += 1;
        if pos < len && fmt[pos] == b'*' {
            pos += 1;
            Precision::FromArg
        } else {
            let start = pos;
            while pos < len && fmt[pos].is_ascii_digit() {
                pos += 1;
            }
            Precision::Fixed(if pos > start {
                parse_decimal(&fmt[start..pos])
            } else {
                0
            })
        }
    } else {
        Precision::None
    };

    // --- length modifier ---
    let length = if pos < len {
        match fmt[pos] {
            b'h' => {
                pos += 1;
                if pos < len && fmt[pos] == b'h' {
                    pos += 1;
                    LengthMod::Hh
                } else {
                    LengthMod::H
                }
            }
            b'l' => {
                pos += 1;
                if pos < len && fmt[pos] == b'l' {
                    pos += 1;
                    LengthMod::Ll
                } else {
                    LengthMod::L
                }
            }
            b'z' => {
                pos += 1;
                LengthMod::Z
            }
            b't' => {
                pos += 1;
                LengthMod::T
            }
            b'j' => {
                pos += 1;
                LengthMod::J
            }
            b'L' => {
                pos += 1;
                LengthMod::BigL
            }
            _ => LengthMod::None,
        }
    } else {
        LengthMod::None
    };

    // --- conversion specifier ---
    if pos >= len {
        return None;
    }
    let conversion = fmt[pos];
    pos += 1;

    match conversion {
        b'd' | b'i' | b'u' | b'x' | b'X' | b'o' | b's' | b'c' | b'p' | b'n' | b'%' | b'f'
        | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {}
        _ => return None,
    }

    Some((
        FormatSpec {
            flags,
            width,
            precision,
            length,
            conversion,
        },
        pos,
    ))
}

/// Iterate over segments of a printf format string.
///
/// Yields `FormatSegment::Literal` for literal runs and `FormatSegment::Spec`
/// for each `%`-directive. `%%` yields `FormatSegment::Percent`.
pub fn parse_format_string(fmt: &[u8]) -> Vec<FormatSegment<'_>> {
    let mut segments = Vec::new();
    let mut pos = 0;
    let len = fmt.len();

    while pos < len {
        // Find the next '%' or end of string.
        let start = pos;
        while pos < len && fmt[pos] != b'%' {
            pos += 1;
        }
        if pos > start {
            segments.push(FormatSegment::Literal(&fmt[start..pos]));
        }
        if pos >= len {
            break;
        }
        // Skip the '%'.
        pos += 1;
        if pos >= len {
            // Trailing '%' with nothing after — treat as literal.
            segments.push(FormatSegment::Literal(&fmt[pos - 1..pos]));
            break;
        }
        if fmt[pos] == b'%' {
            segments.push(FormatSegment::Percent);
            pos += 1;
            continue;
        }
        if let Some((spec, consumed)) = parse_format_spec(&fmt[pos..]) {
            pos += consumed;
            segments.push(FormatSegment::Spec(spec));
        } else {
            // Malformed spec — emit the '%' as literal and continue.
            segments.push(FormatSegment::Literal(&fmt[pos - 1..pos]));
        }
    }
    segments
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

/// Render a signed integer to `buf` according to `spec`.
pub fn format_signed(value: i64, spec: &FormatSpec, buf: &mut Vec<u8>) {
    let negative = value < 0;
    let abs = if negative {
        (value as i128).unsigned_abs() as u64
    } else {
        value as u64
    };

    let (base, uppercase) = int_base(spec.conversion);
    let mut digits = [0u8; 64];
    let digit_count = render_digits(abs, base, uppercase, &mut digits);
    let digit_slice = &digits[64 - digit_count..];

    // Determine sign character.
    let sign = if negative {
        Some(b'-')
    } else if spec.flags.force_sign {
        Some(b'+')
    } else if spec.flags.space_sign {
        Some(b' ')
    } else {
        None
    };

    // Precision: minimum digits (pad with zeros).
    let precision = match spec.precision {
        Precision::Fixed(p) => p,
        _ => 1, // default: at least 1 digit
    };
    let zero_prefix_count = precision.saturating_sub(digit_count);

    // Alternate form prefix.
    let prefix = alt_prefix(spec);

    // Total content width.
    let content_len = sign.is_some() as usize + prefix.len() + zero_prefix_count + digit_count;

    // Handle explicit precision 0 with value 0: no digits emitted.
    let suppress_zero = value == 0 && matches!(spec.precision, Precision::Fixed(0));

    let effective_content = if suppress_zero {
        sign.is_some() as usize + prefix.len()
    } else {
        content_len
    };

    let width = resolve_width(spec);
    let pad_total = width.saturating_sub(effective_content);

    let has_precision = !matches!(spec.precision, Precision::None);
    let zero_pad = spec.flags.zero_pad && !has_precision;

    // Emit.
    if !spec.flags.left_justify && !zero_pad {
        pad(buf, b' ', pad_total);
    }
    if let Some(s) = sign {
        buf.push(s);
    }
    buf.extend_from_slice(prefix);
    if !spec.flags.left_justify && zero_pad {
        pad(buf, b'0', pad_total);
    }
    if !suppress_zero {
        pad(buf, b'0', zero_prefix_count);
        buf.extend_from_slice(digit_slice);
    }
    if spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
}

/// Render an unsigned integer to `buf` according to `spec`.
pub fn format_unsigned(value: u64, spec: &FormatSpec, buf: &mut Vec<u8>) {
    let (base, uppercase) = int_base(spec.conversion);
    let mut digits = [0u8; 64];
    let digit_count = render_digits(value, base, uppercase, &mut digits);
    let digit_slice = &digits[64 - digit_count..];

    let precision = match spec.precision {
        Precision::Fixed(p) => p,
        _ => 1,
    };
    let zero_prefix_count = precision.saturating_sub(digit_count);

    let prefix = if value != 0 {
        alt_prefix(spec)
    } else {
        b"" as &[u8]
    };

    let content_len = prefix.len() + zero_prefix_count + digit_count;

    let suppress_zero = value == 0 && matches!(spec.precision, Precision::Fixed(0));
    let effective_content = if suppress_zero {
        prefix.len()
    } else {
        content_len
    };

    let width = resolve_width(spec);
    let pad_total = width.saturating_sub(effective_content);

    let has_precision = !matches!(spec.precision, Precision::None);
    let zero_pad = spec.flags.zero_pad && !has_precision;

    if !spec.flags.left_justify && !zero_pad {
        pad(buf, b' ', pad_total);
    }
    buf.extend_from_slice(prefix);
    if !spec.flags.left_justify && zero_pad {
        pad(buf, b'0', pad_total);
    }
    if !suppress_zero {
        pad(buf, b'0', zero_prefix_count);
        buf.extend_from_slice(digit_slice);
    }
    if spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
}

/// Render a floating-point value to `buf` according to `spec`.
///
/// Supports `%f`/`%F`, `%e`/`%E`, and `%g`/`%G` conversions.
/// Uses Rust's `format!` machinery internally for digit generation,
/// then applies POSIX width/flag rules.
pub fn format_float(value: f64, spec: &FormatSpec, buf: &mut Vec<u8>) {
    let precision = match spec.precision {
        Precision::Fixed(p) => p,
        Precision::None => 6, // POSIX default
        Precision::FromArg => 6,
    };

    // Handle special values.
    if value.is_nan() {
        let s = if spec.conversion.is_ascii_uppercase() {
            b"NAN"
        } else {
            b"nan"
        };
        return format_float_special(s, spec, buf);
    }
    if value.is_infinite() {
        let s = if spec.conversion.is_ascii_uppercase() {
            if value > 0.0 {
                b"INF" as &[u8]
            } else {
                b"-INF" as &[u8]
            }
        } else if value > 0.0 {
            b"inf" as &[u8]
        } else {
            b"-inf" as &[u8]
        };
        return format_float_special(s, spec, buf);
    }

    let negative = value.is_sign_negative();
    let abs = value.abs();

    // Generate digit string.
    let body = match spec.conversion | 0x20 {
        b'f' => format_f(abs, precision, spec.flags.alt_form),
        b'e' => format_e(
            abs,
            precision,
            spec.conversion.is_ascii_uppercase(),
            spec.flags.alt_form,
        ),
        b'g' => format_g(
            abs,
            precision,
            spec.conversion.is_ascii_uppercase(),
            spec.flags.alt_form,
        ),
        _ => format_f(abs, precision, spec.flags.alt_form),
    };

    let sign = if negative {
        Some(b'-')
    } else if spec.flags.force_sign {
        Some(b'+')
    } else if spec.flags.space_sign {
        Some(b' ')
    } else {
        None
    };

    let content_len = sign.is_some() as usize + body.len();
    let width = resolve_width(spec);
    let pad_total = width.saturating_sub(content_len);

    if !spec.flags.left_justify && !spec.flags.zero_pad {
        pad(buf, b' ', pad_total);
    }
    if let Some(s) = sign {
        buf.push(s);
    }
    if !spec.flags.left_justify && spec.flags.zero_pad {
        pad(buf, b'0', pad_total);
    }
    buf.extend_from_slice(body.as_bytes());
    if spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
}

/// Render a string argument to `buf` according to `spec`.
///
/// `s` is the raw byte content (may not be NUL-terminated).
/// Precision truncates the string if set.
pub fn format_str(s: &[u8], spec: &FormatSpec, buf: &mut Vec<u8>) {
    let max_len = match spec.precision {
        Precision::Fixed(p) => p,
        _ => s.len(),
    };
    let effective = &s[..s.len().min(max_len)];
    let width = resolve_width(spec);
    let pad_total = width.saturating_sub(effective.len());

    if !spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
    buf.extend_from_slice(effective);
    if spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
}

/// Render a character to `buf` according to `spec`.
pub fn format_char(c: u8, spec: &FormatSpec, buf: &mut Vec<u8>) {
    let width = resolve_width(spec);
    let pad_total = width.saturating_sub(1);

    if !spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
    buf.push(c);
    if spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
}

/// Render a pointer to `buf` as `0x...` hex.
pub fn format_pointer(addr: usize, spec: &FormatSpec, buf: &mut Vec<u8>) {
    if addr == 0 {
        let s = b"(nil)";
        let width = resolve_width(spec);
        let pad_total = width.saturating_sub(s.len());
        if !spec.flags.left_justify {
            pad(buf, b' ', pad_total);
        }
        buf.extend_from_slice(s);
        if spec.flags.left_justify {
            pad(buf, b' ', pad_total);
        }
        return;
    }

    let mut digits = [0u8; 64];
    let count = render_digits(addr as u64, 16, false, &mut digits);
    let digit_slice = &digits[64 - count..];
    let content_len = 2 + count; // "0x" + digits
    let width = resolve_width(spec);
    let pad_total = width.saturating_sub(content_len);

    if !spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
    buf.extend_from_slice(b"0x");
    buf.extend_from_slice(digit_slice);
    if spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_decimal(digits: &[u8]) -> usize {
    let mut result = 0_usize;
    for &d in digits {
        result = result
            .saturating_mul(10)
            .saturating_add((d - b'0') as usize);
    }
    result
}

fn resolve_width(spec: &FormatSpec) -> usize {
    match spec.width {
        Width::Fixed(w) => w,
        _ => 0,
    }
}

fn int_base(conversion: u8) -> (u64, bool) {
    match conversion {
        b'o' => (8, false),
        b'x' => (16, false),
        b'X' => (16, true),
        _ => (10, false),
    }
}

/// Render `value` in the given `base` into the END of `buf`.
/// Returns the number of digits written. Digits are placed right-aligned.
fn render_digits(mut value: u64, base: u64, uppercase: bool, buf: &mut [u8; 64]) -> usize {
    if value == 0 {
        buf[63] = b'0';
        return 1;
    }
    let alpha = if uppercase { b'A' } else { b'a' };
    let mut pos = 64;
    while value > 0 && pos > 0 {
        pos -= 1;
        let digit = (value % base) as u8;
        buf[pos] = if digit < 10 {
            b'0' + digit
        } else {
            alpha + (digit - 10)
        };
        value /= base;
    }
    64 - pos
}

fn alt_prefix(spec: &FormatSpec) -> &'static [u8] {
    if !spec.flags.alt_form {
        return b"";
    }
    match spec.conversion {
        b'o' => b"0",
        b'x' => b"0x",
        b'X' => b"0X",
        _ => b"",
    }
}

fn pad(buf: &mut Vec<u8>, byte: u8, count: usize) {
    // Bounded: maximum pad from width spec.
    let count = count.min(4096);
    for _ in 0..count {
        buf.push(byte);
    }
}

/// Format a special float value (nan/inf) with width/flags.
fn format_float_special(s: &[u8], spec: &FormatSpec, buf: &mut Vec<u8>) {
    let width = resolve_width(spec);
    let pad_total = width.saturating_sub(s.len());
    if !spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
    buf.extend_from_slice(s);
    if spec.flags.left_justify {
        pad(buf, b' ', pad_total);
    }
}

/// `%f` / `%F` formatting: fixed-point decimal.
fn format_f(value: f64, precision: usize, alt_form: bool) -> String {
    if precision == 0 {
        let int_part = value as u64;
        if alt_form {
            alloc::format!("{}.", int_part)
        } else {
            alloc::format!("{}", int_part)
        }
    } else {
        alloc::format!("{:.prec$}", value, prec = precision)
    }
}

/// `%e` / `%E` formatting: scientific notation.
fn format_e(value: f64, precision: usize, uppercase: bool, _alt_form: bool) -> String {
    if value == 0.0 {
        let e_char = if uppercase { 'E' } else { 'e' };
        if precision == 0 {
            return alloc::format!("0{e_char}+00");
        }
        let zeros: String = core::iter::repeat_n('0', precision).collect();
        return alloc::format!("0.{zeros}{e_char}+00");
    }
    let exp = value.log10().floor() as i32;
    let mantissa = value / 10_f64.powi(exp);
    let e_char = if uppercase { 'E' } else { 'e' };
    let sign = if exp < 0 { '-' } else { '+' };
    let abs_exp = exp.unsigned_abs();
    if precision == 0 {
        alloc::format!("{}{e_char}{sign}{abs_exp:02}", mantissa.round() as u64)
    } else {
        alloc::format!(
            "{:.prec$}{e_char}{sign}{abs_exp:02}",
            mantissa,
            prec = precision
        )
    }
}

/// `%g` / `%G` formatting: shortest of `%f` or `%e`.
fn format_g(value: f64, precision: usize, uppercase: bool, alt_form: bool) -> String {
    let p = if precision == 0 { 1 } else { precision };

    if value == 0.0 {
        if alt_form {
            if p <= 1 {
                return "0.".into();
            }
            let zeros: String = core::iter::repeat_n('0', p - 1).collect();
            return alloc::format!("0.{zeros}");
        }
        return "0".into();
    }

    let exp = value.log10().floor() as i32;
    if exp >= -(1) && exp < p as i32 {
        // Use %f style.
        let frac_digits = (p as i32 - 1 - exp).max(0) as usize;
        let mut s = alloc::format!("{:.prec$}", value, prec = frac_digits);
        if !alt_form {
            strip_trailing_zeros(&mut s);
        }
        s
    } else {
        // Use %e style.
        let mut s = format_e(value, p.saturating_sub(1), uppercase, alt_form);
        if !alt_form {
            // Strip trailing zeros from the mantissa part (before 'e'/'E').
            if let Some(e_pos) = s.bytes().position(|b| b == b'e' || b == b'E') {
                let mut mantissa = s[..e_pos].to_string();
                strip_trailing_zeros(&mut mantissa);
                let exp_part = &s[e_pos..];
                s = alloc::format!("{mantissa}{exp_part}");
            }
        }
        s
    }
}

/// Remove trailing zeros after the decimal point.
fn strip_trailing_zeros(s: &mut String) {
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
}

// We need alloc for String formatting of floats.
extern crate alloc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_int() {
        let (spec, consumed) = parse_format_spec(b"d").unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(spec.conversion, b'd');
        assert_eq!(spec.width, Width::None);
        assert_eq!(spec.precision, Precision::None);
    }

    #[test]
    fn test_parse_width_precision() {
        let (spec, consumed) = parse_format_spec(b"10.5f").unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(spec.conversion, b'f');
        assert_eq!(spec.width, Width::Fixed(10));
        assert_eq!(spec.precision, Precision::Fixed(5));
    }

    #[test]
    fn test_parse_flags() {
        let (spec, _) = parse_format_spec(b"-+#010d").unwrap();
        // '-' overrides '0'
        assert!(spec.flags.left_justify);
        assert!(spec.flags.force_sign);
        assert!(spec.flags.alt_form);
        assert!(!spec.flags.zero_pad); // overridden by '-'
    }

    #[test]
    fn test_parse_length_hh() {
        let (spec, _) = parse_format_spec(b"hhd").unwrap();
        assert_eq!(spec.length, LengthMod::Hh);
        assert_eq!(spec.conversion, b'd');
    }

    #[test]
    fn test_parse_length_ll() {
        let (spec, _) = parse_format_spec(b"llu").unwrap();
        assert_eq!(spec.length, LengthMod::Ll);
        assert_eq!(spec.conversion, b'u');
    }

    #[test]
    fn test_parse_star_width() {
        let (spec, _) = parse_format_spec(b"*d").unwrap();
        assert_eq!(spec.width, Width::FromArg);
    }

    #[test]
    fn test_parse_star_precision() {
        let (spec, _) = parse_format_spec(b".*f").unwrap();
        assert_eq!(spec.precision, Precision::FromArg);
    }

    #[test]
    fn test_parse_format_string_segments() {
        let segments = parse_format_string(b"hello %d world %s!");
        assert_eq!(segments.len(), 5);
        assert!(matches!(segments[0], FormatSegment::Literal(b"hello ")));
        assert!(matches!(&segments[1], FormatSegment::Spec(s) if s.conversion == b'd'));
        assert!(matches!(segments[2], FormatSegment::Literal(b" world ")));
        assert!(matches!(&segments[3], FormatSegment::Spec(s) if s.conversion == b's'));
        assert!(matches!(segments[4], FormatSegment::Literal(b"!")));
    }

    #[test]
    fn test_parse_percent_escape() {
        let segments = parse_format_string(b"100%%");
        assert_eq!(segments.len(), 2);
        assert!(matches!(segments[0], FormatSegment::Literal(b"100")));
        assert!(matches!(segments[1], FormatSegment::Percent));
    }

    #[test]
    fn test_format_signed_basic() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(42, &spec, &mut buf);
        assert_eq!(&buf, b"42");
    }

    #[test]
    fn test_format_signed_negative() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(-123, &spec, &mut buf);
        assert_eq!(&buf, b"-123");
    }

    #[test]
    fn test_format_signed_width_pad() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::Fixed(8),
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(42, &spec, &mut buf);
        assert_eq!(&buf, b"      42");
    }

    #[test]
    fn test_format_signed_zero_pad() {
        let spec = FormatSpec {
            flags: FormatFlags {
                zero_pad: true,
                ..Default::default()
            },
            width: Width::Fixed(8),
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(42, &spec, &mut buf);
        assert_eq!(&buf, b"00000042");
    }

    #[test]
    fn test_format_signed_left_justify() {
        let spec = FormatSpec {
            flags: FormatFlags {
                left_justify: true,
                ..Default::default()
            },
            width: Width::Fixed(8),
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(42, &spec, &mut buf);
        assert_eq!(&buf, b"42      ");
    }

    #[test]
    fn test_format_unsigned_hex() {
        let spec = FormatSpec {
            flags: FormatFlags {
                alt_form: true,
                ..Default::default()
            },
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'x',
        };
        let mut buf = Vec::new();
        format_unsigned(255, &spec, &mut buf);
        assert_eq!(&buf, b"0xff");
    }

    #[test]
    fn test_format_unsigned_octal() {
        let spec = FormatSpec {
            flags: FormatFlags {
                alt_form: true,
                ..Default::default()
            },
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'o',
        };
        let mut buf = Vec::new();
        format_unsigned(8, &spec, &mut buf);
        assert_eq!(&buf, b"010");
    }

    #[test]
    fn test_format_str_basic() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b's',
        };
        let mut buf = Vec::new();
        format_str(b"hello", &spec, &mut buf);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_format_str_precision_truncate() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::Fixed(3),
            length: LengthMod::None,
            conversion: b's',
        };
        let mut buf = Vec::new();
        format_str(b"hello", &spec, &mut buf);
        assert_eq!(&buf, b"hel");
    }

    #[test]
    fn test_format_char() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::Fixed(5),
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'c',
        };
        let mut buf = Vec::new();
        format_char(b'A', &spec, &mut buf);
        assert_eq!(&buf, b"    A");
    }

    #[test]
    fn test_format_pointer_null() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'p',
        };
        let mut buf = Vec::new();
        format_pointer(0, &spec, &mut buf);
        assert_eq!(&buf, b"(nil)");
    }

    #[test]
    fn test_format_pointer_nonzero() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'p',
        };
        let mut buf = Vec::new();
        format_pointer(0xDEAD, &spec, &mut buf);
        assert_eq!(&buf, b"0xdead");
    }

    #[test]
    fn test_format_float_basic() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'f',
        };
        let mut buf = Vec::new();
        format_float(core::f64::consts::PI, &spec, &mut buf);
        let s = String::from_utf8_lossy(&buf);
        assert!(s.starts_with("3.14"));
    }

    #[test]
    fn test_format_float_nan() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'f',
        };
        let mut buf = Vec::new();
        format_float(f64::NAN, &spec, &mut buf);
        assert_eq!(&buf, b"nan");
    }

    #[test]
    fn test_format_float_inf() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'f',
        };
        let mut buf = Vec::new();
        format_float(f64::INFINITY, &spec, &mut buf);
        assert_eq!(&buf, b"inf");
    }

    #[test]
    fn test_precision_zero_int() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::Fixed(0),
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(0, &spec, &mut buf);
        assert_eq!(&buf, b""); // POSIX: precision 0 with value 0 produces no digits
    }

    #[test]
    fn test_force_sign() {
        let spec = FormatSpec {
            flags: FormatFlags {
                force_sign: true,
                ..Default::default()
            },
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(42, &spec, &mut buf);
        assert_eq!(&buf, b"+42");
    }

    #[test]
    fn test_i64_min() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
        };
        let mut buf = Vec::new();
        format_signed(i64::MIN, &spec, &mut buf);
        assert_eq!(&buf, b"-9223372036854775808");
    }
}
