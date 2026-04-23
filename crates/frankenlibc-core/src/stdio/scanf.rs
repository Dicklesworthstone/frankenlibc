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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ScanfHandler {
    Invalid = 0,
    SignedDecimal,
    SignedAutoBase,
    UnsignedDecimal,
    UnsignedOctal,
    UnsignedHex,
    Float,
    Character,
    String,
    Scanset,
    CharsConsumed,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ScanfArgCategory {
    None = 0,
    SignedInt,
    UnsignedInt,
    Float,
    CharBuffer,
    StringBuffer,
    Store,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanArgKind {
    SignedInt,
    UnsignedInt,
    Float,
    CharBuffer,
    StringBuffer,
    Store,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntScanKind {
    SignedDecimal,
    SignedAutoBase,
    UnsignedDecimal,
    UnsignedOctal,
    UnsignedHex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanOperationKind {
    Int(IntScanKind),
    Float,
    Character,
    String,
    Scanset,
    CharsConsumed,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScanfRoute {
    handler: ScanfHandler,
    length_mask: u8,
    skips_leading_whitespace: bool,
    arg_category: ScanfArgCategory,
}

impl ScanfRoute {
    const fn invalid() -> Self {
        Self {
            handler: ScanfHandler::Invalid,
            length_mask: 0,
            skips_leading_whitespace: false,
            arg_category: ScanfArgCategory::None,
        }
    }

    fn is_valid(self) -> bool {
        !matches!(self.handler, ScanfHandler::Invalid)
    }

    fn accepts_length(self, length: LengthMod) -> bool {
        match length {
            LengthMod::None => true,
            LengthMod::Hh => self.length_mask & 0b0000_0001 != 0,
            LengthMod::H => self.length_mask & 0b0000_0010 != 0,
            LengthMod::L => self.length_mask & 0b0000_0100 != 0,
            LengthMod::Ll => self.length_mask & 0b0000_1000 != 0,
            LengthMod::J => self.length_mask & 0b0001_0000 != 0,
            LengthMod::Z => self.length_mask & 0b0010_0000 != 0,
            LengthMod::T => self.length_mask & 0b0100_0000 != 0,
            LengthMod::BigL => self.length_mask & 0b1000_0000 != 0,
        }
    }

    fn arg_kind(self) -> Option<ScanArgKind> {
        match self.arg_category {
            ScanfArgCategory::None => None,
            ScanfArgCategory::SignedInt => Some(ScanArgKind::SignedInt),
            ScanfArgCategory::UnsignedInt => Some(ScanArgKind::UnsignedInt),
            ScanfArgCategory::Float => Some(ScanArgKind::Float),
            ScanfArgCategory::CharBuffer => Some(ScanArgKind::CharBuffer),
            ScanfArgCategory::StringBuffer => Some(ScanArgKind::StringBuffer),
            ScanfArgCategory::Store => Some(ScanArgKind::Store),
            ScanfArgCategory::Pointer => Some(ScanArgKind::Pointer),
        }
    }

    fn scan_operation_kind(self) -> Option<ScanOperationKind> {
        match self.handler {
            ScanfHandler::Invalid => None,
            ScanfHandler::SignedDecimal => Some(ScanOperationKind::Int(IntScanKind::SignedDecimal)),
            ScanfHandler::SignedAutoBase => {
                Some(ScanOperationKind::Int(IntScanKind::SignedAutoBase))
            }
            ScanfHandler::UnsignedDecimal => {
                Some(ScanOperationKind::Int(IntScanKind::UnsignedDecimal))
            }
            ScanfHandler::UnsignedOctal => Some(ScanOperationKind::Int(IntScanKind::UnsignedOctal)),
            ScanfHandler::UnsignedHex => Some(ScanOperationKind::Int(IntScanKind::UnsignedHex)),
            ScanfHandler::Float => Some(ScanOperationKind::Float),
            ScanfHandler::Character => Some(ScanOperationKind::Character),
            ScanfHandler::String => Some(ScanOperationKind::String),
            ScanfHandler::Scanset => Some(ScanOperationKind::Scanset),
            ScanfHandler::CharsConsumed => Some(ScanOperationKind::CharsConsumed),
            ScanfHandler::Pointer => Some(ScanOperationKind::Pointer),
        }
    }
}

mod generated_scanf_tables {
    include!(concat!(
        env!("OUT_DIR"),
        "/stdio_synth/synth/scanf_table.rs"
    ));
}

use generated_scanf_tables::SCANF_TABLE;

fn scanf_route(conversion: u8) -> Option<ScanfRoute> {
    let route = SCANF_TABLE[conversion as usize];
    if !route.is_valid() { None } else { Some(route) }
}

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
    route: ScanfRoute,
}

impl ScanSpec {
    pub fn arg_kind(&self) -> Option<ScanArgKind> {
        self.route.arg_kind()
    }

    pub fn skips_leading_whitespace(&self) -> bool {
        self.route.skips_leading_whitespace
    }

    pub fn stores_count(&self) -> bool {
        matches!(self.arg_kind(), Some(ScanArgKind::Store))
    }

    pub fn writes_char_buffer(&self) -> bool {
        matches!(self.arg_kind(), Some(ScanArgKind::CharBuffer))
    }

    pub fn writes_string_buffer(&self) -> bool {
        matches!(self.arg_kind(), Some(ScanArgKind::StringBuffer))
    }

    pub fn writes_float(&self) -> bool {
        matches!(self.arg_kind(), Some(ScanArgKind::Float))
    }

    pub fn writes_pointer(&self) -> bool {
        matches!(self.arg_kind(), Some(ScanArgKind::Pointer))
    }

    fn scan_operation_kind(&self) -> Option<ScanOperationKind> {
        self.route.scan_operation_kind()
    }

    fn bind_route(&mut self) -> bool {
        let Some(route) = scanf_route(self.conversion) else {
            return false;
        };
        if !route.accepts_length(self.length) {
            return false;
        }
        self.route = route;
        true
    }

    fn scan_at(&self, input: &[u8], pos: usize) -> Option<(Option<ScanValue>, usize)> {
        self.scan_operation_kind()?.scan(input, pos, self)
    }
}

impl IntScanKind {
    fn scan(self, input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
        match self {
            IntScanKind::SignedDecimal => scan_int(input, pos, spec, 10, true),
            IntScanKind::SignedAutoBase => scan_int_auto(input, pos, spec),
            IntScanKind::UnsignedDecimal => scan_int(input, pos, spec, 10, false),
            IntScanKind::UnsignedOctal => scan_int(input, pos, spec, 8, false),
            IntScanKind::UnsignedHex => scan_int(input, pos, spec, 16, false),
        }
    }
}

impl ScanOperationKind {
    fn scan(self, input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
        match self {
            ScanOperationKind::Int(kind) => kind.scan(input, pos, spec),
            ScanOperationKind::Float => scan_float(input, pos, spec),
            ScanOperationKind::Character => scan_char(input, pos, spec),
            ScanOperationKind::String => scan_string(input, pos, spec),
            ScanOperationKind::Scanset => scan_scanset(input, pos, spec),
            ScanOperationKind::CharsConsumed => Some((Some(ScanValue::CharsConsumed(pos)), pos)),
            ScanOperationKind::Pointer => scan_pointer(input, pos, spec),
        }
    }
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
                route: ScanfRoute::invalid(),
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

            if !spec.bind_route() {
                break;
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
                let result = spec.scan_at(input, pos);
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

fn apply_leading_whitespace_policy(input: &[u8], pos: usize, spec: &ScanSpec) -> usize {
    if spec.skips_leading_whitespace() {
        skip_ws(input, pos)
    } else {
        pos
    }
}

/// Scan an integer with specified base. If `signed`, allow leading +/-.
fn scan_int(
    input: &[u8],
    pos: usize,
    spec: &ScanSpec,
    base: u32,
    signed: bool,
) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
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
        // Apply overflow wrapping based on length modifier per glibc behavior.
        let wrapped = match spec.length {
            LengthMod::Hh => (signed_val as i8) as i64,
            LengthMod::H => (signed_val as i16) as i64,
            LengthMod::Ll | LengthMod::J => signed_val, // Full i64, no wrap
            LengthMod::Z | LengthMod::T => signed_val,  // Platform isize, assume 64-bit
            _ => (signed_val as i32) as i64,            // Default: int (32-bit)
        };
        ScanValue::SignedInt(wrapped)
    } else {
        // Apply overflow wrapping for unsigned types.
        let wrapped = match spec.length {
            LengthMod::Hh => (val as u8) as u64,
            LengthMod::H => (val as u16) as u64,
            LengthMod::Ll | LengthMod::J => val, // Full u64, no wrap
            LengthMod::Z | LengthMod::T => val,  // Platform usize, assume 64-bit
            _ => (val as u32) as u64,            // Default: unsigned int (32-bit)
        };
        ScanValue::UnsignedInt(wrapped)
    };

    Some((Some(value), i))
}

/// Scan integer with auto-detected base (%i: 0x=hex, 0=octal, else decimal).
fn scan_int_auto(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
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
    // Apply overflow wrapping based on length modifier per glibc behavior.
    let wrapped = match spec.length {
        LengthMod::Hh => (signed_val as i8) as i64,
        LengthMod::H => (signed_val as i16) as i64,
        LengthMod::Ll | LengthMod::J => signed_val, // Full i64, no wrap
        LengthMod::Z | LengthMod::T => signed_val,  // Platform isize, assume 64-bit
        _ => (signed_val as i32) as i64,            // Default: int (32-bit)
    };

    Some((Some(ScanValue::SignedInt(wrapped)), i))
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
    let pos = apply_leading_whitespace_policy(input, pos, spec);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);
    let mut i = pos;
    let mut chars_read = 0usize;
    let negative;

    // Sign.
    if i < input.len() && chars_read < max_chars && (input[i] == b'+' || input[i] == b'-') {
        negative = input[i] == b'-';
        i += 1;
        chars_read += 1;
    } else {
        negative = false;
    }

    // Check for inf/infinity/nan.
    let remaining = &input[i..];
    if chars_read + 3 <= max_chars {
        if remaining.len() >= 3 && remaining[..3].eq_ignore_ascii_case(b"inf") {
            i += 3;
            chars_read += 3;
            if remaining.len() >= 8
                && chars_read + 5 <= max_chars
                && remaining[..8].eq_ignore_ascii_case(b"infinity")
            {
                i += 5;
            }
            let val: f64 = if negative {
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

    // Check for hex float (0x prefix).
    // Per C11/strtod, if we see "0x" but hex parsing fails (e.g., "0xyz" has no
    // hex digits after 0x), we fall back to decimal parsing which will parse "0".
    if chars_read + 2 <= max_chars
        && i + 1 < input.len()
        && input[i] == b'0'
        && (input[i + 1] == b'x' || input[i + 1] == b'X')
        && let Some(result) = scan_hex_float(input, pos, i, chars_read, negative, max_chars)
    {
        return Some(result);
    }
    // If hex prefix was seen but parsing failed, we fall through to decimal
    // parsing. This handles cases like "0xyz" where we should parse "0" as decimal.

    // Decimal float: digits, decimal point, exponent.
    let mut buf = Vec::with_capacity(64);
    if negative {
        buf.push(b'-');
    }
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

/// Scan a hex float (0x[h...h][.h...h][pN]) per C11 7.21.6.2.
/// Called after the optional sign and 0x prefix have been detected.
fn scan_hex_float(
    input: &[u8],
    _start_pos: usize,
    mut i: usize,
    mut chars_read: usize,
    negative: bool,
    max_chars: usize,
) -> Option<(Option<ScanValue>, usize)> {
    // Skip 0x/0X prefix.
    i += 2;
    chars_read += 2;

    // Parse hex significand: integer part, optional '.', fractional part.
    let mut significand: u64 = 0;
    let mut frac_digits: i32 = 0;
    let mut any_hex_digit = false;
    let mut in_fraction = false;

    while i < input.len() && chars_read < max_chars {
        let c = input[i];
        if c == b'.' && !in_fraction {
            in_fraction = true;
            i += 1;
            chars_read += 1;
            continue;
        }
        let digit_val = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' => (c - b'a' + 10) as u64,
            b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => break,
        };
        any_hex_digit = true;
        // Each hex digit is 4 bits. Guard against overflow by checking high bits.
        if significand < (1u64 << 60) {
            significand = (significand << 4) | digit_val;
            if in_fraction {
                frac_digits += 1;
            }
        } else if !in_fraction {
            // Overflow in integer part - this is a very large number.
            // Keep consuming digits but don't shift anymore.
        }
        i += 1;
        chars_read += 1;
    }

    if !any_hex_digit {
        // No hex digits after 0x - "0" itself is valid, reparse from start.
        // Back up to just after sign (or start) and let decimal parser handle "0".
        return None;
    }

    // Parse binary exponent (p/P followed by optional sign and decimal digits).
    let mut bin_exp: i32 = 0;
    if i < input.len() && chars_read < max_chars && (input[i] == b'p' || input[i] == b'P') {
        let saved_i = i;
        let saved_chars_read = chars_read;
        i += 1;
        chars_read += 1;

        let exp_negative;
        if i < input.len() && chars_read < max_chars {
            if input[i] == b'-' {
                exp_negative = true;
                i += 1;
                chars_read += 1;
            } else if input[i] == b'+' {
                exp_negative = false;
                i += 1;
                chars_read += 1;
            } else {
                exp_negative = false;
            }
        } else {
            exp_negative = false;
        }

        let mut any_exp_digit = false;
        while i < input.len() && chars_read < max_chars && input[i].is_ascii_digit() {
            any_exp_digit = true;
            let d = (input[i] - b'0') as i32;
            bin_exp = bin_exp.saturating_mul(10).saturating_add(d);
            i += 1;
            chars_read += 1;
        }

        if !any_exp_digit {
            // 'p' without exponent digits - back up past 'p' and sign.
            // Per C11, if 'p' is present, exponent digits are required.
            // Restore position and treat as if we never saw the 'p'.
            i = saved_i;
            let _ = saved_chars_read; // chars_read logically restored but unused after this point
        } else if exp_negative {
            bin_exp = -bin_exp;
        }
    }

    // Convert to f64:
    // value = significand * 2^(bin_exp - 4*frac_digits)
    // Each hex fractional digit shifts the binary point 4 bits.
    let total_exp = bin_exp - (frac_digits * 4);
    let mut val = significand as f64;
    if total_exp != 0 {
        val *= 2_f64.powi(total_exp);
    }
    if negative {
        val = -val;
    }

    Some((Some(ScanValue::Float(val)), i))
}

/// Scan character(s) (%c). No whitespace skip. Width = number of chars.
fn scan_char(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
    let n = spec.width.unwrap_or(1);
    // Guard against pathological widths that overflow pos + n. Under
    // debug_assertions `usize` add panics; in release it wraps and
    // would skip the bounds check below, reading past input. (bd-35vob)
    let end = pos.checked_add(n)?;
    if end > input.len() {
        return None;
    }
    let chars = input[pos..end].to_vec();
    Some((Some(ScanValue::Char(chars)), end))
}

/// Scan a string (%s). Skips whitespace, then reads non-whitespace.
fn scan_string(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
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
    let pos = apply_leading_whitespace_policy(input, pos, spec);
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
    let pos = apply_leading_whitespace_policy(input, pos, spec);
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
    fn test_scan_int_overflow_wraps_to_int32() {
        // 2147483648 (INT_MAX + 1) should wrap to -2147483648 (INT_MIN)
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"2147483648", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(
            result.values[0],
            ScanValue::SignedInt(-2147483648)
        ));
    }

    #[test]
    fn test_scan_int_underflow_wraps_to_int32() {
        // -2147483649 (INT_MIN - 1) should wrap to 2147483647 (INT_MAX)
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"-2147483649", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(2147483647)));
    }

    #[test]
    fn test_scan_lld_no_overflow_wrap() {
        // %lld should not wrap since it's a full i64
        let dirs = parse_scanf_format(b"%lld");
        let result = scan_input(b"2147483648", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(2147483648)));
    }

    #[test]
    fn test_scan_hd_overflow_wraps_to_int16() {
        // 32768 (SHRT_MAX + 1) should wrap to -32768 (SHRT_MIN)
        let dirs = parse_scanf_format(b"%hd");
        let result = scan_input(b"32768", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(-32768)));
    }

    #[test]
    fn test_scan_u_overflow_wraps_to_uint32() {
        // Values > UINT_MAX should wrap
        let dirs = parse_scanf_format(b"%u");
        let result = scan_input(b"4294967296", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::UnsignedInt(0)));
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
    fn test_parse_invalid_conversion_stops_scanf_parse() {
        let dirs = parse_scanf_format(b"%Q%d");
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_parse_invalid_length_modifier_stops_scanf_parse() {
        let dirs = parse_scanf_format(b"%Ls%d");
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_generated_scanf_route_metadata_covers_core_specifiers() {
        let decimal = scanf_route(b'd').expect("decimal route");
        let string = scanf_route(b's').expect("string route");
        let scanset = scanf_route(b'[').expect("scanset route");

        assert_eq!(decimal.handler, ScanfHandler::SignedDecimal);
        assert_eq!(string.handler, ScanfHandler::String);
        assert_eq!(scanset.handler, ScanfHandler::Scanset);
        assert_eq!(decimal.arg_kind(), Some(ScanArgKind::SignedInt));
        assert_eq!(string.arg_kind(), Some(ScanArgKind::StringBuffer));
        assert_eq!(scanset.arg_kind(), Some(ScanArgKind::StringBuffer));
        assert_eq!(
            decimal.scan_operation_kind(),
            Some(ScanOperationKind::Int(IntScanKind::SignedDecimal))
        );
        assert_eq!(
            string.scan_operation_kind(),
            Some(ScanOperationKind::String)
        );
        assert_eq!(
            scanset.scan_operation_kind(),
            Some(ScanOperationKind::Scanset)
        );
        assert!(decimal.skips_leading_whitespace);
        assert!(!scanset.skips_leading_whitespace);
        assert!(string.accepts_length(LengthMod::L));
        assert!(!string.accepts_length(LengthMod::BigL));
        assert!(scanf_route(b'Q').is_none());
    }

    #[test]
    fn test_parsed_scanf_specs_embed_generated_routes() {
        let dirs = parse_scanf_format(b"%3s%c");
        let specs: Vec<_> = dirs
            .iter()
            .filter_map(|directive| match directive {
                ScanDirective::Spec(spec) => Some(spec),
                _ => None,
            })
            .collect();

        assert_eq!(specs.len(), 2);
        assert!(specs[0].writes_string_buffer());
        assert!(specs[0].skips_leading_whitespace());
        assert_eq!(
            specs[0].scan_operation_kind(),
            Some(ScanOperationKind::String)
        );
        assert!(specs[1].writes_char_buffer());
        assert!(!specs[1].skips_leading_whitespace());
        assert_eq!(
            specs[1].scan_operation_kind(),
            Some(ScanOperationKind::Character)
        );
    }

    #[test]
    fn test_scan_spec_helper_methods_follow_generated_arg_categories() {
        let dirs = parse_scanf_format(b"%d %n %p %f");
        let specs: Vec<_> = dirs
            .iter()
            .filter_map(|directive| match directive {
                ScanDirective::Spec(spec) => Some(spec),
                _ => None,
            })
            .collect();

        assert_eq!(specs.len(), 4);
        assert_eq!(specs[0].arg_kind(), Some(ScanArgKind::SignedInt));
        assert!(!specs[0].writes_float());
        assert!(specs[1].stores_count());
        assert!(specs[2].writes_pointer());
        assert!(specs[3].writes_float());
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
    fn test_scan_hex_float_basic() {
        // 0x1.fp+2 = 1.9375 * 4 = 7.75
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x1.fp+2", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 7.75).abs() < 1e-10, "expected 7.75, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_integer() {
        // 0x1p10 = 1 * 2^10 = 1024
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x1p10", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 1024.0).abs() < 1e-10, "expected 1024, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_negative() {
        // -0x1p0 = -1.0
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"-0x1p0", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - (-1.0)).abs() < 1e-10, "expected -1.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_negative_exponent() {
        // 0x1p-1 = 1 * 2^-1 = 0.5
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x1p-1", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 0.5).abs() < 1e-10, "expected 0.5, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_uppercase() {
        // 0X1.8P+2 = 1.5 * 4 = 6.0
        let dirs = parse_scanf_format(b"%A");
        let result = scan_input(b"0X1.8P+2", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 6.0).abs() < 1e-10, "expected 6.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_leading_dot() {
        // 0x.8p0 = 0.5 (8/16)
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x.8p0", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 0.5).abs() < 1e-10, "expected 0.5, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_zero() {
        // 0x0p0 = 0.0
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x0p0", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!(v == 0.0, "expected 0.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_no_exponent() {
        // 0x10 = 16 (no p exponent means p0)
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x10", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 16.0).abs() < 1e-10, "expected 16.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_trailing_zeros() {
        // 0x1.00p0 = 1.0
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x1.00p0", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 1.0).abs() < 1e-10, "expected 1.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_invalid_fallback() {
        // "0xyz" should parse "0" as decimal (hex parsing fails, falls back)
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0xyz", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!(v == 0.0, "expected 0.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_p_without_digits() {
        // "0x1.0p" should parse "0x1.0" (= 1.0) and leave 'p' unconsumed.
        // Per C11, 'p' without following digits is not a valid exponent.
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x1.0p", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 1.0).abs() < 1e-10, "expected 1.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_p_sign_without_digits() {
        // "0x1.0p-" should parse "0x1.0" (= 1.0) and leave "p-" unconsumed.
        let dirs = parse_scanf_format(b"%a");
        let result = scan_input(b"0x1.0p-", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 1.0).abs() < 1e-10, "expected 1.0, got {}", v);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_scan_hex_float_p_sign_then_text() {
        // "0x2p-foo" should parse "0x2" (= 2.0) leaving "p-foo" unconsumed.
        let dirs = parse_scanf_format(b"%a%s");
        let result = scan_input(b"0x2p-foo", &dirs);
        assert_eq!(result.count, 2, "should parse float then string");
        if let ScanValue::Float(v) = result.values[0] {
            assert!((v - 2.0).abs() < 1e-10, "expected 2.0, got {}", v);
        } else {
            panic!("expected Float");
        }
        // The remaining "p-foo" should be captured by %s
        if let ScanValue::String(ref s) = result.values[1] {
            assert_eq!(s.as_slice(), b"p-foo", "expected 'p-foo', got {:?}", s);
        } else {
            panic!("expected String for second value");
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
