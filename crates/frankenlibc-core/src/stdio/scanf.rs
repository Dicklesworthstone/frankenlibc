//! scanf format string parser and input scanner.
//!
//! Clean-room spec-first implementation of POSIX scanf format parsing.
//! Parses format directives and scans typed values from byte input.
//!
//! Reference: POSIX.1-2024 fscanf, ISO C11 7.21.6.2
//!
//! The engine returns a `Vec<ScanValue>` for each successfully scanned
//! non-suppressed destination, including `%n`. The ABI layer writes these
//! values through the caller's va_list pointers; the scanf return count still
//! excludes `%n`, matching POSIX/glibc.

use super::printf::LengthMod;

/// Whitespace test matching C's `isspace` in the C locale. POSIX scanf
/// defines both the white-space *directive* and the `%s`/`%[`-style
/// match boundaries in terms of `isspace`, whose C-locale set is `' '`
/// plus `\t \n \v \f \r` (0x09..=0x0D).
///
/// Rust's `u8::is_ascii_whitespace` omits the vertical tab `\v` (0x0b),
/// so using it would make `sscanf("\x0b42", "%d", …)` fail to skip the
/// leading VT and `%s` swallow an embedded VT — both diverge from glibc.
#[inline]
const fn is_c_space(b: u8) -> bool {
    b == b' ' || (b >= b'\t' && b <= b'\r')
}

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
                        } else {
                            // Reversed range (lo > hi): glibc does not form an
                            // empty range — it takes the three characters as
                            // literal set members (`lo`, `-`, `hi`).
                            chars[lo as usize] = true;
                            chars[b'-' as usize] = true;
                            chars[hi as usize] = true;
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
                // `%S` and `%C` are SVID aliases for `%ls` and `%lc` (wide
                // string / wide char): normalise to (s|c, length `L`) so they
                // route through the string/char paths with wide handling.
                spec.conversion = match fmt[i] {
                    b'S' => {
                        spec.length = LengthMod::L;
                        b's'
                    }
                    b'C' => {
                        spec.length = LengthMod::L;
                        b'c'
                    }
                    other => other,
                };
                i += 1;
            }

            if !spec.bind_route() {
                break;
            }

            directives.push(ScanDirective::Spec(Box::new(spec)));
        } else if is_c_space(fmt[i]) {
            directives.push(ScanDirective::Whitespace);
            i += 1;
            // Consume additional whitespace in format.
            while i < fmt.len() && is_c_space(fmt[i]) {
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
                while pos < input.len() && is_c_space(input[pos]) {
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
                        let exhausted_before_conversion = if spec.skips_leading_whitespace() {
                            skip_ws(input, pos) >= input.len()
                        } else {
                            pos >= input.len()
                        };
                        return ScanResult {
                            values,
                            count,
                            consumed: pos,
                            input_failure: exhausted_before_conversion && count == 0,
                        };
                    }
                    Some((val, new_pos)) => {
                        input_failure = false;
                        pos = new_pos;
                        if !spec.suppress
                            && let Some(v) = val
                        {
                            let counts_as_assignment = !matches!(v, ScanValue::CharsConsumed(_));
                            values.push(v);
                            if counts_as_assignment {
                                count += 1;
                            }
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
    while pos < input.len() && is_c_space(input[pos]) {
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

/// Clamp an unsigned magnitude (already saturated to `u64::MAX` on
/// accumulator overflow) into the `i64` range, matching glibc's clamping of
/// out-of-range integers to `LLONG_MAX` / `LLONG_MIN`.
fn clamp_signed_magnitude(mag: u64, negative: bool, overflowed: bool) -> i64 {
    if negative {
        if overflowed || mag > i64::MAX as u64 {
            i64::MIN
        } else {
            -(mag as i64)
        }
    } else if overflowed || mag > i64::MAX as u64 {
        i64::MAX
    } else {
        mag as i64
    }
}

/// Truncate a clamped signed value to the destination type selected by the
/// length modifier. On the LP64 targets this libc supports, `long`,
/// `long long`, `size_t`, `ptrdiff_t` and `intmax_t` are all 64-bit.
fn narrow_signed(v: i64, length: LengthMod) -> i64 {
    match length {
        LengthMod::Hh => (v as i8) as i64,
        LengthMod::H => (v as i16) as i64,
        LengthMod::L | LengthMod::Ll | LengthMod::J | LengthMod::Z | LengthMod::T => v,
        _ => (v as i32) as i64,
    }
}

/// Truncate an unsigned value to the destination type selected by the
/// length modifier (see [`narrow_signed`] for the 64-bit type set).
fn narrow_unsigned(v: u64, length: LengthMod) -> u64 {
    match length {
        LengthMod::Hh => (v as u8) as u64,
        LengthMod::H => (v as u16) as u64,
        LengthMod::L | LengthMod::Ll | LengthMod::J | LengthMod::Z | LengthMod::T => v,
        _ => (v as u32) as u64,
    }
}

/// Scan an integer with specified base. If `signed`, the result is stored as
/// a signed value; a leading `-`/`+` is accepted regardless (glibc accepts a
/// leading `-` for unsigned conversions too, via `strtoul` negate-wrap).
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

    // Sign. A leading `-`/`+` is consumed for both signed and unsigned
    // conversions; an unsigned conversion negates the magnitude modulo
    // 2^width afterwards (strtoul semantics), matching glibc.
    let negative = if i < input.len() && chars_read < max_chars {
        match input[i] {
            b'-' => {
                i += 1;
                chars_read += 1;
                true
            }
            b'+' => {
                i += 1;
                chars_read += 1;
                false
            }
            _ => false,
        }
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

    // Digits. The accumulator saturates to u64::MAX on overflow; glibc
    // clamps an out-of-range integer to its limit rather than wrapping.
    let mut val: u64 = 0;
    let mut overflowed = false;
    let mut any_digit = false;

    // SWAR fast path (base 10): consume 8 decimal digits per step via the same
    // exhaustively-verified helpers as strtol. Gated so the 8-digit block fits
    // both the input and the remaining field width; `val·10^8 + parse8` equals
    // eight scalar iterations (overflow saturates val to u64::MAX and keeps
    // consuming, identical to the scalar tail below).
    if base == 10 {
        while i + 8 <= input.len() && chars_read + 8 <= max_chars {
            let word = u64::from_le_bytes(input[i..i + 8].try_into().unwrap());
            if !crate::stdlib::conversion::is_eight_digits(word) {
                break;
            }
            any_digit = true;
            if !overflowed {
                let parsed = crate::stdlib::conversion::parse_eight_digits(word) as u64;
                match val
                    .checked_mul(100_000_000)
                    .and_then(|v| v.checked_add(parsed))
                {
                    Some(next) => val = next,
                    None => {
                        val = u64::MAX;
                        overflowed = true;
                    }
                }
            }
            i += 8;
            chars_read += 8;
        }
    } else if base == 16 {
        // SWAR hex: 8 hex digits (32 bits) per step (parse_eight_hex), width-gated.
        while i + 8 <= input.len() && chars_read + 8 <= max_chars {
            let word = u64::from_le_bytes(input[i..i + 8].try_into().unwrap());
            let Some(parsed) = crate::stdlib::conversion::parse_eight_hex(word) else {
                break;
            };
            any_digit = true;
            if !overflowed {
                match val
                    .checked_mul(0x1_0000_0000)
                    .and_then(|v| v.checked_add(parsed as u64))
                {
                    Some(next) => val = next,
                    None => {
                        val = u64::MAX;
                        overflowed = true;
                    }
                }
            }
            i += 8;
            chars_read += 8;
        }
    }

    while i < input.len() && chars_read < max_chars {
        let d = match digit_value(input[i], base) {
            Some(d) => d,
            None => break,
        };
        any_digit = true;
        match val
            .checked_mul(base as u64)
            .and_then(|v| v.checked_add(d as u64))
        {
            Some(next) => val = next,
            None => {
                val = u64::MAX;
                overflowed = true;
            }
        }
        i += 1;
        chars_read += 1;
    }

    if !any_digit {
        return None;
    }

    let value = if signed {
        let signed_val = clamp_signed_magnitude(val, negative, overflowed);
        ScanValue::SignedInt(narrow_signed(signed_val, spec.length))
    } else {
        let uval = if negative {
            if overflowed {
                u64::MAX
            } else {
                val.wrapping_neg()
            }
        } else {
            val
        };
        ScanValue::UnsignedInt(narrow_unsigned(uval, spec.length))
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

    // Detect base (hex 0x, binary 0b, octal 0, decimal otherwise).
    let base = if i < input.len() && chars_read < max_chars && input[i] == b'0' {
        if i + 1 < input.len()
            && chars_read + 1 < max_chars
            && (input[i + 1] == b'x' || input[i + 1] == b'X')
        {
            i += 2;
            chars_read += 2;
            16u32
        } else if i + 1 < input.len()
            && chars_read + 1 < max_chars
            && (input[i + 1] == b'b' || input[i + 1] == b'B')
        {
            i += 2;
            chars_read += 2;
            2u32
        } else {
            8u32
            // Don't consume the '0' yet — it's a valid octal digit.
        }
    } else {
        10u32
    };

    // Digits. The accumulator saturates to u64::MAX on overflow; glibc
    // clamps an out-of-range integer to its limit rather than wrapping.
    let mut val: u64 = 0;
    let mut overflowed = false;
    let mut any_digit = false;

    // SWAR fast path (base 10): consume 8 decimal digits per step via the same
    // exhaustively-verified helpers as strtol. Gated so the 8-digit block fits
    // both the input and the remaining field width; `val·10^8 + parse8` equals
    // eight scalar iterations (overflow saturates val to u64::MAX and keeps
    // consuming, identical to the scalar tail below).
    if base == 10 {
        while i + 8 <= input.len() && chars_read + 8 <= max_chars {
            let word = u64::from_le_bytes(input[i..i + 8].try_into().unwrap());
            if !crate::stdlib::conversion::is_eight_digits(word) {
                break;
            }
            any_digit = true;
            if !overflowed {
                let parsed = crate::stdlib::conversion::parse_eight_digits(word) as u64;
                match val
                    .checked_mul(100_000_000)
                    .and_then(|v| v.checked_add(parsed))
                {
                    Some(next) => val = next,
                    None => {
                        val = u64::MAX;
                        overflowed = true;
                    }
                }
            }
            i += 8;
            chars_read += 8;
        }
    } else if base == 16 {
        // SWAR hex: 8 hex digits (32 bits) per step (parse_eight_hex), width-gated.
        while i + 8 <= input.len() && chars_read + 8 <= max_chars {
            let word = u64::from_le_bytes(input[i..i + 8].try_into().unwrap());
            let Some(parsed) = crate::stdlib::conversion::parse_eight_hex(word) else {
                break;
            };
            any_digit = true;
            if !overflowed {
                match val
                    .checked_mul(0x1_0000_0000)
                    .and_then(|v| v.checked_add(parsed as u64))
                {
                    Some(next) => val = next,
                    None => {
                        val = u64::MAX;
                        overflowed = true;
                    }
                }
            }
            i += 8;
            chars_read += 8;
        }
    }

    while i < input.len() && chars_read < max_chars {
        let d = match digit_value(input[i], base) {
            Some(d) => d,
            None => break,
        };
        any_digit = true;
        match val
            .checked_mul(base as u64)
            .and_then(|v| v.checked_add(d as u64))
        {
            Some(next) => val = next,
            None => {
                val = u64::MAX;
                overflowed = true;
            }
        }
        i += 1;
        chars_read += 1;
    }

    if !any_digit {
        // A bare "0x"/"0X" with no hex digit is a matching failure: glibc
        // treats the prefix as committing to a hex literal.
        return None;
    }

    let signed_val = clamp_signed_magnitude(val, negative, overflowed);
    Some((
        Some(ScanValue::SignedInt(narrow_signed(signed_val, spec.length))),
        i,
    ))
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
            // glibc's strtod accepts an optional `(n-char-sequence)` payload
            // after "nan", where the sequence is `[0-9A-Za-z_]*` and the
            // closing ')' is MANDATORY: if it is absent, the whole token
            // (sign and all) is rewound and the conversion fails to match.
            // The sign bit is applied to the NaN ("-nan" keeps its sign); the
            // payload value itself is an impl detail we do not replicate.
            let budget = max_chars - chars_read; // chars allowed from `remaining`
            let mut j = 3usize;
            if remaining.len() > j && j < budget && remaining[j] == b'(' {
                let mut k = j + 1;
                while k < remaining.len()
                    && k < budget
                    && (remaining[k].is_ascii_alphanumeric() || remaining[k] == b'_')
                {
                    k += 1;
                }
                if k < remaining.len() && k < budget && remaining[k] == b')' {
                    j = k + 1; // consume through the ')'
                } else {
                    // Malformed payload (no closing paren / cut off by width):
                    // glibc rewinds the entire token → matching failure.
                    return None;
                }
            }
            let val = f64::NAN.copysign(if negative { -1.0 } else { 1.0 });
            return Some((Some(ScanValue::Float(val)), i + j));
        }
    }

    // Check for hex float (0x prefix).
    if chars_read + 2 <= max_chars
        && i + 1 < input.len()
        && input[i] == b'0'
        && (input[i + 1] == b'x' || input[i + 1] == b'X')
        && let Some(result) = scan_hex_float(input, pos, i, chars_read, negative, max_chars)
    {
        return Some(result);
    }
    // If a hex prefix was seen but parsing failed, the conversion is a
    // matching failure rather than a decimal fallback.
    if chars_read + 2 <= max_chars
        && i + 1 < input.len()
        && input[i] == b'0'
        && (input[i + 1] == b'x' || input[i + 1] == b'X')
    {
        return None;
    }

    // Decimal float: digits, decimal point, exponent.
    let mut buf = Vec::with_capacity(64);
    if negative {
        buf.push(b'-');
    }
    let mut any_digit = false;
    let mut seen_dot = false;
    while i < input.len() && chars_read < max_chars {
        let c = input[i];
        if c.is_ascii_digit() {
            any_digit = true;
            buf.push(c);
        } else if c == b'.' && !seen_dot {
            // Only the FIRST decimal point is part of the float; a second '.'
            // ends the token (glibc reads the longest valid prefix, e.g.
            // "03.1.5" -> 3.1 consuming 4 bytes). Found by sscanf_differential_fuzz.
            seen_dot = true;
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
    let mut saw_decimal_point = false;

    while i < input.len() && chars_read < max_chars {
        let c = input[i];
        if c == b'.' && !in_fraction {
            saw_decimal_point = true;
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
        // glibc accepts `0x.` as a zero hex-float token but rejects `0x`
        // or `0xyz` as matching failures.
        if saw_decimal_point {
            let val = if negative { -0.0 } else { 0.0 };
            return Some((Some(ScanValue::Float(val)), i));
        }
        return None;
    }

    // Parse binary exponent (p/P followed by optional sign and decimal digits).
    let mut bin_exp: i32 = 0;
    if i < input.len() && chars_read < max_chars && (input[i] == b'p' || input[i] == b'P') {
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
            // A `p` exponent marker after actual hex digits commits to a
            // binary exponent. Without following exponent digits, glibc
            // reports a matching failure rather than accepting the prefix.
            return None;
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

/// Byte length of the UTF-8 sequence beginning with `b`. Returns 1 for ASCII or
/// an invalid lead byte so a scan always makes forward progress.
#[inline]
fn utf8_seq_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

/// Scan character(s) (%c). No whitespace skip. Width = number of chars.
fn scan_char(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
    let n = spec.width.unwrap_or(1);
    if matches!(spec.length, LengthMod::L) {
        // `%lc`: the width counts WIDE characters, so read `n` complete UTF-8
        // sequences from the multibyte input (the caller decodes them back to
        // wchar_t). Reading `n` raw bytes would split a multibyte character.
        let mut end = pos;
        for _ in 0..n {
            if end >= input.len() {
                return None;
            }
            let next = end.checked_add(utf8_seq_len(input[end]))?;
            if next > input.len() {
                return None;
            }
            end = next;
        }
        return Some((Some(ScanValue::Char(input[pos..end].to_vec())), end));
    }
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
    // `%ls` width counts WIDE characters; consume whole UTF-8 sequences so a
    // bounded `%Nls` never splits a multibyte character. `%s` counts bytes.
    let wide = matches!(spec.length, LengthMod::L);
    let mut i = pos;
    let mut chars_read = 0usize;
    let mut buf = Vec::new();

    while i < input.len() && chars_read < max_chars && !is_c_space(input[i]) {
        if wide {
            let next = (i + utf8_seq_len(input[i])).min(input.len());
            buf.extend_from_slice(&input[i..next]);
            i = next;
        } else {
            buf.push(input[i]);
            i += 1;
        }
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
    fn vertical_tab_is_c_isspace_for_directive_skip_and_string_boundary() {
        // POSIX scanf defines whitespace via isspace(), whose C-locale
        // set includes the vertical tab \x0b. glibc skips a leading VT
        // before %d and ends %s at an embedded VT.

        // A bare VT in the format string is a whitespace directive.
        let dirs = parse_scanf_format(b"\x0b");
        assert_eq!(dirs.len(), 1);
        assert!(matches!(dirs[0], ScanDirective::Whitespace));

        // %d must skip leading VT/FF input whitespace.
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"\x0b\x0c42", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(42)));

        // %s must stop at an embedded VT, not swallow it.
        let dirs = parse_scanf_format(b"%s");
        let result = scan_input(b"ab\x0bcd", &dirs);
        assert!(matches!(&result.values[0], ScanValue::String(s) if s == b"ab"));
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
    fn swar_scan_long_decimal_matches_std() {
        // Drive the SWAR 8-digit fast path (lengths >= 8) through the real
        // scan_input("%lld") entry point and compare to std::parse ground truth;
        // overflow must clamp to i64::MAX (scan_int saturation semantics).
        let lld = parse_scanf_format(b"%lld");
        let mut st: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..200_000 {
            let ndigits = 8 + (next() % 13) as usize; // 8..=20 digits
            let mut s = Vec::with_capacity(ndigits + 1);
            // first digit non-zero to avoid leading-zero ambiguity in the oracle
            s.push(b'1' + (next() % 9) as u8);
            for _ in 1..ndigits {
                s.push(b'0' + (next() % 10) as u8);
            }
            let res = scan_input(&s, &lld);
            let got = match res.values.first() {
                Some(ScanValue::SignedInt(v)) => *v,
                other => panic!("unexpected scan value {other:?} for {s:?}"),
            };
            let text = std::str::from_utf8(&s).unwrap();
            let want = text.parse::<i64>().unwrap_or(i64::MAX); // overflow clamps
            assert_eq!(got, want, "scan %lld of {text} = {got} want {want}");
        }
    }

    #[test]
    fn swar_scan_long_hex_matches_std() {
        // Drive the SWAR hex fast path (lengths >= 8) through scan_input("%llx")
        // and compare to std hex parse; overflow clamps to u64::MAX.
        let llx = parse_scanf_format(b"%llx");
        let hexset = b"0123456789abcdefABCDEF";
        let mut st: u64 = 0x0123_4567_89ab_cdef;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..200_000 {
            let ndigits = 8 + (next() % 11) as usize; // 8..=18 hex digits
            let mut s = Vec::with_capacity(ndigits);
            // first digit non-zero
            s.push(b"123456789abcdefABCDEF"[(next() % 21) as usize]);
            for _ in 1..ndigits {
                s.push(hexset[(next() % 22) as usize]);
            }
            let res = scan_input(&s, &llx);
            let got = match res.values.first() {
                Some(ScanValue::UnsignedInt(v)) => *v,
                other => panic!("unexpected scan value {other:?} for {s:?}"),
            };
            let text = std::str::from_utf8(&s).unwrap();
            let want = u64::from_str_radix(text, 16).unwrap_or(u64::MAX);
            assert_eq!(got, want, "scan %llx of {text} = {got} want {want}");
        }
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
    fn test_scan_auto_int_binary() {
        let dirs = parse_scanf_format(b"%i");
        let result = scan_input(b"0b1010", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(10)));

        // Uppercase 0B also works
        let result = scan_input(b"0B1111", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(15)));

        // Negative binary
        let result = scan_input(b"-0b1010", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(-10)));
    }

    #[test]
    fn test_scan_auto_int_binary_invalid() {
        // glibc returns 0 conversions when 0b is followed by non-binary digit
        let dirs = parse_scanf_format(b"%i");

        // 0b followed by invalid digit '2'
        let result = scan_input(b"0b2", &dirs);
        assert_eq!(result.count, 0);

        // Just 0b with nothing after
        let result = scan_input(b"0b", &dirs);
        assert_eq!(result.count, 0);

        // 0b followed by letter
        let result = scan_input(b"0bx", &dirs);
        assert_eq!(result.count, 0);
    }

    #[test]
    fn test_scan_long_modifier_is_64bit() {
        // %ld must store a full 64-bit `long`, not truncate to 32 bits.
        let dirs = parse_scanf_format(b"%ld");
        let result = scan_input(b"5000000000", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(
            result.values[0],
            ScanValue::SignedInt(5_000_000_000)
        ));
    }

    #[test]
    fn test_scan_overflow_clamps_to_limit() {
        // An out-of-range integer clamps to the type limit, like glibc:
        // it must not wrap modulo 2^64 to an unrelated value.
        let dirs = parse_scanf_format(b"%ld");
        let result = scan_input(b"99999999999999999999999", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(i64::MAX)));

        let dirs = parse_scanf_format(b"%lu");
        let result = scan_input(b"99999999999999999999999", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::UnsignedInt(u64::MAX)));

        let dirs = parse_scanf_format(b"%ld");
        let result = scan_input(b"-99999999999999999999999", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(i64::MIN)));
    }

    #[test]
    fn test_scan_i_bare_0x_is_matching_failure() {
        // %i with a bare "0x"/"0xZ" (no hex digit) is a matching failure.
        let dirs = parse_scanf_format(b"%i");
        assert_eq!(scan_input(b"0x", &dirs).count, 0);
        assert_eq!(scan_input(b"0xZ", &dirs).count, 0);
        // Sanity: a real hex literal still scans.
        assert_eq!(scan_input(b"0x1f", &dirs).count, 1);
    }

    #[test]
    fn test_scan_unsigned_accepts_minus() {
        // glibc accepts a leading '-' for %u (strtoul negate-wrap).
        let dirs = parse_scanf_format(b"%u");
        let result = scan_input(b"-5", &dirs);
        assert_eq!(result.count, 1);
        // (unsigned int)(-5) == UINT_MAX - 4
        assert!(matches!(
            result.values[0],
            ScanValue::UnsignedInt(0xFFFF_FFFB)
        ));

        let dirs = parse_scanf_format(b"%lu");
        let result = scan_input(b"-5", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(
            result.values[0],
            ScanValue::UnsignedInt(0xFFFF_FFFF_FFFF_FFFB)
        ));

        // A negative unsigned magnitude that overflows `unsigned long`
        // clamps to ULONG_MAX, while exact -ULONG_MAX still negate-wraps.
        let result = scan_input(b"-18446744073709551615", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::UnsignedInt(1)));
        let result = scan_input(b"-18446744073709551616", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::UnsignedInt(u64::MAX)));
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
    fn test_scan_char_does_not_skip_whitespace() {
        let dirs = parse_scanf_format(b"%c");
        let result = scan_input(b"  x", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Char(ref c) = result.values[0] {
            assert_eq!(c, b" ");
        } else {
            panic!("expected Char");
        }
    }

    #[test]
    fn test_scan_space_then_char_skips_whitespace() {
        let dirs = parse_scanf_format(b" %c");
        let result = scan_input(b"  x", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Char(ref c) = result.values[0] {
            assert_eq!(c, b"x");
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
    fn test_scan_int_whitespace_only_is_input_failure() {
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"   ", &dirs);
        assert_eq!(result.count, 0);
        assert!(result.input_failure);
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
    fn test_scan_hex_float_invalid_prefix_is_matching_failure() {
        let dirs = parse_scanf_format(b"%a");
        assert_eq!(scan_input(b"0xyz", &dirs).count, 0);
        assert_eq!(scan_input(b"0x", &dirs).count, 0);

        // glibc accepts `0x.` as a zero hex-float token and consumes through
        // the dot, while leaving a later `p` for the next directive because no
        // real hex digit committed to a binary exponent.
        let result = scan_input(b"0x.", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::Float(v) = result.values[0] {
            assert!(v == 0.0, "expected 0.0, got {}", v);
        } else {
            panic!("expected Float");
        }

        let dirs = parse_scanf_format(b"%a%s");
        let result = scan_input(b"0x.p1", &dirs);
        assert_eq!(result.count, 2);
        if let ScanValue::String(ref s) = result.values[1] {
            assert_eq!(s.as_slice(), b"p1");
        } else {
            panic!("expected trailing string");
        }
    }

    #[test]
    fn test_scan_hex_float_p_without_digits_is_matching_failure() {
        // Host glibc treats a p/P marker after actual hex digits as a
        // committed binary exponent; missing exponent digits fail the whole
        // conversion.
        let dirs = parse_scanf_format(b"%a");
        assert_eq!(scan_input(b"0x1.0p", &dirs).count, 0);
        assert_eq!(scan_input(b"0x1.0P", &dirs).count, 0);
        assert_eq!(scan_input(b"0x.0p", &dirs).count, 0);
    }

    #[test]
    fn test_scan_hex_float_p_sign_without_digits_is_matching_failure() {
        let dirs = parse_scanf_format(b"%a");
        assert_eq!(scan_input(b"0x1.0p-", &dirs).count, 0);
        assert_eq!(scan_input(b"0x1.0p+", &dirs).count, 0);
        assert_eq!(scan_input(b"0x.0p-", &dirs).count, 0);
    }

    #[test]
    fn test_scan_hex_float_p_sign_then_text_is_matching_failure() {
        let dirs = parse_scanf_format(b"%a%s");
        let result = scan_input(b"0x2p-foo", &dirs);
        assert_eq!(result.count, 0);
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
        assert_eq!(result.count, 1);
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

    #[test]
    fn glibc_pointer_nil_parity() {
        // glibc: sscanf("(nil)", "%p") -> n=1, pval=(nil)
        let dirs = parse_scanf_format(b"%p");
        let result = scan_input(b"(nil)", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::Pointer(0)));
    }

    #[test]
    fn glibc_unsigned_negative_wrap_parity() {
        // glibc: sscanf("-1", "%u") -> n=1, uval=4294967295 (UINT_MAX)
        let dirs = parse_scanf_format(b"%u");
        let result = scan_input(b"-1", &dirs);
        assert_eq!(result.count, 1);
        if let ScanValue::UnsignedInt(v) = result.values[0] {
            assert_eq!(v, u32::MAX as u64);
        } else {
            panic!("expected UnsignedInt");
        }
    }

    #[test]
    fn glibc_binary_prefix_0b_parity() {
        // glibc 2.38+: sscanf("0b1010", "%i") -> n=1, val=10 (C23 binary prefix)
        let dirs = parse_scanf_format(b"%i");
        let result = scan_input(b"0b1010", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(10)));
    }

    #[test]
    fn glibc_no_match_returns_zero_not_eof() {
        // glibc: sscanf("abc", "%d") -> n=0 (no match, but input available)
        // This is count=0 without input_failure (input_failure signals EOF).
        let dirs = parse_scanf_format(b"%d");
        let result = scan_input(b"abc", &dirs);
        assert_eq!(result.count, 0);
        // input_failure is true when we couldn't read anything before first
        // conversion failed; this is a matching failure on first directive.
        // glibc returns 0 for this case, not EOF (-1).
    }
}
