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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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
    FromArgPosition(usize),
}

impl Width {
    pub fn uses_arg(self) -> bool {
        matches!(self, Self::FromArg | Self::FromArgPosition(_))
    }

    pub fn position(self) -> Option<usize> {
        match self {
            Self::FromArgPosition(position) => Some(position),
            _ => None,
        }
    }
}

/// Precision specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precision {
    None,
    Fixed(usize),
    FromArg, // '.*'
    FromArgPosition(usize),
}

impl Precision {
    pub fn uses_arg(self) -> bool {
        matches!(self, Self::FromArg | Self::FromArgPosition(_))
    }

    pub fn position(self) -> Option<usize> {
        match self {
            Self::FromArgPosition(position) => Some(position),
            _ => None,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PrintfHandler {
    Invalid = 0,
    SignedDecimal,
    UnsignedOctal,
    UnsignedDecimal,
    UnsignedHexLower,
    UnsignedHexUpper,
    FloatFixed,
    FloatExp,
    FloatGeneral,
    FloatHex,
    Character,
    String,
    Pointer,
    StoreCount,
    LiteralPercent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ArgCategory {
    None = 0,
    SignedInt,
    UnsignedInt,
    Float,
    Pointer,
    String,
    Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueArgKind {
    Gp,
    Fp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloatFormatKind {
    Fixed,
    Exp,
    General,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnsignedFormatKind {
    Decimal,
    Octal,
    HexLower,
    HexUpper,
}

impl UnsignedFormatKind {
    fn int_base(self) -> (u64, bool) {
        match self {
            Self::Decimal => (10, false),
            Self::Octal => (8, false),
            Self::HexLower => (16, false),
            Self::HexUpper => (16, true),
        }
    }

    fn alt_prefix(self) -> &'static [u8] {
        match self {
            Self::Decimal => b"",
            Self::Octal => b"0",
            Self::HexLower => b"0x",
            Self::HexUpper => b"0X",
        }
    }

    fn formatted_prefix(
        self,
        value: u64,
        alt_form: bool,
        first_digit_is_zero: bool,
    ) -> &'static [u8] {
        if !alt_form || value == 0 {
            return b"";
        }
        match self {
            Self::Octal if first_digit_is_zero => b"",
            _ => self.alt_prefix(),
        }
    }

    fn preserves_single_zero_when_suppressed(self, alt_form: bool) -> bool {
        alt_form && matches!(self, Self::Octal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawValueRenderKind {
    SignedInt,
    UnsignedInt(UnsignedFormatKind),
    Float(FloatFormatKind),
    Character,
    Pointer,
}

impl RawValueRenderKind {
    fn unsigned_kind(self) -> Option<UnsignedFormatKind> {
        match self {
            Self::UnsignedInt(kind) => Some(kind),
            _ => None,
        }
    }

    fn int_base(self) -> Option<(u64, bool)> {
        self.unsigned_kind().map(UnsignedFormatKind::int_base)
    }

    fn alt_prefix(self) -> Option<&'static [u8]> {
        self.unsigned_kind().map(UnsignedFormatKind::alt_prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrintfRoute {
    handler: PrintfHandler,
    length_mask: u8,
    flag_mask: u8,
    arg_category: ArgCategory,
}

impl PrintfRoute {
    fn is_valid(self) -> bool {
        !matches!(self.handler, PrintfHandler::Invalid)
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

    fn sanitize_flags(self, flags: &mut FormatFlags) {
        if self.flag_mask & 0b0000_0001 == 0 {
            flags.left_justify = false;
        }
        if self.flag_mask & 0b0000_0010 == 0 {
            flags.force_sign = false;
        }
        if self.flag_mask & 0b0000_0100 == 0 {
            flags.space_sign = false;
        }
        if self.flag_mask & 0b0000_1000 == 0 {
            flags.alt_form = false;
        }
        if self.flag_mask & 0b0001_0000 == 0 {
            flags.zero_pad = false;
        }
    }

    fn value_arg_kind(self) -> Option<ValueArgKind> {
        match self.arg_category {
            ArgCategory::None => None,
            ArgCategory::Float => Some(ValueArgKind::Fp),
            ArgCategory::SignedInt
            | ArgCategory::UnsignedInt
            | ArgCategory::Pointer
            | ArgCategory::String
            | ArgCategory::Store => Some(ValueArgKind::Gp),
        }
    }

    fn raw_render_kind(self) -> Option<RawValueRenderKind> {
        match self.handler {
            PrintfHandler::SignedDecimal => Some(RawValueRenderKind::SignedInt),
            PrintfHandler::UnsignedDecimal => {
                Some(RawValueRenderKind::UnsignedInt(UnsignedFormatKind::Decimal))
            }
            PrintfHandler::UnsignedOctal => {
                Some(RawValueRenderKind::UnsignedInt(UnsignedFormatKind::Octal))
            }
            PrintfHandler::UnsignedHexLower => Some(RawValueRenderKind::UnsignedInt(
                UnsignedFormatKind::HexLower,
            )),
            PrintfHandler::UnsignedHexUpper => Some(RawValueRenderKind::UnsignedInt(
                UnsignedFormatKind::HexUpper,
            )),
            PrintfHandler::FloatFixed => Some(RawValueRenderKind::Float(FloatFormatKind::Fixed)),
            PrintfHandler::FloatExp => Some(RawValueRenderKind::Float(FloatFormatKind::Exp)),
            PrintfHandler::FloatGeneral => {
                Some(RawValueRenderKind::Float(FloatFormatKind::General))
            }
            PrintfHandler::FloatHex => Some(RawValueRenderKind::Float(FloatFormatKind::Hex)),
            PrintfHandler::Character => Some(RawValueRenderKind::Character),
            PrintfHandler::Pointer => Some(RawValueRenderKind::Pointer),
            PrintfHandler::String
            | PrintfHandler::StoreCount
            | PrintfHandler::LiteralPercent
            | PrintfHandler::Invalid => None,
        }
    }

    fn is_string_arg(self) -> bool {
        matches!(self.arg_category, ArgCategory::String)
    }

    fn is_literal_percent(self) -> bool {
        matches!(self.handler, PrintfHandler::LiteralPercent)
    }

    fn is_store_count(self) -> bool {
        matches!(self.handler, PrintfHandler::StoreCount)
    }
}

mod generated_printf_tables {
    include!(concat!(
        env!("OUT_DIR"),
        "/stdio_synth/synth/printf_table.rs"
    ));
}

use generated_printf_tables::PRINTF_TABLE;

/// A parsed printf format specifier.
#[derive(Debug, Clone)]
pub struct FormatSpec {
    pub flags: FormatFlags,
    pub width: Width,
    pub precision: Precision,
    pub length: LengthMod,
    pub conversion: u8,
    pub value_position: Option<usize>,
    route: Option<PrintfRoute>,
}

impl FormatSpec {
    pub fn new(
        flags: FormatFlags,
        width: Width,
        precision: Precision,
        length: LengthMod,
        conversion: u8,
        value_position: Option<usize>,
    ) -> Self {
        let route = if conversion == b'm' {
            None
        } else {
            printf_route(conversion)
        };
        Self {
            flags,
            width,
            precision,
            length,
            conversion,
            value_position,
            route,
        }
    }

    pub fn uses_positional_args(&self) -> bool {
        self.value_position.is_some()
            || self.width.position().is_some()
            || self.precision.position().is_some()
    }

    pub fn consumes_value_arg(&self) -> bool {
        self.value_arg_kind().is_some()
    }

    pub fn value_arg_kind(&self) -> Option<ValueArgKind> {
        if self.conversion == b'm' {
            return None;
        }
        self.route().and_then(PrintfRoute::value_arg_kind)
    }

    pub fn positional_width_arg_kind(&self) -> Option<(usize, ValueArgKind)> {
        self.width
            .position()
            .map(|position| (position, ValueArgKind::Gp))
    }

    pub fn positional_precision_arg_kind(&self) -> Option<(usize, ValueArgKind)> {
        self.precision
            .position()
            .map(|position| (position, ValueArgKind::Gp))
    }

    pub fn positional_value_arg_kind(&self) -> Option<(usize, ValueArgKind)> {
        self.value_position.zip(self.value_arg_kind())
    }

    pub fn value_arg_is_float(&self) -> bool {
        matches!(self.value_arg_kind(), Some(ValueArgKind::Fp))
    }

    pub fn value_arg_is_gp(&self) -> bool {
        matches!(self.value_arg_kind(), Some(ValueArgKind::Gp))
    }

    pub fn value_arg_is_string(&self) -> bool {
        self.route().is_some_and(PrintfRoute::is_string_arg)
    }

    pub fn is_literal_percent(&self) -> bool {
        self.route().is_some_and(PrintfRoute::is_literal_percent)
    }

    pub fn is_errno_message(&self) -> bool {
        self.conversion == b'm'
    }

    pub fn stores_count(&self) -> bool {
        self.route().is_some_and(PrintfRoute::is_store_count)
    }

    fn raw_render_kind(&self) -> Option<RawValueRenderKind> {
        self.route().and_then(PrintfRoute::raw_render_kind)
    }

    fn int_base(&self) -> (u64, bool) {
        self.raw_render_kind()
            .and_then(RawValueRenderKind::int_base)
            .unwrap_or((10, false))
    }

    fn alt_prefix(&self) -> &'static [u8] {
        if !self.flags.alt_form {
            return b"";
        }
        self.raw_render_kind()
            .and_then(RawValueRenderKind::alt_prefix)
            .unwrap_or(b"")
    }

    pub fn render_value_arg(&self, raw: u64, buf: &mut Vec<u8>) -> bool {
        match self.raw_render_kind() {
            Some(RawValueRenderKind::SignedInt) => {
                let val = match self.length {
                    LengthMod::Hh => (raw as i8) as i64,
                    LengthMod::H => (raw as i16) as i64,
                    LengthMod::L | LengthMod::Ll | LengthMod::J => raw as i64,
                    _ => (raw as i32) as i64,
                };
                format_signed(val, self, buf);
                true
            }
            Some(RawValueRenderKind::UnsignedInt(_)) => {
                let val = match self.length {
                    LengthMod::Hh => (raw as u8) as u64,
                    LengthMod::H => (raw as u16) as u64,
                    LengthMod::L | LengthMod::Ll | LengthMod::J | LengthMod::Z => raw,
                    _ => (raw as u32) as u64,
                };
                format_unsigned(val, self, buf);
                true
            }
            Some(RawValueRenderKind::Float(_)) => {
                format_float(f64::from_bits(raw), self, buf);
                true
            }
            Some(RawValueRenderKind::Character) => {
                format_char(raw as u8, self, buf);
                true
            }
            Some(RawValueRenderKind::Pointer) => {
                format_pointer(raw as usize, self, buf);
                true
            }
            None => false,
        }
    }

    fn route(&self) -> Option<PrintfRoute> {
        if self.conversion == b'm' {
            None
        } else {
            self.route.or_else(|| printf_route(self.conversion))
        }
    }
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
    /// For `%m` extension (strerror(errno)).
    Errno,
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

/// Whether a format string uses implicit, explicit, or mixed argument numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatPositionalMode {
    None,
    Implicit,
    Explicit,
    Mixed,
}

/// First-use validation artifact for a parsed printf format string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatStringCertificate {
    pub format_hash: u64,
    pub positional_mode: FormatPositionalMode,
    pub directive_count: usize,
    pub malformed_directive_count: usize,
    pub percent_escape_count: usize,
    pub writeback_directive_count: usize,
}

impl FormatStringCertificate {
    pub fn valid_for_render(self) -> bool {
        self.malformed_directive_count == 0
            && !matches!(self.positional_mode, FormatPositionalMode::Mixed)
    }
}

/// Observable cache telemetry for first-use format validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatStringCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: usize,
}

#[expect(
    dead_code,
    reason = "format-string certificate caching is staged for follow-up integration into printf rendering"
)]
fn stable_format_hash(fmt: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in fmt {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn format_string_certificate_cache() -> &'static Mutex<HashMap<Vec<u8>, FormatStringCertificate>> {
    static CACHE: OnceLock<Mutex<HashMap<Vec<u8>, FormatStringCertificate>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn format_string_cache_hits() -> &'static AtomicU64 {
    static HITS: AtomicU64 = AtomicU64::new(0);
    &HITS
}

fn format_string_cache_misses() -> &'static AtomicU64 {
    static MISSES: AtomicU64 = AtomicU64::new(0);
    &MISSES
}

#[expect(
    dead_code,
    reason = "format-string certificate caching is staged for follow-up integration into printf rendering"
)]
fn store_format_string_certificate(fmt: &[u8], certificate: FormatStringCertificate) {
    let mut cache = format_string_certificate_cache()
        .lock()
        .expect("format-string certificate cache mutex poisoned");
    if cache.contains_key(fmt) {
        format_string_cache_hits().fetch_add(1, Ordering::Relaxed);
    } else {
        cache.insert(fmt.to_vec(), certificate);
        format_string_cache_misses().fetch_add(1, Ordering::Relaxed);
    }
}

pub fn format_string_cache_stats() -> FormatStringCacheStats {
    let cache = format_string_certificate_cache()
        .lock()
        .expect("format-string certificate cache mutex poisoned");
    FormatStringCacheStats {
        hits: format_string_cache_hits().load(Ordering::Relaxed),
        misses: format_string_cache_misses().load(Ordering::Relaxed),
        entries: cache.len(),
    }
}

#[cfg(test)]
#[expect(
    dead_code,
    reason = "test-only cache reset helper is kept for focused printf cache tests"
)]
fn reset_format_string_cache_for_tests() {
    let mut cache = format_string_certificate_cache()
        .lock()
        .expect("format-string certificate cache mutex poisoned");
    cache.clear();
    format_string_cache_hits().store(0, Ordering::Relaxed);
    format_string_cache_misses().store(0, Ordering::Relaxed);
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
    let value_position = if let Some((position, consumed)) = parse_positional_index(fmt) {
        pos += consumed;
        Some(position)
    } else {
        None
    };

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
        if let Some((position, consumed)) = parse_positional_index(&fmt[pos..]) {
            pos += consumed;
            Width::FromArgPosition(position)
        } else {
            Width::FromArg
        }
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
            if let Some((position, consumed)) = parse_positional_index(&fmt[pos..]) {
                pos += consumed;
                Precision::FromArgPosition(position)
            } else {
                Precision::FromArg
            }
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

    let route = if conversion == b'm' {
        None
    } else {
        let route = printf_route(conversion)?;
        if !route.accepts_length(length) {
            return None;
        }
        route.sanitize_flags(&mut flags);
        Some(route)
    };

    Some((
        FormatSpec {
            flags,
            width,
            precision,
            length,
            conversion,
            value_position,
            route,
        },
        pos,
    ))
}

fn printf_route(conversion: u8) -> Option<PrintfRoute> {
    let route = PRINTF_TABLE[conversion as usize];
    if !route.is_valid() { None } else { Some(route) }
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

    let (base, uppercase) = spec.int_base();
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
    let prefix = spec.alt_prefix();

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
    let (base, uppercase) = spec.int_base();
    let mut digits = [0u8; 64];
    let digit_count = render_digits(value, base, uppercase, &mut digits);
    let digit_slice = &digits[64 - digit_count..];
    let unsigned_kind = spec
        .raw_render_kind()
        .and_then(RawValueRenderKind::unsigned_kind);

    let precision = match spec.precision {
        Precision::Fixed(p) => p,
        _ => 1,
    };
    let zero_prefix_count = precision.saturating_sub(digit_count);

    // For octal with # flag: only add "0" prefix if precision doesn't already
    // ensure a leading zero. Per C11 7.21.6.1: "For o conversion, it increases
    // the precision, if and only if necessary, to force the first digit to be zero"
    let first_digit_is_zero = zero_prefix_count > 0 || (digit_count > 0 && digit_slice[0] == b'0');
    let prefix: &[u8] = unsigned_kind
        .map(|kind| kind.formatted_prefix(value, spec.flags.alt_form, first_digit_is_zero))
        .unwrap_or(b"");

    let content_len = prefix.len() + zero_prefix_count + digit_count;

    let mut suppress_zero = value == 0 && matches!(spec.precision, Precision::Fixed(0));
    // POSIX: For 'o' conversion with '#', if the value and precision are both 0, a single 0 is printed.
    if suppress_zero
        && unsigned_kind
            .is_some_and(|kind| kind.preserves_single_zero_when_suppressed(spec.flags.alt_form))
    {
        suppress_zero = false;
    }

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
        Precision::FromArg | Precision::FromArgPosition(_) => 6,
    };

    // Handle special values.
    if value.is_nan() || value.is_infinite() {
        let negative = value.is_sign_negative();
        let sign_prefix: &[u8] = if negative {
            b"-"
        } else if spec.flags.force_sign {
            b"+"
        } else if spec.flags.space_sign {
            b" "
        } else {
            b""
        };
        let label: &[u8] = if value.is_nan() {
            if spec.conversion.is_ascii_uppercase() {
                b"NAN"
            } else {
                b"nan"
            }
        } else if spec.conversion.is_ascii_uppercase() {
            b"INF"
        } else {
            b"inf"
        };
        let total_len = sign_prefix.len() + label.len();
        let width = resolve_width(spec);
        let pad_total = width.saturating_sub(total_len);
        if !spec.flags.left_justify {
            pad(buf, b' ', pad_total);
        }
        buf.extend_from_slice(sign_prefix);
        buf.extend_from_slice(label);
        if spec.flags.left_justify {
            pad(buf, b' ', pad_total);
        }
        return;
    }

    let negative = value.is_sign_negative();
    let abs = value.abs();

    // Generate digit string.
    let body = match spec.raw_render_kind() {
        Some(RawValueRenderKind::Float(FloatFormatKind::Fixed)) => {
            format_f(abs, precision, spec.flags.alt_form)
        }
        Some(RawValueRenderKind::Float(FloatFormatKind::Exp)) => format_e(
            abs,
            precision,
            spec.conversion.is_ascii_uppercase(),
            spec.flags.alt_form,
        ),
        Some(RawValueRenderKind::Float(FloatFormatKind::General)) => format_g(
            abs,
            precision,
            spec.conversion.is_ascii_uppercase(),
            spec.flags.alt_form,
        ),
        Some(RawValueRenderKind::Float(FloatFormatKind::Hex)) => format_a(
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

fn parse_positional_index(fmt: &[u8]) -> Option<(usize, usize)> {
    let mut pos = 0usize;
    while pos < fmt.len() && fmt[pos].is_ascii_digit() {
        pos += 1;
    }
    if pos == 0 || pos >= fmt.len() || fmt[pos] != b'$' {
        return None;
    }
    let position = parse_decimal(&fmt[..pos]);
    if position == 0 {
        return None;
    }
    Some((position, pos + 1))
}

fn resolve_width(spec: &FormatSpec) -> usize {
    match spec.width {
        Width::Fixed(w) => w,
        _ => 0,
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

fn pad(buf: &mut Vec<u8>, byte: u8, count: usize) {
    // Bounded to prevent pathological allocations while allowing POSIX-conformant
    // wide fields. 1 MiB is generous enough for any real-world format width.
    let count = count.min(1_048_576);
    buf.extend(std::iter::repeat_n(byte, count));
}

/// `%f` / `%F` formatting: fixed-point decimal.
fn format_f(value: f64, precision: usize, alt_form: bool) -> String {
    if precision == 0 {
        // Use Rust's Display to format the integer part rather than casting to u64,
        // which would saturate for values > u64::MAX (~1.8e19).
        // round_ties_even implements IEEE 754 round-half-to-even (banker's rounding)
        // per POSIX conformance requirements.
        let rounded = value.round_ties_even();
        if alt_form {
            alloc::format!("{rounded:.0}.")
        } else {
            alloc::format!("{rounded:.0}")
        }
    } else {
        alloc::format!("{:.prec$}", value, prec = precision)
    }
}

/// `%e` / `%E` formatting: scientific notation.
fn format_e(value: f64, precision: usize, uppercase: bool, alt_form: bool) -> String {
    let e_char = if uppercase { 'E' } else { 'e' };
    if value == 0.0 {
        if precision == 0 {
            let dot = if alt_form { "." } else { "" };
            return alloc::format!("0{dot}{e_char}+00");
        }
        let zeros: String = core::iter::repeat_n('0', precision).collect();
        return alloc::format!("0.{zeros}{e_char}+00");
    }
    // Use log10 + floor to compute the exponent, then correct for rounding
    // edge cases (e.g., log10(1e15) might yield 14.999… instead of 15).
    let mut exp = value.log10().floor() as i32;
    let mut mantissa = if exp.abs() > 300 {
        let mut m = value;
        if exp > 0 {
            for _ in 0..exp {
                m /= 10.0;
            }
        } else {
            for _ in 0..(-exp) {
                m *= 10.0;
            }
        }
        m
    } else {
        value / 10_f64.powi(exp)
    };
    // Correct log10 imprecision: mantissa should be in [1.0, 10.0).
    if mantissa >= 10.0 {
        mantissa /= 10.0;
        exp += 1;
    } else if mantissa < 1.0 && mantissa > 0.0 {
        mantissa *= 10.0;
        exp -= 1;
    }
    // Handle rounding carry: rounding the formatted mantissa may push it to 10.
    // Use round_ties_even for IEEE 754 banker's rounding compliance.
    let scale = 10_f64.powi(precision as i32);
    let rounded_mantissa = (mantissa * scale).round_ties_even() / scale;
    if rounded_mantissa >= 10.0 {
        mantissa = rounded_mantissa / 10.0;
        exp += 1;
    }
    let sign = if exp < 0 { '-' } else { '+' };
    let abs_exp = exp.unsigned_abs();
    if precision == 0 {
        let digit = mantissa.round_ties_even() as u64;
        let dot = if alt_form { "." } else { "" };
        alloc::format!("{digit}{dot}{e_char}{sign}{abs_exp:02}")
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
    // C11 7.21.6.1 para 8: use %e style iff exp < -4 OR exp >= precision;
    // otherwise %f. The lower bound is -4 (not -1): e.g. 0.0001234 has
    // exp = -4 and precision = 6, so it must render as "0.0001234".
    if exp >= -4 && exp < p as i32 {
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

/// `%a` / `%A` formatting: hexadecimal floating-point.
///
/// Produces output of the form `0xh.hhhhp±d` where `h` are hex digits and
/// `d` is the binary exponent in decimal.
fn format_a(value: f64, precision: usize, uppercase: bool, alt_form: bool) -> String {
    let p_char = if uppercase { 'P' } else { 'p' };
    let hex_alpha = if uppercase { b'A' } else { b'a' };

    if value == 0.0 {
        let prefix = if uppercase { "0X" } else { "0x" };
        if precision == 0 && !alt_form {
            return alloc::format!("{prefix}0{p_char}+0");
        }
        let prec = if precision == 0 { 0 } else { precision };
        if prec == 0 {
            return alloc::format!("{prefix}0.{p_char}+0");
        }
        let zeros: String = core::iter::repeat_n('0', prec).collect();
        return alloc::format!("{prefix}0.{zeros}{p_char}+0");
    }

    let bits = value.to_bits();
    let mantissa_bits = bits & 0x000F_FFFF_FFFF_FFFF;
    let biased_exp = ((bits >> 52) & 0x7FF) as i32;

    let (lead_digit, bin_exp) = if biased_exp == 0 {
        // Subnormal: leading digit is 0, exponent is -1022.
        (0u8, -1022i32)
    } else {
        // Normal: leading digit is 1, exponent is biased_exp - 1023.
        (1u8, biased_exp - 1023)
    };

    // The 52-bit mantissa gives 13 hex digits of fractional part.
    let default_prec = 13;
    let prec = if precision == 0 && !alt_form {
        // When precision is unspecified (0 default), use enough digits to
        // represent the value exactly.
        if mantissa_bits == 0 {
            0
        } else {
            // Strip trailing zero nibbles.
            let mut trailing = 0;
            let mut m = mantissa_bits;
            while m & 0xF == 0 && trailing < default_prec {
                m >>= 4;
                trailing += 1;
            }
            default_prec - trailing
        }
    } else {
        precision
    };

    let prefix = if uppercase { "0X" } else { "0x" };
    let sign = if bin_exp < 0 { '-' } else { '+' };
    let abs_exp = bin_exp.unsigned_abs();

    if prec == 0 {
        let dot = if alt_form { "." } else { "" };
        let lead_hex = if lead_digit < 10 {
            (b'0' + lead_digit) as char
        } else {
            (hex_alpha + (lead_digit - 10)) as char
        };
        alloc::format!("{prefix}{lead_hex}{dot}{p_char}{sign}{abs_exp}")
    } else {
        // Build hex fractional digits from mantissa_bits, left-to-right.
        let mut frac = String::with_capacity(prec);
        for i in 0..prec {
            let nibble = if i < default_prec {
                ((mantissa_bits >> (48 - i * 4)) & 0xF) as u8
            } else {
                0
            };
            let ch = if nibble < 10 {
                (b'0' + nibble) as char
            } else {
                (hex_alpha + (nibble - 10)) as char
            };
            frac.push(ch);
        }
        alloc::format!("{prefix}{lead_digit}.{frac}{p_char}{sign}{abs_exp}")
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
        assert_eq!(spec.value_position, None);
    }

    #[test]
    fn test_generated_printf_table_routes_core_specifiers() {
        let signed = printf_route(b'd').expect("signed decimal route");
        let floating = printf_route(b'g').expect("general float route");
        let literal = printf_route(b'%').expect("literal percent route");

        assert_eq!(signed.handler, PrintfHandler::SignedDecimal);
        assert_eq!(signed.arg_category, ArgCategory::SignedInt);
        assert_eq!(signed.value_arg_kind(), Some(ValueArgKind::Gp));
        assert_eq!(
            signed.raw_render_kind(),
            Some(RawValueRenderKind::SignedInt)
        );
        assert!(signed.accepts_length(LengthMod::L));
        assert!(!signed.accepts_length(LengthMod::BigL));
        assert_eq!(floating.handler, PrintfHandler::FloatGeneral);
        assert_eq!(floating.arg_category, ArgCategory::Float);
        assert_eq!(floating.value_arg_kind(), Some(ValueArgKind::Fp));
        assert_eq!(
            floating.raw_render_kind(),
            Some(RawValueRenderKind::Float(FloatFormatKind::General))
        );
        assert_eq!(literal.handler, PrintfHandler::LiteralPercent);
        assert!(literal.is_literal_percent());
        assert_eq!(
            printf_route(b'X').and_then(PrintfRoute::raw_render_kind),
            Some(RawValueRenderKind::UnsignedInt(
                UnsignedFormatKind::HexUpper
            ))
        );
        assert_eq!(
            printf_route(b'X')
                .and_then(PrintfRoute::raw_render_kind)
                .and_then(RawValueRenderKind::int_base),
            Some((16, true))
        );
        assert_eq!(
            printf_route(b'o')
                .and_then(PrintfRoute::raw_render_kind)
                .and_then(RawValueRenderKind::unsigned_kind),
            Some(UnsignedFormatKind::Octal)
        );
        assert!(printf_route(b'Q').is_none());
    }

    #[test]
    fn test_format_spec_route_helpers_follow_generated_metadata() {
        let signed = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'd',
            None,
        );
        let string = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b's',
            None,
        );
        let float = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'f',
            None,
        );
        let store = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'n',
            None,
        );
        let percent = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'%',
            None,
        );
        let errno = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'm',
            None,
        );
        let positional = FormatSpec::new(
            FormatFlags::default(),
            Width::FromArgPosition(2),
            Precision::FromArgPosition(4),
            LengthMod::None,
            b'd',
            Some(3),
        );

        assert!(signed.consumes_value_arg());
        assert_eq!(signed.value_arg_kind(), Some(ValueArgKind::Gp));
        assert!(signed.value_arg_is_gp());
        assert!(!signed.value_arg_is_string());
        assert!(!signed.stores_count());
        assert_eq!(
            signed.raw_render_kind(),
            Some(RawValueRenderKind::SignedInt)
        );
        assert!(string.value_arg_is_string());
        assert_eq!(string.value_arg_kind(), Some(ValueArgKind::Gp));
        assert!(string.value_arg_is_gp());
        assert_eq!(float.value_arg_kind(), Some(ValueArgKind::Fp));
        assert!(float.value_arg_is_float());
        assert!(!float.value_arg_is_gp());
        assert_eq!(
            float.raw_render_kind(),
            Some(RawValueRenderKind::Float(FloatFormatKind::Fixed))
        );
        assert!(store.stores_count());
        assert_eq!(store.value_arg_kind(), Some(ValueArgKind::Gp));
        assert!(store.value_arg_is_gp());
        assert!(percent.is_literal_percent());
        assert!(errno.is_errno_message());
        assert!(!errno.consumes_value_arg());
        assert_eq!(errno.value_arg_kind(), None);
        assert!(!errno.value_arg_is_gp());
        assert_eq!(
            positional.positional_width_arg_kind(),
            Some((2, ValueArgKind::Gp))
        );
        assert_eq!(
            positional.positional_precision_arg_kind(),
            Some((4, ValueArgKind::Gp))
        );
        assert_eq!(
            positional.positional_value_arg_kind(),
            Some((3, ValueArgKind::Gp))
        );
        assert_eq!(errno.positional_value_arg_kind(), None);

        let hex = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'x',
            None,
        );
        assert_eq!(
            hex.raw_render_kind(),
            Some(RawValueRenderKind::UnsignedInt(
                UnsignedFormatKind::HexLower
            ))
        );
        assert_eq!(
            hex.raw_render_kind()
                .and_then(RawValueRenderKind::alt_prefix),
            Some(&b"0x"[..])
        );
        assert_eq!(
            FormatSpec::new(
                FormatFlags {
                    alt_form: true,
                    ..FormatFlags::default()
                },
                Width::None,
                Precision::Fixed(0),
                LengthMod::None,
                b'o',
                None,
            )
            .raw_render_kind()
            .and_then(RawValueRenderKind::unsigned_kind)
            .map(|kind| kind.preserves_single_zero_when_suppressed(true)),
            Some(true)
        );
    }

    #[test]
    fn test_render_value_arg_routes_non_string_handlers() {
        let hex = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'x',
            None,
        );
        let pointer = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'p',
            None,
        );
        let string = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b's',
            None,
        );

        let mut buf = Vec::new();
        assert!(hex.render_value_arg(0x2a, &mut buf));
        assert_eq!(buf, b"2a");

        buf.clear();
        assert!(pointer.render_value_arg(0x1234, &mut buf));
        assert_eq!(buf, b"0x1234");

        buf.clear();
        assert!(!string.render_value_arg(0x1234, &mut buf));
        assert!(buf.is_empty());
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
    fn test_parse_invalid_length_modifier_rejects_printf_spec() {
        assert!(parse_format_spec(b"Ls").is_none());
    }

    #[test]
    fn test_parse_sanitizes_flags_using_generated_route_mask() {
        let (spec, _) = parse_format_spec(b"+#0s").unwrap();
        assert!(!spec.flags.force_sign);
        assert!(!spec.flags.alt_form);
        assert!(!spec.flags.zero_pad);
        assert!(!spec.flags.space_sign);
        assert!(!spec.flags.left_justify);
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
    fn test_parse_positional_value_width_and_precision() {
        let (spec, consumed) = parse_format_spec(b"3$*2$.*1$f").unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(spec.value_position, Some(3));
        assert_eq!(spec.width, Width::FromArgPosition(2));
        assert_eq!(spec.precision, Precision::FromArgPosition(1));
        assert_eq!(spec.conversion, b'f');
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
    fn test_parse_format_string_positional_segments() {
        let segments = parse_format_string(b"%2$s is %1$d");
        assert_eq!(segments.len(), 3);
        assert!(
            matches!(&segments[0], FormatSegment::Spec(s) if s.value_position == Some(2) && s.conversion == b's')
        );
        assert!(matches!(segments[1], FormatSegment::Literal(b" is ")));
        assert!(
            matches!(&segments[2], FormatSegment::Spec(s) if s.value_position == Some(1) && s.conversion == b'd')
        );
    }

    #[test]
    fn test_format_signed_basic() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'd',
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
        };
        let mut buf = Vec::new();
        format_float(f64::INFINITY, &spec, &mut buf);
        assert_eq!(&buf, b"inf");
    }

    #[test]
    fn test_format_float_bankers_rounding() {
        // IEEE 754 round-half-to-even (banker's rounding) test.
        // 2.5 -> 2 (nearest even), 3.5 -> 4 (nearest even), 1.5 -> 2 (nearest even)
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::Fixed(0),
            length: LengthMod::None,
            conversion: b'f',
            value_position: None,
            route: None,
        };

        let mut buf = Vec::new();
        format_float(2.5, &spec, &mut buf);
        assert_eq!(&buf, b"2", "2.5 should round to 2 (nearest even)");

        buf.clear();
        format_float(3.5, &spec, &mut buf);
        assert_eq!(&buf, b"4", "3.5 should round to 4 (nearest even)");

        buf.clear();
        format_float(1.5, &spec, &mut buf);
        assert_eq!(&buf, b"2", "1.5 should round to 2 (nearest even)");

        buf.clear();
        format_float(-2.5, &spec, &mut buf);
        assert_eq!(&buf, b"-2", "-2.5 should round to -2 (nearest even)");

        buf.clear();
        format_float(-3.5, &spec, &mut buf);
        assert_eq!(&buf, b"-4", "-3.5 should round to -4 (nearest even)");

        // Confirm non-half values round normally
        buf.clear();
        format_float(2.4, &spec, &mut buf);
        assert_eq!(&buf, b"2", "2.4 rounds to 2");

        buf.clear();
        format_float(2.6, &spec, &mut buf);
        assert_eq!(&buf, b"3", "2.6 rounds to 3");
    }

    #[test]
    fn test_precision_zero_int() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::Fixed(0),
            length: LengthMod::None,
            conversion: b'd',
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
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
            value_position: None,
            route: None,
        };
        let mut buf = Vec::new();
        format_signed(i64::MIN, &spec, &mut buf);
        assert_eq!(&buf, b"-9223372036854775808");
    }
}
