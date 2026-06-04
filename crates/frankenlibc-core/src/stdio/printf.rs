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

use crate::{ArtifactHashMap, artifact_hash_map};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const MAX_FLOAT_PRECISION: usize = 65_535;

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
    pub group: bool,        // '\'' (POSIX thousands grouping)
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
#[derive(Debug, Clone, Copy)]
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

    /// True when no flags, width, or precision are set: the bare `%d`/`%u`
    /// conversion whose output is just the (optionally `-`-signed) digits, with
    /// no prefix or padding. Lets the integer formatters skip the entire
    /// prefix/precision/width/justify pipeline on the overwhelmingly common
    /// case. A few branch tests in exchange for ~15 skipped operations.
    fn is_bare_integer(&self) -> bool {
        let f = &self.flags;
        !f.left_justify
            && !f.force_sign
            && !f.space_sign
            && !f.alt_form
            && !f.zero_pad
            && !f.group
            && matches!(self.width, Width::None)
            && matches!(self.precision, Precision::None)
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

pub fn positional_printf_arg_plan(segments: &[FormatSegment<'_>]) -> Option<Vec<ValueArgKind>> {
    let mut any_positional = false;
    let mut plan: Vec<Option<ValueArgKind>> = Vec::new();

    let mut assign = |position: usize, kind: ValueArgKind| {
        if position == 0 {
            return;
        }
        any_positional = true;
        let slot = position - 1;
        if slot >= plan.len() {
            plan.resize(slot + 1, None);
        }
        if plan[slot].is_none() {
            plan[slot] = Some(kind);
        }
    };

    for seg in segments {
        if let FormatSegment::Spec(spec) = seg {
            if let Some((position, kind)) = spec.positional_width_arg_kind() {
                assign(position, kind);
            }
            if let Some((position, kind)) = spec.positional_precision_arg_kind() {
                assign(position, kind);
            }
            if let Some((position, kind)) = spec.positional_value_arg_kind() {
                assign(position, kind);
            }
        }
    }

    any_positional.then(|| {
        plan.into_iter()
            .map(|kind| kind.unwrap_or(ValueArgKind::Gp))
            .collect()
    })
}

pub fn count_printf_args(segments: &[FormatSegment<'_>]) -> usize {
    if let Some(plan) = positional_printf_arg_plan(segments) {
        return plan.len();
    }

    let mut needed = 0usize;
    for seg in segments {
        if let FormatSegment::Spec(spec) = seg {
            if spec.width.uses_arg() {
                needed += 1;
            }
            if spec.precision.uses_arg() {
                needed += 1;
            }
            if spec.consumes_value_arg() {
                needed += 1;
            }
        }
    }
    needed
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
#[derive(Debug, Clone, Copy)]
pub enum FormatSegment<'a> {
    /// Literal bytes to emit verbatim.
    Literal(&'a [u8]),
    /// A `%%` escape (emit a single '%').
    Percent,
    /// A conversion specifier requiring an argument.
    Spec(FormatSpec),
}

/// Parsed printf segments with a no-heap fast path for one-segment formats.
#[derive(Debug, Clone)]
pub struct FormatSegments<'a> {
    first: Option<FormatSegment<'a>>,
    heap: Option<Vec<FormatSegment<'a>>>,
}

impl<'a> FormatSegments<'a> {
    pub fn new() -> Self {
        Self {
            first: None,
            heap: None,
        }
    }

    pub fn as_slice(&self) -> &[FormatSegment<'a>] {
        match &self.heap {
            Some(heap) => heap.as_slice(),
            None => self.first.as_slice(),
        }
    }

    pub fn push(&mut self, segment: FormatSegment<'a>) {
        if let Some(heap) = &mut self.heap {
            heap.push(segment);
            return;
        }

        if self.first.is_none() {
            self.first = Some(segment);
            return;
        }

        let mut heap = Vec::with_capacity(8);
        heap.push(self.first.take().expect("first segment present"));
        heap.push(segment);
        self.heap = Some(heap);
    }
}

impl<'a> Default for FormatSegments<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Deref for FormatSegments<'a> {
    type Target = [FormatSegment<'a>];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

pub enum FormatSegmentsIntoIter<'a> {
    One(std::option::IntoIter<FormatSegment<'a>>),
    Heap(std::vec::IntoIter<FormatSegment<'a>>),
}

impl<'a> Iterator for FormatSegmentsIntoIter<'a> {
    type Item = FormatSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::One(iter) => iter.next(),
            Self::Heap(iter) => iter.next(),
        }
    }
}

impl<'a> IntoIterator for FormatSegments<'a> {
    type Item = FormatSegment<'a>;
    type IntoIter = FormatSegmentsIntoIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self.heap {
            Some(heap) => FormatSegmentsIntoIter::Heap(heap.into_iter()),
            None => FormatSegmentsIntoIter::One(self.first.into_iter()),
        }
    }
}

impl<'segments, 'a> IntoIterator for &'segments FormatSegments<'a> {
    type Item = &'segments FormatSegment<'a>;
    type IntoIter = std::slice::Iter<'segments, FormatSegment<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
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

fn format_string_certificate_cache()
-> &'static Mutex<ArtifactHashMap<Vec<u8>, FormatStringCertificate>> {
    static CACHE: OnceLock<Mutex<ArtifactHashMap<Vec<u8>, FormatStringCertificate>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(artifact_hash_map()))
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
            // POSIX thousands-grouping flag. The active locale is the C
            // locale (empty `grouping`/`thousands_sep`), so glibc emits no
            // separators and the flag is a no-op — but it must be accepted
            // and consumed, not treated as the conversion specifier.
            b'\'' => flags.group = true,
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
pub fn parse_format_string(fmt: &[u8]) -> FormatSegments<'_> {
    let mut segments = FormatSegments::new();
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

    // Fast path: a bare `%d`/`%i` (base 10, no flags/width/precision) emits an
    // optional '-' followed by the digits — nothing else. Skips the entire
    // prefix/precision/width/justify pipeline below. Parity-identical: with no
    // flags the only sign possible is '-' for a negative value.
    if base == 10 && spec.is_bare_integer() {
        if negative {
            buf.push(b'-');
        }
        buf.extend_from_slice(digit_slice);
        return;
    }

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

    // Fast path: a bare `%u` (base 10, no flags/width/precision) emits just the
    // digits — base 10 has no alternate-form prefix, so there is nothing else
    // to compute. Skips the prefix/precision/width/justify pipeline below.
    if base == 10 && spec.is_bare_integer() {
        buf.extend_from_slice(digit_slice);
        return;
    }

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
    // Rust's core::fmt stores precision as u16 internally and panics with
    // "Formatting argument out of range" for precision >= 65536. Cap to
    // 65535 to prevent a process abort from any adversarial `%.99999f`-style
    // format string. Formats above this already panic with today's code, so
    // capping loses no currently-working behavior. (bd-h7ede)
    let precision = precision.min(MAX_FLOAT_PRECISION);

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
            hex_float_precision(spec),
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

    let hex_zero_prefix_len = if spec.flags.zero_pad
        && spec
            .raw_render_kind()
            .is_some_and(|kind| kind == RawValueRenderKind::Float(FloatFormatKind::Hex))
        && (body.starts_with("0x") || body.starts_with("0X"))
    {
        2
    } else {
        0
    };

    if !spec.flags.left_justify && !spec.flags.zero_pad {
        pad(buf, b' ', pad_total);
    }
    if let Some(s) = sign {
        buf.push(s);
    }
    if hex_zero_prefix_len > 0 {
        buf.extend_from_slice(&body.as_bytes()[..hex_zero_prefix_len]);
    }
    if !spec.flags.left_justify && spec.flags.zero_pad {
        pad(buf, b'0', pad_total);
    }
    buf.extend_from_slice(&body.as_bytes()[hex_zero_prefix_len..]);
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

fn hex_float_precision(spec: &FormatSpec) -> Option<usize> {
    match spec.precision {
        Precision::Fixed(p) => Some(p.min(MAX_FLOAT_PRECISION)),
        Precision::None => None,
        Precision::FromArg | Precision::FromArgPosition(_) => Some(6),
    }
}

fn resolve_width(spec: &FormatSpec) -> usize {
    match spec.width {
        Width::Fixed(w) => w,
        _ => 0,
    }
}

/// Render `value` in the given `base` into the END of `buf`.
/// Returns the number of digits written. Digits are placed right-aligned.
/// Two-ASCII-digit lookup table for decimal pairs `00`..=`99`, built at compile
/// time (`DEC_PAIRS[2*n..2*n+2]` is the zero-padded decimal of `n`). Used by
/// [`render_decimal`] to emit two digits per division.
static DEC_PAIRS: [u8; 200] = build_dec_pairs();

const fn build_dec_pairs() -> [u8; 200] {
    let mut table = [0u8; 200];
    let mut n = 0usize;
    while n < 100 {
        table[2 * n] = b'0' + (n / 10) as u8;
        table[2 * n + 1] = b'0' + (n % 10) as u8;
        n += 1;
    }
    table
}

/// Specialised decimal renderer (base 10): emits two digits per iteration via
/// [`DEC_PAIRS`] with a compile-time divisor of 100, so the compiler lowers the
/// division to a magic-multiply instead of the runtime `DIV` that the
/// general-base [`render_digits`] loop is forced to use. Writes least-
/// significant digits at the high end of `buf` and returns the digit count —
/// byte-for-byte identical output to the general loop with `base == 10`.
fn render_decimal(mut value: u64, buf: &mut [u8; 64]) -> usize {
    let mut pos = 64;
    while value >= 100 {
        let pair = (value % 100) as usize;
        value /= 100;
        pos -= 2;
        buf[pos] = DEC_PAIRS[2 * pair];
        buf[pos + 1] = DEC_PAIRS[2 * pair + 1];
    }
    // 0..=99 remains: one digit if < 10, else the final pair.
    if value >= 10 {
        let pair = value as usize;
        pos -= 2;
        buf[pos] = DEC_PAIRS[2 * pair];
        buf[pos + 1] = DEC_PAIRS[2 * pair + 1];
    } else {
        pos -= 1;
        buf[pos] = b'0' + value as u8;
    }
    64 - pos
}

fn render_digits(mut value: u64, base: u64, uppercase: bool, buf: &mut [u8; 64]) -> usize {
    // Decimal is the overwhelmingly common case (%d/%i/%u); take the LUT path
    // with a const divisor. The general loop below handles hex/octal/binary.
    if base == 10 {
        return render_decimal(value, buf);
    }
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
    // Rust's `{:e}` formatting is correctly rounded (round-half-to-even) at
    // any precision. Dividing `value` by a power of 10 to recover the
    // mantissa loses low-order bits, so digits past ~15 significant figures
    // came out wrong; render with `{:e}` directly and only translate the
    // exponent into C's `e±dd` form (explicit sign, minimum two digits).
    let raw = alloc::format!("{:.prec$e}", value, prec = precision);
    let e_pos = raw
        .bytes()
        .position(|b| b == b'e')
        .expect("Rust scientific formatting always contains 'e'");
    let mantissa = &raw[..e_pos];
    let exp: i32 = raw[e_pos + 1..]
        .parse()
        .expect("Rust scientific exponent is always a valid integer");
    let sign = if exp < 0 { '-' } else { '+' };
    let abs_exp = exp.unsigned_abs();
    // With `#` (alt_form) the result must always carry a decimal point, even
    // at precision 0 where the mantissa is a single bare digit.
    let dot = if alt_form && !mantissa.contains('.') {
        "."
    } else {
        ""
    };
    alloc::format!("{mantissa}{dot}{e_char}{sign}{abs_exp:02}")
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
    let use_f_style = exp >= -4 && exp < p as i32;
    if use_f_style {
        // Use %f style.
        let frac_digits = (p as i32 - 1 - exp).max(0) as usize;
        let mut s = alloc::format!("{:.prec$}", value, prec = frac_digits);
        // Rounding can push the integer part up a decade (e.g. 999999.5
        // with precision 6 rounds to 1000000, which now has 7 digits and
        // violates the precision contract). Glibc switches to %e style
        // in that case (bd-ju24y). Detect by counting the integer-part
        // digits of the rendered value.
        let int_digits = match s.bytes().position(|b| b == b'.') {
            Some(dot) => dot,
            None => s.len(),
        };
        if int_digits > p {
            // Fall through to %e style below.
        } else {
            if alt_form {
                // C11 7.21.6.1: `#` requires the result to always contain a
                // decimal point — append one when precision yielded none.
                if !s.contains('.') {
                    s.push('.');
                }
            } else {
                strip_trailing_zeros(&mut s);
            }
            return s;
        }
    }
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

/// `%a` / `%A` formatting: hexadecimal floating-point.
///
/// Produces output of the form `0xh.hhhhp±d` where `h` are hex digits and
/// `d` is the binary exponent in decimal.
fn format_a(value: f64, precision: Option<usize>, uppercase: bool, alt_form: bool) -> String {
    let p_char = if uppercase { 'P' } else { 'p' };
    let hex_alpha = if uppercase { b'A' } else { b'a' };

    if value == 0.0 {
        let prefix = if uppercase { "0X" } else { "0x" };
        let prec = precision.unwrap_or(0);
        if prec == 0 && !alt_form {
            return alloc::format!("{prefix}0{p_char}+0");
        }
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
    let prec = precision.unwrap_or_else(|| exact_hex_fraction_digits(mantissa_bits, default_prec));

    let prefix = if uppercase { "0X" } else { "0x" };
    let sign = if bin_exp < 0 { '-' } else { '+' };
    let abs_exp = bin_exp.unsigned_abs();

    let (lead_digit, frac_digits) =
        rounded_hex_components(lead_digit, mantissa_bits, prec, default_prec);

    if prec == 0 {
        let dot = if alt_form { "." } else { "" };
        let lead_hex = if lead_digit < 10 {
            (b'0' + lead_digit) as char
        } else {
            (hex_alpha + (lead_digit - 10)) as char
        };
        alloc::format!("{prefix}{lead_hex}{dot}{p_char}{sign}{abs_exp}")
    } else {
        let mut frac = String::with_capacity(prec);
        for nibble in frac_digits {
            let ch = if nibble < 10 {
                (b'0' + nibble) as char
            } else {
                (hex_alpha + (nibble - 10)) as char
            };
            frac.push(ch);
        }
        let lead_hex = if lead_digit < 10 {
            (b'0' + lead_digit) as char
        } else {
            (hex_alpha + (lead_digit - 10)) as char
        };
        alloc::format!("{prefix}{lead_hex}.{frac}{p_char}{sign}{abs_exp}")
    }
}

fn rounded_hex_components(
    mut lead_digit: u8,
    mantissa_bits: u64,
    precision: usize,
    default_prec: usize,
) -> (u8, Vec<u8>) {
    let mut frac: Vec<u8> = (0..precision)
        .map(|i| hex_fraction_nibble(mantissa_bits, i, default_prec))
        .collect();
    if precision >= default_prec {
        return (lead_digit, frac);
    }

    let first_discarded = hex_fraction_nibble(mantissa_bits, precision, default_prec);
    let lower_nibbles = default_prec.saturating_sub(precision + 1);
    let lower_nonzero = if lower_nibbles == 0 {
        false
    } else {
        let lower_mask = (1_u64 << (lower_nibbles * 4)) - 1;
        mantissa_bits & lower_mask != 0
    };
    let last_kept_odd = if precision == 0 {
        lead_digit & 1 != 0
    } else {
        frac[precision - 1] & 1 != 0
    };
    let round_up =
        first_discarded > 8 || (first_discarded == 8 && (lower_nonzero || last_kept_odd));
    if !round_up {
        return (lead_digit, frac);
    }

    if precision == 0 {
        lead_digit = lead_digit.saturating_add(1);
        return (lead_digit, frac);
    }

    let mut carry = true;
    for nibble in frac.iter_mut().rev() {
        if *nibble < 0xF {
            *nibble += 1;
            carry = false;
            break;
        }
        *nibble = 0;
    }
    if carry {
        lead_digit = lead_digit.saturating_add(1);
    }
    (lead_digit, frac)
}

fn hex_fraction_nibble(mantissa_bits: u64, index: usize, default_prec: usize) -> u8 {
    if index < default_prec {
        ((mantissa_bits >> (48 - index * 4)) & 0xF) as u8
    } else {
        0
    }
}

fn exact_hex_fraction_digits(mantissa_bits: u64, default_prec: usize) -> usize {
    if mantissa_bits == 0 {
        return 0;
    }
    let mut trailing = 0;
    let mut m = mantissa_bits;
    while m & 0xF == 0 && trailing < default_prec {
        m >>= 4;
        trailing += 1;
    }
    default_prec - trailing
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

    // Reference decimal renderer: the original general-base loop, kept here so
    // the LUT path can be proven byte-for-byte isomorphic to it.
    fn render_decimal_reference(mut value: u64, buf: &mut [u8; 64]) -> usize {
        if value == 0 {
            buf[63] = b'0';
            return 1;
        }
        let mut pos = 64;
        while value > 0 {
            pos -= 1;
            buf[pos] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        64 - pos
    }

    #[test]
    fn render_decimal_isomorphic_to_reference_and_std() {
        let mut probes: Vec<u64> = vec![
            0,
            1,
            9,
            10,
            99,
            100,
            999,
            1000,
            12_345,
            4_294_967_295,
            4_294_967_296,
            9_999_999_999,
            10_000_000_000,
            18_446_744_073_709_551_614,
            u64::MAX,
        ];
        // Every power of ten and its neighbours (digit-count boundaries).
        let mut p: u64 = 1;
        loop {
            probes.push(p.saturating_sub(1));
            probes.push(p);
            probes.push(p + 1);
            match p.checked_mul(10) {
                Some(next) => p = next,
                None => break,
            }
        }
        // Deterministic LCG sweep across the whole u64 range.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..200_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            probes.push(state);
        }

        for &v in &probes {
            let mut lut = [0u8; 64];
            let mut reff = [0u8; 64];
            let nl = render_decimal(v, &mut lut);
            let nr = render_decimal_reference(v, &mut reff);
            assert_eq!(nl, nr, "digit count mismatch for {v}");
            assert_eq!(
                &lut[64 - nl..],
                &reff[64 - nr..],
                "LUT vs reference digits mismatch for {v}"
            );
            assert_eq!(
                &lut[64 - nl..],
                v.to_string().as_bytes(),
                "LUT vs std::to_string mismatch for {v}"
            );
            // render_digits(base=10) must dispatch to the same bytes.
            let mut viad = [0u8; 64];
            let nd = render_digits(v, 10, false, &mut viad);
            assert_eq!(&viad[64 - nd..], &lut[64 - nl..], "render_digits(10) mismatch for {v}");
        }
    }

    #[test]
    fn bare_integer_fast_path_matches_canonical() {
        let u_spec = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::Ll,
            b'u',
            None,
        );
        let i_spec = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::Ll,
            b'd',
            None,
        );

        let mut state: u64 = 0xDEAD_BEEF_CAFE_F00D;
        for i in 0..200_000u64 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // unsigned
            let mut ub = Vec::new();
            format_unsigned(state, &u_spec, &mut ub);
            assert_eq!(ub, state.to_string().as_bytes(), "%u mismatch for {state}");
            // signed (reinterpret bits across the full i64 range)
            let s = state as i64;
            let mut sb = Vec::new();
            format_signed(s, &i_spec, &mut sb);
            assert_eq!(sb, s.to_string().as_bytes(), "%d mismatch for {s}");
            if i < 5 {
                // also pin the small/edge values explicitly
                for &edge in &[0i64, 1, -1, 9, -9, 10, i64::MIN, i64::MAX] {
                    let mut eb = Vec::new();
                    format_signed(edge, &i_spec, &mut eb);
                    assert_eq!(eb, edge.to_string().as_bytes(), "%d edge {edge}");
                }
            }
        }
    }

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
    fn test_grouping_flag_parsed_and_c_locale_noop() {
        // POSIX `'` flag must be consumed as a flag, not mistaken for the
        // conversion specifier. glibc in the C locale accepts it and emits no
        // separators (empty `grouping`), so output equals the un-flagged form.
        let (spec, consumed) = parse_format_spec(b"'d").unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(spec.conversion, b'd');
        assert!(spec.flags.group);

        let mut buf = Vec::new();
        format_signed(1_000_000, &spec, &mut buf);
        assert_eq!(&buf, b"1000000");

        // Combines with other flags and width: glibc `%'+8d` of 1234 -> "   +1234".
        let (spec, _) = parse_format_spec(b"'+8d").unwrap();
        assert!(spec.flags.group && spec.flags.force_sign);
        let mut buf = Vec::new();
        format_signed(1234, &spec, &mut buf);
        assert_eq!(&buf, b"   +1234");
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
    fn test_printf_arg_plan_helpers_cover_gp_and_fp_positions() {
        let segments = parse_format_string(b"%2$.*1$f %4$*3$s");
        assert_eq!(
            positional_printf_arg_plan(&segments),
            Some(vec![
                ValueArgKind::Gp,
                ValueArgKind::Fp,
                ValueArgKind::Gp,
                ValueArgKind::Gp,
            ])
        );
        assert_eq!(count_printf_args(&segments), 4);

        let sequential = parse_format_string(b"%*.*f %s");
        assert_eq!(positional_printf_arg_plan(&sequential), None);
        assert_eq!(count_printf_args(&sequential), 4);
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
    fn test_hex_float_default_precision_is_exact() {
        let spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'a',
            value_position: None,
            route: None,
        };
        let mut buf = Vec::new();
        format_float(1.5, &spec, &mut buf);
        assert_eq!(&buf, b"0x1.8p+0");

        buf.clear();
        format_float(1.0, &spec, &mut buf);
        assert_eq!(&buf, b"0x1p+0");

        buf.clear();
        format_float(0.0, &spec, &mut buf);
        assert_eq!(&buf, b"0x0p+0");
    }

    #[test]
    fn test_hex_float_alt_form_keeps_decimal_point() {
        let spec = FormatSpec {
            flags: FormatFlags {
                alt_form: true,
                ..FormatFlags::default()
            },
            width: Width::None,
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'a',
            value_position: None,
            route: None,
        };
        let mut buf = Vec::new();
        format_float(1.0, &spec, &mut buf);
        assert_eq!(&buf, b"0x1.p+0");

        buf.clear();
        format_float(0.0, &spec, &mut buf);
        assert_eq!(&buf, b"0x0.p+0");
    }

    #[test]
    fn test_hex_float_explicit_precision_rounds_nibbles() {
        let mut spec = FormatSpec {
            flags: FormatFlags::default(),
            width: Width::None,
            precision: Precision::Fixed(1),
            length: LengthMod::None,
            conversion: b'a',
            value_position: None,
            route: None,
        };
        let mut buf = Vec::new();

        // 1.09375 == 0x1.18p+0. At one hex digit this is an exact
        // half-way case; ties round to even, so the odd retained
        // nibble 1 rounds up to 2.
        format_float(1.09375, &spec, &mut buf);
        assert_eq!(&buf, b"0x1.2p+0");

        buf.clear();
        // 1.03125 == 0x1.08p+0. The retained nibble is even, so the
        // half-way discarded 8 does not round up.
        format_float(1.03125, &spec, &mut buf);
        assert_eq!(&buf, b"0x1.0p+0");

        buf.clear();
        spec.conversion = b'A';
        format_float(0.1, &spec, &mut buf);
        assert_eq!(&buf, b"0X1.AP-4");

        buf.clear();
        spec.conversion = b'a';
        spec.precision = Precision::Fixed(0);
        format_float(1.5, &spec, &mut buf);
        assert_eq!(&buf, b"0x2p+0");

        buf.clear();
        format_float(1.9999999999999998, &spec, &mut buf);
        assert_eq!(&buf, b"0x2p+0");
    }

    #[test]
    fn test_hex_float_zero_padding_keeps_prefix_before_zeroes() {
        let mut spec = FormatSpec {
            flags: FormatFlags {
                zero_pad: true,
                ..FormatFlags::default()
            },
            width: Width::Fixed(20),
            precision: Precision::None,
            length: LengthMod::None,
            conversion: b'a',
            value_position: None,
            route: None,
        };
        let mut buf = Vec::new();

        format_float(1.0, &spec, &mut buf);
        assert_eq!(&buf, b"0x000000000000001p+0");

        buf.clear();
        format_float(-1.0, &spec, &mut buf);
        assert_eq!(&buf, b"-0x00000000000001p+0");

        buf.clear();
        spec.flags.force_sign = true;
        spec.conversion = b'A';
        format_float(1.0, &spec, &mut buf);
        assert_eq!(&buf, b"+0X00000000000001P+0");

        buf.clear();
        spec.flags.force_sign = false;
        spec.flags.alt_form = true;
        spec.precision = Precision::Fixed(0);
        spec.conversion = b'a';
        format_float(0.0, &spec, &mut buf);
        assert_eq!(&buf, b"0x00000000000000.p+0");
    }

    #[test]
    fn test_hex_float_glibc_edge_cases() {
        let mut spec = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::None,
            LengthMod::None,
            b'a',
            None,
        );
        let mut buf = Vec::new();

        format_float(-0.0, &spec, &mut buf);
        assert_eq!(&buf, b"-0x0p+0");

        buf.clear();
        format_float(f64::from_bits(1), &spec, &mut buf);
        assert_eq!(&buf, b"0x0.0000000000001p-1022");

        buf.clear();
        spec.precision = Precision::Fixed(0);
        format_float(f64::from_bits(1), &spec, &mut buf);
        assert_eq!(&buf, b"0x0p-1022");

        buf.clear();
        format_float(f64::MIN_POSITIVE, &spec, &mut buf);
        assert_eq!(&buf, b"0x1p-1022");

        buf.clear();
        format_float(f64::from_bits(0x7fefffffffffffff), &spec, &mut buf);
        assert_eq!(&buf, b"0x2p+1023");
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

    // Regression for bd-ju24y. Values whose rounded %f-style representation
    // has more integer digits than the %g precision must switch to %e style,
    // matching glibc. Before the fix, format_g(999999.5, 6, _, _) returned
    // "1000000" (7 digits, violating the precision-6 contract); now it
    // returns "1e+06".
    #[test]
    fn test_g_rounding_overflow_switches_to_e() {
        assert_eq!(format_g(999999.5, 6, false, false), "1e+06");
        // Control: values that don't cross a decade stay in %f.
        assert_eq!(format_g(99999.5, 6, false, false), "99999.5");
        assert_eq!(format_g(9999.5, 6, false, false), "9999.5");
        // Uppercase variant.
        assert_eq!(format_g(999999.5, 6, true, false), "1E+06");
    }

    // Regression for the %e digit-accuracy bug: the mantissa was recomputed
    // as value / 10^exp, which lost low-order bits. High-precision %e must
    // emit the same correctly-rounded digits glibc does.
    #[test]
    fn test_e_high_precision_exact_digits() {
        assert_eq!(
            format_e(123456789.0, 17, false, false),
            "1.23456789000000000e+08"
        );
        assert_eq!(
            format_e(0.1, 20, false, false),
            "1.00000000000000005551e-01"
        );
        // Basic cases and exponent formatting still hold.
        assert_eq!(format_e(0.0, 2, false, false), "0.00e+00");
        assert_eq!(format_e(1.0, 0, false, false), "1e+00");
        assert_eq!(format_e(1.5e300, 1, false, false), "1.5e+300");
        assert_eq!(format_e(2.0e-9, 0, true, false), "2E-09");
        // Rounding carry across a decade (9.99 -> 1.0e1).
        assert_eq!(format_e(9.96, 1, false, false), "1.0e+01");
        // alt_form keeps a decimal point at precision 0.
        assert_eq!(format_e(7.0, 0, false, true), "7.e+00");
    }

    // Regression for the %#g decimal-point bug: C11 7.21.6.1 requires the
    // alternate form to always keep a decimal point even when the precision
    // leaves zero fractional digits.
    #[test]
    fn test_hash_g_keeps_decimal_point() {
        assert_eq!(format_g(3.0, 0, false, true), "3.");
        assert_eq!(format_g(3.0, 1, false, true), "3.");
        assert_eq!(format_g(100.0, 3, false, true), "100.");
        // Without alt_form trailing zeros are still stripped.
        assert_eq!(format_g(3.0, 1, false, false), "3");
        // alt_form with fractional digits keeps the trailing zeros too.
        assert_eq!(format_g(3.0, 3, false, true), "3.00");
    }

    // Regression for bd-h7ede. Rust's core::fmt stores precision as u16 and
    // panics ("Formatting argument out of range") for precision >= 65536.
    // format_float must cap precision before it reaches format!/%.*f, or any
    // C caller with a format like `%.99999f` would abort the process.
    #[test]
    fn format_float_does_not_panic_on_huge_precision() {
        // Exercise %f, %e, %g, %a at prec = 65536 (the first panicking value)
        // and at prec = usize::MAX / 2 (pathological) — neither must panic.
        for prec in [65_536usize, 100_000, usize::MAX / 2] {
            for conv in *b"fegaFEGA" {
                let spec = FormatSpec::new(
                    FormatFlags::default(),
                    Width::None,
                    Precision::Fixed(prec),
                    LengthMod::None,
                    conv,
                    None,
                );
                let mut buf = Vec::new();
                // Must return without panicking. Output is allowed to be
                // truncated — we only pin the no-abort contract.
                format_float(1.5_f64, &spec, &mut buf);
                assert!(
                    !buf.is_empty(),
                    "%{}: format_float produced empty output at prec={prec}",
                    conv as char
                );
            }
        }
    }

    #[test]
    fn format_float_still_honors_precision_up_to_cap() {
        // At prec = 65535 (the cap) the formatter must still produce the
        // requested number of fractional digits — capping to 65535 preserves
        // currently-working behavior.
        let spec = FormatSpec::new(
            FormatFlags::default(),
            Width::None,
            Precision::Fixed(65_535),
            LengthMod::None,
            b'f',
            None,
        );
        let mut buf = Vec::new();
        format_float(1.0_f64, &spec, &mut buf);
        // "1." + 65535 '0's = 65537 bytes.
        assert_eq!(buf.len(), 65_537);
        assert_eq!(&buf[..2], b"1.");
    }
}
