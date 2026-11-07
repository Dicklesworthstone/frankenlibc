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
use core::num::NonZeroU32;

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
    UnsignedBinary,
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
    UnsignedBinary,
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
            ScanfHandler::UnsignedBinary => {
                Some(ScanOperationKind::Int(IntScanKind::UnsignedBinary))
            }
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

/// Inline capacity for a scanned byte run, in bytes.
///
/// Chosen to cover ordinary scanf tokens — identifiers, numbers, dotted quads,
/// key=value halves — while keeping [`ScanValue`] small enough that the
/// per-call `Vec<ScanValue>` stays one modest allocation.
pub const SCAN_INLINE_CAP: usize = 32;

/// Bytes captured by a `%s`, `%c` or `%[...]` conversion, stored inline when
/// they fit.
///
/// WHY THIS EXISTS, and why the inline case is the one that matters.
/// `scan_string` and `scan_scanset` already locate the token without copying and
/// then take it in one shot; what remained was `to_vec()`, i.e. **one heap
/// allocation per string conversion**. In FrankenLibC that allocation is not
/// cheap the way it is in glibc: it goes through fl's own allocator, measured
/// this session at 6.62x glibc on malloc/free and ~31 ns per pair.
///
/// The certified sscanf numbers say the cost is fixed per conversion rather than
/// per byte, which is what makes an inline buffer the right shape:
///
///   string_token  2.016x   short token
///   two_strings   1.923x   two short tokens
///   long_string   1.054x   ONE LONG token — nearly parity
///
/// If the loss were the copying, the long case would be the worst. It is the
/// best. The gap tracks the NUMBER of conversions, not the number of bytes, so
/// it is the allocation, and removing it for short tokens targets exactly the
/// cases that lose. Long tokens keep the heap path, where the copy dominates and
/// fl already runs at parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanBytes {
    /// Fits in `SCAN_INLINE_CAP`; no allocation.
    Inline { len: u8, buf: [u8; SCAN_INLINE_CAP] },
    /// Too long to inline; one allocation, amortised over many bytes.
    Heap(Vec<u8>),
}

impl ScanBytes {
    /// Capture `bytes`, inline when they fit.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        if bytes.len() <= SCAN_INLINE_CAP {
            let mut buf = [0u8; SCAN_INLINE_CAP];
            buf[..bytes.len()].copy_from_slice(bytes);
            ScanBytes::Inline {
                len: bytes.len() as u8,
                buf,
            }
        } else {
            ScanBytes::Heap(bytes.to_vec())
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            ScanBytes::Inline { len, buf } => &buf[..*len as usize],
            ScanBytes::Heap(v) => v.as_slice(),
        }
    }
}

impl std::ops::Deref for ScanBytes {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq<[u8]> for ScanBytes {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for ScanBytes {
    #[inline]
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

// `&scan_bytes == b"ab"` desugars to `ScanBytes: PartialEq<[u8; N]>`, NOT to the
// reference form above — `&A == &B` requires `A: PartialEq<B>`. Both impls are
// needed so callers can write either spelling.
impl<const N: usize> PartialEq<[u8; N]> for ScanBytes {
    #[inline]
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// A successfully scanned value from input.
#[derive(Debug, Clone, Default)]
pub enum ScanValue {
    /// Placeholder for unused inline slots in [`ScanValues`]; never read.
    #[default]
    Unset,
    SignedInt(i64),
    UnsignedInt(u64),
    Float(f64),
    /// An x87 extended-precision value, in memory order, produced ONLY by a
    /// `%Lf` conversion.
    ///
    /// `%Lf` stores a `long double`, and routing it through `Float(f64)` fixed
    /// the significand at 53 bits before any writer saw it — so
    /// `sscanf("1.0000000000000000001", "%Lf", &ld)` stored exactly 1.0 and no
    /// later widening could recover what the parse had already discarded. The
    /// ten bytes here are what `float128::strtold_scan` produced from the same
    /// accepted token, so the value reaching the caller is the one `strtold`
    /// would have returned for that text.
    ///
    /// Ten bytes rather than sixteen: that is the significant extent of the x87
    /// encoding, and the ABI writer owns the padding of the 16-byte storage
    /// slot.
    LongDouble([u8; 10]),
    Char(ScanBytes),
    String(ScanBytes),
    CharsConsumed(usize),
    Pointer(usize),
}

// ---------------------------------------------------------------------------
// Scan spec types
// ---------------------------------------------------------------------------

impl Default for ScanDirective {
    /// Placeholder for unused inline slots in [`ScanDirectives`], never read.
    ///
    /// `Malformed` is chosen deliberately over a plausible-looking directive: if
    /// a bug ever exposed a slot past `len`, the inert value that performs no
    /// conversion is the one that fails safe.
    fn default() -> Self {
        ScanDirective::Malformed
    }
}

/// A parsed scanf format directive.
#[derive(Debug, Clone)]
pub enum ScanDirective {
    /// Literal byte(s) to match.
    Literal(u8),
    /// A non-ASCII literal in a wide format, matched as one complete character.
    WideLiteral(u32),
    /// Whitespace directive: skip zero or more whitespace chars.
    Whitespace,
    /// A conversion specifier.
    /// A conversion specifier.
    ///
    /// Held INLINE, not boxed. It used to be `Box<ScanSpec>` because `ScanSpec`
    /// embedded a `ScanSet` (a 257-byte table) and that would have made every
    /// directive huge — but only `%[...]` needs a scanset, so the TABLE is boxed
    /// instead and the ordinary spec costs nothing. Counted with a global
    /// allocator, the box was one allocation per conversion: `sscanf("%s%n")`
    /// made three allocations where glibc makes none.
    Spec(ScanSpec),
    /// A malformed directive: parsing stops here, performing no conversion.
    ///
    /// Currently only an unterminated scanset (`%[^]`). This is deliberately
    /// NOT the same as ending the directive list: an empty list leaves
    /// `input_failure` set and reports EOF, whereas glibc reports a MATCHING
    /// failure (return 0) because the fault is in the format, not the input.
    Malformed,
}

/// A parsed scanf conversion specifier.
#[derive(Debug, Clone)]
pub struct ScanSpec {
    pub suppress: bool,
    pub width: Option<usize>,
    /// One-based POSIX destination index (`%2$s`), recognized by the wide parser.
    /// Narrow parsing leaves this unset until its ABI writers support indices.
    /// Fits the existing padding; POSIX destination limits are below u32::MAX.
    /// The parser rejects larger indices rather than truncating them.
    pub argument_index: Option<NonZeroU32>,
    pub length: LengthMod,
    pub conversion: u8,
    /// Boxed so a spec without a scanset — every conversion except `%[...]` —
    /// stays small enough to live inline in [`ScanDirective::Spec`].
    ///
    /// `None` for a ONE-MEMBER set, which [`ScanSpec::simple_set`] carries
    /// inline instead; see there.
    pub scanset: Option<Box<ScanSet>>,
    /// A one-member scanset, held inline so it costs no allocation.
    ///
    /// `%[^=]`, `%[^\n]` and `%[^,]` are the scansets real code actually writes,
    /// and each of them needed a 32-byte `Box<ScanSet>` built and freed on EVERY
    /// call. A profile of `sscanf("key=value", "%[^=]=%s")` put that pair at 6.8%
    /// of the call (`native_libc_malloc` 2.93%, `native_libc_free_with_slot`
    /// 3.90%). One byte and a flag answer the same question.
    ///
    /// This is deliberately not an optimisation of the FORMAT text: the parser
    /// builds the bitmap as before and then asks whether exactly one bit is set,
    /// so `%[=]`, `%[^=]` and a range that collapsed to a single character are
    /// all recognised, and any set with two or more members still boxes.
    pub simple_set: SimpleScanSet,
    /// True when this directive is scanned from a WIDE input stream (swscanf /
    /// fwscanf), whose bytes are the UTF-8 encoding of wide characters. In that
    /// mode leading-whitespace skipping and `%s` token boundaries recognise
    /// Unicode whitespace (`iswspace`), not just ASCII. Set by the wide scanf
    /// parser; defaults to false for narrow `sscanf`.
    pub wide_input: bool,
    /// Accept a `0b`/`0B` prefix for `%i`, as required by the C23 scanf aliases.
    /// Legacy and C99 entry points leave this false, even on a C23-capable libc.
    pub binary_prefix: bool,
    /// True when the GNU `m` assignment-allocation modifier was given (`%ms`,
    /// `%m[`, `%mc`): the destination argument is a `char **` and the matched
    /// text is stored into a freshly allocated buffer. Only meaningful for the
    /// string conversions; the ABI layer performs the allocation.
    pub alloc: bool,
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

    /// A missing outer result is a failure before consuming a token; a missing
    /// value inside a result is a matching failure at the returned position.
    /// Suppressed successful conversions still return their parsed value.
    fn scan_at(
        &self,
        input: &[u8],
        pos: usize,
        wide_input: bool,
    ) -> Option<(Option<ScanValue>, usize)> {
        self.scan_operation_kind()?
            .scan(input, pos, self, wide_input)
    }
}

impl IntScanKind {
    fn scan(self, input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
        match self {
            IntScanKind::SignedDecimal => scan_int(input, pos, spec, 10, true),
            IntScanKind::SignedAutoBase => scan_int_auto(input, pos, spec),
            IntScanKind::UnsignedDecimal => scan_int(input, pos, spec, 10, false),
            IntScanKind::UnsignedOctal => scan_int(input, pos, spec, 8, false),
            IntScanKind::UnsignedBinary => scan_int(input, pos, spec, 2, false),
            IntScanKind::UnsignedHex => scan_int(input, pos, spec, 16, false),
        }
    }
}

impl ScanOperationKind {
    fn scan(
        self,
        input: &[u8],
        pos: usize,
        spec: &ScanSpec,
        wide_input: bool,
    ) -> Option<(Option<ScanValue>, usize)> {
        match self {
            ScanOperationKind::Int(kind) => kind.scan(input, pos, spec),
            ScanOperationKind::Float => scan_float(input, pos, spec),
            ScanOperationKind::Character => scan_char(input, pos, spec, wide_input),
            ScanOperationKind::String => scan_string(input, pos, spec, wide_input),
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
    /// Membership as a 256-BIT map, not a 256-BYTE table.
    ///
    /// The table was `[bool; 256]`, which made `ScanSet` 257 bytes and forced a
    /// heap allocation to keep `ScanSpec` small enough to hold inline. 32 bytes
    /// of bits carry the same information: the boxed allocation shrinks from 257
    /// bytes to 40, and the per-character membership test touches one 8-byte
    /// word instead of walking a table that spans four cache lines.
    ///
    /// Kept private so the representation stays an implementation detail;
    /// `contains` is the only reader.
    bits: [u64; 4],
    /// Inclusive scalar ranges above U+00FF for a wide scanset. Empty narrow
    /// and ASCII-only wide sets do not allocate storage for this slice.
    wide_ranges: Box<[(u32, u32)]>,
}

/// Membership bits accumulated while parsing a `%[...]` set.
///
/// Exists so the parser never materialises a 256-byte scratch table: `insert`
/// is one shift and one OR, the same cost as storing a bool, and there is no
/// packing pass afterwards.
#[derive(Clone, Copy, Default)]
pub struct ScanSetBits([u64; 4]);

/// A scanset small enough to hold inline, so it needs no allocation.
///
/// Two bytes, which fit in `ScanSpec`'s existing padding — the size pin
/// `a_simple_scanset_does_not_grow_the_directive` holds that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SimpleScanSet {
    /// No set, or a set with two or more members (which boxes as before).
    #[default]
    None,
    /// `%[X]` — matches exactly this byte.
    Byte(u8),
    /// `%[^X]` — matches everything except this byte.
    NegatedByte(u8),
}

impl ScanSetBits {
    #[inline]
    pub fn insert(&mut self, c: u8) {
        self.0[(c >> 6) as usize] |= 1u64 << (c & 63);
    }

    /// The set's only member, when it has exactly one.
    ///
    /// This is what lets `%[^=]`, `%[^\n]` and `%[^,]` — the overwhelmingly
    /// common scansets in real code — skip the `Box<ScanSet>` entirely. Four
    /// `count_ones` and a `trailing_zeros` cost a handful of instructions
    /// against a malloc/free pair, which a profile of `sscanf("key=value",
    /// "%[^=]=%s")` measured at 6.8% of the whole call
    /// (`native_libc_malloc` 2.93% + `native_libc_free_with_slot` 3.90%).
    ///
    /// Recognising it from the accumulated BITS rather than from the format
    /// text means every spelling of a one-member set is caught, including a
    /// reversed range that collapsed to one character.
    #[inline]
    pub fn single_member(&self) -> Option<u8> {
        let mut found = None;
        for (word, bits) in self.0.iter().enumerate() {
            match bits.count_ones() {
                0 => {}
                1 if found.is_none() => {
                    found = Some((word as u8) << 6 | bits.trailing_zeros() as u8);
                }
                _ => return None,
            }
        }
        found
    }
}

impl ScanSet {
    /// Build from bits accumulated during the parse.
    pub fn from_bits(negated: bool, bits: ScanSetBits) -> Self {
        Self {
            negated,
            bits: bits.0,
            wide_ranges: Box::default(),
        }
    }

    /// Whether `c` is in the set, before `negated` is applied.
    #[inline]
    pub fn contains(&self, c: u8) -> bool {
        self.bits[(c >> 6) as usize] & (1u64 << (c & 63)) != 0
    }

    #[inline]
    fn contains_wide(&self, c: u32) -> bool {
        if c <= u8::MAX as u32 {
            self.contains(c as u8)
        } else {
            self.wide_ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi)
        }
    }
}

// ---------------------------------------------------------------------------
// Format string parser
// ---------------------------------------------------------------------------

/// Parse a scanf format string into a list of directives.
pub fn parse_scanf_format(fmt: &[u8]) -> ScanDirectives {
    parse_scanf_format_impl::<false, _>(fmt, &crate::string::wchar::iswspace)
}

/// Parse the UTF-8 representation of a wide scanf format. Scansets and
/// whitespace use wide characters, and destination indices are one-based.
pub fn parse_scanf_format_wide(fmt: &[u8]) -> ScanDirectives {
    parse_scanf_format_wide_with_space(fmt, &crate::string::wchar::iswspace)
}

/// Parse a wide format using the same immutable locale classification that
/// will be supplied to the wide stream scanner. A non-ASCII character which
/// is not whitespace in that locale remains a literal.
pub fn parse_scanf_format_wide_with_space<S>(fmt: &[u8], is_space: &S) -> ScanDirectives
where
    S: Fn(u32) -> bool,
{
    parse_scanf_format_impl::<true, S>(fmt, is_space)
}

fn parse_scanf_format_impl<const WIDE_INPUT: bool, S>(fmt: &[u8], is_space: &S) -> ScanDirectives
where
    S: Fn(u32) -> bool,
{
    let wide_input = WIDE_INPUT;
    let mut directives = ScanDirectives::default();
    let mut i = 0;
    let whitespace_len = |pos| {
        if wide_input {
            wide_character_at(fmt, pos)
                .filter(|&(character, _)| is_space(character))
                .map_or(0, |(_, len)| len)
        } else {
            ws_seq_len(fmt, pos, false)
        }
    };

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
                argument_index: None,
                length: LengthMod::None,
                conversion: 0,
                scanset: None,
                simple_set: SimpleScanSet::None,
                wide_input,
                binary_prefix: false,
                alloc: false,
                route: ScanfRoute::invalid(),
            };

            // Positional indices precede suppression and field width. Keeping
            // this wide-only avoids changing narrow writers' argument order.
            if wide_input && fmt[i].is_ascii_digit() {
                let mut end = i;
                let mut index = Some(0u32);
                while end < fmt.len() && fmt[end].is_ascii_digit() {
                    index = index
                        .and_then(|n| n.checked_mul(10)?.checked_add((fmt[end] - b'0') as u32));
                    end += 1;
                }
                if end < fmt.len() && fmt[end] == b'$' {
                    let Some(index) = index.and_then(NonZeroU32::new) else {
                        directives.push(ScanDirective::Malformed);
                        break;
                    };
                    spec.argument_index = Some(index);
                    i = end + 1;
                }
            }

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

            // GNU `m` assignment-allocation modifier (`%ms`, `%m[`, `%mc`,
            // optionally combined with `l`). It precedes the length modifier;
            // the destination is a `char **` filled with a malloc'd buffer.
            if i < fmt.len() && fmt[i] == b'm' {
                spec.alloc = true;
                i += 1;
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

            if wide_input && fmt[i] == b'[' {
                let Some((simple, set, end)) = parse_wide_scanset(fmt, i + 1) else {
                    directives.push(ScanDirective::Malformed);
                    break;
                };
                spec.conversion = b'[';
                spec.simple_set = simple;
                spec.scanset = set;
                i = end;
            } else if fmt[i] == b'[' {
                // Parse scanset.
                i += 1;
                let mut negated = false;
                if i < fmt.len() && fmt[i] == b'^' {
                    negated = true;
                    i += 1;
                }
                // Bits are set DIRECTLY here. An earlier version built a
                // `[bool; 256]` and packed it afterwards, which cost a
                // 256-iteration pass on EVERY `%[...]` parse — measured as a
                // large regression on exactly the scanset cases (see the
                // 2026-08-16 ledger row). Setting a bit is the same work as
                // setting a bool, so the table bought nothing.
                let mut set = ScanSetBits::default();
                // First char after [ or [^ can be ']'.
                if i < fmt.len() && fmt[i] == b']' {
                    set.insert(b']');
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
                                set.insert(ch);
                            }
                        } else {
                            // Reversed range (lo > hi): glibc does not form an
                            // empty range — it takes the three characters as
                            // literal set members (`lo`, `-`, `hi`).
                            set.insert(lo);
                            set.insert(b'-');
                            set.insert(hi);
                        }
                        i += 3;
                    } else {
                        set.insert(c);
                        i += 1;
                    }
                }
                // The scanset MUST be closed. `%[^]` looks complete but is not:
                // a `]` immediately after `[` or `[^` is a literal member (the
                // branch above consumes it), so the set is still open and the
                // format simply ends. fl used to build a valid negated set from
                // it and match the entire input; glibc treats the directive as
                // malformed, performs no conversion, and returns the number of
                // assignments already made (0 for `sscanf("^abc", "%[^]")`).
                //
                // Breaking here — the same path a failed bind_route takes —
                // drops the directive instead of running it, so nothing is
                // written to the caller's buffer. That matters beyond the
                // return value: fl previously stored "^abc" into a buffer the
                // caller had every reason to believe was untouched.
                let terminated = i < fmt.len() && fmt[i] == b']';
                if !terminated {
                    directives.push(ScanDirective::Malformed);
                    break;
                }
                i += 1;
                spec.conversion = b'[';
                // A one-member set is carried inline; anything larger boxes.
                match set.single_member() {
                    Some(byte) => {
                        spec.simple_set = if negated {
                            SimpleScanSet::NegatedByte(byte)
                        } else {
                            SimpleScanSet::Byte(byte)
                        };
                    }
                    None => {
                        spec.scanset = Some(Box::new(ScanSet::from_bits(negated, set)));
                    }
                }
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

            directives.push(ScanDirective::Spec(spec));
        } else if whitespace_len(i) != 0 {
            directives.push(ScanDirective::Whitespace);
            // Consume additional whitespace in format.
            loop {
                let len = whitespace_len(i);
                if len == 0 {
                    break;
                }
                i += len;
            }
        } else if wide_input && !fmt[i].is_ascii() {
            let Some((character, len)) = wide_character_at(fmt, i) else {
                directives.push(ScanDirective::Malformed);
                break;
            };
            directives.push(ScanDirective::WideLiteral(character));
            i += len;
        } else {
            directives.push(ScanDirective::Literal(fmt[i]));
            i += 1;
        }
    }

    directives
}

/// Read one scalar from the internal UTF-8 representation without accepting a
/// partial sequence as a scanset member or literal.
fn wide_character_at(input: &[u8], pos: usize) -> Option<(u32, usize)> {
    let len = utf8_seq_len(*input.get(pos)?);
    let bytes = input.get(pos..pos.checked_add(len)?)?;
    let character = core::str::from_utf8(bytes).ok()?.chars().next()?;
    Some((character as u32, len))
}

fn parse_wide_scanset(
    fmt: &[u8],
    mut pos: usize,
) -> Option<(SimpleScanSet, Option<Box<ScanSet>>, usize)> {
    let negated = fmt.get(pos) == Some(&b'^');
    pos += usize::from(negated);
    let mut bits = ScanSetBits::default();
    let mut ranges = Vec::new();
    let mut insert_range = |lo: u32, hi: u32| {
        if lo <= u8::MAX as u32 {
            for c in lo..=hi.min(u8::MAX as u32) {
                bits.insert(c as u8);
            }
        }
        if hi > u8::MAX as u32 {
            ranges.push((lo.max(u8::MAX as u32 + 1), hi));
        }
    };
    if fmt.get(pos) == Some(&b']') {
        insert_range(b']' as u32, b']' as u32);
        pos += 1;
    }
    while fmt.get(pos).is_some_and(|&b| b != 0 && b != b']') {
        let (lo, len) = wide_character_at(fmt, pos)?;
        pos += len;
        if fmt.get(pos) == Some(&b'-') && fmt.get(pos + 1).is_some_and(|&b| b != 0 && b != b']') {
            let (hi, len) = wide_character_at(fmt, pos + 1)?;
            pos += 1 + len;
            if lo <= hi {
                insert_range(lo, hi);
            } else {
                insert_range(lo, lo);
                insert_range(b'-' as u32, b'-' as u32);
                insert_range(hi, hi);
            }
        } else {
            insert_range(lo, lo);
        }
    }
    if fmt.get(pos) != Some(&b']') {
        return None;
    }
    if ranges.is_empty()
        && let Some(byte) = bits.single_member()
    {
        let simple = if negated {
            SimpleScanSet::NegatedByte(byte)
        } else {
            SimpleScanSet::Byte(byte)
        };
        return Some((simple, None, pos + 1));
    }
    Some((
        SimpleScanSet::None,
        Some(Box::new(ScanSet {
            negated,
            bits: bits.0,
            wide_ranges: ranges.into_boxed_slice(),
        })),
        pos + 1,
    ))
}

// ---------------------------------------------------------------------------
// Input scanner
// ---------------------------------------------------------------------------

/// Inline capacity for one call's scanned values.
///
/// Four covers the overwhelming majority of real formats (`%d`, `%s`, `%d %d`,
/// `key=%s`, a dotted quad is four but arrives through the int fast path), and
/// `ScanValue` is ~40 bytes, so the array costs ~160 bytes of stack against one
/// heap allocation avoided.
pub const SCAN_VALUES_INLINE: usize = 4;

/// One call's scanned values, without a heap allocation for the common case.
///
/// WHY THIS EXISTS. `scan_input` used to collect into `Vec::new()`, so the first
/// push allocated and the buffer doubled from there. Counted with a global
/// allocator, one engine-path `sscanf` made FOUR allocations where glibc makes
/// none, and this family is a measured loss (`string_token` 2.238x, fl 93.765 ns
/// against 41.880 ns). The cases that already avoid the engine —
/// `single_int`, `two_ints`, served by `strict_scan_decimal_ints` — are the
/// least bad in the family, which is the existing evidence that the per-call
/// heap traffic is worth removing.
///
/// The inline half is a real `[ScanValue; N]` rather than `[Option<ScanValue>; N]`
/// because the ABI writer consumes a contiguous `&[ScanValue]`; an Option array
/// cannot produce one. That is what `ScanValue: Default` is for, and the default
/// slots past `len` are never read.
pub struct InlineVec<T: Default, const N: usize> {
    inline: [T; N],
    inline_len: usize,
    spill: Vec<T>,
}

impl<T: Default, const N: usize> Default for InlineVec<T, N> {
    fn default() -> Self {
        Self {
            inline: core::array::from_fn(|_| T::default()),
            inline_len: 0,
            spill: Vec::new(),
        }
    }
}

impl<T: Default, const N: usize> InlineVec<T, N> {
    /// Append, moving to the heap only past the inline capacity.
    pub fn push(&mut self, value: T) {
        if !self.spill.is_empty() {
            self.spill.push(value);
            return;
        }
        if self.inline_len < N {
            self.inline[self.inline_len] = value;
            self.inline_len += 1;
            return;
        }
        // Overflow: migrate the inline run once, then continue on the heap.
        self.spill.reserve(N + 1);
        for slot in self.inline.iter_mut() {
            self.spill.push(core::mem::take(slot));
        }
        self.spill.push(value);
    }

    /// One contiguous slice, which is what both consumers want: the ABI value
    /// writer takes `&[ScanValue]` and the engine takes `&[ScanDirective]`.
    pub fn as_slice(&self) -> &[T] {
        if self.spill.is_empty() {
            &self.inline[..self.inline_len]
        } else {
            &self.spill
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        if self.spill.is_empty() {
            &mut self.inline[..self.inline_len]
        } else {
            &mut self.spill
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Default, const N: usize> core::ops::Deref for InlineVec<T, N> {
    type Target = [T];

    /// Deref to the slice so this drops into every place a `Vec` stood:
    /// indexing, `iter()`, `first()`, and `&values` coercing to `&[T]` at a call
    /// site. Without it the switch away from `Vec` would have meant touching
    /// every consumer and every test that reads a scanned value.
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Default, const N: usize> core::ops::DerefMut for InlineVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

/// One call's scanned values.
pub type ScanValues = InlineVec<ScanValue, SCAN_VALUES_INLINE>;

/// Inline capacity for one format's directives.
///
/// FOUR, measured — not chosen for coverage. Eight was the intuitive pick, since
/// every literal byte is its own directive and `"key=%s"` is five. But the slots
/// are initialised on EVERY call, and instruction counts (which, unlike cycles,
/// are immune to the code-layout differences between two builds) say that cost
/// dominates the allocation it was meant to avoid:
///
///   case          base      inline=8      inline=4
///   string_token  252.58M   290.18M       224.45M
///   key_value     373.79M   419.12M       353.53M
///   long_literal  278.61M   336.25M       270.49M
///   single_int    49.91M    49.91M        49.86M   (control, engine not reached)
///
/// `long_literal` (`"id=%d"`, five directives) is the case that SPILLS to the
/// heap at four, and it is still cheaper there than at eight — the spilled
/// allocation costs less than initialising four more slots on every call. At
/// eight the whole engine path was a 12-21% instruction REGRESSION against the
/// pre-change baseline; at four it is a 3-11% improvement.
pub const SCAN_DIRECTIVES_INLINE: usize = 4;

/// One format's parsed directives.
pub type ScanDirectives = InlineVec<ScanDirective, SCAN_DIRECTIVES_INLINE>;

/// Scan result from the engine.
pub struct ScanResult {
    /// Successfully scanned non-suppressed values.
    pub values: ScanValues,
    /// Number of successful assignments.
    pub count: i32,
    /// Total input bytes consumed.
    pub consumed: usize,
    /// Whether a required read failed. Callers report EOF only when `count` is
    /// zero; wide scans also retain this flag after earlier assignments so a
    /// stream adapter can distinguish exhausted input from a completed format.
    pub input_failure: bool,
    /// The conversion that stopped the scan was an assigning `%m` one. glibc
    /// stores NULL through its `char **` then -- even when the call returns EOF
    /// -- because it frees the buffer it had started; callers must do the same.
    /// A `%m` conversion never reached (an earlier directive failed) is left alone.
    pub failed_alloc: bool,
}

/// Location of the conversion currently being delivered to a wide scan writer.
/// All offsets address the internal UTF-8 input, even when the destination uses
/// another encoding. For text conversions, the token excludes skipped leading
/// whitespace. A failed `%m` notification has no value and an empty token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanWriteContext {
    pub directive_index: usize,
    pub token_start: usize,
    pub token_end: usize,
}

/// Stop scanning when a destination cannot accept the current conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanWriteError {
    /// Absolute UTF-8 byte offset consumed by this conversion. This must lie
    /// within the supplied token and on a character boundary. The engine
    /// defensively clamps an invalid offset and rounds it down to a boundary.
    pub consumed: usize,
    /// Whether this failure should return EOF when no assignment preceded it.
    /// An ABI writer may separately override the return for fatal ENOMEM.
    pub input_failure: bool,
}

/// Scan input according to parsed directives.
/// Run the parsed directives against a NARROW (byte) input stream (sscanf et al.):
/// `%s`/`%c`/`%[` field widths count bytes.
pub fn scan_input(input: &[u8], directives: &[ScanDirective]) -> ScanResult {
    scan_input_impl::<true, false, _>(input, directives, |_, _, _| Ok(()))
}

/// The engine's `%f` spec, built ONCE.
///
/// The previous attempt built this per call — including its 16-byte
/// `Option<usize>` width — and called `bind_route`, a table lookup plus a length
/// check, every time. That setup, not the parsing, is what put the float field
/// 1265 instructions per call above its own ceiling and got the lever rejected.
fn default_float_spec() -> &'static ScanSpec {
    static SPEC: std::sync::OnceLock<ScanSpec> = std::sync::OnceLock::new();
    SPEC.get_or_init(|| {
        let mut spec = ScanSpec {
            suppress: false,
            width: None,
            argument_index: None,
            length: LengthMod::None,
            conversion: b'f',
            scanset: None,
            simple_set: SimpleScanSet::None,
            wide_input: false,
            binary_prefix: false,
            alloc: false,
            route: ScanfRoute::invalid(),
        };
        // A `%f` route always binds. If it ever stopped, `scan_float` would
        // decline every input and the differential would go red, rather than
        // values silently going wrong.
        let _ = spec.bind_route();
        spec
    })
}

/// Scan ONE default-width float from `input` at `pos`, returning its value and
/// the position just past it.
///
/// Exists so the ABI's strict fast paths can serve a `%f`/`%lf` field WITHOUT
/// reimplementing the float grammar — hex floats, `inf`/`infinity`/`nan`,
/// subnormals, the sign rules. It calls the engine's own `scan_float` through
/// the shared spec above, and a fast path cannot do this itself because
/// `ScanSpec::route` is private, so the spec cannot be built outside this module.
///
/// `None` means the conversion did not match — the caller must distinguish an
/// exhausted input from a malformed one itself, since both look the same here.
pub fn scan_default_float(input: &[u8], pos: usize) -> Option<(f64, usize)> {
    match scan_float(input, pos, default_float_spec()) {
        Some((Some(ScanValue::Float(value)), next)) => Some((value, next)),
        _ => None,
    }
}

/// Run the parsed directives against a WIDE input stream (swscanf et al.), passed
/// in here as its UTF-8 multibyte encoding. `%s`/`%c` field widths count WIDE
/// characters (whole UTF-8 sequences), matching the C wide-scanf semantics, even
/// without an `l` length modifier.
pub fn scan_input_wide(input: &[u8], directives: &[ScanDirective]) -> ScanResult {
    scan_input_impl::<true, true, _>(input, directives, |_, _, _| Ok(()))
}

/// Scan a wide input with a writer invoked before parsing the next directive.
///
/// `input` is the valid UTF-8 representation of wide characters, and directives
/// should come from [`parse_scanf_format_wide`]. Each successful nonsuppressed
/// conversion is delivered once. `None` is delivered only for a reached,
/// nonsuppressed `%m` conversion which failed before producing a value, so the
/// writer can clear that allocation destination. Suppressed conversions never
/// call the writer and therefore do not perform destination encoding.
///
/// A writer error leaves prior assignments intact and prevents later directives
/// (including `%n`) from running. This sink API leaves [`ScanResult::values`]
/// empty; the ordinary collecting APIs use the same scanner without allocating
/// a callback or adding dynamic dispatch.
pub fn scan_input_wide_with<F>(input: &[u8], directives: &[ScanDirective], writer: F) -> ScanResult
where
    F: FnMut(&ScanSpec, Option<&ScanValue>, ScanWriteContext) -> Result<(), ScanWriteError>,
{
    scan_input_impl::<false, true, _>(input, directives, writer)
}

/// One result from a wide stream read. The ABI owns decoding, errno, and FILE
/// indicators; the scanner asks for another result only when a directive needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideScanInput {
    Character(u32),
    Eof,
    Error,
}

/// Explicit format whitespace tolerates a failed read and still reaches `%n`.
/// Keeping its read purpose separate lets the ABI preserve the incoming errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideScanReadPurpose {
    FormatWhitespace,
    Conversion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WideScanSummary {
    pub count: i32,
    /// Logical wide characters consumed, excluding any unread lookahead.
    pub consumed: usize,
    pub input_failure: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideScanProgress {
    NeedInput(WideScanReadPurpose),
    Complete(WideScanSummary),
}

/// Text destinations are opened once, receive each character immediately,
/// and are either completed or abandoned. Suppressed conversions emit no events.
#[derive(Debug)]
pub enum WideScanEvent {
    BeginText,
    Character(u32),
    EndText,
    AbortText,
    Value(ScanValue),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WideScanContext {
    pub directive_index: usize,
    /// Includes the current character for a Character event, even if its
    /// destination encoding fails. All units are wide characters, not bytes.
    pub consumed: usize,
    pub matched: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WideScanWriteError {
    pub input_failure: bool,
}

enum WideScanPhase {
    Directive,
    Leading(ScanOperationKind),
    Text {
        kind: ScanOperationKind,
        matched: usize,
    },
    Number(WideScanNumber),
}

/// Resumable wide FILE scanning, with no whole-input buffer or replayed stores.
///
/// Start with `resume(None, ...)`, then supply exactly one input result after
/// each NeedInput. Text is delivered before asking for its next character, so
/// an unrepresentable destination character cannot cause a speculative read.
/// Numeric tokens alone retain their spelling until the existing value parser
/// runs once; ordinary tokens fit inline. The locale radix and whitespace
/// predicate must describe the same immutable locale snapshot for the call.
pub struct WideScanSession<'a> {
    directives: &'a [ScanDirective],
    directive_index: usize,
    count: i32,
    consumed: usize,
    radix: u32,
    phase: WideScanPhase,
    lookahead: Option<u32>,
    replay: std::collections::VecDeque<u32>,
    terminal: Option<WideScanInput>,
    waiting: bool,
    complete: Option<WideScanSummary>,
}

impl<'a> WideScanSession<'a> {
    #[must_use]
    pub fn new(directives: &'a [ScanDirective], radix: u32) -> Self {
        Self {
            directives,
            directive_index: 0,
            count: 0,
            consumed: 0,
            radix,
            phase: WideScanPhase::Directive,
            lookahead: None,
            replay: std::collections::VecDeque::new(),
            terminal: None,
            waiting: false,
            complete: None,
        }
    }

    /// Characters fetched but not consumed, in original input order. After
    /// Complete, the ABI restores these in reverse order through wide pushback.
    pub fn unread(&self) -> impl DoubleEndedIterator<Item = u32> + '_ {
        self.replay.iter().copied().chain(self.lookahead)
    }

    fn available(&self) -> Option<WideScanInput> {
        self.replay
            .front()
            .copied()
            .or(self.lookahead)
            .map(WideScanInput::Character)
            .or(self.terminal)
    }

    fn consume(&mut self) {
        if self.replay.pop_front().is_none() {
            let _ = self.lookahead.take();
        }
        self.consumed = self.consumed.saturating_add(1);
    }

    fn need_input(&mut self, purpose: WideScanReadPurpose) -> WideScanProgress {
        self.waiting = true;
        WideScanProgress::NeedInput(purpose)
    }

    fn finish(&mut self, input_failure: bool) -> WideScanProgress {
        let summary = WideScanSummary {
            count: self.count,
            consumed: self.consumed,
            input_failure,
        };
        self.complete = Some(summary);
        WideScanProgress::Complete(summary)
    }

    fn context(&self, matched: usize) -> WideScanContext {
        WideScanContext {
            directive_index: self.directive_index,
            consumed: self.consumed,
            matched,
        }
    }

    fn start_operation(kind: ScanOperationKind) -> WideScanPhase {
        match kind {
            ScanOperationKind::Character
            | ScanOperationKind::String
            | ScanOperationKind::Scanset => WideScanPhase::Text { kind, matched: 0 },
            _ => WideScanPhase::Number(WideScanNumber::new(kind)),
        }
    }

    fn end_text<F>(
        &mut self,
        spec: &ScanSpec,
        matched: usize,
        successful: bool,
        input_failure: bool,
        writer: &mut F,
    ) -> Option<WideScanProgress>
    where
        F: FnMut(&ScanSpec, WideScanEvent, WideScanContext) -> Result<(), WideScanWriteError>,
    {
        if !spec.suppress {
            let event = if successful {
                WideScanEvent::EndText
            } else {
                WideScanEvent::AbortText
            };
            if let Err(error) = writer(spec, event, self.context(matched)) {
                return Some(self.finish(error.input_failure));
            }
        }
        if !successful {
            return Some(self.finish(input_failure));
        }
        if !spec.suppress {
            self.count = self.count.saturating_add(1);
        }
        self.directive_index += 1;
        None
    }

    fn end_number<F>(
        &mut self,
        spec: &ScanSpec,
        number: WideScanNumber,
        writer: &mut F,
    ) -> Option<WideScanProgress>
    where
        F: FnMut(&ScanSpec, WideScanEvent, WideScanContext) -> Result<(), WideScanWriteError>,
    {
        let token = number.bytes.as_slice();
        let result = match number.kind {
            ScanOperationKind::Int(kind) => kind.scan(token, 0, spec),
            ScanOperationKind::Float => scan_float_c_radix(token, 0, spec),
            ScanOperationKind::Pointer => scan_pointer(token, 0, spec),
            _ => unreachable!("only numerical conversions collect a token"),
        };
        let (value, end) = result.unwrap_or((None, 0));
        // Only the numerical parser can rewind a speculative spelling, such
        // as the optional suffix of infinity. Restore scalar radix characters,
        // not their normalized one-byte representation, before existing lookahead.
        for &byte in token[end..].iter().rev() {
            let character = if number.kind == ScanOperationKind::Float && byte == b'.' {
                self.radix
            } else {
                u32::from(byte)
            };
            self.replay.push_front(character);
        }
        self.consumed -= token.len() - end;
        let Some(value) = value else {
            let exhausted = token.is_empty()
                && matches!(
                    self.available(),
                    Some(WideScanInput::Eof | WideScanInput::Error)
                );
            return Some(self.finish(exhausted));
        };
        if !spec.suppress {
            if let Err(error) = writer(spec, WideScanEvent::Value(value), self.context(end)) {
                return Some(self.finish(error.input_failure));
            }
            self.count = self.count.saturating_add(1);
        }
        self.directive_index += 1;
        None
    }

    /// Resume without repeating any completed conversion or writer event.
    /// A writer returning Err owns cleanup of that failed event; AbortText is
    /// reserved for a conversion abandoned by the parser itself.
    pub fn resume<F, S>(
        &mut self,
        input: Option<WideScanInput>,
        writer: &mut F,
        is_space: &S,
    ) -> WideScanProgress
    where
        F: FnMut(&ScanSpec, WideScanEvent, WideScanContext) -> Result<(), WideScanWriteError>,
        S: Fn(u32) -> bool,
    {
        if let Some(summary) = self.complete {
            return WideScanProgress::Complete(summary);
        }
        if let Some(input) = input {
            assert!(self.waiting, "supply input only after NeedInput");
            match input {
                WideScanInput::Character(character) => self.lookahead = Some(character),
                WideScanInput::Eof | WideScanInput::Error => self.terminal = Some(input),
            }
            self.waiting = false;
        }
        // Copy the borrowed slice so references into it do not borrow mutable
        // cursor state while a writer or state transition is being processed.
        let directives = self.directives;
        loop {
            let Some(directive) = directives.get(self.directive_index) else {
                return self.finish(false);
            };
            let phase = core::mem::replace(&mut self.phase, WideScanPhase::Directive);
            match phase {
                WideScanPhase::Directive => match directive {
                    ScanDirective::Malformed => return self.finish(false),
                    ScanDirective::Whitespace => match self.available() {
                        None => return self.need_input(WideScanReadPurpose::FormatWhitespace),
                        Some(WideScanInput::Character(character)) if is_space(character) => {
                            self.consume();
                        }
                        Some(_) => self.directive_index += 1,
                    },
                    ScanDirective::Literal(_) | ScanDirective::WideLiteral(_) => {
                        let expected = match directive {
                            ScanDirective::Literal(byte) => u32::from(*byte),
                            ScanDirective::WideLiteral(character) => *character,
                            _ => unreachable!(),
                        };
                        match self.available() {
                            None => return self.need_input(WideScanReadPurpose::Conversion),
                            Some(WideScanInput::Character(character)) if character == expected => {
                                self.consume();
                                self.directive_index += 1;
                            }
                            Some(WideScanInput::Character(_)) => return self.finish(false),
                            Some(WideScanInput::Eof | WideScanInput::Error) => {
                                return self.finish(true);
                            }
                        }
                    }
                    ScanDirective::Spec(spec) => {
                        let Some(kind) = spec.scan_operation_kind() else {
                            return self.finish(false);
                        };
                        if kind == ScanOperationKind::CharsConsumed {
                            if !spec.suppress
                                && let Err(error) = writer(
                                    spec,
                                    WideScanEvent::Value(ScanValue::CharsConsumed(self.consumed)),
                                    self.context(0),
                                )
                            {
                                return self.finish(error.input_failure);
                            }
                            self.directive_index += 1;
                            continue;
                        }
                        if matches!(
                            kind,
                            ScanOperationKind::Character
                                | ScanOperationKind::String
                                | ScanOperationKind::Scanset
                        ) && !spec.suppress
                            && let Err(error) =
                                writer(spec, WideScanEvent::BeginText, self.context(0))
                        {
                            return self.finish(error.input_failure);
                        }
                        self.phase = if spec.skips_leading_whitespace() {
                            WideScanPhase::Leading(kind)
                        } else {
                            Self::start_operation(kind)
                        };
                    }
                },
                WideScanPhase::Leading(kind) => {
                    let ScanDirective::Spec(spec) = directive else {
                        unreachable!("a conversion owns leading whitespace")
                    };
                    match self.available() {
                        None => {
                            self.phase = WideScanPhase::Leading(kind);
                            return self.need_input(WideScanReadPurpose::Conversion);
                        }
                        Some(WideScanInput::Character(character)) if is_space(character) => {
                            self.consume();
                            self.phase = WideScanPhase::Leading(kind);
                        }
                        Some(WideScanInput::Character(_)) => {
                            self.phase = Self::start_operation(kind)
                        }
                        Some(WideScanInput::Eof | WideScanInput::Error) => {
                            if matches!(
                                kind,
                                ScanOperationKind::Character
                                    | ScanOperationKind::String
                                    | ScanOperationKind::Scanset
                            ) && let Some(result) = self.end_text(spec, 0, false, true, writer)
                            {
                                return result;
                            }
                            return self.finish(true);
                        }
                    }
                }
                WideScanPhase::Text { kind, matched } => {
                    let ScanDirective::Spec(spec) = directive else {
                        unreachable!("a text conversion owns its character cursor")
                    };
                    let width = effective_width(
                        spec,
                        if kind == ScanOperationKind::Character {
                            1
                        } else {
                            usize::MAX
                        },
                    );
                    if matched == width {
                        if let Some(result) = self.end_text(
                            spec,
                            matched,
                            matched != 0 || kind == ScanOperationKind::Character,
                            false,
                            writer,
                        ) {
                            return result;
                        }
                        continue;
                    }
                    match self.available() {
                        None => {
                            self.phase = WideScanPhase::Text { kind, matched };
                            return self.need_input(WideScanReadPurpose::Conversion);
                        }
                        Some(WideScanInput::Character(character)) => {
                            let accepted = match kind {
                                ScanOperationKind::Character => true,
                                ScanOperationKind::String => !is_space(character),
                                ScanOperationKind::Scanset => wide_scanset_accepts(spec, character),
                                _ => unreachable!(),
                            };
                            if !accepted {
                                if let Some(result) =
                                    self.end_text(spec, matched, matched != 0, false, writer)
                                {
                                    return result;
                                }
                                continue;
                            }
                            self.consume();
                            let matched = matched + 1;
                            self.phase = WideScanPhase::Text { kind, matched };
                            if !spec.suppress
                                && let Err(error) = writer(
                                    spec,
                                    WideScanEvent::Character(character),
                                    self.context(matched),
                                )
                            {
                                return self.finish(error.input_failure);
                            }
                        }
                        Some(WideScanInput::Eof | WideScanInput::Error) => {
                            // Character fields must reach their full width;
                            // strings and scansets may finish a nonempty prefix.
                            if let Some(result) = self.end_text(
                                spec,
                                matched,
                                matched != 0 && kind != ScanOperationKind::Character,
                                true,
                                writer,
                            ) {
                                return result;
                            }
                        }
                    }
                }
                WideScanPhase::Number(mut number) => {
                    let ScanDirective::Spec(spec) = directive else {
                        unreachable!("a numerical conversion owns its token")
                    };
                    let width = effective_width(spec, usize::MAX);
                    // Floats and complete word spellings end at their width.
                    // GNU integer fields still fetch a lookahead at that point.
                    let at_width = number.bytes.len() == width;
                    if number.complete() || (at_width && number.kind == ScanOperationKind::Float) {
                        if let Some(result) = self.end_number(spec, number, writer) {
                            return result;
                        }
                        continue;
                    }
                    match self.available() {
                        None => {
                            self.phase = WideScanPhase::Number(number);
                            return self.need_input(WideScanReadPurpose::Conversion);
                        }
                        Some(WideScanInput::Character(character))
                            if !at_width && number.accept(character, spec, self.radix) =>
                        {
                            self.consume();
                            self.phase = WideScanPhase::Number(number);
                        }
                        Some(_) => {
                            if let Some(result) = self.end_number(spec, number, writer) {
                                return result;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn wide_scanset_accepts(spec: &ScanSpec, character: u32) -> bool {
    match spec.simple_set {
        SimpleScanSet::Byte(byte) => character == u32::from(byte),
        SimpleScanSet::NegatedByte(byte) => character != u32::from(byte),
        SimpleScanSet::None => spec
            .scanset
            .as_ref()
            .is_some_and(|set| set.contains_wide(character) != set.negated),
    }
}

#[derive(Clone, Copy)]
enum WideNumberState {
    Start,
    IntegerZero { base: u32, auto: bool },
    IntegerDigits(u32),
    FloatZero,
    Mantissa { hex: bool, dot: bool, digits: bool },
    Exponent { sign: bool },
    Word { word: &'static [u8], matched: usize },
    Infinity(usize),
    Nan,
    NanPayload,
    Complete,
}

struct WideScanNumber {
    kind: ScanOperationKind,
    state: WideNumberState,
    // Normalizing the locale radix to one byte preserves scalar field widths
    // and lets the existing numerical parsers run once without UTF-8 offsets.
    bytes: InlineVec<u8, 64>,
}

impl WideScanNumber {
    fn new(kind: ScanOperationKind) -> Self {
        Self {
            kind,
            state: WideNumberState::Start,
            bytes: InlineVec::default(),
        }
    }

    fn complete(&self) -> bool {
        matches!(self.state, WideNumberState::Complete)
    }

    fn accept(&mut self, character: u32, spec: &ScanSpec, radix: u32) -> bool {
        let radix_position = self.kind == ScanOperationKind::Float
            && matches!(
                self.state,
                WideNumberState::Start
                    | WideNumberState::FloatZero
                    | WideNumberState::Mantissa { .. }
            );
        let byte = if radix_position && character == radix {
            b'.'
        } else if character < 0x80 && !(radix_position && character == u32::from(b'.')) {
            character as u8
        } else {
            return false;
        };
        if self.accept_byte(byte, spec) {
            self.bytes.push(byte);
            true
        } else {
            false
        }
    }

    fn accept_byte(&mut self, byte: u8, spec: &ScanSpec) -> bool {
        match self.state {
            WideNumberState::Start => {
                if self.bytes.is_empty() && matches!(byte, b'+' | b'-') {
                    return true;
                }
                if self.kind == ScanOperationKind::Float {
                    self.state = match byte {
                        b'0' => WideNumberState::FloatZero,
                        b'1'..=b'9' => WideNumberState::Mantissa {
                            hex: false,
                            dot: false,
                            digits: true,
                        },
                        b'.' => WideNumberState::Mantissa {
                            hex: false,
                            dot: true,
                            digits: false,
                        },
                        b'i' | b'I' => WideNumberState::Word {
                            word: b"inf",
                            matched: 1,
                        },
                        b'n' | b'N' => WideNumberState::Word {
                            word: b"nan",
                            matched: 1,
                        },
                        _ => return false,
                    };
                    return true;
                }
                if self.kind == ScanOperationKind::Pointer
                    && self.bytes.is_empty()
                    && byte == b'('
                    && effective_width(spec, usize::MAX) >= 5
                {
                    self.state = WideNumberState::Word {
                        word: b"(nil)",
                        matched: 1,
                    };
                    return true;
                }
                let (base, auto) = match self.kind {
                    ScanOperationKind::Int(IntScanKind::SignedAutoBase) => {
                        (if byte == b'0' { 8 } else { 10 }, true)
                    }
                    ScanOperationKind::Int(IntScanKind::UnsignedOctal) => (8, false),
                    ScanOperationKind::Int(IntScanKind::UnsignedBinary) => (2, false),
                    ScanOperationKind::Int(IntScanKind::UnsignedHex)
                    | ScanOperationKind::Pointer => (16, false),
                    _ => (10, false),
                };
                if digit_value(byte, base).is_none() {
                    return false;
                }
                self.state = if byte == b'0' && (auto || base == 2 || base == 16) {
                    WideNumberState::IntegerZero { base, auto }
                } else {
                    WideNumberState::IntegerDigits(base)
                };
                true
            }
            WideNumberState::IntegerZero { base, auto } => {
                let prefix_base = if byte.eq_ignore_ascii_case(&b'x') && (auto || base == 16) {
                    Some(16)
                } else if byte.eq_ignore_ascii_case(&b'b')
                    && (base == 2 || (auto && spec.binary_prefix))
                {
                    Some(2)
                } else {
                    None
                };
                if let Some(base) = prefix_base {
                    self.state = WideNumberState::IntegerDigits(base);
                    true
                } else {
                    self.state = WideNumberState::IntegerDigits(base);
                    digit_value(byte, base).is_some()
                }
            }
            WideNumberState::IntegerDigits(base) => digit_value(byte, base).is_some(),
            WideNumberState::FloatZero => {
                if byte.eq_ignore_ascii_case(&b'x') {
                    self.state = WideNumberState::Mantissa {
                        hex: true,
                        dot: false,
                        digits: false,
                    };
                    true
                } else {
                    self.state = WideNumberState::Mantissa {
                        hex: false,
                        dot: false,
                        digits: true,
                    };
                    self.accept_byte(byte, spec)
                }
            }
            WideNumberState::Mantissa { hex, dot, digits } => {
                if digit_value(byte, if hex { 16 } else { 10 }).is_some() {
                    self.state = WideNumberState::Mantissa {
                        hex,
                        dot,
                        digits: true,
                    };
                    true
                } else if byte == b'.' && !dot {
                    self.state = WideNumberState::Mantissa {
                        hex,
                        dot: true,
                        digits,
                    };
                    true
                } else if digits && byte.eq_ignore_ascii_case(&if hex { b'p' } else { b'e' }) {
                    self.state = WideNumberState::Exponent { sign: true };
                    true
                } else {
                    false
                }
            }
            WideNumberState::Exponent { sign } => {
                if byte.is_ascii_digit() || (sign && matches!(byte, b'+' | b'-')) {
                    self.state = WideNumberState::Exponent { sign: false };
                    true
                } else {
                    false
                }
            }
            WideNumberState::Word { word, matched } => {
                if !byte.eq_ignore_ascii_case(&word[matched]) {
                    return false;
                }
                self.state = if matched + 1 < word.len() {
                    WideNumberState::Word {
                        word,
                        matched: matched + 1,
                    }
                } else if word == b"inf" {
                    WideNumberState::Infinity(0)
                } else if word == b"nan" {
                    WideNumberState::Nan
                } else {
                    WideNumberState::Complete
                };
                true
            }
            WideNumberState::Infinity(matched) => {
                if !byte.eq_ignore_ascii_case(&b"inity"[matched]) {
                    return false;
                }
                self.state = if matched == 4 {
                    WideNumberState::Complete
                } else {
                    WideNumberState::Infinity(matched + 1)
                };
                true
            }
            WideNumberState::Nan => {
                if byte == b'(' {
                    self.state = WideNumberState::NanPayload;
                    true
                } else {
                    false
                }
            }
            WideNumberState::NanPayload => {
                if byte == b')' {
                    self.state = WideNumberState::Complete;
                    true
                } else {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                }
            }
            WideNumberState::Complete => false,
        }
    }
}

fn scan_input_impl<const COLLECT: bool, const WIDE_INPUT: bool, F>(
    input: &[u8],
    directives: &[ScanDirective],
    mut writer: F,
) -> ScanResult
where
    F: FnMut(&ScanSpec, Option<&ScanValue>, ScanWriteContext) -> Result<(), ScanWriteError>,
{
    let wide_input = WIDE_INPUT;
    let mut pos = 0;
    let mut values = ScanValues::default();
    let mut count: i32 = 0;
    // Count wide characters only when `%n` requests them, and visit each input
    // byte at most once across repeated `%n` directives.
    let mut count_prefix_end = 0;
    let mut wide_char_count = 0;
    // NOTE: there is deliberately no running `input_failure` flag any more.
    // Each arm below decides EOF from what IT observed -- a directive that
    // demanded input and did not get it -- rather than from whether some
    // earlier directive happened to succeed. The running flag got both
    // directions wrong: it stayed set through a format that completed
    // (reporting EOF for `swscanf("xC6", " ")`, which glibc answers 0) and
    // it got cleared by a SUPPRESSED conversion (reporting 0 for
    // `swscanf("1", " %*2xx")`, which glibc answers -1).

    for (directive_index, dir) in directives.iter().enumerate() {
        match dir {
            // Malformed format: stop with the assignments already made and
            // report a MATCHING failure, not EOF. glibc returns 0 for
            // sscanf("^abc", "%[^]") — input was available, the format was
            // broken — so input_failure must be cleared here even though no
            // conversion succeeded.
            ScanDirective::Malformed => {
                return ScanResult {
                    values,
                    count,
                    // `pos`, not 0: whatever earlier directives legitimately
                    // consumed still counts, so a trailing `%n` in a format
                    // that also contains a malformed scanset reports the right
                    // offset.
                    consumed: pos,
                    input_failure: false,
                    failed_alloc: false,
                };
            }
            ScanDirective::Whitespace => {
                // Skip whitespace in input (Unicode-aware for a wide stream).
                pos = skip_ws(input, pos, wide_input);
            }
            ScanDirective::Literal(expected) => {
                if pos >= input.len() {
                    // A literal that runs out of input IS an input failure,
                    // regardless of whether an earlier directive already read
                    // something. Measured on glibc 2.42:
                    //     swscanf("1",  " %*2xx") -> -1
                    //     swscanf("",   "x")      -> -1
                    // In the first, the suppressed %2x consumed the whole input
                    // and cleared the running flag, yet glibc still reports EOF
                    // because no ASSIGNMENT had been made. The caller applies
                    // `input_failure && count == 0`, so reporting the input
                    // failure here is what makes both rows come out right;
                    // carrying the running flag reported 0 for the first.
                    return ScanResult {
                        values,
                        count,
                        consumed: pos,
                        input_failure: true,
                        failed_alloc: false,
                    };
                }
                if input[pos] != *expected {
                    return ScanResult {
                        values,
                        count,
                        consumed: pos,
                        input_failure: false,
                        failed_alloc: false,
                    };
                }
                pos += 1;
            }
            ScanDirective::WideLiteral(expected) => {
                let character = wide_character_at(input, pos);
                if character.is_none_or(|(actual, _)| actual != *expected) {
                    return ScanResult {
                        values,
                        count,
                        consumed: pos,
                        input_failure: pos >= input.len(),
                        failed_alloc: false,
                    };
                }
                pos += character.expect("the complete wide literal matched").1;
            }
            ScanDirective::Spec(spec) => {
                let result = spec.scan_at(input, pos, wide_input);
                match result {
                    None => {
                        // Matching failure or input exhaustion.
                        //
                        // `%c`/`%mc`/`%lc` ARE DIFFERENT: their width is a
                        // REQUIREMENT, so running short of it is input exhaustion
                        // and glibc answers EOF, not a matching failure. Measured
                        // on glibc 2.42: sscanf("ab", "%5c") == -1,
                        // sscanf("ab", "%5mc") == -1, sscanf("", "%1c") == -1,
                        // while sscanf("ab", "%2c") == 1 and consumes both bytes.
                        // Without this the engine reported a match failure and the
                        // caller returned 0 where the host returns EOF (bd-7ilguh).
                        let stopped_pos = if wide_input && spec.skips_leading_whitespace() {
                            skip_ws(input, pos, true)
                        } else {
                            pos
                        };
                        let exhausted_before_conversion = if spec.skips_leading_whitespace() {
                            skip_ws(input, pos, spec.wide_input) >= input.len()
                        } else if spec.conversion == b'c' {
                            let needed = spec.width.unwrap_or(1).max(1);
                            let available = if spec.wide_input {
                                let mut count = 0usize;
                                let mut i = pos;
                                while i < input.len() {
                                    let len = utf8_seq_len(input[i]);
                                    if i + len > input.len() {
                                        break;
                                    }
                                    i += len;
                                    count += 1;
                                }
                                count
                            } else {
                                input.len() - pos
                            };
                            available < needed
                        } else {
                            pos >= input.len()
                        };
                        let input_failure =
                            exhausted_before_conversion && (wide_input || count == 0);
                        if spec.alloc && !spec.suppress {
                            let context = ScanWriteContext {
                                directive_index,
                                token_start: stopped_pos,
                                token_end: stopped_pos,
                            };
                            if let Err(error) = writer(spec, None, context) {
                                return ScanResult {
                                    values,
                                    count,
                                    consumed: scan_write_error_offset(input, context, error),
                                    input_failure: error.input_failure,
                                    failed_alloc: true,
                                };
                            }
                        }
                        return ScanResult {
                            values,
                            count,
                            consumed: stopped_pos,
                            input_failure,
                            failed_alloc: spec.alloc && !spec.suppress,
                        };
                    }
                    Some((None, new_pos)) => {
                        // An incomplete integer token consumes its sign/prefix
                        // but neither assigns a value nor reaches later %n or
                        // suppressed directives (GNU 2.43 semantics).
                        return ScanResult {
                            values,
                            count,
                            consumed: new_pos,
                            input_failure: false,
                            failed_alloc: false,
                        };
                    }
                    Some((Some(mut v), new_pos)) => {
                        let previous_pos = pos;
                        pos = new_pos;
                        if !spec.suppress {
                            if wide_input && let ScanValue::CharsConsumed(ref mut n) = v {
                                wide_char_count += input[count_prefix_end..pos]
                                    .iter()
                                    .filter(|&&b| b & 0xc0 != 0x80)
                                    .count();
                                count_prefix_end = pos;
                                *n = wide_char_count;
                            }
                            let counts_as_assignment = !matches!(v, ScanValue::CharsConsumed(_));
                            let token_start = match &v {
                                ScanValue::Char(bytes) | ScanValue::String(bytes) => {
                                    new_pos - bytes.len()
                                }
                                _ => previous_pos,
                            };
                            let context = ScanWriteContext {
                                directive_index,
                                token_start,
                                token_end: new_pos,
                            };
                            if let Err(error) = writer(spec, Some(&v), context) {
                                return ScanResult {
                                    values,
                                    count,
                                    consumed: scan_write_error_offset(input, context, error),
                                    input_failure: error.input_failure,
                                    failed_alloc: spec.alloc,
                                };
                            }
                            if COLLECT {
                                values.push(v);
                            }
                            if counts_as_assignment {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Every directive was satisfied, so this is NOT an input failure -- whatever
    // the running flag says. It starts `true` and is only cleared by a
    // successful CONVERSION, so a format that completes without one left it set
    // and the caller reported EOF. Measured on glibc 2.42:
    //     swscanf("xC6", " ") -> 0     whitespace-only format
    //     swscanf("",    " ") -> 0     ...even against empty input
    //     swscanf("xx",  "x") -> 0     literal matched, nothing assigned
    // Whitespace matches zero or more characters and so can never fail, which
    // is why the second row is 0 and not EOF; `x` against "" is EOF only
    // because the literal demanded a character that was not there, and that is
    // handled at the Literal arm above.
    //
    // `stdio_abi`'s strict fast-path scanner already returned `false` here; this
    // is the general engine catching up with it.
    ScanResult {
        values,
        count,
        consumed: pos,
        input_failure: false,
        failed_alloc: false,
    }
}

fn scan_write_error_offset(
    input: &[u8],
    context: ScanWriteContext,
    error: ScanWriteError,
) -> usize {
    let mut pos = error.consumed.clamp(context.token_start, context.token_end);
    while pos > context.token_start && input.get(pos).is_some_and(|b| b & 0xc0 == 0x80) {
        pos -= 1;
    }
    pos
}

/// Byte length of a whitespace run starting at `pos`, or 0 if `pos` is not
/// whitespace. For a narrow stream this is `1` iff the byte is ASCII whitespace.
/// For a WIDE stream the input bytes are the UTF-8 encoding of wide characters,
/// so the whole UTF-8 sequence is decoded and tested with `iswspace`, matching
/// glibc's wide scanf (which recognises U+2003, U+205F, U+3000, … as space).
#[inline]
fn ws_seq_len(input: &[u8], pos: usize, wide: bool) -> usize {
    if pos >= input.len() {
        return 0;
    }
    if !wide {
        return if is_c_space(input[pos]) { 1 } else { 0 };
    }
    let len = utf8_seq_len(input[pos]);
    if pos + len > input.len() {
        // Truncated trailing sequence: fall back to the ASCII test.
        return if is_c_space(input[pos]) { 1 } else { 0 };
    }
    match core::str::from_utf8(&input[pos..pos + len]) {
        Ok(s) => match s.chars().next() {
            Some(c) if crate::string::wchar::iswspace(c as u32) => len,
            _ => 0,
        },
        Err(_) => {
            if is_c_space(input[pos]) {
                1
            } else {
                0
            }
        }
    }
}

/// Skip leading whitespace. Returns new position. When `wide`, Unicode
/// whitespace (whole UTF-8 sequences) is skipped, not just ASCII.
fn skip_ws(input: &[u8], mut pos: usize, wide: bool) -> usize {
    loop {
        let n = ws_seq_len(input, pos, wide);
        if n == 0 {
            break;
        }
        pos += n;
    }
    pos
}

/// Effective width: explicit or unlimited.
fn effective_width(spec: &ScanSpec, default: usize) -> usize {
    spec.width.unwrap_or(default)
}

fn apply_leading_whitespace_policy(input: &[u8], pos: usize, spec: &ScanSpec) -> usize {
    if spec.skips_leading_whitespace() {
        skip_ws(input, pos, spec.wide_input)
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

    // A base prefix is consumed input, not a significand digit. GNU 2.43
    // rejects a bare prefix even when a field width ends immediately after it.
    let mut any_digit = false;
    // Explicit %b accepts 0b/0B in every standards mode, independently of
    // the dialect flag that controls binary prefixes for %i.
    if matches!(base, 2 | 16)
        && i + 1 < input.len()
        && chars_read + 2 <= max_chars
        && input[i] == b'0'
        && input[i + 1].eq_ignore_ascii_case(&if base == 2 { b'b' } else { b'x' })
    {
        i += 2;
        chars_read += 2;
    }

    // Digits. The accumulator saturates to u64::MAX on overflow; glibc
    // clamps an out-of-range integer to its limit rather than wrapping.
    let mut val: u64 = 0;
    let mut overflowed = false;

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
        return Some((None, i));
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
        if spec.writes_pointer() {
            // `%p` uses the hexadecimal scanner, but stores a whole pointer,
            // not the default-width unsigned int used by `%x`.
            ScanValue::Pointer(uval as usize)
        } else {
            ScanValue::UnsignedInt(narrow_unsigned(uval, spec.length))
        }
    };

    Some((Some(value), i))
}

/// Scan integer with auto-detected base (`%i`, including `0b` only for C23).
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

    // As in explicit hex conversion, a prefix needs a following digit. Retain
    // its consumed position separately from whether conversion succeeded.
    let mut any_digit = false;
    // Detect base (hex 0x, C23 binary 0b, octal 0, decimal otherwise).
    let base = if i < input.len() && chars_read < max_chars && input[i] == b'0' {
        if i + 1 < input.len()
            && chars_read + 1 < max_chars
            && (input[i + 1] == b'x' || input[i + 1] == b'X')
        {
            i += 2;
            chars_read += 2;
            16u32
        } else if spec.binary_prefix
            && i + 1 < input.len()
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
        return Some((None, i));
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

/// Wrap a scanned float value, carrying full x87 precision for `%Lf`.
///
/// The engine parses every float to `f64`, which is the right width for `%f`
/// and `%lf` and the WRONG one for `%Lf`: the significand is truncated to 53
/// bits before any writer sees the value, and widening at the ABI cannot
/// recover digits the parse already threw away. For a long-double conversion
/// the accepted token is re-read with [`crate::float128::strtold_scan`] — the
/// same front end `strtold` uses, verified against glibc over 625 vectors.
///
/// `token` is the byte range this conversion ACCEPTED: sign included, field
/// width already applied, trailing garbage already excluded. Passing the token
/// rather than the remaining input is what keeps the two scanners from
/// disagreeing about where the number ends — matching, backtracking and the
/// consumed count all stay with the caller, and only the value's precision
/// changes here.
#[inline]
fn float_scan_value(spec: &ScanSpec, val: f64, token: &[u8]) -> ScanValue {
    if spec.length == LengthMod::BigL {
        // The token is already in C form (see `scan_float`).
        ScanValue::LongDouble(crate::float128::strtold_scan_c(token).bytes)
    } else {
        ScanValue::Float(val)
    }
}

/// Scan a floating-point number.
fn scan_float(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    // A non-"." LC_NUMERIC radix: scan the C form of the token from `pos`
    // (offsets unchanged, so the resulting position maps straight back).
    if crate::stdio::printf::numeric_radix_byte().is_some() && pos <= input.len() {
        let mut tail = input[pos..].to_vec();
        tail.push(0);
        if let Some(mut c_form) = crate::stdlib::conversion::c_radix_copy(&tail) {
            c_form.pop(); // the parsers' NUL; scanf input is length-delimited
            let (value, end) = scan_float_c_radix(&c_form, 0, spec)?;
            return Some((value, pos + end));
        }
    }
    scan_float_c_radix(input, pos, spec)
}

/// [`scan_float`] for input whose radix is ".".
fn scan_float_c_radix(
    input: &[u8],
    pos: usize,
    spec: &ScanSpec,
) -> Option<(Option<ScanValue>, usize)> {
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
            return Some((Some(float_scan_value(spec, val, &input[pos..i])), i));
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
            let mut payload: u64 = 0;
            if remaining.len() > j && j < budget && remaining[j] == b'(' {
                let mut k = j + 1;
                while k < remaining.len()
                    && k < budget
                    && (remaining[k].is_ascii_alphanumeric() || remaining[k] == b'_')
                {
                    k += 1;
                }
                if k < remaining.len() && k < budget && remaining[k] == b')' {
                    // glibc does not discard the sequence: __strtod_nan runs it
                    // through strtoull with base 0 and, when the WHOLE sequence
                    // parses to a nonzero value, ORs it into the mantissa. So
                    // "nan(1)" is 0x7fc00001 as a float, not the default quiet
                    // NaN. Base 0 means "0x1ff" is hex and a leading "0" is
                    // octal; a sequence that is not a number at all ("abc") or
                    // is empty leaves the default, and glibc still ACCEPTS the
                    // token either way.
                    payload = crate::stdlib::conversion::parse_nan_payload(&remaining[j + 1..k]);
                    j = k + 1; // consume through the ')'
                } else {
                    // Malformed payload (no closing paren / cut off by width):
                    // glibc rewinds the entire token → matching failure.
                    return None;
                }
            }
            // Reuse strtod's encoder rather than open-coding the bit layout:
            // the payload lives in the LOW mantissa bits so that
            // narrow_f64_to_f32 (which takes the low 23) lands a `%f` store on
            // glibc's value with no second encoding step. Sharing it also keeps
            // scanf and strtod from drifting apart on the same grammar.
            let val = crate::stdlib::conversion::nan_f64(payload, negative);
            return Some((Some(float_scan_value(spec, val, &input[pos..i + j])), i + j));
        }
    }

    // Check for hex float (0x prefix).
    if chars_read + 2 <= max_chars
        && i + 1 < input.len()
        && input[i] == b'0'
        && (input[i + 1] == b'x' || input[i + 1] == b'X')
        && let Some(result) = scan_hex_float(input, pos, i, chars_read, negative, max_chars, spec)
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
    //
    // The accepted token is CONTIGUOUS in `input`, so it is parsed in place.
    // This used to copy it byte by byte into a `Vec::with_capacity(64)` just to
    // hand a slice to `str::parse` -- one heap allocation and one push per
    // character on every float conversion, where glibc allocates nothing at all.
    //
    // The sign is applied AFTER parsing the magnitude rather than being
    // prepended to a buffer, which is what lets the token be read straight out
    // of `input`. That is exact for the cases that matter: "0.0" negated is
    // -0.0, and "1e400" negated is -inf, matching what parsing "-0.0" and
    // "-1e400" produced before.
    let tok_start = i;
    let mut any_digit = false;
    let mut seen_dot = false;
    let mut value_end = None;
    while i < input.len() && chars_read < max_chars {
        let c = input[i];
        if c.is_ascii_digit() {
            any_digit = true;
        } else if c == b'.' && !seen_dot {
            // Only the FIRST decimal point is part of the float; a second '.'
            // ends the token (glibc reads the longest valid prefix, e.g.
            // "03.1.5" -> 3.1 consuming 4 bytes). Found by sscanf_differential_fuzz.
            seen_dot = true;
        } else if (c == b'e' || c == b'E') && any_digit {
            let mantissa_end = i;
            i += 1;
            chars_read += 1;
            // Optional exponent sign.
            if i < input.len() && chars_read < max_chars && (input[i] == b'+' || input[i] == b'-') {
                i += 1;
                chars_read += 1;
            }
            // Exponent digits.
            let exponent_start = i;
            while i < input.len() && chars_read < max_chars && input[i].is_ascii_digit() {
                i += 1;
                chars_read += 1;
            }
            if i == exponent_start {
                // GNU scanf consumes an incomplete exponent marker and its
                // optional sign, but assigns the mantissa. Rust's float parser
                // rejects that suffix, so separate value parsing from input
                // consumption; `%n` and the following directive still see `i`.
                value_end = Some(mantissa_end);
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

    // Parse the accepted token straight out of `input`.
    let s = core::str::from_utf8(input.get(tok_start..value_end.unwrap_or(i))?).ok()?;
    let magnitude: f64 = s.parse().ok()?;
    let val = if negative { -magnitude } else { magnitude };

    Some((Some(float_scan_value(spec, val, &input[pos..i])), i))
}

/// Scan a hex float (0x[h...h][.h...h][pN]) per C11 7.21.6.2.
/// Called after the optional sign and 0x prefix have been detected.
fn scan_hex_float(
    input: &[u8],
    start_pos: usize,
    mut i: usize,
    mut chars_read: usize,
    negative: bool,
    max_chars: usize,
    spec: &ScanSpec,
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
            return Some((Some(float_scan_value(spec, val, &input[start_pos..i])), i));
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

        while i < input.len() && chars_read < max_chars && input[i].is_ascii_digit() {
            let d = (input[i] - b'0') as i32;
            bin_exp = bin_exp.saturating_mul(10).saturating_add(d);
            i += 1;
            chars_read += 1;
        }

        // As for decimal exponents, GNU scanf consumes an incomplete `p`/`P`
        // suffix and optional sign, retaining the significand with exponent 0.
        if exp_negative {
            bin_exp = -bin_exp;
        }
    }

    // Convert to f64: value = significand * 2^(bin_exp - 4*frac_digits). Each
    // hex fractional digit shifts the binary point 4 bits. Scale with
    // `libm::ldexp` (== scalbn) rather than `* 2_f64.powi(n)`: for a large
    // negative exponent `powi` evaluates 1/2^|n|, and 2^1074 overflows to inf,
    // so the smallest subnormal `0x1p-1074` (5e-324) wrongly underflowed to 0.
    // ldexp handles the full subnormal/overflow range correctly.
    //
    // Restored under bd-2g7oyh: 8f0dda241 fixed this and 73c8da5cd reverted it
    // (1424 insertions against 9431 deletions). The saturating arithmetic went
    // with it — plain `bin_exp - frac_digits * 4` can overflow on an input with
    // enough fractional digits, which is reachable from untrusted text.
    let total_exp = bin_exp.saturating_sub(frac_digits.saturating_mul(4));
    let mut val = libm::ldexp(significand as f64, total_exp);
    if negative {
        val = -val;
    }

    Some((Some(float_scan_value(spec, val, &input[start_pos..i])), i))
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
fn scan_char(
    input: &[u8],
    pos: usize,
    spec: &ScanSpec,
    wide_input: bool,
) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
    let n = spec.width.unwrap_or(1);
    // `%lc` ALWAYS counts wide characters; for a WIDE scanf stream (swscanf) the
    // input is multibyte-encoded wide text, so even a narrow `%c` width counts
    // WIDE characters — read `n` complete UTF-8 sequences either way so a width
    // never splits a multibyte character.
    if wide_input || matches!(spec.length, LengthMod::L) {
        // REQUIRE THE FULL WIDTH. glibc FAILS the conversion when the input runs
        // out before `n` characters — measured on glibc 2.42: swscanf(L"ab",
        // L"%5lc") == -1 (and sscanf("ab", "%5c") == -1 for the narrow form
        // below), while swscanf(L"ab", L"%2lc") == 1 with both characters. An
        // earlier revision of this branch read UP TO `n` and still succeeded, on
        // the claim that glibc clamps; that claim is wrong and the differential
        // gate caught it (bd-7ilguh).
        let mut end = pos;
        let mut read = 0usize;
        while read < n && end < input.len() {
            let next = end.checked_add(utf8_seq_len(input[end]))?;
            if next > input.len() {
                break; // incomplete trailing sequence — cannot complete `n` chars
            }
            end = next;
            read += 1;
        }
        if read < n {
            return None;
        }
        return Some((
            Some(ScanValue::Char(ScanBytes::from_slice(&input[pos..end]))),
            end,
        ));
    }
    // Guard against pathological widths that overflow pos + n. Under
    // debug_assertions `usize` add panics; in release it wraps and
    // would skip the bounds check below, reading past input. (bd-35vob)
    let want_end = pos.checked_add(n)?;
    // The width is a REQUIREMENT, not a budget: if the input cannot supply `n`
    // bytes the conversion fails and the engine reports it the way glibc does.
    if want_end > input.len() {
        return None;
    }
    let end = want_end;
    let chars = input[pos..end].to_vec();
    Some((Some(ScanValue::Char(ScanBytes::from_slice(&chars))), end))
}

/// Scan a string (%s). Skips whitespace, then reads non-whitespace.
fn scan_string(
    input: &[u8],
    pos: usize,
    spec: &ScanSpec,
    wide_input: bool,
) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);
    // `%ls` width counts WIDE characters; consume whole UTF-8 sequences so a
    // bounded `%Nls` never splits a multibyte character. A narrow `%s` counts
    // bytes for a narrow stream (sscanf) but WIDE characters for a wide stream
    // (swscanf), whose input is multibyte-encoded wide text.
    let wide = wide_input || matches!(spec.length, LengthMod::L);
    let mut i = pos;
    let mut chars_read = 0usize;

    // Find the token end WITHOUT copying, then take the bytes in one shot.
    // This used to push a byte at a time into a `Vec::new()`, which starts at
    // zero capacity: a long token paid a reallocate-and-memcpy every time the
    // buffer doubled, plus a capacity check per byte, and the token is
    // contiguous in `input` the whole time. `long_string` was the worst case in
    // the whole sscanf family at 2.387x glibc, and it is precisely the case
    // with the most bytes to move.
    while i < input.len() && chars_read < max_chars {
        // The token ends at whitespace. For a wide stream that means Unicode
        // whitespace (a whole UTF-8 sequence), not only ASCII — `wide_input` is
        // the STREAM flag (distinct from `wide`, which also covers narrow `%ls`).
        if ws_seq_len(input, i, wide_input) != 0 {
            break;
        }
        if wide {
            i = (i + utf8_seq_len(input[i])).min(input.len());
        } else {
            i += 1;
        }
        chars_read += 1;
    }

    if i == pos {
        return None;
    }

    Some((
        Some(ScanValue::String(ScanBytes::from_slice(&input[pos..i]))),
        i,
    ))
}

#[cfg(test)]
mod scanset_bitmap_tests {
    use super::{ScanSet, ScanSetBits};

    /// The bitmap must answer exactly what the table it replaced answered, for
    /// every one of the 256 byte values — including the high half, where a
    /// shift-based index is easiest to get wrong.
    #[test]
    fn bitmap_matches_the_table_for_every_byte() {
        // A deliberately awkward set: both ends, both sides of every word
        // boundary (63/64, 127/128, 191/192), and a scattering between.
        let mut table = [false; 256];
        for c in [
            0u8, 1, 62, 63, 64, 65, 97, 122, 126, 127, 128, 129, 190, 191, 192, 193, 254, 255,
        ] {
            table[c as usize] = true;
        }
        let mut bits = ScanSetBits::default();
        for (c, &present) in table.iter().enumerate() {
            if present {
                bits.insert(c as u8);
            }
        }
        let set = ScanSet::from_bits(false, bits);
        for c in 0..=255u8 {
            assert_eq!(
                set.contains(c),
                table[c as usize],
                "byte {c}: bitmap and table disagree"
            );
        }
    }

    /// An empty set contains nothing and a full set contains everything; both
    /// are reachable from real formats (`%[]` handling and `%[^]` negation).
    #[test]
    fn empty_and_full_sets_round_trip() {
        let empty = ScanSet::from_bits(false, ScanSetBits::default());
        let mut all = ScanSetBits::default();
        for c in 0..=255u8 {
            all.insert(c);
        }
        let full = ScanSet::from_bits(true, all);
        for c in 0..=255u8 {
            assert!(!empty.contains(c), "empty set claimed to contain {c}");
            assert!(full.contains(c), "full set missing {c}");
        }
        assert!(!empty.negated);
        assert!(full.negated);
    }
}

/// Scan a scanset (%[...]). No whitespace skip.
fn scan_scanset(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    if spec.wide_input {
        return scan_scanset_wide(input, pos, spec);
    }
    let pos = apply_leading_whitespace_policy(input, pos, spec);
    // Exactly one of the two representations is populated: a one-member set
    // inline, anything larger boxed. Neither means this is not a scanset spec.
    let scanset = match spec.simple_set {
        SimpleScanSet::None => Some(spec.scanset.as_ref()?),
        _ => None,
    };
    let max_chars = effective_width(spec, usize::MAX);
    let mut i = pos;
    let mut chars_read = 0usize;

    // Same two-phase shape as `scan_string`: locate the run, then copy it once.
    // A scanset run is contiguous, so growing a Vec byte by byte only added
    // reallocations (`scanset_only` measured 1.651x glibc).
    while i < input.len() && chars_read < max_chars {
        let c = input[i];
        let accept = match spec.simple_set {
            SimpleScanSet::Byte(b) => c == b,
            SimpleScanSet::NegatedByte(b) => c != b,
            SimpleScanSet::None => {
                // SAFETY of the unwrap: `scanset` is `Some` exactly when
                // `simple_set` is `None`, established above.
                let table = scanset.expect("a scanset spec has one representation");
                let in_set = table.contains(c);
                if table.negated { !in_set } else { in_set }
            }
        };
        if !accept {
            break;
        }
        i += 1;
        chars_read += 1;
    }

    if i == pos {
        return None;
    }

    Some((
        Some(ScanValue::String(ScanBytes::from_slice(&input[pos..i]))),
        i,
    ))
}

/// Wide scansets test scalar membership and charge one field-width unit per
/// complete character. The narrow scanner above keeps its byte-only loop.
fn scan_scanset_wide(
    input: &[u8],
    pos: usize,
    spec: &ScanSpec,
) -> Option<(Option<ScanValue>, usize)> {
    let scanset = match spec.simple_set {
        SimpleScanSet::None => Some(spec.scanset.as_ref()?),
        _ => None,
    };
    let max_chars = effective_width(spec, usize::MAX);
    let mut end = pos;
    let mut chars_read = 0;
    while chars_read < max_chars {
        let Some((character, len)) = wide_character_at(input, end) else {
            break;
        };
        let accept = match spec.simple_set {
            SimpleScanSet::Byte(byte) => character == byte as u32,
            SimpleScanSet::NegatedByte(byte) => character != byte as u32,
            SimpleScanSet::None => {
                let set = scanset.expect("a scanset spec has one representation");
                set.contains_wide(character) != set.negated
            }
        };
        if !accept {
            break;
        }
        end += len;
        chars_read += 1;
    }
    if end == pos {
        return None;
    }
    Some((
        Some(ScanValue::String(ScanBytes::from_slice(&input[pos..end]))),
        end,
    ))
}

/// Scan a pointer (%p): unsigned hexadecimal or GNU's case-insensitive (nil).
fn scan_pointer(input: &[u8], pos: usize, spec: &ScanSpec) -> Option<(Option<ScanValue>, usize)> {
    let pos = apply_leading_whitespace_policy(input, pos, spec);
    if pos >= input.len() {
        return None;
    }

    let max_chars = effective_width(spec, usize::MAX);

    // GNU attempts this spelling only when the whole token fits the width.
    // On failure, matched prefix bytes stay consumed; the first mismatch
    // stays unread. Return a matching failure even if that prefix reaches EOF.
    if input[pos] == b'(' && max_chars >= 5 {
        let mut i = pos;
        for expected in b"(nil)" {
            if input
                .get(i)
                .is_none_or(|b| !b.eq_ignore_ascii_case(expected))
            {
                return Some((None, i));
            }
            i += 1;
        }
        return Some((Some(ScanValue::Pointer(0)), i));
    }

    scan_int(input, pos, spec, 16, false)
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
            assert!(ss.contains(b'a'));
            assert!(ss.contains(b'b'));
            assert!(ss.contains(b'c'));
            assert!(!ss.contains(b'd'));
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
            assert!(ss.contains(b'a'));
        } else {
            panic!("expected Spec");
        }
    }

    /// Helper: the single `ScanSpec` a one-directive format parses to.
    fn only_spec(fmt: &[u8]) -> ScanSpec {
        let dirs = parse_scanf_format(fmt);
        assert_eq!(dirs.len(), 1, "expected exactly one directive from {fmt:?}");
        match &dirs[0] {
            ScanDirective::Spec(s) => s.clone(),
            other => panic!("expected Spec from {fmt:?}, got {other:?}"),
        }
    }

    fn c23_format(fmt: &[u8]) -> ScanDirectives {
        let mut dirs = parse_scanf_format(fmt);
        for dir in dirs.as_mut_slice() {
            if let ScanDirective::Spec(spec) = dir {
                spec.binary_prefix = true;
            }
        }
        dirs
    }

    #[test]
    fn parses_gnu_m_allocation_modifier_on_string_conversions() {
        // GNU `%ms` / `%m[` / `%mc`: the destination is a `char **` and the ABI
        // layer allocates. Core's only job is to record that it was asked for.
        // Checked against live glibc 2.42: sscanf("hello world", "%ms", &p)
        // yields 1 with p == "hello", likewise "%m[a-z]" and "%mc".
        for (fmt, conversion) in [
            (b"%ms".as_slice(), b's'),
            (b"%m[a-z]", b'['),
            (b"%mc", b'c'),
        ] {
            let spec = only_spec(fmt);
            assert!(spec.alloc, "{fmt:?} must set alloc");
            assert_eq!(spec.conversion, conversion, "{fmt:?} conversion");
        }
    }

    #[test]
    fn gnu_m_modifier_sits_between_width_and_length() {
        // Order is load-bearing and was verified against live glibc:
        //   "%4ms" -> 1, "hell"   (width still applies, so m follows the width)
        //   "%mls" -> 1, wide     (m precedes the length modifier)
        //   "%lms" -> 0           (m AFTER the length modifier is not the
        //                          modifier at all — glibc assigns nothing)
        let spec = only_spec(b"%4ms");
        assert!(spec.alloc);
        assert_eq!(spec.width, Some(4));
        assert_eq!(spec.conversion, b's');

        let spec = only_spec(b"%mls");
        assert!(spec.alloc);
        assert!(matches!(spec.length, LengthMod::L));
        assert_eq!(spec.conversion, b's');

        // `%lms` reads `m` as the conversion character, which binds no route,
        // so the directive is rejected outright — matching glibc returning 0.
        assert!(
            parse_scanf_format(b"%lms").is_empty(),
            "%lms must not parse as an allocating directive"
        );
    }

    #[test]
    fn gnu_m_modifier_composes_with_suppression_and_is_off_by_default() {
        let spec = only_spec(b"%*ms");
        assert!(spec.suppress, "%*ms suppresses");
        assert!(spec.alloc, "%*ms still records the m modifier");

        // Regression guard: ordinary directives must not claim allocation.
        for fmt in [b"%s".as_slice(), b"%c", b"%[a-z]", b"%d", b"%ls"] {
            assert!(!only_spec(fmt).alloc, "{fmt:?} must not set alloc",);
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
        let dirs = c23_format(b"%i");
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
    fn test_scan_binary_all_integer_lengths_and_dialects() {
        for (format, expected) in [
            (b"%hhb%n".as_slice(), 251),
            (b"%hb%n", 65531),
            (b"%b%n", u32::MAX as u64 - 4),
            (b"%lb%n", u64::MAX - 4),
            (b"%llb%n", u64::MAX - 4),
            (b"%jb%n", u64::MAX - 4),
            (b"%zb%n", u64::MAX - 4),
            (b"%tb%n", u64::MAX - 4),
        ] {
            // Unlike %i, %b accepts a binary prefix in every standards mode.
            for dirs in [parse_scanf_format(format), c23_format(format)] {
                let result = scan_input(b"-0B101!", &dirs);
                assert_eq!(result.count, 1, "format={format:?}");
                assert_eq!(result.values.len(), 2);
                assert!(matches!(result.values[0], ScanValue::UnsignedInt(v) if v == expected));
                assert!(matches!(result.values[1], ScanValue::CharsConsumed(6)));
                assert_eq!(result.consumed, 6);
            }
        }
        let dirs = parse_scanf_format(b"%llb%n");
        for bits in [64, 65, 600] {
            let input = "1".repeat(bits);
            let result = scan_input(input.as_bytes(), &dirs);
            assert_eq!(result.count, 1);
            assert!(matches!(result.values[0], ScanValue::UnsignedInt(u64::MAX)));
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(n) if n == bits));
        }
    }

    #[test]
    fn test_scan_binary_width_failure_and_suppression() {
        for (input, format, consumed) in [
            (b"0b!".as_slice(), b"%b%n".as_slice(), 2),
            (b"-0B", b"%b%n", 3),
            (b"0b101!", b"%2b%n", 2),
            (b"0b!", b"%*b%n%d", 2),
            (b"2!", b"%b%n", 0),
        ] {
            let result = scan_input(input, &parse_scanf_format(format));
            assert_eq!(result.count, 0, "input={input:?} format={format:?}");
            assert!(result.values.is_empty());
            assert_eq!(result.consumed, consumed);
            assert!(!result.input_failure);
        }
        for (format, value, consumed) in [(b"%1b%n".as_slice(), 0, 1), (b"%3b%n", 1, 3)] {
            let result = scan_input(b"0b101!", &parse_scanf_format(format));
            assert_eq!(result.count, 1);
            assert!(matches!(result.values[0], ScanValue::UnsignedInt(v) if v == value));
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(n) if n == consumed));
        }
        let result = scan_input(b"101 7!", &parse_scanf_format(b"%*b%n%d"));
        assert_eq!(result.count, 1);
        assert_eq!(result.values.len(), 2);
        assert!(matches!(result.values[0], ScanValue::CharsConsumed(3)));
        assert!(matches!(result.values[1], ScanValue::SignedInt(7)));
        assert_eq!(result.consumed, 5);
        let result = scan_input(b"7 -0b!", &parse_scanf_format(b"%d%b%n"));
        assert_eq!(result.count, 1);
        assert_eq!(result.values.len(), 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(7)));
        assert_eq!(result.consumed, 5);
        assert!(!result.input_failure);
        let result = scan_input(b"\t ", &parse_scanf_format(b"%b%n"));
        assert_eq!(result.count, 0);
        assert!(result.values.is_empty());
        assert!(result.input_failure);
    }

    #[test]
    fn test_scan_auto_int_binary_prefix_without_following_digits() {
        // GNU 2.43 consumes an incomplete prefix but performs no assignment;
        // in particular, a following %n must not execute.
        let dirs = c23_format(b"%i%n");
        for input in [b"0b2".as_slice(), b"0b", b"0bx", b"-0B!", b"+0b"] {
            let result = scan_input(input, &dirs);
            assert_eq!(result.count, 0, "input={input:?}");
            assert!(result.values.is_empty(), "input={input:?}");
            let expected = if matches!(input[0], b'-' | b'+') {
                3
            } else {
                2
            };
            assert_eq!(result.consumed, expected, "input={input:?}");
            assert!(!result.input_failure, "input={input:?}");
        }
        let dirs = c23_format(b"%1i%n");
        let result = scan_input(b"0b!", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(0)));
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(1)));
        let dirs = c23_format(b"%i%n");
        let result = scan_input(b"0b0!", &dirs);
        assert_eq!(result.count, 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(0)));
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(3)));
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
    fn test_scan_integer_bare_hex_prefix_is_matching_failure() {
        // GNU 2.43 rejects incomplete prefixes in both explicit and auto-base
        // conversions, without rewinding the consumed sign/prefix.
        for fmt in [b"%i%n".as_slice(), b"%x%n", b"%2i%n", b"%2x%n"] {
            let dirs = parse_scanf_format(fmt);
            for input in [b"0x".as_slice(), b"0xZ", b"0X!"] {
                let result = scan_input(input, &dirs);
                assert_eq!(result.count, 0, "fmt={fmt:?} input={input:?}");
                assert!(result.values.is_empty(), "fmt={fmt:?} input={input:?}");
                assert_eq!(result.consumed, 2);
                assert!(!result.input_failure);
            }
        }
        let dirs = parse_scanf_format(b"%i");
        assert_eq!(scan_input(b"0x1f", &dirs).count, 1);
        for fmt in [b"%1i%n".as_slice(), b"%1x%n"] {
            let dirs = parse_scanf_format(fmt);
            let result = scan_input(b"0x!", &dirs);
            assert_eq!(result.count, 1);
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(1)));
        }
    }

    #[test]
    fn test_scan_incomplete_integer_keeps_prior_assignments_and_stops() {
        for fmt in [b"%d%i%n".as_slice(), b"%d%x%n"] {
            let dirs = parse_scanf_format(fmt);
            let result = scan_input(b"7 -0x!", &dirs);
            assert_eq!(result.count, 1);
            assert_eq!(result.values.len(), 1);
            assert!(matches!(result.values[0], ScanValue::SignedInt(7)));
            assert_eq!(result.consumed, 5);
            assert!(!result.input_failure);
        }
        for fmt in [b"%*i%n%i".as_slice(), b"%*x%n%x"] {
            let dirs = parse_scanf_format(fmt);
            let result = scan_input(b"0x!", &dirs);
            assert_eq!(result.count, 0);
            assert!(result.values.is_empty());
            assert_eq!(result.consumed, 2);
            assert!(!result.input_failure);
        }
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

    // -----------------------------------------------------------------
    // ScanBytes inline/heap boundary.
    //
    // The whole point of `ScanBytes` is that a short token skips the heap. That
    // makes the boundary the one place a bug can hide: an off-by-one in the
    // `<=` would either spill 32-byte tokens to the heap (silently losing the
    // lever, with every test still green) or try to inline 33 bytes into a
    // 32-byte array (a panic, or a truncated token if the length were clamped).
    // Both sides are asserted, and the CONTENTS are checked as well as the
    // storage, so a variant that stores the right bytes in the wrong place and
    // one that stores the wrong bytes both fail.

    #[test]
    fn scan_bytes_inlines_up_to_capacity_and_spills_past_it() {
        for len in [0usize, 1, 2, 31, SCAN_INLINE_CAP] {
            let src: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            let got = ScanBytes::from_slice(&src);
            assert!(
                matches!(got, ScanBytes::Inline { .. }),
                "len {len} must inline (capacity is {SCAN_INLINE_CAP})"
            );
            assert_eq!(got.as_slice(), &src[..], "len {len} round-trip");
        }
        for len in [SCAN_INLINE_CAP + 1, SCAN_INLINE_CAP + 2, 200] {
            let src: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            let got = ScanBytes::from_slice(&src);
            assert!(
                matches!(got, ScanBytes::Heap(_)),
                "len {len} must spill to the heap"
            );
            assert_eq!(got.as_slice(), &src[..], "len {len} round-trip");
        }
    }

    #[test]
    fn scanned_strings_round_trip_across_the_inline_boundary() {
        // Through the real engine, not just the constructor: a token one byte
        // either side of the boundary must scan to exactly the same bytes.
        for len in [
            1usize,
            SCAN_INLINE_CAP - 1,
            SCAN_INLINE_CAP,
            SCAN_INLINE_CAP + 1,
            100,
        ] {
            let token: Vec<u8> = (0..len).map(|i| b'A' + (i % 26) as u8).collect();
            let dirs = parse_scanf_format(b"%s");
            let result = scan_input(&token, &dirs);
            assert_eq!(result.count, 1, "len {len} should scan one token");
            match &result.values[0] {
                ScanValue::String(bytes) => {
                    assert_eq!(bytes.as_slice(), &token[..], "len {len} token bytes")
                }
                other => panic!("len {len}: expected String, got {other:?}"),
            }
        }
    }

    #[test]
    fn scanned_scanset_and_char_round_trip_across_the_inline_boundary() {
        // %[...] and %c share the same storage; both sides of the boundary.
        for len in [SCAN_INLINE_CAP, SCAN_INLINE_CAP + 1] {
            let token: Vec<u8> = std::iter::repeat_n(b'x', len).collect();

            let dirs = parse_scanf_format(b"%[x]");
            let result = scan_input(&token, &dirs);
            assert_eq!(result.count, 1, "scanset len {len}");
            match &result.values[0] {
                ScanValue::String(bytes) => {
                    assert_eq!(bytes.as_slice(), &token[..], "scanset len {len}")
                }
                other => panic!("scanset len {len}: expected String, got {other:?}"),
            }

            let fmt = format!("%{len}c");
            let dirs = parse_scanf_format(fmt.as_bytes());
            let result = scan_input(&token, &dirs);
            assert_eq!(result.count, 1, "%c len {len}");
            match &result.values[0] {
                ScanValue::Char(bytes) => {
                    assert_eq!(bytes.as_slice(), &token[..], "%c len {len}")
                }
                other => panic!("%c len {len}: expected Char, got {other:?}"),
            }
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
    fn test_scan_hex_float_p_without_digits_retains_significand() {
        let dirs = parse_scanf_format(b"%a%n");
        for (input, expected) in [
            (b"0x1.0p".as_slice(), 1.0),
            (b"0x1.0P", 1.0),
            (b"0x.0p", 0.0),
        ] {
            let result = scan_input(input, &dirs);
            assert_eq!(result.count, 1);
            assert!(matches!(result.values[0], ScanValue::Float(v) if v == expected));
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(n) if n == input.len()));
            assert_eq!(result.consumed, input.len());
        }
    }

    #[test]
    fn test_scan_hex_float_p_sign_without_digits_retains_significand() {
        let dirs = parse_scanf_format(b"%a%n");
        for (input, expected) in [
            (b"0x1.0p-".as_slice(), 1.0),
            (b"0x1.0p+", 1.0),
            (b"0x.0p-", 0.0),
        ] {
            let result = scan_input(input, &dirs);
            assert_eq!(result.count, 1);
            assert!(matches!(result.values[0], ScanValue::Float(v) if v == expected));
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(n) if n == input.len()));
            assert_eq!(result.consumed, input.len());
        }
    }

    #[test]
    fn test_scan_hex_float_p_sign_leaves_following_text() {
        let dirs = parse_scanf_format(b"%a%n%s");
        let result = scan_input(b"0x2p-foo", &dirs);
        assert_eq!(result.count, 2);
        assert!(matches!(result.values[0], ScanValue::Float(v) if v == 2.0));
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(5)));
        assert!(matches!(&result.values[2], ScanValue::String(s) if s.as_slice() == b"foo"));
    }

    #[test]
    fn test_scan_incomplete_exponent_widths_counts_and_leftovers() {
        // Exact GNU sscanf/__isoc99_sscanf/__isoc23_sscanf probes agree:
        // consume the exponent prefix while assigning the mantissa.
        for (input, format, expected, consumed, tail) in [
            (
                b"27EeA7".as_slice(),
                b"%lf%n%c".as_slice(),
                27.0_f64,
                3,
                b'e',
            ),
            (b"+9.e!", b"%lf%n%c", 9.0, 4, b'!'),
            (b"-0e+!", b"%lf%n%c", -0.0, 4, b'!'),
            (b".5E-!", b"%lf%n%c", 0.5, 4, b'!'),
            (b"1e+7!", b"%1lf%n%c", 1.0, 1, b'e'),
            (b"1e+7!", b"%2lf%n%c", 1.0, 2, b'+'),
            (b"1e+7!", b"%3lf%n%c", 1.0, 3, b'7'),
            (b"0x1p+7!", b"%4lf%n%c", 1.0, 4, b'+'),
            (b"0x1p+7!", b"%5lf%n%c", 1.0, 5, b'7'),
            (b"1e+2!", b"%lf%n%c", 100.0, 4, b'!'),
        ] {
            let dirs = parse_scanf_format(format);
            let result = scan_input(input, &dirs);
            assert_eq!(result.count, 2, "input={input:?}, format={format:?}");
            assert!(
                matches!(result.values[0], ScanValue::Float(v) if v.to_bits() == expected.to_bits())
            );
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(n) if n == consumed));
            assert!(
                matches!(&result.values[2], ScanValue::Char(bytes) if bytes.as_slice() == [tail])
            );
            assert_eq!(result.consumed, consumed + 1);
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
    fn test_scan_pointer_hexadecimal_and_nil() {
        for (input, format, value, consumed) in [
            (b"123!".as_slice(), b"%p%n".as_slice(), 0x123, 3),
            (b"0!", b"%p%n", 0, 1),
            (b"+0Xabc!", b"%p%n", 0xabc, 6),
            (b"-1!", b"%p%n", usize::MAX, 2),
            (b"ABCdef!", b"%p%n", 0xabcdef, 6),
            (b"(nil)!", b"%p%n", 0, 5),
            (b"(NIL)!", b"%p%n", 0, 5),
            (b"(nIl)!", b"%5p%n", 0, 5),
            (b"0x1!", b"%1p%n", 0, 1),
            (b"0x1!", b"%3p%n", 1, 3),
            (b" \t123!", b"%p%n", 0x123, 5),
        ] {
            let result = scan_input(input, &parse_scanf_format(format));
            assert_eq!(result.count, 1, "input={input:?} format={format:?}");
            assert_eq!(result.values.len(), 2);
            assert!(matches!(result.values[0], ScanValue::Pointer(v) if v == value));
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(n) if n == consumed));
            assert_eq!(result.consumed, consumed);
            assert!(!result.input_failure);
        }
        // The default `%x` destination is 32-bit; `%p` must retain all 64
        // bits rather than applying that default integer narrowing.
        #[cfg(target_pointer_width = "64")]
        for (input, value) in [
            (b"0xffffffffffffffff!".as_slice(), usize::MAX),
            (b"8000000000000001!", 0x8000_0000_0000_0001),
        ] {
            let result = scan_input(input, &parse_scanf_format(b"%p%n"));
            assert_eq!(result.count, 1);
            assert!(matches!(result.values[0], ScanValue::Pointer(v) if v == value));
            assert_eq!(result.consumed, input.len() - 1);
        }
    }

    #[test]
    fn test_scan_pointer_failure_width_and_suppression() {
        for (input, format, consumed) in [
            (b"0x!".as_slice(), b"%p%n".as_slice(), 2),
            (b"0x", b"%p%n", 2),
            (b"0x1!", b"%2p%n", 2),
            (b"(ni!", b"%p%n", 3),
            (b"(nil", b"%p%n", 4),
            (b"(", b"%p%n", 1),
            (b"(nix)!", b"%p%n", 3),
            (b"(nilX", b"%p%n", 4),
            (b"+(nil)!", b"%p%n", 1),
            (b"(nil)!", b"%3p%n", 0),
            (b"(nil)!", b"%4p%n", 0),
            (b"!", b"%p%n", 0),
            (b"(nix)!", b"%*p%n%d", 3),
        ] {
            let result = scan_input(input, &parse_scanf_format(format));
            assert_eq!(result.count, 0, "input={input:?} format={format:?}");
            assert!(result.values.is_empty());
            assert_eq!(result.consumed, consumed);
            assert!(!result.input_failure);
        }
        for input in [b"".as_slice(), b" \t"] {
            let result = scan_input(input, &parse_scanf_format(b"%p%n"));
            assert_eq!(result.count, 0);
            assert!(result.values.is_empty());
            assert!(result.input_failure);
        }
        for input in [b"123 7!".as_slice(), b"(NiL) 7!"] {
            let result = scan_input(input, &parse_scanf_format(b"%*p%n%d"));
            assert_eq!(result.count, 1);
            assert_eq!(result.values.len(), 2);
            assert!(matches!(result.values[1], ScanValue::SignedInt(7)));
            assert_eq!(result.consumed, input.len() - 1);
        }
        let result = scan_input(b"7 (nix)!", &parse_scanf_format(b"%d%p%n"));
        assert_eq!(result.count, 1);
        assert_eq!(result.values.len(), 1);
        assert!(matches!(result.values[0], ScanValue::SignedInt(7)));
        assert_eq!(result.consumed, 5);
        assert!(!result.input_failure);
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
        // Only C23 enables the binary prefix. GNU 2.43 treats a field ending
        // inside that prefix as a consuming matching failure.
        for (format, legacy_n, c23_n, c23_value) in [
            (b"%i%n".as_slice(), 1, 5, Some(5)),
            (b"%1i%n", 1, 1, Some(0)),
            (b"%2i%n", 1, 2, None),
            (b"%3i%n", 1, 3, Some(1)),
        ] {
            for (dirs, consumed, value) in [
                (parse_scanf_format(format), legacy_n, Some(0)),
                (c23_format(format), c23_n, c23_value),
            ] {
                let result = scan_input(b"0b101!", &dirs);
                if let Some(value) = value {
                    assert_eq!(result.count, 1);
                    assert!(matches!(result.values[0], ScanValue::SignedInt(v) if v == value));
                    assert!(
                        matches!(result.values[1], ScanValue::CharsConsumed(n) if n == consumed)
                    );
                } else {
                    assert_eq!(result.count, 0);
                    assert!(result.values.is_empty());
                }
                assert_eq!(result.consumed, consumed);
                assert!(!result.input_failure);
            }
        }
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

#[cfg(test)]
mod wide_scan_tests {
    use super::*;

    fn scan(format: &str, input: &str) -> ScanResult {
        let directives = parse_scanf_format_wide(format.as_bytes());
        scan_input_wide(input.as_bytes(), &directives)
    }

    #[test]
    fn writer_error_preserves_prior_assignment_and_stops_before_later_directives() {
        let input = "7 é€X 9";
        let directives = parse_scanf_format_wide(b"%d %s %d%n");
        let mut integer = -1;
        let mut text = Vec::new();
        let mut reached = Vec::new();
        let result = scan_input_wide_with(input.as_bytes(), &directives, |spec, value, context| {
            reached.push(context.directive_index);
            match value.expect("both reached conversions matched input") {
                ScanValue::SignedInt(n) => integer = *n,
                ScanValue::String(bytes) => {
                    assert_eq!(spec.conversion, b's');
                    assert_eq!(context.token_start, 2);
                    assert_eq!(context.token_end, "7 é€X".len());
                    // A Latin-1 destination can accept é, but not the next €.
                    // Its partial output survives; the failed character is
                    // consumed and neither the later integer nor %n is reached.
                    assert_eq!(bytes.as_slice(), "é€X".as_bytes());
                    text.push(0xe9);
                    return Err(ScanWriteError {
                        consumed: "7 é€".len(),
                        input_failure: false,
                    });
                }
                other => panic!("a later conversion ran: {other:?}"),
            }
            Ok(())
        });
        assert_eq!(integer, 7);
        assert_eq!(text, [0xe9]);
        assert_eq!(reached, [0, 2]);
        assert_eq!(result.count, 1);
        assert_eq!(result.consumed, "7 é€".len());
        assert!(!result.input_failure);
        assert!(result.values.is_empty(), "a sink must not collect outputs");
    }

    #[test]
    fn writer_error_distinguishes_character_input_failure_from_string_failure() {
        for (format, input_failure) in [("%2c%n", true), ("%2s%n", false)] {
            let directives = parse_scanf_format_wide(format.as_bytes());
            let mut calls = 0;
            let result =
                scan_input_wide_with("é€X".as_bytes(), &directives, |_, value, context| {
                    calls += 1;
                    assert!(value.is_some());
                    assert_eq!(context.token_end, "é€".len());
                    Err(ScanWriteError {
                        consumed: context.token_end,
                        input_failure,
                    })
                });
            assert_eq!(calls, 1, "trailing %n must remain untouched");
            assert_eq!(result.count, 0);
            assert_eq!(result.consumed, "é€".len());
            assert_eq!(result.input_failure, input_failure);
        }
    }

    #[test]
    fn suppressed_wide_text_bypasses_writer_and_counts_characters() {
        for format in ["%*s%n", "%*3c%n", "%*[^ ]%n", "%*ms%n", "%*m[^ ]%n"] {
            let directives = parse_scanf_format_wide(format.as_bytes());
            let mut calls = 0;
            let result =
                scan_input_wide_with("é€X".as_bytes(), &directives, |spec, value, _| {
                    calls += 1;
                    assert!(spec.stores_count(), "suppressed text reached the writer");
                    assert!(matches!(value, Some(ScanValue::CharsConsumed(3))));
                    Ok(())
                });
            assert_eq!(calls, 1, "{format}");
            assert_eq!(result.count, 0);
            assert_eq!(result.consumed, "é€X".len());
            assert!(!result.input_failure);
        }
    }

    #[test]
    fn reached_failed_allocation_notifies_only_its_destination() {
        for format in ["%n%ms%d", "%n%m[^ ]%d", "%n%mc%d"] {
            let directives = parse_scanf_format_wide(format.as_bytes());
            let mut reached = Vec::new();
            let result = scan_input_wide_with(b"", &directives, |spec, value, context| {
                reached.push(context.directive_index);
                if context.directive_index == 0 {
                    assert!(matches!(value, Some(ScanValue::CharsConsumed(0))));
                } else {
                    assert!(spec.alloc);
                    assert!(value.is_none());
                    assert_eq!((context.token_start, context.token_end), (0, 0));
                }
                Ok(())
            });
            assert_eq!(reached, [0, 1], "{format}");
            assert_eq!(result.count, 0);
            assert!(result.input_failure);
            assert!(result.failed_alloc);
        }
        let directives = parse_scanf_format_wide(b"%d%ms");
        let result = scan_input_wide_with(b"X", &directives, |_, _, _| {
            panic!("an unreached allocation destination must not be touched")
        });
        assert!(!result.failed_alloc);
    }

    #[test]
    fn writer_error_offset_is_bounded_and_never_splits_a_character() {
        let directives = parse_scanf_format_wide(b"%s");
        let input = " é€X";
        for (requested, expected) in [(0, 1), (usize::MAX, input.len()), (2, 1), (4, 3)] {
            let result = scan_input_wide_with(input.as_bytes(), &directives, |_, _, context| {
                assert_eq!(context.token_start, 1);
                Err(ScanWriteError {
                    consumed: requested,
                    input_failure: false,
                })
            });
            assert_eq!(result.consumed, expected);
            assert!(input.is_char_boundary(result.consumed));
        }
    }

    #[test]
    fn wide_n_counts_literals_suppression_whitespace_and_multibyte_scalars() {
        let input = "é€😀\u{2003}X";
        let result = scan("é%n%*2c%n\u{2003}%1[^ ]%n", input);
        assert_eq!(result.count, 1);
        assert_eq!(result.consumed, input.len());
        assert!(matches!(result.values[0], ScanValue::CharsConsumed(1)));
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(3)));
        assert!(matches!(&result.values[2], ScanValue::String(s) if s == b"X"));
        assert!(matches!(result.values[3], ScanValue::CharsConsumed(5)));
    }

    #[test]
    fn wide_scanset_width_and_ranges_consume_complete_scalars() {
        for (format, input, matched) in [
            ("%1[^ ]%n", "éX", "é"),
            ("%1[é]%n", "éX", "é"),
            ("%1[à-ÿ]%n", "éX", "é"),
            ("%1[α-ω]%n", "βX", "β"),
            ("%1[😀-🙏]%n", "😃X", "😃"),
            ("%1[^😀]%n", "€😀", "€"),
        ] {
            let result = scan(format, input);
            assert_eq!(result.count, 1, "{format}: {input}");
            assert_eq!(result.consumed, matched.len());
            assert!(
                matches!(&result.values[0], ScanValue::String(s) if s.as_slice() == matched.as_bytes())
            );
            assert!(matches!(result.values[1], ScanValue::CharsConsumed(1)));
        }
    }

    #[test]
    fn wide_scanset_membership_does_not_match_a_shared_utf8_prefix() {
        let result = scan("%[é]%n", "ê");
        assert_eq!((result.count, result.consumed), (0, 0));
        assert!(result.values.is_empty());
        let result = scan("%[é]%n", "éê");
        assert_eq!((result.count, result.consumed), (1, "é".len()));
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(1)));

        let result = scan("%[ω-α]%n", "ω-αβ");
        assert_eq!(result.consumed, "ω-α".len());
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(3)));
        let result = scan("%[]α]%n", "]αX");
        assert_eq!(result.consumed, "]α".len());
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(2)));
    }

    #[test]
    fn wide_literal_mismatch_leaves_the_entire_character_unread() {
        let result = scan("é%n", "ê");
        assert_eq!((result.count, result.consumed), (0, 0));
        assert!(result.values.is_empty());
        assert!(!result.input_failure);
        let result = scan("😀%n", "😃");
        assert_eq!(result.consumed, 0);
        let result = scan("\u{2003}é%n", " \t\u{3000}é");
        assert!(matches!(result.values[0], ScanValue::CharsConsumed(4)));
    }

    #[test]
    fn wide_positional_indices_are_distinct_from_field_widths() {
        let directives = parse_scanf_format_wide(b"%2$3ls %1$d %3$n %4$*ms");
        let specs: Vec<_> = directives
            .iter()
            .filter_map(|directive| match directive {
                ScanDirective::Spec(spec) => Some(spec),
                _ => None,
            })
            .collect();
        let indices: Vec<_> = specs
            .iter()
            .map(|spec| spec.argument_index.unwrap().get())
            .collect();
        assert_eq!(indices, [2, 1, 3, 4]);
        assert_eq!(specs[0].width, Some(3));
        assert_eq!(specs[0].length, LengthMod::L);
        assert!(specs.iter().all(|spec| spec.wide_input));
        assert!(specs[3].suppress && specs[3].alloc);

        let directives = parse_scanf_format_wide(b"%23s");
        assert!(
            matches!(&directives[0], ScanDirective::Spec(spec) if spec.width == Some(23) && spec.argument_index.is_none())
        );
        assert!(
            parse_scanf_format(b"%2$s").is_empty(),
            "narrow positional support is unchanged"
        );
        for malformed in [
            b"%0$s".as_slice(),
            b"%4294967296$s",
            b"%999999999999999999999999999999999999999$s",
        ] {
            let directives = parse_scanf_format_wide(malformed);
            assert!(matches!(directives[0], ScanDirective::Malformed));
        }
    }

    #[test]
    fn wide_failed_conversion_consumes_skipped_whitespace() {
        for (input, exhausted) in [("  X", false), ("  ", true), ("\u{2003}X", false)] {
            let result = scan("%d", input);
            assert_eq!(result.count, 0);
            assert_eq!(result.consumed, input.trim_end_matches('X').len());
            assert_eq!(result.input_failure, exhausted);
        }
        let result = scan("%s%n%d", "é X");
        assert_eq!(result.count, 1);
        assert_eq!(result.consumed, "é ".len());
        assert!(matches!(result.values[1], ScanValue::CharsConsumed(1)));
        assert!(!result.input_failure);
        let result = scan("%d%d", "7 ");
        assert_eq!(result.count, 1);
        assert_eq!(result.consumed, 2);
        assert!(
            result.input_failure,
            "the stream adapter needs the failed read after an assignment"
        );
    }
}

#[cfg(test)]
mod wide_stream_scan_tests {
    use super::*;

    struct Trace {
        summary: WideScanSummary,
        unread: Vec<u32>,
        requests: Vec<WideScanReadPurpose>,
        texts: Vec<Vec<u32>>,
        values: Vec<ScanValue>,
        ends: usize,
        aborts: usize,
    }

    fn run_locale<S>(
        format: &str,
        input: &str,
        terminal: Option<WideScanInput>,
        radix: u32,
        is_space: &S,
    ) -> Trace
    where
        S: Fn(u32) -> bool,
    {
        let directives = parse_scanf_format_wide_with_space(format.as_bytes(), is_space);
        let mut session = WideScanSession::new(&directives, radix);
        let mut source = input.chars();
        let mut texts: Vec<Vec<u32>> = Vec::new();
        let mut values = Vec::new();
        let mut ends = 0;
        let mut aborts = 0;
        let mut writer = |_: &ScanSpec, event, _: WideScanContext| {
            match event {
                WideScanEvent::BeginText => texts.push(Vec::new()),
                WideScanEvent::Character(character) => texts.last_mut().unwrap().push(character),
                WideScanEvent::EndText => ends += 1,
                WideScanEvent::AbortText => aborts += 1,
                WideScanEvent::Value(value) => values.push(value),
            }
            Ok(())
        };
        let mut requests = Vec::new();
        let mut supplied = None;
        let summary = loop {
            match session.resume(supplied, &mut writer, is_space) {
                WideScanProgress::Complete(summary) => break summary,
                WideScanProgress::NeedInput(purpose) => {
                    requests.push(purpose);
                    supplied = Some(source.next().map_or_else(
                        || terminal.expect("the completed directive must not demand another read"),
                        |character| WideScanInput::Character(character as u32),
                    ));
                }
            }
        };
        Trace {
            summary,
            unread: session.unread().collect(),
            requests,
            texts,
            values,
            ends,
            aborts,
        }
    }

    fn run(format: &str, input: &str, terminal: Option<WideScanInput>) -> Trace {
        run_locale(
            format,
            input,
            terminal,
            u32::from(b'.'),
            &crate::string::wchar::iswspace,
        )
    }

    #[test]
    fn unbounded_text_and_allocated_scanset_cross_the_old_input_limit() {
        let input = format!("{} {}!", "é".repeat(20_000), "a".repeat(6_000));
        let trace = run("%s%n %m[a-z]%n", &input, None);
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 2,
                consumed: 26_001,
                input_failure: false
            }
        );
        assert_eq!(trace.texts[0], vec![0xe9; 20_000]);
        assert_eq!(trace.texts[1], vec![u32::from(b'a'); 6_000]);
        assert_eq!((trace.ends, trace.aborts), (2, 0));
        assert!(matches!(
            trace.values.as_slice(),
            [
                ScanValue::CharsConsumed(20_000),
                ScanValue::CharsConsumed(26_001)
            ]
        ));
        assert_eq!(trace.unread, [u32::from(b'!')]);
        assert_eq!(trace.requests.len(), 26_002);
    }

    #[test]
    fn bounded_text_literals_and_counts_never_request_a_suffix() {
        for format in ["%1c%n", "%1lc%n", "%1s%n", "%1[é]%n", "%1m[^X]%n"] {
            let trace = run(format, "é", None);
            assert_eq!(
                trace.summary,
                WideScanSummary {
                    count: 1,
                    consumed: 1,
                    input_failure: false
                },
                "{format}"
            );
            assert_eq!(trace.requests.len(), 1);
            assert_eq!(trace.texts, [vec![0xe9]]);
            assert!(matches!(
                trace.values.as_slice(),
                [ScanValue::CharsConsumed(1)]
            ));
        }
        let trace = run("%n€%n", "€", None);
        assert_eq!(trace.requests.len(), 1);
        assert!(matches!(
            trace.values.as_slice(),
            [ScanValue::CharsConsumed(0), ScanValue::CharsConsumed(1)]
        ));
        assert_eq!(trace.summary.count, 0);
        let trace = run("%n", "", None);
        assert!(trace.requests.is_empty());
        assert!(matches!(
            trace.values.as_slice(),
            [ScanValue::CharsConsumed(0)]
        ));
    }

    #[test]
    fn destination_failure_stops_before_any_additional_input_or_assignment() {
        let directives = parse_scanf_format_wide(b"%d %ms%n%d");
        let mut session = WideScanSession::new(&directives, u32::from(b'.'));
        let mut input = "7 é€".chars();
        let mut integer = None;
        let mut partial = Vec::new();
        let mut begins = 0;
        let mut writer = |_: &ScanSpec, event, context: WideScanContext| {
            match event {
                WideScanEvent::Value(ScanValue::SignedInt(value)) => {
                    assert!(
                        integer.replace(value).is_none(),
                        "an assignment was replayed"
                    );
                }
                WideScanEvent::BeginText => begins += 1,
                WideScanEvent::Character(0xe9) => partial.push(0xe9u8),
                WideScanEvent::Character(0x20ac) => {
                    assert_eq!(
                        (context.directive_index, context.consumed, context.matched),
                        (2, 4, 2)
                    );
                    return Err(WideScanWriteError {
                        input_failure: false,
                    });
                }
                event => panic!("an event ran after the destination error: {event:?}"),
            }
            Ok(())
        };
        let mut supplied = None;
        let summary = loop {
            match session.resume(supplied, &mut writer, &crate::string::wchar::iswspace) {
                WideScanProgress::Complete(summary) => break summary,
                WideScanProgress::NeedInput(_) => {
                    supplied = Some(WideScanInput::Character(
                        input
                            .next()
                            .expect("encoding failure must return before another read")
                            as u32,
                    ));
                }
            }
        };
        assert_eq!(
            summary,
            WideScanSummary {
                count: 1,
                consumed: 4,
                input_failure: false
            }
        );
        assert_eq!((integer, begins, partial), (Some(7), 1, vec![0xe9]));
        assert!(session.unread().next().is_none());
    }

    #[test]
    fn failed_character_destination_remains_an_input_failure() {
        let directives = parse_scanf_format_wide(b"%2c%n");
        let mut session = WideScanSession::new(&directives, u32::from(b'.'));
        let mut calls = 0;
        let mut writer = |_: &ScanSpec, event, _: WideScanContext| {
            calls += 1;
            match event {
                WideScanEvent::BeginText | WideScanEvent::Character(0xe9) => Ok(()),
                WideScanEvent::Character(0x20ac) => Err(WideScanWriteError {
                    input_failure: true,
                }),
                _ => panic!("failure must not emit EndText, AbortText, or %n"),
            }
        };
        assert!(matches!(
            session.resume(None, &mut writer, &|_| false),
            WideScanProgress::NeedInput(_)
        ));
        assert!(matches!(
            session.resume(Some(WideScanInput::Character(0xe9)), &mut writer, &|_| {
                false
            }),
            WideScanProgress::NeedInput(_)
        ));
        assert_eq!(
            session.resume(Some(WideScanInput::Character(0x20ac)), &mut writer, &|_| {
                false
            }),
            WideScanProgress::Complete(WideScanSummary {
                count: 0,
                consumed: 2,
                input_failure: true
            })
        );
        assert_eq!(calls, 3);
    }

    #[test]
    fn source_end_aborts_short_character_fields_and_finishes_strings() {
        for terminal in [WideScanInput::Eof, WideScanInput::Error] {
            for (format, characters) in [
                ("%3c%n", true),
                ("%3lc%n", true),
                ("%3mc%n", true),
                ("%3mlc%n", true),
                ("%s%n", false),
                ("%[A-Z]%n", false),
            ] {
                for input in ["A", "AB"] {
                    let trace = run(format, input, Some(terminal));
                    assert_eq!(
                        trace.summary,
                        WideScanSummary {
                            count: i32::from(!characters),
                            consumed: input.len(),
                            input_failure: characters
                        },
                        "{format}/{input}/{terminal:?}"
                    );
                    assert_eq!(
                        (trace.ends, trace.aborts),
                        (usize::from(!characters), usize::from(characters))
                    );
                    if characters {
                        assert!(trace.values.is_empty());
                    } else {
                        assert!(
                            matches!(trace.values[0], ScanValue::CharsConsumed(n) if n == input.len())
                        );
                    }
                }
                if characters {
                    let trace = run(format, "ABC", Some(terminal));
                    assert_eq!(
                        trace.summary,
                        WideScanSummary {
                            count: 1,
                            consumed: 3,
                            input_failure: false
                        }
                    );
                    assert_eq!((trace.ends, trace.aborts), (1, 0));
                    assert_eq!(trace.requests.len(), 3);
                    assert!(matches!(
                        trace.values.as_slice(),
                        [ScanValue::CharsConsumed(3)]
                    ));
                }
            }
            let trace = run("%*3c%n", "A", Some(terminal));
            assert_eq!(trace.summary.count, 0);
            assert!(trace.summary.input_failure);
            assert!(trace.texts.is_empty());
            assert!(trace.values.is_empty());
            assert_eq!(trace.requests.len(), 2);
        }
    }

    #[test]
    fn only_reached_empty_allocations_are_aborted() {
        for terminal in [WideScanInput::Eof, WideScanInput::Error] {
            for format in ["%ms%n", "%mc%n", "%m[A-Z]%n"] {
                let trace = run(format, "", Some(terminal));
                assert_eq!(
                    trace.summary,
                    WideScanSummary {
                        count: 0,
                        consumed: 0,
                        input_failure: true
                    }
                );
                assert_eq!((trace.texts.len(), trace.ends, trace.aborts), (1, 0, 1));
                assert!(trace.values.is_empty());
            }
        }
        let trace = run("X%ms", "Y", None);
        assert!(trace.texts.is_empty());
        assert_eq!(trace.unread, [u32::from(b'Y')]);
        assert!(!trace.summary.input_failure);
    }

    #[test]
    fn suppressed_long_text_emits_no_destination_events() {
        let trace = run("%*20000c%n", &"€".repeat(20_000), None);
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 0,
                consumed: 20_000,
                input_failure: false
            }
        );
        assert!(trace.texts.is_empty());
        assert_eq!((trace.ends, trace.aborts), (0, 0));
        assert!(matches!(
            trace.values.as_slice(),
            [ScanValue::CharsConsumed(20_000)]
        ));
        assert_eq!(trace.requests.len(), 20_000);
    }

    #[test]
    fn format_whitespace_read_errors_still_reach_counts() {
        let trace = run("%n %n", " \t", Some(WideScanInput::Error));
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 0,
                consumed: 2,
                input_failure: false
            }
        );
        assert!(
            trace
                .requests
                .iter()
                .all(|purpose| *purpose == WideScanReadPurpose::FormatWhitespace)
        );
        assert!(matches!(
            trace.values.as_slice(),
            [ScanValue::CharsConsumed(0), ScanValue::CharsConsumed(2)]
        ));
        let trace = run("%d", " \t", Some(WideScanInput::Error));
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 0,
                consumed: 2,
                input_failure: true
            }
        );
        assert!(
            trace
                .requests
                .iter()
                .all(|purpose| *purpose == WideScanReadPurpose::Conversion)
        );
    }

    #[test]
    fn locale_predicate_controls_format_and_input_whitespace() {
        let c_space = |wc| u8::try_from(wc).is_ok_and(is_c_space);
        let trace = run_locale("\u{2003}%n%1c", " \tX", None, u32::from(b'.'), &c_space);
        assert_eq!(trace.summary.consumed, 0);
        assert_eq!(trace.unread, [u32::from(b' ')]);
        let trace = run("\u{2003}%n%1c", " \tX", None);
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 1,
                consumed: 3,
                input_failure: false
            }
        );
        assert!(matches!(
            trace.values.as_slice(),
            [ScanValue::CharsConsumed(2)]
        ));
        let trace = run_locale("%1s%n", "\u{2003}", None, u32::from(b'.'), &c_space);
        assert_eq!(trace.texts, [vec![0x2003]]);
        let trace = run("%1s%n", "\u{2003}X", None);
        assert_eq!(trace.texts, [vec![u32::from(b'X')]]);
        assert!(matches!(
            trace.values.as_slice(),
            [ScanValue::CharsConsumed(2)]
        ));
    }

    #[test]
    fn scalar_scansets_and_literal_mismatches_keep_whole_characters() {
        let trace = run("%2[α-ω]%n", "βω", None);
        assert_eq!(trace.texts, [vec![0x3b2, 0x3c9]]);
        assert!(matches!(
            trace.values.as_slice(),
            [ScanValue::CharsConsumed(2)]
        ));
        let trace = run("%[é]%n", "ê", None);
        assert_eq!(trace.summary.consumed, 0);
        assert_eq!(trace.unread, [0xea]);
        assert_eq!((trace.ends, trace.aborts), (0, 1));
        let trace = run("😀%n", "😃", None);
        assert_eq!(trace.summary.consumed, 0);
        assert_eq!(trace.unread, [0x1f603]);
    }

    #[test]
    fn numeric_fields_have_their_own_lookahead_rules() {
        for (format, input) in [
            ("%1lf%n", "1"),
            ("%2lf%n", "1."),
            ("%3lf%n", "1e+"),
            ("%3lf%n", "inf"),
            ("%3lf%n", "nan"),
            ("%lf%n", "infinity"),
            ("%lf%n", "nan()"),
            ("%p%n", "(nil)"),
        ] {
            let trace = run(format, input, None);
            assert_eq!(trace.summary.count, 1, "{format}/{input}");
            assert_eq!(trace.requests.len(), input.len());
            assert!(
                matches!(trace.values.last(), Some(ScanValue::CharsConsumed(n)) if *n == input.len())
            );
        }
        for input in ["1X", "1"] {
            let trace = run("%1d%n", input, Some(WideScanInput::Eof));
            assert_eq!(trace.requests.len(), 2, "integer width requires lookahead");
            assert!(matches!(
                trace.values.as_slice(),
                [ScanValue::SignedInt(1), ScanValue::CharsConsumed(1)]
            ));
        }
    }

    #[test]
    fn locale_radix_counts_scalars_and_rewinds_its_original_character() {
        let trace = run_locale(
            "%3lf%n%1c",
            "1٫5X",
            None,
            0x66b,
            &crate::string::wchar::iswspace,
        );
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 2,
                consumed: 4,
                input_failure: false
            }
        );
        assert!(
            matches!(trace.values.as_slice(), [ScanValue::Float(value), ScanValue::CharsConsumed(3)] if *value == 1.5)
        );
        assert_eq!(trace.texts, [vec![u32::from(b'X')]]);
        let trace = run_locale(
            "%lf%n%1c",
            "1.5",
            None,
            u32::from(b','),
            &crate::string::wchar::iswspace,
        );
        assert!(
            matches!(trace.values.as_slice(), [ScanValue::Float(value), ScanValue::CharsConsumed(1)] if *value == 1.0)
        );
        assert_eq!(trace.texts, [vec![u32::from(b'.')]]);
        assert_eq!(trace.requests.len(), 2);
        let trace = run_locale("%lf", "٫X", None, 0x66b, &crate::string::wchar::iswspace);
        assert_eq!(trace.summary.consumed, 0);
        assert_eq!(trace.unread, [0x66b, u32::from(b'X')]);
    }

    #[test]
    fn numerical_rollback_is_replayed_before_existing_lookahead() {
        let trace = run("%lf%2c%n", "infiX", None);
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 2,
                consumed: 5,
                input_failure: false
            }
        );
        assert!(
            matches!(trace.values.as_slice(), [ScanValue::Float(value), ScanValue::CharsConsumed(5)] if value.is_infinite() && value.is_sign_positive())
        );
        assert_eq!(trace.texts, [vec![u32::from(b'i'), u32::from(b'X')]]);
        assert_eq!(trace.requests.len(), 5);
        assert!(trace.unread.is_empty());
        let trace = run("%i%n", "0xZ", None);
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 0,
                consumed: 2,
                input_failure: false
            }
        );
        assert!(trace.values.is_empty());
        assert_eq!(trace.unread, [u32::from(b'Z')]);
    }

    #[test]
    fn long_numeric_tokens_keep_the_existing_saturation_and_count() {
        let input = format!("{}Z", "9".repeat(7_000));
        let trace = run("%llu%n", &input, None);
        assert_eq!(
            trace.summary,
            WideScanSummary {
                count: 1,
                consumed: 7_000,
                input_failure: false
            }
        );
        assert!(matches!(
            trace.values.as_slice(),
            [
                ScanValue::UnsignedInt(u64::MAX),
                ScanValue::CharsConsumed(7_000)
            ]
        ));
        assert_eq!(trace.unread, [u32::from(b'Z')]);
    }

    #[test]
    fn stream_character_events_retain_gnu_extended_wide_values() {
        let directives = parse_scanf_format_wide(b"%lc%n");
        let mut session = WideScanSession::new(&directives, u32::from(b'.'));
        let mut characters = Vec::new();
        let mut counts = Vec::new();
        let mut writer = |_: &ScanSpec, event, _: WideScanContext| {
            match event {
                WideScanEvent::Character(wc) => characters.push(wc),
                WideScanEvent::Value(ScanValue::CharsConsumed(n)) => counts.push(n),
                WideScanEvent::BeginText | WideScanEvent::EndText => {}
                _ => panic!("unexpected extended-character event"),
            }
            Ok(())
        };
        assert!(matches!(
            session.resume(None, &mut writer, &|_| false),
            WideScanProgress::NeedInput(_)
        ));
        assert_eq!(
            session.resume(
                Some(WideScanInput::Character(0x20_0000)),
                &mut writer,
                &|_| false
            ),
            WideScanProgress::Complete(WideScanSummary {
                count: 1,
                consumed: 1,
                input_failure: false
            })
        );
        assert_eq!(characters, [0x20_0000]);
        assert_eq!(counts, [1]);
    }

    #[test]
    fn initial_allocation_failure_preserves_prior_assignments_without_reading() {
        let directives = parse_scanf_format_wide(b"%d%1ms%100000000mc%n");
        let mut session = WideScanSession::new(&directives, u32::from(b'.'));
        let mut input = "7A".chars();
        let mut integer = None;
        let mut text = Vec::new();
        let mut completed_text = 0;
        let mut allocation_attempts = 0;
        let mut writer = |spec: &ScanSpec, event, context: WideScanContext| {
            match event {
                WideScanEvent::Value(ScanValue::SignedInt(value)) => {
                    assert!(integer.replace(value).is_none());
                }
                WideScanEvent::BeginText if spec.conversion == b's' => {}
                WideScanEvent::Character(character) => text.push(character),
                WideScanEvent::EndText => completed_text += 1,
                WideScanEvent::BeginText => {
                    assert!(spec.alloc && spec.writes_char_buffer());
                    assert_eq!(
                        (context.directive_index, context.consumed, context.matched),
                        (2, 2, 0)
                    );
                    allocation_attempts += 1;
                    return Err(WideScanWriteError {
                        input_failure: true,
                    });
                }
                event => panic!("an event followed the initial allocation failure: {event:?}"),
            }
            Ok(())
        };
        let mut supplied = None;
        let summary = loop {
            match session.resume(supplied, &mut writer, &crate::string::wchar::iswspace) {
                WideScanProgress::Complete(summary) => break summary,
                WideScanProgress::NeedInput(_) => {
                    supplied = Some(WideScanInput::Character(
                        input
                            .next()
                            .expect("initial allocation failure must precede another read")
                            as u32,
                    ));
                }
            }
        };
        assert_eq!(
            summary,
            WideScanSummary {
                count: 2,
                consumed: 2,
                input_failure: true
            }
        );
        assert_eq!(integer, Some(7));
        assert_eq!(text, [u32::from(b'A')]);
        assert_eq!((completed_text, allocation_attempts), (1, 1));
        assert!(session.unread().next().is_none());
    }
}
