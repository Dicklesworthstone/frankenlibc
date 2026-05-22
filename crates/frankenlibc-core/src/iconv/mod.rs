//! Character set conversion.
//!
//! Implements `<iconv.h>` functions for converting between character encodings.

use crate::errno;

/// Core iconv error code: output buffer has insufficient capacity.
pub const ICONV_E2BIG: i32 = errno::E2BIG;
/// Core iconv error code: invalid multibyte sequence encountered.
pub const ICONV_EILSEQ: i32 = errno::EILSEQ;
/// Core iconv error code: incomplete multibyte sequence at end of input.
pub const ICONV_EINVAL: i32 = errno::EINVAL;

/// Dispatch classification for codec lookup in the phase-1 runtime table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecDispatchPath {
    IncludedCanonical,
    IncludedAlias,
    ExcludedFamily,
    UnsupportedCodec,
}

impl CodecDispatchPath {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CodecDispatchPath::IncludedCanonical => "included-canonical",
            CodecDispatchPath::IncludedAlias => "included-alias",
            CodecDispatchPath::ExcludedFamily => "excluded-family",
            CodecDispatchPath::UnsupportedCodec => "unsupported-codec",
        }
    }
}

/// Deterministic fallback policy returned when `iconv_open` cannot route a codec pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconvFallbackPolicy {
    ExcludedCodecFamily,
    UnsupportedCodec,
}

impl IconvFallbackPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            IconvFallbackPolicy::ExcludedCodecFamily => "excluded-family-einval",
            IconvFallbackPolicy::UnsupportedCodec => "unsupported-codec-einval",
        }
    }
}

/// Runtime lookup metadata for deterministic iconv dispatch telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconvDispatchMetadata {
    pub to_codec: &'static str,
    pub from_codec: &'static str,
    pub to_dispatch_path: CodecDispatchPath,
    pub from_dispatch_path: CodecDispatchPath,
}

/// Detailed failure contract for `iconv_open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconvOpenError {
    pub policy: IconvFallbackPolicy,
    pub dispatch: IconvDispatchMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Ascii,
    Latin1,
    Utf16Le,
    Utf32,
    Koi8R,
    Cp437,
}

struct CodecSpec {
    encoding: Encoding,
    canonical: &'static str,
    normalized: &'static str,
    aliases: &'static [&'static str],
}

struct ExcludedCodecSpec {
    canonical: &'static str,
    normalized: &'static str,
}

const PHASE1_CODEC_TABLE: [CodecSpec; 7] = [
    CodecSpec {
        encoding: Encoding::Utf8,
        canonical: "UTF-8",
        normalized: "UTF8",
        aliases: &["UTF8"],
    },
    CodecSpec {
        encoding: Encoding::Ascii,
        canonical: "ASCII",
        normalized: "ASCII",
        aliases: &["USASCII", "ANSIX3.41968", "ANSIX341968", "ISO646US"],
    },
    CodecSpec {
        encoding: Encoding::Latin1,
        canonical: "ISO-8859-1",
        normalized: "ISO88591",
        aliases: &["ISO88591", "LATIN1"],
    },
    CodecSpec {
        encoding: Encoding::Utf16Le,
        canonical: "UTF-16LE",
        normalized: "UTF16LE",
        aliases: &["UTF16LE"],
    },
    CodecSpec {
        encoding: Encoding::Utf32,
        canonical: "UTF-32",
        normalized: "UTF32",
        aliases: &["UTF32"],
    },
    CodecSpec {
        encoding: Encoding::Koi8R,
        canonical: "KOI8-R",
        normalized: "KOI8R",
        aliases: &["KOI8R", "CSKOI8R"],
    },
    CodecSpec {
        encoding: Encoding::Cp437,
        canonical: "CP437",
        normalized: "CP437",
        aliases: &["IBM437", "437", "CSPC8CODEPAGE437"],
    },
];

const PHASE1_EXCLUDED_CODEC_TABLE: [ExcludedCodecSpec; 6] = [
    ExcludedCodecSpec {
        canonical: "ISO-2022-CN-EXT",
        normalized: "ISO2022CNEXT",
    },
    ExcludedCodecSpec {
        canonical: "ISO-2022-JP",
        normalized: "ISO2022JP",
    },
    ExcludedCodecSpec {
        canonical: "EUC-JP",
        normalized: "EUCJP",
    },
    ExcludedCodecSpec {
        canonical: "SHIFT_JIS",
        normalized: "SHIFTJIS",
    },
    ExcludedCodecSpec {
        canonical: "GB18030",
        normalized: "GB18030",
    },
    ExcludedCodecSpec {
        canonical: "BIG5-HKSCS",
        normalized: "BIG5HKSCS",
    },
];

/// Canonical phase-1 codecs intentionally supported by the in-tree iconv engine.
pub const ICONV_PHASE1_INCLUDED_CODECS: [&str; 7] =
    ["UTF-8", "ASCII", "ISO-8859-1", "UTF-16LE", "UTF-32", "KOI8-R", "CP437"];

/// Canonical alias map for phase-1 supported codecs.
pub const ICONV_PHASE1_ALIAS_NORMALIZATIONS: [(&str, &str); 5] = [
    ("LATIN1", "ISO-8859-1"),
    ("USASCII", "ASCII"),
    ("ANSIX3.41968", "ASCII"),
    ("ANSIX341968", "ASCII"),
    ("ISO646US", "ASCII"),
];

/// Known out-of-scope codec families for phase-1 implementation.
pub const ICONV_PHASE1_EXCLUDED_CODEC_FAMILIES: [&str; 6] = [
    "ISO-2022-CN-EXT",
    "ISO-2022-JP",
    "EUC-JP",
    "SHIFT_JIS",
    "GB18030",
    "BIG5-HKSCS",
];

/// Opaque conversion descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconvDescriptor {
    from: Encoding,
    to: Encoding,
    emit_bom: bool,
    dispatch: IconvDispatchMetadata,
}

impl IconvDescriptor {
    #[must_use]
    pub const fn dispatch_metadata(&self) -> IconvDispatchMetadata {
        self.dispatch
    }
}

/// Conversion progress/result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconvResult {
    /// Number of non-reversible conversions (always 0 for this phase-1 engine).
    pub non_reversible: usize,
    /// Number of input bytes consumed.
    pub in_consumed: usize,
    /// Number of output bytes produced.
    pub out_written: usize,
}

/// Conversion failure with deterministic errno-style code and progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconvError {
    /// Errno-style code (`ICONV_E2BIG`, `ICONV_EILSEQ`, `ICONV_EINVAL`).
    pub code: i32,
    /// Number of input bytes consumed before the failure point.
    pub in_consumed: usize,
    /// Number of output bytes produced before the failure point.
    pub out_written: usize,
}

enum DecodeError {
    Incomplete,
    Invalid,
}

enum EncodeError {
    NoSpace,
    Unrepresentable,
}

fn normalize_encoding_label(raw: &[u8]) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(raw.len());
    for &b in raw {
        if matches!(b, b'-' | b'_' | b' ' | b'\t') {
            continue;
        }
        canonical.push(b.to_ascii_uppercase());
    }
    canonical
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodingLookup {
    encoding: Option<Encoding>,
    canonical: &'static str,
    dispatch_path: CodecDispatchPath,
}

fn classify_encoding(raw: &[u8]) -> EncodingLookup {
    let canonical = normalize_encoding_label(raw);

    for spec in PHASE1_CODEC_TABLE {
        if canonical.as_slice() == spec.normalized.as_bytes() {
            return EncodingLookup {
                encoding: Some(spec.encoding),
                canonical: spec.canonical,
                dispatch_path: CodecDispatchPath::IncludedCanonical,
            };
        }
        if spec
            .aliases
            .iter()
            .any(|alias| canonical.as_slice() == alias.as_bytes())
        {
            return EncodingLookup {
                encoding: Some(spec.encoding),
                canonical: spec.canonical,
                dispatch_path: CodecDispatchPath::IncludedAlias,
            };
        }
    }

    for spec in PHASE1_EXCLUDED_CODEC_TABLE {
        if canonical.as_slice() == spec.normalized.as_bytes() {
            return EncodingLookup {
                encoding: None,
                canonical: spec.canonical,
                dispatch_path: CodecDispatchPath::ExcludedFamily,
            };
        }
    }

    EncodingLookup {
        encoding: None,
        canonical: "UNSUPPORTED",
        dispatch_path: CodecDispatchPath::UnsupportedCodec,
    }
}

#[allow(dead_code)]
fn parse_encoding(raw: &[u8]) -> Option<Encoding> {
    classify_encoding(raw).encoding
}

fn decode_utf8(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }

    let b0 = input[0];
    if b0 < 0x80 {
        return Ok((char::from(b0), 1));
    }

    if (0xC2..=0xDF).contains(&b0) {
        if input.len() < 2 {
            return Err(DecodeError::Incomplete);
        }
        let b1 = input[1];
        if (b1 & 0xC0) != 0x80 {
            return Err(DecodeError::Invalid);
        }
        let cp = u32::from(b0 & 0x1F) << 6 | u32::from(b1 & 0x3F);
        if let Some(ch) = char::from_u32(cp) {
            return Ok((ch, 2));
        }
        return Err(DecodeError::Invalid);
    }

    if (0xE0..=0xEF).contains(&b0) {
        if input.len() < 3 {
            return Err(DecodeError::Incomplete);
        }
        let b1 = input[1];
        let b2 = input[2];
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
            return Err(DecodeError::Invalid);
        }
        if (b0 == 0xE0 && b1 < 0xA0) || (b0 == 0xED && b1 >= 0xA0) {
            return Err(DecodeError::Invalid);
        }
        let cp = u32::from(b0 & 0x0F) << 12 | u32::from(b1 & 0x3F) << 6 | u32::from(b2 & 0x3F);
        if let Some(ch) = char::from_u32(cp) {
            return Ok((ch, 3));
        }
        return Err(DecodeError::Invalid);
    }

    if (0xF0..=0xF4).contains(&b0) {
        if input.len() < 4 {
            return Err(DecodeError::Incomplete);
        }
        let b1 = input[1];
        let b2 = input[2];
        let b3 = input[3];
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
            return Err(DecodeError::Invalid);
        }
        if (b0 == 0xF0 && b1 < 0x90) || (b0 == 0xF4 && b1 > 0x8F) {
            return Err(DecodeError::Invalid);
        }
        let cp = u32::from(b0 & 0x07) << 18
            | u32::from(b1 & 0x3F) << 12
            | u32::from(b2 & 0x3F) << 6
            | u32::from(b3 & 0x3F);
        if let Some(ch) = char::from_u32(cp) {
            return Ok((ch, 4));
        }
        return Err(DecodeError::Invalid);
    }

    Err(DecodeError::Invalid)
}

fn decode_utf16le(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.len() < 2 {
        return Err(DecodeError::Incomplete);
    }

    let u1 = u16::from_le_bytes([input[0], input[1]]);
    if (0xD800..=0xDBFF).contains(&u1) {
        if input.len() < 4 {
            return Err(DecodeError::Incomplete);
        }
        let u2 = u16::from_le_bytes([input[2], input[3]]);
        if !(0xDC00..=0xDFFF).contains(&u2) {
            return Err(DecodeError::Invalid);
        }
        let cp = 0x10000 + (((u32::from(u1) - 0xD800) << 10) | (u32::from(u2) - 0xDC00));
        if let Some(ch) = char::from_u32(cp) {
            return Ok((ch, 4));
        }
        return Err(DecodeError::Invalid);
    }

    if (0xDC00..=0xDFFF).contains(&u1) {
        return Err(DecodeError::Invalid);
    }

    if let Some(ch) = char::from_u32(u32::from(u1)) {
        return Ok((ch, 2));
    }
    Err(DecodeError::Invalid)
}

fn decode_utf32(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.len() < 4 {
        return Err(DecodeError::Incomplete);
    }

    let cp = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    if let Some(ch) = char::from_u32(cp) {
        return Ok((ch, 4));
    }
    Err(DecodeError::Invalid)
}

/// KOI8-R to Unicode mapping table for bytes 0x80-0xFF.
/// Bytes 0x00-0x7F map directly to ASCII/Unicode.
const KOI8R_TO_UNICODE: [u16; 128] = [
    0x2500, 0x2502, 0x250C, 0x2510, 0x2514, 0x2518, 0x251C, 0x2524, // 80-87
    0x252C, 0x2534, 0x253C, 0x2580, 0x2584, 0x2588, 0x258C, 0x2590, // 88-8F
    0x2591, 0x2592, 0x2593, 0x2320, 0x25A0, 0x2219, 0x221A, 0x2248, // 90-97
    0x2264, 0x2265, 0x00A0, 0x2321, 0x00B0, 0x00B2, 0x00B7, 0x00F7, // 98-9F
    0x2550, 0x2551, 0x2552, 0x0451, 0x2553, 0x2554, 0x2555, 0x2556, // A0-A7
    0x2557, 0x2558, 0x2559, 0x255A, 0x255B, 0x255C, 0x255D, 0x255E, // A8-AF
    0x255F, 0x2560, 0x2561, 0x0401, 0x2562, 0x2563, 0x2564, 0x2565, // B0-B7
    0x2566, 0x2567, 0x2568, 0x2569, 0x256A, 0x256B, 0x256C, 0x00A9, // B8-BF
    0x044E, 0x0430, 0x0431, 0x0446, 0x0434, 0x0435, 0x0444, 0x0433, // C0-C7
    0x0445, 0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, // C8-CF
    0x043F, 0x044F, 0x0440, 0x0441, 0x0442, 0x0443, 0x0436, 0x0432, // D0-D7
    0x044C, 0x044B, 0x0437, 0x0448, 0x044D, 0x0449, 0x0447, 0x044A, // D8-DF
    0x042E, 0x0410, 0x0411, 0x0426, 0x0414, 0x0415, 0x0424, 0x0413, // E0-E7
    0x0425, 0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, // E8-EF
    0x041F, 0x042F, 0x0420, 0x0421, 0x0422, 0x0423, 0x0416, 0x0412, // F0-F7
    0x042C, 0x042B, 0x0417, 0x0428, 0x042D, 0x0429, 0x0427, 0x042A, // F8-FF
];

fn decode_koi8r(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = KOI8R_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_koi8r(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    // ASCII range
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    // Search reverse mapping
    for (idx, &unicode) in KOI8R_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP437 (IBM437) to Unicode mapping table for bytes 0x80-0xFF.
/// Bytes 0x00-0x7F are standard ASCII (with graphical chars in 0x00-0x1F).
const CP437_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, // 88-8F
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, // 90-97
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, // 98-9F
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, // E0-E7
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229, // E8-EF
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, // F0-F7
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp437(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        // Standard ASCII (0x00-0x7F treated as printable in CP437)
        Ok((char::from(b), 1))
    } else {
        let cp = CP437_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp437(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    // ASCII range (simplified: treat 0x00-0x7F as direct mapping)
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    // Search reverse mapping
    for (idx, &unicode) in CP437_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

fn decode_char(enc: Encoding, input: &[u8]) -> Result<(char, usize), DecodeError> {
    match enc {
        Encoding::Utf8 => decode_utf8(input),
        Encoding::Ascii => {
            if input.is_empty() {
                Err(DecodeError::Incomplete)
            } else if input[0] <= 0x7F {
                Ok((char::from(input[0]), 1))
            } else {
                Err(DecodeError::Invalid)
            }
        }
        Encoding::Latin1 => {
            if input.is_empty() {
                Err(DecodeError::Incomplete)
            } else {
                Ok((char::from(input[0]), 1))
            }
        }
        Encoding::Utf16Le => decode_utf16le(input),
        Encoding::Utf32 => decode_utf32(input),
        Encoding::Koi8R => decode_koi8r(input),
        Encoding::Cp437 => decode_cp437(input),
    }
}

fn encode_char(enc: Encoding, ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    match enc {
        Encoding::Utf8 => {
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf).as_bytes();
            if out.len() < encoded.len() {
                return Err(EncodeError::NoSpace);
            }
            out[..encoded.len()].copy_from_slice(encoded);
            Ok(encoded.len())
        }
        Encoding::Ascii => {
            let cp = ch as u32;
            if cp > 0x7F {
                return Err(EncodeError::Unrepresentable);
            }
            if out.is_empty() {
                return Err(EncodeError::NoSpace);
            }
            out[0] = cp as u8;
            Ok(1)
        }
        Encoding::Latin1 => {
            let cp = ch as u32;
            if cp > 0xFF {
                return Err(EncodeError::Unrepresentable);
            }
            if out.is_empty() {
                return Err(EncodeError::NoSpace);
            }
            out[0] = cp as u8;
            Ok(1)
        }
        Encoding::Utf16Le => {
            let mut units = [0u16; 2];
            let encoded_units = ch.encode_utf16(&mut units);
            let needed = encoded_units.len() * 2;
            if out.len() < needed {
                return Err(EncodeError::NoSpace);
            }
            for (idx, unit) in encoded_units.iter().enumerate() {
                let bytes = unit.to_le_bytes();
                out[idx * 2] = bytes[0];
                out[idx * 2 + 1] = bytes[1];
            }
            Ok(needed)
        }
        Encoding::Utf32 => {
            if out.len() < 4 {
                return Err(EncodeError::NoSpace);
            }
            let bytes = (ch as u32).to_le_bytes();
            out[..4].copy_from_slice(&bytes);
            Ok(4)
        }
        Encoding::Koi8R => encode_koi8r(ch, out),
        Encoding::Cp437 => encode_cp437(ch, out),
    }
}

/// Opens a character set conversion descriptor with deterministic dispatch metadata.
///
/// Equivalent to C `iconv_open`. Converts from `fromcode` encoding to `tocode` encoding.
/// Returns explicit fallback policy metadata when the conversion is unsupported.
pub fn iconv_open_detailed(
    tocode: &[u8],
    fromcode: &[u8],
) -> Result<(IconvDescriptor, IconvDispatchMetadata), IconvOpenError> {
    let to_lookup = classify_encoding(tocode);
    let from_lookup = classify_encoding(fromcode);

    let dispatch = IconvDispatchMetadata {
        to_codec: to_lookup.canonical,
        from_codec: from_lookup.canonical,
        to_dispatch_path: to_lookup.dispatch_path,
        from_dispatch_path: from_lookup.dispatch_path,
    };

    let Some(to) = to_lookup.encoding else {
        let policy = if matches!(to_lookup.dispatch_path, CodecDispatchPath::ExcludedFamily) {
            IconvFallbackPolicy::ExcludedCodecFamily
        } else {
            IconvFallbackPolicy::UnsupportedCodec
        };
        return Err(IconvOpenError { policy, dispatch });
    };

    let Some(from) = from_lookup.encoding else {
        let policy = if matches!(from_lookup.dispatch_path, CodecDispatchPath::ExcludedFamily) {
            IconvFallbackPolicy::ExcludedCodecFamily
        } else {
            IconvFallbackPolicy::UnsupportedCodec
        };
        return Err(IconvOpenError { policy, dispatch });
    };

    Ok((
        IconvDescriptor {
            from,
            to,
            emit_bom: matches!(to, Encoding::Utf32),
            dispatch,
        },
        dispatch,
    ))
}

/// Opens a character set conversion descriptor.
///
/// Equivalent to C `iconv_open`. Converts from `fromcode` encoding to
/// `tocode` encoding. Returns `None` if the conversion is not supported.
pub fn iconv_open(tocode: &[u8], fromcode: &[u8]) -> Option<IconvDescriptor> {
    iconv_open_detailed(tocode, fromcode)
        .ok()
        .map(|(desc, _)| desc)
}

/// Performs character set conversion.
///
/// Equivalent to C `iconv`. Converts bytes from `inbuf` and writes to `outbuf`.
/// Returns deterministic conversion progress and either success or errno-style failure.
pub fn iconv(
    cd: &mut IconvDescriptor,
    inbuf: Option<&[u8]>,
    outbuf: &mut [u8],
) -> Result<IconvResult, IconvError> {
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;
    let non_reversible = 0usize;

    // Standard iconv reset behavior: if inbuf is None, reset shift state and
    // potentially emit a Byte Order Mark if the destination encoding requires it.
    let input = match inbuf {
        Some(b) => b,
        None => {
            if cd.emit_bom && !outbuf.is_empty() {
                let bom = match cd.to {
                    Encoding::Utf16Le => &[0xFF, 0xFE][..],
                    Encoding::Utf32 => &[0xFF, 0xFE, 0x00, 0x00][..],
                    _ => &[][..],
                };
                if !bom.is_empty() {
                    if outbuf.len() < bom.len() {
                        return Err(IconvError {
                            code: ICONV_E2BIG,
                            in_consumed: 0,
                            out_written: 0,
                        });
                    }
                    outbuf[..bom.len()].copy_from_slice(bom);
                    out_pos = bom.len();
                }
                cd.emit_bom = false;
            } else if cd.emit_bom && outbuf.is_empty() {
                // If outbuf is empty but we need to emit a BOM, we don't
                // emit it yet and don't clear emit_bom, unless this is
                // a pure state reset which POSIX allows to have null outbuf.
                // For stateless phase-1, we just return success.
            }
            return Ok(IconvResult {
                non_reversible,
                in_consumed: 0,
                out_written: out_pos,
            });
        }
    };

    if cd.emit_bom {
        let bom = match cd.to {
            Encoding::Utf32 => &[0xFF, 0xFE, 0x00, 0x00][..],
            _ => &[][..],
        };
        if !bom.is_empty() {
            if outbuf.len() < bom.len() {
                return Err(IconvError {
                    code: ICONV_E2BIG,
                    in_consumed: 0,
                    out_written: 0,
                });
            }
            outbuf[..bom.len()].copy_from_slice(bom);
            out_pos = bom.len();
        }
        cd.emit_bom = false;
    }

    while in_pos < input.len() {
        let (ch, consumed) = match decode_char(cd.from, &input[in_pos..]) {
            Ok(v) => v,
            Err(DecodeError::Incomplete) => {
                return Err(IconvError {
                    code: ICONV_EINVAL,
                    in_consumed: in_pos,
                    out_written: out_pos,
                });
            }
            Err(DecodeError::Invalid) => {
                return Err(IconvError {
                    code: ICONV_EILSEQ,
                    in_consumed: in_pos,
                    out_written: out_pos,
                });
            }
        };

        let written = match encode_char(cd.to, ch, &mut outbuf[out_pos..]) {
            Ok(v) => v,
            Err(EncodeError::NoSpace) => {
                return Err(IconvError {
                    code: ICONV_E2BIG,
                    in_consumed: in_pos,
                    out_written: out_pos,
                });
            }
            Err(EncodeError::Unrepresentable) => {
                return Err(IconvError {
                    code: ICONV_EILSEQ,
                    in_consumed: in_pos,
                    out_written: out_pos,
                });
            }
        };

        in_pos += consumed;
        out_pos += written;
    }

    Ok(IconvResult {
        non_reversible,
        in_consumed: in_pos,
        out_written: out_pos,
    })
}

/// Closes a character set conversion descriptor.
///
/// Equivalent to C `iconv_close`. Returns 0 on success, -1 on error.
pub fn iconv_close(_cd: IconvDescriptor) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iconv_open_recognizes_phase1_encodings() {
        assert!(iconv_open(b"UTF-8", b"ISO-8859-1").is_some());
        assert!(iconv_open(b"utf8", b"latin1").is_some());
        assert!(iconv_open(b"ASCII", b"UTF-8").is_some());
        assert!(iconv_open(b"UTF-8", b"US-ASCII").is_some());
        assert!(iconv_open(b"UTF16LE", b"UTF-8").is_some());
        assert!(iconv_open(b"UTF-32", b"UTF-8").is_some());
    }

    #[test]
    fn iconv_open_normalizes_encoding_tokens() {
        assert!(iconv_open(b"utf 16_le", b" latin-1 ").is_some());
        assert!(iconv_open(b"utf-32", b"utf 8").is_some());
    }

    #[test]
    fn iconv_open_rejects_out_of_scope_codecs() {
        for codec in ICONV_PHASE1_EXCLUDED_CODEC_FAMILIES {
            assert!(
                iconv_open(codec.as_bytes(), b"UTF-8").is_none(),
                "phase-1 should reject unsupported destination codec {codec}"
            );
            assert!(
                iconv_open(b"UTF-8", codec.as_bytes()).is_none(),
                "phase-1 should reject unsupported source codec {codec}"
            );
        }
    }

    #[test]
    fn iconv_open_detailed_reports_alias_dispatch() {
        let (desc, meta) =
            iconv_open_detailed(b"utf-8", b"latin1").expect("alias path should open");
        assert_eq!(desc.dispatch_metadata(), meta);
        assert_eq!(meta.to_codec, "UTF-8");
        assert_eq!(meta.from_codec, "ISO-8859-1");
        assert_eq!(meta.to_dispatch_path, CodecDispatchPath::IncludedCanonical);
        assert_eq!(meta.from_dispatch_path, CodecDispatchPath::IncludedAlias);
    }

    #[test]
    fn iconv_open_detailed_reports_excluded_family_policy() {
        let err =
            iconv_open_detailed(b"UTF-8", b"SHIFT_JIS").expect_err("excluded codec must fail");
        assert_eq!(err.policy, IconvFallbackPolicy::ExcludedCodecFamily);
        assert_eq!(err.dispatch.from_codec, "SHIFT_JIS");
        assert_eq!(
            err.dispatch.from_dispatch_path,
            CodecDispatchPath::ExcludedFamily
        );
    }

    #[test]
    fn iconv_open_detailed_reports_unsupported_policy() {
        let err = iconv_open_detailed(b"UTF-8", b"UTF-7").expect_err("unknown codec must fail");
        assert_eq!(err.policy, IconvFallbackPolicy::UnsupportedCodec);
        assert_eq!(
            err.dispatch.from_dispatch_path,
            CodecDispatchPath::UnsupportedCodec
        );
    }

    #[test]
    fn utf8_to_latin1_basic_conversion() {
        let mut cd = iconv_open(b"ISO-8859-1", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some("Héllo".as_bytes()), &mut out).unwrap();
        assert_eq!(res.in_consumed, "Héllo".len());
        assert_eq!(res.out_written, 5);
        assert_eq!(&out[..5], b"H\xe9llo");
    }

    #[test]
    fn latin1_to_utf8_basic_conversion() {
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-1").unwrap();
        let input = [0x48, 0xE9];
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some(&input), &mut out).unwrap();
        assert_eq!(res.in_consumed, 2);
        assert_eq!(res.out_written, 3);
        assert_eq!(&out[..3], "Hé".as_bytes());
    }

    #[test]
    fn ascii_roundtrip_accepts_7_bit_bytes() {
        let mut cd = iconv_open(b"ASCII", b"US-ASCII").unwrap();
        let mut out = [0u8; 8];
        let res = iconv(&mut cd, Some(b"Az09!?"), &mut out).unwrap();
        assert_eq!(res.in_consumed, 6);
        assert_eq!(res.out_written, 6);
        assert_eq!(&out[..6], b"Az09!?");
    }

    #[test]
    fn utf8_to_ascii_rejects_non_ascii_code_point() {
        let mut cd = iconv_open(b"ASCII", b"UTF-8").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some("é".as_bytes()), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn ascii_to_utf8_rejects_high_bit_input() {
        let mut cd = iconv_open(b"UTF-8", b"ASCII").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some(&[0x80]), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn utf8_to_utf16le_conversion() {
        let mut cd = iconv_open(b"UTF-16LE", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some("A€".as_bytes()), &mut out).unwrap();
        assert_eq!(res.in_consumed, "A€".len());
        assert_eq!(res.out_written, 4);
        assert_eq!(&out[..4], &[0x41, 0x00, 0xAC, 0x20]);
    }

    #[test]
    fn utf16le_to_utf8_conversion() {
        let mut cd = iconv_open(b"UTF-8", b"UTF-16LE").unwrap();
        let input = [0x41, 0x00, 0xAC, 0x20];
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some(&input), &mut out).unwrap();
        assert_eq!(res.in_consumed, 4);
        assert_eq!(res.out_written, "A€".len());
        assert_eq!(&out[..res.out_written], "A€".as_bytes());
    }

    #[test]
    fn utf8_to_utf32_conversion_reset_emits_bom() {
        let mut cd = iconv_open(b"UTF-32", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        // First call with None should emit BOM
        let res1 = iconv(&mut cd, None, &mut out).unwrap();
        assert_eq!(res1.in_consumed, 0);
        assert_eq!(res1.out_written, 4);
        assert_eq!(&out[..4], &[0xFF, 0xFE, 0x00, 0x00]);

        // Second call with Some should convert without another BOM
        let res2 = iconv(&mut cd, Some(b"A"), &mut out[4..]).unwrap();
        assert_eq!(res2.in_consumed, 1);
        assert_eq!(res2.out_written, 4);
        assert_eq!(&out[4..8], &[0x41, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn utf8_to_utf32_first_conversion_emits_bom() {
        let mut cd = iconv_open(b"UTF-32", b"UTF-8").unwrap();
        let mut out = [0u8; 8];
        let res = iconv(&mut cd, Some(b"A"), &mut out).unwrap();
        assert_eq!(res.in_consumed, 1);
        assert_eq!(res.out_written, 8);
        assert_eq!(&out[..8], &[0xFF, 0xFE, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn utf8_to_utf16le_first_conversion_does_not_emit_bom() {
        let mut cd = iconv_open(b"UTF-16LE", b"UTF-8").unwrap();
        let mut out = [0u8; 4];
        let res = iconv(&mut cd, Some(b"A"), &mut out).unwrap();
        assert_eq!(res.in_consumed, 1);
        assert_eq!(res.out_written, 2);
        assert_eq!(&out[..2], &[0x41, 0x00]);
    }

    #[test]
    fn utf8_to_utf32_e2big_before_bom() {
        let mut cd = iconv_open(b"UTF-32", b"UTF-8").unwrap();
        let mut out = [0u8; 3];
        let err = iconv(&mut cd, None, &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_E2BIG);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn e2big_reports_partial_progress() {
        let mut cd = iconv_open(b"UTF-16LE", b"UTF-8").unwrap();
        let mut out = [0u8; 2];
        let err = iconv(&mut cd, Some(b"AB"), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_E2BIG);
        assert_eq!(err.in_consumed, 1);
        assert_eq!(err.out_written, 2);
    }

    #[test]
    fn invalid_utf8_reports_eilseq() {
        let mut cd = iconv_open(b"UTF-16LE", b"UTF-8").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some(&[0xC3, 0x28]), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn incomplete_utf8_reports_einval() {
        let mut cd = iconv_open(b"UTF-16LE", b"UTF-8").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some(&[0xE2, 0x82]), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EINVAL);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn invalid_utf16_reports_eilseq() {
        let mut cd = iconv_open(b"UTF-8", b"UTF-16LE").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some(&[0x00, 0xDC]), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn incomplete_utf16_reports_einval() {
        let mut cd = iconv_open(b"UTF-8", b"UTF-16LE").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some(&[0x34]), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EINVAL);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn latin1_unrepresentable_reports_eilseq() {
        let mut cd = iconv_open(b"ISO-8859-1", b"UTF-8").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some("€".as_bytes()), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn iconv_close_succeeds() {
        let cd = iconv_open(b"UTF-8", b"UTF-16LE").unwrap();
        assert_eq!(iconv_close(cd), 0);
    }

    #[test]
    fn koi8r_to_utf8_round_trip() {
        // KOI8-R bytes for "Привет" (Privet, Hello in Russian)
        let koi8r_input: &[u8] = &[0xF0, 0xD2, 0xC9, 0xD7, 0xC5, 0xD4];
        let expected_utf8 = "Привет";

        // KOI8-R → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"KOI8-R").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(koi8r_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 6);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → KOI8-R (reverse)
        let mut cd2 = iconv_open(b"KOI8-R", b"UTF-8").unwrap();
        let mut koi8r_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut koi8r_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&koi8r_out[..result2.out_written], koi8r_input);
    }

    #[test]
    fn koi8r_unrepresentable_reports_eilseq() {
        let mut cd = iconv_open(b"KOI8-R", b"UTF-8").unwrap();
        let mut out = [0u8; 8];
        // Japanese character not in KOI8-R
        let err = iconv(&mut cd, Some("日".as_bytes()), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
    }

    #[test]
    fn cp437_to_utf8_round_trip() {
        // CP437 bytes: box-drawing chars ┌─┐
        let cp437_input: &[u8] = &[0xDA, 0xC4, 0xBF];
        let expected_utf8 = "┌─┐";

        // CP437 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"CP437").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp437_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 3);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → CP437 (reverse)
        let mut cd2 = iconv_open(b"CP437", b"UTF-8").unwrap();
        let mut cp437_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp437_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&cp437_out[..result2.out_written], cp437_input);
    }

    #[test]
    fn cp437_accepts_ibm437_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM437");
        assert!(cd.is_some());
    }
}
