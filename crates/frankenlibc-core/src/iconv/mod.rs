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
    Koi8U,
    Cp437,
    Cp1252,
    Iso88592,
    Iso88594,
    Iso88595,
    Iso88597,
    Iso88599,
    Iso885913,
    Iso885915,
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

const PHASE1_CODEC_TABLE: [CodecSpec; 16] = [
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
        encoding: Encoding::Koi8U,
        canonical: "KOI8-U",
        normalized: "KOI8U",
        aliases: &["KOI8U"],
    },
    CodecSpec {
        encoding: Encoding::Cp437,
        canonical: "CP437",
        normalized: "CP437",
        aliases: &["IBM437", "437", "CSPC8CODEPAGE437"],
    },
    CodecSpec {
        encoding: Encoding::Cp1252,
        canonical: "CP1252",
        normalized: "CP1252",
        aliases: &["WINDOWS1252", "MS-ANSI", "1252"],
    },
    CodecSpec {
        encoding: Encoding::Iso88592,
        canonical: "ISO-8859-2",
        normalized: "ISO88592",
        aliases: &["ISO88592", "LATIN2", "CSISOLATIN2"],
    },
    CodecSpec {
        encoding: Encoding::Iso88594,
        canonical: "ISO-8859-4",
        normalized: "ISO88594",
        aliases: &["ISO88594", "LATIN4", "CSISOLATIN4", "BALTIC"],
    },
    CodecSpec {
        encoding: Encoding::Iso88595,
        canonical: "ISO-8859-5",
        normalized: "ISO88595",
        aliases: &["ISO88595", "CYRILLIC", "CSISOLATINCYRILLIC"],
    },
    CodecSpec {
        encoding: Encoding::Iso88597,
        canonical: "ISO-8859-7",
        normalized: "ISO88597",
        aliases: &["ISO88597", "GREEK", "GREEK8", "CSISOLATINGREEK", "ELOT928", "ECMA118"],
    },
    CodecSpec {
        encoding: Encoding::Iso88599,
        canonical: "ISO-8859-9",
        normalized: "ISO88599",
        aliases: &["ISO88599", "LATIN5", "CSISOLATIN5", "TURKISH"],
    },
    CodecSpec {
        encoding: Encoding::Iso885913,
        canonical: "ISO-8859-13",
        normalized: "ISO885913",
        aliases: &["ISO885913", "LATIN7", "CSISOLATIN7", "BALTICRIM"],
    },
    CodecSpec {
        encoding: Encoding::Iso885915,
        canonical: "ISO-8859-15",
        normalized: "ISO885915",
        aliases: &["ISO885915", "LATIN9", "CSISOLATIN9"],
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
pub const ICONV_PHASE1_INCLUDED_CODECS: [&str; 16] =
    ["UTF-8", "ASCII", "ISO-8859-1", "UTF-16LE", "UTF-32", "KOI8-R", "KOI8-U", "CP437", "CP1252", "ISO-8859-2", "ISO-8859-4", "ISO-8859-5", "ISO-8859-7", "ISO-8859-9", "ISO-8859-13", "ISO-8859-15"];

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

/// KOI8-U (Ukrainian) differs from KOI8-R at 8 positions.
/// This table lists (byte, unicode) pairs for the differing positions.
const KOI8U_DIFFS: [(u8, u16); 8] = [
    (0xA4, 0x0404), // Є (Ukrainian Ye)
    (0xA6, 0x0406), // І (Ukrainian I)
    (0xA7, 0x0407), // Ї (Ukrainian Yi)
    (0xAD, 0x0490), // Ґ (Ukrainian Ghe with upturn)
    (0xB4, 0x0454), // є (Ukrainian ye)
    (0xB6, 0x0456), // і (Ukrainian i)
    (0xB7, 0x0457), // ї (Ukrainian yi)
    (0xBD, 0x0491), // ґ (Ukrainian ghe with upturn)
];

fn decode_koi8u(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        return Ok((char::from(b), 1));
    }
    // Check KOI8-U specific mappings first
    for &(byte, unicode) in &KOI8U_DIFFS {
        if b == byte {
            return Ok((char::from_u32(u32::from(unicode)).unwrap_or('\u{FFFD}'), 1));
        }
    }
    // Otherwise same as KOI8-R
    let cp = KOI8R_TO_UNICODE[(b - 0x80) as usize];
    Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
}

fn encode_koi8u(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    // Check KOI8-U specific mappings first
    for &(byte, unicode) in &KOI8U_DIFFS {
        if u32::from(unicode) == cp {
            out[0] = byte;
            return Ok(1);
        }
    }
    // Otherwise try KOI8-R mapping
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

/// ISO-8859-2 (Latin-2/Central European) to Unicode mapping for bytes 0xA0-0xFF.
const ISO88592_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0104, 0x02D8, 0x0141, 0x00A4, 0x013D, 0x015A, 0x00A7, // A0-A7
    0x00A8, 0x0160, 0x015E, 0x0164, 0x0179, 0x00AD, 0x017D, 0x017B, // A8-AF
    0x00B0, 0x0105, 0x02DB, 0x0142, 0x00B4, 0x013E, 0x015B, 0x02C7, // B0-B7
    0x00B8, 0x0161, 0x015F, 0x0165, 0x017A, 0x02DD, 0x017E, 0x017C, // B8-BF
    0x0154, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0139, 0x0106, 0x00C7, // C0-C7
    0x010C, 0x00C9, 0x0118, 0x00CB, 0x011A, 0x00CD, 0x00CE, 0x010E, // C8-CF
    0x0110, 0x0143, 0x0147, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x00D7, // D0-D7
    0x0158, 0x016E, 0x00DA, 0x0170, 0x00DC, 0x00DD, 0x0162, 0x00DF, // D8-DF
    0x0155, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x013A, 0x0107, 0x00E7, // E0-E7
    0x010D, 0x00E9, 0x0119, 0x00EB, 0x011B, 0x00ED, 0x00EE, 0x010F, // E8-EF
    0x0111, 0x0144, 0x0148, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x00F7, // F0-F7
    0x0159, 0x016F, 0x00FA, 0x0171, 0x00FC, 0x00FD, 0x0163, 0x02D9, // F8-FF
];

fn decode_iso88592(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88592_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso88592(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO88592_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ISO-8859-4 (Latin-4/Baltic) to Unicode mapping for bytes 0xA0-0xFF.
const ISO88594_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0104, 0x0138, 0x0156, 0x00A4, 0x0128, 0x013B, 0x00A7, // A0-A7
    0x00A8, 0x0160, 0x0112, 0x0122, 0x0166, 0x00AD, 0x017D, 0x00AF, // A8-AF
    0x00B0, 0x0105, 0x02DB, 0x0157, 0x00B4, 0x0129, 0x013C, 0x02C7, // B0-B7
    0x00B8, 0x0161, 0x0113, 0x0123, 0x0167, 0x014A, 0x017E, 0x014B, // B8-BF
    0x0100, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x012E, // C0-C7
    0x010C, 0x00C9, 0x0118, 0x00CB, 0x0116, 0x00CD, 0x00CE, 0x012A, // C8-CF
    0x0110, 0x0145, 0x014C, 0x0136, 0x00D4, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x0172, 0x00DA, 0x00DB, 0x00DC, 0x0168, 0x016A, 0x00DF, // D8-DF
    0x0101, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x012F, // E0-E7
    0x010D, 0x00E9, 0x0119, 0x00EB, 0x0117, 0x00ED, 0x00EE, 0x012B, // E8-EF
    0x0111, 0x0146, 0x014D, 0x0137, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x0173, 0x00FA, 0x00FB, 0x00FC, 0x0169, 0x016B, 0x02D9, // F8-FF
];

fn decode_iso88594(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88594_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso88594(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO88594_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ISO-8859-5 (Cyrillic) to Unicode mapping for bytes 0xA0-0xFF.
/// Bytes 0x00-0x9F map directly to Unicode (ASCII + C1 controls).
const ISO88595_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0406, 0x0407, // A0-A7
    0x0408, 0x0409, 0x040A, 0x040B, 0x040C, 0x00AD, 0x040E, 0x040F, // A8-AF
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // B0-B7
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // B8-BF
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // C0-C7
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // C8-CF
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // D0-D7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // D8-DF
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // E0-E7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // E8-EF
    0x2116, 0x0451, 0x0452, 0x0453, 0x0454, 0x0455, 0x0456, 0x0457, // F0-F7
    0x0458, 0x0459, 0x045A, 0x045B, 0x045C, 0x00A7, 0x045E, 0x045F, // F8-FF
];

fn decode_iso88595(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        // 0x00-0x9F map directly to Unicode
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88595_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso88595(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    // Direct mapping range (0x00-0x9F)
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    // Search in the 0xA0-0xFF range
    for (idx, &unicode) in ISO88595_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ISO-8859-7 (Greek) to Unicode lookup table for bytes 0xA0-0xFF.
const ISO88597_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x2018, 0x2019, 0x00A3, 0x20AC, 0x20AF, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x037A, 0x00AB, 0x00AC, 0x00AD, 0xFFFD, 0x2015, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x0384, 0x0385, 0x0386, 0x00B7, // B0-B7
    0x0388, 0x0389, 0x038A, 0x00BB, 0x038C, 0x00BD, 0x038E, 0x038F, // B8-BF
    0x0390, 0x0391, 0x0392, 0x0393, 0x0394, 0x0395, 0x0396, 0x0397, // C0-C7
    0x0398, 0x0399, 0x039A, 0x039B, 0x039C, 0x039D, 0x039E, 0x039F, // C8-CF
    0x03A0, 0x03A1, 0xFFFD, 0x03A3, 0x03A4, 0x03A5, 0x03A6, 0x03A7, // D0-D7
    0x03A8, 0x03A9, 0x03AA, 0x03AB, 0x03AC, 0x03AD, 0x03AE, 0x03AF, // D8-DF
    0x03B0, 0x03B1, 0x03B2, 0x03B3, 0x03B4, 0x03B5, 0x03B6, 0x03B7, // E0-E7
    0x03B8, 0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, 0x03BE, 0x03BF, // E8-EF
    0x03C0, 0x03C1, 0x03C2, 0x03C3, 0x03C4, 0x03C5, 0x03C6, 0x03C7, // F0-F7
    0x03C8, 0x03C9, 0x03CA, 0x03CB, 0x03CC, 0x03CD, 0x03CE, 0xFFFD, // F8-FF
];

fn decode_iso88597(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88597_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso88597(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO88597_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1252 (CP1252) to Unicode lookup table for bytes 0x80-0x9F.
/// These 32 positions differ from ISO-8859-1 (C1 control codes in 8859-1,
/// printable characters in CP1252). 0xFFFF marks undefined positions.
const CP1252_TO_UNICODE: [u16; 32] = [
    0x20AC, 0xFFFF, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFF, 0x017D, 0xFFFF, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFF, 0x017E, 0x0178, // 98-9F
];

fn decode_cp1252(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b >= 0x80 && b <= 0x9F {
        let cp = CP1252_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    } else {
        Ok((char::from(b), 1))
    }
}

fn encode_cp1252(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 || (cp >= 0xA0 && cp <= 0xFF) {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1252_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ISO-8859-9 (Latin-5/Turkish) differs from ISO-8859-1 at 6 positions.
/// This table lists (byte, unicode) pairs for the differing positions.
const ISO88599_DIFFS: [(u8, u16); 6] = [
    (0xD0, 0x011E), // Ğ (G with breve)
    (0xDD, 0x0130), // İ (I with dot above)
    (0xDE, 0x015E), // Ş (S with cedilla)
    (0xF0, 0x011F), // ğ (g with breve)
    (0xFD, 0x0131), // ı (dotless i)
    (0xFE, 0x015F), // ş (s with cedilla)
];

fn decode_iso88599(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    for &(byte, unicode) in &ISO88599_DIFFS {
        if b == byte {
            return Ok((char::from_u32(u32::from(unicode)).unwrap_or('\u{FFFD}'), 1));
        }
    }
    Ok((char::from(b), 1))
}

fn encode_iso88599(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    for &(byte, unicode) in &ISO88599_DIFFS {
        if u32::from(unicode) == cp {
            out[0] = byte;
            return Ok(1);
        }
    }
    if cp <= 0xFF {
        out[0] = cp as u8;
        return Ok(1);
    }
    Err(EncodeError::Unrepresentable)
}

/// ISO-8859-13 (Latin-7/Baltic Rim) to Unicode mapping for bytes 0xA0-0xFF.
const ISO885913_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x201D, 0x00A2, 0x00A3, 0x00A4, 0x201E, 0x00A6, 0x00A7, // A0-A7
    0x00D8, 0x00A9, 0x0156, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00C6, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x201C, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00F8, 0x00B9, 0x0157, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00E6, // B8-BF
    0x0104, 0x012E, 0x0100, 0x0106, 0x00C4, 0x00C5, 0x0118, 0x0112, // C0-C7
    0x010C, 0x00C9, 0x0179, 0x0116, 0x0122, 0x0136, 0x012A, 0x013B, // C8-CF
    0x0160, 0x0143, 0x0145, 0x00D3, 0x014C, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x0172, 0x0141, 0x015A, 0x016A, 0x00DC, 0x017B, 0x017D, 0x00DF, // D8-DF
    0x0105, 0x012F, 0x0101, 0x0107, 0x00E4, 0x00E5, 0x0119, 0x0113, // E0-E7
    0x010D, 0x00E9, 0x017A, 0x0117, 0x0123, 0x0137, 0x012B, 0x013C, // E8-EF
    0x0161, 0x0144, 0x0146, 0x00F3, 0x014D, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x0173, 0x0142, 0x015B, 0x016B, 0x00FC, 0x017C, 0x017E, 0x2019, // F8-FF
];

fn decode_iso885913(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO885913_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso885913(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO885913_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ISO-8859-15 (Latin-9) differs from ISO-8859-1 at 8 positions.
/// This table lists (byte, unicode) pairs for the differing positions.
const ISO885915_DIFFS: [(u8, u16); 8] = [
    (0xA4, 0x20AC), // Euro sign
    (0xA6, 0x0160), // Š
    (0xA8, 0x0161), // š
    (0xB4, 0x017D), // Ž
    (0xB8, 0x017E), // ž
    (0xBC, 0x0152), // Œ
    (0xBD, 0x0153), // œ
    (0xBE, 0x0178), // Ÿ
];

fn decode_iso885915(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    // Check for ISO-8859-15 specific mappings
    for &(byte, unicode) in &ISO885915_DIFFS {
        if b == byte {
            return Ok((char::from_u32(u32::from(unicode)).unwrap_or('\u{FFFD}'), 1));
        }
    }
    // Otherwise same as Latin-1
    Ok((char::from(b), 1))
}

fn encode_iso885915(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    // Check for ISO-8859-15 specific mappings
    for &(byte, unicode) in &ISO885915_DIFFS {
        if cp == u32::from(unicode) {
            out[0] = byte;
            return Ok(1);
        }
    }
    // Check if it's a Latin-1 character NOT replaced by ISO-8859-15
    if cp <= 0xFF {
        let b = cp as u8;
        // Reject the Latin-1 characters that are replaced in ISO-8859-15
        if matches!(b, 0xA4 | 0xA6 | 0xA8 | 0xB4 | 0xB8 | 0xBC | 0xBD | 0xBE) {
            return Err(EncodeError::Unrepresentable);
        }
        out[0] = b;
        return Ok(1);
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
        Encoding::Koi8U => decode_koi8u(input),
        Encoding::Cp437 => decode_cp437(input),
        Encoding::Cp1252 => decode_cp1252(input),
        Encoding::Iso88592 => decode_iso88592(input),
        Encoding::Iso88594 => decode_iso88594(input),
        Encoding::Iso88595 => decode_iso88595(input),
        Encoding::Iso88597 => decode_iso88597(input),
        Encoding::Iso88599 => decode_iso88599(input),
        Encoding::Iso885913 => decode_iso885913(input),
        Encoding::Iso885915 => decode_iso885915(input),
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
        Encoding::Koi8U => encode_koi8u(ch, out),
        Encoding::Cp437 => encode_cp437(ch, out),
        Encoding::Cp1252 => encode_cp1252(ch, out),
        Encoding::Iso88592 => encode_iso88592(ch, out),
        Encoding::Iso88594 => encode_iso88594(ch, out),
        Encoding::Iso88595 => encode_iso88595(ch, out),
        Encoding::Iso88597 => encode_iso88597(ch, out),
        Encoding::Iso88599 => encode_iso88599(ch, out),
        Encoding::Iso885913 => encode_iso885913(ch, out),
        Encoding::Iso885915 => encode_iso885915(ch, out),
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

    #[test]
    fn cp1252_to_utf8_round_trip() {
        // CP1252 bytes: curly quotes ""
        // " = 0x93, " = 0x94
        let cp1252_input: &[u8] = &[0x93, 0x94];
        let expected_utf8 = "\u{201C}\u{201D}";

        // CP1252 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"CP1252").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp1252_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 2);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → CP1252 (reverse)
        let mut cd2 = iconv_open(b"CP1252", b"UTF-8").unwrap();
        let mut cp1252_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1252_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&cp1252_out[..result2.out_written], cp1252_input);
    }

    #[test]
    fn cp1252_accepts_windows1252_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1252");
        assert!(cd.is_some());
    }

    #[test]
    fn koi8u_to_utf8_round_trip() {
        // KOI8-U bytes for "Київ" (Kyiv with Ukrainian-specific chars)
        // К=0xEB, и=0xC9, ї=0xB7, в=0xD7
        let koi8u_input: &[u8] = &[0xEB, 0xC9, 0xB7, 0xD7];
        let expected_utf8 = "Київ";

        // KOI8-U → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"KOI8-U").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(koi8u_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 4);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → KOI8-U (reverse)
        let mut cd2 = iconv_open(b"KOI8-U", b"UTF-8").unwrap();
        let mut koi8u_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut koi8u_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&koi8u_out[..result2.out_written], koi8u_input);
    }

    #[test]
    fn koi8u_differs_from_koi8r() {
        // Ukrainian Ї (yi) is at 0xB7 in KOI8-U but 0xB7 is · in KOI8-R
        let koi8u_yi: &[u8] = &[0xB7];

        let mut cd = iconv_open(b"UTF-8", b"KOI8-U").unwrap();
        let mut utf8_out = [0u8; 8];
        let result = iconv(&mut cd, Some(koi8u_yi), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, "ї"); // Ukrainian yi
    }

    #[test]
    fn iso88595_to_utf8_round_trip() {
        // ISO-8859-5 bytes for "Привет" (same as KOI8-R but different byte values)
        // П=0xBF, р=0xE0, и=0xD8, в=0xD2, е=0xD5, т=0xE2
        let iso_input: &[u8] = &[0xBF, 0xE0, 0xD8, 0xD2, 0xD5, 0xE2];
        let expected_utf8 = "Привет";

        // ISO-8859-5 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-5").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 6);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-5 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-5", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88595_accepts_cyrillic_alias() {
        let cd = iconv_open(b"UTF-8", b"CYRILLIC");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88597_to_utf8_round_trip() {
        // ISO-8859-7 bytes for "Ελλάδα" (Greece)
        // Ε=0xC5, λ=0xEB, λ=0xEB, ά=0xDC, δ=0xE4, α=0xE1
        let iso_input: &[u8] = &[0xC5, 0xEB, 0xEB, 0xDC, 0xE4, 0xE1];
        let expected_utf8 = "Ελλάδα";

        // ISO-8859-7 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-7").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 6);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-7 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-7", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88597_accepts_greek_alias() {
        let cd = iconv_open(b"UTF-8", b"GREEK");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88599_to_utf8_round_trip() {
        // ISO-8859-9 bytes for "Türkçe" (Turkish)
        // T=0x54, ü=0xFC, r=0x72, k=0x6B, ç=0xE7, e=0x65
        // Note: ç (0xE7) is same as Latin-1, ü (0xFC) is same as Latin-1
        let iso_input: &[u8] = &[0x54, 0xFC, 0x72, 0x6B, 0xE7, 0x65];
        let expected_utf8 = "Türkçe";

        // ISO-8859-9 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-9").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 6);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-9 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-9", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88599_accepts_turkish_alias() {
        let cd = iconv_open(b"UTF-8", b"TURKISH");
        assert!(cd.is_some());
    }

    #[test]
    fn iso885913_to_utf8_round_trip() {
        // ISO-8859-13 bytes for "Łódź" (Polish city with Polish chars)
        // Ł=0xD9, ó=0xF3, d=0x64, ź=0xF9
        let iso_input: &[u8] = &[0xD9, 0xF3, 0x64, 0xEA];
        let expected_utf8 = "Łódź";

        // ISO-8859-13 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-13").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 4);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-13 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-13", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso885913_accepts_latin7_alias() {
        let cd = iconv_open(b"UTF-8", b"LATIN7");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88592_to_utf8_round_trip() {
        // ISO-8859-2 bytes for "Čeština" (Czech)
        // Č=0xC8, e=0x65, š=0xB9, t=0x74, i=0x69, n=0x6E, a=0x61
        let iso_input: &[u8] = &[0xC8, 0x65, 0xB9, 0x74, 0x69, 0x6E, 0x61];
        let expected_utf8 = "Čeština";

        // ISO-8859-2 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-2").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 7);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-2 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-2", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88592_accepts_latin2_alias() {
        let cd = iconv_open(b"UTF-8", b"LATIN2");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88594_to_utf8_round_trip() {
        // ISO-8859-4 bytes for "Rīga" (Latvian capital)
        // R=0x52, ī=0xEF, g=0x67, a=0x61
        let iso_input: &[u8] = &[0x52, 0xEF, 0x67, 0x61];
        let expected_utf8 = "Rīga";

        // ISO-8859-4 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-4").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 4);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-4 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-4", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88594_accepts_latin4_alias() {
        let cd = iconv_open(b"UTF-8", b"LATIN4");
        assert!(cd.is_some());
    }

    #[test]
    fn iso885915_euro_sign_round_trip() {
        // ISO-8859-15 byte 0xA4 is Euro sign (€), not currency sign (¤)
        let iso_input: &[u8] = &[0xA4];
        let expected_utf8 = "€";

        // ISO-8859-15 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-15").unwrap();
        let mut utf8_out = [0u8; 8];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-15 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-15", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 8];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso885915_latin1_currency_sign_unrepresentable() {
        // Currency sign (¤, U+00A4) is NOT in ISO-8859-15 (replaced by Euro)
        let mut cd = iconv_open(b"ISO-8859-15", b"UTF-8").unwrap();
        let mut out = [0u8; 8];
        let err = iconv(&mut cd, Some("¤".as_bytes()), &mut out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
    }

    #[test]
    fn iso885915_accepts_latin9_alias() {
        let cd = iconv_open(b"UTF-8", b"LATIN9");
        assert!(cd.is_some());
    }
}
