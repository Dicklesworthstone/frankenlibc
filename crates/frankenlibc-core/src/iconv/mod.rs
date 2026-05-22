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
    Utf16Be,
    Utf32,
    Utf32Be,
    Koi8R,
    Koi8U,
    Cp437,
    Cp1250,
    Cp1251,
    Cp1252,
    Cp1253,
    Cp1254,
    Cp1255,
    Cp1256,
    Cp1257,
    Cp1258,
    Cp874,
    Cp866,
    Cp850,
    MacRoman,
    Iso88592,
    Iso88593,
    Iso88594,
    Iso88595,
    Iso88596,
    Iso88597,
    Iso88598,
    Iso88599,
    Iso885910,
    Iso885911,
    Iso885913,
    Iso885914,
    Iso885915,
    Iso885916,
    EucJp,
    ShiftJis,
    Big5,
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

const PHASE1_CODEC_TABLE: [CodecSpec; 40] = [
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
        encoding: Encoding::Utf16Be,
        canonical: "UTF-16BE",
        normalized: "UTF16BE",
        aliases: &["UTF16BE"],
    },
    CodecSpec {
        encoding: Encoding::Utf32,
        canonical: "UTF-32",
        normalized: "UTF32",
        aliases: &["UTF32"],
    },
    CodecSpec {
        encoding: Encoding::Utf32Be,
        canonical: "UTF-32BE",
        normalized: "UTF32BE",
        aliases: &["UTF32BE"],
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
        encoding: Encoding::Cp1250,
        canonical: "CP1250",
        normalized: "CP1250",
        aliases: &["WINDOWS1250", "1250"],
    },
    CodecSpec {
        encoding: Encoding::Cp1251,
        canonical: "CP1251",
        normalized: "CP1251",
        aliases: &["WINDOWS1251", "1251"],
    },
    CodecSpec {
        encoding: Encoding::Cp1253,
        canonical: "CP1253",
        normalized: "CP1253",
        aliases: &["WINDOWS1253", "1253"],
    },
    CodecSpec {
        encoding: Encoding::Cp1254,
        canonical: "CP1254",
        normalized: "CP1254",
        aliases: &["WINDOWS1254", "1254"],
    },
    CodecSpec {
        encoding: Encoding::Cp1255,
        canonical: "CP1255",
        normalized: "CP1255",
        aliases: &["WINDOWS1255", "1255"],
    },
    CodecSpec {
        encoding: Encoding::Cp1256,
        canonical: "CP1256",
        normalized: "CP1256",
        aliases: &["WINDOWS1256", "1256"],
    },
    CodecSpec {
        encoding: Encoding::Cp1257,
        canonical: "CP1257",
        normalized: "CP1257",
        aliases: &["WINDOWS1257", "1257"],
    },
    CodecSpec {
        encoding: Encoding::Cp1258,
        canonical: "CP1258",
        normalized: "CP1258",
        aliases: &["WINDOWS1258", "1258"],
    },
    CodecSpec {
        encoding: Encoding::Cp874,
        canonical: "CP874",
        normalized: "CP874",
        aliases: &["WINDOWS874", "874", "TIS620"],
    },
    CodecSpec {
        encoding: Encoding::Cp866,
        canonical: "CP866",
        normalized: "CP866",
        aliases: &["IBM866", "866", "CSIBM866"],
    },
    CodecSpec {
        encoding: Encoding::Cp850,
        canonical: "CP850",
        normalized: "CP850",
        aliases: &["IBM850", "850", "CSPC850MULTILINGUAL"],
    },
    CodecSpec {
        encoding: Encoding::MacRoman,
        canonical: "MACROMAN",
        normalized: "MACROMAN",
        aliases: &["MACINTOSH", "MAC", "CSMACINTOSH"],
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
        encoding: Encoding::Iso88593,
        canonical: "ISO-8859-3",
        normalized: "ISO88593",
        aliases: &["ISO88593", "LATIN3", "CSISOLATIN3"],
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
        encoding: Encoding::Iso88596,
        canonical: "ISO-8859-6",
        normalized: "ISO88596",
        aliases: &["ISO88596", "ARABIC", "CSISOLATINARABIC", "ASMO708", "ECMA114"],
    },
    CodecSpec {
        encoding: Encoding::Iso88597,
        canonical: "ISO-8859-7",
        normalized: "ISO88597",
        aliases: &["ISO88597", "GREEK", "GREEK8", "CSISOLATINGREEK", "ELOT928", "ECMA118"],
    },
    CodecSpec {
        encoding: Encoding::Iso88598,
        canonical: "ISO-8859-8",
        normalized: "ISO88598",
        aliases: &["ISO88598", "HEBREW", "CSISOLATINHEBREW"],
    },
    CodecSpec {
        encoding: Encoding::Iso88599,
        canonical: "ISO-8859-9",
        normalized: "ISO88599",
        aliases: &["ISO88599", "LATIN5", "CSISOLATIN5", "TURKISH"],
    },
    CodecSpec {
        encoding: Encoding::Iso885910,
        canonical: "ISO-8859-10",
        normalized: "ISO885910",
        aliases: &["ISO885910", "LATIN6", "CSISOLATIN6", "NORDIC"],
    },
    CodecSpec {
        encoding: Encoding::Iso885911,
        canonical: "ISO-8859-11",
        normalized: "ISO885911",
        aliases: &["ISO885911", "THAI"],
    },
    CodecSpec {
        encoding: Encoding::Iso885913,
        canonical: "ISO-8859-13",
        normalized: "ISO885913",
        aliases: &["ISO885913", "LATIN7", "CSISOLATIN7", "BALTICRIM"],
    },
    CodecSpec {
        encoding: Encoding::Iso885914,
        canonical: "ISO-8859-14",
        normalized: "ISO885914",
        aliases: &["ISO885914", "LATIN8", "CSISOLATIN8", "CELTIC", "ISOCELTIC"],
    },
    CodecSpec {
        encoding: Encoding::Iso885915,
        canonical: "ISO-8859-15",
        normalized: "ISO885915",
        aliases: &["ISO885915", "LATIN9", "CSISOLATIN9"],
    },
    CodecSpec {
        encoding: Encoding::Iso885916,
        canonical: "ISO-8859-16",
        normalized: "ISO885916",
        aliases: &["ISO885916", "LATIN10", "CSISOLATIN10", "ROMANIAN"],
    },
    CodecSpec {
        encoding: Encoding::EucJp,
        canonical: "EUC-JP",
        normalized: "EUCJP",
        aliases: &["EUCJP", "CSEUCPKDFMTJAPANESE", "UJIS"],
    },
    CodecSpec {
        encoding: Encoding::ShiftJis,
        canonical: "SHIFT_JIS",
        normalized: "SHIFTJIS",
        aliases: &["SHIFTJIS", "SJIS", "CP932", "MS_KANJI", "CSSHIFTJIS"],
    },
    CodecSpec {
        encoding: Encoding::Big5,
        canonical: "BIG5",
        normalized: "BIG5",
        aliases: &["CSBIG5", "BIG5TW", "BIGFIVE"],
    },
];

const PHASE1_EXCLUDED_CODEC_TABLE: [ExcludedCodecSpec; 4] = [
    ExcludedCodecSpec {
        canonical: "ISO-2022-CN-EXT",
        normalized: "ISO2022CNEXT",
    },
    ExcludedCodecSpec {
        canonical: "ISO-2022-JP",
        normalized: "ISO2022JP",
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
pub const ICONV_PHASE1_INCLUDED_CODECS: [&str; 40] =
    ["UTF-8", "ASCII", "ISO-8859-1", "UTF-16LE", "UTF-16BE", "UTF-32", "UTF-32BE", "KOI8-R", "KOI8-U", "CP437", "CP850", "CP866", "CP874", "MACROMAN", "CP1250", "CP1251", "CP1252", "CP1253", "CP1254", "CP1255", "CP1256", "CP1257", "CP1258", "ISO-8859-2", "ISO-8859-3", "ISO-8859-4", "ISO-8859-5", "ISO-8859-6", "ISO-8859-7", "ISO-8859-8", "ISO-8859-9", "ISO-8859-10", "ISO-8859-11", "ISO-8859-13", "ISO-8859-14", "ISO-8859-15", "ISO-8859-16", "EUC-JP", "SHIFT_JIS", "BIG5"];

/// Canonical alias map for phase-1 supported codecs.
pub const ICONV_PHASE1_ALIAS_NORMALIZATIONS: [(&str, &str); 5] = [
    ("LATIN1", "ISO-8859-1"),
    ("USASCII", "ASCII"),
    ("ANSIX3.41968", "ASCII"),
    ("ANSIX341968", "ASCII"),
    ("ISO646US", "ASCII"),
];

/// Known out-of-scope codec families for phase-1 implementation.
pub const ICONV_PHASE1_EXCLUDED_CODEC_FAMILIES: [&str; 4] = [
    "ISO-2022-CN-EXT",
    "ISO-2022-JP",
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

fn decode_utf16be(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.len() < 2 {
        return Err(DecodeError::Incomplete);
    }

    let u1 = u16::from_be_bytes([input[0], input[1]]);
    if (0xD800..=0xDBFF).contains(&u1) {
        if input.len() < 4 {
            return Err(DecodeError::Incomplete);
        }
        let u2 = u16::from_be_bytes([input[2], input[3]]);
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

fn decode_utf32be(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.len() < 4 {
        return Err(DecodeError::Incomplete);
    }

    let cp = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
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

/// Windows-1250 (CP1250/Central European) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const CP1250_TO_UNICODE: [u16; 128] = [
    0x20AC, 0xFFFF, 0x201A, 0xFFFF, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0xFFFF, 0x2030, 0x0160, 0x2039, 0x015A, 0x0164, 0x017D, 0x0179, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0x2122, 0x0161, 0x203A, 0x015B, 0x0165, 0x017E, 0x017A, // 98-9F
    0x00A0, 0x02C7, 0x02D8, 0x0141, 0x00A4, 0x0104, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x015E, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x017B, // A8-AF
    0x00B0, 0x00B1, 0x02DB, 0x0142, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x0105, 0x015F, 0x00BB, 0x013D, 0x02DD, 0x013E, 0x017C, // B8-BF
    0x0154, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0139, 0x0106, 0x00C7, // C0-C7
    0x010C, 0x00C9, 0x0118, 0x00CB, 0x011A, 0x00CD, 0x00CE, 0x010E, // C8-CF
    0x0110, 0x0143, 0x0147, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x00D7, // D0-D7
    0x0158, 0x016E, 0x00DA, 0x0170, 0x00DC, 0x00DD, 0x0162, 0x00DF, // D8-DF
    0x0155, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x013A, 0x0107, 0x00E7, // E0-E7
    0x010D, 0x00E9, 0x0119, 0x00EB, 0x011B, 0x00ED, 0x00EE, 0x010F, // E8-EF
    0x0111, 0x0144, 0x0148, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x00F7, // F0-F7
    0x0159, 0x016F, 0x00FA, 0x0171, 0x00FC, 0x00FD, 0x0163, 0x02D9, // F8-FF
];

fn decode_cp1250(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1250_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1250(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1250_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1251 (CP1251/Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
const CP1251_TO_UNICODE: [u16; 128] = [
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F, // 88-8F
    0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F, // 98-9F
    0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7, // A0-A7
    0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407, // A8-AF
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457, // B8-BF
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // C0-C7
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // C8-CF
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // D0-D7
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // D8-DF
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // E0-E7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // E8-EF
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // F0-F7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // F8-FF
];

fn decode_cp1251(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1251_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1251(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1251_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1253 (CP1253/Greek) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const CP1253_TO_UNICODE: [u16; 128] = [
    0x20AC, 0xFFFF, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0xFFFF, 0x2030, 0xFFFF, 0x2039, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0x2122, 0xFFFF, 0x203A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 98-9F
    0x00A0, 0x0385, 0x0386, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0xFFFF, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x2015, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x0384, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x0388, 0x0389, 0x038A, 0x00BB, 0x038C, 0x00BD, 0x038E, 0x038F, // B8-BF
    0x0390, 0x0391, 0x0392, 0x0393, 0x0394, 0x0395, 0x0396, 0x0397, // C0-C7
    0x0398, 0x0399, 0x039A, 0x039B, 0x039C, 0x039D, 0x039E, 0x039F, // C8-CF
    0x03A0, 0x03A1, 0xFFFF, 0x03A3, 0x03A4, 0x03A5, 0x03A6, 0x03A7, // D0-D7
    0x03A8, 0x03A9, 0x03AA, 0x03AB, 0x03AC, 0x03AD, 0x03AE, 0x03AF, // D8-DF
    0x03B0, 0x03B1, 0x03B2, 0x03B3, 0x03B4, 0x03B5, 0x03B6, 0x03B7, // E0-E7
    0x03B8, 0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, 0x03BE, 0x03BF, // E8-EF
    0x03C0, 0x03C1, 0x03C2, 0x03C3, 0x03C4, 0x03C5, 0x03C6, 0x03C7, // F0-F7
    0x03C8, 0x03C9, 0x03CA, 0x03CB, 0x03CC, 0x03CD, 0x03CE, 0xFFFF, // F8-FF
];

fn decode_cp1253(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1253_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1253(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1253_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1254 (CP1254/Turkish) to Unicode mapping for bytes 0x80-0xFF.
/// Very similar to ISO-8859-9 (0xA0-0xFF) with typographic chars in 0x80-0x9F.
/// 0xFFFF marks undefined positions.
const CP1254_TO_UNICODE: [u16; 128] = [
    0x20AC, 0xFFFF, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFF, 0xFFFF, 0x0178, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x011E, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x0130, 0x015E, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x011F, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x0131, 0x015F, 0x00FF, // F8-FF
];

fn decode_cp1254(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1254_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1254(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1254_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1255 (CP1255/Hebrew) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const CP1255_TO_UNICODE: [u16; 128] = [
    0x20AC, 0xFFFF, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0xFFFF, 0x2039, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0xFFFF, 0x203A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x20AA, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00D7, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00F7, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x05B0, 0x05B1, 0x05B2, 0x05B3, 0x05B4, 0x05B5, 0x05B6, 0x05B7, // C0-C7
    0x05B8, 0x05B9, 0x05BA, 0x05BB, 0x05BC, 0x05BD, 0x05BE, 0x05BF, // C8-CF
    0x05C0, 0x05C1, 0x05C2, 0x05C3, 0x05F0, 0x05F1, 0x05F2, 0x05F3, // D0-D7
    0x05F4, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, 0x05D6, 0x05D7, // E0-E7
    0x05D8, 0x05D9, 0x05DA, 0x05DB, 0x05DC, 0x05DD, 0x05DE, 0x05DF, // E8-EF
    0x05E0, 0x05E1, 0x05E2, 0x05E3, 0x05E4, 0x05E5, 0x05E6, 0x05E7, // F0-F7
    0x05E8, 0x05E9, 0x05EA, 0xFFFF, 0xFFFF, 0x200E, 0x200F, 0xFFFF, // F8-FF
];

fn decode_cp1255(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1255_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1255(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1255_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1256 (CP1256/Arabic) to Unicode mapping for bytes 0x80-0xFF.
const CP1256_TO_UNICODE: [u16; 128] = [
    0x20AC, 0x067E, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0x0679, 0x2039, 0x0152, 0x0686, 0x0698, 0x0688, // 88-8F
    0x06AF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x06A9, 0x2122, 0x0691, 0x203A, 0x0153, 0x200C, 0x200D, 0x06BA, // 98-9F
    0x00A0, 0x060C, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x06BE, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x061B, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x061F, // B8-BF
    0x06C1, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627, // C0-C7
    0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F, // C8-CF
    0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x00D7, // D0-D7
    0x0637, 0x0638, 0x0639, 0x063A, 0x0640, 0x0641, 0x0642, 0x0643, // D8-DF
    0x00E0, 0x0644, 0x00E2, 0x0645, 0x0646, 0x0647, 0x0648, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x0649, 0x064A, 0x00EE, 0x00EF, // E8-EF
    0x064B, 0x064C, 0x064D, 0x064E, 0x00F4, 0x064F, 0x0650, 0x00F7, // F0-F7
    0x0651, 0x00F9, 0x0652, 0x00FB, 0x00FC, 0x200E, 0x200F, 0x06D2, // F8-FF
];

fn decode_cp1256(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1256_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1256(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1256_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1257 (CP1257/Baltic) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const CP1257_TO_UNICODE: [u16; 128] = [
    0x20AC, 0xFFFF, 0x201A, 0xFFFF, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0xFFFF, 0x2030, 0xFFFF, 0x2039, 0xFFFF, 0x00A8, 0x02C7, 0x00B8, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0x2122, 0xFFFF, 0x203A, 0xFFFF, 0x00AF, 0x02DB, 0xFFFF, // 98-9F
    0x00A0, 0xFFFF, 0x00A2, 0x00A3, 0x00A4, 0xFFFF, 0x00A6, 0x00A7, // A0-A7
    0x00D8, 0x00A9, 0x0156, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00C6, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00F8, 0x00B9, 0x0157, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00E6, // B8-BF
    0x0104, 0x012E, 0x0100, 0x0106, 0x00C4, 0x00C5, 0x0118, 0x0112, // C0-C7
    0x010C, 0x00C9, 0x0179, 0x0116, 0x0122, 0x0136, 0x012A, 0x013B, // C8-CF
    0x0160, 0x0143, 0x0145, 0x00D3, 0x014C, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x0172, 0x0141, 0x015A, 0x016A, 0x00DC, 0x017B, 0x017D, 0x00DF, // D8-DF
    0x0105, 0x012F, 0x0101, 0x0107, 0x00E4, 0x00E5, 0x0119, 0x0113, // E0-E7
    0x010D, 0x00E9, 0x017A, 0x0117, 0x0123, 0x0137, 0x012B, 0x013C, // E8-EF
    0x0161, 0x0144, 0x0146, 0x00F3, 0x014D, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x0173, 0x0142, 0x015B, 0x016B, 0x00FC, 0x017C, 0x017E, 0x02D9, // F8-FF
];

fn decode_cp1257(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1257_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1257(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1257_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-1258 (CP1258/Vietnamese) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const CP1258_TO_UNICODE: [u16; 128] = [
    0x20AC, 0xFFFF, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0xFFFF, 0x2039, 0x0152, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0xFFFF, 0x203A, 0x0153, 0xFFFF, 0xFFFF, 0x0178, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x0300, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x0110, 0x00D1, 0x0309, 0x00D3, 0x00D4, 0x01A0, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x01AF, 0x0303, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x0301, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x0111, 0x00F1, 0x0323, 0x00F3, 0x00F4, 0x01A1, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x01B0, 0x20AB, 0x00FF, // F8-FF
];

fn decode_cp1258(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1258_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp1258(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1258_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Windows-874 (CP874/Thai/TIS-620) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const CP874_TO_UNICODE: [u16; 128] = [
    0x20AC, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x2026, 0xFFFF, 0xFFFF, // 80-87
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 98-9F
    0x00A0, 0x0E01, 0x0E02, 0x0E03, 0x0E04, 0x0E05, 0x0E06, 0x0E07, // A0-A7
    0x0E08, 0x0E09, 0x0E0A, 0x0E0B, 0x0E0C, 0x0E0D, 0x0E0E, 0x0E0F, // A8-AF
    0x0E10, 0x0E11, 0x0E12, 0x0E13, 0x0E14, 0x0E15, 0x0E16, 0x0E17, // B0-B7
    0x0E18, 0x0E19, 0x0E1A, 0x0E1B, 0x0E1C, 0x0E1D, 0x0E1E, 0x0E1F, // B8-BF
    0x0E20, 0x0E21, 0x0E22, 0x0E23, 0x0E24, 0x0E25, 0x0E26, 0x0E27, // C0-C7
    0x0E28, 0x0E29, 0x0E2A, 0x0E2B, 0x0E2C, 0x0E2D, 0x0E2E, 0x0E2F, // C8-CF
    0x0E30, 0x0E31, 0x0E32, 0x0E33, 0x0E34, 0x0E35, 0x0E36, 0x0E37, // D0-D7
    0x0E38, 0x0E39, 0x0E3A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0E3F, // D8-DF
    0x0E40, 0x0E41, 0x0E42, 0x0E43, 0x0E44, 0x0E45, 0x0E46, 0x0E47, // E0-E7
    0x0E48, 0x0E49, 0x0E4A, 0x0E4B, 0x0E4C, 0x0E4D, 0x0E4E, 0x0E4F, // E8-EF
    0x0E50, 0x0E51, 0x0E52, 0x0E53, 0x0E54, 0x0E55, 0x0E56, 0x0E57, // F0-F7
    0x0E58, 0x0E59, 0x0E5A, 0x0E5B, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_cp874(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP874_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp874(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP874_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP866 (DOS Russian/OEM Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
const CP866_TO_UNICODE: [u16; 128] = [
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87 (А-З)
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F (И-П)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97 (Р-Ч)
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F (Ш-Я)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // A0-A7 (а-з)
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // A8-AF (и-п)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7 (box)
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF (box)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7 (box)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF (box)
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7 (box)
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF (box)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // E0-E7 (р-ч)
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // E8-EF (ш-я)
    0x0401, 0x0451, 0x0404, 0x0454, 0x0407, 0x0457, 0x040E, 0x045E, // F0-F7 (Ё,ё,Є,є,Ї,ї,Ў,ў)
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x2116, 0x00A4, 0x25A0, 0x00A0, // F8-FF (°,∙,·,√,№,¤,■,nbsp)
];

fn decode_cp866(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP866_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp866(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP866_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP850 (DOS Western European/Multilingual Latin 1) to Unicode mapping for bytes 0x80-0xFF.
const CP850_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, // 88-8F
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, // 90-97
    0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x0192, // 98-9F
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x00C0, // B0-B7
    0x00A9, 0x2563, 0x2551, 0x2557, 0x255D, 0x00A2, 0x00A5, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E3, 0x00C3, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, // C8-CF
    0x00F0, 0x00D0, 0x00CA, 0x00CB, 0x00C8, 0x0131, 0x00CD, 0x00CE, // D0-D7
    0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580, // D8-DF
    0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0x00FE, // E0-E7
    0x00DE, 0x00DA, 0x00DB, 0x00D9, 0x00FD, 0x00DD, 0x00AF, 0x00B4, // E8-EF
    0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8, // F0-F7
    0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp850(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP850_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp850(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP850_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// MacRoman (Apple Macintosh Roman) to Unicode mapping for bytes 0x80-0xFF.
const MACROMAN_TO_UNICODE: [u16; 128] = [
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, // 80-87
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E8, // 88-8F
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3, // 90-97
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC, // 98-9F
    0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6, 0x00DF, // A0-A7
    0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6, 0x00D8, // A8-AF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202, 0x2211, // B0-B7
    0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x00E6, 0x00F8, // B8-BF
    0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB, // C0-C7
    0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152, 0x0153, // C8-CF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x25CA, // D0-D7
    0x00FF, 0x0178, 0x2044, 0x20AC, 0x2039, 0x203A, 0xFB01, 0xFB02, // D8-DF
    0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA, 0x00C1, // E0-E7
    0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3, 0x00D4, // E8-EF
    0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6, 0x02DC, // F0-F7
    0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB, 0x02C7, // F8-FF
];

fn decode_macroman(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACROMAN_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_macroman(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACROMAN_TO_UNICODE.iter().enumerate() {
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

/// ISO-8859-3 (Latin-3/South European) to Unicode mapping for bytes 0xA0-0xFF.
/// 0xFFFF marks undefined positions.
const ISO88593_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0126, 0x02D8, 0x00A3, 0x00A4, 0xFFFF, 0x0124, 0x00A7, // A0-A7
    0x00A8, 0x0130, 0x015E, 0x011E, 0x0134, 0x00AD, 0xFFFF, 0x017B, // A8-AF
    0x00B0, 0x0127, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x0125, 0x00B7, // B0-B7
    0x00B8, 0x0131, 0x015F, 0x011F, 0x0135, 0x00BD, 0xFFFF, 0x017C, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0xFFFF, 0x00C4, 0x010A, 0x0108, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0xFFFF, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x0120, 0x00D6, 0x00D7, // D0-D7
    0x011C, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x016C, 0x015C, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0xFFFF, 0x00E4, 0x010B, 0x0109, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0xFFFF, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x0121, 0x00F6, 0x00F7, // F0-F7
    0x011D, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x016D, 0x015D, 0x02D9, // F8-FF
];

fn decode_iso88593(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88593_TO_UNICODE[(b - 0xA0) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso88593(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO88593_TO_UNICODE.iter().enumerate() {
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

/// ISO-8859-6 (Arabic) to Unicode mapping for bytes 0xA0-0xFF.
/// Many positions are undefined (0xFFFF marks these).
const ISO88596_TO_UNICODE: [u16; 96] = [
    0x00A0, 0xFFFF, 0xFFFF, 0xFFFF, 0x00A4, 0xFFFF, 0xFFFF, 0xFFFF, // A0-A7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x060C, 0x00AD, 0xFFFF, 0xFFFF, // A8-AF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // B0-B7
    0xFFFF, 0xFFFF, 0xFFFF, 0x061B, 0xFFFF, 0xFFFF, 0xFFFF, 0x061F, // B8-BF
    0xFFFF, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627, // C0-C7
    0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F, // C8-CF
    0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x0637, // D0-D7
    0x0638, 0x0639, 0x063A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    0x0640, 0x0641, 0x0642, 0x0643, 0x0644, 0x0645, 0x0646, 0x0647, // E0-E7
    0x0648, 0x0649, 0x064A, 0x064B, 0x064C, 0x064D, 0x064E, 0x064F, // E8-EF
    0x0650, 0x0651, 0x0652, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_iso88596(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88596_TO_UNICODE[(b - 0xA0) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso88596(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO88596_TO_UNICODE.iter().enumerate() {
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

/// ISO-8859-8 (Hebrew) to Unicode mapping for bytes 0xA0-0xFF.
/// Many positions are undefined (0xFFFF marks these).
const ISO88598_TO_UNICODE: [u16; 96] = [
    0x00A0, 0xFFFF, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00D7, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00F7, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0xFFFF, // B8-BF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C0-C7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x2017, // D8-DF
    0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, 0x05D6, 0x05D7, // E0-E7
    0x05D8, 0x05D9, 0x05DA, 0x05DB, 0x05DC, 0x05DD, 0x05DE, 0x05DF, // E8-EF
    0x05E0, 0x05E1, 0x05E2, 0x05E3, 0x05E4, 0x05E5, 0x05E6, 0x05E7, // F0-F7
    0x05E8, 0x05E9, 0x05EA, 0xFFFF, 0xFFFF, 0x200E, 0x200F, 0xFFFF, // F8-FF
];

fn decode_iso88598(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88598_TO_UNICODE[(b - 0xA0) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso88598(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO88598_TO_UNICODE.iter().enumerate() {
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

/// ISO-8859-10 (Latin-6/Nordic) to Unicode mapping for bytes 0xA0-0xFF.
const ISO885910_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0104, 0x0112, 0x0122, 0x012A, 0x0128, 0x0136, 0x00A7, // A0-A7
    0x013B, 0x0110, 0x0160, 0x0166, 0x017D, 0x00AD, 0x016A, 0x014A, // A8-AF
    0x00B0, 0x0105, 0x0113, 0x0123, 0x012B, 0x0129, 0x0137, 0x00B7, // B0-B7
    0x013C, 0x0111, 0x0161, 0x0167, 0x017E, 0x2015, 0x016B, 0x014B, // B8-BF
    0x0100, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x012E, // C0-C7
    0x010C, 0x00C9, 0x0118, 0x00CB, 0x0116, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x00D0, 0x0145, 0x014C, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x0168, // D0-D7
    0x00D8, 0x0172, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF, // D8-DF
    0x0101, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x012F, // E0-E7
    0x010D, 0x00E9, 0x0119, 0x00EB, 0x0117, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x00F0, 0x0146, 0x014D, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x0169, // F0-F7
    0x00F8, 0x0173, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x0138, // F8-FF
];

fn decode_iso885910(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO885910_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso885910(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO885910_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ISO-8859-11 (Thai) to Unicode mapping for bytes 0xA0-0xFF.
/// 0xFFFF marks undefined positions (0xDB-0xDE, 0xFC-0xFF).
const ISO885911_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0E01, 0x0E02, 0x0E03, 0x0E04, 0x0E05, 0x0E06, 0x0E07, // A0-A7
    0x0E08, 0x0E09, 0x0E0A, 0x0E0B, 0x0E0C, 0x0E0D, 0x0E0E, 0x0E0F, // A8-AF
    0x0E10, 0x0E11, 0x0E12, 0x0E13, 0x0E14, 0x0E15, 0x0E16, 0x0E17, // B0-B7
    0x0E18, 0x0E19, 0x0E1A, 0x0E1B, 0x0E1C, 0x0E1D, 0x0E1E, 0x0E1F, // B8-BF
    0x0E20, 0x0E21, 0x0E22, 0x0E23, 0x0E24, 0x0E25, 0x0E26, 0x0E27, // C0-C7
    0x0E28, 0x0E29, 0x0E2A, 0x0E2B, 0x0E2C, 0x0E2D, 0x0E2E, 0x0E2F, // C8-CF
    0x0E30, 0x0E31, 0x0E32, 0x0E33, 0x0E34, 0x0E35, 0x0E36, 0x0E37, // D0-D7
    0x0E38, 0x0E39, 0x0E3A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0E3F, // D8-DF
    0x0E40, 0x0E41, 0x0E42, 0x0E43, 0x0E44, 0x0E45, 0x0E46, 0x0E47, // E0-E7
    0x0E48, 0x0E49, 0x0E4A, 0x0E4B, 0x0E4C, 0x0E4D, 0x0E4E, 0x0E4F, // E8-EF
    0x0E50, 0x0E51, 0x0E52, 0x0E53, 0x0E54, 0x0E55, 0x0E56, 0x0E57, // F0-F7
    0x0E58, 0x0E59, 0x0E5A, 0x0E5B, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_iso885911(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO885911_TO_UNICODE[(b - 0xA0) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso885911(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO885911_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
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

/// ISO-8859-14 (Latin-8/Celtic) to Unicode mapping for bytes 0xA0-0xFF.
const ISO885914_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x1E02, 0x1E03, 0x00A3, 0x010A, 0x010B, 0x1E0A, 0x00A7, // A0-A7
    0x1E80, 0x00A9, 0x1E82, 0x1E0B, 0x1EF2, 0x00AD, 0x00AE, 0x0178, // A8-AF
    0x1E1E, 0x1E1F, 0x0120, 0x0121, 0x1E40, 0x1E41, 0x00B6, 0x1E56, // B0-B7
    0x1E81, 0x1E57, 0x1E83, 0x1E60, 0x1EF3, 0x1E84, 0x1E85, 0x1E61, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x0174, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x1E6A, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x0176, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x0175, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x1E6B, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x0177, 0x00FF, // F8-FF
];

fn decode_iso885914(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO885914_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso885914(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO885914_TO_UNICODE.iter().enumerate() {
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

/// ISO-8859-16 (Latin-10/Romanian) to Unicode mapping for bytes 0xA0-0xFF.
const ISO885916_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0104, 0x0105, 0x0141, 0x20AC, 0x201E, 0x0160, 0x00A7, // A0-A7
    0x0161, 0x00A9, 0x0218, 0x00AB, 0x0179, 0x00AD, 0x017A, 0x017B, // A8-AF
    0x00B0, 0x00B1, 0x010C, 0x0142, 0x017D, 0x201D, 0x00B6, 0x00B7, // B0-B7
    0x017E, 0x010D, 0x0219, 0x00BB, 0x0152, 0x0153, 0x0178, 0x017C, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0106, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x0110, 0x0143, 0x00D2, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x015A, // D0-D7
    0x0170, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x0118, 0x021A, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x0107, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x0111, 0x0144, 0x00F2, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x015B, // F0-F7
    0x0171, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x0119, 0x021B, 0x00FF, // F8-FF
];

fn decode_iso885916(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO885916_TO_UNICODE[(b - 0xA0) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_iso885916(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO885916_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

fn decode_eucjp(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b0 = input[0];
    if b0 <= 0x7F {
        return Ok((char::from(b0), 1));
    }
    if b0 == 0x8E {
        if input.len() < 2 {
            return Err(DecodeError::Incomplete);
        }
        let b1 = input[1];
        if (0xA1..=0xDF).contains(&b1) {
            let cp = 0xFF61 + u32::from(b1 - 0xA1);
            return Ok((char::from_u32(cp).unwrap_or('\u{FFFD}'), 2));
        }
        return Err(DecodeError::Invalid);
    }
    if b0 == 0x8F {
        if input.len() < 3 {
            return Err(DecodeError::Incomplete);
        }
        return Err(DecodeError::Invalid);
    }
    if (0xA1..=0xFE).contains(&b0) {
        if input.len() < 2 {
            return Err(DecodeError::Incomplete);
        }
        let b1 = input[1];
        if !(0xA1..=0xFE).contains(&b1) {
            return Err(DecodeError::Invalid);
        }
        return Err(DecodeError::Invalid);
    }
    Err(DecodeError::Invalid)
}

fn encode_eucjp(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    let cp = ch as u32;
    if cp <= 0x7F {
        if out.is_empty() {
            return Err(EncodeError::NoSpace);
        }
        out[0] = cp as u8;
        return Ok(1);
    }
    if (0xFF61..=0xFF9F).contains(&cp) {
        if out.len() < 2 {
            return Err(EncodeError::NoSpace);
        }
        out[0] = 0x8E;
        out[1] = (cp - 0xFF61 + 0xA1) as u8;
        return Ok(2);
    }
    Err(EncodeError::Unrepresentable)
}

fn decode_shiftjis(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b0 = input[0];
    if b0 <= 0x7F {
        return Ok((char::from(b0), 1));
    }
    if (0xA1..=0xDF).contains(&b0) {
        let cp = 0xFF61 + u32::from(b0 - 0xA1);
        return Ok((char::from_u32(cp).unwrap_or('\u{FFFD}'), 1));
    }
    if (0x81..=0x9F).contains(&b0) || (0xE0..=0xEF).contains(&b0) {
        if input.len() < 2 {
            return Err(DecodeError::Incomplete);
        }
        let b1 = input[1];
        if !((0x40..=0x7E).contains(&b1) || (0x80..=0xFC).contains(&b1)) {
            return Err(DecodeError::Invalid);
        }
        return Err(DecodeError::Invalid);
    }
    Err(DecodeError::Invalid)
}

fn encode_shiftjis(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    let cp = ch as u32;
    if cp <= 0x7F {
        if out.is_empty() {
            return Err(EncodeError::NoSpace);
        }
        out[0] = cp as u8;
        return Ok(1);
    }
    if (0xFF61..=0xFF9F).contains(&cp) {
        if out.is_empty() {
            return Err(EncodeError::NoSpace);
        }
        out[0] = (cp - 0xFF61 + 0xA1) as u8;
        return Ok(1);
    }
    Err(EncodeError::Unrepresentable)
}

fn decode_big5(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b0 = input[0];
    if b0 <= 0x7F {
        return Ok((char::from(b0), 1));
    }
    if (0x81..=0xFE).contains(&b0) {
        if input.len() < 2 {
            return Err(DecodeError::Incomplete);
        }
        let b1 = input[1];
        if !((0x40..=0x7E).contains(&b1) || (0xA1..=0xFE).contains(&b1)) {
            return Err(DecodeError::Invalid);
        }
        return Err(DecodeError::Invalid);
    }
    Err(DecodeError::Invalid)
}

fn encode_big5(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    let cp = ch as u32;
    if cp <= 0x7F {
        if out.is_empty() {
            return Err(EncodeError::NoSpace);
        }
        out[0] = cp as u8;
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
        Encoding::Utf16Be => decode_utf16be(input),
        Encoding::Utf32 => decode_utf32(input),
        Encoding::Utf32Be => decode_utf32be(input),
        Encoding::Koi8R => decode_koi8r(input),
        Encoding::Koi8U => decode_koi8u(input),
        Encoding::Cp437 => decode_cp437(input),
        Encoding::Cp1250 => decode_cp1250(input),
        Encoding::Cp1251 => decode_cp1251(input),
        Encoding::Cp1253 => decode_cp1253(input),
        Encoding::Cp1254 => decode_cp1254(input),
        Encoding::Cp1255 => decode_cp1255(input),
        Encoding::Cp1256 => decode_cp1256(input),
        Encoding::Cp1257 => decode_cp1257(input),
        Encoding::Cp1258 => decode_cp1258(input),
        Encoding::Cp874 => decode_cp874(input),
        Encoding::Cp866 => decode_cp866(input),
        Encoding::Cp850 => decode_cp850(input),
        Encoding::MacRoman => decode_macroman(input),
        Encoding::Cp1252 => decode_cp1252(input),
        Encoding::Iso88592 => decode_iso88592(input),
        Encoding::Iso88593 => decode_iso88593(input),
        Encoding::Iso88594 => decode_iso88594(input),
        Encoding::Iso88595 => decode_iso88595(input),
        Encoding::Iso88596 => decode_iso88596(input),
        Encoding::Iso88597 => decode_iso88597(input),
        Encoding::Iso88598 => decode_iso88598(input),
        Encoding::Iso88599 => decode_iso88599(input),
        Encoding::Iso885910 => decode_iso885910(input),
        Encoding::Iso885911 => decode_iso885911(input),
        Encoding::Iso885913 => decode_iso885913(input),
        Encoding::Iso885914 => decode_iso885914(input),
        Encoding::Iso885915 => decode_iso885915(input),
        Encoding::Iso885916 => decode_iso885916(input),
        Encoding::EucJp => decode_eucjp(input),
        Encoding::ShiftJis => decode_shiftjis(input),
        Encoding::Big5 => decode_big5(input),
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
        Encoding::Utf16Be => {
            let mut units = [0u16; 2];
            let encoded_units = ch.encode_utf16(&mut units);
            let needed = encoded_units.len() * 2;
            if out.len() < needed {
                return Err(EncodeError::NoSpace);
            }
            for (idx, unit) in encoded_units.iter().enumerate() {
                let bytes = unit.to_be_bytes();
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
        Encoding::Utf32Be => {
            if out.len() < 4 {
                return Err(EncodeError::NoSpace);
            }
            let bytes = (ch as u32).to_be_bytes();
            out[..4].copy_from_slice(&bytes);
            Ok(4)
        }
        Encoding::Koi8R => encode_koi8r(ch, out),
        Encoding::Koi8U => encode_koi8u(ch, out),
        Encoding::Cp437 => encode_cp437(ch, out),
        Encoding::Cp1250 => encode_cp1250(ch, out),
        Encoding::Cp1251 => encode_cp1251(ch, out),
        Encoding::Cp1253 => encode_cp1253(ch, out),
        Encoding::Cp1254 => encode_cp1254(ch, out),
        Encoding::Cp1255 => encode_cp1255(ch, out),
        Encoding::Cp1256 => encode_cp1256(ch, out),
        Encoding::Cp1257 => encode_cp1257(ch, out),
        Encoding::Cp1258 => encode_cp1258(ch, out),
        Encoding::Cp874 => encode_cp874(ch, out),
        Encoding::Cp866 => encode_cp866(ch, out),
        Encoding::Cp850 => encode_cp850(ch, out),
        Encoding::MacRoman => encode_macroman(ch, out),
        Encoding::Cp1252 => encode_cp1252(ch, out),
        Encoding::Iso88592 => encode_iso88592(ch, out),
        Encoding::Iso88593 => encode_iso88593(ch, out),
        Encoding::Iso88594 => encode_iso88594(ch, out),
        Encoding::Iso88595 => encode_iso88595(ch, out),
        Encoding::Iso88596 => encode_iso88596(ch, out),
        Encoding::Iso88597 => encode_iso88597(ch, out),
        Encoding::Iso88598 => encode_iso88598(ch, out),
        Encoding::Iso88599 => encode_iso88599(ch, out),
        Encoding::Iso885910 => encode_iso885910(ch, out),
        Encoding::Iso885911 => encode_iso885911(ch, out),
        Encoding::Iso885913 => encode_iso885913(ch, out),
        Encoding::Iso885914 => encode_iso885914(ch, out),
        Encoding::Iso885915 => encode_iso885915(ch, out),
        Encoding::Iso885916 => encode_iso885916(ch, out),
        Encoding::EucJp => encode_eucjp(ch, out),
        Encoding::ShiftJis => encode_shiftjis(ch, out),
        Encoding::Big5 => encode_big5(ch, out),
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
            iconv_open_detailed(b"UTF-8", b"GB18030").expect_err("excluded codec must fail");
        assert_eq!(err.policy, IconvFallbackPolicy::ExcludedCodecFamily);
        assert_eq!(err.dispatch.from_codec, "GB18030");
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
    fn utf16be_to_utf8_conversion() {
        let mut cd = iconv_open(b"UTF-8", b"UTF-16BE").unwrap();
        // Big-endian: 'A' = 0x0041, '€' = 0x20AC
        let input = [0x00, 0x41, 0x20, 0xAC];
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some(&input), &mut out).unwrap();
        assert_eq!(res.in_consumed, 4);
        assert_eq!(res.out_written, "A€".len());
        assert_eq!(&out[..res.out_written], "A€".as_bytes());
    }

    #[test]
    fn utf8_to_utf16be_conversion() {
        let mut cd = iconv_open(b"UTF-16BE", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some("A€".as_bytes()), &mut out).unwrap();
        assert_eq!(res.in_consumed, "A€".len());
        assert_eq!(res.out_written, 4);
        // Big-endian output: 'A' = 0x0041, '€' = 0x20AC
        assert_eq!(&out[..4], &[0x00, 0x41, 0x20, 0xAC]);
    }

    #[test]
    fn utf32be_to_utf8_conversion() {
        let mut cd = iconv_open(b"UTF-8", b"UTF-32BE").unwrap();
        // Big-endian: 'A' = 0x00000041
        let input = [0x00, 0x00, 0x00, 0x41];
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some(&input), &mut out).unwrap();
        assert_eq!(res.in_consumed, 4);
        assert_eq!(res.out_written, 1);
        assert_eq!(&out[..1], b"A");
    }

    #[test]
    fn utf8_to_utf32be_conversion() {
        let mut cd = iconv_open(b"UTF-32BE", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let res = iconv(&mut cd, Some(b"A"), &mut out).unwrap();
        assert_eq!(res.in_consumed, 1);
        assert_eq!(res.out_written, 4);
        // Big-endian output: 'A' = 0x00000041
        assert_eq!(&out[..4], &[0x00, 0x00, 0x00, 0x41]);
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
    fn cp1250_to_utf8_round_trip() {
        // CP1250: Polish Ł (0xA3) and ł (0xB3)
        let cp1250_input: &[u8] = &[0xA3, 0xB3];
        let expected_utf8 = "\u{0141}\u{0142}";

        let mut cd = iconv_open(b"UTF-8", b"CP1250").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1250_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1250", b"UTF-8").unwrap();
        let mut cp1250_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1250_out).unwrap();
        assert_eq!(&cp1250_out[..result2.out_written], cp1250_input);
    }

    #[test]
    fn cp1250_accepts_windows1250_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1250");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1251_to_utf8_round_trip() {
        // CP1251: Russian А (0xC0) and а (0xE0)
        let cp1251_input: &[u8] = &[0xC0, 0xE0];
        let expected_utf8 = "\u{0410}\u{0430}";

        let mut cd = iconv_open(b"UTF-8", b"CP1251").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1251_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1251", b"UTF-8").unwrap();
        let mut cp1251_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1251_out).unwrap();
        assert_eq!(&cp1251_out[..result2.out_written], cp1251_input);
    }

    #[test]
    fn cp1251_accepts_windows1251_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1251");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1253_to_utf8_round_trip() {
        // CP1253: Greek Α (0xC1) and α (0xE1)
        let cp1253_input: &[u8] = &[0xC1, 0xE1];
        let expected_utf8 = "\u{0391}\u{03B1}";

        let mut cd = iconv_open(b"UTF-8", b"CP1253").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1253_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1253", b"UTF-8").unwrap();
        let mut cp1253_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1253_out).unwrap();
        assert_eq!(&cp1253_out[..result2.out_written], cp1253_input);
    }

    #[test]
    fn cp1253_accepts_windows1253_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1253");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1254_to_utf8_round_trip() {
        // CP1254: Turkish Ğ (0xD0) and ğ (0xF0)
        let cp1254_input: &[u8] = &[0xD0, 0xF0];
        let expected_utf8 = "\u{011E}\u{011F}";

        let mut cd = iconv_open(b"UTF-8", b"CP1254").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1254_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1254", b"UTF-8").unwrap();
        let mut cp1254_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1254_out).unwrap();
        assert_eq!(&cp1254_out[..result2.out_written], cp1254_input);
    }

    #[test]
    fn cp1254_accepts_windows1254_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1254");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1255_to_utf8_round_trip() {
        // CP1255: Hebrew א (0xE0) and ב (0xE1)
        let cp1255_input: &[u8] = &[0xE0, 0xE1];
        let expected_utf8 = "\u{05D0}\u{05D1}";

        let mut cd = iconv_open(b"UTF-8", b"CP1255").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1255_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1255", b"UTF-8").unwrap();
        let mut cp1255_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1255_out).unwrap();
        assert_eq!(&cp1255_out[..result2.out_written], cp1255_input);
    }

    #[test]
    fn cp1255_accepts_windows1255_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1255");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1256_to_utf8_round_trip() {
        // CP1256: Arabic ا (alef, 0xC7) and ب (beh, 0xC8)
        let cp1256_input: &[u8] = &[0xC7, 0xC8];
        let expected_utf8 = "\u{0627}\u{0628}";

        let mut cd = iconv_open(b"UTF-8", b"CP1256").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1256_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1256", b"UTF-8").unwrap();
        let mut cp1256_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1256_out).unwrap();
        assert_eq!(&cp1256_out[..result2.out_written], cp1256_input);
    }

    #[test]
    fn cp1256_accepts_windows1256_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1256");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1257_to_utf8_round_trip() {
        // CP1257: Lithuanian Ą (A with ogonek, 0xC0) and ą (0xE0)
        let cp1257_input: &[u8] = &[0xC0, 0xE0];
        let expected_utf8 = "\u{0104}\u{0105}";

        let mut cd = iconv_open(b"UTF-8", b"CP1257").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1257_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1257", b"UTF-8").unwrap();
        let mut cp1257_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1257_out).unwrap();
        assert_eq!(&cp1257_out[..result2.out_written], cp1257_input);
    }

    #[test]
    fn cp1257_accepts_windows1257_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1257");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1258_to_utf8_round_trip() {
        // CP1258: Vietnamese Đ (D with stroke, 0xD0) and đ (0xF0)
        let cp1258_input: &[u8] = &[0xD0, 0xF0];
        let expected_utf8 = "\u{0110}\u{0111}";

        let mut cd = iconv_open(b"UTF-8", b"CP1258").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1258_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1258", b"UTF-8").unwrap();
        let mut cp1258_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1258_out).unwrap();
        assert_eq!(&cp1258_out[..result2.out_written], cp1258_input);
    }

    #[test]
    fn cp1258_accepts_windows1258_alias() {
        let cd = iconv_open(b"UTF-8", b"WINDOWS1258");
        assert!(cd.is_some());
    }

    #[test]
    fn cp874_to_utf8_round_trip() {
        // CP874: Thai ก (KO KAI, 0xA1) and ข (KHO KHAI, 0xA2)
        let cp874_input: &[u8] = &[0xA1, 0xA2];
        let expected_utf8 = "\u{0E01}\u{0E02}";

        let mut cd = iconv_open(b"UTF-8", b"CP874").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp874_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP874", b"UTF-8").unwrap();
        let mut cp874_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp874_out).unwrap();
        assert_eq!(&cp874_out[..result2.out_written], cp874_input);
    }

    #[test]
    fn cp874_accepts_tis620_alias() {
        let cd = iconv_open(b"UTF-8", b"TIS620");
        assert!(cd.is_some());
    }

    #[test]
    fn cp866_to_utf8_round_trip() {
        // CP866: Russian А (0x80) and Б (0x81)
        let cp866_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{0410}\u{0411}";

        let mut cd = iconv_open(b"UTF-8", b"CP866").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp866_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP866", b"UTF-8").unwrap();
        let mut cp866_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp866_out).unwrap();
        assert_eq!(&cp866_out[..result2.out_written], cp866_input);
    }

    #[test]
    fn cp866_accepts_ibm866_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM866");
        assert!(cd.is_some());
    }

    #[test]
    fn cp850_to_utf8_round_trip() {
        // CP850: Ç (0x80) and ü (0x81)
        let cp850_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{00C7}\u{00FC}";

        let mut cd = iconv_open(b"UTF-8", b"CP850").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp850_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP850", b"UTF-8").unwrap();
        let mut cp850_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp850_out).unwrap();
        assert_eq!(&cp850_out[..result2.out_written], cp850_input);
    }

    #[test]
    fn cp850_accepts_ibm850_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM850");
        assert!(cd.is_some());
    }

    #[test]
    fn macroman_to_utf8_round_trip() {
        // MacRoman: Ä (0x80) and Å (0x81)
        let mac_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{00C4}\u{00C5}";

        let mut cd = iconv_open(b"UTF-8", b"MACROMAN").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACROMAN", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macroman_accepts_macintosh_alias() {
        let cd = iconv_open(b"UTF-8", b"MACINTOSH");
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
    fn iso88596_to_utf8_round_trip() {
        // ISO-8859-6 bytes for "مرحبا" (hello in Arabic)
        // م=0xE5, ر=0xD1, ح=0xCD, ب=0xC8, ا=0xC7
        let iso_input: &[u8] = &[0xE5, 0xD1, 0xCD, 0xC8, 0xC7];
        let expected_utf8 = "مرحبا";

        // ISO-8859-6 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-6").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 5);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-6 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-6", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88596_accepts_arabic_alias() {
        let cd = iconv_open(b"UTF-8", b"ARABIC");
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
    fn iso88598_to_utf8_round_trip() {
        // ISO-8859-8 bytes for "שלום" (Hebrew "shalom")
        // ש=0xF9, ל=0xEC, ו=0xE5, ם=0xED
        let iso_input: &[u8] = &[0xF9, 0xEC, 0xE5, 0xED];
        let expected_utf8 = "\u{05E9}\u{05DC}\u{05D5}\u{05DD}";

        // ISO-8859-8 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-8").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 4);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-8 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-8", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88598_accepts_hebrew_alias() {
        let cd = iconv_open(b"UTF-8", b"HEBREW");
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
    fn iso885910_to_utf8_round_trip() {
        // ISO-8859-10 bytes for "Þórður" (Icelandic name)
        // Þ=0xDE, ó=0xF3, r=0x72, ð=0xF0, u=0x75, r=0x72
        let iso_input: &[u8] = &[0xDE, 0xF3, 0x72, 0xF0, 0x75, 0x72];
        let expected_utf8 = "Þórður";

        // ISO-8859-10 → UTF-8
        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-10").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 6);
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        // UTF-8 → ISO-8859-10 (reverse)
        let mut cd2 = iconv_open(b"ISO-8859-10", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 32];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(result2.in_consumed, expected_utf8.len());
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso885910_accepts_nordic_alias() {
        let cd = iconv_open(b"UTF-8", b"NORDIC");
        assert!(cd.is_some());
    }

    #[test]
    fn iso885911_to_utf8_round_trip() {
        // ISO-8859-11: Thai ก (KO KAI, 0xA1) and ข (KHO KHAI, 0xA2)
        let iso_input: &[u8] = &[0xA1, 0xA2];
        let expected_utf8 = "\u{0E01}\u{0E02}";

        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-11").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ISO-8859-11", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso885911_accepts_thai_alias() {
        let cd = iconv_open(b"UTF-8", b"THAI");
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
    fn iso885914_to_utf8_round_trip() {
        // ISO-8859-14 bytes for "Cymraeg" with Welsh W-circumflex
        // Using Ŵ (0xD0) and ŵ (0xF0) which are Celtic-specific
        let iso_input: &[u8] = &[0xD0, 0xF0]; // Ŵŵ
        let expected_utf8 = "\u{0174}\u{0175}";

        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-14").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ISO-8859-14", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso885914_accepts_celtic_alias() {
        let cd = iconv_open(b"UTF-8", b"CELTIC");
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
    fn iso88593_to_utf8_round_trip() {
        // ISO-8859-3: Maltese Ħ (H with stroke, 0xA1) and ħ (0xB1)
        let iso_input: &[u8] = &[0xA1, 0xB1];
        let expected_utf8 = "\u{0126}\u{0127}";

        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-3").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ISO-8859-3", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso88593_accepts_latin3_alias() {
        let cd = iconv_open(b"UTF-8", b"LATIN3");
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

    #[test]
    fn iso885916_to_utf8_round_trip() {
        // ISO-8859-16 Romanian: Ș (0xAA) and ș (0xBA) with comma below
        let iso_input: &[u8] = &[0xAA, 0xBA];
        let expected_utf8 = "\u{0218}\u{0219}";

        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-16").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ISO-8859-16", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(&iso_out[..result2.out_written], iso_input);
    }

    #[test]
    fn iso885916_accepts_romanian_alias() {
        let cd = iconv_open(b"UTF-8", b"ROMANIAN");
        assert!(cd.is_some());
    }

    #[test]
    fn eucjp_ascii_round_trip() {
        let euc_input: &[u8] = b"Hello";
        let mut cd = iconv_open(b"UTF-8", b"EUC-JP").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(euc_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 5);
        assert_eq!(&utf8_out[..result.out_written], b"Hello");

        let mut cd2 = iconv_open(b"EUC-JP", b"UTF-8").unwrap();
        let mut euc_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(b"Hello"), &mut euc_out).unwrap();
        assert_eq!(&euc_out[..result2.out_written], b"Hello");
    }

    #[test]
    fn eucjp_halfwidth_katakana_round_trip() {
        // EUC-JP half-width katakana: SS2 (0x8E) + 0xA1-0xDF → U+FF61-U+FF9F
        // ｱ (U+FF71) = 0x8E 0xB1, ｲ (U+FF72) = 0x8E 0xB2
        let euc_input: &[u8] = &[0x8E, 0xB1, 0x8E, 0xB2];
        let expected_utf8 = "\u{FF71}\u{FF72}";

        let mut cd = iconv_open(b"UTF-8", b"EUC-JP").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(euc_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"EUC-JP", b"UTF-8").unwrap();
        let mut euc_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut euc_out).unwrap();
        assert_eq!(&euc_out[..result2.out_written], euc_input);
    }

    #[test]
    fn eucjp_accepts_ujis_alias() {
        let cd = iconv_open(b"UTF-8", b"UJIS");
        assert!(cd.is_some());
    }

    #[test]
    fn shiftjis_ascii_round_trip() {
        let sjis_input: &[u8] = b"Hello";
        let mut cd = iconv_open(b"UTF-8", b"SHIFT_JIS").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(sjis_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 5);
        assert_eq!(&utf8_out[..result.out_written], b"Hello");

        let mut cd2 = iconv_open(b"SHIFT_JIS", b"UTF-8").unwrap();
        let mut sjis_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(b"Hello"), &mut sjis_out).unwrap();
        assert_eq!(&sjis_out[..result2.out_written], b"Hello");
    }

    #[test]
    fn shiftjis_halfwidth_katakana_round_trip() {
        // Shift_JIS half-width katakana: 0xA1-0xDF (single byte) → U+FF61-U+FF9F
        // ｱ (U+FF71) = 0xB1, ｲ (U+FF72) = 0xB2
        let sjis_input: &[u8] = &[0xB1, 0xB2];
        let expected_utf8 = "\u{FF71}\u{FF72}";

        let mut cd = iconv_open(b"UTF-8", b"SHIFT_JIS").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(sjis_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"SHIFT_JIS", b"UTF-8").unwrap();
        let mut sjis_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut sjis_out).unwrap();
        assert_eq!(&sjis_out[..result2.out_written], sjis_input);
    }

    #[test]
    fn shiftjis_accepts_cp932_alias() {
        let cd = iconv_open(b"UTF-8", b"CP932");
        assert!(cd.is_some());
    }

    #[test]
    fn shiftjis_accepts_sjis_alias() {
        let cd = iconv_open(b"UTF-8", b"SJIS");
        assert!(cd.is_some());
    }

    #[test]
    fn big5_ascii_round_trip() {
        let big5_input: &[u8] = b"Hello";
        let mut cd = iconv_open(b"UTF-8", b"BIG5").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(big5_input), &mut utf8_out).unwrap();
        assert_eq!(result.in_consumed, 5);
        assert_eq!(&utf8_out[..result.out_written], b"Hello");

        let mut cd2 = iconv_open(b"BIG5", b"UTF-8").unwrap();
        let mut big5_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(b"Hello"), &mut big5_out).unwrap();
        assert_eq!(&big5_out[..result2.out_written], b"Hello");
    }

    #[test]
    fn big5_accepts_csbig5_alias() {
        let cd = iconv_open(b"UTF-8", b"CSBIG5");
        assert!(cd.is_some());
    }
}
