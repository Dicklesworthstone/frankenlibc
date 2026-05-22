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
    Cp862,
    Cp863,
    Cp865,
    Cp857,
    Cp860,
    Cp861,
    Cp869,
    Cp737,
    Cp855,
    Cp864,
    Cp775,
    Viscii,
    Tcvn,
    Armscii8,
    Geostd8,
    Pt154,
    Mulelao,
    HpRoman8,
    Nextstep,
    Atarist,
    RiscosLatin1,
    Cp852,
    MacCyrillic,
    MacGreek,
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

const PHASE1_CODEC_TABLE: [CodecSpec; 64] = [
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
        encoding: Encoding::Cp862,
        canonical: "CP862",
        normalized: "CP862",
        aliases: &["IBM862", "862", "CSPC862LATINHEBREW"],
    },
    CodecSpec {
        encoding: Encoding::Cp863,
        canonical: "CP863",
        normalized: "CP863",
        aliases: &["IBM863", "863", "CSIBM863"],
    },
    CodecSpec {
        encoding: Encoding::Cp865,
        canonical: "CP865",
        normalized: "CP865",
        aliases: &["IBM865", "865", "CSIBM865"],
    },
    CodecSpec {
        encoding: Encoding::Cp857,
        canonical: "CP857",
        normalized: "CP857",
        aliases: &["IBM857", "857", "CSIBM857"],
    },
    CodecSpec {
        encoding: Encoding::Cp860,
        canonical: "CP860",
        normalized: "CP860",
        aliases: &["IBM860", "860", "CSIBM860"],
    },
    CodecSpec {
        encoding: Encoding::Cp861,
        canonical: "CP861",
        normalized: "CP861",
        aliases: &["IBM861", "861", "CSIBM861", "CPIS"],
    },
    CodecSpec {
        encoding: Encoding::Cp869,
        canonical: "CP869",
        normalized: "CP869",
        aliases: &["IBM869", "869", "CSIBM869", "CPGR2"],
    },
    CodecSpec {
        encoding: Encoding::Cp737,
        canonical: "CP737",
        normalized: "CP737",
        aliases: &["IBM737", "737"],
    },
    CodecSpec {
        encoding: Encoding::Cp855,
        canonical: "CP855",
        normalized: "CP855",
        aliases: &["IBM855", "855", "CSIBM855"],
    },
    CodecSpec {
        encoding: Encoding::Cp864,
        canonical: "CP864",
        normalized: "CP864",
        aliases: &["IBM864", "864", "CSIBM864"],
    },
    CodecSpec {
        encoding: Encoding::Cp775,
        canonical: "CP775",
        normalized: "CP775",
        aliases: &["IBM775", "775", "CSPC775BALTIC"],
    },
    CodecSpec {
        encoding: Encoding::Viscii,
        canonical: "VISCII",
        normalized: "VISCII",
        aliases: &["CSVISCII", "VISCII11"],
    },
    CodecSpec {
        encoding: Encoding::Tcvn,
        canonical: "TCVN",
        normalized: "TCVN",
        aliases: &["TCVN5712-1", "VN3"],
    },
    CodecSpec {
        encoding: Encoding::Armscii8,
        canonical: "ARMSCII-8",
        normalized: "ARMSCII8",
        aliases: &["ARMSCII8"],
    },
    CodecSpec {
        encoding: Encoding::Geostd8,
        canonical: "GEORGIAN-PS",
        normalized: "GEORGIANPS",
        aliases: &["GEOSTD8"],
    },
    CodecSpec {
        encoding: Encoding::Pt154,
        canonical: "PT154",
        normalized: "PT154",
        aliases: &["PTCP154", "CP154", "CSPTCP154"],
    },
    CodecSpec {
        encoding: Encoding::Mulelao,
        canonical: "MULELAO-1",
        normalized: "MULELAO1",
        aliases: &["MULELAO"],
    },
    CodecSpec {
        encoding: Encoding::HpRoman8,
        canonical: "HP-ROMAN8",
        normalized: "HPROMAN8",
        aliases: &["ROMAN8", "R8", "CSHPROMAN8"],
    },
    CodecSpec {
        encoding: Encoding::Nextstep,
        canonical: "NEXTSTEP",
        normalized: "NEXTSTEP",
        aliases: &["NEXT"],
    },
    CodecSpec {
        encoding: Encoding::Atarist,
        canonical: "ATARI-ST",
        normalized: "ATARIST",
        aliases: &["ATARIST"],
    },
    CodecSpec {
        encoding: Encoding::RiscosLatin1,
        canonical: "RISCOS-LATIN1",
        normalized: "RISCOSLATIN1",
        aliases: &["RISCOS"],
    },
    CodecSpec {
        encoding: Encoding::Cp852,
        canonical: "CP852",
        normalized: "CP852",
        aliases: &["IBM852", "852", "CSPCP852"],
    },
    CodecSpec {
        encoding: Encoding::MacCyrillic,
        canonical: "MACCYRILLIC",
        normalized: "MACCYRILLIC",
        aliases: &["XMACCYRILLIC"],
    },
    CodecSpec {
        encoding: Encoding::MacGreek,
        canonical: "MACGREEK",
        normalized: "MACGREEK",
        aliases: &["XMACGREEK"],
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
pub const ICONV_PHASE1_INCLUDED_CODECS: [&str; 53] =
    ["UTF-8", "ASCII", "ISO-8859-1", "UTF-16LE", "UTF-16BE", "UTF-32", "UTF-32BE", "KOI8-R", "KOI8-U", "CP437", "CP775", "CP850", "CP855", "CP857", "CP860", "CP861", "CP862", "CP863", "CP864", "CP865", "CP866", "CP869", "CP874", "MACROMAN", "VISCII", "TCVN", "ARMSCII-8", "CP1250", "CP1251", "CP1252", "CP1253", "CP1254", "CP1255", "CP1256", "CP1257", "CP1258", "ISO-8859-2", "ISO-8859-3", "ISO-8859-4", "ISO-8859-5", "ISO-8859-6", "ISO-8859-7", "ISO-8859-8", "ISO-8859-9", "ISO-8859-10", "ISO-8859-11", "ISO-8859-13", "ISO-8859-14", "ISO-8859-15", "ISO-8859-16", "EUC-JP", "SHIFT_JIS", "BIG5"];

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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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

/// CP862 (DOS Hebrew) to Unicode mapping for bytes 0x80-0xFF.
const CP862_TO_UNICODE: [u16; 128] = [
    0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, 0x05D6, 0x05D7, // 80-87 (א-ח)
    0x05D8, 0x05D9, 0x05DA, 0x05DB, 0x05DC, 0x05DD, 0x05DE, 0x05DF, // 88-8F (ט-ן)
    0x05E0, 0x05E1, 0x05E2, 0x05E3, 0x05E4, 0x05E5, 0x05E6, 0x05E7, // 90-97 (נ-ק)
    0x05E8, 0x05E9, 0x05EA, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, // 98-9F (ר-ת,¢,£,¥,₧,ƒ)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7 (box)
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF (box)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7 (box)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF (box)
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7 (box)
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF (box)
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, // E0-E7
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229, // E8-EF
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, // F0-F7
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp862(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP862_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp862(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP862_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP863 (DOS Canadian French) to Unicode mapping for bytes 0x80-0xFF.
const CP863_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00C2, 0x00E0, 0x00B6, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x2017, 0x00C0, 0x00A7, // 88-8F
    0x00C9, 0x00C8, 0x00CA, 0x00F4, 0x00CB, 0x00CF, 0x00FB, 0x00F9, // 90-97
    0x00A4, 0x00D4, 0x00DC, 0x00A2, 0x00A3, 0x00D9, 0x00DB, 0x0192, // 98-9F
    0x00A6, 0x00B4, 0x00F3, 0x00FA, 0x00A8, 0x00B8, 0x00B3, 0x00AF, // A0-A7
    0x00CE, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00BE, 0x00AB, 0x00BB, // A8-AF
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

fn decode_cp863(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP863_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp863(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP863_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP865 (DOS Nordic) to Unicode mapping for bytes 0x80-0xFF.
const CP865_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, // 88-8F
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, // 90-97
    0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x20A7, 0x0192, // 98-9F (₧ at 9E, different from CP850)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00A4, // A8-AF (¤ at AF, different from CP437)
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

fn decode_cp865(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP865_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp865(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP865_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP857 (DOS Turkish) to Unicode mapping for bytes 0x80-0xFF.
const CP857_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x0131, 0x00C4, 0x00C5, // 88-8F (ı at 8D)
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, // 90-97
    0x0130, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x015E, 0x015F, // 98-9F (İ at 98, Ş at 9E, ş at 9F)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x011E, 0x011F, // A0-A7 (Ğ at A6, ğ at A7)
    0x00BF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x00C0, // B0-B7
    0x00A9, 0x2563, 0x2551, 0x2557, 0x255D, 0x00A2, 0x00A5, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E3, 0x00C3, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, // C8-CF
    0x00BA, 0x00AA, 0x00CA, 0x00CB, 0x00C8, 0xFFFF, 0x00CD, 0x00CE, // D0-D7 (undefined at D5)
    0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580, // D8-DF
    0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0xFFFF, // E0-E7 (undefined at E7)
    0x00D7, 0x00DA, 0x00DB, 0x00D9, 0x00EC, 0x00FF, 0x00AF, 0x00B4, // E8-EF
    0x00AD, 0x00B1, 0xFFFF, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8, // F0-F7 (undefined at F2)
    0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp857(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP857_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp857(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP857_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP860 (DOS Portuguese) to Unicode mapping for bytes 0x80-0xFF.
const CP860_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E3, 0x00E0, 0x00C1, 0x00E7, // 80-87 (ã at 84, Á at 86)
    0x00EA, 0x00CA, 0x00E8, 0x00CD, 0x00D4, 0x00EC, 0x00C3, 0x00C2, // 88-8F (Ê at 89, Í at 8B, Ô at 8C, Ã at 8E, Â at 8F)
    0x00C9, 0x00C0, 0x00C8, 0x00F4, 0x00F5, 0x00F2, 0x00DA, 0x00F9, // 90-97 (À at 91, È at 92, õ at 94, Ú at 96)
    0x00CC, 0x00D5, 0x00DC, 0x00A2, 0x00A3, 0x00D9, 0x20A7, 0x00D3, // 98-9F (Ì at 98, Õ at 99, Ù at 9D, Ó at 9F)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x00D2, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF (Ò at A9)
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

fn decode_cp860(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP860_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp860(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP860_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP861 (DOS Icelandic) to Unicode mapping for bytes 0x80-0xFF.
const CP861_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00D0, 0x00F0, 0x00DE, 0x00C4, 0x00C5, // 88-8F (Ð at 8B, ð at 8C, Þ at 8D)
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00FE, 0x00FB, 0x00DD, // 90-97 (þ at 95, Ý at 97)
    0x00FD, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x20A7, 0x0192, // 98-9F (ý at 98)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00C1, 0x00CD, 0x00D3, 0x00DA, // A0-A7 (Á at A4, Í at A5, Ó at A6, Ú at A7)
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

fn decode_cp861(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP861_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp861(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP861_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP869 (DOS Greek 2) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const CP869_TO_UNICODE: [u16; 128] = [
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0386, 0xFFFF, // 80-87 (Ά at 86)
    0x00B7, 0x00AC, 0x00A6, 0x2018, 0x2019, 0x0388, 0x2015, 0x0389, // 88-8F (Έ at 8D, Ή at 8F)
    0x038A, 0x03AA, 0x038C, 0xFFFF, 0xFFFF, 0x038E, 0x03AB, 0x00A9, // 90-97 (Ί,Ϊ,Ό at 90-92, Ύ,Ϋ at 95-96)
    0x038F, 0x00B2, 0x00B3, 0x03AC, 0x00A3, 0x03AD, 0x03AE, 0x03AF, // 98-9F (Ώ at 98, ά,έ,ή,ί at 9B-9F)
    0x03CA, 0x0390, 0x03CC, 0x03CD, 0x0391, 0x0392, 0x0393, 0x0394, // A0-A7 (ϊ,ΐ,ό,ύ at A0-A3, Α-Δ at A4-A7)
    0x0395, 0x0396, 0x0397, 0x00BD, 0x0398, 0x0399, 0x00AB, 0x00BB, // A8-AF (Ε-Η at A8-AA, Θ,Ι at AC-AD)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x039A, 0x039B, 0x039C, // B0-B7 (Κ,Λ,Μ at B5-B7)
    0x039D, 0x2563, 0x2551, 0x2557, 0x255D, 0x039E, 0x039F, 0x2510, // B8-BF (Ν at B8, Ξ,Ο at BD-BE)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x03A0, 0x03A1, // C0-C7 (Π,Ρ at C6-C7)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x03A3, // C8-CF (Σ at CF)
    0x03A4, 0x03A5, 0x03A6, 0x03A7, 0x03A8, 0x03A9, 0x03B1, 0x03B2, // D0-D7 (Τ-Ω at D0-D5, α,β at D6-D7)
    0x03B3, 0x2518, 0x250C, 0x2588, 0x2584, 0x03B4, 0x03B5, 0x2580, // D8-DF (γ at D8, δ,ε at DD-DE)
    0x03B6, 0x03B7, 0x03B8, 0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, // E0-E7 (ζ-ν)
    0x03BE, 0x03BF, 0x03C0, 0x03C1, 0x03C3, 0x03C2, 0x03C4, 0x0384, // E8-EF (ξ-τ, ΄ at EF)
    0x00AD, 0x00B1, 0x03C5, 0x03C6, 0x03C7, 0x00A7, 0x03C8, 0x0385, // F0-F7 (υ-χ at F2-F4, ψ at F6, ΅ at F7)
    0x00B0, 0x00A8, 0x03C9, 0x03CB, 0x03B0, 0x03CE, 0x25A0, 0x00A0, // F8-FF (ω,ϋ,ΰ,ώ at FA-FD)
];

fn decode_cp869(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP869_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp869(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP869_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP737 (Greek DOS) to Unicode mapping for bytes 0x80-0xFF.
const CP737_TO_UNICODE: [u16; 128] = [
    0x0391, 0x0392, 0x0393, 0x0394, 0x0395, 0x0396, 0x0397, 0x0398, // 80-87 (Α-Θ)
    0x0399, 0x039A, 0x039B, 0x039C, 0x039D, 0x039E, 0x039F, 0x03A0, // 88-8F (Ι-Π)
    0x03A1, 0x03A3, 0x03A4, 0x03A5, 0x03A6, 0x03A7, 0x03A8, 0x03A9, // 90-97 (Ρ-Ω)
    0x03B1, 0x03B2, 0x03B3, 0x03B4, 0x03B5, 0x03B6, 0x03B7, 0x03B8, // 98-9F (α-θ)
    0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, 0x03BE, 0x03BF, 0x03C0, // A0-A7 (ι-π)
    0x03C1, 0x03C3, 0x03C2, 0x03C4, 0x03C5, 0x03C6, 0x03C7, 0x03C8, // A8-AF (ρ,σ,ς,τ-ψ)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7 (box drawing)
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    0x03C9, 0x03AC, 0x03AD, 0x03AE, 0x03CA, 0x03AF, 0x03CC, 0x03CD, // E0-E7 (ω,ά,έ,ή,ϊ,ί,ό,ύ)
    0x03CB, 0x03CE, 0x0386, 0x0388, 0x0389, 0x038A, 0x038C, 0x038E, // E8-EF (ϋ,ώ,Ά,Έ,Ή,Ί,Ό,Ύ)
    0x038F, 0x00B1, 0x2265, 0x2264, 0x03AA, 0x03AB, 0x00F7, 0x2248, // F0-F7 (Ώ,±,≥,≤,Ϊ,Ϋ,÷,≈)
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // F8-FF (°,∙,·,√,ⁿ,²,■,NBSP)
];

fn decode_cp737(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP737_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp737(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP737_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP855 (DOS Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
const CP855_TO_UNICODE: [u16; 128] = [
    0x0452, 0x0402, 0x0453, 0x0403, 0x0451, 0x0401, 0x0454, 0x0404, // 80-87 (ђ,Ђ,ѓ,Ѓ,ё,Ё,є,Є)
    0x0455, 0x0405, 0x0456, 0x0406, 0x0457, 0x0407, 0x0458, 0x0408, // 88-8F (ѕ,Ѕ,і,І,ї,Ї,ј,Ј)
    0x0459, 0x0409, 0x045A, 0x040A, 0x045B, 0x040B, 0x045C, 0x040C, // 90-97 (љ,Љ,њ,Њ,ћ,Ћ,ќ,Ќ)
    0x045E, 0x040E, 0x045F, 0x040F, 0x044E, 0x042E, 0x044A, 0x042A, // 98-9F (ў,Ў,џ,Џ,ю,Ю,ъ,Ъ)
    0x0430, 0x0410, 0x0431, 0x0411, 0x0446, 0x0426, 0x0434, 0x0414, // A0-A7 (а,А,б,Б,ц,Ц,д,Д)
    0x0435, 0x0415, 0x0444, 0x0424, 0x0433, 0x0413, 0x00AB, 0x00BB, // A8-AF (е,Е,ф,Ф,г,Г,«,»)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x0445, 0x0425, 0x0438, // B0-B7 (box, х,Х,и)
    0x0418, 0x2563, 0x2551, 0x2557, 0x255D, 0x0439, 0x0419, 0x2510, // B8-BF (И, box, й,Й, box)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x043A, 0x041A, // C0-C7 (box, к,К)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, // C8-CF (box, ¤)
    0x043B, 0x041B, 0x043C, 0x041C, 0x043D, 0x041D, 0x043E, 0x041E, // D0-D7 (л,Л,м,М,н,Н,о,О)
    0x043F, 0x2518, 0x250C, 0x2588, 0x2584, 0x041F, 0x044F, 0x2580, // D8-DF (п, box, П,я, box)
    0x042F, 0x0440, 0x0420, 0x0441, 0x0421, 0x0442, 0x0422, 0x0443, // E0-E7 (Я,р,Р,с,С,т,Т,у)
    0x0423, 0x0436, 0x0416, 0x0432, 0x0412, 0x044C, 0x042C, 0x2116, // E8-EF (У,ж,Ж,в,В,ь,Ь,№)
    0x00AD, 0x044B, 0x042B, 0x0437, 0x0417, 0x0448, 0x0428, 0x044D, // F0-F7 (­,ы,Ы,з,З,ш,Ш,э)
    0x042D, 0x0449, 0x0429, 0x0447, 0x0427, 0x00A7, 0x25A0, 0x00A0, // F8-FF (Э,щ,Щ,ч,Ч,§,■, )
];

fn decode_cp855(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP855_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp855(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP855_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP864 (DOS Arabic) to Unicode mapping for bytes 0x80-0xFF.
/// Some positions are undefined (0xFFFF).
const CP864_TO_UNICODE: [u16; 128] = [
    0x00B0, 0x00B7, 0x2219, 0x221A, 0x2592, 0x2500, 0x2502, 0x253C, // 80-87
    0x2524, 0x252C, 0x251C, 0x2534, 0x2510, 0x250C, 0x2514, 0x2518, // 88-8F
    0x03B2, 0x221E, 0x03C6, 0x00B1, 0x00BD, 0x00BC, 0x2248, 0x00AB, // 90-97
    0x00BB, 0xFEF7, 0xFEF8, 0xFFFF, 0xFFFF, 0xFEFB, 0xFEFC, 0xFFFF, // 98-9F
    0x00A0, 0x00AD, 0xFE82, 0x00A3, 0x00A4, 0xFE84, 0xFFFF, 0xFFFF, // A0-A7
    0xFE8E, 0xFE8F, 0xFE95, 0xFE99, 0x060C, 0xFE9D, 0xFEA1, 0xFEA5, // A8-AF
    0x0660, 0x0661, 0x0662, 0x0663, 0x0664, 0x0665, 0x0666, 0x0667, // B0-B7 (Arabic-Indic digits)
    0x0668, 0x0669, 0xFED1, 0x061B, 0xFEB1, 0xFEB5, 0xFEB9, 0x061F, // B8-BF
    0x00A2, 0xFE80, 0xFE81, 0xFE83, 0xFE85, 0xFECA, 0xFE8B, 0xFE8D, // C0-C7
    0xFE91, 0xFE93, 0xFE97, 0xFE9B, 0xFE9F, 0xFEA3, 0xFEA7, 0xFEA9, // C8-CF
    0xFEAB, 0xFEAD, 0xFEAF, 0xFEB3, 0xFEB7, 0xFEBB, 0xFEBF, 0xFEC1, // D0-D7
    0xFEC5, 0xFECB, 0xFECF, 0x00A6, 0x00AC, 0x00F7, 0x00D7, 0xFEC9, // D8-DF
    0x0640, 0xFED3, 0xFED7, 0xFEDB, 0xFEDF, 0xFEE3, 0xFEE7, 0xFEEB, // E0-E7
    0xFEED, 0xFEEF, 0xFEF3, 0xFEBD, 0xFECC, 0xFECE, 0xFECD, 0xFEE1, // E8-EF
    0xFE7D, 0x0651, 0xFEE5, 0xFEE9, 0xFEEC, 0xFEF0, 0xFEF2, 0xFED0, // F0-F7
    0xFED5, 0xFEF5, 0xFEF6, 0xFEDD, 0xFED9, 0xFEF1, 0x25A0, 0xFFFF, // F8-FF
];

fn decode_cp864(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP864_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp864(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP864_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP775 (DOS Baltic Rim) to Unicode mapping for bytes 0x80-0xFF.
const CP775_TO_UNICODE: [u16; 128] = [
    0x0106, 0x00FC, 0x00E9, 0x0101, 0x00E4, 0x0123, 0x00E5, 0x0107, // 80-87 (Ć,ü,é,ā,ä,ģ,å,ć)
    0x0142, 0x0113, 0x0156, 0x0157, 0x012B, 0x0179, 0x00C4, 0x00C5, // 88-8F (ł,ē,Ŗ,ŗ,ī,Ź,Ä,Å)
    0x00C9, 0x00E6, 0x00C6, 0x014D, 0x00F6, 0x0122, 0x00A2, 0x015A, // 90-97 (É,æ,Æ,ō,ö,Ģ,¢,Ś)
    0x015B, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x00A4, // 98-9F (ś,Ö,Ü,ø,£,Ø,×,¤)
    0x0100, 0x012A, 0x00F3, 0x017B, 0x017C, 0x017A, 0x201D, 0x00A6, // A0-A7 (Ā,Ī,ó,Ż,ż,ź,",¦)
    0x00A9, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x0141, 0x00AB, 0x00BB, // A8-AF (©,®,¬,½,¼,Ł,«,»)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x0104, 0x010C, 0x0118, // B0-B7 (box,Ą,Č,Ę)
    0x0116, 0x2563, 0x2551, 0x2557, 0x255D, 0x012E, 0x0160, 0x2510, // B8-BF (Ė,box,Į,Š,box)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x0172, 0x016A, // C0-C7 (box,Ų,Ū)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x017D, // C8-CF (box,Ž)
    0x0105, 0x010D, 0x0119, 0x0117, 0x012F, 0x0161, 0x0173, 0x016B, // D0-D7 (ą,č,ę,ė,į,š,ų,ū)
    0x017E, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF (ž,box)
    0x00D3, 0x00DF, 0x014C, 0x0143, 0x00F5, 0x00D5, 0x00B5, 0x0144, // E0-E7 (Ó,ß,Ō,Ń,õ,Õ,µ,ń)
    0x0136, 0x0137, 0x013B, 0x013C, 0x0146, 0x0112, 0x0145, 0x2019, // E8-EF (Ķ,ķ,Ļ,ļ,ņ,Ē,Ņ,')
    0x00AD, 0x00B1, 0x201C, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x201E, // F0-F7 (­,±,",¾,¶,§,÷,„)
    0x00B0, 0x2219, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0, // F8-FF (°,∙,·,¹,³,²,■, )
];

fn decode_cp775(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP775_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp775(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP775_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// VISCII (Vietnamese) to Unicode mapping for bytes 0x80-0xFF.
const VISCII_TO_UNICODE: [u16; 128] = [
    0x1EA0, 0x1EAE, 0x1EB0, 0x1EB6, 0x1EA4, 0x1EA6, 0x1EA8, 0x1EAC, // 80-87 (Ạ,Ắ,Ằ,Ặ,Ấ,Ầ,Ẩ,Ậ)
    0x1EBC, 0x1EB8, 0x1EBE, 0x1EC0, 0x1EC2, 0x1EC4, 0x1EC6, 0x1ED0, // 88-8F (Ẽ,Ẹ,Ế,Ề,Ể,Ễ,Ệ,Ố)
    0x1ED2, 0x1ED4, 0x1ED6, 0x1ED8, 0x1EE2, 0x1EDA, 0x1EDC, 0x1EDE, // 90-97 (Ồ,Ổ,Ỗ,Ộ,Ợ,Ớ,Ờ,Ở)
    0x1ECA, 0x1ECE, 0x1ECC, 0x1EC8, 0x1EE6, 0x0168, 0x1EE4, 0x1EF2, // 98-9F (Ị,Ỏ,Ọ,Ỉ,Ủ,Ũ,Ụ,Ỳ)
    0x00D5, 0x1EAF, 0x1EB1, 0x1EB7, 0x1EA5, 0x1EA7, 0x1EA9, 0x1EAD, // A0-A7 (Õ,ắ,ằ,ặ,ấ,ầ,ẩ,ậ)
    0x1EBD, 0x1EB9, 0x1EBF, 0x1EC1, 0x1EC3, 0x1EC5, 0x1EC7, 0x1ED1, // A8-AF (ẽ,ẹ,ế,ề,ể,ễ,ệ,ố)
    0x1ED3, 0x1ED5, 0x1ED7, 0x1EE0, 0x01A0, 0x1ED9, 0x1EDD, 0x1EDF, // B0-B7 (ồ,ổ,ỗ,Ỡ,Ơ,ộ,ờ,ở)
    0x1ECB, 0x1EF0, 0x1EE8, 0x1EEA, 0x1EEC, 0x01A1, 0x1EDB, 0x01AF, // B8-BF (ị,Ự,Ứ,Ừ,Ử,ơ,ớ,Ư)
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x1EA2, 0x0102, 0x1EB3, 0x1EB5, // C0-C7 (À,Á,Â,Ã,Ả,Ă,ẳ,ẵ)
    0x00C8, 0x00C9, 0x00CA, 0x1EBA, 0x00CC, 0x00CD, 0x0128, 0x1EF3, // C8-CF (È,É,Ê,Ẻ,Ì,Í,Ĩ,ỳ)
    0x0110, 0x1EE9, 0x00D2, 0x00D3, 0x00D4, 0x1EA1, 0x1EF7, 0x1EEB, // D0-D7 (Đ,ứ,Ò,Ó,Ô,ạ,ỷ,ừ)
    0x1EED, 0x00D9, 0x00DA, 0x1EF9, 0x1EF1, 0x01B0, 0x1EE1, 0x1EEF, // D8-DF (ử,Ù,Ú,ỹ,ự,ư,ỡ,ữ)
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x1EA3, 0x0103, 0x1EEE, 0x1EAB, // E0-E7 (à,á,â,ã,ả,ă,Ữ,ẫ)
    0x00E8, 0x00E9, 0x00EA, 0x1EBB, 0x00EC, 0x00ED, 0x0129, 0x1EC9, // E8-EF (è,é,ê,ẻ,ì,í,ĩ,ỉ)
    0x0111, 0x1EF5, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x1ECF, 0x1ECD, // F0-F7 (đ,ỵ,ò,ó,ô,õ,ỏ,ọ)
    0x1EE5, 0x00F9, 0x00FA, 0x0169, 0x1EE7, 0x00FD, 0x1EE3, 0x1EF1, // F8-FF (ụ,ù,ú,ũ,ủ,ý,ợ,ự)
];

fn decode_viscii(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = VISCII_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_viscii(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in VISCII_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// TCVN (TCVN5712-1, VN3 Vietnamese) to Unicode mapping for bytes 0x80-0xFF.
const TCVN_TO_UNICODE: [u16; 128] = [
    0x00C0, 0x1EA2, 0x00C3, 0x00C1, 0x1EA0, 0x1EB6, 0x1EAC, 0x00C8, // 80-87 (À,Ả,Ã,Á,Ạ,Ặ,Ậ,È)
    0x1EBA, 0x1EBC, 0x00C9, 0x1EB8, 0x1EC6, 0x00CC, 0x1EC8, 0x0128, // 88-8F (Ẻ,Ẽ,É,Ẹ,Ệ,Ì,Ỉ,Ĩ)
    0x00CD, 0x1ECA, 0x00D2, 0x1ECE, 0x00D5, 0x00D3, 0x1ECC, 0x1ED8, // 90-97 (Í,Ị,Ò,Ỏ,Õ,Ó,Ọ,Ộ)
    0x1EDC, 0x1EDE, 0x1EE0, 0x1EDA, 0x1EE2, 0x00D9, 0x1EE6, 0x0168, // 98-9F (Ờ,Ở,Ỡ,Ớ,Ợ,Ù,Ủ,Ũ)
    0x00A0, 0x0102, 0x00C2, 0x00CA, 0x00D4, 0x01A0, 0x01AF, 0x0110, // A0-A7 ( ,Ă,Â,Ê,Ô,Ơ,Ư,Đ)
    0x0103, 0x00E2, 0x00EA, 0x00F4, 0x01A1, 0x01B0, 0x0111, 0x1EB0, // A8-AF (ă,â,ê,ô,ơ,ư,đ,Ằ)
    0x00DA, 0x1EE4, 0x1EF2, 0x1EF6, 0x1EF8, 0x00DD, 0x1EF4, 0x00E0, // B0-B7 (Ú,Ụ,Ỳ,Ỷ,Ỹ,Ý,Ỵ,à)
    0x1EA3, 0x00E3, 0x00E1, 0x1EA1, 0x1EB2, 0x1EB4, 0x1EAF, 0x1EB1, // B8-BF (ả,ã,á,ạ,Ẳ,Ẵ,ắ,ằ)
    0x1EB3, 0x1EB5, 0x1EAD, 0x00E8, 0x1EA9, 0x1EAB, 0x1EA5, 0x1EA7, // C0-C7 (ẳ,ẵ,ậ,è,ẩ,ẫ,ấ,ầ)
    0x1EBB, 0x1EBD, 0x00E9, 0x1EB9, 0x1EC1, 0x1EC3, 0x1EC5, 0x1EBF, // C8-CF (ẻ,ẽ,é,ẹ,ề,ể,ễ,ế)
    0x1EC7, 0x00EC, 0x1EC9, 0x0129, 0x00ED, 0x1ECB, 0x00F2, 0x1ED3, // D0-D7 (ệ,ì,ỉ,ĩ,í,ị,ò,ồ)
    0x1ECF, 0x00F5, 0x00F3, 0x1ECD, 0x1ED5, 0x1ED7, 0x1ED1, 0x1ED9, // D8-DF (ỏ,õ,ó,ọ,ổ,ỗ,ố,ộ)
    0x1EDD, 0x1EDF, 0x1EE1, 0x1EDB, 0x1EE3, 0x00F9, 0x1EE7, 0x0169, // E0-E7 (ờ,ở,ỡ,ớ,ợ,ù,ủ,ũ)
    0x00FA, 0x1EE5, 0x1EF3, 0x1EF7, 0x1EF9, 0x00FD, 0x1EF5, 0x1EED, // E8-EF (ú,ụ,ỳ,ỷ,ỹ,ý,ỵ,ử)
    0x1EEF, 0x1EE9, 0x1EEB, 0x1EF1, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7 (ữ,ứ,ừ,ự, undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF (undefined)
];

fn decode_tcvn(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = TCVN_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_tcvn(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in TCVN_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ARMSCII-8 (Armenian) to Unicode mapping for bytes 0x80-0xFF.
/// 0xFFFF marks undefined positions.
const ARMSCII8_TO_UNICODE: [u16; 128] = [
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 80-87 (undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F (undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 90-97 (undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 98-9F (undefined)
    0x00A0, 0xFFFF, 0x0587, 0x0589, 0x0029, 0x0028, 0x00BB, 0x00AB, // A0-A7 (NBSP, և, ։, etc.)
    0x2014, 0x002E, 0x055D, 0x002C, 0x002D, 0x055F, 0x2026, 0x055C, // A8-AF (—, ., ՝, etc.)
    0x055B, 0x055E, 0x0531, 0x0561, 0x0532, 0x0562, 0x0533, 0x0563, // B0-B7 (՛, ՞, Ա, ա, Բ, բ, Գ, գ)
    0x0534, 0x0564, 0x0535, 0x0565, 0x0536, 0x0566, 0x0537, 0x0567, // B8-BF (Դ, դ, Ե, delays, Զ, զ, Է, է)
    0x0538, 0x0568, 0x0539, 0x0569, 0x053A, 0x056A, 0x053B, 0x056B, // C0-C7 (Ը, ը, Թ, թ, Ժ, ժ, Ի, ի)
    0x053C, 0x056C, 0x053D, 0x056D, 0x053E, 0x056E, 0x053F, 0x056F, // C8-CF (Լ, լ, Խ, խ, Ծ, ծ, Կ, կ)
    0x0540, 0x0570, 0x0541, 0x0571, 0x0542, 0x0572, 0x0543, 0x0573, // D0-D7 (Հ, հ, Ձ, ձ, Ղ, ղ, Ճ, ճ)
    0x0544, 0x0574, 0x0545, 0x0575, 0x0546, 0x0576, 0x0547, 0x0577, // D8-DF (Մ, մ, Յ, յ, Ն, ն, Շ, շ)
    0x0548, 0x0578, 0x0549, 0x0579, 0x054A, 0x057A, 0x054B, 0x057B, // E0-E7 (Ո, delays, Չ, չ, Պ, պ, Ջ, ջ)
    0x054C, 0x057C, 0x054D, 0x057D, 0x054E, 0x057E, 0x054F, 0x057F, // E8-EF (Ռ, ռ, Ս, delays, Delays, վ, Տ, տ)
    0x0550, 0x0580, 0x0551, 0x0581, 0x0552, 0x0582, 0x0553, 0x0583, // F0-F7 (Delays, delays, Ց, ց, Delays, delays, Փ, delays)
    0x0554, 0x0584, 0x0555, 0x0585, 0x0556, 0x0586, 0xFFFF, 0xFFFF, // F8-FF (Ք, ք, Delays, delays, Delays, delays)
];

fn decode_armscii8(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = ARMSCII8_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_armscii8(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ARMSCII8_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// GEOSTD8 (Georgian-PS) to Unicode mapping for bytes 0x80-0xFF.
/// Georgian letters are in the 0xC0-0xEF range, mapping to U+10D0-U+10FF.
const GEOSTD8_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87 (C1 controls)
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x10D0, 0x10D1, 0x10D2, 0x10D3, 0x10D4, 0x10D5, 0x10D6, 0x10D7, // C0-C7 (ა-თ)
    0x10D8, 0x10D9, 0x10DA, 0x10DB, 0x10DC, 0x10DD, 0x10DE, 0x10DF, // C8-CF (ი-პ)
    0x10E0, 0x10E1, 0x10E2, 0x10E3, 0x10E4, 0x10E5, 0x10E6, 0x10E7, // D0-D7 (ჟ-ხ)
    0x10E8, 0x10E9, 0x10EA, 0x10EB, 0x10EC, 0x10ED, 0x10EE, 0x10EF, // D8-DF (შ-ჯ)
    0x10F0, 0x10F1, 0x10F2, 0x10F3, 0x10F4, 0x10F5, 0x10F6, 0x00E7, // E0-E7 (ჰ-ჶ, ç)
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF (è-ï)
    0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7 (ð-÷)
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF, // F8-FF (ø-ÿ)
];

fn decode_geostd8(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = GEOSTD8_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_geostd8(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in GEOSTD8_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// PT154 (ParaType Kazakh Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
/// Used for Kazakh language with additional Cyrillic letters.
const PT154_TO_UNICODE: [u16; 128] = [
    0x0496, 0x0492, 0x04EE, 0x0493, 0x201E, 0x2026, 0x04B6, 0x04AE, // 80-87 (Ж with descender, Г with stroke, etc.)
    0x04B2, 0x04AF, 0x04A0, 0x04E2, 0x04A2, 0x049A, 0x04BA, 0x04B8, // 88-8F
    0x0497, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x04B3, 0x04B7, 0x04A1, 0x04E3, 0x04A3, 0x049B, 0x04BB, 0x04B9, // 98-9F
    0x00A0, 0x040E, 0x045E, 0x0408, 0x04E8, 0x0498, 0x04B0, 0x00A7, // A0-A7
    0x0401, 0x00A9, 0x04D8, 0x00AB, 0x00AC, 0x04EF, 0x00AE, 0x049C, // A8-AF
    0x00B0, 0x04B1, 0x0406, 0x0456, 0x0499, 0x04E9, 0x00B6, 0x00B7, // B0-B7
    0x0451, 0x2116, 0x04D9, 0x00BB, 0x0458, 0x04AA, 0x04AB, 0x049D, // B8-BF
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // C0-C7 (А-З)
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // C8-CF (И-П)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // D0-D7 (Р-Ч)
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // D8-DF (Ш-Я)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // E0-E7 (а-з)
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // E8-EF (и-п)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // F0-F7 (р-ч)
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // F8-FF (ш-я)
];

fn decode_pt154(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = PT154_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_pt154(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in PT154_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// MULELAO-1 (Lao script) to Unicode mapping for bytes 0xA0-0xFF.
/// Maps Lao characters in the 0xA0-0xFF range to U+0E80-U+0EFF.
const MULELAO_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x0E81, 0x0E82, 0x0E84, 0x0E87, 0x0E88, 0x0EAA, 0x0E8A, // A0-A7
    0x0E8D, 0x0E94, 0x0E95, 0x0E96, 0x0E97, 0x0E99, 0x0E9A, 0x0E9B, // A8-AF
    0x0E9C, 0x0E9D, 0x0E9E, 0x0E9F, 0x0EA1, 0x0EA2, 0x0EA3, 0x0EA5, // B0-B7
    0x0EA7, 0x0EAB, 0x0EAD, 0x0EAE, 0xFFFF, 0xFFFF, 0xFFFF, 0x0EAF, // B8-BF (undefined at BC-BE)
    0x0EB0, 0x0EB2, 0x0EB3, 0x0EB4, 0x0EB5, 0x0EB6, 0x0EB7, 0x0EB8, // C0-C7
    0x0EB9, 0x0EBB, 0x0EBC, 0x0EBD, 0x0EC0, 0x0EC1, 0x0EC2, 0x0EC3, // C8-CF
    0x0EC4, 0x0EC6, 0xFFFF, 0xFFFF, 0x0EC8, 0x0EC9, 0x0ECA, 0x0ECB, // D0-D7 (undefined at D2-D3)
    0x0ECC, 0x0ECD, 0x0EDC, 0x0EDD, 0x0ED0, 0x0ED1, 0x0ED2, 0x0ED3, // D8-DF
    0x0ED4, 0x0ED5, 0x0ED6, 0x0ED7, 0x0ED8, 0x0ED9, 0xFFFF, 0xFFFF, // E0-E7 (undefined at E6-E7)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF (undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7 (undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF (undefined)
];

fn decode_mulelao(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = MULELAO_TO_UNICODE[(b - 0xA0) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_mulelao(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MULELAO_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// HP-ROMAN8 to Unicode mapping for bytes 0xA0-0xFF.
/// HP proprietary character set used on HP-UX and HP terminals.
const HPROMAN8_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x00C0, 0x00C2, 0x00C8, 0x00CA, 0x00CB, 0x00CE, 0x00CF, // A0-A7
    0x00B4, 0x02CB, 0x02C6, 0x00A8, 0x02DC, 0x00D9, 0x00DB, 0x20A4, // A8-AF
    0x00AF, 0x00DD, 0x00FD, 0x00B0, 0x00C7, 0x00E7, 0x00D1, 0x00F1, // B0-B7
    0x00A1, 0x00BF, 0x00A4, 0x00A3, 0x00A5, 0x00A7, 0x0192, 0x00A2, // B8-BF
    0x00E2, 0x00EA, 0x00F4, 0x00FB, 0x00E1, 0x00E9, 0x00F3, 0x00FA, // C0-C7
    0x00E0, 0x00E8, 0x00F2, 0x00F9, 0x00E4, 0x00EB, 0x00F6, 0x00FC, // C8-CF
    0x00C5, 0x00EE, 0x00D8, 0x00C6, 0x00E5, 0x00ED, 0x00F8, 0x00E6, // D0-D7
    0x00C4, 0x00EC, 0x00D6, 0x00DC, 0x00C9, 0x00EF, 0x00DF, 0x00D4, // D8-DF
    0x00C1, 0x00C3, 0x00E3, 0x00D0, 0x00F0, 0x00CD, 0x00CC, 0x00D3, // E0-E7
    0x00D2, 0x00D5, 0x00F5, 0x0160, 0x0161, 0x00DA, 0x0178, 0x00FF, // E8-EF
    0x00DE, 0x00FE, 0x00B7, 0x00B5, 0x00B6, 0x00BE, 0x2014, 0x00BC, // F0-F7
    0x00BD, 0x00AA, 0x00BA, 0x00AB, 0x25A0, 0x00BB, 0x00B1, 0xFFFF, // F8-FF (0xFF undefined)
];

fn decode_hproman8(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = HPROMAN8_TO_UNICODE[(b - 0xA0) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_hproman8(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in HPROMAN8_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// NEXTSTEP encoding to Unicode mapping for bytes 0x80-0xFF.
/// Used by NeXTSTEP operating system.
const NEXTSTEP_TO_UNICODE: [u16; 128] = [
    0x00A0, 0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C7, // 80-87
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // 88-8F
    0x00D0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D9, // 90-97
    0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00B5, 0x00D7, 0x00F7, // 98-9F
    0x00A9, 0x00A1, 0x00A2, 0x00A3, 0x2044, 0x00A5, 0x0192, 0x00A7, // A0-A7
    0x00A4, 0x2019, 0x201C, 0x00AB, 0x2039, 0x203A, 0xFB01, 0xFB02, // A8-AF
    0x00AE, 0x2013, 0x2020, 0x2021, 0x00B7, 0x00A6, 0x00B6, 0x2022, // B0-B7
    0x201A, 0x201E, 0x201D, 0x00BB, 0x2026, 0x2030, 0x00AC, 0x00BF, // B8-BF
    0x00B9, 0x02CB, 0x00B4, 0x02C6, 0x02DC, 0x00AF, 0x02D8, 0x02D9, // C0-C7
    0x00A8, 0x02DA, 0x00B8, 0x02DD, 0x02DB, 0x02C7, 0x2014, 0x00B1, // C8-CF
    0x00BC, 0x00BD, 0x00BE, 0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, // D0-D7
    0x00E5, 0x00E7, 0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00C6, // D8-DF
    0x00ED, 0x00AA, 0x00EE, 0x00EF, 0x00F0, 0x00F1, 0x0141, 0x00D8, // E0-E7
    0x0152, 0x00BA, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00E6, // E8-EF
    0x00F9, 0x00FA, 0x00FB, 0x0131, 0x00FC, 0x00FD, 0x0142, 0x00F8, // F0-F7
    0x0153, 0x00DF, 0x00FE, 0x00FF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF (FC-FF undefined)
];

fn decode_nextstep(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = NEXTSTEP_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_nextstep(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in NEXTSTEP_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ATARI-ST to Unicode mapping for bytes 0x80-0xFF.
/// Character set used by Atari ST computers.
const ATARIST_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, // 88-8F
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, // 90-97
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x00DF, 0x0192, // 98-9F
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF
    0x00E3, 0x00F5, 0x00D8, 0x00F8, 0x0153, 0x0152, 0x00C0, 0x00C3, // B0-B7
    0x00D5, 0x00A8, 0x00B4, 0x2020, 0x00B6, 0x00A9, 0x00AE, 0x2122, // B8-BF
    0x0133, 0x0132, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, // C0-C7 (ij,IJ,Hebrew)
    0x05D6, 0x05D7, 0x05D8, 0x05D9, 0x05DB, 0x05DC, 0x05DE, 0x05E0, // C8-CF
    0x05E1, 0x05E2, 0x05E4, 0x05E6, 0x05E7, 0x05E8, 0x05E9, 0x05EA, // D0-D7
    0x05DF, 0x05DA, 0x05DD, 0x05E3, 0x05E5, 0x00A7, 0x2227, 0x221E, // D8-DF
    0x03B1, 0x03B2, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, // E0-E7
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x222E, 0x03C6, 0x2208, 0x2229, // E8-EF
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, // F0-F7
    0x00B0, 0x2022, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x00B3, 0x00AF, // F8-FF
];

fn decode_atarist(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = ATARIST_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_atarist(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ATARIST_TO_UNICODE.iter().enumerate() {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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

/// RISC OS Latin-1 to Unicode mapping for bytes 0x80-0xFF.
/// 0x80-0x9F contain various symbols, 0xA0-0xFF match Latin-1.
const RISCOSLATIN1_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x20AC, 0x0174, 0x0175, 0xFFFF, 0xFFFF, 0x0176, 0x0177, 0xFFFF, // 80-87 (€,Ŵ,ŵ,-,-,Ŷ,ŷ,-)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x2026, 0x2122, 0x2030, 0x2022, // 88-8F (-,-,-,-,…,™,‰,•)
    // 0x90-0x9F
    0x2018, 0x2019, 0x2039, 0x203A, 0x201C, 0x201D, 0x201E, 0x2013, // 90-97 (',',‹,›,",",„,–)
    0x2014, 0x2212, 0x0152, 0x0153, 0x2020, 0x2021, 0xFB01, 0xFB02, // 98-9F (—,−,Œ,œ,†,‡,ﬁ,ﬂ)
    // 0xA0-0xFF: same as Latin-1 (U+00A0-U+00FF)
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x00D0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF, // F8-FF
];

fn decode_riscoslatin1(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = RISCOSLATIN1_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
        }
    }
}

fn encode_riscoslatin1(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in RISCOSLATIN1_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP852 (DOS Latin-2 / Central European) to Unicode mapping for bytes 0x80-0xFF.
const CP852_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x016F, 0x0107, 0x00E7, // 80-87 (Ç,ü,é,â,ä,ů,ć,ç)
    0x0142, 0x00EB, 0x0150, 0x0151, 0x00EE, 0x0179, 0x00C4, 0x0106, // 88-8F (ł,ë,Ő,ő,î,Ź,Ä,Ć)
    // 0x90-0x9F
    0x00C9, 0x0139, 0x013A, 0x00F4, 0x00F6, 0x013D, 0x013E, 0x015A, // 90-97 (É,Ĺ,ĺ,ô,ö,Ľ,ľ,Ś)
    0x015B, 0x00D6, 0x00DC, 0x0164, 0x0165, 0x0141, 0x00D7, 0x010D, // 98-9F (ś,Ö,Ü,Ť,ť,Ł,×,č)
    // 0xA0-0xAF
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x0104, 0x0105, 0x017D, 0x017E, // A0-A7 (á,í,ó,ú,Ą,ą,Ž,ž)
    0x0118, 0x0119, 0x00AC, 0x017A, 0x010C, 0x015F, 0x00AB, 0x00BB, // A8-AF (Ę,ę,¬,ź,Č,ş,«,»)
    // 0xB0-0xBF (box drawing)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x011A, // B0-B7
    0x015E, 0x2563, 0x2551, 0x2557, 0x255D, 0x017B, 0x017C, 0x2510, // B8-BF
    // 0xC0-0xCF (box drawing)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x0102, 0x0103, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, // C8-CF
    // 0xD0-0xDF (box drawing + misc)
    0x0111, 0x0110, 0x010E, 0x00CB, 0x010F, 0x0147, 0x00CD, 0x00CE, // D0-D7
    0x011B, 0x2518, 0x250C, 0x2588, 0x2584, 0x0162, 0x016E, 0x2580, // D8-DF
    // 0xE0-0xEF
    0x00D3, 0x00DF, 0x00D4, 0x0143, 0x0144, 0x0148, 0x0160, 0x0161, // E0-E7 (Ó,ß,Ô,Ń,ń,ň,Š,š)
    0x0154, 0x00DA, 0x0155, 0x0170, 0x00FD, 0x00DD, 0x0163, 0x00B4, // E8-EF (Ŕ,Ú,ŕ,Ű,ý,Ý,ţ,´)
    // 0xF0-0xFF
    0x00AD, 0x02DD, 0x02DB, 0x02C7, 0x02D8, 0x00A7, 0x00F7, 0x00B8, // F0-F7 (SHY,˝,˛,ˇ,˘,§,÷,¸)
    0x00B0, 0x00A8, 0x02D9, 0x0171, 0x0158, 0x0159, 0x25A0, 0x00A0, // F8-FF (°,¨,˙,ű,Ř,ř,■,NBSP)
];

fn decode_cp852(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP852_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_cp852(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP852_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Cyrillic to Unicode mapping for bytes 0x80-0xFF.
const MACCYRILLIC_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Cyrillic А-Р)
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87 (А-З)
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F (И-П)
    // 0x90-0x9F (Cyrillic Р-Я)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97 (Р-Ч)
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F (Ш-Я)
    // 0xA0-0xAF (misc symbols)
    0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6, 0x0406, // A0-A7 (†,°,¢,£,§,•,¶,І)
    0x00AE, 0x00A9, 0x2122, 0x0402, 0x0452, 0x2260, 0x0403, 0x0453, // A8-AF (®,©,™,Ђ,ђ,≠,Ѓ,ѓ)
    // 0xB0-0xBF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x0456, 0x00B5, 0x2202, 0x0408, // B0-B7 (∞,±,≤,≥,і,µ,∂,Ј)
    0x0404, 0x0454, 0x0407, 0x0457, 0x0409, 0x0459, 0x040A, 0x045A, // B8-BF (Є,є,Ї,ї,Љ,љ,Њ,њ)
    // 0xC0-0xCF
    0x0458, 0x0405, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB, // C0-C7 (ј,Ѕ,¬,√,ƒ,≈,∆,«)
    0x00BB, 0x2026, 0x00A0, 0x040B, 0x045B, 0x040C, 0x045C, 0x0455, // C8-CF (»,…,NBSP,Ћ,ћ,Ќ,ќ,ѕ)
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x201E, // D0-D7 (–,—,",",',',÷,„)
    0x040E, 0x045E, 0x040F, 0x045F, 0x2116, 0x0401, 0x0451, 0x044F, // D8-DF (Ў,ў,Џ,џ,№,Ё,ё,я)
    // 0xE0-0xEF (Cyrillic а-р)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // E0-E7 (а-з)
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // E8-EF (и-п)
    // 0xF0-0xFF (Cyrillic р-ю + €)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // F0-F7 (р-ч)
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x20AC, // F8-FF (ш-ю,€)
];

fn decode_maccyrillic(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACCYRILLIC_TO_UNICODE[(b - 0x80) as usize];
        Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
    }
}

fn encode_maccyrillic(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACCYRILLIC_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Greek to Unicode mapping for bytes 0x80-0xFF.
const MACGREEK_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x00B9, 0x00B2, 0x00C9, 0x00B3, 0x00D6, 0x00DC, 0x0385, // 80-87 (Ä,¹,²,É,³,Ö,Ü,΅)
    0x00E0, 0x00E2, 0x00E4, 0x0384, 0x00A8, 0x00E7, 0x00E9, 0x00E8, // 88-8F (à,â,ä,΄,¨,ç,é,è)
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00A3, 0x2122, 0x00EE, 0x00EF, 0x2022, 0x00BD, // 90-97 (ê,ë,£,™,î,ï,•,½)
    0x2030, 0x00F4, 0x00F6, 0x00A6, 0x00AD, 0x00F9, 0x00FB, 0x00FC, // 98-9F (‰,ô,ö,¦,SHY,ù,û,ü)
    // 0xA0-0xAF
    0x2020, 0x0393, 0x0394, 0x0398, 0x039B, 0x039E, 0x03A0, 0x00DF, // A0-A7 (†,Γ,Δ,Θ,Λ,Ξ,Π,ß)
    0x00AE, 0x00A9, 0x03A3, 0x03AA, 0x00A7, 0x2260, 0x00B0, 0x00B7, // A8-AF (®,©,Σ,Ϊ,§,≠,°,·)
    // 0xB0-0xBF
    0x0391, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x0392, 0x0395, 0x0396, // B0-B7 (Α,±,≤,≥,¥,Β,Ε,Ζ)
    0x0397, 0x0399, 0x039A, 0x039C, 0x03A6, 0x03AB, 0x03A8, 0x03A9, // B8-BF (Η,Ι,Κ,Μ,Φ,Ϋ,Ψ,Ω)
    // 0xC0-0xCF
    0x03AC, 0x039D, 0x00AC, 0x039F, 0x03A1, 0x2248, 0x03A4, 0x00AB, // C0-C7 (ά,Ν,¬,Ο,Ρ,≈,Τ,«)
    0x00BB, 0x2026, 0x00A0, 0x03A5, 0x03A7, 0x0386, 0x0388, 0x0153, // C8-CF (»,…,NBSP,Υ,Χ,Ά,Έ,œ)
    // 0xD0-0xDF
    0x2013, 0x2015, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x0389, // D0-D7 (–,―,",",',',÷,Ή)
    0x038A, 0x038C, 0x038E, 0x03AD, 0x03AE, 0x03AF, 0x03CC, 0x038F, // D8-DF (Ί,Ό,Ύ,έ,ή,ί,ό,Ώ)
    // 0xE0-0xEF
    0x03CD, 0x03B1, 0x03B2, 0x03C8, 0x03B4, 0x03B5, 0x03C6, 0x03B3, // E0-E7 (ύ,α,β,ψ,δ,ε,φ,γ)
    0x03B7, 0x03B9, 0x03BE, 0x03BA, 0x03BB, 0x03BC, 0x03BD, 0x03BF, // E8-EF (η,ι,ξ,κ,λ,μ,ν,ο)
    // 0xF0-0xFF
    0x03C0, 0x03CE, 0x03C1, 0x03C3, 0x03C4, 0x03B8, 0x03C9, 0x03C2, // F0-F7 (π,ώ,ρ,σ,τ,θ,ω,ς)
    0x03C7, 0x03C5, 0x03B6, 0x03CA, 0x03CB, 0x0390, 0x03B0, 0xFFFF, // F8-FF (χ,υ,ζ,ϊ,ϋ,ΐ,ΰ,-)
];

fn decode_macgreek(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACGREEK_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
        }
    }
}

fn encode_macgreek(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACGREEK_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
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
        Encoding::Cp862 => decode_cp862(input),
        Encoding::Cp863 => decode_cp863(input),
        Encoding::Cp865 => decode_cp865(input),
        Encoding::Cp857 => decode_cp857(input),
        Encoding::Cp860 => decode_cp860(input),
        Encoding::Cp861 => decode_cp861(input),
        Encoding::Cp869 => decode_cp869(input),
        Encoding::Cp737 => decode_cp737(input),
        Encoding::Cp855 => decode_cp855(input),
        Encoding::Cp864 => decode_cp864(input),
        Encoding::Cp775 => decode_cp775(input),
        Encoding::Viscii => decode_viscii(input),
        Encoding::Tcvn => decode_tcvn(input),
        Encoding::Armscii8 => decode_armscii8(input),
        Encoding::Geostd8 => decode_geostd8(input),
        Encoding::Pt154 => decode_pt154(input),
        Encoding::Mulelao => decode_mulelao(input),
        Encoding::HpRoman8 => decode_hproman8(input),
        Encoding::Nextstep => decode_nextstep(input),
        Encoding::Atarist => decode_atarist(input),
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
        Encoding::RiscosLatin1 => decode_riscoslatin1(input),
        Encoding::Cp852 => decode_cp852(input),
        Encoding::MacCyrillic => decode_maccyrillic(input),
        Encoding::MacGreek => decode_macgreek(input),
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
        Encoding::Cp862 => encode_cp862(ch, out),
        Encoding::Cp863 => encode_cp863(ch, out),
        Encoding::Cp865 => encode_cp865(ch, out),
        Encoding::Cp857 => encode_cp857(ch, out),
        Encoding::Cp860 => encode_cp860(ch, out),
        Encoding::Cp861 => encode_cp861(ch, out),
        Encoding::Cp869 => encode_cp869(ch, out),
        Encoding::Cp737 => encode_cp737(ch, out),
        Encoding::Cp855 => encode_cp855(ch, out),
        Encoding::Cp864 => encode_cp864(ch, out),
        Encoding::Cp775 => encode_cp775(ch, out),
        Encoding::Viscii => encode_viscii(ch, out),
        Encoding::Tcvn => encode_tcvn(ch, out),
        Encoding::Armscii8 => encode_armscii8(ch, out),
        Encoding::Geostd8 => encode_geostd8(ch, out),
        Encoding::Pt154 => encode_pt154(ch, out),
        Encoding::Mulelao => encode_mulelao(ch, out),
        Encoding::HpRoman8 => encode_hproman8(ch, out),
        Encoding::Nextstep => encode_nextstep(ch, out),
        Encoding::Atarist => encode_atarist(ch, out),
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
        Encoding::RiscosLatin1 => encode_riscoslatin1(ch, out),
        Encoding::Cp852 => encode_cp852(ch, out),
        Encoding::MacCyrillic => encode_maccyrillic(ch, out),
        Encoding::MacGreek => encode_macgreek(ch, out),
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
    fn cp862_to_utf8_round_trip() {
        // CP862: Hebrew א (Alef, 0x80) and ב (Bet, 0x81)
        let cp862_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{05D0}\u{05D1}";

        let mut cd = iconv_open(b"UTF-8", b"CP862").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp862_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP862", b"UTF-8").unwrap();
        let mut cp862_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp862_out).unwrap();
        assert_eq!(&cp862_out[..result2.out_written], cp862_input);
    }

    #[test]
    fn cp862_accepts_ibm862_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM862");
        assert!(cd.is_some());
    }

    #[test]
    fn cp863_to_utf8_round_trip() {
        // CP863: Ç (0x80) and ü (0x81)
        let cp863_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{00C7}\u{00FC}";

        let mut cd = iconv_open(b"UTF-8", b"CP863").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp863_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP863", b"UTF-8").unwrap();
        let mut cp863_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp863_out).unwrap();
        assert_eq!(&cp863_out[..result2.out_written], cp863_input);
    }

    #[test]
    fn cp863_accepts_ibm863_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM863");
        assert!(cd.is_some());
    }

    #[test]
    fn cp865_to_utf8_round_trip() {
        // CP865: Ç (0x80) and ü (0x81)
        let cp865_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{00C7}\u{00FC}";

        let mut cd = iconv_open(b"UTF-8", b"CP865").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp865_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP865", b"UTF-8").unwrap();
        let mut cp865_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp865_out).unwrap();
        assert_eq!(&cp865_out[..result2.out_written], cp865_input);
    }

    #[test]
    fn cp865_accepts_ibm865_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM865");
        assert!(cd.is_some());
    }

    #[test]
    fn cp857_to_utf8_round_trip() {
        // CP857: Ç (0x80), ı (0x8D Turkish dotless i), İ (0x98 Turkish dotted I)
        let cp857_input: &[u8] = &[0x80, 0x8D, 0x98];
        let expected_utf8 = "\u{00C7}\u{0131}\u{0130}";

        let mut cd = iconv_open(b"UTF-8", b"CP857").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp857_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP857", b"UTF-8").unwrap();
        let mut cp857_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp857_out).unwrap();
        assert_eq!(&cp857_out[..result2.out_written], cp857_input);
    }

    #[test]
    fn cp857_accepts_ibm857_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM857");
        assert!(cd.is_some());
    }

    #[test]
    fn cp860_to_utf8_round_trip() {
        // CP860: Ç (0x80), ã (0x84 Portuguese a-tilde)
        let cp860_input: &[u8] = &[0x80, 0x84];
        let expected_utf8 = "\u{00C7}\u{00E3}";

        let mut cd = iconv_open(b"UTF-8", b"CP860").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp860_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP860", b"UTF-8").unwrap();
        let mut cp860_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp860_out).unwrap();
        assert_eq!(&cp860_out[..result2.out_written], cp860_input);
    }

    #[test]
    fn cp860_accepts_ibm860_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM860");
        assert!(cd.is_some());
    }

    #[test]
    fn cp861_to_utf8_round_trip() {
        // CP861: Ð (0x8B Icelandic Eth), Þ (0x8D Icelandic Thorn)
        let cp861_input: &[u8] = &[0x8B, 0x8D];
        let expected_utf8 = "\u{00D0}\u{00DE}";

        let mut cd = iconv_open(b"UTF-8", b"CP861").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp861_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP861", b"UTF-8").unwrap();
        let mut cp861_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp861_out).unwrap();
        assert_eq!(&cp861_out[..result2.out_written], cp861_input);
    }

    #[test]
    fn cp861_accepts_ibm861_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM861");
        assert!(cd.is_some());
    }

    #[test]
    fn cp869_to_utf8_round_trip() {
        // CP869: Α (0xA4 Greek Alpha), β (0xD7 Greek beta)
        let cp869_input: &[u8] = &[0xA4, 0xD7];
        let expected_utf8 = "\u{0391}\u{03B2}";

        let mut cd = iconv_open(b"UTF-8", b"CP869").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp869_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP869", b"UTF-8").unwrap();
        let mut cp869_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp869_out).unwrap();
        assert_eq!(&cp869_out[..result2.out_written], cp869_input);
    }

    #[test]
    fn cp869_accepts_ibm869_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM869");
        assert!(cd.is_some());
    }

    #[test]
    fn cp737_to_utf8_round_trip() {
        // CP737: Α (0x80 Greek Alpha), Β (0x81 Greek Beta)
        let cp737_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{0391}\u{0392}";

        let mut cd = iconv_open(b"UTF-8", b"CP737").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp737_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP737", b"UTF-8").unwrap();
        let mut cp737_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp737_out).unwrap();
        assert_eq!(&cp737_out[..result2.out_written], cp737_input);
    }

    #[test]
    fn cp737_accepts_ibm737_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM737");
        assert!(cd.is_some());
    }

    #[test]
    fn cp855_to_utf8_round_trip() {
        // CP855: а (0xA0 Cyrillic small a), Ё (0x85 Cyrillic capital Io)
        let cp855_input: &[u8] = &[0xA0, 0x85];
        let expected_utf8 = "\u{0430}\u{0401}";

        let mut cd = iconv_open(b"UTF-8", b"CP855").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp855_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP855", b"UTF-8").unwrap();
        let mut cp855_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp855_out).unwrap();
        assert_eq!(&cp855_out[..result2.out_written], cp855_input);
    }

    #[test]
    fn cp855_accepts_ibm855_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM855");
        assert!(cd.is_some());
    }

    #[test]
    fn cp864_to_utf8_round_trip() {
        // CP864: ٠ (0xB0 Arabic-Indic digit 0), ١ (0xB1 digit 1)
        let cp864_input: &[u8] = &[0xB0, 0xB1];
        let expected_utf8 = "\u{0660}\u{0661}";

        let mut cd = iconv_open(b"UTF-8", b"CP864").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp864_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP864", b"UTF-8").unwrap();
        let mut cp864_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp864_out).unwrap();
        assert_eq!(&cp864_out[..result2.out_written], cp864_input);
    }

    #[test]
    fn cp864_accepts_ibm864_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM864");
        assert!(cd.is_some());
    }

    #[test]
    fn cp775_to_utf8_round_trip() {
        // CP775: Ć (0x80 Latin C with acute), ā (0x83 Latin a with macron)
        let cp775_input: &[u8] = &[0x80, 0x83];
        let expected_utf8 = "\u{0106}\u{0101}";

        let mut cd = iconv_open(b"UTF-8", b"CP775").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp775_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP775", b"UTF-8").unwrap();
        let mut cp775_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp775_out).unwrap();
        assert_eq!(&cp775_out[..result2.out_written], cp775_input);
    }

    #[test]
    fn cp775_accepts_ibm775_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM775");
        assert!(cd.is_some());
    }

    #[test]
    fn viscii_to_utf8_round_trip() {
        // VISCII: Ạ (0x80), Ắ (0x81) - Vietnamese characters
        let viscii_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{1EA0}\u{1EAE}";

        let mut cd = iconv_open(b"UTF-8", b"VISCII").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(viscii_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"VISCII", b"UTF-8").unwrap();
        let mut viscii_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut viscii_out).unwrap();
        assert_eq!(&viscii_out[..result2.out_written], viscii_input);
    }

    #[test]
    fn viscii_accepts_csviscii_alias() {
        let cd = iconv_open(b"UTF-8", b"CSVISCII");
        assert!(cd.is_some());
    }

    #[test]
    fn tcvn_to_utf8_round_trip() {
        // TCVN: À (0x80), Ả (0x81) - Vietnamese characters
        let tcvn_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{00C0}\u{1EA2}";

        let mut cd = iconv_open(b"UTF-8", b"TCVN").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(tcvn_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"TCVN", b"UTF-8").unwrap();
        let mut tcvn_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut tcvn_out).unwrap();
        assert_eq!(&tcvn_out[..result2.out_written], tcvn_input);
    }

    #[test]
    fn tcvn_accepts_vn3_alias() {
        let cd = iconv_open(b"UTF-8", b"VN3");
        assert!(cd.is_some());
    }

    #[test]
    fn armscii8_to_utf8_round_trip() {
        // ARMSCII-8: Ա (0xB2 Armenian Ayb), delays (0xB3 Armenian ayb)
        let armscii8_input: &[u8] = &[0xB2, 0xB3];
        let expected_utf8 = "\u{0531}\u{0561}";

        let mut cd = iconv_open(b"UTF-8", b"ARMSCII-8").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(armscii8_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ARMSCII-8", b"UTF-8").unwrap();
        let mut armscii8_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut armscii8_out).unwrap();
        assert_eq!(&armscii8_out[..result2.out_written], armscii8_input);
    }

    #[test]
    fn armscii8_accepts_armscii8_alias() {
        let cd = iconv_open(b"UTF-8", b"ARMSCII8");
        assert!(cd.is_some());
    }

    #[test]
    fn geostd8_to_utf8_round_trip() {
        // GEOSTD8: ა (0xC0 Georgian Ani), ბ (0xC1 Georgian Bani)
        let geostd8_input: &[u8] = &[0xC0, 0xC1];
        let expected_utf8 = "\u{10D0}\u{10D1}";

        let mut cd = iconv_open(b"UTF-8", b"GEORGIAN-PS").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(geostd8_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"GEORGIAN-PS", b"UTF-8").unwrap();
        let mut geostd8_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut geostd8_out).unwrap();
        assert_eq!(&geostd8_out[..result2.out_written], geostd8_input);
    }

    #[test]
    fn geostd8_accepts_geostd8_alias() {
        let cd = iconv_open(b"UTF-8", b"GEOSTD8");
        assert!(cd.is_some());
    }

    #[test]
    fn pt154_to_utf8_round_trip() {
        // PT154: А (0xC0 Cyrillic A), Б (0xC1 Cyrillic Be)
        let pt154_input: &[u8] = &[0xC0, 0xC1];
        let expected_utf8 = "\u{0410}\u{0411}";

        let mut cd = iconv_open(b"UTF-8", b"PT154").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(pt154_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"PT154", b"UTF-8").unwrap();
        let mut pt154_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut pt154_out).unwrap();
        assert_eq!(&pt154_out[..result2.out_written], pt154_input);
    }

    #[test]
    fn pt154_accepts_ptcp154_alias() {
        let cd = iconv_open(b"UTF-8", b"PTCP154");
        assert!(cd.is_some());
    }

    #[test]
    fn mulelao_to_utf8_round_trip() {
        // MULELAO: ກ (0xA1 Lao Ko Kai), ຂ (0xA2 Lao Kho Khai)
        let mulelao_input: &[u8] = &[0xA1, 0xA2];
        let expected_utf8 = "\u{0E81}\u{0E82}";

        let mut cd = iconv_open(b"UTF-8", b"MULELAO-1").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(mulelao_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MULELAO-1", b"UTF-8").unwrap();
        let mut mulelao_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mulelao_out).unwrap();
        assert_eq!(&mulelao_out[..result2.out_written], mulelao_input);
    }

    #[test]
    fn mulelao_accepts_mulelao_alias() {
        let cd = iconv_open(b"UTF-8", b"MULELAO");
        assert!(cd.is_some());
    }

    #[test]
    fn hproman8_to_utf8_round_trip() {
        // HP-ROMAN8: À (0xA1), Â (0xA2)
        let hproman8_input: &[u8] = &[0xA1, 0xA2];
        let expected_utf8 = "\u{00C0}\u{00C2}";

        let mut cd = iconv_open(b"UTF-8", b"HP-ROMAN8").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(hproman8_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"HP-ROMAN8", b"UTF-8").unwrap();
        let mut hproman8_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut hproman8_out).unwrap();
        assert_eq!(&hproman8_out[..result2.out_written], hproman8_input);
    }

    #[test]
    fn hproman8_accepts_roman8_alias() {
        let cd = iconv_open(b"UTF-8", b"ROMAN8");
        assert!(cd.is_some());
    }

    #[test]
    fn nextstep_to_utf8_round_trip() {
        // NEXTSTEP: À (0x81), Á (0x82)
        let nextstep_input: &[u8] = &[0x81, 0x82];
        let expected_utf8 = "\u{00C0}\u{00C1}";

        let mut cd = iconv_open(b"UTF-8", b"NEXTSTEP").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(nextstep_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"NEXTSTEP", b"UTF-8").unwrap();
        let mut nextstep_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut nextstep_out).unwrap();
        assert_eq!(&nextstep_out[..result2.out_written], nextstep_input);
    }

    #[test]
    fn nextstep_accepts_next_alias() {
        let cd = iconv_open(b"UTF-8", b"NEXT");
        assert!(cd.is_some());
    }

    #[test]
    fn atarist_to_utf8_round_trip() {
        // ATARI-ST: Ç (0x80), ü (0x81)
        let atarist_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{00C7}\u{00FC}";

        let mut cd = iconv_open(b"UTF-8", b"ATARI-ST").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(atarist_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ATARI-ST", b"UTF-8").unwrap();
        let mut atarist_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut atarist_out).unwrap();
        assert_eq!(&atarist_out[..result2.out_written], atarist_input);
    }

    #[test]
    fn atarist_accepts_atarist_alias() {
        let cd = iconv_open(b"UTF-8", b"ATARIST");
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
    fn riscoslatin1_to_utf8_round_trip() {
        // RISC OS Latin-1: € (0x80), Ŵ (0x81), ' (0x90), — (0x98)
        let riscos_input: &[u8] = &[0x80, 0x81, 0x90, 0x98];
        let expected_utf8 = "\u{20AC}\u{0174}\u{2018}\u{2014}";

        let mut cd = iconv_open(b"UTF-8", b"RISCOS-LATIN1").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(riscos_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"RISCOS-LATIN1", b"UTF-8").unwrap();
        let mut riscos_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut riscos_out).unwrap();
        assert_eq!(&riscos_out[..result2.out_written], riscos_input);
    }

    #[test]
    fn riscoslatin1_undefined_positions_decode_to_replacement() {
        // 0x83 is undefined in RISC OS Latin-1
        let riscos_input: &[u8] = &[0x41, 0x83, 0x42];
        let mut cd = iconv_open(b"UTF-8", b"RISCOS-LATIN1").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(riscos_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, "A\u{FFFD}B");
    }

    #[test]
    fn riscoslatin1_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"RISC-OS");
        assert!(cd.is_some());
    }

    #[test]
    fn cp852_to_utf8_round_trip() {
        // CP852 Central European: ů (0x85), Ő (0x8A), ł (0x88), Ž (0xA6)
        let cp852_input: &[u8] = &[0x85, 0x8A, 0x88, 0xA6];
        let expected_utf8 = "\u{016F}\u{0150}\u{0142}\u{017D}";

        let mut cd = iconv_open(b"UTF-8", b"CP852").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp852_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP852", b"UTF-8").unwrap();
        let mut cp852_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp852_out).unwrap();
        assert_eq!(&cp852_out[..result2.out_written], cp852_input);
    }

    #[test]
    fn cp852_accepts_ibm852_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM852");
        assert!(cd.is_some());
    }

    #[test]
    fn maccyrillic_to_utf8_round_trip() {
        // Mac Cyrillic: А (0x80), Б (0x81), а (0xE0), б (0xE1)
        let mac_input: &[u8] = &[0x80, 0x81, 0xE0, 0xE1];
        let expected_utf8 = "\u{0410}\u{0411}\u{0430}\u{0431}";

        let mut cd = iconv_open(b"UTF-8", b"MACCYRILLIC").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACCYRILLIC", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn maccyrillic_accepts_xmaccyrillic_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-CYRILLIC");
        assert!(cd.is_some());
    }

    #[test]
    fn macgreek_to_utf8_round_trip() {
        // Mac Greek: Γ (0xA1), Δ (0xA2), α (0xE1), β (0xE2)
        let mac_input: &[u8] = &[0xA1, 0xA2, 0xE1, 0xE2];
        let expected_utf8 = "\u{0393}\u{0394}\u{03B1}\u{03B2}";

        let mut cd = iconv_open(b"UTF-8", b"MACGREEK").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACGREEK", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macgreek_accepts_xmacgreek_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-GREEK");
        assert!(cd.is_some());
    }

    #[test]
    fn macgreek_undefined_position_decodes_to_replacement() {
        // 0xFF is undefined in Mac Greek
        let mac_input: &[u8] = &[0x41, 0xFF, 0x42];
        let mut cd = iconv_open(b"UTF-8", b"MACGREEK").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, "A\u{FFFD}B");
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
