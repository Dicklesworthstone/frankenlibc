//! Character set conversion.
//!
//! Implements `<iconv.h>` functions for converting between character encodings.

use crate::errno;
use std::simd::{Simd, cmp::SimdPartialEq, cmp::SimdPartialOrd, num::SimdUint};

mod cjk_tables;

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
    /// Unmarked `UTF-16`: BOM-based endianness (decode strips/honors a leading
    /// BOM, defaulting to native LE; encode emits an LE BOM), mirroring `Utf32`.
    Utf16,
    Utf32,
    Utf32Be,
    Utf32Le,
    Koi8R,
    Koi8U,
    Koi8Ru,
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
    GeorgianPs,
    GeorgianAcademy,
    Pt154,
    Rk1048,
    Mulelao,
    HpRoman8,
    Nextstep,
    Atarist,
    RiscosLatin1,
    Cp852,
    MacCyrillic,
    MacGreek,
    MacTurkish,
    MacIceland,
    MacCentralEurope,
    MacUkraine,
    Cp858,
    MacRomanian,
    MacSami,
    MacCroatian,
    Cp720,
    MacHebrew,
    MacArabic,
    MacThai,
    MacFarsi,
    MacDevanagari,
    MacGurmukhi,
    MacGujarati,
    MacKannada,
    MacTelugu,
    MacOriya,
    MacBengali,
    MacMalayalam,
    MacTamil,
    Cp1006,
    Cp1008,
    Cp1046,
    Cp1124,
    Cp1129,
    Cp1133,
    Cp774,
    Cp773,
    Cp772,
    Cp771,
    Cp770,
    Cp868,
    Cp813,
    Cp916,
    Cp1161,
    Cp1162,
    Cp1163,
    Isiri3342,
    Mik,
    Koi8T,
    EcmaCyrillic,
    Cp866Nav,
    DecMcs,
    HpRoman9,
    HpGreek8,
    HpThai8,
    HpTurkish8,
    Cp1004,
    Ibm1167,
    Cwi,
    Strk10482002,
    Csn369103,
    Ibm902,
    Ibm901,
    Cp856,
    Cp1125,
    Cp850,
    Cp851,
    MacRoman,
    Iso88592,
    Iso88593,
    Iso88594,
    Iso88595,
    Iso88596,
    Iso88597,
    Iso88598,
    Iso88599,
    Iso88599e,
    Iso885910,
    Iso885911,
    Iso885913,
    Iso885914,
    Iso885915,
    Iso885916,
    EucJp,
    ShiftJis,
    Big5,
    Gbk,
    EucKr,
    Cp949,
    Gb2312,
    Gb18030,
    Johab,
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

const PHASE1_CODEC_TABLE: [CodecSpec; 136] = [
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
        aliases: &[
            "USASCII",
            "ANSIX3.41968",
            "ANSIX341968",
            "ISO646US",
            "CSASCII",
            "US",
            "CP367",
            "IBM367",
        ],
    },
    CodecSpec {
        encoding: Encoding::Latin1,
        canonical: "ISO-8859-1",
        normalized: "ISO88591",
        aliases: &[
            "ISO88591",
            "LATIN1",
            "8859_1",
            "CSISOLATIN1",
            "ISOIR100",
            "CP819",
            "IBM819",
        ],
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
        encoding: Encoding::Utf16,
        canonical: "UTF-16",
        normalized: "UTF16",
        aliases: &["UTF16"],
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
        encoding: Encoding::Utf32Le,
        canonical: "UTF-32LE",
        normalized: "UTF32LE",
        aliases: &["UTF32LE"],
    },
    CodecSpec {
        encoding: Encoding::Koi8R,
        canonical: "KOI8-R",
        normalized: "KOI8R",
        aliases: &["KOI8R", "CSKOI8R", "KOI8"],
    },
    CodecSpec {
        encoding: Encoding::Koi8U,
        canonical: "KOI8-U",
        normalized: "KOI8U",
        aliases: &["KOI8U"],
    },
    CodecSpec {
        encoding: Encoding::Koi8Ru,
        canonical: "KOI8-RU",
        normalized: "KOI8RU",
        aliases: &["KOI8RU"],
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
        aliases: &["WINDOWS1250", "1250", "MSEE"],
    },
    CodecSpec {
        encoding: Encoding::Cp1251,
        canonical: "CP1251",
        normalized: "CP1251",
        aliases: &["WINDOWS1251", "1251", "MSCYRL"],
    },
    CodecSpec {
        encoding: Encoding::Cp1253,
        canonical: "CP1253",
        normalized: "CP1253",
        aliases: &["WINDOWS1253", "1253", "MSGREEK"],
    },
    CodecSpec {
        encoding: Encoding::Cp1254,
        canonical: "CP1254",
        normalized: "CP1254",
        aliases: &["WINDOWS1254", "1254", "MSTURK"],
    },
    CodecSpec {
        encoding: Encoding::Cp1255,
        canonical: "CP1255",
        normalized: "CP1255",
        aliases: &["WINDOWS1255", "1255", "MSHEBR"],
    },
    CodecSpec {
        encoding: Encoding::Cp1256,
        canonical: "CP1256",
        normalized: "CP1256",
        aliases: &["WINDOWS1256", "1256", "MSARAB"],
    },
    CodecSpec {
        encoding: Encoding::Cp1257,
        canonical: "CP1257",
        normalized: "CP1257",
        aliases: &["WINDOWS1257", "1257", "WINBALTRIM"],
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
        aliases: &["TCVN57121", "VN3"],
    },
    CodecSpec {
        encoding: Encoding::Armscii8,
        canonical: "ARMSCII-8",
        normalized: "ARMSCII8",
        aliases: &["ARMSCII8"],
    },
    CodecSpec {
        encoding: Encoding::Geostd8,
        canonical: "GEOSTD8",
        normalized: "GEOSTD8",
        aliases: &[],
    },
    CodecSpec {
        encoding: Encoding::GeorgianPs,
        canonical: "GEORGIAN-PS",
        normalized: "GEORGIANPS",
        aliases: &["GEORGIANPS"],
    },
    CodecSpec {
        encoding: Encoding::GeorgianAcademy,
        canonical: "GEORGIAN-ACADEMY",
        normalized: "GEORGIANACADEMY",
        aliases: &["GEORGIANACADEMY"],
    },
    CodecSpec {
        encoding: Encoding::Pt154,
        canonical: "PT154",
        normalized: "PT154",
        aliases: &["PTCP154", "CP154", "CSPTCP154"],
    },
    CodecSpec {
        encoding: Encoding::Rk1048,
        canonical: "RK1048",
        normalized: "RK1048",
        aliases: &["STRK10482002", "KZ1048"],
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
        aliases: &["XMACCYRILLIC", "CP10007", "IBM10007"],
    },
    CodecSpec {
        encoding: Encoding::MacGreek,
        canonical: "MACGREEK",
        normalized: "MACGREEK",
        aliases: &["XMACGREEK"],
    },
    CodecSpec {
        encoding: Encoding::MacTurkish,
        canonical: "MACTURKISH",
        normalized: "MACTURKISH",
        aliases: &["XMACTURKISH"],
    },
    CodecSpec {
        encoding: Encoding::MacIceland,
        canonical: "MACICELAND",
        normalized: "MACICELAND",
        aliases: &["XMACICELANDIC"],
    },
    CodecSpec {
        encoding: Encoding::MacCentralEurope,
        canonical: "MACCENTRALEUROPE",
        normalized: "MACCENTRALEUROPE",
        aliases: &["XMACCE", "MACCE"],
    },
    CodecSpec {
        encoding: Encoding::MacUkraine,
        canonical: "MACUKRAINE",
        normalized: "MACUKRAINE",
        aliases: &["XMACUKRAINIAN"],
    },
    CodecSpec {
        encoding: Encoding::Cp858,
        canonical: "CP858",
        normalized: "CP858",
        aliases: &["IBM858", "858", "PCMULTILINGUAL850EURO"],
    },
    CodecSpec {
        encoding: Encoding::MacRomanian,
        canonical: "MACROMANIA",
        normalized: "MACROMANIA",
        aliases: &["XMACROMANIAN"],
    },
    CodecSpec {
        encoding: Encoding::MacSami,
        canonical: "MAC-SAMI",
        normalized: "MACSAMI",
        aliases: &["MACSAMI"],
    },
    CodecSpec {
        encoding: Encoding::MacCroatian,
        canonical: "MACCROATIAN",
        normalized: "MACCROATIAN",
        aliases: &["XMACCROATIAN"],
    },
    CodecSpec {
        encoding: Encoding::Cp720,
        canonical: "CP720",
        normalized: "CP720",
        aliases: &["IBM720", "720"],
    },
    CodecSpec {
        encoding: Encoding::MacHebrew,
        canonical: "MACHEBREW",
        normalized: "MACHEBREW",
        aliases: &["XMACHEBREW"],
    },
    CodecSpec {
        encoding: Encoding::MacArabic,
        canonical: "MACARABIC",
        normalized: "MACARABIC",
        aliases: &["XMACARABIC"],
    },
    CodecSpec {
        encoding: Encoding::MacThai,
        canonical: "MACTHAI",
        normalized: "MACTHAI",
        aliases: &["XMACTHAI"],
    },
    CodecSpec {
        encoding: Encoding::MacFarsi,
        canonical: "MACFARSI",
        normalized: "MACFARSI",
        aliases: &["XMACFARSI"],
    },
    CodecSpec {
        encoding: Encoding::MacDevanagari,
        canonical: "MACDEVANAGARI",
        normalized: "MACDEVANAGARI",
        aliases: &["XMACDEVANAGARI"],
    },
    CodecSpec {
        encoding: Encoding::MacGurmukhi,
        canonical: "MACGURMUKHI",
        normalized: "MACGURMUKHI",
        aliases: &["XMACGURMUKHI"],
    },
    CodecSpec {
        encoding: Encoding::MacGujarati,
        canonical: "MACGUJARATI",
        normalized: "MACGUJARATI",
        aliases: &["XMACGUJARATI"],
    },
    CodecSpec {
        encoding: Encoding::MacKannada,
        canonical: "MACKANNADA",
        normalized: "MACKANNADA",
        aliases: &["XMACKANNADA"],
    },
    CodecSpec {
        encoding: Encoding::MacTelugu,
        canonical: "MACTELUGU",
        normalized: "MACTELUGU",
        aliases: &["XMACTELUGU"],
    },
    CodecSpec {
        encoding: Encoding::MacOriya,
        canonical: "MACORIYA",
        normalized: "MACORIYA",
        aliases: &["XMACORIYA"],
    },
    CodecSpec {
        encoding: Encoding::MacBengali,
        canonical: "MACBENGALI",
        normalized: "MACBENGALI",
        aliases: &["XMACBENGALI"],
    },
    CodecSpec {
        encoding: Encoding::MacMalayalam,
        canonical: "MACMALAYALAM",
        normalized: "MACMALAYALAM",
        aliases: &["XMACMALAYALAM"],
    },
    CodecSpec {
        encoding: Encoding::MacTamil,
        canonical: "MACTAMIL",
        normalized: "MACTAMIL",
        aliases: &["XMACTAMIL"],
    },
    CodecSpec {
        encoding: Encoding::Cp1006,
        canonical: "CP1006",
        normalized: "CP1006",
        aliases: &["IBM1006"],
    },
    CodecSpec {
        encoding: Encoding::Cp1008,
        canonical: "CP1008",
        normalized: "CP1008",
        aliases: &["IBM1008"],
    },
    CodecSpec {
        encoding: Encoding::Cp1046,
        canonical: "CP1046",
        normalized: "CP1046",
        aliases: &["IBM1046"],
    },
    CodecSpec {
        encoding: Encoding::Cp1124,
        canonical: "CP1124",
        normalized: "CP1124",
        aliases: &["IBM1124"],
    },
    CodecSpec {
        encoding: Encoding::Cp1129,
        canonical: "CP1129",
        normalized: "CP1129",
        aliases: &["IBM1129"],
    },
    CodecSpec {
        encoding: Encoding::Cp1133,
        canonical: "CP1133",
        normalized: "CP1133",
        aliases: &["IBM1133", "CSIBM1133"],
    },
    CodecSpec {
        encoding: Encoding::Cp774,
        canonical: "CP774",
        normalized: "CP774",
        aliases: &["IBM774"],
    },
    CodecSpec {
        encoding: Encoding::Cp773,
        canonical: "CP773",
        normalized: "CP773",
        aliases: &["IBM773"],
    },
    CodecSpec {
        encoding: Encoding::Cp772,
        canonical: "CP772",
        normalized: "CP772",
        aliases: &["IBM772"],
    },
    CodecSpec {
        encoding: Encoding::Cp771,
        canonical: "CP771",
        normalized: "CP771",
        aliases: &["IBM771"],
    },
    CodecSpec {
        encoding: Encoding::Cp770,
        canonical: "CP770",
        normalized: "CP770",
        aliases: &["IBM770"],
    },
    CodecSpec {
        encoding: Encoding::Cp868,
        canonical: "CP868",
        normalized: "CP868",
        aliases: &["IBM868", "CSIBM868"],
    },
    CodecSpec {
        encoding: Encoding::Cp813,
        canonical: "CP813",
        normalized: "CP813",
        aliases: &["IBM813"],
    },
    CodecSpec {
        encoding: Encoding::Cp916,
        canonical: "CP916",
        normalized: "CP916",
        aliases: &["IBM916"],
    },
    CodecSpec {
        encoding: Encoding::Cp1161,
        canonical: "CP1161",
        normalized: "CP1161",
        aliases: &["IBM1161"],
    },
    CodecSpec {
        encoding: Encoding::Cp1162,
        canonical: "CP1162",
        normalized: "CP1162",
        aliases: &["IBM1162"],
    },
    CodecSpec {
        encoding: Encoding::Cp1163,
        canonical: "CP1163",
        normalized: "CP1163",
        aliases: &["IBM1163"],
    },
    CodecSpec {
        encoding: Encoding::Isiri3342,
        canonical: "ISIRI-3342",
        normalized: "ISIRI3342",
        aliases: &["ISIRI3342"],
    },
    CodecSpec {
        encoding: Encoding::Mik,
        canonical: "MIK",
        normalized: "MIK",
        aliases: &[],
    },
    CodecSpec {
        encoding: Encoding::Koi8T,
        canonical: "KOI8-T",
        normalized: "KOI8T",
        aliases: &["KOI8T"],
    },
    CodecSpec {
        encoding: Encoding::EcmaCyrillic,
        canonical: "ECMA-CYRILLIC",
        normalized: "ECMACYRILLIC",
        aliases: &["ECMACYRILLIC", "ISOIR111", "CSISO111ECMACYRILLIC"],
    },
    CodecSpec {
        encoding: Encoding::Cp866Nav,
        canonical: "CP866NAV",
        normalized: "CP866NAV",
        aliases: &["IBM866NAV"],
    },
    CodecSpec {
        encoding: Encoding::DecMcs,
        canonical: "DEC-MCS",
        normalized: "DECMCS",
        aliases: &["DECMCS", "DEC"],
    },
    CodecSpec {
        encoding: Encoding::HpRoman9,
        canonical: "HP-ROMAN9",
        normalized: "HPROMAN9",
        aliases: &["HPROMAN9", "ROMAN9"],
    },
    CodecSpec {
        encoding: Encoding::HpGreek8,
        canonical: "HP-GREEK8",
        normalized: "HPGREEK8",
        aliases: &["HPGREEK8", "GREEK8"],
    },
    CodecSpec {
        encoding: Encoding::HpThai8,
        canonical: "HP-THAI8",
        normalized: "HPTHAI8",
        aliases: &["HPTHAI8", "THAI8"],
    },
    CodecSpec {
        encoding: Encoding::HpTurkish8,
        canonical: "HP-TURKISH8",
        normalized: "HPTURKISH8",
        aliases: &["HPTURKISH8", "TURKISH8"],
    },
    CodecSpec {
        encoding: Encoding::Cp1004,
        canonical: "CP1004",
        normalized: "CP1004",
        aliases: &["1004", "IBM1004"],
    },
    CodecSpec {
        encoding: Encoding::Ibm1167,
        canonical: "IBM-1167",
        normalized: "IBM1167",
        aliases: &["IBM1167", "CP1167", "1167", "KOI8RU"],
    },
    CodecSpec {
        encoding: Encoding::Cwi,
        canonical: "CWI",
        normalized: "CWI",
        aliases: &["CWI2"],
    },
    CodecSpec {
        encoding: Encoding::Strk10482002,
        canonical: "STRK1048-2002",
        normalized: "STRK10482002",
        aliases: &["RK1048", "KZ1048"],
    },
    CodecSpec {
        encoding: Encoding::Csn369103,
        canonical: "CSN_369103",
        normalized: "CSN369103",
        aliases: &["CSN369103"],
    },
    CodecSpec {
        encoding: Encoding::Ibm902,
        canonical: "IBM-902",
        normalized: "IBM902",
        aliases: &["IBM902", "CP902", "902"],
    },
    CodecSpec {
        encoding: Encoding::Ibm901,
        canonical: "IBM-901",
        normalized: "IBM901",
        aliases: &["IBM901", "CP901", "901"],
    },
    CodecSpec {
        encoding: Encoding::Cp856,
        canonical: "CP856",
        normalized: "CP856",
        aliases: &["IBM856", "856"],
    },
    CodecSpec {
        encoding: Encoding::Cp1125,
        canonical: "CP1125",
        normalized: "CP1125",
        aliases: &[],
    },
    CodecSpec {
        encoding: Encoding::Cp850,
        canonical: "CP850",
        normalized: "CP850",
        aliases: &["IBM850", "850", "CSPC850MULTILINGUAL"],
    },
    CodecSpec {
        encoding: Encoding::Cp851,
        canonical: "CP851",
        normalized: "CP851",
        aliases: &["IBM851", "851", "CSIBM851"],
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
        aliases: &["WINDOWS1252", "MSANSI", "1252"],
    },
    CodecSpec {
        encoding: Encoding::Iso88592,
        canonical: "ISO-8859-2",
        normalized: "ISO88592",
        aliases: &[
            "ISO88592",
            "LATIN2",
            "CSISOLATIN2",
            "CP912",
            "IBM912",
            "8859_2",
            "ISOIR101",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88593,
        canonical: "ISO-8859-3",
        normalized: "ISO88593",
        aliases: &[
            "ISO88593",
            "LATIN3",
            "CSISOLATIN3",
            "CP913",
            "IBM913",
            "8859_3",
            "ISOIR109",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88594,
        canonical: "ISO-8859-4",
        normalized: "ISO88594",
        aliases: &[
            "ISO88594",
            "LATIN4",
            "CSISOLATIN4",
            "BALTIC",
            "CP914",
            "IBM914",
            "8859_4",
            "ISOIR110",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88595,
        canonical: "ISO-8859-5",
        normalized: "ISO88595",
        aliases: &[
            "ISO88595",
            "CYRILLIC",
            "CSISOLATINCYRILLIC",
            "CP915",
            "IBM915",
            "8859_5",
            "ISOIR144",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88596,
        canonical: "ISO-8859-6",
        normalized: "ISO88596",
        aliases: &[
            "ISO88596",
            "ARABIC",
            "CSISOLATINARABIC",
            "ASMO708",
            "ECMA114",
            "CP1089",
            "IBM1089",
            "8859_6",
            "ISOIR127",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88597,
        canonical: "ISO-8859-7",
        normalized: "ISO88597",
        aliases: &[
            "ISO88597",
            "GREEK",
            "GREEK8",
            "CSISOLATINGREEK",
            "ELOT928",
            "ECMA118",
            "8859_7",
            "ISOIR126",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88598,
        canonical: "ISO-8859-8",
        normalized: "ISO88598",
        aliases: &[
            "ISO88598",
            "HEBREW",
            "CSISOLATINHEBREW",
            "8859_8",
            "ISOIR138",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88599,
        canonical: "ISO-8859-9",
        normalized: "ISO88599",
        aliases: &[
            "ISO88599",
            "LATIN5",
            "CSISOLATIN5",
            "TURKISH",
            "CP920",
            "IBM920",
            "8859_9",
            "ISOIR148",
            "ECMA128",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso88599e,
        canonical: "ISO-8859-9E",
        normalized: "ISO88599E",
        aliases: &["ISO88599E"],
    },
    CodecSpec {
        encoding: Encoding::Iso885910,
        canonical: "ISO-8859-10",
        normalized: "ISO885910",
        aliases: &["ISO885910", "LATIN6", "CSISOLATIN6", "NORDIC", "ISOIR157"],
    },
    CodecSpec {
        encoding: Encoding::Iso885911,
        canonical: "ISO-8859-11",
        normalized: "ISO885911",
        aliases: &["ISO885911", "THAI", "ISOIR166"],
    },
    CodecSpec {
        encoding: Encoding::Iso885913,
        canonical: "ISO-8859-13",
        normalized: "ISO885913",
        aliases: &[
            "ISO885913",
            "LATIN7",
            "CSISOLATIN7",
            "BALTICRIM",
            "ISOIR179",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso885914,
        canonical: "ISO-8859-14",
        normalized: "ISO885914",
        aliases: &[
            "ISO885914",
            "LATIN8",
            "CSISOLATIN8",
            "CELTIC",
            "ISOCELTIC",
            "ISOIR199",
        ],
    },
    CodecSpec {
        encoding: Encoding::Iso885915,
        canonical: "ISO-8859-15",
        normalized: "ISO885915",
        aliases: &["ISO885915", "LATIN9", "CSISOLATIN9", "ISOIR203"],
    },
    CodecSpec {
        encoding: Encoding::Iso885916,
        canonical: "ISO-8859-16",
        normalized: "ISO885916",
        aliases: &[
            "ISO885916",
            "LATIN10",
            "CSISOLATIN10",
            "ROMANIAN",
            "ISOIR226",
        ],
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
        aliases: &["CSBIG5", "BIG5TW", "BIGFIVE", "CNBIG5"],
    },
    CodecSpec {
        encoding: Encoding::Gbk,
        canonical: "GBK",
        normalized: "GBK",
        aliases: &["CP936", "MS936", "WINDOWS936"],
    },
    CodecSpec {
        encoding: Encoding::EucKr,
        canonical: "EUC-KR",
        normalized: "EUCKR",
        aliases: &["EUCKR", "CSEUCKR", "KSC5601", "KOREAN"],
    },
    CodecSpec {
        encoding: Encoding::Cp949,
        canonical: "CP949",
        normalized: "CP949",
        aliases: &["UHC", "MSCP949", "WINDOWS949"],
    },
    CodecSpec {
        encoding: Encoding::Gb2312,
        canonical: "GB2312",
        normalized: "GB2312",
        aliases: &[
            "EUC-CN",
            "EUCCN",
            "CSGB2312",
            "GB2312-1980",
            "CSISO58GB231280",
        ],
    },
    CodecSpec {
        encoding: Encoding::Gb18030,
        canonical: "GB18030",
        normalized: "GB18030",
        aliases: &["GB18030-2000", "GB18030-2005"],
    },
    CodecSpec {
        encoding: Encoding::Johab,
        canonical: "JOHAB",
        normalized: "JOHAB",
        aliases: &["CP1361", "MS1361"],
    },
];

const PHASE1_EXCLUDED_CODEC_TABLE: [ExcludedCodecSpec; 3] = [
    ExcludedCodecSpec {
        canonical: "ISO-2022-CN-EXT",
        normalized: "ISO2022CNEXT",
    },
    ExcludedCodecSpec {
        canonical: "ISO-2022-JP",
        normalized: "ISO2022JP",
    },
    ExcludedCodecSpec {
        canonical: "BIG5-HKSCS",
        normalized: "BIG5HKSCS",
    },
];

/// Canonical phase-1 codecs intentionally supported by the in-tree iconv engine.
pub const ICONV_PHASE1_INCLUDED_CODECS: [&str; 55] = [
    "UTF-8",
    "ASCII",
    "ISO-8859-1",
    "UTF-16LE",
    "UTF-16BE",
    "UTF-32",
    "UTF-32BE",
    "KOI8-R",
    "KOI8-U",
    "KOI8-RU",
    "KOI8-T",
    "CP437",
    "CP775",
    "CP850",
    "CP855",
    "CP857",
    "CP860",
    "CP861",
    "CP862",
    "CP863",
    "CP864",
    "CP865",
    "CP866",
    "CP869",
    "CP874",
    "MACROMAN",
    "VISCII",
    "TCVN",
    "ARMSCII-8",
    "CP1250",
    "CP1251",
    "CP1252",
    "CP1253",
    "CP1254",
    "CP1255",
    "CP1256",
    "CP1257",
    "CP1258",
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-9",
    "ISO-8859-10",
    "ISO-8859-11",
    "ISO-8859-13",
    "ISO-8859-14",
    "ISO-8859-15",
    "ISO-8859-16",
    "EUC-JP",
    "SHIFT_JIS",
    "BIG5",
];

/// Canonical alias map for phase-1 supported codecs.
pub const ICONV_PHASE1_ALIAS_NORMALIZATIONS: [(&str, &str); 18] = [
    ("LATIN1", "ISO-8859-1"),
    ("USASCII", "ASCII"),
    ("ANSIX3.41968", "ASCII"),
    ("ANSIX341968", "ASCII"),
    ("ISO646US", "ASCII"),
    ("KOI8R", "KOI8-R"),
    ("CSKOI8R", "KOI8-R"),
    ("KOI8", "KOI8-R"),
    ("KOI8U", "KOI8-U"),
    ("KOI8RU", "KOI8-RU"),
    ("KOI8T", "KOI8-T"),
    ("EUCJP", "EUC-JP"),
    ("UJIS", "EUC-JP"),
    ("CP932", "SHIFT_JIS"),
    ("SJIS", "SHIFT_JIS"),
    ("MSKANJI", "SHIFT_JIS"),
    ("CSBIG5", "BIG5"),
    ("BIGFIVE", "BIG5"),
];

/// Known out-of-scope codec families for phase-1 implementation.
pub const ICONV_PHASE1_EXCLUDED_CODEC_FAMILIES: [&str; 3] =
    ["ISO-2022-CN-EXT", "ISO-2022-JP", "BIG5-HKSCS"];

/// Opaque conversion descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconvDescriptor {
    from: Encoding,
    to: Encoding,
    emit_bom: bool,
    dispatch: IconvDispatchMetadata,
    /// Cached at open time: true when every byte `0x00..=0x7F` decodes (under
    /// `from`) and re-encodes (under `to`) as the identical single byte, so the
    /// iconv loop can SIMD-bulk-copy ASCII runs. Probed, not hardcoded — see
    /// [`pair_is_ascii_identity`].
    fast_ascii: bool,
    /// Cached at open time for single-byte -> single-byte conversions: a direct
    /// `input_byte -> output_byte` table (`-1` = unrepresentable / invalid).
    /// Lets the loop translate each high byte with one O(1) lookup instead of
    /// decode_char + the O(128) linear reverse-search inside encode_*. `None`
    /// when either endpoint is multibyte. See [`build_sb_translation`].
    sb_translation: Option<[i16; 256]>,
    /// Cached at open time when `to` is a single-byte codec: a codepoint ->
    /// byte reverse map, so encoding a decoded char (from ANY source, e.g.
    /// UTF-8) is an O(1) direct BMP-page lookup for common codepages, falling
    /// back to O(log n) binary search instead of the O(128) linear scan inside
    /// encode_*. `None` when `to` is multibyte. See
    /// [`build_to_reverse`].
    to_reverse: Option<SingleByteReverse>,
    /// Unmarked `UTF-16`/`UTF-32` source only: a leading Byte Order Mark has not
    /// yet been consumed. glibc's BOM-bearing converters strip an initial BOM and
    /// switch endianness from it (no BOM => the platform-native LE default), so we
    /// resolve it once at the start of the first input. Explicit-endianness
    /// codecs (`UTF-16LE`/`BE`, `UTF-32LE`/`BE`) leave this `false`.
    from_bom_pending: bool,
    /// Resolved source endianness for the unmarked `UTF-16`/`UTF-32` decoder once
    /// the BOM has been inspected: `true` = big-endian (a `FE FF` / `00 00 FE FF`
    /// BOM was seen), `false` = little-endian (an LE BOM or no BOM — native).
    from_unmarked_be: bool,
}

const REVERSE_DIRECT_PAGES: usize = 8;
const REVERSE_DIRECT_MISSING: u8 = u8::MAX;

/// Codepoint -> output-byte reverse map for a single-byte target codec.
/// Codepoints `< 0x80` are the implicit ASCII identity (matching the `cp < 0x80`
/// shortcut in every single-byte `encode_*`); only `>= 0x80` codepoints that
/// `encode_*` would emit (canonical first-match byte) are stored.
///
/// Most legacy single-byte targets are sparse over a handful of BMP pages
/// (KOI8-R: Cyrillic plus box drawing). `direct_page_slot` maps a Unicode high
/// byte to one of the cached 256-byte pages, and `direct_page_byte[slot][low]`
/// stores the output byte (`0` = absent). The sorted arrays remain a fallback
/// for unusually wide page spreads and non-BMP codepoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SingleByteReverse {
    direct_page_slot: [u8; 256],
    direct_page_byte: [[u8; 256]; REVERSE_DIRECT_PAGES],
    high_cp: [u32; 128],
    high_byte: [u8; 128],
    high_len: u16,
}

impl SingleByteReverse {
    /// Returns the output byte for `ch`, or `None` if unrepresentable — exactly
    /// matching what the codec's `encode_*` would produce for a successful
    /// encode (callers delegate the `None` / no-space cases to `encode_char` so
    /// per-codec error ordering is preserved).
    fn lookup(&self, ch: char) -> Option<u8> {
        let cp = ch as u32;
        if cp < 0x80 {
            return Some(cp as u8);
        }
        if cp <= u32::from(u16::MAX) {
            let page = (cp >> 8) as usize;
            let slot = self.direct_page_slot[page];
            if slot != REVERSE_DIRECT_MISSING {
                let byte = self.direct_page_byte[slot as usize][(cp & 0xFF) as usize];
                if byte != 0 {
                    return Some(byte);
                }
            }
        }
        let hi = &self.high_cp[..self.high_len as usize];
        match hi.binary_search(&cp) {
            Ok(idx) => Some(self.high_byte[idx]),
            Err(_) => None,
        }
    }
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

/// Map a single-byte codepage table entry to a decoded char.
///
/// An *undefined* position in a `*_TO_UNICODE` table is marked with one of two
/// sentinels: `0xFFFF` (the CP* / Mac* / KOI8* tables) or `0xFFFD` (the
/// ISO-8859 family). Neither U+FFFF (a noncharacter) nor U+FFFD (the
/// replacement character) is ever a legitimate codepage→Unicode mapping, so
/// both unambiguously mean "this byte is not assigned." glibc's gconv
/// converters reject an undefined byte with `EILSEQ` — without
/// `//TRANSLIT`/`//IGNORE` they never substitute — so an undefined entry is
/// `DecodeError::Invalid` here, NOT a substituted character.
///
/// This centralizes the rule the hand-written single-byte decoders applied
/// inconsistently: the CP* family guarded `cp == 0xFFFF`, but the ISO-8859
/// family (and several others) silently substituted U+FFFD and reported
/// success where glibc returns EILSEQ — found by `iconv_differential_fuzz`.
#[inline]
fn map_single_byte(cp: u16) -> Result<(char, usize), DecodeError> {
    if cp == 0xFFFF || cp == 0xFFFD {
        return Err(DecodeError::Invalid);
    }
    // Defined table entries are always valid scalar values; the `unwrap_or`
    // never fires (kept as a defensive identity).
    Ok((char::from_u32(u32::from(cp)).unwrap_or('\u{FFFD}'), 1))
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
    // Delegate to the shared glibc-exact UTF-8 stepper (the same primitive that
    // fixed mbrtowc — cc7e76c0 — verified by mbrtowc_differential_probe and now
    // iconv_differential_fuzz). The previous hand-rolled RFC-3629-strict decoder
    // diverged from glibc's gconv UTF-8 converter on the incomplete-vs-invalid
    // distinction (EINVAL vs EILSEQ):
    //   * it checked the byte COUNT before the present continuation bytes, so a
    //     lead followed by a non-continuation byte (e.g. `E4 DD`) wrongly read
    //     as Incomplete/EINVAL where glibc returns EILSEQ; and
    //   * it rejected 0xF5..=0xFD leads at the lead byte, so a valid-so-far but
    //     truncated 4/5/6-byte tail (e.g. `F7 82 9B`) wrongly read as
    //     Invalid/EILSEQ where glibc — which counts those as multibyte leads and
    //     defers the range check — returns EINVAL.
    // utf8_decode_step encodes glibc's actual rule: validate the present
    // continuation bytes first (a bad one is Invalid immediately), report a
    // valid-but-short prefix as Incomplete, and enforce overlong/surrogate only
    // on the complete sequence. An assembled code point that is not a Unicode
    // scalar value (a complete 0xF5..=0xFD sequence is above U+10FFFF) is not
    // representable, so it is EILSEQ here too — matching glibc's gconv.
    match crate::string::wchar::utf8_decode_step(input) {
        crate::string::wchar::Utf8Step::Char { wc, len } => char::from_u32(wc)
            .map(|ch| (ch, len))
            .ok_or(DecodeError::Invalid),
        crate::string::wchar::Utf8Step::Incomplete => Err(DecodeError::Incomplete),
        crate::string::wchar::Utf8Step::Invalid => Err(DecodeError::Invalid),
    }
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

fn decode_utf32le(input: &[u8]) -> Result<(char, usize), DecodeError> {
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
        map_single_byte(cp)
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
            return map_single_byte(unicode);
        }
    }
    // Otherwise same as KOI8-R
    let cp = KOI8R_TO_UNICODE[(b - 0x80) as usize];
    map_single_byte(cp)
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

const KOI8RU_DIFFS: &[(u8, u16)] = &[
    (0x93, 0x201C), // left double quotation mark
    (0x96, 0x201D), // right double quotation mark
    (0x97, 0x2014), // em dash
    (0x98, 0x2116), // numero sign
    (0x99, 0x2122), // trademark sign
    (0x9B, 0x00BB), // right angle quote
    (0x9C, 0x00AE), // registered sign
    (0x9D, 0x00AB), // left angle quote
    (0x9F, 0x00A4), // currency sign
    (0xA4, 0x0454), // Ukrainian small ye
    (0xA6, 0x0456), // Ukrainian small i
    (0xA7, 0x0457), // Ukrainian small yi
    (0xAD, 0x0491), // Ukrainian small ghe with upturn
    (0xAE, 0x045E), // Belarusian small short u
    (0xB4, 0x0404), // Ukrainian capital Ye
    (0xB6, 0x0406), // Ukrainian capital I
    (0xB7, 0x0407), // Ukrainian capital Yi
    (0xBD, 0x0490), // Ukrainian capital Ghe with upturn
    (0xBE, 0x040E), // Belarusian capital short U
];

fn decode_koi8ru(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        return Ok((char::from(b), 1));
    }
    for &(byte, unicode) in KOI8RU_DIFFS {
        if b == byte {
            return map_single_byte(unicode);
        }
    }
    let unicode = KOI8R_TO_UNICODE[(b - 0x80) as usize];
    map_single_byte(unicode)
}

fn encode_koi8ru(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for &(byte, unicode) in KOI8RU_DIFFS {
        if u32::from(unicode) == cp {
            out[0] = byte;
            return Ok(1);
        }
    }
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
    0x0401, 0x0451, 0x0404, 0x0454, 0x0407, 0x0457, 0x040E,
    0x045E, // F0-F7 (Ё,ё,Є,є,Ї,ї,Ў,ў)
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x2116, 0x00A4, 0x25A0,
    0x00A0, // F8-FF (°,∙,·,√,№,¤,■,nbsp)
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
        map_single_byte(cp)
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
    0x05E8, 0x05E9, 0x05EA, 0x00A2, 0x00A3, 0x00A5, 0x20A7,
    0x0192, // 98-9F (ר-ת,¢,£,¥,₧,ƒ)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
    0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x20A7,
    0x0192, // 98-9F (₧ at 9E, different from CP850)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB,
    0x00A4, // A8-AF (¤ at AF, different from CP437)
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
        map_single_byte(cp)
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
    0x0130, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x015E,
    0x015F, // 98-9F (İ at 98, Ş at 9E, ş at 9F)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x011E,
    0x011F, // A0-A7 (Ğ at A6, ğ at A7)
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
        map_single_byte(cp)
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
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E3, 0x00E0, 0x00C1,
    0x00E7, // 80-87 (ã at 84, Á at 86)
    0x00EA, 0x00CA, 0x00E8, 0x00CD, 0x00D4, 0x00EC, 0x00C3,
    0x00C2, // 88-8F (Ê at 89, Í at 8B, Ô at 8C, Ã at 8E, Â at 8F)
    0x00C9, 0x00C0, 0x00C8, 0x00F4, 0x00F5, 0x00F2, 0x00DA,
    0x00F9, // 90-97 (À at 91, È at 92, õ at 94, Ú at 96)
    0x00CC, 0x00D5, 0x00DC, 0x00A2, 0x00A3, 0x00D9, 0x20A7,
    0x00D3, // 98-9F (Ì at 98, Õ at 99, Ù at 9D, Ó at 9F)
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
        map_single_byte(cp)
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
    0x00EA, 0x00EB, 0x00E8, 0x00D0, 0x00F0, 0x00DE, 0x00C4,
    0x00C5, // 88-8F (Ð at 8B, ð at 8C, Þ at 8D)
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00FE, 0x00FB,
    0x00DD, // 90-97 (þ at 95, Ý at 97)
    0x00FD, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x20A7, 0x0192, // 98-9F (ý at 98)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00C1, 0x00CD, 0x00D3,
    0x00DA, // A0-A7 (Á at A4, Í at A5, Ó at A6, Ú at A7)
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
        map_single_byte(cp)
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
    0x00B7, 0x00AC, 0x00A6, 0x2018, 0x2019, 0x0388, 0x2015,
    0x0389, // 88-8F (Έ at 8D, Ή at 8F)
    0x038A, 0x03AA, 0x038C, 0xFFFF, 0xFFFF, 0x038E, 0x03AB,
    0x00A9, // 90-97 (Ί,Ϊ,Ό at 90-92, Ύ,Ϋ at 95-96)
    0x038F, 0x00B2, 0x00B3, 0x03AC, 0x00A3, 0x03AD, 0x03AE,
    0x03AF, // 98-9F (Ώ at 98, ά,έ,ή,ί at 9B-9F)
    0x03CA, 0x0390, 0x03CC, 0x03CD, 0x0391, 0x0392, 0x0393,
    0x0394, // A0-A7 (ϊ,ΐ,ό,ύ at A0-A3, Α-Δ at A4-A7)
    0x0395, 0x0396, 0x0397, 0x00BD, 0x0398, 0x0399, 0x00AB,
    0x00BB, // A8-AF (Ε-Η at A8-AA, Θ,Ι at AC-AD)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x039A, 0x039B,
    0x039C, // B0-B7 (Κ,Λ,Μ at B5-B7)
    0x039D, 0x2563, 0x2551, 0x2557, 0x255D, 0x039E, 0x039F,
    0x2510, // B8-BF (Ν at B8, Ξ,Ο at BD-BE)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x03A0, 0x03A1, // C0-C7 (Π,Ρ at C6-C7)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x03A3, // C8-CF (Σ at CF)
    0x03A4, 0x03A5, 0x03A6, 0x03A7, 0x03A8, 0x03A9, 0x03B1,
    0x03B2, // D0-D7 (Τ-Ω at D0-D5, α,β at D6-D7)
    0x03B3, 0x2518, 0x250C, 0x2588, 0x2584, 0x03B4, 0x03B5,
    0x2580, // D8-DF (γ at D8, δ,ε at DD-DE)
    0x03B6, 0x03B7, 0x03B8, 0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, // E0-E7 (ζ-ν)
    0x03BE, 0x03BF, 0x03C0, 0x03C1, 0x03C3, 0x03C2, 0x03C4, 0x0384, // E8-EF (ξ-τ, ΄ at EF)
    0x00AD, 0x00B1, 0x03C5, 0x03C6, 0x03C7, 0x00A7, 0x03C8,
    0x0385, // F0-F7 (υ-χ at F2-F4, ψ at F6, ΅ at F7)
    0x00B0, 0x00A8, 0x03C9, 0x03CB, 0x03B0, 0x03CE, 0x25A0,
    0x00A0, // F8-FF (ω,ϋ,ΰ,ώ at FA-FD)
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
        map_single_byte(cp)
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
    0x03C9, 0x03AC, 0x03AD, 0x03AE, 0x03CA, 0x03AF, 0x03CC,
    0x03CD, // E0-E7 (ω,ά,έ,ή,ϊ,ί,ό,ύ)
    0x03CB, 0x03CE, 0x0386, 0x0388, 0x0389, 0x038A, 0x038C,
    0x038E, // E8-EF (ϋ,ώ,Ά,Έ,Ή,Ί,Ό,Ύ)
    0x038F, 0x00B1, 0x2265, 0x2264, 0x03AA, 0x03AB, 0x00F7,
    0x2248, // F0-F7 (Ώ,±,≥,≤,Ϊ,Ϋ,÷,≈)
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0,
    0x00A0, // F8-FF (°,∙,·,√,ⁿ,²,■,NBSP)
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
        map_single_byte(cp)
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
    0x0452, 0x0402, 0x0453, 0x0403, 0x0451, 0x0401, 0x0454,
    0x0404, // 80-87 (ђ,Ђ,ѓ,Ѓ,ё,Ё,є,Є)
    0x0455, 0x0405, 0x0456, 0x0406, 0x0457, 0x0407, 0x0458,
    0x0408, // 88-8F (ѕ,Ѕ,і,І,ї,Ї,ј,Ј)
    0x0459, 0x0409, 0x045A, 0x040A, 0x045B, 0x040B, 0x045C,
    0x040C, // 90-97 (љ,Љ,њ,Њ,ћ,Ћ,ќ,Ќ)
    0x045E, 0x040E, 0x045F, 0x040F, 0x044E, 0x042E, 0x044A,
    0x042A, // 98-9F (ў,Ў,џ,Џ,ю,Ю,ъ,Ъ)
    0x0430, 0x0410, 0x0431, 0x0411, 0x0446, 0x0426, 0x0434,
    0x0414, // A0-A7 (а,А,б,Б,ц,Ц,д,Д)
    0x0435, 0x0415, 0x0444, 0x0424, 0x0433, 0x0413, 0x00AB,
    0x00BB, // A8-AF (е,Е,ф,Ф,г,Г,«,»)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x0445, 0x0425, 0x0438, // B0-B7 (box, х,Х,и)
    0x0418, 0x2563, 0x2551, 0x2557, 0x255D, 0x0439, 0x0419,
    0x2510, // B8-BF (И, box, й,Й, box)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x043A, 0x041A, // C0-C7 (box, к,К)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, // C8-CF (box, ¤)
    0x043B, 0x041B, 0x043C, 0x041C, 0x043D, 0x041D, 0x043E,
    0x041E, // D0-D7 (л,Л,м,М,н,Н,о,О)
    0x043F, 0x2518, 0x250C, 0x2588, 0x2584, 0x041F, 0x044F,
    0x2580, // D8-DF (п, box, П,я, box)
    0x042F, 0x0440, 0x0420, 0x0441, 0x0421, 0x0442, 0x0422,
    0x0443, // E0-E7 (Я,р,Р,с,С,т,Т,у)
    0x0423, 0x0436, 0x0416, 0x0432, 0x0412, 0x044C, 0x042C,
    0x2116, // E8-EF (У,ж,Ж,в,В,ь,Ь,№)
    0x00AD, 0x044B, 0x042B, 0x0437, 0x0417, 0x0448, 0x0428,
    0x044D, // F0-F7 (­,ы,Ы,з,З,ш,Ш,э)
    0x042D, 0x0449, 0x0429, 0x0447, 0x0427, 0x00A7, 0x25A0,
    0x00A0, // F8-FF (Э,щ,Щ,ч,Ч,§,■, )
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
        map_single_byte(cp)
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
    0x0660, 0x0661, 0x0662, 0x0663, 0x0664, 0x0665, 0x0666,
    0x0667, // B0-B7 (Arabic-Indic digits)
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
        map_single_byte(cp)
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
    0x0106, 0x00FC, 0x00E9, 0x0101, 0x00E4, 0x0123, 0x00E5,
    0x0107, // 80-87 (Ć,ü,é,ā,ä,ģ,å,ć)
    0x0142, 0x0113, 0x0156, 0x0157, 0x012B, 0x0179, 0x00C4,
    0x00C5, // 88-8F (ł,ē,Ŗ,ŗ,ī,Ź,Ä,Å)
    0x00C9, 0x00E6, 0x00C6, 0x014D, 0x00F6, 0x0122, 0x00A2,
    0x015A, // 90-97 (É,æ,Æ,ō,ö,Ģ,¢,Ś)
    0x015B, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7,
    0x00A4, // 98-9F (ś,Ö,Ü,ø,£,Ø,×,¤)
    0x0100, 0x012A, 0x00F3, 0x017B, 0x017C, 0x017A, 0x201D,
    0x00A6, // A0-A7 (Ā,Ī,ó,Ż,ż,ź,",¦)
    0x00A9, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x0141, 0x00AB,
    0x00BB, // A8-AF (©,®,¬,½,¼,Ł,«,»)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x0104, 0x010C, 0x0118, // B0-B7 (box,Ą,Č,Ę)
    0x0116, 0x2563, 0x2551, 0x2557, 0x255D, 0x012E, 0x0160,
    0x2510, // B8-BF (Ė,box,Į,Š,box)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x0172, 0x016A, // C0-C7 (box,Ų,Ū)
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x017D, // C8-CF (box,Ž)
    0x0105, 0x010D, 0x0119, 0x0117, 0x012F, 0x0161, 0x0173,
    0x016B, // D0-D7 (ą,č,ę,ė,į,š,ų,ū)
    0x017E, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF (ž,box)
    0x00D3, 0x00DF, 0x014C, 0x0143, 0x00F5, 0x00D5, 0x00B5,
    0x0144, // E0-E7 (Ó,ß,Ō,Ń,õ,Õ,µ,ń)
    0x0136, 0x0137, 0x013B, 0x013C, 0x0146, 0x0112, 0x0145,
    0x2019, // E8-EF (Ķ,ķ,Ļ,ļ,ņ,Ē,Ņ,')
    0x00AD, 0x00B1, 0x201C, 0x00BE, 0x00B6, 0x00A7, 0x00F7,
    0x201E, // F0-F7 (­,±,",¾,¶,§,÷,„)
    0x00B0, 0x2219, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0,
    0x00A0, // F8-FF (°,∙,·,¹,³,²,■, )
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
        map_single_byte(cp)
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
    0x1EA0, 0x1EAE, 0x1EB0, 0x1EB6, 0x1EA4, 0x1EA6, 0x1EA8,
    0x1EAC, // 80-87 (Ạ,Ắ,Ằ,Ặ,Ấ,Ầ,Ẩ,Ậ)
    0x1EBC, 0x1EB8, 0x1EBE, 0x1EC0, 0x1EC2, 0x1EC4, 0x1EC6,
    0x1ED0, // 88-8F (Ẽ,Ẹ,Ế,Ề,Ể,Ễ,Ệ,Ố)
    0x1ED2, 0x1ED4, 0x1ED6, 0x1ED8, 0x1EE2, 0x1EDA, 0x1EDC,
    0x1EDE, // 90-97 (Ồ,Ổ,Ỗ,Ộ,Ợ,Ớ,Ờ,Ở)
    0x1ECA, 0x1ECE, 0x1ECC, 0x1EC8, 0x1EE6, 0x0168, 0x1EE4,
    0x1EF2, // 98-9F (Ị,Ỏ,Ọ,Ỉ,Ủ,Ũ,Ụ,Ỳ)
    0x00D5, 0x1EAF, 0x1EB1, 0x1EB7, 0x1EA5, 0x1EA7, 0x1EA9,
    0x1EAD, // A0-A7 (Õ,ắ,ằ,ặ,ấ,ầ,ẩ,ậ)
    0x1EBD, 0x1EB9, 0x1EBF, 0x1EC1, 0x1EC3, 0x1EC5, 0x1EC7,
    0x1ED1, // A8-AF (ẽ,ẹ,ế,ề,ể,ễ,ệ,ố)
    0x1ED3, 0x1ED5, 0x1ED7, 0x1EE0, 0x01A0, 0x1ED9, 0x1EDD,
    0x1EDF, // B0-B7 (ồ,ổ,ỗ,Ỡ,Ơ,ộ,ờ,ở)
    0x1ECB, 0x1EF0, 0x1EE8, 0x1EEA, 0x1EEC, 0x01A1, 0x1EDB,
    0x01AF, // B8-BF (ị,Ự,Ứ,Ừ,Ử,ơ,ớ,Ư)
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x1EA2, 0x0102, 0x1EB3,
    0x1EB5, // C0-C7 (À,Á,Â,Ã,Ả,Ă,ẳ,ẵ)
    0x00C8, 0x00C9, 0x00CA, 0x1EBA, 0x00CC, 0x00CD, 0x0128,
    0x1EF3, // C8-CF (È,É,Ê,Ẻ,Ì,Í,Ĩ,ỳ)
    0x0110, 0x1EE9, 0x00D2, 0x00D3, 0x00D4, 0x1EA1, 0x1EF7,
    0x1EEB, // D0-D7 (Đ,ứ,Ò,Ó,Ô,ạ,ỷ,ừ)
    0x1EED, 0x00D9, 0x00DA, 0x1EF9, 0x1EF1, 0x01B0, 0x1EE1,
    0x1EEF, // D8-DF (ử,Ù,Ú,ỹ,ự,ư,ỡ,ữ)
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x1EA3, 0x0103, 0x1EEE,
    0x1EAB, // E0-E7 (à,á,â,ã,ả,ă,Ữ,ẫ)
    0x00E8, 0x00E9, 0x00EA, 0x1EBB, 0x00EC, 0x00ED, 0x0129,
    0x1EC9, // E8-EF (è,é,ê,ẻ,ì,í,ĩ,ỉ)
    0x0111, 0x1EF5, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x1ECF,
    0x1ECD, // F0-F7 (đ,ỵ,ò,ó,ô,õ,ỏ,ọ)
    0x1EE5, 0x00F9, 0x00FA, 0x0169, 0x1EE7, 0x00FD, 0x1EE3,
    0x1EF1, // F8-FF (ụ,ù,ú,ũ,ủ,ý,ợ,ự)
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
        map_single_byte(cp)
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
    0x00C0, 0x1EA2, 0x00C3, 0x00C1, 0x1EA0, 0x1EB6, 0x1EAC,
    0x00C8, // 80-87 (À,Ả,Ã,Á,Ạ,Ặ,Ậ,È)
    0x1EBA, 0x1EBC, 0x00C9, 0x1EB8, 0x1EC6, 0x00CC, 0x1EC8,
    0x0128, // 88-8F (Ẻ,Ẽ,É,Ẹ,Ệ,Ì,Ỉ,Ĩ)
    0x00CD, 0x1ECA, 0x00D2, 0x1ECE, 0x00D5, 0x00D3, 0x1ECC,
    0x1ED8, // 90-97 (Í,Ị,Ò,Ỏ,Õ,Ó,Ọ,Ộ)
    0x1EDC, 0x1EDE, 0x1EE0, 0x1EDA, 0x1EE2, 0x00D9, 0x1EE6,
    0x0168, // 98-9F (Ờ,Ở,Ỡ,Ớ,Ợ,Ù,Ủ,Ũ)
    0x00A0, 0x0102, 0x00C2, 0x00CA, 0x00D4, 0x01A0, 0x01AF,
    0x0110, // A0-A7 ( ,Ă,Â,Ê,Ô,Ơ,Ư,Đ)
    0x0103, 0x00E2, 0x00EA, 0x00F4, 0x01A1, 0x01B0, 0x0111,
    0x1EB0, // A8-AF (ă,â,ê,ô,ơ,ư,đ,Ằ)
    0x00DA, 0x1EE4, 0x1EF2, 0x1EF6, 0x1EF8, 0x00DD, 0x1EF4,
    0x00E0, // B0-B7 (Ú,Ụ,Ỳ,Ỷ,Ỹ,Ý,Ỵ,à)
    0x1EA3, 0x00E3, 0x00E1, 0x1EA1, 0x1EB2, 0x1EB4, 0x1EAF,
    0x1EB1, // B8-BF (ả,ã,á,ạ,Ẳ,Ẵ,ắ,ằ)
    0x1EB3, 0x1EB5, 0x1EAD, 0x00E8, 0x1EA9, 0x1EAB, 0x1EA5,
    0x1EA7, // C0-C7 (ẳ,ẵ,ậ,è,ẩ,ẫ,ấ,ầ)
    0x1EBB, 0x1EBD, 0x00E9, 0x1EB9, 0x1EC1, 0x1EC3, 0x1EC5,
    0x1EBF, // C8-CF (ẻ,ẽ,é,ẹ,ề,ể,ễ,ế)
    0x1EC7, 0x00EC, 0x1EC9, 0x0129, 0x00ED, 0x1ECB, 0x00F2,
    0x1ED3, // D0-D7 (ệ,ì,ỉ,ĩ,í,ị,ò,ồ)
    0x1ECF, 0x00F5, 0x00F3, 0x1ECD, 0x1ED5, 0x1ED7, 0x1ED1,
    0x1ED9, // D8-DF (ỏ,õ,ó,ọ,ổ,ỗ,ố,ộ)
    0x1EDD, 0x1EDF, 0x1EE1, 0x1EDB, 0x1EE3, 0x00F9, 0x1EE7,
    0x0169, // E0-E7 (ờ,ở,ỡ,ớ,ợ,ù,ủ,ũ)
    0x00FA, 0x1EE5, 0x1EF3, 0x1EF7, 0x1EF9, 0x00FD, 0x1EF5,
    0x1EED, // E8-EF (ú,ụ,ỳ,ỷ,ỹ,ý,ỵ,ử)
    0x1EEF, 0x1EE9, 0x1EEB, 0x1EF1, 0xFFFF, 0xFFFF, 0xFFFF,
    0xFFFF, // F0-F7 (ữ,ứ,ừ,ự, undefined)
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
        map_single_byte(cp)
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
    0x00A0, 0xFFFF, 0x0587, 0x0589, 0x0029, 0x0028, 0x00BB,
    0x00AB, // A0-A7 (NBSP, և, ։, etc.)
    0x2014, 0x002E, 0x055D, 0x002C, 0x002D, 0x055F, 0x2026,
    0x055C, // A8-AF (—, ., ՝, etc.)
    0x055B, 0x055E, 0x0531, 0x0561, 0x0532, 0x0562, 0x0533,
    0x0563, // B0-B7 (՛, ՞, Ա, ա, Բ, բ, Գ, գ)
    0x0534, 0x0564, 0x0535, 0x0565, 0x0536, 0x0566, 0x0537,
    0x0567, // B8-BF (Դ, դ, Ե, delays, Զ, զ, Է, է)
    0x0538, 0x0568, 0x0539, 0x0569, 0x053A, 0x056A, 0x053B,
    0x056B, // C0-C7 (Ը, ը, Թ, թ, Ժ, ժ, Ի, ի)
    0x053C, 0x056C, 0x053D, 0x056D, 0x053E, 0x056E, 0x053F,
    0x056F, // C8-CF (Լ, լ, Խ, խ, Ծ, ծ, Կ, կ)
    0x0540, 0x0570, 0x0541, 0x0571, 0x0542, 0x0572, 0x0543,
    0x0573, // D0-D7 (Հ, հ, Ձ, ձ, Ղ, ղ, Ճ, ճ)
    0x0544, 0x0574, 0x0545, 0x0575, 0x0546, 0x0576, 0x0547,
    0x0577, // D8-DF (Մ, մ, Յ, յ, Ն, ն, Շ, շ)
    0x0548, 0x0578, 0x0549, 0x0579, 0x054A, 0x057A, 0x054B,
    0x057B, // E0-E7 (Ո, delays, Չ, չ, Պ, պ, Ջ, ջ)
    0x054C, 0x057C, 0x054D, 0x057D, 0x054E, 0x057E, 0x054F,
    0x057F, // E8-EF (Ռ, ռ, Ս, delays, Delays, վ, Տ, տ)
    0x0550, 0x0580, 0x0551, 0x0581, 0x0552, 0x0582, 0x0553,
    0x0583, // F0-F7 (Delays, delays, Ց, ց, Delays, delays, Փ, delays)
    0x0554, 0x0584, 0x0555, 0x0585, 0x0556, 0x0586, 0xFFFF,
    0xFFFF, // F8-FF (Ք, ք, Delays, delays, Delays, delays)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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

/// Georgian-PS to Unicode mapping for bytes 0x80-0xFF.
/// Windows-1252 compatible in 0x80-0x9F, with non-contiguous Georgian letter placement.
const GEORGIAN_PS_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x009E, 0x0178, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x10D0, 0x10D1, 0x10D2, 0x10D3, 0x10D4, 0x10D5, 0x10D6, 0x10F1, // C0-C7 (ა-ვ, ჱ)
    0x10D7, 0x10D8, 0x10D9, 0x10DA, 0x10DB, 0x10DC, 0x10F2,
    0x10DD, // C8-CF (თ-ნ, ჲ, ო)
    0x10DE, 0x10DF, 0x10E0, 0x10E1, 0x10E2, 0x10F3, 0x10E3,
    0x10E4, // D0-D7 (პ-ტ, ჳ, უ-ფ)
    0x10E5, 0x10E6, 0x10E7, 0x10E8, 0x10E9, 0x10EA, 0x10EB, 0x10EC, // D8-DF (ქ-წ)
    0x10ED, 0x10EE, 0x10F4, 0x10EF, 0x10F0, 0x10F5, 0x00E6,
    0x00E7, // E0-E7 (ჭ-ხ, ჴ, ჯ-ჰ, ჵ, æç)
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF (è-ï)
    0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7 (ð-÷)
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF, // F8-FF (ø-ÿ)
];

fn decode_georgian_ps(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = GEORGIAN_PS_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_georgian_ps(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in GEORGIAN_PS_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Georgian Academy to Unicode mapping for bytes 0x80-0xFF.
/// Similar to Georgian-PS but with contiguous Georgian letter placement.
const GEORGIAN_ACADEMY_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x009E, 0x0178, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x10D0, 0x10D1, 0x10D2, 0x10D3, 0x10D4, 0x10D5, 0x10D6, 0x10D7, // C0-C7
    0x10D8, 0x10D9, 0x10DA, 0x10DB, 0x10DC, 0x10DD, 0x10DE, 0x10DF, // C8-CF
    0x10E0, 0x10E1, 0x10E2, 0x10E3, 0x10E4, 0x10E5, 0x10E6, 0x10E7, // D0-D7
    0x10E8, 0x10E9, 0x10EA, 0x10EB, 0x10EC, 0x10ED, 0x10EE, 0x10EF, // D8-DF
    0x10F0, 0x10F1, 0x10F2, 0x10F3, 0x10F4, 0x10F5, 0x10F6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF, // F8-FF
];

fn decode_georgian_academy(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = GEORGIAN_ACADEMY_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_georgian_academy(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in GEORGIAN_ACADEMY_TO_UNICODE.iter().enumerate() {
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
    0x0496, 0x0492, 0x04EE, 0x0493, 0x201E, 0x2026, 0x04B6,
    0x04AE, // 80-87 (Ж with descender, Г with stroke, etc.)
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
        map_single_byte(cp)
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

/// RK1048 (Kazakh Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
/// Based on Windows-1251 with Kazakh-specific characters.
/// Position 0x98 is undefined.
const RK1048_TO_UNICODE: [u16; 128] = [
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x049A, 0x04BA, 0x040F, // 88-8F
    0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0x2122, 0x0459, 0x203A, 0x045A, 0x049B, 0x04BB, 0x045F, // 98-9F
    0x00A0, 0x04B0, 0x04B1, 0x04D8, 0x00A4, 0x04E8, 0x00A6, 0x00A7, // A0-A7
    0x0401, 0x00A9, 0x0492, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x04AE, // A8-AF
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x04E9, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x0451, 0x2116, 0x0493, 0x00BB, 0x04D9, 0x04A2, 0x04A3, 0x04AF, // B8-BF
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // C0-C7
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // C8-CF
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // D0-D7
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // D8-DF
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // E0-E7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // E8-EF
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // F0-F7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // F8-FF
];

fn decode_rk1048(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = RK1048_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_rk1048(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in RK1048_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
    0x0EA7, 0x0EAB, 0x0EAD, 0x0EAE, 0xFFFF, 0xFFFF, 0xFFFF,
    0x0EAF, // B8-BF (undefined at BC-BE)
    0x0EB0, 0x0EB2, 0x0EB3, 0x0EB4, 0x0EB5, 0x0EB6, 0x0EB7, 0x0EB8, // C0-C7
    0x0EB9, 0x0EBB, 0x0EBC, 0x0EBD, 0x0EC0, 0x0EC1, 0x0EC2, 0x0EC3, // C8-CF
    0x0EC4, 0x0EC6, 0xFFFF, 0xFFFF, 0x0EC8, 0x0EC9, 0x0ECA,
    0x0ECB, // D0-D7 (undefined at D2-D3)
    0x0ECC, 0x0ECD, 0x0EDC, 0x0EDD, 0x0ED0, 0x0ED1, 0x0ED2, 0x0ED3, // D8-DF
    0x0ED4, 0x0ED5, 0x0ED6, 0x0ED7, 0x0ED8, 0x0ED9, 0xFFFF,
    0xFFFF, // E0-E7 (undefined at E6-E7)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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

/// CP851 (DOS Greek) to Unicode mapping for bytes 0x80-0xFF.
/// Position 0x91 is undefined and marked with 0xFFFF.
const CP851_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x0386, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x0388, 0x00C4, 0x0389, // 88-8F
    0x038A, 0xFFFF, 0x038C, 0x00F4, 0x00F6, 0x038E, 0x00FB, 0x00F9, // 90-97
    0x038F, 0x00D6, 0x00DC, 0x03AC, 0x00A3, 0x03AD, 0x03AE, 0x03AF, // 98-9F
    0x03CA, 0x0390, 0x03CC, 0x03CD, 0x0391, 0x0392, 0x0393, 0x0394, // A0-A7
    0x0395, 0x0396, 0x0397, 0x00BD, 0x0398, 0x0399, 0x00AB, 0x00BB, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x039A, 0x039B, 0x039D, // B0-B7
    0x039C, 0x2563, 0x2551, 0x2557, 0x255D, 0x039E, 0x039F, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x03A0, 0x03A1, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x03A3, // C8-CF
    0x03A4, 0x03A5, 0x03A6, 0x03A7, 0x03A8, 0x03A9, 0x03B1, 0x03B2, // D0-D7
    0x03B3, 0x2518, 0x250C, 0x2588, 0x2584, 0x03B4, 0x03B5, 0x2580, // D8-DF
    0x03B6, 0x03B7, 0x03B8, 0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, // E0-E7
    0x03BE, 0x03BF, 0x03C0, 0x03C1, 0x03C3, 0x03C2, 0x03C4, 0x00B4, // E8-EF
    0x00AD, 0x00B1, 0x03C5, 0x03C6, 0x03C7, 0x00A7, 0x03C8, 0x02DB, // F0-F7
    0x00B0, 0x00A8, 0x03C9, 0x03CB, 0x03B0, 0x03CE, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp851(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP851_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_cp851(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP851_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
    if (0x80..=0x9F).contains(&b) {
        let cp = CP1252_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    } else {
        Ok((char::from(b), 1))
    }
}

fn encode_cp1252(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 || (0xA0..=0xFF).contains(&cp) {
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
            return map_single_byte(unicode);
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

/// ISO-8859-9E (Extended Turkish) to Unicode mapping for bytes 0xA0-0xFF.
const ISO88599E_TO_UNICODE: [u16; 96] = [
    0x00A0, 0x017D, 0x00A2, 0x00A3, 0x20AC, 0x00A5, 0x012C, 0x00A7, // A0-A7
    0x016C, 0x00A9, 0x01E6, 0x00AB, 0x014A, 0x00AD, 0x00AE, 0x01D1, // A8-AF
    0x00B0, 0x017E, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x012D, 0x00B7, // B0-B7
    0x016D, 0x00B9, 0x01E7, 0x00BB, 0x014B, 0x00BD, 0x0178, 0x01D2, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x018F, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x011E, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00DD, // D0-D7
    0x019F, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x0130, 0x015E, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x0259, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x011F, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00FD, // F0-F7
    0x0275, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x0131, 0x015F, 0x00FF, // F8-FF
];

fn decode_iso88599e(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISO88599E_TO_UNICODE[(b - 0xA0) as usize];
        map_single_byte(cp)
    }
}

fn encode_iso88599e(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISO88599E_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
        map_single_byte(cp)
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
            return map_single_byte(unicode);
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
        map_single_byte(cp)
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
    0x20AC, 0x0174, 0x0175, 0xFFFF, 0xFFFF, 0x0176, 0x0177,
    0xFFFF, // 80-87 (€,Ŵ,ŵ,-,-,Ŷ,ŷ,-)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x2026, 0x2122, 0x2030,
    0x2022, // 88-8F (-,-,-,-,…,™,‰,•)
    // 0x90-0x9F
    0x2018, 0x2019, 0x2039, 0x203A, 0x201C, 0x201D, 0x201E,
    0x2013, // 90-97 (',',‹,›,",",„,–)
    0x2014, 0x2212, 0x0152, 0x0153, 0x2020, 0x2021, 0xFB01,
    0xFB02, // 98-9F (—,−,Œ,œ,†,‡,ﬁ,ﬂ)
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
            map_single_byte(cp)
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
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x016F, 0x0107,
    0x00E7, // 80-87 (Ç,ü,é,â,ä,ů,ć,ç)
    0x0142, 0x00EB, 0x0150, 0x0151, 0x00EE, 0x0179, 0x00C4,
    0x0106, // 88-8F (ł,ë,Ő,ő,î,Ź,Ä,Ć)
    // 0x90-0x9F
    0x00C9, 0x0139, 0x013A, 0x00F4, 0x00F6, 0x013D, 0x013E,
    0x015A, // 90-97 (É,Ĺ,ĺ,ô,ö,Ľ,ľ,Ś)
    0x015B, 0x00D6, 0x00DC, 0x0164, 0x0165, 0x0141, 0x00D7,
    0x010D, // 98-9F (ś,Ö,Ü,Ť,ť,Ł,×,č)
    // 0xA0-0xAF
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x0104, 0x0105, 0x017D,
    0x017E, // A0-A7 (á,í,ó,ú,Ą,ą,Ž,ž)
    0x0118, 0x0119, 0x00AC, 0x017A, 0x010C, 0x015F, 0x00AB,
    0x00BB, // A8-AF (Ę,ę,¬,ź,Č,ş,«,»)
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
    0x00D3, 0x00DF, 0x00D4, 0x0143, 0x0144, 0x0148, 0x0160,
    0x0161, // E0-E7 (Ó,ß,Ô,Ń,ń,ň,Š,š)
    0x0154, 0x00DA, 0x0155, 0x0170, 0x00FD, 0x00DD, 0x0163,
    0x00B4, // E8-EF (Ŕ,Ú,ŕ,Ű,ý,Ý,ţ,´)
    // 0xF0-0xFF
    0x00AD, 0x02DD, 0x02DB, 0x02C7, 0x02D8, 0x00A7, 0x00F7,
    0x00B8, // F0-F7 (SHY,˝,˛,ˇ,˘,§,÷,¸)
    0x00B0, 0x00A8, 0x02D9, 0x0171, 0x0158, 0x0159, 0x25A0,
    0x00A0, // F8-FF (°,¨,˙,ű,Ř,ř,■,NBSP)
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
        map_single_byte(cp)
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
    0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6,
    0x0406, // A0-A7 (†,°,¢,£,§,•,¶,І)
    0x00AE, 0x00A9, 0x2122, 0x0402, 0x0452, 0x2260, 0x0403,
    0x0453, // A8-AF (®,©,™,Ђ,ђ,≠,Ѓ,ѓ)
    // 0xB0-0xBF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x0456, 0x00B5, 0x2202,
    0x0408, // B0-B7 (∞,±,≤,≥,і,µ,∂,Ј)
    0x0404, 0x0454, 0x0407, 0x0457, 0x0409, 0x0459, 0x040A,
    0x045A, // B8-BF (Є,є,Ї,ї,Љ,љ,Њ,њ)
    // 0xC0-0xCF
    0x0458, 0x0405, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206,
    0x00AB, // C0-C7 (ј,Ѕ,¬,√,ƒ,≈,∆,«)
    0x00BB, 0x2026, 0x00A0, 0x040B, 0x045B, 0x040C, 0x045C,
    0x0455, // C8-CF (»,…,NBSP,Ћ,ћ,Ќ,ќ,ѕ)
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x201E, // D0-D7 (–,—,",",',',÷,„)
    0x040E, 0x045E, 0x040F, 0x045F, 0x2116, 0x0401, 0x0451,
    0x044F, // D8-DF (Ў,ў,Џ,џ,№,Ё,ё,я)
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
        map_single_byte(cp)
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
    0x00C4, 0x00B9, 0x00B2, 0x00C9, 0x00B3, 0x00D6, 0x00DC,
    0x0385, // 80-87 (Ä,¹,²,É,³,Ö,Ü,΅)
    0x00E0, 0x00E2, 0x00E4, 0x0384, 0x00A8, 0x00E7, 0x00E9,
    0x00E8, // 88-8F (à,â,ä,΄,¨,ç,é,è)
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00A3, 0x2122, 0x00EE, 0x00EF, 0x2022,
    0x00BD, // 90-97 (ê,ë,£,™,î,ï,•,½)
    0x2030, 0x00F4, 0x00F6, 0x00A6, 0x00AD, 0x00F9, 0x00FB,
    0x00FC, // 98-9F (‰,ô,ö,¦,SHY,ù,û,ü)
    // 0xA0-0xAF
    0x2020, 0x0393, 0x0394, 0x0398, 0x039B, 0x039E, 0x03A0,
    0x00DF, // A0-A7 (†,Γ,Δ,Θ,Λ,Ξ,Π,ß)
    0x00AE, 0x00A9, 0x03A3, 0x03AA, 0x00A7, 0x2260, 0x00B0,
    0x00B7, // A8-AF (®,©,Σ,Ϊ,§,≠,°,·)
    // 0xB0-0xBF
    0x0391, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x0392, 0x0395,
    0x0396, // B0-B7 (Α,±,≤,≥,¥,Β,Ε,Ζ)
    0x0397, 0x0399, 0x039A, 0x039C, 0x03A6, 0x03AB, 0x03A8,
    0x03A9, // B8-BF (Η,Ι,Κ,Μ,Φ,Ϋ,Ψ,Ω)
    // 0xC0-0xCF
    0x03AC, 0x039D, 0x00AC, 0x039F, 0x03A1, 0x2248, 0x03A4,
    0x00AB, // C0-C7 (ά,Ν,¬,Ο,Ρ,≈,Τ,«)
    0x00BB, 0x2026, 0x00A0, 0x03A5, 0x03A7, 0x0386, 0x0388,
    0x0153, // C8-CF (»,…,NBSP,Υ,Χ,Ά,Έ,œ)
    // 0xD0-0xDF
    0x2013, 0x2015, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x0389, // D0-D7 (–,―,",",',',÷,Ή)
    0x038A, 0x038C, 0x038E, 0x03AD, 0x03AE, 0x03AF, 0x03CC,
    0x038F, // D8-DF (Ί,Ό,Ύ,έ,ή,ί,ό,Ώ)
    // 0xE0-0xEF
    0x03CD, 0x03B1, 0x03B2, 0x03C8, 0x03B4, 0x03B5, 0x03C6,
    0x03B3, // E0-E7 (ύ,α,β,ψ,δ,ε,φ,γ)
    0x03B7, 0x03B9, 0x03BE, 0x03BA, 0x03BB, 0x03BC, 0x03BD,
    0x03BF, // E8-EF (η,ι,ξ,κ,λ,μ,ν,ο)
    // 0xF0-0xFF
    0x03C0, 0x03CE, 0x03C1, 0x03C3, 0x03C4, 0x03B8, 0x03C9,
    0x03C2, // F0-F7 (π,ώ,ρ,σ,τ,θ,ω,ς)
    0x03C7, 0x03C5, 0x03B6, 0x03CA, 0x03CB, 0x0390, 0x03B0,
    0xFFFF, // F8-FF (χ,υ,ζ,ϊ,ϋ,ΐ,ΰ,-)
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
            map_single_byte(cp)
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

/// Mac Turkish to Unicode mapping for bytes 0x80-0xFF.
/// Based on Mac Roman but with Turkish-specific characters.
const MACTURKISH_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC,
    0x00E1, // 80-87 (Ä,Å,Ç,É,Ñ,Ö,Ü,á)
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9,
    0x00E8, // 88-8F (à,â,ä,ã,å,ç,é,è)
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1,
    0x00F3, // 90-97 (ê,ë,í,ì,î,ï,ñ,ó)
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB,
    0x00FC, // 98-9F (ò,ô,ö,õ,ú,ù,û,ü)
    // 0xA0-0xAF
    0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6,
    0x00DF, // A0-A7 (†,°,¢,£,§,•,¶,ß)
    0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6,
    0x00D8, // A8-AF (®,©,™,´,¨,≠,Æ,Ø)
    // 0xB0-0xBF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202,
    0x2211, // B0-B7 (∞,±,≤,≥,¥,µ,∂,∑)
    0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x00E6,
    0x00F8, // B8-BF (∏,π,∫,ª,º,Ω,æ,ø)
    // 0xC0-0xCF
    0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206,
    0x00AB, // C0-C7 (¿,¡,¬,√,ƒ,≈,∆,«)
    0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152,
    0x0153, // C8-CF (»,…,NBSP,À,Ã,Õ,Œ,œ)
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x25CA, // D0-D7 (–,—,",",',',÷,◊)
    0x00FF, 0x0178, 0x011E, 0x011F, 0x0130, 0x0131, 0x015E,
    0x015F, // D8-DF (ÿ,Ÿ,Ğ,ğ,İ,ı,Ş,ş)
    // 0xE0-0xEF
    0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA,
    0x00C1, // E0-E7 (‡,·,‚,„,‰,Â,Ê,Á)
    0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3,
    0x00D4, // E8-EF (Ë,È,Í,Î,Ï,Ì,Ó,Ô)
    // 0xF0-0xFF
    0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x00F0, 0x02C6,
    0x02DC, // F0-F7 (Apple,Ò,Ú,Û,Ù,ð,ˆ,˜)
    0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB,
    0x02C7, // F8-FF (¯,˘,˙,˚,¸,˝,˛,ˇ)
];

fn decode_macturkish(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACTURKISH_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_macturkish(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACTURKISH_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Icelandic to Unicode mapping for bytes 0x80-0xFF.
/// Based on Mac Roman with Icelandic-specific characters.
const MACICELAND_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC,
    0x00E1, // 80-87 (Ä,Å,Ç,É,Ñ,Ö,Ü,á)
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9,
    0x00E8, // 88-8F (à,â,ä,ã,å,ç,é,è)
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1,
    0x00F3, // 90-97 (ê,ë,í,ì,î,ï,ñ,ó)
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB,
    0x00FC, // 98-9F (ò,ô,ö,õ,ú,ù,û,ü)
    // 0xA0-0xAF
    0x00DD, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6,
    0x00DF, // A0-A7 (Ý,°,¢,£,§,•,¶,ß)
    0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6,
    0x00D8, // A8-AF (®,©,™,´,¨,≠,Æ,Ø)
    // 0xB0-0xBF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202,
    0x2211, // B0-B7 (∞,±,≤,≥,¥,µ,∂,∑)
    0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x00E6,
    0x00F8, // B8-BF (∏,π,∫,ª,º,Ω,æ,ø)
    // 0xC0-0xCF
    0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206,
    0x00AB, // C0-C7 (¿,¡,¬,√,ƒ,≈,∆,«)
    0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152,
    0x0153, // C8-CF (»,…,NBSP,À,Ã,Õ,Œ,œ)
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x25CA, // D0-D7 (–,—,",",',',÷,◊)
    0x00FF, 0x0178, 0x2044, 0x00A4, 0x00D0, 0x00F0, 0x00DE,
    0x00FE, // D8-DF (ÿ,Ÿ,⁄,¤,Ð,ð,Þ,þ)
    // 0xE0-0xEF
    0x00FD, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA,
    0x00C1, // E0-E7 (ý,·,‚,„,‰,Â,Ê,Á)
    0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3,
    0x00D4, // E8-EF (Ë,È,Í,Î,Ï,Ì,Ó,Ô)
    // 0xF0-0xFF
    0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6,
    0x02DC, // F0-F7 (Apple,Ò,Ú,Û,Ù,ı,ˆ,˜)
    0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB,
    0x02C7, // F8-FF (¯,˘,˙,˚,¸,˝,˛,ˇ)
];

fn decode_maciceland(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACICELAND_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_maciceland(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACICELAND_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Central European to Unicode mapping for bytes 0x80-0xFF.
/// Used for Polish, Czech, Slovak, Hungarian on classic Mac OS.
const MACCENTRALEUROPE_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x0100, 0x0101, 0x00C9, 0x0104, 0x00D6, 0x00DC,
    0x00E1, // 80-87 (Ä,Ā,ā,É,Ą,Ö,Ü,á)
    0x0105, 0x010C, 0x00E4, 0x010D, 0x0106, 0x0107, 0x00E9,
    0x0179, // 88-8F (ą,Č,ä,č,Ć,ć,é,Ź)
    // 0x90-0x9F
    0x017A, 0x010E, 0x00ED, 0x010F, 0x0112, 0x0113, 0x0116,
    0x00F3, // 90-97 (ź,Ď,í,ď,Ē,ē,Ė,ó)
    0x0117, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x011A, 0x011B,
    0x00FC, // 98-9F (ė,ô,ö,õ,ú,Ě,ě,ü)
    // 0xA0-0xAF
    0x2020, 0x00B0, 0x0118, 0x00A3, 0x00A7, 0x2022, 0x00B6,
    0x00DF, // A0-A7 (†,°,Ę,£,§,•,¶,ß)
    0x00AE, 0x00A9, 0x2122, 0x0119, 0x00A8, 0x2260, 0x0123,
    0x012E, // A8-AF (®,©,™,ę,¨,≠,ģ,Į)
    // 0xB0-0xBF
    0x012F, 0x012A, 0x2264, 0x2265, 0x012B, 0x0136, 0x2202,
    0x2211, // B0-B7 (į,Ī,≤,≥,ī,Ķ,∂,∑)
    0x0142, 0x013B, 0x013C, 0x013D, 0x013E, 0x0139, 0x013A,
    0x0145, // B8-BF (ł,Ļ,ļ,Ľ,ľ,Ĺ,ĺ,Ņ)
    // 0xC0-0xCF
    0x0146, 0x0143, 0x00AC, 0x221A, 0x0144, 0x0147, 0x2206,
    0x00AB, // C0-C7 (ņ,Ń,¬,√,ń,Ň,∆,«)
    0x00BB, 0x2026, 0x00A0, 0x0148, 0x0150, 0x00D5, 0x0151,
    0x014C, // C8-CF (»,…,NBSP,ň,Ő,Õ,ő,Ō)
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x25CA, // D0-D7 (–,—,",",',',÷,◊)
    0x014D, 0x0154, 0x0155, 0x0158, 0x2039, 0x203A, 0x0159,
    0x0156, // D8-DF (ō,Ŕ,ŕ,Ř,‹,›,ř,Ŗ)
    // 0xE0-0xEF
    0x0157, 0x0160, 0x201A, 0x201E, 0x0161, 0x015A, 0x015B,
    0x00C1, // E0-E7 (ŗ,Š,‚,„,š,Ś,ś,Á)
    0x0164, 0x0165, 0x00CD, 0x017D, 0x017E, 0x016A, 0x00D3,
    0x00D4, // E8-EF (Ť,ť,Í,Ž,ž,Ū,Ó,Ô)
    // 0xF0-0xFF
    0x016B, 0x016E, 0x00DA, 0x016F, 0x0170, 0x0171, 0x0172,
    0x0173, // F0-F7 (ū,Ů,Ú,ů,Ű,ű,Ų,ų)
    0x00DD, 0x00FD, 0x0137, 0x017B, 0x0141, 0x017C, 0x0122,
    0x02C7, // F8-FF (Ý,ý,ķ,Ż,Ł,ż,Ģ,ˇ)
];

fn decode_maccentraleurope(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACCENTRALEUROPE_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_maccentraleurope(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACCENTRALEUROPE_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Ukrainian to Unicode mapping for bytes 0x80-0xFF.
/// Similar to Mac Cyrillic but with Ukrainian-specific characters.
const MACUKRAINE_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Cyrillic А-П)
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87 (А-З)
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F (И-П)
    // 0x90-0x9F (Cyrillic Р-Я)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97 (Р-Ч)
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F (Ш-Я)
    // 0xA0-0xAF
    0x2020, 0x00B0, 0x0490, 0x00A3, 0x00A7, 0x2022, 0x00B6,
    0x0406, // A0-A7 (†,°,Ґ,£,§,•,¶,І)
    0x00AE, 0x00A9, 0x2122, 0x0402, 0x0452, 0x2260, 0x0403,
    0x0453, // A8-AF (®,©,™,Ђ,ђ,≠,Ѓ,ѓ)
    // 0xB0-0xBF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x0456, 0x00B5, 0x0491,
    0x0408, // B0-B7 (∞,±,≤,≥,і,µ,ґ,Ј)
    0x0404, 0x0454, 0x0407, 0x0457, 0x0409, 0x0459, 0x040A,
    0x045A, // B8-BF (Є,є,Ї,ї,Љ,љ,Њ,њ)
    // 0xC0-0xCF
    0x0458, 0x0405, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206,
    0x00AB, // C0-C7 (ј,Ѕ,¬,√,ƒ,≈,∆,«)
    0x00BB, 0x2026, 0x00A0, 0x040B, 0x045B, 0x040C, 0x045C,
    0x0455, // C8-CF (»,…,NBSP,Ћ,ћ,Ќ,ќ,ѕ)
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x201E, // D0-D7 (–,—,",",',',÷,„)
    0x040E, 0x045E, 0x040F, 0x045F, 0x2116, 0x0401, 0x0451,
    0x044F, // D8-DF (Ў,ў,Џ,џ,№,Ё,ё,я)
    // 0xE0-0xEF (Cyrillic а-п)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // E0-E7 (а-з)
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // E8-EF (и-п)
    // 0xF0-0xFF (Cyrillic р-ю + €)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // F0-F7 (р-ч)
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x20AC, // F8-FF (ш-ю,€)
];

fn decode_macukraine(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACUKRAINE_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_macukraine(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACUKRAINE_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP858 (DOS multilingual with Euro) to Unicode mapping for bytes 0x80-0xFF.
/// Same as CP850 but position 0xD5 has Euro (€) instead of dotless i (ı).
const CP858_TO_UNICODE: [u16; 128] = [
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
    0x00F0, 0x00D0, 0x00CA, 0x00CB, 0x00C8, 0x20AC, 0x00CD, 0x00CE, // D0-D7 (0xD5=€)
    0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580, // D8-DF
    0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0x00FE, // E0-E7
    0x00DE, 0x00DA, 0x00DB, 0x00D9, 0x00FD, 0x00DD, 0x00AF, 0x00B4, // E8-EF
    0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8, // F0-F7
    0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp858(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP858_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp858(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP858_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Romanian to Unicode mapping for bytes 0x80-0xFF.
/// Similar to Mac Roman but with Romanian-specific Ș, ș, Ț, ț characters.
const MACROMANIAN_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC,
    0x00E1, // 80-87 (Ä,Å,Ç,É,Ñ,Ö,Ü,á)
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9,
    0x00E8, // 88-8F (à,â,ä,ã,å,ç,é,è)
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1,
    0x00F3, // 90-97 (ê,ë,í,ì,î,ï,ñ,ó)
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB,
    0x00FC, // 98-9F (ò,ô,ö,õ,ú,ù,û,ü)
    // 0xA0-0xAF
    0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6,
    0x00DF, // A0-A7 (†,°,¢,£,§,•,¶,ß)
    0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x0102,
    0x0218, // A8-AF (®,©,™,´,¨,≠,Ă,Ș)
    // 0xB0-0xBF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202,
    0x2211, // B0-B7 (∞,±,≤,≥,¥,µ,∂,∑)
    0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x0103,
    0x0219, // B8-BF (∏,π,∫,ª,º,Ω,ă,ș)
    // 0xC0-0xCF
    0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206,
    0x00AB, // C0-C7 (¿,¡,¬,√,ƒ,≈,∆,«)
    0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152,
    0x0153, // C8-CF (»,…,NBSP,À,Ã,Õ,Œ,œ)
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x25CA, // D0-D7 (–,—,",",',',÷,◊)
    0x00FF, 0x0178, 0x2044, 0x00A4, 0x021A, 0x021B, 0x2039,
    0x203A, // D8-DF (ÿ,Ÿ,⁄,¤,Ț,ț,‹,›)
    // 0xE0-0xEF
    0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA,
    0x00C1, // E0-E7 (‡,·,‚,„,‰,Â,Ê,Á)
    0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3,
    0x00D4, // E8-EF (Ë,È,Í,Î,Ï,Ì,Ó,Ô)
    // 0xF0-0xFF
    0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6,
    0x02DC, // F0-F7 (Apple,Ò,Ú,Û,Ù,ı,ˆ,˜)
    0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB,
    0x02C7, // F8-FF (¯,˘,˙,˚,¸,˝,˛,ˇ)
];

fn decode_macromanian(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACROMANIAN_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_macromanian(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACROMANIAN_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Sami (Northern Sami) to Unicode mapping for bytes 0x80-0xFF.
/// Used for Sami languages in Scandinavian countries.
const MACSAMI_TO_UNICODE: [u16; 128] = [
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, // 80-87
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E8, // 88-8F
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3, // 90-97
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC, // 98-9F
    0x00DD, 0x00B0, 0x010C, 0x00A3, 0x00A7, 0x2022, 0x00B6, 0x00DF, // A0-A7
    0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6, 0x00D8, // A8-AF
    0x0110, 0x014A, 0x021E, 0x021F, 0x0160, 0x0166, 0x2202, 0x017D, // B0-B7
    0x010D, 0x0111, 0x014B, 0x0161, 0x0167, 0x017E, 0x00E6, 0x00F8, // B8-BF
    0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB, // C0-C7
    0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152, 0x0153, // C8-CF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x25CA, // D0-D7
    0x00FF, 0x0178, 0x2044, 0x00A4, 0x00D0, 0x00F0, 0x00DE, 0x00FE, // D8-DF
    0x00FD, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA, 0x00C1, // E0-E7
    0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3, 0x00D4, // E8-EF
    0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x01B7, 0x0292, // F0-F7
    0x01EE, 0x01EF, 0x01E4, 0x01E5, 0x01E6, 0x01E7, 0x01E8, 0x01E9, // F8-FF
];

fn decode_macsami(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACSAMI_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_macsami(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACSAMI_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// Mac Croatian to Unicode mapping for bytes 0x80-0xFF.
/// Similar to Mac Roman but with Croatian/Slovenian-specific characters.
const MACCROATIAN_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC,
    0x00E1, // 80-87 (Ä,Å,Ç,É,Ñ,Ö,Ü,á)
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9,
    0x00E8, // 88-8F (à,â,ä,ã,å,ç,é,è)
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1,
    0x00F3, // 90-97 (ê,ë,í,ì,î,ï,ñ,ó)
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB,
    0x00FC, // 98-9F (ò,ô,ö,õ,ú,ù,û,ü)
    // 0xA0-0xAF
    0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6,
    0x00DF, // A0-A7 (†,°,¢,£,§,•,¶,ß)
    0x00AE, 0x0160, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x017D,
    0x00D8, // A8-AF (®,Š,™,´,¨,≠,Ž,Ø)
    // 0xB0-0xBF
    0x221E, 0x00B1, 0x2264, 0x2265, 0x2206, 0x00B5, 0x2202,
    0x2211, // B0-B7 (∞,±,≤,≥,∆,µ,∂,∑)
    0x220F, 0x0161, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x017E,
    0x00F8, // B8-BF (∏,š,∫,ª,º,Ω,ž,ø)
    // 0xC0-0xCF
    0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x0106,
    0x00AB, // C0-C7 (¿,¡,¬,√,ƒ,≈,Ć,«)
    0x010C, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152,
    0x0153, // C8-CF (Č,…,NBSP,À,Ã,Õ,Œ,œ)
    // 0xD0-0xDF
    0x0110, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7,
    0x25CA, // D0-D7 (Đ,—,",",',',÷,◊)
    0x00FF, 0x0178, 0x2044, 0x00A4, 0x0111, 0x0107, 0x010D,
    0x010D, // D8-DF (ÿ,Ÿ,⁄,¤,đ,ć,č,č)
    // 0xE0-0xEF
    0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x0107,
    0x00C1, // E0-E7 (‡,·,‚,„,‰,Â,ć,Á)
    0x010D, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3,
    0x00D4, // E8-EF (č,È,Í,Î,Ï,Ì,Ó,Ô)
    // 0xF0-0xFF
    0x0111, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6,
    0x02DC, // F0-F7 (đ,Ò,Ú,Û,Ù,ı,ˆ,˜)
    0x00AF, 0x03C0, 0x00CB, 0x02DA, 0x00B8, 0x00CA, 0x00E6,
    0x02C7, // F8-FF (¯,π,Ë,˚,¸,Ê,æ,ˇ)
];

fn decode_maccroatian(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACCROATIAN_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_maccroatian(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACCROATIAN_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP720 (DOS Arabic) to Unicode mapping for bytes 0x80-0xFF.
const CP720_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (undefined/control + some Arabic)
    0xFFFF, 0xFFFF, 0x00E9, 0x00E2, 0xFFFF, 0x00E0, 0xFFFF, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    // 0x90-0x9F (undefined + some)
    0xFFFF, 0x0651, 0x0652, 0x00F4, 0x00A4, 0x0640, 0x00FB, 0x00F9, // 90-97
    0x0621, 0x0622, 0x0623, 0x0624, 0x00A3, 0x0625, 0x0626, 0x0627, // 98-9F
    // 0xA0-0xAF (Arabic letters)
    0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F, // A0-A7
    0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x00AB, 0x00BB, // A8-AF
    // 0xB0-0xBF (box drawing)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    // 0xC0-0xCF (box drawing)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    // 0xD0-0xDF (box drawing + misc)
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    // 0xE0-0xEF (Arabic letters)
    0x0636, 0x0637, 0x0638, 0x0639, 0x063A, 0x0641, 0x00B5, 0x0642, // E0-E7
    0x0643, 0x0644, 0x0645, 0x0646, 0x0647, 0x0648, 0x0649, 0x064A, // E8-EF
    // 0xF0-0xFF (misc symbols)
    0x2261, 0x064B, 0x064C, 0x064D, 0x064E, 0x064F, 0x0650, 0x2248, // F0-F7
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp720(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP720_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_cp720(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP720_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACHEBREW_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x05F2, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, // 80-87
    0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E8, // 88-8F
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3, // 90-97
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC, // 98-9F
    // 0xA0-0xAF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x20AA, 0xFFFF, // A0-A7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // A8-AF
    // 0xB0-0xBF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // B0-B7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // B8-BF
    // 0xC0-0xCF
    0xFFFF, 0x201E, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x05BC, 0xFB4B, // C0-C7
    0xFB35, 0x2026, 0x00A0, 0x05B8, 0x05B7, 0x05B5, 0x05B6, 0x05B4, // C8-CF
    // 0xD0-0xDF
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0xFB2A, 0xFB2B, // D0-D7
    0x05BF, 0x05B0, 0x05B2, 0x05B1, 0x05BB, 0x05B9, 0xFFFF, 0x05B3, // D8-DF
    // 0xE0-0xEF (Hebrew letters)
    0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, 0x05D6, 0x05D7, // E0-E7
    0x05D8, 0x05D9, 0x05DA, 0x05DB, 0x05DC, 0x05DD, 0x05DE, 0x05DF, // E8-EF
    // 0xF0-0xFF (Hebrew letters)
    0x05E0, 0x05E1, 0x05E2, 0x05E3, 0x05E4, 0x05E5, 0x05E6, 0x05E7, // F0-F7
    0x05E8, 0x05E9, 0x05EA, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_machebrew(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACHEBREW_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_machebrew(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACHEBREW_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACARABIC_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F
    0x00C4, 0x00A0, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, // 80-87
    0x00E0, 0x00E2, 0x00E4, 0x06BA, 0x00AB, 0x00E7, 0x00E9, 0x00E8, // 88-8F
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00ED, 0x2026, 0x00EE, 0x00EF, 0x00F1, 0x00F3, // 90-97
    0x00BB, 0x00F4, 0x00F6, 0x00F7, 0x00FA, 0x00F9, 0x00FB, 0x00FC, // 98-9F
    // 0xA0-0xAF (Arabic)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // A0-A7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x060C, 0xFFFF, 0xFFFF, 0xFFFF, // A8-AF
    // 0xB0-0xBF (Arabic)
    0x0660, 0x0661, 0x0662, 0x0663, 0x0664, 0x0665, 0x0666, 0x0667, // B0-B7
    0x0668, 0x0669, 0xFFFF, 0x061B, 0xFFFF, 0xFFFF, 0xFFFF, 0x061F, // B8-BF
    // 0xC0-0xCF (Arabic letters)
    0x066D, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627, // C0-C7
    0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F, // C8-CF
    // 0xD0-0xDF (Arabic letters)
    0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x0637, // D0-D7
    0x0638, 0x0639, 0x063A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Arabic letters)
    0x0640, 0x0641, 0x0642, 0x0643, 0x0644, 0x0645, 0x0646, 0x0647, // E0-E7
    0x0648, 0x0649, 0x064A, 0x064B, 0x064C, 0x064D, 0x064E, 0x064F, // E8-EF
    // 0xF0-0xFF
    0x0650, 0x0651, 0x0652, 0x067E, 0x0679, 0x0686, 0x06D5, 0x06A4, // F0-F7
    0x06AF, 0x0688, 0x0691, 0xFFFF, 0xFFFF, 0xFFFF, 0x0698, 0x06D2, // F8-FF
];

fn decode_macarabic(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACARABIC_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macarabic(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACARABIC_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACTHAI_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Mac specific symbols)
    0x00AB, 0x00BB, 0x2026, 0xF88C, 0xF88F, 0xF892, 0xF895, 0xF898, // 80-87
    0xF88B, 0xF88E, 0xF891, 0xF894, 0xF897, 0x201C, 0x201D, 0xF899, // 88-8F
    // 0x90-0x9F (Mac specific)
    0xFFFF, 0x2022, 0xF884, 0xF889, 0xF885, 0xF886, 0xF887, 0xF888, // 90-97
    0xF88A, 0xF88D, 0xF890, 0xF893, 0xF896, 0x2018, 0x2019, 0xFFFF, // 98-9F
    // 0xA0-0xAF (Thai consonants)
    0x00A0, 0x0E01, 0x0E02, 0x0E03, 0x0E04, 0x0E05, 0x0E06, 0x0E07, // A0-A7
    0x0E08, 0x0E09, 0x0E0A, 0x0E0B, 0x0E0C, 0x0E0D, 0x0E0E, 0x0E0F, // A8-AF
    // 0xB0-0xBF (Thai consonants)
    0x0E10, 0x0E11, 0x0E12, 0x0E13, 0x0E14, 0x0E15, 0x0E16, 0x0E17, // B0-B7
    0x0E18, 0x0E19, 0x0E1A, 0x0E1B, 0x0E1C, 0x0E1D, 0x0E1E, 0x0E1F, // B8-BF
    // 0xC0-0xCF (Thai consonants and vowels)
    0x0E20, 0x0E21, 0x0E22, 0x0E23, 0x0E24, 0x0E25, 0x0E26, 0x0E27, // C0-C7
    0x0E28, 0x0E29, 0x0E2A, 0x0E2B, 0x0E2C, 0x0E2D, 0x0E2E, 0x0E2F, // C8-CF
    // 0xD0-0xDF (Thai vowels)
    0x0E30, 0x0E31, 0x0E32, 0x0E33, 0x0E34, 0x0E35, 0x0E36, 0x0E37, // D0-D7
    0x0E38, 0x0E39, 0x0E3A, 0xFEFF, 0x200B, 0x2013, 0x2014, 0x0E3F, // D8-DF
    // 0xE0-0xEF (Thai vowels and tone marks)
    0x0E40, 0x0E41, 0x0E42, 0x0E43, 0x0E44, 0x0E45, 0x0E46, 0x0E47, // E0-E7
    0x0E48, 0x0E49, 0x0E4A, 0x0E4B, 0x0E4C, 0x0E4D, 0x2122, 0x0E4F, // E8-EF
    // 0xF0-0xFF (Thai digits and special)
    0x0E50, 0x0E51, 0x0E52, 0x0E53, 0x0E54, 0x0E55, 0x0E56, 0x0E57, // F0-F7
    0x0E58, 0x0E59, 0x00AE, 0x00A9, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_macthai(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACTHAI_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macthai(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACTHAI_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACFARSI_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (same as MacArabic)
    0x00C4, 0x00A0, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, // 80-87
    0x00E0, 0x00E2, 0x00E4, 0x06BA, 0x00AB, 0x00E7, 0x00E9, 0x00E8, // 88-8F
    // 0x90-0x9F
    0x00EA, 0x00EB, 0x00ED, 0x2026, 0x00EE, 0x00EF, 0x00F1, 0x00F3, // 90-97
    0x00BB, 0x00F4, 0x00F6, 0x00F7, 0x00FA, 0x00F9, 0x00FB, 0x00FC, // 98-9F
    // 0xA0-0xAF (Persian digits)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // A0-A7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x060C, 0xFFFF, 0xFFFF, 0xFFFF, // A8-AF
    // 0xB0-0xBF (Persian-Eastern Arabic digits)
    0x06F0, 0x06F1, 0x06F2, 0x06F3, 0x06F4, 0x06F5, 0x06F6, 0x06F7, // B0-B7
    0x06F8, 0x06F9, 0xFFFF, 0x061B, 0xFFFF, 0xFFFF, 0xFFFF, 0x061F, // B8-BF
    // 0xC0-0xCF (Arabic letters)
    0x066D, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627, // C0-C7
    0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F, // C8-CF
    // 0xD0-0xDF (Arabic letters)
    0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x0637, // D0-D7
    0x0638, 0x0639, 0x063A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Arabic letters)
    0x0640, 0x0641, 0x0642, 0x06A9, 0x0644, 0x0645, 0x0646,
    0x0647, // E0-E7 (0xE3=ک instead of ك)
    0x0648, 0x0649, 0x06CC, 0x064B, 0x064C, 0x064D, 0x064E,
    0x064F, // E8-EF (0xEA=ی instead of ي)
    // 0xF0-0xFF (Persian-specific)
    0x0650, 0x0651, 0x0652, 0x067E, 0x0679, 0x0686, 0x06D5, 0x06A4, // F0-F7
    0x06AF, 0x0688, 0x0691, 0xFFFF, 0xFFFF, 0xFFFF, 0x0698, 0x06D2, // F8-FF
];

fn decode_macfarsi(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACFARSI_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macfarsi(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACFARSI_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACDEVANAGARI_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Devanagari vowels)
    0xFFFF, 0x0901, 0x0902, 0x0903, 0x0905, 0x0906, 0x0907, 0x0908, // 80-87
    0x0909, 0x090A, 0x090B, 0x090E, 0x090F, 0x0910, 0x090D, 0x0912, // 88-8F
    // 0x90-0x9F (Devanagari vowels and consonants)
    0x0913, 0x0914, 0x0911, 0x0915, 0x0916, 0x0917, 0x0918, 0x0919, // 90-97
    0x091A, 0x091B, 0x091C, 0x091D, 0x091E, 0x091F, 0x0920, 0x0921, // 98-9F
    // 0xA0-0xAF (Devanagari consonants)
    0x0922, 0x0923, 0x0924, 0x0925, 0x0926, 0x0927, 0x0928, 0x0929, // A0-A7
    0x092A, 0x092B, 0x092C, 0x092D, 0x092E, 0x092F, 0x095F, 0x0930, // A8-AF
    // 0xB0-0xBF (Devanagari consonants and matras)
    0x0931, 0x0932, 0x0933, 0x0934, 0x0935, 0x0936, 0x0937, 0x0938, // B0-B7
    0x0939, 0xFFFF, 0x093E, 0x093F, 0x0940, 0x0941, 0x0942, 0x0943, // B8-BF
    // 0xC0-0xCF (Devanagari matras and marks)
    0x0946, 0x0947, 0x0948, 0x0945, 0x094A, 0x094B, 0x094C, 0x0949, // C0-C7
    0x094D, 0x093C, 0x0964, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Devanagari digits)
    0x0966, 0x0967, 0x0968, 0x0969, 0x096A, 0x096B, 0x096C, 0x096D, // E0-E7
    0x096E, 0x096F, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0x0950, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_macdevanagari(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACDEVANAGARI_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macdevanagari(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACDEVANAGARI_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACGURMUKHI_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Gurmukhi vowels)
    0xFFFF, 0x0A01, 0x0A02, 0x0A03, 0x0A05, 0x0A06, 0x0A07, 0x0A08, // 80-87
    0x0A09, 0x0A0A, 0xFFFF, 0xFFFF, 0xFFFF, 0x0A0F, 0x0A10, 0xFFFF, // 88-8F
    // 0x90-0x9F (Gurmukhi vowels and consonants)
    0xFFFF, 0x0A13, 0x0A14, 0x0A15, 0x0A16, 0x0A17, 0x0A18, 0x0A19, // 90-97
    0x0A1A, 0x0A1B, 0x0A1C, 0x0A1D, 0x0A1E, 0x0A1F, 0x0A20, 0x0A21, // 98-9F
    // 0xA0-0xAF (Gurmukhi consonants)
    0x0A22, 0x0A23, 0x0A24, 0x0A25, 0x0A26, 0x0A27, 0x0A28, 0xFFFF, // A0-A7
    0x0A2A, 0x0A2B, 0x0A2C, 0x0A2D, 0x0A2E, 0x0A2F, 0xFFFF, 0x0A30, // A8-AF
    // 0xB0-0xBF (Gurmukhi consonants and matras)
    0xFFFF, 0x0A32, 0x0A33, 0xFFFF, 0x0A35, 0x0A36, 0x0A37, 0x0A38, // B0-B7
    0x0A39, 0xFFFF, 0x0A3E, 0x0A3F, 0x0A40, 0x0A41, 0x0A42, 0xFFFF, // B8-BF
    // 0xC0-0xCF (Gurmukhi matras and marks)
    0x0A47, 0x0A48, 0xFFFF, 0xFFFF, 0x0A4B, 0x0A4C, 0x0A4D, 0xFFFF, // C0-C7
    0xFFFF, 0x0A3C, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Gurmukhi digits)
    0x0A66, 0x0A67, 0x0A68, 0x0A69, 0x0A6A, 0x0A6B, 0x0A6C, 0x0A6D, // E0-E7
    0x0A6E, 0x0A6F, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0x0A74, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_macgurmukhi(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACGURMUKHI_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macgurmukhi(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACGURMUKHI_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACGUJARATI_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Gujarati vowels)
    0xFFFF, 0x0A81, 0x0A82, 0x0A83, 0x0A85, 0x0A86, 0x0A87, 0x0A88, // 80-87
    0x0A89, 0x0A8A, 0x0A8B, 0xFFFF, 0x0A8F, 0x0A90, 0x0A8D, 0xFFFF, // 88-8F
    // 0x90-0x9F (Gujarati vowels and consonants)
    0x0A93, 0x0A94, 0x0A91, 0x0A95, 0x0A96, 0x0A97, 0x0A98, 0x0A99, // 90-97
    0x0A9A, 0x0A9B, 0x0A9C, 0x0A9D, 0x0A9E, 0x0A9F, 0x0AA0, 0x0AA1, // 98-9F
    // 0xA0-0xAF (Gujarati consonants)
    0x0AA2, 0x0AA3, 0x0AA4, 0x0AA5, 0x0AA6, 0x0AA7, 0x0AA8, 0xFFFF, // A0-A7
    0x0AAA, 0x0AAB, 0x0AAC, 0x0AAD, 0x0AAE, 0x0AAF, 0xFFFF, 0x0AB0, // A8-AF
    // 0xB0-0xBF (Gujarati consonants and matras)
    0xFFFF, 0x0AB2, 0x0AB3, 0xFFFF, 0x0AB5, 0x0AB6, 0x0AB7, 0x0AB8, // B0-B7
    0x0AB9, 0xFFFF, 0x0ABE, 0x0ABF, 0x0AC0, 0x0AC1, 0x0AC2, 0x0AC3, // B8-BF
    // 0xC0-0xCF (Gujarati matras and marks)
    0xFFFF, 0x0AC7, 0x0AC8, 0x0AC5, 0xFFFF, 0x0ACB, 0x0ACC, 0x0AC9, // C0-C7
    0x0ACD, 0x0ABC, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Gujarati digits)
    0x0AE6, 0x0AE7, 0x0AE8, 0x0AE9, 0x0AEA, 0x0AEB, 0x0AEC, 0x0AED, // E0-E7
    0x0AEE, 0x0AEF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0x0AD0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_macgujarati(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACGUJARATI_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macgujarati(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACGUJARATI_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACKANNADA_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Kannada vowels)
    0xFFFF, 0xFFFF, 0x0C82, 0x0C83, 0xFFFF, 0x0C85, 0x0C86, 0x0C87, // 80-87
    0x0C88, 0x0C89, 0x0C8A, 0x0C8B, 0x0C8C, 0xFFFF, 0x0C8E, 0x0C8F, // 88-8F
    // 0x90-0x9F (Kannada vowels and consonants)
    0x0C90, 0xFFFF, 0x0C92, 0x0C93, 0x0C94, 0x0C95, 0x0C96, 0x0C97, // 90-97
    0x0C98, 0x0C99, 0x0C9A, 0x0C9B, 0x0C9C, 0x0C9D, 0x0C9E, 0x0C9F, // 98-9F
    // 0xA0-0xAF (Kannada consonants)
    0x0CA0, 0x0CA1, 0x0CA2, 0x0CA3, 0x0CA4, 0x0CA5, 0x0CA6, 0x0CA7, // A0-A7
    0x0CA8, 0xFFFF, 0x0CAA, 0x0CAB, 0x0CAC, 0x0CAD, 0x0CAE, 0x0CAF, // A8-AF
    // 0xB0-0xBF (Kannada consonants and matras)
    0x0CB0, 0x0CB1, 0x0CB2, 0x0CB3, 0xFFFF, 0x0CB5, 0x0CB6, 0x0CB7, // B0-B7
    0x0CB8, 0x0CB9, 0xFFFF, 0x0CBE, 0x0CBF, 0x0CC0, 0x0CC1, 0x0CC2, // B8-BF
    // 0xC0-0xCF (Kannada matras and marks)
    0x0CC3, 0x0CC4, 0xFFFF, 0x0CC6, 0x0CC7, 0x0CC8, 0xFFFF, 0x0CCA, // C0-C7
    0x0CCB, 0x0CCC, 0x0CCD, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Kannada digits)
    0x0CE6, 0x0CE7, 0x0CE8, 0x0CE9, 0x0CEA, 0x0CEB, 0x0CEC, 0x0CED, // E0-E7
    0x0CEE, 0x0CEF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_mackannada(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACKANNADA_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_mackannada(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACKANNADA_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACTELUGU_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Telugu vowels)
    0xFFFF, 0x0C01, 0x0C02, 0x0C03, 0xFFFF, 0x0C05, 0x0C06, 0x0C07, // 80-87
    0x0C08, 0x0C09, 0x0C0A, 0x0C0B, 0x0C0C, 0xFFFF, 0x0C0E, 0x0C0F, // 88-8F
    // 0x90-0x9F (Telugu vowels and consonants)
    0x0C10, 0xFFFF, 0x0C12, 0x0C13, 0x0C14, 0x0C15, 0x0C16, 0x0C17, // 90-97
    0x0C18, 0x0C19, 0x0C1A, 0x0C1B, 0x0C1C, 0x0C1D, 0x0C1E, 0x0C1F, // 98-9F
    // 0xA0-0xAF (Telugu consonants)
    0x0C20, 0x0C21, 0x0C22, 0x0C23, 0x0C24, 0x0C25, 0x0C26, 0x0C27, // A0-A7
    0x0C28, 0xFFFF, 0x0C2A, 0x0C2B, 0x0C2C, 0x0C2D, 0x0C2E, 0x0C2F, // A8-AF
    // 0xB0-0xBF (Telugu consonants and matras)
    0x0C30, 0x0C31, 0x0C32, 0x0C33, 0xFFFF, 0x0C35, 0x0C36, 0x0C37, // B0-B7
    0x0C38, 0x0C39, 0xFFFF, 0x0C3E, 0x0C3F, 0x0C40, 0x0C41, 0x0C42, // B8-BF
    // 0xC0-0xCF (Telugu matras and marks)
    0x0C43, 0x0C44, 0xFFFF, 0x0C46, 0x0C47, 0x0C48, 0xFFFF, 0x0C4A, // C0-C7
    0x0C4B, 0x0C4C, 0x0C4D, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Telugu digits)
    0x0C66, 0x0C67, 0x0C68, 0x0C69, 0x0C6A, 0x0C6B, 0x0C6C, 0x0C6D, // E0-E7
    0x0C6E, 0x0C6F, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_mactelugu(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACTELUGU_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_mactelugu(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACTELUGU_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACORIYA_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Oriya vowels)
    0xFFFF, 0x0B01, 0x0B02, 0x0B03, 0xFFFF, 0x0B05, 0x0B06, 0x0B07, // 80-87
    0x0B08, 0x0B09, 0x0B0A, 0x0B0B, 0x0B0C, 0xFFFF, 0xFFFF, 0x0B0F, // 88-8F
    // 0x90-0x9F (Oriya vowels and consonants)
    0x0B10, 0xFFFF, 0xFFFF, 0x0B13, 0x0B14, 0x0B15, 0x0B16, 0x0B17, // 90-97
    0x0B18, 0x0B19, 0x0B1A, 0x0B1B, 0x0B1C, 0x0B1D, 0x0B1E, 0x0B1F, // 98-9F
    // 0xA0-0xAF (Oriya consonants)
    0x0B20, 0x0B21, 0x0B22, 0x0B23, 0x0B24, 0x0B25, 0x0B26, 0x0B27, // A0-A7
    0x0B28, 0xFFFF, 0x0B2A, 0x0B2B, 0x0B2C, 0x0B2D, 0x0B2E, 0x0B2F, // A8-AF
    // 0xB0-0xBF (Oriya consonants and matras)
    0x0B30, 0xFFFF, 0x0B32, 0x0B33, 0xFFFF, 0xFFFF, 0x0B36, 0x0B37, // B0-B7
    0x0B38, 0x0B39, 0xFFFF, 0x0B3E, 0x0B3F, 0x0B40, 0x0B41, 0x0B42, // B8-BF
    // 0xC0-0xCF (Oriya matras and marks)
    0x0B43, 0xFFFF, 0xFFFF, 0x0B47, 0x0B48, 0xFFFF, 0xFFFF, 0x0B4B, // C0-C7
    0x0B4C, 0x0B4D, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF (Oriya special characters)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0B5C, 0x0B5D, // D0-D7
    0xFFFF, 0x0B5F, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Oriya digits)
    0x0B66, 0x0B67, 0x0B68, 0x0B69, 0x0B6A, 0x0B6B, 0x0B6C, 0x0B6D, // E0-E7
    0x0B6E, 0x0B6F, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_macoriya(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACORIYA_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macoriya(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACORIYA_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACBENGALI_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Bengali vowels and signs)
    0xFFFF, 0x0981, 0x0982, 0x0983, 0xFFFF, 0x0985, 0x0986, 0x0987, // 80-87
    0x0988, 0x0989, 0x098A, 0x098B, 0x098C, 0xFFFF, 0xFFFF, 0x098F, // 88-8F
    // 0x90-0x9F (Bengali vowels and consonants)
    0x0990, 0xFFFF, 0xFFFF, 0x0993, 0x0994, 0x0995, 0x0996, 0x0997, // 90-97
    0x0998, 0x0999, 0x099A, 0x099B, 0x099C, 0x099D, 0x099E, 0x099F, // 98-9F
    // 0xA0-0xAF (Bengali consonants)
    0x09A0, 0x09A1, 0x09A2, 0x09A3, 0x09A4, 0x09A5, 0x09A6, 0x09A7, // A0-A7
    0x09A8, 0xFFFF, 0x09AA, 0x09AB, 0x09AC, 0x09AD, 0x09AE, 0x09AF, // A8-AF
    // 0xB0-0xBF (Bengali consonants and matras)
    0x09B0, 0xFFFF, 0x09B2, 0xFFFF, 0xFFFF, 0xFFFF, 0x09B6, 0x09B7, // B0-B7
    0x09B8, 0x09B9, 0xFFFF, 0x09BE, 0x09BF, 0x09C0, 0x09C1, 0x09C2, // B8-BF
    // 0xC0-0xCF (Bengali matras and marks)
    0x09C3, 0x09C4, 0xFFFF, 0x09C7, 0x09C8, 0xFFFF, 0xFFFF, 0x09CB, // C0-C7
    0x09CC, 0x09CD, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF (Bengali special characters)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x09DC, 0x09DD, // D0-D7
    0xFFFF, 0x09DF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Bengali digits)
    0x09E6, 0x09E7, 0x09E8, 0x09E9, 0x09EA, 0x09EB, 0x09EC, 0x09ED, // E0-E7
    0x09EE, 0x09EF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_macbengali(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACBENGALI_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macbengali(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACBENGALI_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACMALAYALAM_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Malayalam vowels and signs)
    0xFFFF, 0x0D01, 0x0D02, 0x0D03, 0xFFFF, 0x0D05, 0x0D06, 0x0D07, // 80-87
    0x0D08, 0x0D09, 0x0D0A, 0x0D0B, 0x0D0C, 0xFFFF, 0x0D0E, 0x0D0F, // 88-8F
    // 0x90-0x9F (Malayalam vowels and consonants)
    0x0D10, 0xFFFF, 0x0D12, 0x0D13, 0x0D14, 0x0D15, 0x0D16, 0x0D17, // 90-97
    0x0D18, 0x0D19, 0x0D1A, 0x0D1B, 0x0D1C, 0x0D1D, 0x0D1E, 0x0D1F, // 98-9F
    // 0xA0-0xAF (Malayalam consonants)
    0x0D20, 0x0D21, 0x0D22, 0x0D23, 0x0D24, 0x0D25, 0x0D26, 0x0D27, // A0-A7
    0x0D28, 0xFFFF, 0x0D2A, 0x0D2B, 0x0D2C, 0x0D2D, 0x0D2E, 0x0D2F, // A8-AF
    // 0xB0-0xBF (Malayalam consonants and matras)
    0x0D30, 0x0D31, 0x0D32, 0x0D33, 0x0D34, 0x0D35, 0x0D36, 0x0D37, // B0-B7
    0x0D38, 0x0D39, 0xFFFF, 0x0D3E, 0x0D3F, 0x0D40, 0x0D41, 0x0D42, // B8-BF
    // 0xC0-0xCF (Malayalam matras and marks)
    0x0D43, 0xFFFF, 0x0D46, 0x0D47, 0x0D48, 0xFFFF, 0x0D4A, 0x0D4B, // C0-C7
    0x0D4C, 0x0D4D, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Malayalam digits)
    0x0D66, 0x0D67, 0x0D68, 0x0D69, 0x0D6A, 0x0D6B, 0x0D6C, 0x0D6D, // E0-E7
    0x0D6E, 0x0D6F, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_macmalayalam(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACMALAYALAM_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_macmalayalam(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACMALAYALAM_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MACTAMIL_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Tamil vowels and signs)
    0xFFFF, 0xFFFF, 0x0B82, 0x0B83, 0xFFFF, 0x0B85, 0x0B86, 0x0B87, // 80-87
    0x0B88, 0x0B89, 0x0B8A, 0xFFFF, 0xFFFF, 0xFFFF, 0x0B8E, 0x0B8F, // 88-8F
    // 0x90-0x9F (Tamil vowels and consonants)
    0x0B90, 0xFFFF, 0x0B92, 0x0B93, 0x0B94, 0x0B95, 0xFFFF, 0xFFFF, // 90-97
    0xFFFF, 0x0B99, 0x0B9A, 0xFFFF, 0x0B9C, 0xFFFF, 0x0B9E, 0x0B9F, // 98-9F
    // 0xA0-0xAF (Tamil consonants)
    0xFFFF, 0xFFFF, 0xFFFF, 0x0BA3, 0x0BA4, 0xFFFF, 0xFFFF, 0xFFFF, // A0-A7
    0x0BA8, 0x0BA9, 0x0BAA, 0xFFFF, 0xFFFF, 0xFFFF, 0x0BAE, 0x0BAF, // A8-AF
    // 0xB0-0xBF (Tamil consonants and matras)
    0x0BB0, 0x0BB1, 0x0BB2, 0x0BB3, 0x0BB4, 0x0BB5, 0xFFFF, 0x0BB7, // B0-B7
    0x0BB8, 0x0BB9, 0xFFFF, 0x0BBE, 0x0BBF, 0x0BC0, 0x0BC1, 0x0BC2, // B8-BF
    // 0xC0-0xCF (Tamil matras and marks)
    0xFFFF, 0xFFFF, 0x0BC6, 0x0BC7, 0x0BC8, 0xFFFF, 0x0BCA, 0x0BCB, // C0-C7
    0x0BCC, 0x0BCD, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Tamil digits)
    0x0BE6, 0x0BE7, 0x0BE8, 0x0BE9, 0x0BEA, 0x0BEB, 0x0BEC, 0x0BED, // E0-E7
    0x0BEE, 0x0BEF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_mactamil(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MACTAMIL_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_mactamil(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MACTAMIL_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const CP1006_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Arabic letters)
    0x06F0, 0x06F1, 0x06F2, 0x06F3, 0x06F4, 0x06F5, 0x06F6, 0x06F7, // 80-87
    0x06F8, 0x06F9, 0x060C, 0x061B, 0x061F, 0x0622, 0x0627, 0x0628, // 88-8F
    // 0x90-0x9F (Arabic letters)
    0x067E, 0x0629, 0x062A, 0x062B, 0x062C, 0x0686, 0x062D, 0x062E, // 90-97
    0x062F, 0x0688, 0x0630, 0x0631, 0x0691, 0x0632, 0x0698, 0x0633, // 98-9F
    // 0xA0-0xAF (Arabic letters)
    0x0634, 0x0635, 0x0636, 0x0637, 0x0638, 0x0639, 0x063A, 0x0641, // A0-A7
    0x0642, 0x06A9, 0x06AF, 0x0644, 0x0645, 0x0646, 0x06BA, 0x0648, // A8-AF
    // 0xB0-0xBF (Arabic letters and signs)
    0x0647, 0x06C1, 0x06BE, 0x06CC, 0x06D2, 0x064F, 0x0650, 0x064E, // B0-B7
    0x0651, 0x0670, 0x064B, 0x064D, 0x064C, 0x0654, 0x0657, 0x0656, // B8-BF
    // 0xC0-0xCF (Control/undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C0-C7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF (Control/undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Control/undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E0-E7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    // 0xF0-0xFF (Control/undefined)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_cp1006(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1006_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_cp1006(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1006_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1008 (IBM Arabic) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Arabic presentation forms. Position 0xFF is undefined.
const CP1008_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0x00A0, 0x060C, 0x00A2, 0x061B, 0x061F, 0xFE7C, 0x00A6, 0xFE7D, // A0-A7
    0x0640, 0xF8FC, 0xFE80, 0xFE81, 0x00AC, 0x00AD, 0xFE82, 0xFE83, // A8-AF
    0x0660, 0x0661, 0x0662, 0x0663, 0x0664, 0x0665, 0x0666, 0x0667, // B0-B7
    0x0668, 0x0669, 0xFE84, 0xFE85, 0xFE8B, 0xFE8D, 0xFE8E, 0xFE8F, // B8-BF
    0xFE91, 0xFE93, 0xFE95, 0xFE97, 0xFE99, 0xFE9B, 0xFE9D, 0xFE9F, // C0-C7
    0xFEA1, 0xFEA3, 0xFEA5, 0xFEA7, 0xFEA9, 0xFEAB, 0xFEAD, 0xFEAF, // C8-CF
    0xF8F6, 0xFEB3, 0xF8F5, 0xFEB7, 0xF8F4, 0xFEBB, 0xF8F7, 0x00D7, // D0-D7
    0xFEBF, 0xFEC3, 0xFEC7, 0xFEC9, 0xFECA, 0xFECB, 0xFECC, 0xFECD, // D8-DF
    0xFECE, 0xFECF, 0xFED0, 0xFED1, 0xFED3, 0xFED5, 0xFED7, 0xFED9, // E0-E7
    0xFEDB, 0xFEDD, 0xFEF5, 0xFEF6, 0xFEF7, 0xFEF8, 0xFEFB, 0xFEFC, // E8-EF
    0xFEDF, 0xFEE1, 0xFEE3, 0xFEE5, 0xFEE7, 0xFEE9, 0xFEEB, 0x00F7, // F0-F7
    0xFEEC, 0xFEED, 0xFEEF, 0xFEF0, 0xFEF1, 0xFEF2, 0xFEF3, 0xFFFF, // F8-FF
];

fn decode_cp1008(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1008_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_cp1008(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1008_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1046 (IBM Arabic Extended) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Arabic letters and presentation forms. Position 0xFF is undefined.
const CP1046_TO_UNICODE: [u16; 128] = [
    0xFE88, 0x00D7, 0x00F7, 0xFEB1, 0xFEB5, 0xFEB9, 0xFEBD, 0xFE71, // 80-87
    0x0088, 0x25A0, 0x2502, 0x2500, 0x2510, 0x250C, 0x2514, 0x2518, // 88-8F
    0xFE79, 0xFE7B, 0xFE7D, 0xFE7F, 0xFE77, 0xFE8A, 0xFEF0, 0xFEF3, // 90-97
    0xFEF2, 0xFECE, 0xFECF, 0xFED0, 0xFEF6, 0xFEF8, 0xFEFA, 0xFEFC, // 98-9F
    0x00A0, 0xFE82, 0xFE84, 0xFE88, 0x00A4, 0xFE8E, 0xFE8B, 0xFE91, // A0-A7
    0xFE97, 0xFE9B, 0xFE9F, 0xFEA3, 0x060C, 0x00AD, 0xFEA7, 0xFEB3, // A8-AF
    0x0660, 0x0661, 0x0662, 0x0663, 0x0664, 0x0665, 0x0666, 0x0667, // B0-B7
    0x0668, 0x0669, 0xFEB7, 0x061B, 0xFEBB, 0xFEBF, 0xFECA, 0x061F, // B8-BF
    0xFECB, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627, // C0-C7
    0x0628, 0x0629, 0x062A, 0x062B, 0x062C, 0x062D, 0x062E, 0x062F, // C8-CF
    0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x0637, // D0-D7
    0x0638, 0x0639, 0x063A, 0xFECC, 0xFE82, 0xFE84, 0xFE8E, 0xFED3, // D8-DF
    0x0640, 0x0641, 0x0642, 0x0643, 0x0644, 0x0645, 0x0646, 0x0647, // E0-E7
    0x0648, 0x0649, 0x064A, 0x064B, 0x064C, 0x064D, 0x064E, 0x064F, // E8-EF
    0x0650, 0x0651, 0x0652, 0xFED7, 0xFEDB, 0xFEDF, 0x200B, 0xFEF5, // F0-F7
    0xFEF7, 0xFEF9, 0xFEFB, 0xFEE3, 0xFEE7, 0xFEEC, 0xFEE9, 0xFFFF, // F8-FF
];

fn decode_cp1046(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1046_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_cp1046(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1046_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1124 (IBM Ukrainian Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
const CP1124_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0x00A0, 0x0401, 0x0402, 0x0490, 0x0404, 0x0405, 0x0406, 0x0407, // A0-A7
    0x0408, 0x0409, 0x040A, 0x040B, 0x040C, 0x00AD, 0x040E, 0x040F, // A8-AF
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // B0-B7
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // B8-BF
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // C0-C7
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // C8-CF
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // D0-D7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // D8-DF
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // E0-E7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // E8-EF
    0x2116, 0x0451, 0x0452, 0x0491, 0x0454, 0x0455, 0x0456, 0x0457, // F0-F7
    0x0458, 0x0459, 0x045A, 0x045B, 0x045C, 0x00A7, 0x045E, 0x045F, // F8-FF
];

fn decode_cp1124(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1124_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp1124(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1124_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1129 (IBM Vietnamese) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Vietnamese-specific characters including Đ, Ơ, Ư and dong sign.
const CP1129_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x0153, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x0178, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x0152, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x0300, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x0110, 0x00D1, 0x0309, 0x00D3, 0x00D4, 0x01A0, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x01AF, 0x0303, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x0301, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x0111, 0x00F1, 0x0323, 0x00F3, 0x00F4, 0x01A1, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x01B0, 0x20AB, 0x00FF, // F8-FF
];

fn decode_cp1129(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1129_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp1129(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1129_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1133 (IBM Lao) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Lao script characters, consonants, vowels, tone marks, and digits.
const CP1133_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0xFFFF, 0x0E81, 0x0E82, 0x0E84, 0x0E87, 0x0E88, 0x0EAA, 0x0E8A, // A0-A7
    0x0E8D, 0x0E94, 0x0E95, 0x0E96, 0x0E97, 0x0E99, 0x0E9A, 0x0E9B, // A8-AF
    0x0E9C, 0x0E9D, 0x0E9E, 0x0E9F, 0x0EA1, 0x0EA2, 0x0EA3, 0x0EA5, // B0-B7
    0x0EA7, 0x0EAB, 0x0EAD, 0x0EAE, 0xFFFF, 0xFFFF, 0xFFFF, 0x0EAF, // B8-BF
    0x0EB0, 0x0EB2, 0x0EB3, 0x0EB4, 0x0EB5, 0x0EB6, 0x0EB7, 0x0EB8, // C0-C7
    0x0EB9, 0x0EBC, 0x0EB1, 0x0EBB, 0x0EBD, 0xFFFF, 0xFFFF, 0xFFFF, // C8-CF
    0x0EC0, 0x0EC1, 0x0EC2, 0x0EC3, 0x0EC4, 0x0EC8, 0x0EC9, 0x0ECA, // D0-D7
    0x0ECB, 0x0ECC, 0x0ECD, 0x0EC6, 0xFFFF, 0x0EDC, 0x0EDD, 0x006B, // D8-DF
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E0-E7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    0x0ED0, 0x0ED1, 0x0ED2, 0x0ED3, 0x0ED4, 0x0ED5, 0x0ED6, 0x0ED7, // F0-F7
    0x0ED8, 0x0ED9, 0xFFFF, 0xFFFF, 0x00A2, 0x00AC, 0x00A6, 0x00A0, // F8-FF
];

fn decode_cp1133(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1133_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp1133(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1133_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP774 (Lithuanian ISO) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Lithuanian/Baltic characters, box drawing, and Greek math symbols.
const CP774_TO_UNICODE: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, // 88-8F
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, // 90-97
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, // 98-9F
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, // A0-A7
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x0104, 0x010C, 0x0118, // B0-B7
    0x0116, 0x2563, 0x2551, 0x2557, 0x255D, 0x012E, 0x0160, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x0172, 0x016A, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x017D, // C8-CF
    0x0105, 0x010D, 0x0119, 0x0117, 0x012F, 0x0161, 0x0173, 0x016B, // D0-D7
    0x017E, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, // E0-E7
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229, // E8-EF
    0x2261, 0x00B1, 0x2265, 0x2264, 0x201E, 0x201C, 0x00F7, 0x2248, // F0-F7
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp774(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP774_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp774(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP774_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP773 (Baltic/Polish) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Baltic and Polish characters with extended box drawing.
const CP773_TO_UNICODE: [u16; 128] = [
    0x0106, 0x00FC, 0x00E9, 0x0101, 0x00E4, 0x0123, 0x00E5, 0x0107, // 80-87
    0x0142, 0x0113, 0x0156, 0x0157, 0x012B, 0x0179, 0x00C4, 0x00C5, // 88-8F
    0x00C9, 0x00E6, 0x00C6, 0x014D, 0x00F6, 0x0122, 0x00A2, 0x015A, // 90-97
    0x015B, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x00A4, // 98-9F
    0x0100, 0x012A, 0x00F3, 0x017B, 0x017C, 0x017A, 0x201D, 0x00A6, // A0-A7
    0x00A9, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x0141, 0x00AB, 0x00BB, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x0104, 0x0105, 0x010C, 0x010D, // D8-DF
    0x00D3, 0x00DF, 0x014C, 0x0143, 0x00F5, 0x00D5, 0x00B5, 0x0144, // E0-E7
    0x0136, 0x0137, 0x013B, 0x013C, 0x0146, 0x0112, 0x0145, 0x2019, // E8-EF
    0x0118, 0x0119, 0x0116, 0x0117, 0x012E, 0x012F, 0x0160, 0x0161, // F0-F7
    0x0172, 0x0173, 0x016A, 0x016B, 0x017D, 0x017E, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp773(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP773_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp773(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP773_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP772 (Lithuanian Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Cyrillic alphabet with Lithuanian characters and math symbols.
const CP772_TO_UNICODE: [u16; 128] = [
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // A0-A7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x0104, 0x010C, 0x0118, // B0-B7
    0x0116, 0x2563, 0x2551, 0x2557, 0x255D, 0x012E, 0x0160, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x0172, 0x016A, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x017D, // C8-CF
    0x0105, 0x010D, 0x0119, 0x0117, 0x012F, 0x0161, 0x0173, 0x016B, // D0-D7
    0x017E, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // E0-E7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // E8-EF
    0x0401, 0x0451, 0x2265, 0x2264, 0x201E, 0x201C, 0x00F7, 0x2248, // F0-F7
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp772(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP772_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp772(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP772_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP771 (KOI-8 Lithuanian/Cyrillic) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Cyrillic letters and Baltic letters with box drawing.
const CP771_TO_UNICODE: [u16; 128] = [
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // A0-A7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // A8-AF
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x0104, 0x0105, 0x010C, 0x010D, // D8-DF
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // E0-E7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // E8-EF
    0x0118, 0x0119, 0x0116, 0x0117, 0x012E, 0x012F, 0x0160, 0x0161, // F0-F7
    0x0172, 0x0173, 0x016A, 0x016B, 0x017D, 0x017E, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp771(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP771_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp771(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP771_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP770 (Baltic) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Lithuanian/Baltic characters with box drawing and Greek math symbols.
const CP770_TO_UNICODE: [u16; 128] = [
    0x010C, 0x00FC, 0x0117, 0x0101, 0x00E4, 0x0105, 0x013C, 0x010D, // 80-87
    0x0113, 0x0112, 0x0119, 0x0118, 0x012B, 0x012F, 0x00C4, 0x0104, // 88-8F
    0x0116, 0x017E, 0x017D, 0x00F5, 0x00F6, 0x00D5, 0x016B, 0x0173, // 90-97
    0x0123, 0x00D6, 0x00DC, 0x00A2, 0x013B, 0x201E, 0x0161, 0x0160, // 98-9F
    0x0100, 0x012A, 0x0137, 0x0136, 0x0146, 0x0145, 0x016A, 0x0172, // A0-A7
    0x0122, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x012E, 0x00AB, 0x00BB, // A8-AF
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

fn decode_cp770(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP770_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp770(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP770_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP868 (Urdu/Arabic) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Arabic-Indic digits, Arabic letters and presentation forms.
const CP868_TO_UNICODE: [u16; 128] = [
    0x0660, 0x0661, 0x0662, 0x0663, 0x0664, 0x0665, 0x0666, 0x0667, // 80-87
    0x0668, 0x0669, 0x060C, 0x061B, 0x061F, 0x0622, 0x0627, 0xFE8E, // 88-8F
    0xE016, 0x0628, 0xFE91, 0x067E, 0xFFFF, 0x0629, 0x062A, 0xFE97, // 90-97
    0xFFFF, 0xFFFF, 0x062B, 0xFE9B, 0x062C, 0xFE9F, 0xFFFF, 0xFFFF, // 98-9F
    0x062D, 0xFEA3, 0x062E, 0xFEA7, 0x062F, 0xFFFF, 0x0630, 0x0631, // A0-A7
    0xFFFF, 0x0632, 0xFFFF, 0x0633, 0xFEB3, 0x0634, 0x00AB, 0x00BB, // A8-AF
    0xFEB7, 0x0635, 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0xFEBB, // B0-B7
    0x0636, 0xFEBF, 0x0637, 0x2563, 0x2551, 0x2557, 0x255D, 0x0638, // B8-BF
    0x0639, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, // C0-C7
    0xFECA, 0xFECB, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, // C8-CF
    0x256C, 0xFECC, 0x063A, 0xFECE, 0xFECF, 0xFED0, 0x0641, 0xFED3, // D0-D7
    0x0642, 0xFED7, 0xFEDA, 0x2518, 0x250C, 0x2588, 0x2580, 0xFEDB, // D8-DF
    0xFFFF, 0x2584, 0xFFFF, 0x0644, 0xFEDE, 0xFEE0, 0x0645, 0xFEE3, // E0-E7
    0xFFFF, 0x0646, 0xFEE7, 0xFFFF, 0x0648, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    0xFFFF, 0x0621, 0x00AD, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F0-F7
    0xFFFF, 0xFFFF, 0xFFFF, 0x0651, 0xFE7D, 0xFFFF, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp868(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP868_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp868(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP868_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP813 (Greek ISO) to Unicode mapping for bytes 0x80-0xFF.
/// Similar to ISO-8859-7 with Greek alphabet and Euro sign.
const CP813_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0x00A0, 0x2018, 0x2019, 0x00A3, 0x20AC, 0x20AF, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x037A, 0x00AB, 0x00AC, 0x00AD, 0xFFFF, 0x2015, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x0384, 0x0385, 0x0386, 0x00B7, // B0-B7
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

fn decode_cp813(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP813_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp813(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP813_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP916 (Hebrew ISO) to Unicode mapping for bytes 0x80-0xFF.
/// Similar to ISO-8859-8 with Hebrew alphabet and directional marks.
const CP916_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
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

fn decode_cp916(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP916_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp916(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP916_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1161 (Thai) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Thai script characters with Euro sign at 0xDE.
const CP1161_TO_UNICODE: [u16; 128] = [
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 80-87
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 90-97
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 98-9F
    0x0E48, 0x0E01, 0x0E02, 0x0E03, 0x0E04, 0x0E05, 0x0E06, 0x0E07, // A0-A7
    0x0E08, 0x0E09, 0x0E0A, 0x0E0B, 0x0E0C, 0x0E0D, 0x0E0E, 0x0E0F, // A8-AF
    0x0E10, 0x0E11, 0x0E12, 0x0E13, 0x0E14, 0x0E15, 0x0E16, 0x0E17, // B0-B7
    0x0E18, 0x0E19, 0x0E1A, 0x0E1B, 0x0E1C, 0x0E1D, 0x0E1E, 0x0E1F, // B8-BF
    0x0E20, 0x0E21, 0x0E22, 0x0E23, 0x0E24, 0x0E25, 0x0E26, 0x0E27, // C0-C7
    0x0E28, 0x0E29, 0x0E2A, 0x0E2B, 0x0E2C, 0x0E2D, 0x0E2E, 0x0E2F, // C8-CF
    0x0E30, 0x0E31, 0x0E32, 0x0E33, 0x0E34, 0x0E35, 0x0E36, 0x0E37, // D0-D7
    0x0E38, 0x0E39, 0x0E3A, 0x0E49, 0x0E4A, 0x0E4B, 0x20AC, 0x0E3F, // D8-DF
    0x0E40, 0x0E41, 0x0E42, 0x0E43, 0x0E44, 0x0E45, 0x0E46, 0x0E47, // E0-E7
    0x0E48, 0x0E49, 0x0E4A, 0x0E4B, 0x0E4C, 0x0E4D, 0x0E4E, 0x0E4F, // E8-EF
    0x0E50, 0x0E51, 0x0E52, 0x0E53, 0x0E54, 0x0E55, 0x0E56, 0x0E57, // F0-F7
    0x0E58, 0x0E59, 0x0E5A, 0x0E5B, 0x00A2, 0x00AC, 0x00A6, 0x00A0, // F8-FF
];

fn decode_cp1161(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1161_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp1161(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1161_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1162 (Thai Windows) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Thai script with typographic punctuation in 0x80-0x9F range.
const CP1162_TO_UNICODE: [u16; 128] = [
    0x20AC, 0x0081, 0x0082, 0x0083, 0x0084, 0x2026, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
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

fn decode_cp1162(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1162_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp1162(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1162_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// CP1163 (Vietnamese) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Vietnamese characters with Euro sign and dong sign.
const CP1163_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x20AC, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x0153, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x0178, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x0152, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x0300, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    0x0110, 0x00D1, 0x0309, 0x00D3, 0x00D4, 0x01A0, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x01AF, 0x0303, 0x00DF, // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x0301, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    0x0111, 0x00F1, 0x0323, 0x00F3, 0x00F4, 0x01A1, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x01B0, 0x20AB, 0x00FF, // F8-FF
];

fn decode_cp1163(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1163_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_cp1163(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1163_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ISIRI-3342 (Persian) to Unicode mapping for bytes 0x80-0xFF.
/// Contains Persian/Arabic script with extended Arabic digits.
const ISIRI3342_TO_UNICODE: [u16; 128] = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, // 80-87
    0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, // 88-8F
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, // 90-97
    0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F, // 98-9F
    0x0020, 0x200C, 0x200D, 0x0021, 0x00A4, 0x066A, 0x002E, 0x066C, // A0-A7
    0x0029, 0x0028, 0x00D7, 0x002B, 0x060C, 0x002D, 0x066B, 0x002F, // A8-AF
    0x06F0, 0x06F1, 0x06F2, 0x06F3, 0x06F4, 0x06F5, 0x06F6, 0x06F7, // B0-B7
    0x06F8, 0x06F9, 0x003A, 0x061B, 0x003C, 0x003D, 0x003E, 0x061F, // B8-BF
    0x0622, 0x0627, 0x0621, 0x0628, 0x067E, 0x062A, 0x062B, 0x062C, // C0-C7
    0x0686, 0x062D, 0x062E, 0x062F, 0x0630, 0x0631, 0x0632, 0x0698, // C8-CF
    0x0633, 0x0634, 0x0635, 0x0636, 0x0637, 0x0638, 0x0639, 0x063A, // D0-D7
    0x0641, 0x0642, 0x06A9, 0x06AF, 0x0644, 0x0645, 0x0646, 0x0648, // D8-DF
    0x0647, 0x06CC, 0x005D, 0x005B, 0x007D, 0x007B, 0x00AB, 0x00BB, // E0-E7
    0x002A, 0x0640, 0x007C, 0x005C, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // E8-EF
    0x064E, 0x0650, 0x064F, 0x064B, 0x064D, 0x064C, 0x0651, 0x0652, // F0-F7
    0x0623, 0x0624, 0x0625, 0x0626, 0x0629, 0x0643, 0x064A, 0x007F, // F8-FF
];

fn decode_isiri3342(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = ISIRI3342_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_isiri3342(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ISIRI3342_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const MIK_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Cyrillic capital letters А-П)
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F
    // 0x90-0x9F (Cyrillic capital letters Р-Я)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F
    // 0xA0-0xAF (Cyrillic small letters а-п)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // A0-A7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // A8-AF
    // 0xB0-0xBF (Cyrillic small letters р-я)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // B0-B7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // B8-BF
    // 0xC0-0xCF (Box drawing)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x2563, 0x2551, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2510, // C8-CF
    // 0xD0-0xDF (Box drawing continued)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2557, 0x255D, 0x2518, // D0-D7
    0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, 0x03B1, 0x03B2, // D8-DF
    // 0xE0-0xEF (Greek letters and math symbols)
    0x0393, 0x03C0, 0x03A3, 0x03C3, 0x03C4, 0x03A6, 0x0398, 0x03A9, // E0-E7
    0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, // E8-EF
    // 0xF0-0xFF (Math symbols and special)
    0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, // F0-F7
    0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, 0x00AD, 0x2502, 0x00A4, // F8-FF
];

fn decode_mik(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = MIK_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_mik(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in MIK_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const KOI8T_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Tajik extensions + typographic)
    0x049B, 0x0493, 0x201A, 0x0492, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0xFFFF, 0x2030, 0x04B3, 0x2039, 0x04B2, 0x04B7, 0x04B6, 0xFFFF, // 88-8F
    // 0x90-0x9F (typographic + Tajik)
    0x049A, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0x2122, 0xFFFF, 0x203A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 98-9F
    // 0xA0-0xAF (Tajik + Latin symbols)
    0xFFFF, 0x04EF, 0x04EE, 0x0451, 0x00A4, 0x04E3, 0x00A6, 0x00A7, // A0-A7
    0xFFFF, 0xFFFF, 0xFFFF, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0xFFFF, // A8-AF
    // 0xB0-0xBF (Latin symbols + Tajik)
    0x00B0, 0x00B1, 0x00B2, 0x0401, 0xFFFF, 0x04E2, 0x00B6, 0x00B7, // B0-B7
    0xFFFF, 0x2116, 0xFFFF, 0x00BB, 0xFFFF, 0xFFFF, 0xFFFF, 0x00A9, // B8-BF
    // 0xC0-0xCF (Cyrillic small)
    0x044E, 0x0430, 0x0431, 0x0446, 0x0434, 0x0435, 0x0444, 0x0433, // C0-C7
    0x0445, 0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, // C8-CF
    // 0xD0-0xDF (Cyrillic small continued)
    0x043F, 0x044F, 0x0440, 0x0441, 0x0442, 0x0443, 0x0436, 0x0432, // D0-D7
    0x044C, 0x044B, 0x0437, 0x0448, 0x044D, 0x0449, 0x0447, 0x044A, // D8-DF
    // 0xE0-0xEF (Cyrillic capital)
    0x042E, 0x0410, 0x0411, 0x0426, 0x0414, 0x0415, 0x0424, 0x0413, // E0-E7
    0x0425, 0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, // E8-EF
    // 0xF0-0xFF (Cyrillic capital continued)
    0x041F, 0x042F, 0x0420, 0x0421, 0x0422, 0x0423, 0x0416, 0x0412, // F0-F7
    0x042C, 0x042B, 0x0417, 0x0428, 0x042D, 0x0429, 0x0427, 0x042A, // F8-FF
];

fn decode_koi8t(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = KOI8T_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_koi8t(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in KOI8T_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// ECMA-CYRILLIC (ISO-IR-111) to Unicode mapping for bytes 0x80-0xFF.
/// Different layout from ISO-8859-5, with Serbian/Macedonian letters.
const ECMA_CYRILLIC_TO_UNICODE: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    0x00A0, 0x0452, 0x0453, 0x0451, 0x0454, 0x0455, 0x0456, 0x0457, // A0-A7
    0x0458, 0x0459, 0x045A, 0x045B, 0x045C, 0x00AD, 0x045E, 0x045F, // A8-AF
    0x2116, 0x0402, 0x0403, 0x0401, 0x0404, 0x0405, 0x0406, 0x0407, // B0-B7
    0x0408, 0x0409, 0x040A, 0x040B, 0x040C, 0x00A4, 0x040E, 0x040F, // B8-BF
    0x044E, 0x0430, 0x0431, 0x0446, 0x0434, 0x0435, 0x0444, 0x0433, // C0-C7
    0x0445, 0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, // C8-CF
    0x043F, 0x044F, 0x0440, 0x0441, 0x0442, 0x0443, 0x0436, 0x0432, // D0-D7
    0x044C, 0x044B, 0x0437, 0x0448, 0x044D, 0x0449, 0x0447, 0x044A, // D8-DF
    0x042E, 0x0410, 0x0411, 0x0426, 0x0414, 0x0415, 0x0424, 0x0413, // E0-E7
    0x0425, 0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, // E8-EF
    0x041F, 0x042F, 0x0420, 0x0421, 0x0422, 0x0423, 0x0416, 0x0412, // F0-F7
    0x042C, 0x042B, 0x0417, 0x0428, 0x042D, 0x0429, 0x0427, 0x042A, // F8-FF
];

fn decode_ecma_cyrillic(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = ECMA_CYRILLIC_TO_UNICODE[(b - 0x80) as usize];
        map_single_byte(cp)
    }
}

fn encode_ecma_cyrillic(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in ECMA_CYRILLIC_TO_UNICODE.iter().enumerate() {
        if u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const CP866NAV_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Cyrillic capital А-П)
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F
    // 0x90-0x9F (Cyrillic capital Р-Я)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F
    // 0xA0-0xAF (Cyrillic small а-п)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // A0-A7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // A8-AF
    // 0xB0-0xBF (Box drawing light)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    // 0xC0-0xCF (Box drawing)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    // 0xD0-0xDF (Box drawing + blocks)
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    // 0xE0-0xEF (Cyrillic small р-я)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // E0-E7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // E8-EF
    // 0xF0-0xFF (Ukrainian/Belarusian + symbols)
    0x0401, 0x0451, 0x0490, 0x0491, 0x0404, 0x0454, 0x0406, 0x0456, // F0-F7
    0x0407, 0x0457, 0x040E, 0x045E, 0x2116, 0x00A4, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp866nav(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP866NAV_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp866nav(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP866NAV_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const DECMCS_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (C1 controls)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    // 0x90-0x9F (C1 controls continued)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    // 0xA0-0xAF (Latin symbols, some undefined)
    0xFFFF, 0x00A1, 0x00A2, 0x00A3, 0xFFFF, 0x00A5, 0xFFFF, 0x00A7, // A0-A7
    0x00A4, 0x00A9, 0x00AA, 0x00AB, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // A8-AF
    // 0xB0-0xBF (Latin symbols continued)
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0xFFFF, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0xFFFF, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0xFFFF, 0x00BF, // B8-BF
    // 0xC0-0xCF (Latin capital letters)
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    // 0xD0-0xDF (Latin capital + OE ligature + Y diaeresis)
    0xFFFF, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x0152, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x0178, 0xFFFF, 0x00DF, // D8-DF
    // 0xE0-0xEF (Latin small letters)
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    // 0xF0-0xFF (Latin small + oe ligature)
    0xFFFF, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x0153, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_decmcs(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = DECMCS_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_decmcs(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in DECMCS_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const HPROMAN9_TO_UNICODE: [u16; 96] = [
    // 0xA0-0xAF (Latin symbols + accents)
    0x00A0, 0x00C0, 0x00C2, 0x00C8, 0x00CA, 0x00CB, 0x00CE, 0x00CF, // A0-A7
    0x00B4, 0x02CB, 0x02C6, 0x00A8, 0x02DC, 0x00D9, 0x00DB, 0x20A4, // A8-AF
    // 0xB0-0xBF (Latin symbols continued)
    0x00AF, 0x00DD, 0x00FD, 0x00B0, 0x00C7, 0x00E7, 0x00D1, 0x00F1, // B0-B7
    0x00A1, 0x00BF, 0x20A0, 0x00A3, 0x00A5, 0x00A7, 0x0192, 0x00A2, // B8-BF
    // 0xC0-0xCF (Latin small vowels with accents)
    0x00E2, 0x00EA, 0x00F4, 0x00FB, 0x00E1, 0x00E9, 0x00F3, 0x00FA, // C0-C7
    0x00E0, 0x00E8, 0x00F2, 0x00F9, 0x00E4, 0x00EB, 0x00F6, 0x00FC, // C8-CF
    // 0xD0-0xDF (Nordic + more letters)
    0x00C5, 0x00EE, 0x00D8, 0x00C6, 0x00E5, 0x00ED, 0x00F8, 0x00E6, // D0-D7
    0x00C4, 0x00EC, 0x00D6, 0x00DC, 0x00C9, 0x00EF, 0x00DF, 0x00D4, // D8-DF
    // 0xE0-0xEF (More Latin + Š/š)
    0x00C1, 0x00C3, 0x00E3, 0x00D0, 0x00F0, 0x00CD, 0x00CC, 0x00D3, // E0-E7
    0x00D2, 0x00D5, 0x00F5, 0x0160, 0x0161, 0x00DA, 0x0178, 0x00FF, // E8-EF
    // 0xF0-0xFF (Symbols)
    0x00DE, 0x00FE, 0x00B7, 0x00B5, 0x00B6, 0x00BE, 0x2014, 0x00BC, // F0-F7
    0x00BD, 0x00AA, 0x00BA, 0x00AB, 0x25A0, 0x00BB, 0x00B1, 0xFFFF, // F8-FF
];

fn decode_hproman9(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0xA0 {
        Ok((char::from(b), 1))
    } else {
        let cp = HPROMAN9_TO_UNICODE[(b - 0xA0) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_hproman9(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0xA0 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in HPROMAN9_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0xA0;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const HPGREEK8_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (C1 controls)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    // 0x90-0x9F (C1 controls continued)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    // 0xA0-0xAF (NBSP + undefined)
    0x00A0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // A0-A7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // A8-AF
    // 0xB0-0xBF (undefined + ϊ, ϋ)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // B0-B7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x03CA, 0xFFFF, 0x03CB, 0xFFFF, // B8-BF
    // 0xC0-0xCF (Greek capitals Α-Ξ with gap)
    0xFFFF, 0x0391, 0x0392, 0x0393, 0x0394, 0x0395, 0x0396, 0x0397, // C0-C7
    0x0398, 0x0399, 0xFFFF, 0x039A, 0x039B, 0x039C, 0x039D, 0x039E, // C8-CF
    // 0xD0-0xDF (Greek capitals Ο-Ω + accented)
    0x039F, 0x03A0, 0x03A1, 0x03A3, 0x03A4, 0x03A5, 0x03A6, 0xFFFF, // D0-D7
    0x03A7, 0x03A8, 0x03A9, 0x03AC, 0x03AE, 0x03CC, 0xFFFF, 0xFFFF, // D8-DF
    // 0xE0-0xEF (Greek lowercase α-ξ with gaps)
    0x03CD, 0x03B1, 0x03B2, 0x03B3, 0x03B4, 0x03B5, 0x03B6, 0x03B7, // E0-E7
    0x03B8, 0x03B9, 0xFFFF, 0x03BA, 0x03BB, 0x03BC, 0x03BD, 0x03BE, // E8-EF
    // 0xF0-0xFF (Greek lowercase ο-ω + final sigma + accented)
    0x03BF, 0x03C0, 0x03C1, 0x03C3, 0x03C4, 0x03C5, 0x03C6, 0x03C2, // F0-F7
    0x03C7, 0x03C8, 0x03C9, 0x03AD, 0x03AF, 0x03CE, 0x03F3, 0xFFFF, // F8-FF
];

fn decode_hpgreek8(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = HPGREEK8_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_hpgreek8(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in HPGREEK8_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const HPTHAI8_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (C1 controls)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    // 0x90-0x9F (C1 controls continued)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    // 0xA0-0xAF (NBSP + Thai consonants ก-ฏ)
    0x00A0, 0x0E01, 0x0E02, 0x0E03, 0x0E04, 0x0E05, 0x0E06, 0x0E07, // A0-A7
    0x0E08, 0x0E09, 0x0E0A, 0x0E0B, 0x0E0C, 0x0E0D, 0x0E0E, 0x0E0F, // A8-AF
    // 0xB0-0xBF (Thai consonants ฐ-ฟ)
    0x0E10, 0x0E11, 0x0E12, 0x0E13, 0x0E14, 0x0E15, 0x0E16, 0x0E17, // B0-B7
    0x0E18, 0x0E19, 0x0E1A, 0x0E1B, 0x0E1C, 0x0E1D, 0x0E1E, 0x0E1F, // B8-BF
    // 0xC0-0xCF (Thai consonants ภ-ฮ + vowels)
    0x0E20, 0x0E21, 0x0E22, 0x0E23, 0x0E24, 0x0E25, 0x0E26, 0x0E27, // C0-C7
    0x0E28, 0x0E29, 0x0E2A, 0x0E2B, 0x0E2C, 0x0E2D, 0x0E2E, 0x0E2F, // C8-CF
    // 0xD0-0xDF (Thai vowels + diacritics)
    0x0E30, 0x0E31, 0x0E32, 0x0E33, 0x0E34, 0x0E35, 0x0E36, 0x0E37, // D0-D7
    0x0E38, 0x0E39, 0x0E3A, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0E3F, // D8-DF
    // 0xE0-0xEF (Thai vowels + tone marks + symbols)
    0x0E40, 0x0E41, 0x0E42, 0x0E43, 0x0E44, 0x0E45, 0x0E46, 0x0E47, // E0-E7
    0x0E48, 0x0E49, 0x0E4A, 0x0E4B, 0x0E4C, 0x0E4D, 0x0E4E, 0x0E4F, // E8-EF
    // 0xF0-0xFF (Thai digits + symbols)
    0x0E50, 0x0E51, 0x0E52, 0x0E53, 0x0E54, 0x0E55, 0x0E56, 0x0E57, // F0-F7
    0x0E58, 0x0E59, 0x0E5A, 0x0E5B, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // F8-FF
];

fn decode_hpthai8(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = HPTHAI8_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_hpthai8(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in HPTHAI8_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const HPTURKISH8_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (C1 controls)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    // 0x90-0x9F (C1 controls continued)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    // 0xA0-0xAF (Latin + Turkish Ğ, accents)
    0x00A0, 0x00C7, 0x011E, 0x00C8, 0x00CA, 0x00CB, 0x00CE, 0x00CF, // A0-A7
    0x00B4, 0x02CB, 0x02C6, 0x00A8, 0x02DC, 0x00D9, 0x00DB, 0x20A4, // A8-AF
    // 0xB0-0xBF (symbols + currency)
    0xFFFF, 0x00DD, 0x00FD, 0x00B0, 0xFFFF, 0xFFFF, 0x00D1, 0x00F1, // B0-B7
    0x00A1, 0x00BF, 0x00A4, 0x00A3, 0x00A5, 0x00A7, 0x0192, 0x00A2, // B8-BF
    // 0xC0-0xCF (accented vowels)
    0xFFFF, 0x00EA, 0x00F4, 0xFFFF, 0x00E1, 0x00E9, 0x00F3, 0x00FA, // C0-C7
    0x00E0, 0x00E8, 0x00F2, 0x00F9, 0x00E4, 0x00EB, 0xFFFF, 0xFFFF, // C8-CF
    // 0xD0-0xDF (Nordic + Turkish İ, Ş)
    0x00C5, 0x00EE, 0x00D8, 0x00C6, 0x00E5, 0x00ED, 0x00F8, 0x00E6, // D0-D7
    0x00C4, 0x00EC, 0xFFFF, 0x0130, 0x00D6, 0x015E, 0x00DC, 0x00E7, // D8-DF
    // 0xE0-0xEF (Turkish ğ + Latin)
    0x011F, 0x00C3, 0x00E3, 0x00D0, 0x00F0, 0x00CD, 0x00CC, 0x00D3, // E0-E7
    0x00D2, 0x00D5, 0x00F5, 0x0160, 0x0161, 0x00DA, 0x0178, 0x00FF, // E8-EF
    // 0xF0-0xFF (Symbols + Turkish ı, ö, ş, ü)
    0x00DE, 0x00FE, 0x00B7, 0x00B5, 0x00B6, 0x00BE, 0x2014, 0x00BC, // F0-F7
    0x00BD, 0x00AA, 0x00BA, 0x0131, 0x00F6, 0x015F, 0x00FC, 0xFFFF, // F8-FF
];

fn decode_hpturkish8(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = HPTURKISH8_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_hpturkish8(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in HPTURKISH8_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const CP1004_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (undefined + typographic)
    0xFFFF, 0xFFFF, 0x201A, 0xFFFF, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFF, 0xFFFF, 0xFFFF, // 88-8F
    // 0x90-0x9F (undefined + typographic)
    0xFFFF, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFF, 0xFFFF, 0x0178, // 98-9F
    // 0xA0-0xAF (Latin-1 supplement)
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    // 0xB0-0xBF (Latin-1 supplement continued)
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    // 0xC0-0xCF (Latin-1 supplement continued)
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    // 0xD0-0xDF (Latin-1 supplement continued)
    0x00D0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF, // D8-DF
    // 0xE0-0xEF (Latin-1 supplement continued)
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    // 0xF0-0xFF (Latin-1 supplement continued)
    0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF, // F8-FF
];

fn decode_cp1004(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1004_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp1004(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1004_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const IBM1167_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (box drawing + block elements)
    0x2500, 0x2502, 0x250C, 0x2510, 0x2514, 0x2518, 0x251C, 0x2524, // 80-87
    0x252C, 0x2534, 0x253C, 0x2580, 0x2584, 0x2588, 0x258C, 0x2590, // 88-8F
    // 0x90-0x9F (shades + typographic + symbols)
    0x2591, 0x2592, 0x2593, 0x201C, 0x25A0, 0x2219, 0x201D, 0x2014, // 90-97
    0x2116, 0x2122, 0x00A0, 0x00BB, 0x00AE, 0x00AB, 0x00B7, 0x00A4, // 98-9F
    // 0xA0-0xAF (box drawing + Ukrainian Cyrillic lowercase)
    0x2550, 0x2551, 0x2552, 0x0451, 0x0454, 0x2554, 0x0456, 0x0457, // A0-A7
    0x2557, 0x2558, 0x2559, 0x255A, 0x255B, 0x0491, 0x045E, 0x255E, // A8-AF
    // 0xB0-0xBF (box drawing + Ukrainian Cyrillic uppercase)
    0x255F, 0x2560, 0x2561, 0x0401, 0x0404, 0x2563, 0x0406, 0x0407, // B0-B7
    0x2566, 0x2567, 0x2568, 0x2569, 0x256A, 0x0490, 0x040E, 0x00A9, // B8-BF
    // 0xC0-0xCF (Cyrillic lowercase)
    0x044E, 0x0430, 0x0431, 0x0446, 0x0434, 0x0435, 0x0444, 0x0433, // C0-C7
    0x0445, 0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, // C8-CF
    // 0xD0-0xDF (Cyrillic lowercase continued)
    0x043F, 0x044F, 0x0440, 0x0441, 0x0442, 0x0443, 0x0436, 0x0432, // D0-D7
    0x044C, 0x044B, 0x0437, 0x0448, 0x044D, 0x0449, 0x0447, 0x044A, // D8-DF
    // 0xE0-0xEF (Cyrillic uppercase)
    0x042E, 0x0410, 0x0411, 0x0426, 0x0414, 0x0415, 0x0424, 0x0413, // E0-E7
    0x0425, 0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, // E8-EF
    // 0xF0-0xFF (Cyrillic uppercase continued)
    0x041F, 0x042F, 0x0420, 0x0421, 0x0422, 0x0423, 0x0416, 0x0412, // F0-F7
    0x042C, 0x042B, 0x0417, 0x0428, 0x042D, 0x0429, 0x0427, 0x042A, // F8-FF
];

fn decode_ibm1167(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = IBM1167_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_ibm1167(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in IBM1167_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const CWI_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Latin accented + Hungarian)
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, // 80-87
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00CD, 0x00C4, 0x00C1, // 88-8F
    // 0x90-0x9F (Latin + Hungarian ő, ű, Ő, Ű)
    0x00C9, 0x00E6, 0x00C6, 0x0151, 0x00F6, 0x00D3, 0x0171, 0x00DA, // 90-97
    0x0170, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0xE01F, // 98-9F
    // 0xA0-0xAF (Latin + symbols)
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x0150, // A0-A7
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, // A8-AF
    // 0xB0-0xBF (box drawing shades + characters)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    // 0xC0-0xCF (box drawing)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    // 0xD0-0xDF (box drawing + blocks)
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    // 0xE0-0xEF (Greek + math symbols)
    0x03B1, 0x03B2, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x03BC, 0x03C4, // E0-E7
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x2205, 0x03B5, 0x2229, // E8-EF
    // 0xF0-0xFF (math symbols + NBSP)
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, // F0-F7
    0x2218, 0x00B7, 0x2022, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cwi(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CWI_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cwi(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CWI_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const STRK10482002_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Cyrillic + typographic)
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x049A, 0x04BA, 0x040F, // 88-8F
    // 0x90-0x9F (Cyrillic + typographic)
    0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0xFFFF, 0x2122, 0x0459, 0x203A, 0x045A, 0x049B, 0x04BB, 0x045F, // 98-9F
    // 0xA0-0xAF (Kazakh + symbols)
    0x00A0, 0x04B0, 0x04B1, 0x04D8, 0x00A4, 0x04E8, 0x00A6, 0x00A7, // A0-A7
    0x0401, 0x00A9, 0x0492, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x04AE, // A8-AF
    // 0xB0-0xBF (symbols + Kazakh)
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x04E9, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x0451, 0x2116, 0x0493, 0x00BB, 0x04D9, 0x04A2, 0x04A3, 0x04AF, // B8-BF
    // 0xC0-0xCF (Cyrillic uppercase А-П)
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // C0-C7
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // C8-CF
    // 0xD0-0xDF (Cyrillic uppercase Р-Я)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // D0-D7
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // D8-DF
    // 0xE0-0xEF (Cyrillic lowercase а-п)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // E0-E7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // E8-EF
    // 0xF0-0xFF (Cyrillic lowercase р-я)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // F0-F7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // F8-FF
];

fn decode_strk10482002(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = STRK10482002_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_strk10482002(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in STRK10482002_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const CSN369103_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (C1 controls)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    // 0x90-0x9F (C1 controls continued)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    // 0xA0-0xAF (Latin extended)
    0x00A0, 0x0104, 0x02D8, 0x0141, 0x0024, 0x013D, 0x015A, 0x00A7, // A0-A7
    0x00A8, 0x0160, 0x015E, 0x0164, 0x0179, 0x00AD, 0x017D, 0x017B, // A8-AF
    // 0xB0-0xBF (Latin extended continued)
    0x00B0, 0x0105, 0x02DB, 0x0142, 0x00B4, 0x013E, 0x015B, 0x02C7, // B0-B7
    0x00B8, 0x0161, 0x015F, 0x0165, 0x017A, 0x02DD, 0x017E, 0x017C, // B8-BF
    // 0xC0-0xCF (Latin capital with diacritics)
    0x0154, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0139, 0x0106, 0x00C7, // C0-C7
    0x010C, 0x00C9, 0x0118, 0x00CB, 0x011A, 0x00CD, 0x00CE, 0x010E, // C8-CF
    // 0xD0-0xDF (Latin capital continued)
    0x0110, 0x0143, 0x0147, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x00D7, // D0-D7
    0x0158, 0x016E, 0x00DA, 0x0170, 0x00DC, 0x00DD, 0x0162, 0x00DF, // D8-DF
    // 0xE0-0xEF (Latin small with diacritics)
    0x0155, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x013A, 0x0107, 0x00E7, // E0-E7
    0x010D, 0x00E9, 0x0119, 0x00EB, 0x011B, 0x00ED, 0x00EE, 0x010F, // E8-EF
    // 0xF0-0xFF (Latin small continued)
    0x0111, 0x0144, 0x0148, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x00F7, // F0-F7
    0x0159, 0x016F, 0x00FA, 0x0171, 0x00FC, 0x00FD, 0x0163, 0x02D9, // F8-FF
];

fn decode_csn369103(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CSN369103_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_csn369103(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CSN369103_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const IBM902_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (C1 controls)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    // 0x90-0x9F (C1 controls continued)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    // 0xA0-0xAF (Latin-1 with Euro at 0xA4)
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x20AC, 0x00A5, 0x00A6, 0x00A7, // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, // A8-AF
    // 0xB0-0xBF (Latin-1)
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, // B8-BF
    // 0xC0-0xCF (Latin-1)
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7, // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, // C8-CF
    // 0xD0-0xDF (Š at D0, Ž at DE)
    0x0160, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x017D, 0x00DF, // D8-DF
    // 0xE0-0xEF (Latin-1)
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, // E8-EF
    // 0xF0-0xFF (š at F0, ž at FE)
    0x0161, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x017E, 0x00FF, // F8-FF
];

fn decode_ibm902(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = IBM902_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_ibm902(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in IBM902_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const IBM901_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (C1 controls)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, // 80-87
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F, // 88-8F
    // 0x90-0x9F (C1 controls continued)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097, // 90-97
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, // 98-9F
    // 0xA0-0xAF (Quotes, currency, Nordic)
    0x00A0, 0x201D, 0x00A2, 0x00A3, 0x20AC, 0x201E, 0x00A6, 0x00A7, // A0-A7
    0x00D8, 0x00A9, 0x0156, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00C6, // A8-AF
    // 0xB0-0xBF (Symbols + Nordic)
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x201C, 0x00B5, 0x00B6, 0x00B7, // B0-B7
    0x00F8, 0x00B9, 0x0157, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00E6, // B8-BF
    // 0xC0-0xCF (Baltic capital letters)
    0x0104, 0x012E, 0x0100, 0x0106, 0x00C4, 0x00C5, 0x0118, 0x0112, // C0-C7
    0x010C, 0x00C9, 0x0179, 0x0116, 0x0122, 0x0136, 0x012A, 0x013B, // C8-CF
    // 0xD0-0xDF (Baltic capital continued)
    0x0160, 0x0143, 0x0145, 0x00D3, 0x014C, 0x00D5, 0x00D6, 0x00D7, // D0-D7
    0x0172, 0x0141, 0x015A, 0x016A, 0x00DC, 0x017B, 0x017D, 0x00DF, // D8-DF
    // 0xE0-0xEF (Baltic small letters)
    0x0105, 0x012F, 0x0101, 0x0107, 0x00E4, 0x00E5, 0x0119, 0x0113, // E0-E7
    0x010D, 0x00E9, 0x017A, 0x0117, 0x0123, 0x0137, 0x012B, 0x013C, // E8-EF
    // 0xF0-0xFF (Baltic small continued)
    0x0161, 0x0144, 0x0146, 0x00F3, 0x014D, 0x00F5, 0x00F6, 0x00F7, // F0-F7
    0x0173, 0x0142, 0x015B, 0x016B, 0x00FC, 0x017C, 0x017E, 0x2019, // F8-FF
];

fn decode_ibm901(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = IBM901_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_ibm901(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = u32::from(ch);
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in IBM901_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const CP856_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Hebrew letters)
    0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, 0x05D6, 0x05D7, // 80-87
    0x05D8, 0x05D9, 0x05DA, 0x05DB, 0x05DC, 0x05DD, 0x05DE, 0x05DF, // 88-8F
    // 0x90-0x9F (Hebrew letters continued)
    0x05E0, 0x05E1, 0x05E2, 0x05E3, 0x05E4, 0x05E5, 0x05E6, 0x05E7, // 90-97
    0x05E8, 0x05E9, 0x05EA, 0xFFFF, 0x00A3, 0xFFFF, 0x00D7, 0xFFFF, // 98-9F
    // 0xA0-0xAF (Undefined / control)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // A0-A7
    0xFFFF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0xFFFF, 0x00AB, 0x00BB, // A8-AF
    // 0xB0-0xBF (Box drawing)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0xFFFF, 0xFFFF, 0xFFFF, // B0-B7
    0x00A9, 0x2563, 0x2551, 0x2557, 0x255D, 0x00A2, 0x00A5, 0x2510, // B8-BF
    // 0xC0-0xCF (Box drawing continued)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0xFFFF, 0xFFFF, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, // C8-CF
    // 0xD0-0xDF (Undefined / box drawing)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // D0-D7
    0xFFFF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0xFFFF, 0x2580, // D8-DF
    // 0xE0-0xEF (Greek letters / symbols)
    0xFFFF, 0x00DF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x00B5, 0xFFFF, // E0-E7
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x203E, 0x00B4, // E8-EF
    // 0xF0-0xFF (Symbols)
    0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8, // F0-F7
    0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp856(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP856_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            return Err(DecodeError::Invalid);
        }
        map_single_byte(cp)
    }
}

fn encode_cp856(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP856_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

const CP1125_TO_UNICODE: [u16; 128] = [
    // 0x80-0x8F (Cyrillic uppercase A-P)
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // 80-87
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // 88-8F
    // 0x90-0x9F (Cyrillic uppercase R-Ya + Ukrainian chars)
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // 90-97
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // 98-9F
    // 0xA0-0xAF (Cyrillic lowercase a-p)
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // A0-A7
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // A8-AF
    // 0xB0-0xBF (Box drawing)
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, // B0-B7
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, // B8-BF
    // 0xC0-0xCF (Box drawing continued)
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, // C0-C7
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, // C8-CF
    // 0xD0-0xDF (Box drawing / Cyrillic lowercase continued)
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, // D0-D7
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, // D8-DF
    // 0xE0-0xEF (Cyrillic lowercase r-ya)
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // E0-E7
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // E8-EF
    // 0xF0-0xFF (Ukrainian specific chars)
    0x0401, 0x0451, 0x0490, 0x0491, 0x0404, 0x0454, 0x0406, 0x0456, // F0-F7
    0x0407, 0x0457, 0x00B7, 0x221A, 0x2116, 0x00A4, 0x25A0, 0x00A0, // F8-FF
];

fn decode_cp1125(input: &[u8]) -> Result<(char, usize), DecodeError> {
    if input.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let b = input[0];
    if b < 0x80 {
        Ok((char::from(b), 1))
    } else {
        let cp = CP1125_TO_UNICODE[(b - 0x80) as usize];
        if cp == 0xFFFF {
            Ok(('\u{FFFD}', 1))
        } else {
            map_single_byte(cp)
        }
    }
}

fn encode_cp1125(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.is_empty() {
        return Err(EncodeError::NoSpace);
    }
    let cp = ch as u32;
    if cp < 0x80 {
        out[0] = cp as u8;
        return Ok(1);
    }
    for (idx, &unicode) in CP1125_TO_UNICODE.iter().enumerate() {
        if unicode != 0xFFFF && u32::from(unicode) == cp {
            out[0] = (idx as u8) + 0x80;
            return Ok(1);
        }
    }
    Err(EncodeError::Unrepresentable)
}

/// EUC-JP decoder: variable length via glibc-exact tables (see [`cjk_tables`]).
/// `EUC_JP_ONE_BYTE[b0] >= 0` is a single-byte char; otherwise `EUC_JP_LEAD_LEN`
/// gives the sequence length (2 for 0x8E half-width kana + 0xA1-0xFE JIS X 0208,
/// 3 for the 0x8F JIS X 0212 plane), keyed into `EUC_JP_DBCS2` (`(b0<<8)|b1`) or
/// `EUC_JP_DBCS3` (`(b1<<8)|b2`, since the only 3-byte lead is 0x8F). Short input
/// under a known lead is `Incomplete` (EINVAL); an unknown lead or pair is
/// `Invalid` (EILSEQ) — matching glibc's gconv.
/// EUC-JP decoder matching glibc's gconv exactly, incl. its incomplete-vs-invalid
/// (EINVAL/EILSEQ) classification on malformed/truncated input — driven by the
/// glibc-probed `EUC_JP_SS3_ROW_VALID` / `EUC_JP_LEAD2_DEFER` masks:
///   * `0x00-0x7F` -> 1-byte (via `EUC_JP_ONE_BYTE`);
///   * `0x8F` (SS3) -> 3-byte JIS X 0212: the row byte is validated first against
///     `EUC_JP_SS3_ROW_VALID` (out-of-range row => EILSEQ even if truncated),
///     then the cell byte is required (EINVAL if absent) and the pair looked up
///     in `EUC_JP_DBCS3`;
///   * other high bytes: `EUC_JP_LEAD2_DEFER[b0]` distinguishes a byte whose lead
///     validation glibc defers (a lone such byte is EINVAL, e.g. 0xA0) from one
///     that is always illegal (immediate EILSEQ, e.g. 0xFF); a present pair is
///     looked up in `EUC_JP_DBCS2` (miss => EILSEQ).
fn decode_eucjp(input: &[u8]) -> Result<(char, usize), DecodeError> {
    let Some(&b0) = input.first() else {
        return Err(DecodeError::Incomplete);
    };
    let ob = cjk_tables::EUC_JP_ONE_BYTE[b0 as usize];
    if ob >= 0 {
        return char::from_u32(ob as u32)
            .map(|c| (c, 1))
            .ok_or(DecodeError::Invalid);
    }
    if b0 == 0x8F {
        let Some(&b1) = input.get(1) else {
            return Err(DecodeError::Incomplete);
        };
        if !cjk_tables::EUC_JP_SS3_ROW_VALID[b1 as usize] {
            return Err(DecodeError::Invalid);
        }
        let Some(&b2) = input.get(2) else {
            return Err(DecodeError::Incomplete);
        };
        let key = (u16::from(b1) << 8) | u16::from(b2);
        return match cjk_tables::EUC_JP_DBCS3.binary_search_by_key(&key, |&(k, _)| k) {
            Ok(i) => char::from_u32(cjk_tables::EUC_JP_DBCS3[i].1)
                .map(|c| (c, 3))
                .ok_or(DecodeError::Invalid),
            Err(_) => Err(DecodeError::Invalid),
        };
    }
    if !cjk_tables::EUC_JP_LEAD2_DEFER[b0 as usize] {
        return Err(DecodeError::Invalid);
    }
    let Some(&b1) = input.get(1) else {
        return Err(DecodeError::Incomplete);
    };
    let key = (u16::from(b0) << 8) | u16::from(b1);
    match cjk_tables::EUC_JP_DBCS2.binary_search_by_key(&key, |&(k, _)| k) {
        Ok(i) => char::from_u32(cjk_tables::EUC_JP_DBCS2[i].1)
            .map(|c| (c, 2))
            .ok_or(DecodeError::Invalid),
        Err(_) => Err(DecodeError::Invalid),
    }
}

/// EUC-JP encoder, fully table-driven over the BMP (`EUC_JP_ENC`): a packed
/// value `< 0x100` is 1 byte, `< 0x10000` is 2 bytes `(b0<<8)|b1`, otherwise
/// 3 bytes `(b0<<16)|(b1<<8)|b2` (the 0x8F plane). Absent code points are
/// `Unrepresentable` (EILSEQ).
fn encode_eucjp(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    let cp = ch as u32;
    match cjk_tables::EUC_JP_ENC.binary_search_by_key(&cp, |&(c, _)| c) {
        Ok(i) => {
            let packed = cjk_tables::EUC_JP_ENC[i].1;
            if packed < 0x100 {
                if out.is_empty() {
                    return Err(EncodeError::NoSpace);
                }
                out[0] = packed as u8;
                Ok(1)
            } else if packed < 0x1_0000 {
                if out.len() < 2 {
                    return Err(EncodeError::NoSpace);
                }
                out[0] = (packed >> 8) as u8;
                out[1] = (packed & 0xFF) as u8;
                Ok(2)
            } else {
                if out.len() < 3 {
                    return Err(EncodeError::NoSpace);
                }
                out[0] = (packed >> 16) as u8;
                out[1] = ((packed >> 8) & 0xFF) as u8;
                out[2] = (packed & 0xFF) as u8;
                Ok(3)
            }
        }
        Err(_) => Err(EncodeError::Unrepresentable),
    }
}

/// Generic 2-byte-DBCS decoder (Shift-JIS, BIG5) driven by glibc-exact tables
/// (see [`cjk_tables`]). `one_byte[b0] >= 0` is a single-byte char (ASCII / kana);
/// `is_lead[b0]` marks a double-byte lead whose `(b0<<8)|b1` key is looked up in
/// the sorted `dbcs` table. A lead with no following byte is `Incomplete`
/// (EINVAL); an unknown lead or unknown pair is `Invalid` (EILSEQ) — matching
/// glibc's gconv exactly by construction.
fn decode_dbcs2(
    input: &[u8],
    one_byte: &[i32; 256],
    is_lead: &[bool; 256],
    dbcs: &[(u16, u32)],
) -> Result<(char, usize), DecodeError> {
    let Some(&b0) = input.first() else {
        return Err(DecodeError::Incomplete);
    };
    let ob = one_byte[b0 as usize];
    if ob >= 0 {
        return char::from_u32(ob as u32)
            .map(|c| (c, 1))
            .ok_or(DecodeError::Invalid);
    }
    if !is_lead[b0 as usize] {
        return Err(DecodeError::Invalid);
    }
    let Some(&b1) = input.get(1) else {
        return Err(DecodeError::Incomplete);
    };
    let key = (u16::from(b0) << 8) | u16::from(b1);
    match dbcs.binary_search_by_key(&key, |&(k, _)| k) {
        Ok(i) => char::from_u32(dbcs[i].1)
            .map(|c| (c, 2))
            .ok_or(DecodeError::Invalid),
        Err(_) => Err(DecodeError::Invalid),
    }
}

/// Generic 2-byte-DBCS encoder, fully table-driven (no ASCII shortcut — these
/// codecs are asymmetric in the ASCII range, e.g. SHIFT_JIS maps 0x5C to U+00A5
/// yen, so U+005C is encoded per glibc's table, not as a bare 0x5C). The sorted
/// `enc` table holds glibc's canonical encoding for every representable BMP code
/// point: a packed value `< 0x100` is a single output byte, a larger value is
/// `(b0<<8)|b1`. An absent code point is `Unrepresentable` (EILSEQ).
fn encode_dbcs2(ch: char, out: &mut [u8], enc: &[(u32, u32)]) -> Result<usize, EncodeError> {
    let cp = ch as u32;
    match enc.binary_search_by_key(&cp, |&(c, _)| c) {
        Ok(i) => {
            let packed = enc[i].1;
            if packed < 0x100 {
                if out.is_empty() {
                    return Err(EncodeError::NoSpace);
                }
                out[0] = packed as u8;
                Ok(1)
            } else {
                if out.len() < 2 {
                    return Err(EncodeError::NoSpace);
                }
                out[0] = (packed >> 8) as u8;
                out[1] = (packed & 0xFF) as u8;
                Ok(2)
            }
        }
        Err(_) => Err(EncodeError::Unrepresentable),
    }
}

fn decode_shiftjis(input: &[u8]) -> Result<(char, usize), DecodeError> {
    decode_dbcs2(
        input,
        &cjk_tables::SHIFT_JIS_ONE_BYTE,
        &cjk_tables::SHIFT_JIS_IS_LEAD,
        &cjk_tables::SHIFT_JIS_DBCS,
    )
}

fn encode_shiftjis(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    encode_dbcs2(ch, out, &cjk_tables::SHIFT_JIS_ENC)
}

fn decode_big5(input: &[u8]) -> Result<(char, usize), DecodeError> {
    decode_dbcs2(
        input,
        &cjk_tables::BIG5_ONE_BYTE,
        &cjk_tables::BIG5_IS_LEAD,
        &cjk_tables::BIG5_DBCS,
    )
}

fn encode_big5(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    encode_dbcs2(ch, out, &cjk_tables::BIG5_ENC)
}

/// Probe whether the conversion `from -> to` is an ASCII byte-identity over
/// `0x00..=0x7F`: every such byte must decode (under `from`) to the codepoint of
/// the same value as a single byte AND re-encode (under `to`) back to that same
/// single byte. When true, the iconv loop can bulk-copy ASCII runs verbatim.
///
/// This is computed once per descriptor (in `iconv_open_detailed`) by actually
/// exercising `decode_char`/`encode_char`, so it is correct for ANY codec —
/// UTF-8/ASCII/Latin-1 and the many single-byte codepages (KOI8, CP125x, ...)
/// whose low half is ASCII — without a hand-maintained allow-list, and it
/// automatically excludes multibyte codecs (UTF-16/32) where a single byte is
/// incomplete. Parity-safe by construction: the fast path is enabled only when
/// the identity is proven.
fn pair_is_ascii_identity(from: Encoding, to: Encoding) -> bool {
    let mut buf = [0u8; 8];
    for b in 0u8..0x80 {
        match decode_char(from, &[b]) {
            Ok((ch, 1)) if ch == char::from(b) => {}
            _ => return false,
        }
        match encode_char(to, char::from(b), &mut buf) {
            Ok(1) if buf[0] == b => {}
            _ => return false,
        }
    }
    true
}

/// Build a direct `input_byte -> output_byte` translation table for a
/// single-byte -> single-byte conversion, computed once at open by exercising
/// `decode_char`/`encode_char` over all 256 bytes. `-1` marks a byte that is
/// invalid under `from` or unrepresentable under `to` (both yield EILSEQ).
///
/// Returns `None` (no table) when either endpoint is multibyte — detected
/// structurally: `from` is multibyte if any single byte decodes Incomplete or
/// consumes != 1; `to` is multibyte if encoding a decoded char ever needs > 1
/// byte. Because it is built from the exact decode/encode arms, the table is
/// byte-for-byte equivalent to the scalar decode->encode round trip.
fn build_sb_translation(from: Encoding, to: Encoding) -> Option<[i16; 256]> {
    let mut lut = [-1i16; 256];
    let mut buf = [0u8; 8];
    for b in 0u8..=0xFF {
        match decode_char(from, &[b]) {
            Ok((ch, 1)) => match encode_char(to, ch, &mut buf) {
                Ok(1) => lut[b as usize] = i16::from(buf[0]),
                // `to` produced a multibyte sequence -> not byte-translatable.
                Ok(_) => return None,
                // Unrepresentable under `to`: leave -1 (EILSEQ), same as scalar.
                Err(EncodeError::Unrepresentable) => {}
                Err(EncodeError::NoSpace) => return None, // buf is 8 bytes; unreachable
            },
            // `from` consumed more than one byte -> multibyte source.
            Ok((_, _)) => return None,
            // Byte is invalid under `from`: leave -1 (EILSEQ), same as scalar.
            Err(DecodeError::Invalid) => {}
            // `from` needs more bytes for this lead -> multibyte source.
            Err(DecodeError::Incomplete) => return None,
        }
    }
    Some(lut)
}

/// Length of the leading run of ASCII bytes (`< 0x80`) in `s`, found with a
/// 32-lane SIMD scan. Used by the iconv fast path to bulk-copy ASCII runs
/// between ASCII-transparent encodings instead of dispatching decode_char /
/// encode_char per byte.
fn leading_ascii_len(s: &[u8]) -> usize {
    const LANES: usize = 32;
    let hi = Simd::<u8, LANES>::splat(0x80);
    let mut i = 0;
    while i + LANES <= s.len() {
        let chunk = Simd::<u8, LANES>::from_slice(&s[i..i + LANES]);
        if chunk.simd_ge(hi).any() {
            for k in 0..LANES {
                if s[i + k] >= 0x80 {
                    return i + k;
                }
            }
        }
        i += LANES;
    }
    while i < s.len() {
        if s[i] >= 0x80 {
            return i;
        }
        i += 1;
    }
    s.len()
}

/// Build a codepoint -> byte reverse map for a single-byte target codec, so the
/// conversion loop can encode common BMP codepoints through an O(1) direct page
/// table, with O(log n) binary-search fallback instead of the O(128) linear
/// search in `encode_*`. Returns `None` if `to` is multibyte (some byte decodes
/// Incomplete or consumes != 1).
///
/// Each high byte `b` (0x80..=0xFF) is included only when it round-trips —
/// `decode(b) = cp` (cp >= 0x80) and `encode(cp) = b` — so the map reproduces
/// `encode_*`'s canonical first-match exactly and silently drops undefined /
/// non-canonical bytes (which `lookup` then reports as unrepresentable).
fn build_to_reverse(to: Encoding) -> Option<SingleByteReverse> {
    let mut entries: Vec<(u32, u8)> = Vec::with_capacity(128);
    let mut buf = [0u8; 8];
    for b in 0u8..=0xFF {
        let ch = match decode_char(to, &[b]) {
            Ok((ch, 1)) => ch,
            // `to` is multibyte (lead byte needs continuation / wide unit).
            Ok((_, _)) | Err(DecodeError::Incomplete) => return None,
            Err(DecodeError::Invalid) => continue,
        };
        let cp = ch as u32;
        if cp < 0x80 {
            continue; // handled by the ASCII shortcut in `lookup`
        }
        // Keep only the canonical byte `encode_*` would emit for this cp.
        if matches!(encode_char(to, ch, &mut buf), Ok(1) if buf[0] == b) {
            entries.push((cp, b));
        }
    }
    entries.sort_unstable_by_key(|&(cp, _)| cp);
    entries.dedup_by_key(|&mut (cp, _)| cp);
    if entries.len() > 128 {
        return None; // single-byte codec cannot exceed 128 high entries
    }
    let mut high_cp = [0u32; 128];
    let mut high_byte = [0u8; 128];
    for (i, &(cp, b)) in entries.iter().enumerate() {
        high_cp[i] = cp;
        high_byte[i] = b;
    }
    let mut direct_page_slot = [REVERSE_DIRECT_MISSING; 256];
    let mut direct_page_byte = [[0u8; 256]; REVERSE_DIRECT_PAGES];
    let mut direct_page_count = 0u8;
    for &(cp, b) in &entries {
        if cp > u32::from(u16::MAX) {
            continue;
        }
        debug_assert_ne!(b, 0);
        let page = (cp >> 8) as usize;
        let mut slot = direct_page_slot[page];
        if slot == REVERSE_DIRECT_MISSING {
            if usize::from(direct_page_count) == REVERSE_DIRECT_PAGES {
                continue;
            }
            slot = direct_page_count;
            direct_page_slot[page] = slot;
            direct_page_count += 1;
        }
        direct_page_byte[slot as usize][(cp & 0xFF) as usize] = b;
    }
    Some(SingleByteReverse {
        direct_page_slot,
        direct_page_byte,
        high_cp,
        high_byte,
        high_len: entries.len() as u16,
    })
}

/// Encode one char into `out`, using the cached single-byte reverse map for the
/// common success case (representable codepoint + space available) and otherwise
/// delegating to `encode_char` so each codec's exact NoSpace-vs-Unrepresentable
/// error ordering is preserved.
fn encode_one(cd: &IconvDescriptor, ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    if let Some(rev) = cd.to_reverse.as_ref()
        && !out.is_empty()
        && let Some(byte) = rev.lookup(ch)
    {
        out[0] = byte;
        return Ok(1);
    }
    encode_char(cd.to, ch, out)
}

/// GB18030 four-byte linear index: `L = (b1-0x81)*12600 + (b2-0x30)*1260 +
/// (b3-0x81)*10 + (b4-0x30)` (b2/b4 in 0x30-0x39 → 10 values; b1/b3 in
/// 0x81-0xFE → 126 values). Bytes must be pre-validated to those ranges.
#[inline]
fn gb18030_lin4(b1: u8, b2: u8, b3: u8, b4: u8) -> u32 {
    (u32::from(b1) - 0x81) * 12600
        + (u32::from(b2) - 0x30) * 1260
        + (u32::from(b3) - 0x81) * 10
        + (u32::from(b4) - 0x30)
}

/// Linear index of the contiguous 4-byte run mapping to the supplementary
/// planes: `0x90 0x30 0x81 0x30` → U+10000 … → U+10FFFF.
const GB18030_SUPP_L_LO: u32 = 189_000;
const GB18030_SUPP_L_HI: u32 = 1_237_575;

/// Emit the GB18030 four bytes for linear index `l` (inverse of [`gb18030_lin4`]).
#[inline]
fn gb18030_emit4(l: u32, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.len() < 4 {
        return Err(EncodeError::NoSpace);
    }
    out[0] = (0x81 + l / 12600) as u8;
    out[1] = (0x30 + (l / 1260) % 10) as u8;
    out[2] = (0x81 + (l / 10) % 126) as u8;
    out[3] = (0x30 + l % 10) as u8;
    Ok(4)
}

/// GB18030 decoder (1/2/4-byte) matching glibc's gconv. ASCII is 1-byte; a lead
/// `0x81-0xFE` followed by `0x30-0x39` is a 4-byte sequence (the rest of Unicode
/// via a linear index — supplementary planes by the [`GB18030_SUPP_L_LO`] formula,
/// BMP gaps by the `GB18030_DEC4` RLE segments), otherwise a 2-byte GBK-superset
/// char via `GB18030_DBCS2`. A truncated valid sequence is `Incomplete` (EINVAL);
/// an out-of-range continuation byte or unmapped index is `Invalid` (EILSEQ).
/// Direct `2-byte key -> code point` table for GB18030's two-byte form, lazily
/// built once from the sorted `GB18030_DBCS2` array. A value of 0 means "not a
/// valid 2-byte sequence" (no GB18030 2-byte form decodes to U+0000). Replaces a
/// binary search over the table (~15 cache-missing probes per char) with one
/// O(1) index, matching glibc's static-table decode. Built identically to the
/// binary search, so the result is byte-for-byte the same.
fn gb18030_dbcs2_direct() -> &'static [u32] {
    static TABLE: std::sync::OnceLock<Vec<u32>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = vec![0u32; 0x10000];
        for &(key, cp) in cjk_tables::GB18030_DBCS2.iter() {
            t[key as usize] = cp;
        }
        t
    })
}

fn decode_gb18030(input: &[u8]) -> Result<(char, usize), DecodeError> {
    let Some(&b0) = input.first() else {
        return Err(DecodeError::Incomplete);
    };
    let ob = cjk_tables::GB18030_ONE_BYTE[b0 as usize];
    if ob >= 0 {
        return char::from_u32(ob as u32)
            .map(|c| (c, 1))
            .ok_or(DecodeError::Invalid);
    }
    if !cjk_tables::GB18030_IS_LEAD[b0 as usize] {
        return Err(DecodeError::Invalid);
    }
    let Some(&b1) = input.get(1) else {
        return Err(DecodeError::Incomplete);
    };
    if (0x30..=0x39).contains(&b1) {
        // Four-byte sequence. glibc requires all four bytes present before
        // validating bytes 3-4, so a truncated tail is EINVAL (incomplete) even
        // if a present byte is already out of range.
        if input.len() < 4 {
            return Err(DecodeError::Incomplete);
        }
        let b2 = input[2];
        let b3 = input[3];
        if !(0x81..=0xFE).contains(&b2) || !(0x30..=0x39).contains(&b3) {
            return Err(DecodeError::Invalid);
        }
        let l = gb18030_lin4(b0, b1, b2, b3);
        if (GB18030_SUPP_L_LO..=GB18030_SUPP_L_HI).contains(&l) {
            let cp = 0x10000 + (l - GB18030_SUPP_L_LO);
            return char::from_u32(cp)
                .map(|c| (c, 4))
                .ok_or(DecodeError::Invalid);
        }
        let segs = &cjk_tables::GB18030_DEC4;
        let i = segs.partition_point(|&(lstart, _, _)| lstart <= l);
        if i > 0 {
            let (lstart, cpstart, len) = segs[i - 1];
            if l < lstart + len {
                let cp = cpstart + (l - lstart);
                return char::from_u32(cp)
                    .map(|c| (c, 4))
                    .ok_or(DecodeError::Invalid);
            }
        }
        return Err(DecodeError::Invalid);
    }
    let key = (u16::from(b0) << 8) | u16::from(b1);
    // O(1) direct-table lookup (0 = not a valid 2-byte sequence).
    let cp = gb18030_dbcs2_direct()[key as usize];
    if cp != 0 {
        char::from_u32(cp).map(|c| (c, 2)).ok_or(DecodeError::Invalid)
    } else {
        Err(DecodeError::Invalid)
    }
}

/// GB18030 encoder: ASCII identity; supplementary planes via the linear formula;
/// BMP via the 2-byte table (`GB18030_ENC2`) then the 4-byte RLE segments
/// (`GB18030_ENC4`, sorted by code point). GB18030 covers all of Unicode, so the
/// only `Unrepresentable` cases are surrogates / above U+10FFFF.
/// Direct `code point -> GB18030 2-byte key` table for the BMP (0x80..=0xFFFF),
/// lazily built once from the sorted `GB18030_ENC2` array. A key of 0 means "not
/// 2-byte-encodable" (real GB18030 2-byte keys are >= 0x8140, never 0), so the
/// caller falls through to the 4-byte segments. This replaces a binary search
/// over 23,940 entries (~15 cache-missing probes per char) with one O(1) index,
/// matching glibc's static-table lookup. Built identically to the binary search,
/// so the result is byte-for-byte the same.
fn gb18030_enc2_direct() -> &'static [u16] {
    static TABLE: std::sync::OnceLock<Vec<u16>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = vec![0u16; (0x10000 - 0x80) as usize];
        for &(cp, key) in cjk_tables::GB18030_ENC2.iter() {
            if (0x80..0x10000).contains(&cp) {
                t[(cp - 0x80) as usize] = key;
            }
        }
        t
    })
}

fn encode_gb18030(ch: char, out: &mut [u8]) -> Result<usize, EncodeError> {
    let cp = ch as u32;
    if cp < 0x80 {
        if out.is_empty() {
            return Err(EncodeError::NoSpace);
        }
        out[0] = cp as u8;
        return Ok(1);
    }
    if cp >= 0x10000 {
        if cp > 0x10FFFF {
            return Err(EncodeError::Unrepresentable);
        }
        return gb18030_emit4(GB18030_SUPP_L_LO + (cp - 0x10000), out);
    }
    // O(1) direct-table lookup for the BMP 2-byte form (cp is 0x80..=0xFFFF here,
    // since < 0x80 and >= 0x10000 are handled above). 0 = not 2-byte-encodable.
    let key = gb18030_enc2_direct()[(cp - 0x80) as usize];
    if key != 0 {
        if out.len() < 2 {
            return Err(EncodeError::NoSpace);
        }
        out[0] = (key >> 8) as u8;
        out[1] = (key & 0xFF) as u8;
        return Ok(2);
    }
    let segs = &cjk_tables::GB18030_ENC4;
    let i = segs.partition_point(|&(cpstart, _, _)| cpstart <= cp);
    if i > 0 {
        let (cpstart, lstart, len) = segs[i - 1];
        if cp < cpstart + len {
            return gb18030_emit4(lstart + (cp - cpstart), out);
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
        Encoding::Utf16Be => decode_utf16be(input),
        // Unmarked UTF-16 decodes LE by default; the BOM-resolved endianness is
        // applied by the convert loop (which dispatches to Utf16Be when a BE BOM
        // was seen), exactly like the unmarked Utf32 path.
        Encoding::Utf16 => decode_utf16le(input),
        Encoding::Utf32 => decode_utf32(input),
        Encoding::Utf32Be => decode_utf32be(input),
        Encoding::Utf32Le => decode_utf32le(input),
        Encoding::Koi8R => decode_koi8r(input),
        Encoding::Koi8U => decode_koi8u(input),
        Encoding::Koi8Ru => decode_koi8ru(input),
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
        Encoding::GeorgianPs => decode_georgian_ps(input),
        Encoding::GeorgianAcademy => decode_georgian_academy(input),
        Encoding::Pt154 => decode_pt154(input),
        Encoding::Rk1048 => decode_rk1048(input),
        Encoding::Mulelao => decode_mulelao(input),
        Encoding::HpRoman8 => decode_hproman8(input),
        Encoding::Nextstep => decode_nextstep(input),
        Encoding::Atarist => decode_atarist(input),
        Encoding::Cp850 => decode_cp850(input),
        Encoding::Cp851 => decode_cp851(input),
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
        Encoding::Iso88599e => decode_iso88599e(input),
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
        Encoding::MacTurkish => decode_macturkish(input),
        Encoding::MacIceland => decode_maciceland(input),
        Encoding::MacCentralEurope => decode_maccentraleurope(input),
        Encoding::MacUkraine => decode_macukraine(input),
        Encoding::Cp858 => decode_cp858(input),
        Encoding::MacRomanian => decode_macromanian(input),
        Encoding::MacSami => decode_macsami(input),
        Encoding::MacCroatian => decode_maccroatian(input),
        Encoding::Cp720 => decode_cp720(input),
        Encoding::MacHebrew => decode_machebrew(input),
        Encoding::MacArabic => decode_macarabic(input),
        Encoding::MacThai => decode_macthai(input),
        Encoding::MacFarsi => decode_macfarsi(input),
        Encoding::MacDevanagari => decode_macdevanagari(input),
        Encoding::MacGurmukhi => decode_macgurmukhi(input),
        Encoding::MacGujarati => decode_macgujarati(input),
        Encoding::MacKannada => decode_mackannada(input),
        Encoding::MacTelugu => decode_mactelugu(input),
        Encoding::MacOriya => decode_macoriya(input),
        Encoding::MacBengali => decode_macbengali(input),
        Encoding::MacMalayalam => decode_macmalayalam(input),
        Encoding::MacTamil => decode_mactamil(input),
        Encoding::Cp1006 => decode_cp1006(input),
        Encoding::Cp1008 => decode_cp1008(input),
        Encoding::Cp1046 => decode_cp1046(input),
        Encoding::Cp1124 => decode_cp1124(input),
        Encoding::Cp1129 => decode_cp1129(input),
        Encoding::Cp1133 => decode_cp1133(input),
        Encoding::Cp774 => decode_cp774(input),
        Encoding::Cp773 => decode_cp773(input),
        Encoding::Cp772 => decode_cp772(input),
        Encoding::Cp771 => decode_cp771(input),
        Encoding::Cp770 => decode_cp770(input),
        Encoding::Cp868 => decode_cp868(input),
        Encoding::Cp813 => decode_cp813(input),
        Encoding::Cp916 => decode_cp916(input),
        Encoding::Cp1161 => decode_cp1161(input),
        Encoding::Cp1162 => decode_cp1162(input),
        Encoding::Cp1163 => decode_cp1163(input),
        Encoding::Isiri3342 => decode_isiri3342(input),
        Encoding::Mik => decode_mik(input),
        Encoding::Koi8T => decode_koi8t(input),
        Encoding::EcmaCyrillic => decode_ecma_cyrillic(input),
        Encoding::Cp866Nav => decode_cp866nav(input),
        Encoding::DecMcs => decode_decmcs(input),
        Encoding::HpRoman9 => decode_hproman9(input),
        Encoding::HpGreek8 => decode_hpgreek8(input),
        Encoding::HpThai8 => decode_hpthai8(input),
        Encoding::HpTurkish8 => decode_hpturkish8(input),
        Encoding::Cp1004 => decode_cp1004(input),
        Encoding::Ibm1167 => decode_ibm1167(input),
        Encoding::Cwi => decode_cwi(input),
        Encoding::Strk10482002 => decode_strk10482002(input),
        Encoding::Csn369103 => decode_csn369103(input),
        Encoding::Ibm902 => decode_ibm902(input),
        Encoding::Ibm901 => decode_ibm901(input),
        Encoding::Cp856 => decode_cp856(input),
        Encoding::Cp1125 => decode_cp1125(input),
        Encoding::EucJp => decode_eucjp(input),
        Encoding::ShiftJis => decode_shiftjis(input),
        Encoding::Big5 => decode_big5(input),
        Encoding::Gbk => decode_dbcs2(
            input,
            &cjk_tables::GBK_ONE_BYTE,
            &cjk_tables::GBK_IS_LEAD,
            &cjk_tables::GBK_DBCS,
        ),
        Encoding::EucKr => decode_dbcs2(
            input,
            &cjk_tables::EUC_KR_ONE_BYTE,
            &cjk_tables::EUC_KR_IS_LEAD,
            &cjk_tables::EUC_KR_DBCS,
        ),
        Encoding::Cp949 => decode_dbcs2(
            input,
            &cjk_tables::CP949_ONE_BYTE,
            &cjk_tables::CP949_IS_LEAD,
            &cjk_tables::CP949_DBCS,
        ),
        Encoding::Gb2312 => decode_dbcs2(
            input,
            &cjk_tables::GB2312_ONE_BYTE,
            &cjk_tables::GB2312_IS_LEAD,
            &cjk_tables::GB2312_DBCS,
        ),
        Encoding::Gb18030 => decode_gb18030(input),
        Encoding::Johab => decode_dbcs2(
            input,
            &cjk_tables::JOHAB_ONE_BYTE,
            &cjk_tables::JOHAB_IS_LEAD,
            &cjk_tables::JOHAB_DBCS,
        ),
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
        // Unmarked `Utf16` encodes LE units (its LE BOM is emitted separately by
        // the convert loop), so it shares the explicit-LE encoder here.
        Encoding::Utf16Le | Encoding::Utf16 => {
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
        Encoding::Utf32Le => {
            if out.len() < 4 {
                return Err(EncodeError::NoSpace);
            }
            let bytes = (ch as u32).to_le_bytes();
            out[..4].copy_from_slice(&bytes);
            Ok(4)
        }
        Encoding::Koi8R => encode_koi8r(ch, out),
        Encoding::Koi8U => encode_koi8u(ch, out),
        Encoding::Koi8Ru => encode_koi8ru(ch, out),
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
        Encoding::GeorgianPs => encode_georgian_ps(ch, out),
        Encoding::GeorgianAcademy => encode_georgian_academy(ch, out),
        Encoding::Pt154 => encode_pt154(ch, out),
        Encoding::Rk1048 => encode_rk1048(ch, out),
        Encoding::Mulelao => encode_mulelao(ch, out),
        Encoding::HpRoman8 => encode_hproman8(ch, out),
        Encoding::Nextstep => encode_nextstep(ch, out),
        Encoding::Atarist => encode_atarist(ch, out),
        Encoding::Cp850 => encode_cp850(ch, out),
        Encoding::Cp851 => encode_cp851(ch, out),
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
        Encoding::Iso88599e => encode_iso88599e(ch, out),
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
        Encoding::MacTurkish => encode_macturkish(ch, out),
        Encoding::MacIceland => encode_maciceland(ch, out),
        Encoding::MacCentralEurope => encode_maccentraleurope(ch, out),
        Encoding::MacUkraine => encode_macukraine(ch, out),
        Encoding::Cp858 => encode_cp858(ch, out),
        Encoding::MacRomanian => encode_macromanian(ch, out),
        Encoding::MacSami => encode_macsami(ch, out),
        Encoding::MacCroatian => encode_maccroatian(ch, out),
        Encoding::Cp720 => encode_cp720(ch, out),
        Encoding::MacHebrew => encode_machebrew(ch, out),
        Encoding::MacArabic => encode_macarabic(ch, out),
        Encoding::MacThai => encode_macthai(ch, out),
        Encoding::MacFarsi => encode_macfarsi(ch, out),
        Encoding::MacDevanagari => encode_macdevanagari(ch, out),
        Encoding::MacGurmukhi => encode_macgurmukhi(ch, out),
        Encoding::MacGujarati => encode_macgujarati(ch, out),
        Encoding::MacKannada => encode_mackannada(ch, out),
        Encoding::MacTelugu => encode_mactelugu(ch, out),
        Encoding::MacOriya => encode_macoriya(ch, out),
        Encoding::MacBengali => encode_macbengali(ch, out),
        Encoding::MacMalayalam => encode_macmalayalam(ch, out),
        Encoding::MacTamil => encode_mactamil(ch, out),
        Encoding::Cp1006 => encode_cp1006(ch, out),
        Encoding::Cp1008 => encode_cp1008(ch, out),
        Encoding::Cp1046 => encode_cp1046(ch, out),
        Encoding::Cp1124 => encode_cp1124(ch, out),
        Encoding::Cp1129 => encode_cp1129(ch, out),
        Encoding::Cp1133 => encode_cp1133(ch, out),
        Encoding::Cp774 => encode_cp774(ch, out),
        Encoding::Cp773 => encode_cp773(ch, out),
        Encoding::Cp772 => encode_cp772(ch, out),
        Encoding::Cp771 => encode_cp771(ch, out),
        Encoding::Cp770 => encode_cp770(ch, out),
        Encoding::Cp868 => encode_cp868(ch, out),
        Encoding::Cp813 => encode_cp813(ch, out),
        Encoding::Cp916 => encode_cp916(ch, out),
        Encoding::Cp1161 => encode_cp1161(ch, out),
        Encoding::Cp1162 => encode_cp1162(ch, out),
        Encoding::Cp1163 => encode_cp1163(ch, out),
        Encoding::Isiri3342 => encode_isiri3342(ch, out),
        Encoding::Mik => encode_mik(ch, out),
        Encoding::Koi8T => encode_koi8t(ch, out),
        Encoding::EcmaCyrillic => encode_ecma_cyrillic(ch, out),
        Encoding::Cp866Nav => encode_cp866nav(ch, out),
        Encoding::DecMcs => encode_decmcs(ch, out),
        Encoding::HpRoman9 => encode_hproman9(ch, out),
        Encoding::HpGreek8 => encode_hpgreek8(ch, out),
        Encoding::HpThai8 => encode_hpthai8(ch, out),
        Encoding::HpTurkish8 => encode_hpturkish8(ch, out),
        Encoding::Cp1004 => encode_cp1004(ch, out),
        Encoding::Ibm1167 => encode_ibm1167(ch, out),
        Encoding::Cwi => encode_cwi(ch, out),
        Encoding::Strk10482002 => encode_strk10482002(ch, out),
        Encoding::Csn369103 => encode_csn369103(ch, out),
        Encoding::Ibm902 => encode_ibm902(ch, out),
        Encoding::Ibm901 => encode_ibm901(ch, out),
        Encoding::Cp856 => encode_cp856(ch, out),
        Encoding::Cp1125 => encode_cp1125(ch, out),
        Encoding::EucJp => encode_eucjp(ch, out),
        Encoding::ShiftJis => encode_shiftjis(ch, out),
        Encoding::Big5 => encode_big5(ch, out),
        Encoding::Gbk => encode_dbcs2(ch, out, &cjk_tables::GBK_ENC),
        Encoding::EucKr => encode_dbcs2(ch, out, &cjk_tables::EUC_KR_ENC),
        Encoding::Cp949 => encode_dbcs2(ch, out, &cjk_tables::CP949_ENC),
        Encoding::Gb2312 => encode_dbcs2(ch, out, &cjk_tables::GB2312_ENC),
        Encoding::Gb18030 => encode_gb18030(ch, out),
        Encoding::Johab => encode_dbcs2(ch, out, &cjk_tables::JOHAB_ENC),
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
            emit_bom: matches!(to, Encoding::Utf32 | Encoding::Utf16),
            dispatch,
            fast_ascii: pair_is_ascii_identity(from, to),
            sb_translation: build_sb_translation(from, to),
            to_reverse: build_to_reverse(to),
            from_bom_pending: matches!(from, Encoding::Utf32 | Encoding::Utf16),
            from_unmarked_be: false,
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
                    Encoding::Utf16 => &[0xFF, 0xFE][..],
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

    // NOTE: the destination BOM (unmarked `UTF-32`) is emitted LAZILY, just
    // before the first successfully-converted character is written (see the loop
    // below), NOT eagerly here. glibc only emits the BOM alongside real output:
    // an empty input — or one that errors before producing any character —
    // yields no BOM at all. Emitting it up-front diverged on those cases.

    // Unmarked `UTF-16`/`UTF-32` source: consume a leading BOM once and resolve
    // the decode endianness from it, matching glibc's gconv (LE BOM => LE, BE BOM
    // => BE, no BOM => the native LE default). The BOM width equals the unit
    // width — 2 bytes for UTF-16 (`FF FE`/`FE FF`), 4 for UTF-32
    // (`FF FE 00 00`/`00 00 FE FF`); the UTF-32 BOM shares a prefix with the
    // UTF-16 one, so the check branches on `cd.from`. Only attempt it with a full
    // unit available; with fewer bytes the per-unit decode below returns
    // EINVAL/incomplete and the caller re-presents the tail, so `from_bom_pending`
    // stays set for the next call.
    if cd.from_bom_pending {
        match cd.from {
            Encoding::Utf32 if input.len() - in_pos >= 4 => {
                match input[in_pos..in_pos + 4] {
                    [0xFF, 0xFE, 0x00, 0x00] => {
                        cd.from_unmarked_be = false;
                        in_pos += 4;
                    }
                    [0x00, 0x00, 0xFE, 0xFF] => {
                        cd.from_unmarked_be = true;
                        in_pos += 4;
                    }
                    _ => {} // no BOM: keep the native LE default
                }
                cd.from_bom_pending = false;
            }
            Encoding::Utf16 if input.len() - in_pos >= 2 => {
                match input[in_pos..in_pos + 2] {
                    [0xFF, 0xFE] => {
                        cd.from_unmarked_be = false;
                        in_pos += 2;
                    }
                    [0xFE, 0xFF] => {
                        cd.from_unmarked_be = true;
                        in_pos += 2;
                    }
                    _ => {} // no BOM: keep the native LE default
                }
                cd.from_bom_pending = false;
            }
            _ => {}
        }
    }

    // Source encoding to decode each unit under. For the unmarked UTF-16/UTF-32
    // codecs this reflects the BOM-resolved endianness (the *Le decoders are LE;
    // *Be are big-endian); every other codec decodes under `cd.from` itself.
    let from_enc = match cd.from {
        Encoding::Utf32 if cd.from_unmarked_be => Encoding::Utf32Be,
        Encoding::Utf16 if cd.from_unmarked_be => Encoding::Utf16Be,
        other => other,
    };

    // When both endpoints are ASCII-transparent, any byte < 0x80 converts to
    // itself, so leading ASCII runs can be bulk-copied with a SIMD scan instead
    // of a per-byte decode_char/encode_char round trip. Non-ASCII bytes, errors,
    // and E2BIG all fall through to the unchanged scalar loop, so the result is
    // byte-for-byte identical.
    let fast_ascii = cd.fast_ascii;

    while in_pos < input.len() {
        if fast_ascii && input[in_pos] < 0x80 {
            let avail = outbuf.len() - out_pos;
            if avail > 0 {
                let run = leading_ascii_len(&input[in_pos..]).min(avail);
                if run > 0 {
                    outbuf[out_pos..out_pos + run].copy_from_slice(&input[in_pos..in_pos + run]);
                    in_pos += run;
                    out_pos += run;
                    if in_pos >= input.len() {
                        break;
                    }
                    // Next byte is >= 0x80 (handled below) or the output is full
                    // (the encode path returns E2BIG at this exact position).
                }
            }
        }

        // Single-byte -> single-byte: translate the byte in O(1) via the cached
        // table, skipping decode_char + the O(128) reverse-search in encode_*.
        // (For ASCII-transparent pairs the run above already consumed the
        // <0x80 bytes, so this typically resolves a high byte.) Only the common
        // case — representable AND output space available — is fast-pathed; an
        // unrepresentable byte or a full buffer falls through to the scalar
        // decode/encode below, which reproduces each codec's exact
        // EILSEQ-vs-E2BIG error ordering.
        if let Some(lut) = cd.sb_translation.as_ref() {
            let translated = lut[input[in_pos] as usize];
            if translated >= 0 && out_pos < outbuf.len() {
                outbuf[out_pos] = translated as u8;
                in_pos += 1;
                out_pos += 1;
                continue;
            }
        }

        // SIMD 2-byte fast path: decode a run of >= 8 well-formed 2-byte UTF-8
        // sequences into UTF-32, 8 code points per 16-byte window. A 2-byte char
        // (lead 0xC2..=0xDF + continuation 0x80..=0xBF) yields a code point in
        // 0x80..=0x7FF — provably never overlong (lead >= 0xC2 => wc >= 0x80) nor a
        // surrogate (wc <= 0x7FF) — so a byte-range-validated window needs no
        // further checks and is byte-for-byte what the scalar decode+encode below
        // produces. Only the fixed-width UTF-32 targets use it; everything else
        // (incl. a non-clean window) drops to the scalar fast path and then the
        // generic body, preserving the exact EILSEQ/EINVAL/E2BIG ordering.
        // The `(0xC2..=0xDF)` lead test is first so non-2-byte input (ASCII handled
        // above, 3/4-byte CJK/astral) short-circuits before any other work — zero
        // added cost on those paths.
        // Fixed-width Unicode targets: UTF-32 (4 bytes/char) and UTF-16 (2
        // bytes/char). A 2-byte source code point is 0x80..=0x7FF — a BMP scalar,
        // so its UTF-16 form is a single code unit equal to the code point (no
        // surrogate pair), identical to the scalar `encode_utf16` below.
        if (0xC2..=0xDF).contains(&input[in_pos])
            && from_enc == Encoding::Utf8
            && !cd.emit_bom
            && matches!(
                cd.to,
                Encoding::Utf32Le | Encoding::Utf32Be | Encoding::Utf16Le | Encoding::Utf16Be
            )
        {
            let be = matches!(cd.to, Encoding::Utf32Be | Encoding::Utf16Be);
            let u16_out = matches!(cd.to, Encoding::Utf16Le | Encoding::Utf16Be);
            let obpc = if u16_out { 2 } else { 4 }; // output bytes per char
            while in_pos + 16 <= input.len()
                && out_pos + 8 * obpc <= outbuf.len()
                && (0xC2..=0xDF).contains(&input[in_pos])
            {
                let bytes: [u8; 16] = input[in_pos..in_pos + 16].try_into().unwrap();
                let v = Simd::<u8, 16>::from_array(bytes);
                let leads = std::simd::simd_swizzle!(v, [0, 2, 4, 6, 8, 10, 12, 14]);
                let conts = std::simd::simd_swizzle!(v, [1, 3, 5, 7, 9, 11, 13, 15]);
                let leads_ok = leads.simd_ge(Simd::splat(0xC2)) & leads.simd_le(Simd::splat(0xDF));
                let conts_ok = conts.simd_ge(Simd::splat(0x80)) & conts.simd_le(Simd::splat(0xBF));
                if !(leads_ok & conts_ok).all() {
                    break; // not a clean 2-byte window — scalar path handles it
                }
                let lw = leads.cast::<u32>() & Simd::splat(0x1F);
                let cw = conts.cast::<u32>() & Simd::splat(0x3F);
                let wc = (lw << Simd::splat(6)) | cw;
                for (k, &cp) in wc.to_array().iter().enumerate() {
                    if u16_out {
                        let b = if be {
                            (cp as u16).to_be_bytes()
                        } else {
                            (cp as u16).to_le_bytes()
                        };
                        outbuf[out_pos + k * 2..out_pos + k * 2 + 2].copy_from_slice(&b);
                    } else {
                        let b = if be {
                            cp.to_be_bytes()
                        } else {
                            cp.to_le_bytes()
                        };
                        outbuf[out_pos + k * 4..out_pos + k * 4 + 4].copy_from_slice(&b);
                    }
                }
                in_pos += 16;
                out_pos += 8 * obpc;
            }
        }
        // The 2-byte SIMD block above may have drained the input; the 3-byte block
        // indexes `input[in_pos]` in its guard, so stop here when empty.
        if in_pos >= input.len() {
            break;
        }

        // SIMD 3-byte fast path (ported from mbstowcs): a clean 12-byte window (4
        // sequences, read from a 16-byte load) decodes 4 code points. Validate the
        // full RFC 3629 3-byte shape — lead E0..EF, both continuations 80..BF, no
        // E0 overlong (cont1 >= A0), no ED surrogate (cont1 <= 9F) — then assemble.
        // Lead-byte test first so non-3-byte input short-circuits with zero cost.
        // A validated 3-byte source code point is a BMP non-surrogate scalar
        // (0x800..=0xFFFF minus surrogates), so its UTF-16 form is one code unit
        // equal to the code point — same as the scalar `encode_utf16` below.
        if (0xE0..=0xEF).contains(&input[in_pos])
            && from_enc == Encoding::Utf8
            && !cd.emit_bom
            && matches!(
                cd.to,
                Encoding::Utf32Le | Encoding::Utf32Be | Encoding::Utf16Le | Encoding::Utf16Be
            )
        {
            let be = matches!(cd.to, Encoding::Utf32Be | Encoding::Utf16Be);
            let u16_out = matches!(cd.to, Encoding::Utf16Le | Encoding::Utf16Be);
            let obpc = if u16_out { 2 } else { 4 };
            while in_pos + 16 <= input.len()
                && out_pos + 4 * obpc <= outbuf.len()
                && (0xE0..=0xEF).contains(&input[in_pos])
            {
                let bytes: [u8; 16] = input[in_pos..in_pos + 16].try_into().unwrap();
                let v = Simd::<u8, 16>::from_array(bytes);
                let leads = std::simd::simd_swizzle!(v, [0, 3, 6, 9]);
                let cont1 = std::simd::simd_swizzle!(v, [1, 4, 7, 10]);
                let cont2 = std::simd::simd_swizzle!(v, [2, 5, 8, 11]);
                let leads_ok = leads.simd_ge(Simd::splat(0xE0)) & leads.simd_le(Simd::splat(0xEF));
                let cont1_ok = cont1.simd_ge(Simd::splat(0x80)) & cont1.simd_le(Simd::splat(0xBF));
                let cont2_ok = cont2.simd_ge(Simd::splat(0x80)) & cont2.simd_le(Simd::splat(0xBF));
                let overlong_ok =
                    !leads.simd_eq(Simd::splat(0xE0)) | cont1.simd_ge(Simd::splat(0xA0));
                let surrogate_ok =
                    !leads.simd_eq(Simd::splat(0xED)) | cont1.simd_le(Simd::splat(0x9F));
                if !(leads_ok & cont1_ok & cont2_ok & overlong_ok & surrogate_ok).all() {
                    break; // not a clean 3-byte window — scalar path handles it
                }
                let lw = leads.cast::<u32>() & Simd::splat(0x0F);
                let c1w = cont1.cast::<u32>() & Simd::splat(0x3F);
                let c2w = cont2.cast::<u32>() & Simd::splat(0x3F);
                let wc = (lw << Simd::splat(12)) | (c1w << Simd::splat(6)) | c2w;
                for (k, &cp) in wc.to_array().iter().enumerate() {
                    if u16_out {
                        let b = if be {
                            (cp as u16).to_be_bytes()
                        } else {
                            (cp as u16).to_le_bytes()
                        };
                        outbuf[out_pos + k * 2..out_pos + k * 2 + 2].copy_from_slice(&b);
                    } else {
                        let b = if be {
                            cp.to_be_bytes()
                        } else {
                            cp.to_le_bytes()
                        };
                        outbuf[out_pos + k * 4..out_pos + k * 4 + 4].copy_from_slice(&b);
                    }
                }
                in_pos += 12;
                out_pos += 4 * obpc;
            }
        }
        // The SIMD blocks may have consumed the rest of the input; the scalar fast
        // path and generic body below index `input[in_pos]` unguarded (the only
        // bounds check is the outer `while` top), so stop here when drained.
        if in_pos >= input.len() {
            break;
        }

        // SIMD UTF-8 ENCODE: fixed-width UTF-32/UTF-16 source -> UTF-8 target.
        // Mirrors the wcstombs 2-byte (8 code points -> 16 bytes) and 3-byte
        // (4 -> 12 bytes) SIMD encoders, reading code points from the source units
        // (`scp` bytes each: 4 for UTF-32, 2 for UTF-16 — where a BMP scalar is a
        // single unit equal to the code point). A cheap peek of the first code
        // point routes to the matching width; anything outside the uniform-width
        // range (ASCII, astral, surrogate, out-of-range) or short output falls to
        // the generic decode_char + encode_one body — so UTF-16 surrogate pairs
        // (astral) and lone surrogates are handled exactly by the scalar path.
        if matches!(
            from_enc,
            Encoding::Utf32Le | Encoding::Utf32Be | Encoding::Utf16Le | Encoding::Utf16Be
        ) && cd.to == Encoding::Utf8
        {
            let sbe = matches!(from_enc, Encoding::Utf32Be | Encoding::Utf16Be);
            let scp = if matches!(from_enc, Encoding::Utf16Le | Encoding::Utf16Be) {
                2usize
            } else {
                4usize
            };
            let cp_at = |p: usize| -> u32 {
                if scp == 2 {
                    let b: [u8; 2] = input[p..p + 2].try_into().unwrap();
                    u32::from(if sbe { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
                } else {
                    let b: [u8; 4] = input[p..p + 4].try_into().unwrap();
                    if sbe { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
                }
            };
            // 2-byte output run (code points 0x80..=0x7FF).
            while in_pos + 8 * scp <= input.len()
                && out_pos + 16 <= outbuf.len()
                && (0x80..=0x7FF).contains(&cp_at(in_pos))
            {
                let cps: [u32; 8] = std::array::from_fn(|k| cp_at(in_pos + scp * k));
                let v = Simd::<u32, 8>::from_array(cps);
                if !(v.simd_ge(Simd::splat(0x80)) & v.simd_le(Simd::splat(0x7FF))).all() {
                    break;
                }
                let leads = ((v >> Simd::splat(6)) | Simd::splat(0xC0)).cast::<u8>();
                let conts = ((v & Simd::splat(0x3F)) | Simd::splat(0x80)).cast::<u8>();
                let bytes = std::simd::simd_swizzle!(
                    leads,
                    conts,
                    [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
                );
                bytes.copy_to_slice(&mut outbuf[out_pos..out_pos + 16]);
                in_pos += 8 * scp;
                out_pos += 16;
            }
            if in_pos >= input.len() {
                break;
            }
            // 3-byte output run (BMP non-surrogate 0x800..=0xFFFF).
            while in_pos + 4 * scp <= input.len()
                && out_pos + 12 <= outbuf.len()
                && (0x800..=0xFFFF).contains(&cp_at(in_pos))
            {
                let cps: [u32; 4] = std::array::from_fn(|k| cp_at(in_pos + scp * k));
                let v = Simd::<u32, 4>::from_array(cps);
                let bmp_ok = v.simd_ge(Simd::splat(0x0800)) & v.simd_le(Simd::splat(0xFFFF));
                let sur_ok = v.simd_lt(Simd::splat(0xD800)) | v.simd_gt(Simd::splat(0xDFFF));
                if !(bmp_ok & sur_ok).all() {
                    break;
                }
                let leads = ((v >> Simd::splat(12)) | Simd::splat(0xE0)).cast::<u8>();
                let mids =
                    (((v >> Simd::splat(6)) & Simd::splat(0x3F)) | Simd::splat(0x80)).cast::<u8>();
                let tails = ((v & Simd::splat(0x3F)) | Simd::splat(0x80)).cast::<u8>();
                let lead_mid = std::simd::simd_swizzle!(leads, mids, [0, 4, 1, 5, 2, 6, 3, 7]);
                let zero = Simd::<u8, 4>::splat(0);
                let tails_padded = std::simd::simd_swizzle!(tails, zero, [0, 4, 1, 4, 2, 4, 3, 4]);
                let bytes = std::simd::simd_swizzle!(
                    lead_mid,
                    tails_padded,
                    [0, 1, 8, 2, 3, 10, 4, 5, 12, 6, 7, 14, 0, 0, 0, 0]
                );
                let packed = bytes.to_array();
                outbuf[out_pos..out_pos + 12].copy_from_slice(&packed[..12]);
                in_pos += 4 * scp;
                out_pos += 12;
            }
            if in_pos >= input.len() {
                break;
            }
        }

        // Hot-path specialization (perf): UTF-8 source is the dominant direction,
        // yet the generic body below dispatches decode_char + encode_char (two
        // ~100-arm matches plus nested calls) for every character. For the common
        // UTF-8 -> fixed-width-Unicode and UTF-8 -> single-byte targets, inline
        // the UTF-8 decode and the encode so the steady state is a tight loop.
        // This is byte-for-byte ISOMORPHIC to the generic path: it uses the SAME
        // `utf8_decode_step` + `char::from_u32` validation and the SAME encode
        // logic, and ANY non-trivial outcome (incomplete/invalid sequence,
        // out-of-range scalar, unrepresentable char, insufficient output, or a
        // pending BOM) leaves `in_pos`/`out_pos` untouched and falls through to
        // the generic body, which reproduces the exact EILSEQ/EINVAL/E2BIG
        // ordering. Placed after the ASCII/sb_translation fast paths so their
        // SIMD bulk-copy still wins for ASCII-transparent pairs.
        if from_enc == Encoding::Utf8 && !cd.emit_bom {
            let b0 = input[in_pos];
            let decoded = if b0 < 0x80 {
                Some((u32::from(b0), 1usize))
            } else {
                match crate::string::wchar::utf8_decode_step(&input[in_pos..]) {
                    crate::string::wchar::Utf8Step::Char { wc, len } => Some((wc, len)),
                    _ => None,
                }
            };
            if let Some((wc, len)) = decoded
                && let Some(ch) = char::from_u32(wc)
            {
                let avail = outbuf.len() - out_pos;
                let wrote: Option<usize> = match cd.to {
                    Encoding::Utf32Le if avail >= 4 => {
                        outbuf[out_pos..out_pos + 4].copy_from_slice(&(ch as u32).to_le_bytes());
                        Some(4)
                    }
                    Encoding::Utf32Be if avail >= 4 => {
                        outbuf[out_pos..out_pos + 4].copy_from_slice(&(ch as u32).to_be_bytes());
                        Some(4)
                    }
                    Encoding::Utf16Le | Encoding::Utf16Be => {
                        let mut units = [0u16; 2];
                        let enc = ch.encode_utf16(&mut units);
                        let needed = enc.len() * 2;
                        if avail >= needed {
                            let be = matches!(cd.to, Encoding::Utf16Be);
                            for (idx, unit) in enc.iter().enumerate() {
                                let bytes = if be {
                                    unit.to_be_bytes()
                                } else {
                                    unit.to_le_bytes()
                                };
                                outbuf[out_pos + idx * 2] = bytes[0];
                                outbuf[out_pos + idx * 2 + 1] = bytes[1];
                            }
                            Some(needed)
                        } else {
                            None
                        }
                    }
                    _ => match cd.to_reverse.as_ref() {
                        Some(rev) if avail >= 1 => rev.lookup(ch).map(|byte| {
                            outbuf[out_pos] = byte;
                            1
                        }),
                        Some(_) => None, // single-byte target, no room -> generic
                        // Multibyte target (DBCS: GB18030 / Shift-JIS / EUC-JP /
                        // Big5, or UTF-8 passthrough): encode the already-decoded
                        // char inline via the same `encode_one` the generic body
                        // uses, so the steady state decodes ONCE instead of
                        // decoding here, discarding, and re-decoding below. An
                        // encode error (unrepresentable / no space) yields None and
                        // falls through to the generic body for the exact ordering.
                        None => encode_one(cd, ch, &mut outbuf[out_pos..]).ok(),
                    },
                };
                if let Some(w) = wrote {
                    in_pos += len;
                    out_pos += w;
                    continue;
                }
            }
        }

        // Fast path: GB18030 -> UTF-8. Inline decode_gb18030 (now an O(1) direct
        // table) + a direct UTF-8 encode, so the steady state skips both 100-arm
        // dispatches (decode_char + encode_char) and the encode_one wrapper. Any
        // decode error or insufficient room (< 4 bytes, the max UTF-8 length) drops
        // to the generic body below for the exact EILSEQ/EINVAL/E2BIG ordering.
        // Byte-for-byte identical: same decoder + the same char::encode_utf8.
        if from_enc == Encoding::Gb18030 && cd.to == Encoding::Utf8 {
            while in_pos < input.len() && out_pos + 4 <= outbuf.len() {
                let Ok((ch, consumed)) = decode_gb18030(&input[in_pos..]) else {
                    break;
                };
                let mut buf = [0u8; 4];
                let enc = ch.encode_utf8(&mut buf).len();
                outbuf[out_pos..out_pos + enc].copy_from_slice(&buf[..enc]);
                in_pos += consumed;
                out_pos += enc;
            }
            if in_pos >= input.len() {
                break;
            }
        }

        let (ch, consumed) = match decode_char(from_enc, &input[in_pos..]) {
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

        // A character successfully decoded — emit any pending destination BOM
        // now (lazily), so it precedes the first real output and is omitted
        // entirely when nothing converts (matching glibc).
        if cd.emit_bom {
            let bom: &[u8] = match cd.to {
                Encoding::Utf32 => &[0xFF, 0xFE, 0x00, 0x00],
                Encoding::Utf16 => &[0xFF, 0xFE],
                _ => &[],
            };
            if !bom.is_empty() {
                if outbuf.len() - out_pos < bom.len() {
                    return Err(IconvError {
                        code: ICONV_E2BIG,
                        in_consumed: in_pos,
                        out_written: out_pos,
                    });
                }
                outbuf[out_pos..out_pos + bom.len()].copy_from_slice(bom);
                out_pos += bom.len();
            }
            cd.emit_bom = false;
        }

        let written = match encode_one(cd, ch, &mut outbuf[out_pos..]) {
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

    // Pure scalar reference: the iconv conversion loop WITHOUT the SIMD ASCII
    // fast path, so the fast path can be proven byte-for-byte isomorphic.
    fn iconv_scalar_ref(
        from: Encoding,
        to: Encoding,
        input: &[u8],
        outbuf: &mut [u8],
    ) -> Result<IconvResult, IconvError> {
        let mut in_pos = 0usize;
        let mut out_pos = 0usize;
        while in_pos < input.len() {
            let (ch, consumed) = match decode_char(from, &input[in_pos..]) {
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
            let written = match encode_char(to, ch, &mut outbuf[out_pos..]) {
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
            non_reversible: 0,
            in_consumed: in_pos,
            out_written: out_pos,
        })
    }

    // Normalise a conversion outcome to (code, in_consumed, out_written, bytes)
    // for exact comparison. code = None on success, Some(errno) on error.
    fn normalize(
        r: &Result<IconvResult, IconvError>,
        out: &[u8],
    ) -> (Option<i32>, usize, usize, Vec<u8>) {
        match r {
            Ok(v) => (
                None,
                v.in_consumed,
                v.out_written,
                out[..v.out_written].to_vec(),
            ),
            Err(e) => (
                Some(e.code),
                e.in_consumed,
                e.out_written,
                out[..e.out_written].to_vec(),
            ),
        }
    }

    #[test]
    fn iconv_ascii_fast_path_isomorphic_to_scalar() {
        // Include single-byte legacy codepages (KOI8-R, CP1251) whose low half is
        // ASCII: the probe-cached fast path now applies to them too, so the
        // reference must still match across these pairs and their non-ASCII bytes.
        let names: &[&[u8]] = &[b"UTF-8", b"US-ASCII", b"ISO-8859-1", b"KOI8-R", b"CP1251"];

        // The probe must ENABLE the fast path for single-byte codepages whose
        // low half is ASCII (both directions, incl. codepage<->codepage)...
        assert!(iconv_open(b"KOI8-R", b"UTF-8").unwrap().fast_ascii);
        assert!(iconv_open(b"UTF-8", b"CP1251").unwrap().fast_ascii);
        assert!(iconv_open(b"CP1251", b"KOI8-R").unwrap().fast_ascii);
        // ...and DISABLE it for multibyte codecs, where one byte is incomplete /
        // one ASCII char is >1 byte.
        assert!(!iconv_open(b"UTF-16LE", b"UTF-8").unwrap().fast_ascii);
        assert!(!iconv_open(b"UTF-8", b"UTF-16LE").unwrap().fast_ascii);

        // The byte->byte translation table exists exactly for single-byte ->
        // single-byte pairs, and is absent when either side is multibyte.
        assert!(
            iconv_open(b"CP1251", b"KOI8-R")
                .unwrap()
                .sb_translation
                .is_some()
        );
        assert!(
            iconv_open(b"ISO-8859-1", b"KOI8-R")
                .unwrap()
                .sb_translation
                .is_some()
        );
        assert!(
            iconv_open(b"KOI8-R", b"UTF-8")
                .unwrap()
                .sb_translation
                .is_none()
        );
        assert!(
            iconv_open(b"UTF-8", b"KOI8-R")
                .unwrap()
                .sb_translation
                .is_none()
        );

        // The codepoint->byte reverse map exists whenever `to` is single-byte
        // (incl. UTF-8 -> single-byte, where there is no byte->byte LUT), and is
        // absent when `to` is multibyte.
        assert!(
            iconv_open(b"KOI8-R", b"UTF-8")
                .unwrap()
                .to_reverse
                .is_some()
        );
        let koi8r_reverse = iconv_open(b"KOI8-R", b"UTF-8").unwrap().to_reverse.unwrap();
        assert_ne!(koi8r_reverse.direct_page_slot[0x04], REVERSE_DIRECT_MISSING);
        assert_eq!(koi8r_reverse.lookup('А'), Some(0xE1));
        assert!(
            iconv_open(b"CP1251", b"UTF-8")
                .unwrap()
                .to_reverse
                .is_some()
        );
        assert!(
            iconv_open(b"UTF-8", b"KOI8-R")
                .unwrap()
                .to_reverse
                .is_none()
        );
        assert!(
            iconv_open(b"UTF-16LE", b"UTF-8")
                .unwrap()
                .to_reverse
                .is_none()
        );

        // Corpus: ASCII of every length around the 32-lane boundary, ASCII with
        // a high byte planted at each offset, NUL-laden ASCII, valid multibyte
        // UTF-8, and pseudo-random byte soup (invalid sequences for UTF-8 src).
        let mut corpus: Vec<Vec<u8>> = Vec::new();
        for len in 0..96usize {
            corpus.push((0..len).map(|i| 0x20 + (i % 0x5F) as u8).collect());
        }
        for pos in 0..70usize {
            let mut v: Vec<u8> = (0..70).map(|_| b'k').collect();
            v[pos] = 0xC3; // high byte
            corpus.push(v);
        }
        for pos in 0..40usize {
            let mut v: Vec<u8> = (0..40).map(|i| (i % 128) as u8).collect();
            v[pos] = 0;
            corpus.push(v);
        }
        corpus.push("héllo wörld €☃ end".as_bytes().to_vec());
        let mut state: u64 = 0x0BAD_C0DE_1234_5678;
        for _ in 0..3000 {
            let len = (state % 80) as usize;
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                v.push((state >> 40) as u8);
            }
            corpus.push(v);
        }

        for &fname in names {
            for &tname in names {
                let mut probe = iconv_open(tname, fname).expect("codec");
                let from_enc = probe.from;
                let to_enc = probe.to;
                for src in &corpus {
                    for &cap in &[0usize, 1, 8, 31, 32, 33, 64, 200] {
                        let mut a = vec![0x7Eu8; cap];
                        let mut b = vec![0x7Eu8; cap];
                        let mut cd = iconv_open(tname, fname).expect("codec");
                        let ra = iconv(&mut cd, Some(src), &mut a);
                        let rb = iconv_scalar_ref(from_enc, to_enc, src, &mut b);
                        assert_eq!(
                            normalize(&ra, &a),
                            normalize(&rb, &b),
                            "iconv {fname:?}->{tname:?} mismatch on src={src:02x?} cap={cap}"
                        );
                    }
                }
                let _ = &mut probe;
            }
        }
    }

    type IconvVector<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

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
            iconv_open_detailed(b"UTF-8", b"BIG5-HKSCS").expect_err("excluded codec must fail");
        assert_eq!(err.policy, IconvFallbackPolicy::ExcludedCodecFamily);
        assert_eq!(err.dispatch.from_codec, "BIG5-HKSCS");
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
    fn iconv_open_recognizes_ws6_breadth_codecs_and_aliases() {
        for (tocode, fromcode) in [
            (b"UTF-8".as_slice(), b"KOI8-R".as_slice()),
            (b"UTF-8".as_slice(), b"KOI8-U".as_slice()),
            (b"UTF-8".as_slice(), b"KOI8-RU".as_slice()),
            (b"UTF-8".as_slice(), b"KOI8-T".as_slice()),
            (b"UTF-8".as_slice(), b"EUC-JP".as_slice()),
            (b"UTF-8".as_slice(), b"UJIS".as_slice()),
            (b"UTF-8".as_slice(), b"SHIFT_JIS".as_slice()),
            (b"UTF-8".as_slice(), b"CP932".as_slice()),
            (b"UTF-8".as_slice(), b"BIG5".as_slice()),
            (b"UTF-8".as_slice(), b"BIGFIVE".as_slice()),
        ] {
            assert!(
                iconv_open(tocode, fromcode).is_some(),
                "{} <- {} should open",
                String::from_utf8_lossy(tocode),
                String::from_utf8_lossy(fromcode)
            );
        }
    }

    #[test]
    fn ws6_breadth_codecs_convert_representative_vectors() {
        let cases: &[IconvVector<'_>] = &[
            (b"UTF-8", b"CP932", &[0xB1], "ｱ".as_bytes()),
            (b"UTF-8", b"EUC-JP", &[0x8E, 0xB1], "ｱ".as_bytes()),
            (b"UTF-8", b"BIG5", b"HK", b"HK"),
            (b"UTF-8", b"KOI8-R", &[0xC1], "а".as_bytes()),
            (b"UTF-8", b"KOI8-U", &[0xB6], "і".as_bytes()),
            (b"UTF-8", b"KOI8-RU", &[0xAD], "ґ".as_bytes()),
        ];

        for (tocode, fromcode, input, expected) in cases {
            let mut cd = iconv_open(tocode, fromcode).expect("codec pair should open");
            let mut out = [0_u8; 8];
            let result = iconv(&mut cd, Some(input), &mut out).expect("conversion should succeed");
            assert_eq!(result.in_consumed, input.len());
            assert_eq!(result.out_written, expected.len());
            assert_eq!(&out[..expected.len()], *expected);
            assert_eq!(iconv_close(cd), 0);
        }
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
    fn georgian_academy_to_utf8_round_trip() {
        // Georgian Academy: ა (0xC0), ბ (0xC1), გ (0xC2) — Georgian letters
        let input: &[u8] = &[0xC0, 0xC1, 0xC2];
        let expected_utf8 = "\u{10D0}\u{10D1}\u{10D2}";

        let mut cd = iconv_open(b"UTF-8", b"GEORGIAN-ACADEMY").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"GEORGIAN-ACADEMY", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut out).unwrap();
        assert_eq!(&out[..result2.out_written], input);
    }

    #[test]
    fn georgian_academy_differs_from_georgian_ps_in_low_range() {
        // Georgian Academy has Windows-1252-like mappings in 0x80-0x9F
        // e.g., 0x82 = U+201A (single low-9 quotation mark)
        let input: &[u8] = &[0x82];
        let mut cd = iconv_open(b"UTF-8", b"GEORGIAN-ACADEMY").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, "\u{201A}");
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
    fn rk1048_to_utf8_round_trip() {
        // RK1048: А (0xC0), Б (0xC1), В (0xC2) — Cyrillic letters
        let input: &[u8] = &[0xC0, 0xC1, 0xC2];
        let expected_utf8 = "\u{0410}\u{0411}\u{0412}";

        let mut cd = iconv_open(b"UTF-8", b"RK1048").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"RK1048", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut out).unwrap();
        assert_eq!(&out[..result2.out_written], input);
    }

    #[test]
    fn rk1048_undefined_position_returns_replacement() {
        // Position 0x98 is undefined in RK1048
        let input: &[u8] = &[0x98];
        let mut cd = iconv_open(b"UTF-8", b"RK1048").unwrap();
        let mut out = [0u8; 16];
        let result = iconv(&mut cd, Some(input), &mut out).unwrap();
        let utf8_str = std::str::from_utf8(&out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, "\u{FFFD}");
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
    fn cp851_to_utf8_round_trip() {
        // CP851: Ç (0x80), Greek alpha Α (0xA4), sigma ς (0xED)
        let cp851_input: &[u8] = &[0x80, 0xA4, 0xED];
        let expected_utf8 = "\u{00C7}\u{0391}\u{03C2}";

        let mut cd = iconv_open(b"UTF-8", b"CP851").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp851_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP851", b"UTF-8").unwrap();
        let mut cp851_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp851_out).unwrap();
        assert_eq!(&cp851_out[..result2.out_written], cp851_input);
    }

    #[test]
    fn cp851_undefined_position_returns_replacement() {
        // Position 0x91 is undefined in CP851
        let input: &[u8] = &[0x91];
        let mut cd = iconv_open(b"UTF-8", b"CP851").unwrap();
        let mut out = [0u8; 16];
        let result = iconv(&mut cd, Some(input), &mut out).unwrap();
        let utf8_str = std::str::from_utf8(&out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, "\u{FFFD}");
    }

    #[test]
    fn cp851_accepts_ibm851_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM851");
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
    fn cp1252_accepts_msansi_alias() {
        let cd = iconv_open(b"UTF-8", b"MS-ANSI");
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
    fn koi8ru_to_utf8_round_trip() {
        // KOI8-RU: glibc punctuation plus Ukrainian/Belarusian diff bytes.
        let koi8ru_input: &[u8] = &[0xA4, 0xB4, 0xAD, 0xBD, 0x93, 0x98, 0x9F];
        let expected_utf8 = "\u{0454}\u{0404}\u{0491}\u{0490}\u{201C}\u{2116}\u{00A4}";

        let mut cd = iconv_open(b"UTF-8", b"KOI8-RU").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(koi8ru_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"KOI8-RU", b"UTF-8").unwrap();
        let mut koi8ru_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut koi8ru_out).unwrap();
        assert_eq!(&koi8ru_out[..result2.out_written], koi8ru_input);
    }

    #[test]
    fn koi8ru_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"KOI8RU");
        assert!(cd.is_some());
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
    fn iso88596_accepts_cp1089_alias() {
        let cd = iconv_open(b"UTF-8", b"CP1089");
        assert!(cd.is_some());
        let cd2 = iconv_open(b"UTF-8", b"IBM1089");
        assert!(cd2.is_some());
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
    fn iso88599e_to_utf8_round_trip() {
        // ISO-8859-9E has Euro (0xA4), Ž (0xA1), ž (0xB1), ı (0xFD)
        let iso_input: &[u8] = &[0xA4, 0xA1, 0xB1, 0xFD];
        let expected_utf8 = "\u{20AC}\u{017D}\u{017E}\u{0131}";

        let mut cd = iconv_open(b"UTF-8", b"ISO-8859-9E").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(iso_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ISO-8859-9E", b"UTF-8").unwrap();
        let mut iso_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut iso_out).unwrap();
        assert_eq!(&iso_out[..result2.out_written], iso_input);
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
    fn maccyrillic_accepts_cp10007_alias() {
        let cd = iconv_open(b"UTF-8", b"CP10007");
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
    fn macturkish_to_utf8_round_trip() {
        // Mac Turkish: Ğ (0xDA), ğ (0xDB), İ (0xDC), ı (0xDD), Ş (0xDE), ş (0xDF)
        let mac_input: &[u8] = &[0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
        let expected_utf8 = "\u{011E}\u{011F}\u{0130}\u{0131}\u{015E}\u{015F}";

        let mut cd = iconv_open(b"UTF-8", b"MACTURKISH").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACTURKISH", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macturkish_accepts_xmacturkish_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-TURKISH");
        assert!(cd.is_some());
    }

    #[test]
    fn maciceland_to_utf8_round_trip() {
        // Mac Icelandic: Ð (0xDC), ð (0xDD), Þ (0xDE), þ (0xDF), Ý (0xA0), ý (0xE0)
        let mac_input: &[u8] = &[0xDC, 0xDD, 0xDE, 0xDF, 0xA0, 0xE0];
        let expected_utf8 = "\u{00D0}\u{00F0}\u{00DE}\u{00FE}\u{00DD}\u{00FD}";

        let mut cd = iconv_open(b"UTF-8", b"MACICELAND").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACICELAND", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn maciceland_accepts_xmacicelandic_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-ICELANDIC");
        assert!(cd.is_some());
    }

    #[test]
    fn maccentraleurope_to_utf8_round_trip() {
        // Mac Central Europe: Ą (0x84), ą (0x88), Č (0x89), č (0x8B), Ł (0xFC)
        let mac_input: &[u8] = &[0x84, 0x88, 0x89, 0x8B, 0xFC];
        let expected_utf8 = "\u{0104}\u{0105}\u{010C}\u{010D}\u{0141}";

        let mut cd = iconv_open(b"UTF-8", b"MACCENTRALEUROPE").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACCENTRALEUROPE", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn maccentraleurope_accepts_macce_alias() {
        let cd = iconv_open(b"UTF-8", b"MACCE");
        assert!(cd.is_some());
    }

    #[test]
    fn macukraine_to_utf8_round_trip() {
        // Mac Ukrainian: Ґ (0xA2), ґ (0xB6), І (0xA7), і (0xB4)
        let mac_input: &[u8] = &[0xA2, 0xB6, 0xA7, 0xB4];
        let expected_utf8 = "\u{0490}\u{0491}\u{0406}\u{0456}";

        let mut cd = iconv_open(b"UTF-8", b"MACUKRAINE").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACUKRAINE", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macukraine_accepts_xmacukrainian_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-UKRAINIAN");
        assert!(cd.is_some());
    }

    #[test]
    fn cp858_euro_at_d5() {
        // CP858 has Euro (€) at 0xD5 instead of dotless i (ı)
        let cp858_input: &[u8] = &[0xD5];
        let expected_utf8 = "\u{20AC}";

        let mut cd = iconv_open(b"UTF-8", b"CP858").unwrap();
        let mut utf8_out = [0u8; 8];
        let result = iconv(&mut cd, Some(cp858_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP858", b"UTF-8").unwrap();
        let mut cp858_out = [0u8; 8];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp858_out).unwrap();
        assert_eq!(&cp858_out[..result2.out_written], cp858_input);
    }

    #[test]
    fn cp858_accepts_ibm858_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM858");
        assert!(cd.is_some());
    }

    #[test]
    fn macromanian_to_utf8_round_trip() {
        // Mac Romanian: Ș (0xAF), ș (0xBF), Ț (0xDC), ț (0xDD)
        let mac_input: &[u8] = &[0xAF, 0xBF, 0xDC, 0xDD];
        let expected_utf8 = "\u{0218}\u{0219}\u{021A}\u{021B}";

        let mut cd = iconv_open(b"UTF-8", b"MACROMANIA").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACROMANIA", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macromanian_accepts_xmacromanian_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-ROMANIAN");
        assert!(cd.is_some());
    }

    #[test]
    fn macsami_to_utf8_round_trip() {
        // Mac Sami: Đ (0xB0), Ŋ (0xB1), Š (0xB4), Ŧ (0xB5), Ʒ (0xF6), ʒ (0xF7)
        let mac_input: &[u8] = &[0xB0, 0xB1, 0xB4, 0xB5, 0xF6, 0xF7];
        let expected_utf8 = "\u{0110}\u{014A}\u{0160}\u{0166}\u{01B7}\u{0292}";

        let mut cd = iconv_open(b"UTF-8", b"MAC-SAMI").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MAC-SAMI", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macsami_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"MACSAMI");
        assert!(cd.is_some());
    }

    #[test]
    fn maccroatian_to_utf8_round_trip() {
        // Mac Croatian: Š (0xA9), š (0xB9), Ž (0xAE), ž (0xBE), Đ (0xD0), đ (0xDC)
        let mac_input: &[u8] = &[0xA9, 0xB9, 0xAE, 0xBE, 0xD0, 0xDC];
        let expected_utf8 = "\u{0160}\u{0161}\u{017D}\u{017E}\u{0110}\u{0111}";

        let mut cd = iconv_open(b"UTF-8", b"MACCROATIAN").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACCROATIAN", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn maccroatian_accepts_xmaccroatian_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-CROATIAN");
        assert!(cd.is_some());
    }

    #[test]
    fn cp720_to_utf8_round_trip() {
        // CP720 (DOS Arabic): ب (0xA0), ت (0xA2), ل (0xE9), م (0xEA)
        let cp720_input: &[u8] = &[0xA0, 0xA2, 0xE9, 0xEA];
        let expected_utf8 = "\u{0628}\u{062A}\u{0644}\u{0645}";

        let mut cd = iconv_open(b"UTF-8", b"CP720").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp720_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP720", b"UTF-8").unwrap();
        let mut cp720_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp720_out).unwrap();
        assert_eq!(&cp720_out[..result2.out_written], cp720_input);
    }

    #[test]
    fn cp720_accepts_ibm720_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM720");
        assert!(cd.is_some());
    }

    #[test]
    fn machebrew_to_utf8_round_trip() {
        // MacHebrew: Alef (0xE0), Bet (0xE1), Yod (0xE9), Shin (0xF9)
        let mac_input: &[u8] = &[0xE0, 0xE1, 0xE9, 0xF9];
        let expected_utf8 = "\u{05D0}\u{05D1}\u{05D9}\u{05E9}";

        let mut cd = iconv_open(b"UTF-8", b"MACHEBREW").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACHEBREW", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn machebrew_accepts_xmachebrew_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-HEBREW");
        assert!(cd.is_some());
    }

    #[test]
    fn macarabic_to_utf8_round_trip() {
        // MacArabic: Alef (0xC7), Ba (0xC8), Fa (0xE1), Lam (0xE4)
        let mac_input: &[u8] = &[0xC7, 0xC8, 0xE1, 0xE4];
        let expected_utf8 = "\u{0627}\u{0628}\u{0641}\u{0644}";

        let mut cd = iconv_open(b"UTF-8", b"MACARABIC").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACARABIC", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macarabic_accepts_xmacarabic_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-ARABIC");
        assert!(cd.is_some());
    }

    #[test]
    fn macthai_to_utf8_round_trip() {
        // MacThai: Ko Kai (0xA1), Kho Khai (0xA2), Thai digit 0 (0xF0), Thai digit 1 (0xF1)
        let mac_input: &[u8] = &[0xA1, 0xA2, 0xF0, 0xF1];
        let expected_utf8 = "\u{0E01}\u{0E02}\u{0E50}\u{0E51}";

        let mut cd = iconv_open(b"UTF-8", b"MACTHAI").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACTHAI", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macthai_accepts_xmacthai_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-THAI");
        assert!(cd.is_some());
    }

    #[test]
    fn macfarsi_to_utf8_round_trip() {
        // MacFarsi: Alef (0xC7), Persian Kaf (0xE3), Persian Yeh (0xEA), Gaf (0xF8)
        let mac_input: &[u8] = &[0xC7, 0xE3, 0xEA, 0xF8];
        let expected_utf8 = "\u{0627}\u{06A9}\u{06CC}\u{06AF}";

        let mut cd = iconv_open(b"UTF-8", b"MACFARSI").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACFARSI", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macfarsi_accepts_xmacfarsi_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-FARSI");
        assert!(cd.is_some());
    }

    #[test]
    fn macdevanagari_to_utf8_round_trip() {
        // MacDevanagari: A (0x84), Ka (0x93), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x84, 0x93, 0xE0, 0xE1];
        let expected_utf8 = "\u{0905}\u{0915}\u{0966}\u{0967}";

        let mut cd = iconv_open(b"UTF-8", b"MACDEVANAGARI").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACDEVANAGARI", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macdevanagari_accepts_xmacdevanagari_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-DEVANAGARI");
        assert!(cd.is_some());
    }

    #[test]
    fn macgurmukhi_to_utf8_round_trip() {
        // MacGurmukhi: A (0x84), Ka (0x93), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x84, 0x93, 0xE0, 0xE1];
        let expected_utf8 = "\u{0A05}\u{0A15}\u{0A66}\u{0A67}";

        let mut cd = iconv_open(b"UTF-8", b"MACGURMUKHI").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACGURMUKHI", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macgurmukhi_accepts_xmacgurmukhi_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-GURMUKHI");
        assert!(cd.is_some());
    }

    #[test]
    fn macgujarati_to_utf8_round_trip() {
        // MacGujarati: A (0x84), Ka (0x93), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x84, 0x93, 0xE0, 0xE1];
        let expected_utf8 = "\u{0A85}\u{0A95}\u{0AE6}\u{0AE7}";

        let mut cd = iconv_open(b"UTF-8", b"MACGUJARATI").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACGUJARATI", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macgujarati_accepts_xmacgujarati_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-GUJARATI");
        assert!(cd.is_some());
    }

    #[test]
    fn mackannada_to_utf8_round_trip() {
        // MacKannada: A (0x85), Ka (0x95), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x85, 0x95, 0xE0, 0xE1];
        let expected_utf8 = "\u{0C85}\u{0C95}\u{0CE6}\u{0CE7}";

        let mut cd = iconv_open(b"UTF-8", b"MACKANNADA").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACKANNADA", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn mackannada_accepts_xmackannada_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-KANNADA");
        assert!(cd.is_some());
    }

    #[test]
    fn mactelugu_to_utf8_round_trip() {
        // MacTelugu: A (0x85), Ka (0x95), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x85, 0x95, 0xE0, 0xE1];
        let expected_utf8 = "\u{0C05}\u{0C15}\u{0C66}\u{0C67}";

        let mut cd = iconv_open(b"UTF-8", b"MACTELUGU").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACTELUGU", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn mactelugu_accepts_xmactelugu_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-TELUGU");
        assert!(cd.is_some());
    }

    #[test]
    fn macoriya_to_utf8_round_trip() {
        // MacOriya: A (0x85), Ka (0x95), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x85, 0x95, 0xE0, 0xE1];
        let expected_utf8 = "\u{0B05}\u{0B15}\u{0B66}\u{0B67}";

        let mut cd = iconv_open(b"UTF-8", b"MACORIYA").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACORIYA", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macoriya_accepts_xmacoriya_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-ORIYA");
        assert!(cd.is_some());
    }

    #[test]
    fn macbengali_to_utf8_round_trip() {
        // MacBengali: A (0x85), Ka (0x95), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x85, 0x95, 0xE0, 0xE1];
        let expected_utf8 = "\u{0985}\u{0995}\u{09E6}\u{09E7}";

        let mut cd = iconv_open(b"UTF-8", b"MACBENGALI").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACBENGALI", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macbengali_accepts_xmacbengali_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-BENGALI");
        assert!(cd.is_some());
    }

    #[test]
    fn macmalayalam_to_utf8_round_trip() {
        // MacMalayalam: A (0x85), Ka (0x95), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x85, 0x95, 0xE0, 0xE1];
        let expected_utf8 = "\u{0D05}\u{0D15}\u{0D66}\u{0D67}";

        let mut cd = iconv_open(b"UTF-8", b"MACMALAYALAM").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACMALAYALAM", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn macmalayalam_accepts_xmacmalayalam_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-MALAYALAM");
        assert!(cd.is_some());
    }

    #[test]
    fn mactamil_to_utf8_round_trip() {
        // MacTamil: A (0x85), Ka (0x95), digit 0 (0xE0), digit 1 (0xE1)
        let mac_input: &[u8] = &[0x85, 0x95, 0xE0, 0xE1];
        let expected_utf8 = "\u{0B85}\u{0B95}\u{0BE6}\u{0BE7}";

        let mut cd = iconv_open(b"UTF-8", b"MACTAMIL").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mac_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"MACTAMIL", b"UTF-8").unwrap();
        let mut mac_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mac_out).unwrap();
        assert_eq!(&mac_out[..result2.out_written], mac_input);
    }

    #[test]
    fn mactamil_accepts_xmactamil_alias() {
        let cd = iconv_open(b"UTF-8", b"X-MAC-TAMIL");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1006_to_utf8_round_trip() {
        // CP1006: digit 0 (0x80), digit 1 (0x81), Alef (0x8E), Beh (0x8F)
        let cp_input: &[u8] = &[0x80, 0x81, 0x8E, 0x8F];
        let expected_utf8 = "\u{06F0}\u{06F1}\u{0627}\u{0628}";

        let mut cd = iconv_open(b"UTF-8", b"CP1006").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1006", b"UTF-8").unwrap();
        let mut cp_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp_out).unwrap();
        assert_eq!(&cp_out[..result2.out_written], cp_input);
    }

    #[test]
    fn cp1006_accepts_ibm1006_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1006");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1008_to_utf8_round_trip() {
        // CP1008: Arabic-Indic digits 0-2 (0xB0-0xB2)
        let input: &[u8] = &[0xB0, 0xB1, 0xB2];
        let expected_utf8 = "\u{0660}\u{0661}\u{0662}";

        let mut cd = iconv_open(b"UTF-8", b"CP1008").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1008", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut out).unwrap();
        assert_eq!(&out[..result2.out_written], input);
    }

    #[test]
    fn cp1008_accepts_ibm1008_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1008");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1046_to_utf8_round_trip() {
        // CP1046: Arabic-Indic digits 0-2 (0xB0-0xB2)
        let input: &[u8] = &[0xB0, 0xB1, 0xB2];
        let expected_utf8 = "\u{0660}\u{0661}\u{0662}";

        let mut cd = iconv_open(b"UTF-8", b"CP1046").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1046", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut out).unwrap();
        assert_eq!(&out[..result2.out_written], input);
    }

    #[test]
    fn cp1046_accepts_ibm1046_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1046");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1124_to_utf8_round_trip() {
        // CP1124: Cyrillic А (0xB0), Б (0xB1), В (0xB2)
        let input: &[u8] = &[0xB0, 0xB1, 0xB2];
        let expected_utf8 = "\u{0410}\u{0411}\u{0412}";

        let mut cd = iconv_open(b"UTF-8", b"CP1124").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1124", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut out).unwrap();
        assert_eq!(&out[..result2.out_written], input);
    }

    #[test]
    fn cp1124_accepts_ibm1124_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1124");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1129_to_utf8_round_trip() {
        // CP1129: Vietnamese Đ (0xD0), đ (0xF0), dong sign ₫ (0xFE)
        let input: &[u8] = &[0xD0, 0xF0, 0xFE];
        let expected_utf8 = "\u{0110}\u{0111}\u{20AB}";

        let mut cd = iconv_open(b"UTF-8", b"CP1129").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1129", b"UTF-8").unwrap();
        let mut out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut out).unwrap();
        assert_eq!(&out[..result2.out_written], input);
    }

    #[test]
    fn cp1129_accepts_ibm1129_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1129");
        assert!(cd.is_some());
    }

    #[test]
    fn cp856_to_utf8_round_trip() {
        // CP856: Alef (0x80), Bet (0x81), Gimel (0x82), Dalet (0x83)
        let cp_input: &[u8] = &[0x80, 0x81, 0x82, 0x83];
        let expected_utf8 = "\u{05D0}\u{05D1}\u{05D2}\u{05D3}";

        let mut cd = iconv_open(b"UTF-8", b"CP856").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP856", b"UTF-8").unwrap();
        let mut cp_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp_out).unwrap();
        assert_eq!(&cp_out[..result2.out_written], cp_input);
    }

    #[test]
    fn cp856_accepts_ibm856_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM856");
        assert!(cd.is_some());

        let numeric = iconv_open(b"UTF-8", b"856");
        assert!(numeric.is_some());
    }

    #[test]
    fn cp856_rejects_undefined_bytes() {
        let mut cd = iconv_open(b"UTF-8", b"CP856").unwrap();
        let mut utf8_out = [0u8; 8];
        let err = iconv(&mut cd, Some(&[0x9B]), &mut utf8_out).unwrap_err();
        assert_eq!(err.code, ICONV_EILSEQ);
        assert_eq!(err.in_consumed, 0);
        assert_eq!(err.out_written, 0);
    }

    #[test]
    fn cp1125_to_utf8_round_trip() {
        // CP1125: Cyrillic letters plus the glibc Ukrainian tail.
        let cp_input: &[u8] = &[0x80, 0x81, 0xA0, 0xA1, 0xF0, 0xF1, 0xFC, 0xFD];
        let expected_utf8 = "\u{0410}\u{0411}\u{0430}\u{0431}\u{0401}\u{0451}\u{2116}\u{00A4}";

        let mut cd = iconv_open(b"UTF-8", b"CP1125").unwrap();
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1125", b"UTF-8").unwrap();
        let mut cp_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp_out).unwrap();
        assert_eq!(&cp_out[..result2.out_written], cp_input);
    }

    #[test]
    fn cp1125_rejects_unlisted_aliases() {
        assert!(iconv_open(b"UTF-8", b"IBM1125").is_none());
        assert!(iconv_open(b"UTF-8", b"1125").is_none());
    }

    #[test]
    fn cp1131_rejects_unlisted_encoding() {
        assert!(iconv_open(b"UTF-8", b"CP1131").is_none());
        assert!(iconv_open(b"UTF-8", b"IBM1131").is_none());
        assert!(iconv_open(b"UTF-8", b"1131").is_none());
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

    #[test]
    fn cp1133_lao_round_trip() {
        // CP1133 is IBM Lao encoding
        // 0xA1 = U+0E81 (Lao letter KO), 0xF0 = U+0ED0 (Lao digit zero)
        let cp1133_input: &[u8] = &[0xA1, 0xF0];
        let expected_utf8 = "\u{0E81}\u{0ED0}";

        let mut cd = iconv_open(b"UTF-8", b"CP1133").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1133_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1133", b"UTF-8").unwrap();
        let mut cp1133_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1133_out).unwrap();
        assert_eq!(&cp1133_out[..result2.out_written], cp1133_input);
    }

    #[test]
    fn cp1133_accepts_ibm1133_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1133");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1133_undefined_byte_returns_error() {
        // 0xA0 is undefined in CP1133
        let cp1133_input: &[u8] = &[0xA0];
        let mut cd = iconv_open(b"UTF-8", b"CP1133").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1133_input), &mut utf8_out);
        assert!(result.is_err());
    }

    #[test]
    fn cp774_lithuanian_round_trip() {
        // CP774 is Lithuanian ISO encoding
        // 0xB5 = U+0104 (Latin capital A with ogonek), 0xD0 = U+0105 (Latin small a with ogonek)
        let cp774_input: &[u8] = &[0xB5, 0xD0];
        let expected_utf8 = "\u{0104}\u{0105}";

        let mut cd = iconv_open(b"UTF-8", b"CP774").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp774_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP774", b"UTF-8").unwrap();
        let mut cp774_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp774_out).unwrap();
        assert_eq!(&cp774_out[..result2.out_written], cp774_input);
    }

    #[test]
    fn cp774_accepts_ibm774_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM774");
        assert!(cd.is_some());
    }

    #[test]
    fn cp770_baltic_round_trip() {
        // CP770 is Baltic encoding
        // 0x80 = U+010C (Latin capital C with caron), 0x87 = U+010D (Latin small c with caron)
        let cp770_input: &[u8] = &[0x80, 0x87];
        let expected_utf8 = "\u{010C}\u{010D}";

        let mut cd = iconv_open(b"UTF-8", b"CP770").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp770_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP770", b"UTF-8").unwrap();
        let mut cp770_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp770_out).unwrap();
        assert_eq!(&cp770_out[..result2.out_written], cp770_input);
    }

    #[test]
    fn cp770_accepts_ibm770_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM770");
        assert!(cd.is_some());
    }

    #[test]
    fn cp773_baltic_polish_round_trip() {
        // CP773 is Baltic/Polish encoding
        // 0x80 = U+0106 (Latin capital C with acute), 0x87 = U+0107 (Latin small c with acute)
        let cp773_input: &[u8] = &[0x80, 0x87];
        let expected_utf8 = "\u{0106}\u{0107}";

        let mut cd = iconv_open(b"UTF-8", b"CP773").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp773_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP773", b"UTF-8").unwrap();
        let mut cp773_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp773_out).unwrap();
        assert_eq!(&cp773_out[..result2.out_written], cp773_input);
    }

    #[test]
    fn cp773_accepts_ibm773_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM773");
        assert!(cd.is_some());
    }

    #[test]
    fn cp771_cyrillic_round_trip() {
        // CP771 is KOI-8 Lithuanian/Cyrillic encoding
        // 0x80 = U+0410 (Cyrillic capital A), 0xA0 = U+0430 (Cyrillic small a)
        let cp771_input: &[u8] = &[0x80, 0xA0];
        let expected_utf8 = "\u{0410}\u{0430}";

        let mut cd = iconv_open(b"UTF-8", b"CP771").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp771_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP771", b"UTF-8").unwrap();
        let mut cp771_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp771_out).unwrap();
        assert_eq!(&cp771_out[..result2.out_written], cp771_input);
    }

    #[test]
    fn cp771_accepts_ibm771_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM771");
        assert!(cd.is_some());
    }

    #[test]
    fn cp772_cyrillic_round_trip() {
        // CP772 is Lithuanian Cyrillic encoding
        // 0x80 = U+0410 (Cyrillic capital A), 0xF0 = U+0401 (Cyrillic capital IO)
        let cp772_input: &[u8] = &[0x80, 0xF0];
        let expected_utf8 = "\u{0410}\u{0401}";

        let mut cd = iconv_open(b"UTF-8", b"CP772").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp772_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP772", b"UTF-8").unwrap();
        let mut cp772_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp772_out).unwrap();
        assert_eq!(&cp772_out[..result2.out_written], cp772_input);
    }

    #[test]
    fn cp772_accepts_ibm772_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM772");
        assert!(cd.is_some());
    }

    #[test]
    fn cp868_urdu_round_trip() {
        // CP868 is Urdu/Arabic encoding
        // 0x80 = U+0660 (Arabic-Indic digit 0), 0x81 = U+0661 (Arabic-Indic digit 1)
        let cp868_input: &[u8] = &[0x80, 0x81];
        let expected_utf8 = "\u{0660}\u{0661}";

        let mut cd = iconv_open(b"UTF-8", b"CP868").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp868_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP868", b"UTF-8").unwrap();
        let mut cp868_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp868_out).unwrap();
        assert_eq!(&cp868_out[..result2.out_written], cp868_input);
    }

    #[test]
    fn cp868_accepts_ibm868_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM868");
        assert!(cd.is_some());
    }

    #[test]
    fn cp868_undefined_byte_returns_error() {
        // 0x94 is undefined in CP868
        let cp868_input: &[u8] = &[0x94];
        let mut cd = iconv_open(b"UTF-8", b"CP868").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp868_input), &mut utf8_out);
        assert!(result.is_err());
    }

    #[test]
    fn cp813_greek_round_trip() {
        // CP813 is Greek ISO encoding
        // 0xC1 = U+0391 (Greek capital Alpha), 0xE1 = U+03B1 (Greek small alpha)
        let cp813_input: &[u8] = &[0xC1, 0xE1];
        let expected_utf8 = "\u{0391}\u{03B1}";

        let mut cd = iconv_open(b"UTF-8", b"CP813").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp813_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP813", b"UTF-8").unwrap();
        let mut cp813_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp813_out).unwrap();
        assert_eq!(&cp813_out[..result2.out_written], cp813_input);
    }

    #[test]
    fn cp813_accepts_ibm813_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM813");
        assert!(cd.is_some());
    }

    #[test]
    fn cp916_hebrew_round_trip() {
        // CP916 is Hebrew ISO encoding
        // 0xE0 = U+05D0 (Hebrew letter Alef), 0xE1 = U+05D1 (Hebrew letter Bet)
        let cp916_input: &[u8] = &[0xE0, 0xE1];
        let expected_utf8 = "\u{05D0}\u{05D1}";

        let mut cd = iconv_open(b"UTF-8", b"CP916").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp916_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP916", b"UTF-8").unwrap();
        let mut cp916_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp916_out).unwrap();
        assert_eq!(&cp916_out[..result2.out_written], cp916_input);
    }

    #[test]
    fn cp916_accepts_ibm916_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM916");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88592_accepts_cp912_alias() {
        let cd = iconv_open(b"UTF-8", b"CP912");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88593_accepts_cp913_alias() {
        let cd = iconv_open(b"UTF-8", b"CP913");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88594_accepts_cp914_alias() {
        let cd = iconv_open(b"UTF-8", b"CP914");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88595_accepts_cp915_alias() {
        let cd = iconv_open(b"UTF-8", b"CP915");
        assert!(cd.is_some());
    }

    #[test]
    fn iso88599_accepts_cp920_alias() {
        let cd = iconv_open(b"UTF-8", b"CP920");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1161_thai_round_trip() {
        // CP1161 is Thai encoding
        // 0xA1 = U+0E01 (Thai character KO KAI), 0xF0 = U+0E50 (Thai digit zero)
        let cp1161_input: &[u8] = &[0xA1, 0xF0];
        let expected_utf8 = "\u{0E01}\u{0E50}";

        let mut cd = iconv_open(b"UTF-8", b"CP1161").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1161_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1161", b"UTF-8").unwrap();
        let mut cp1161_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1161_out).unwrap();
        assert_eq!(&cp1161_out[..result2.out_written], cp1161_input);
    }

    #[test]
    fn cp1161_accepts_ibm1161_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1161");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1162_thai_windows_round_trip() {
        // CP1162 is Thai Windows encoding
        // 0xA1 = U+0E01 (Thai character KO KAI), 0x80 = U+20AC (Euro sign)
        let cp1162_input: &[u8] = &[0xA1, 0x80];
        let expected_utf8 = "\u{0E01}\u{20AC}";

        let mut cd = iconv_open(b"UTF-8", b"CP1162").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1162_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1162", b"UTF-8").unwrap();
        let mut cp1162_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1162_out).unwrap();
        assert_eq!(&cp1162_out[..result2.out_written], cp1162_input);
    }

    #[test]
    fn cp1162_accepts_ibm1162_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1162");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1163_vietnamese_round_trip() {
        // CP1163 is Vietnamese encoding
        // 0xD0 = U+0110 (Latin capital D with stroke), 0xF0 = U+0111 (Latin small d with stroke)
        let cp1163_input: &[u8] = &[0xD0, 0xF0];
        let expected_utf8 = "\u{0110}\u{0111}";

        let mut cd = iconv_open(b"UTF-8", b"CP1163").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(cp1163_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"CP1163", b"UTF-8").unwrap();
        let mut cp1163_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1163_out).unwrap();
        assert_eq!(&cp1163_out[..result2.out_written], cp1163_input);
    }

    #[test]
    fn cp1163_accepts_ibm1163_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM1163");
        assert!(cd.is_some());
    }

    #[test]
    fn isiri3342_persian_round_trip() {
        // ISIRI-3342 is Persian encoding
        // 0xB0 = U+06F0 (Extended Arabic digit 0), 0xC0 = U+0622 (Arabic letter Alef with Madda)
        let isiri_input: &[u8] = &[0xB0, 0xC0];
        let expected_utf8 = "\u{06F0}\u{0622}";

        let mut cd = iconv_open(b"UTF-8", b"ISIRI-3342").unwrap();
        let mut utf8_out = [0u8; 16];
        let result = iconv(&mut cd, Some(isiri_input), &mut utf8_out).unwrap();
        let utf8_str = std::str::from_utf8(&utf8_out[..result.out_written]).unwrap();
        assert_eq!(utf8_str, expected_utf8);

        let mut cd2 = iconv_open(b"ISIRI-3342", b"UTF-8").unwrap();
        let mut isiri_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut isiri_out).unwrap();
        assert_eq!(&isiri_out[..result2.out_written], isiri_input);
    }

    #[test]
    fn isiri3342_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"ISIRI3342");
        assert!(cd.is_some());
    }

    #[test]
    fn mik_decode_roundtrip() {
        let mik_input: &[u8] = &[0x80, 0x81, 0xA0, 0xA1, 0xC0, 0xE0];
        let expected_utf8 = "АБаб└Γ";
        let mut cd = iconv_open(b"UTF-8", b"MIK").expect("MIK to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(mik_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"MIK", b"UTF-8").expect("UTF-8 to MIK conversion");
        let mut mik_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut mik_out).unwrap();
        assert_eq!(&mik_out[..result2.out_written], mik_input);
    }

    #[test]
    fn koi8t_decode_roundtrip() {
        let koi8t_input: &[u8] = &[0xC1, 0xC2, 0xE1, 0xE2];
        let expected_utf8 = "абАБ";
        let mut cd = iconv_open(b"UTF-8", b"KOI8-T").expect("KOI8-T to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(koi8t_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"KOI8-T", b"UTF-8").expect("UTF-8 to KOI8-T conversion");
        let mut koi8t_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut koi8t_out).unwrap();
        assert_eq!(&koi8t_out[..result2.out_written], koi8t_input);
    }

    #[test]
    fn koi8t_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"KOI8T");
        assert!(cd.is_some());
    }

    #[test]
    fn cp866nav_decode_roundtrip() {
        let cp866nav_input: &[u8] = &[0x80, 0x81, 0xA0, 0xA1, 0xE0, 0xE1];
        let expected_utf8 = "АБабрс";
        let mut cd = iconv_open(b"UTF-8", b"CP866NAV").expect("CP866NAV to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp866nav_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"CP866NAV", b"UTF-8").expect("UTF-8 to CP866NAV conversion");
        let mut cp866nav_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp866nav_out).unwrap();
        assert_eq!(&cp866nav_out[..result2.out_written], cp866nav_input);
    }

    #[test]
    fn decmcs_decode_roundtrip() {
        let decmcs_input: &[u8] = &[0xC0, 0xC1, 0xE0, 0xE1, 0xD7, 0xF7];
        let expected_utf8 = "ÀÁàáŒœ";
        let mut cd = iconv_open(b"UTF-8", b"DEC-MCS").expect("DEC-MCS to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(decmcs_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"DEC-MCS", b"UTF-8").expect("UTF-8 to DEC-MCS conversion");
        let mut decmcs_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut decmcs_out).unwrap();
        assert_eq!(&decmcs_out[..result2.out_written], decmcs_input);
    }

    #[test]
    fn decmcs_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"DECMCS");
        assert!(cd.is_some());
    }

    #[test]
    fn hproman9_decode_roundtrip() {
        let hproman9_input: &[u8] = &[0xA1, 0xA2, 0xEB, 0xEC];
        let expected_utf8 = "ÀÂŠš";
        let mut cd = iconv_open(b"UTF-8", b"HP-ROMAN9").expect("HP-ROMAN9 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(hproman9_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"HP-ROMAN9", b"UTF-8").expect("UTF-8 to HP-ROMAN9 conversion");
        let mut hproman9_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut hproman9_out).unwrap();
        assert_eq!(&hproman9_out[..result2.out_written], hproman9_input);
    }

    #[test]
    fn hproman9_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"HPROMAN9");
        assert!(cd.is_some());
    }

    #[test]
    fn hpgreek8_decode_roundtrip() {
        let hpgreek8_input: &[u8] = &[0xC1, 0xC2, 0xE1, 0xE2];
        let expected_utf8 = "ΑΒαβ";
        let mut cd = iconv_open(b"UTF-8", b"HP-GREEK8").expect("HP-GREEK8 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(hpgreek8_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"HP-GREEK8", b"UTF-8").expect("UTF-8 to HP-GREEK8 conversion");
        let mut hpgreek8_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut hpgreek8_out).unwrap();
        assert_eq!(&hpgreek8_out[..result2.out_written], hpgreek8_input);
    }

    #[test]
    fn hpgreek8_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"HPGREEK8");
        assert!(cd.is_some());
    }

    #[test]
    fn hpthai8_decode_roundtrip() {
        let hpthai8_input: &[u8] = &[0xA1, 0xA2, 0xF0, 0xF1];
        let expected_utf8 = "กข๐๑";
        let mut cd = iconv_open(b"UTF-8", b"HP-THAI8").expect("HP-THAI8 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(hpthai8_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"HP-THAI8", b"UTF-8").expect("UTF-8 to HP-THAI8 conversion");
        let mut hpthai8_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut hpthai8_out).unwrap();
        assert_eq!(&hpthai8_out[..result2.out_written], hpthai8_input);
    }

    #[test]
    fn hpthai8_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"HPTHAI8");
        assert!(cd.is_some());
    }

    #[test]
    fn hpturkish8_decode_roundtrip() {
        let hpturkish8_input: &[u8] = &[0xA2, 0xE0, 0xDB, 0xFB];
        let expected_utf8 = "Ğğİı";
        let mut cd = iconv_open(b"UTF-8", b"HP-TURKISH8").expect("HP-TURKISH8 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(hpturkish8_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 =
            iconv_open(b"HP-TURKISH8", b"UTF-8").expect("UTF-8 to HP-TURKISH8 conversion");
        let mut hpturkish8_out = [0u8; 16];
        let result2 = iconv(
            &mut cd2,
            Some(expected_utf8.as_bytes()),
            &mut hpturkish8_out,
        )
        .unwrap();
        assert_eq!(&hpturkish8_out[..result2.out_written], hpturkish8_input);
    }

    #[test]
    fn hpturkish8_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"HPTURKISH8");
        assert!(cd.is_some());
    }

    #[test]
    fn cp1004_decode_roundtrip() {
        let cp1004_input: &[u8] = &[0xC0, 0xC1, 0xE0, 0xE1];
        let expected_utf8 = "ÀÁàá";
        let mut cd = iconv_open(b"UTF-8", b"CP1004").expect("CP1004 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cp1004_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"CP1004", b"UTF-8").expect("UTF-8 to CP1004 conversion");
        let mut cp1004_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cp1004_out).unwrap();
        assert_eq!(&cp1004_out[..result2.out_written], cp1004_input);
    }

    #[test]
    fn cp1004_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"1004");
        assert!(cd.is_some());
    }

    #[test]
    fn ibm1167_decode_roundtrip() {
        let ibm1167_input: &[u8] = &[0xC1, 0xC2, 0xE1, 0xE2];
        let expected_utf8 = "абАБ";
        let mut cd = iconv_open(b"UTF-8", b"IBM-1167").expect("IBM-1167 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(ibm1167_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"IBM-1167", b"UTF-8").expect("UTF-8 to IBM-1167 conversion");
        let mut ibm1167_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut ibm1167_out).unwrap();
        assert_eq!(&ibm1167_out[..result2.out_written], ibm1167_input);
    }

    #[test]
    fn ibm1167_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"KOI8RU");
        assert!(cd.is_some());
    }

    #[test]
    fn cwi_decode_roundtrip() {
        let cwi_input: &[u8] = &[0x93, 0x96, 0xA7, 0x98];
        let expected_utf8 = "őűŐŰ";
        let mut cd = iconv_open(b"UTF-8", b"CWI").expect("CWI to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(cwi_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"CWI", b"UTF-8").expect("UTF-8 to CWI conversion");
        let mut cwi_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut cwi_out).unwrap();
        assert_eq!(&cwi_out[..result2.out_written], cwi_input);
    }

    #[test]
    fn cwi_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"CWI2");
        assert!(cd.is_some());
    }

    #[test]
    fn strk10482002_decode_roundtrip() {
        let strk_input: &[u8] = &[0xC0, 0xC1, 0xE0, 0xE1];
        let expected_utf8 = "АБаб";
        let mut cd =
            iconv_open(b"UTF-8", b"STRK1048-2002").expect("STRK1048-2002 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(strk_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 =
            iconv_open(b"STRK1048-2002", b"UTF-8").expect("UTF-8 to STRK1048-2002 conversion");
        let mut strk_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut strk_out).unwrap();
        assert_eq!(&strk_out[..result2.out_written], strk_input);
    }

    #[test]
    fn strk10482002_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"RK1048");
        assert!(cd.is_some());
    }

    #[test]
    fn csn369103_decode_roundtrip() {
        let csn_input: &[u8] = &[0xC1, 0xC9, 0xE1, 0xE9];
        let expected_utf8 = "ÁÉáé";
        let mut cd = iconv_open(b"UTF-8", b"CSN_369103").expect("CSN_369103 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(csn_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"CSN_369103", b"UTF-8").expect("UTF-8 to CSN_369103 conversion");
        let mut csn_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut csn_out).unwrap();
        assert_eq!(&csn_out[..result2.out_written], csn_input);
    }

    #[test]
    fn csn369103_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"CSN369103");
        assert!(cd.is_some());
    }

    #[test]
    fn ibm902_decode_roundtrip() {
        let ibm902_input: &[u8] = &[0xD0, 0xDE, 0xF0, 0xFE, 0xA4];
        let expected_utf8 = "ŠŽšž€";
        let mut cd = iconv_open(b"UTF-8", b"IBM-902").expect("IBM-902 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(ibm902_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"IBM-902", b"UTF-8").expect("UTF-8 to IBM-902 conversion");
        let mut ibm902_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut ibm902_out).unwrap();
        assert_eq!(&ibm902_out[..result2.out_written], ibm902_input);
    }

    #[test]
    fn ibm902_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM902");
        assert!(cd.is_some());
    }

    #[test]
    fn ibm901_decode_roundtrip() {
        let ibm901_input: &[u8] = &[0xC0, 0xC1, 0xE0, 0xE1, 0xA4];
        let expected_utf8 = "ĄĮąį€";
        let mut cd = iconv_open(b"UTF-8", b"IBM-901").expect("IBM-901 to UTF-8 conversion");
        let mut utf8_out = [0u8; 32];
        let result = iconv(&mut cd, Some(ibm901_input), &mut utf8_out).unwrap();
        assert_eq!(&utf8_out[..result.out_written], expected_utf8.as_bytes());
        let mut cd2 = iconv_open(b"IBM-901", b"UTF-8").expect("UTF-8 to IBM-901 conversion");
        let mut ibm901_out = [0u8; 16];
        let result2 = iconv(&mut cd2, Some(expected_utf8.as_bytes()), &mut ibm901_out).unwrap();
        assert_eq!(&ibm901_out[..result2.out_written], ibm901_input);
    }

    #[test]
    fn ibm901_accepts_alias() {
        let cd = iconv_open(b"UTF-8", b"IBM901");
        assert!(cd.is_some());
    }
}
