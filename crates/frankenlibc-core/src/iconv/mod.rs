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
    Latin1,
    Utf16Le,
    Utf32,
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

const PHASE1_CODEC_TABLE: [CodecSpec; 4] = [
    CodecSpec {
        encoding: Encoding::Utf8,
        canonical: "UTF-8",
        normalized: "UTF8",
        // ASCII / US-ASCII / ANSI_X3.4-1968 / ISO646-US are all 7-bit
        // codecs whose byte set is a strict subset of UTF-8. Aliasing them
        // to UTF-8 means ASCII→UTF-8 passes through identically, and
        // UTF-8→ASCII passes through any UTF-8-valid byte (including
        // multi-byte sequences). The latter is more permissive than glibc's
        // strict ASCII codec, which rejects non-ASCII with EILSEQ — that
        // remains a parity gap (bd-b60b5d) until we implement a dedicated
        // ASCII codec with proper rejection.
        aliases: &["UTF8", "ASCII", "USASCII", "ANSIX341968", "ISO646US"],
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
pub const ICONV_PHASE1_INCLUDED_CODECS: [&str; 4] = ["UTF-8", "ISO-8859-1", "UTF-16LE", "UTF-32"];

/// Canonical alias map for phase-1 supported codecs.
pub const ICONV_PHASE1_ALIAS_NORMALIZATIONS: [(&str, &str); 1] = [("LATIN1", "ISO-8859-1")];

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

fn decode_char(enc: Encoding, input: &[u8]) -> Result<(char, usize), DecodeError> {
    match enc {
        Encoding::Utf8 => decode_utf8(input),
        Encoding::Latin1 => {
            if input.is_empty() {
                Err(DecodeError::Incomplete)
            } else {
                Ok((char::from(input[0]), 1))
            }
        }
        Encoding::Utf16Le => decode_utf16le(input),
        Encoding::Utf32 => decode_utf32(input),
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
}
