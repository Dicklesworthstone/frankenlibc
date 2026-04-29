//! Multibyte ↔ wide character conversion (UTF-8 only).
//!
//! Implements `<wchar.h>` / `<stdlib.h>` conversion functions assuming UTF-8
//! encoding. This is appropriate for the "C.UTF-8" / "POSIX.UTF-8" locale.

/// Unicode "REPLACEMENT CHARACTER" — emitted by [`decode_utf8_lossy`]
/// for malformed sequences instead of returning an error.
pub const REPLACEMENT_CODEPOINT: u32 = 0xFFFD;

/// Lossy UTF-8 decode: like [`mbtowc`] but never returns `None`.
///
/// Returns `(codepoint, bytes_consumed)` where `codepoint` is the
/// decoded scalar value for a well-formed sequence, or
/// [`REPLACEMENT_CODEPOINT`] (`U+FFFD`) for invalid/incomplete input.
/// On invalid input the consumed-bytes count is the smaller of:
///   - 1 (continuation-without-lead, empty input, invalid lead byte),
///   - the candidate sequence length when the lead byte is valid but
///     a continuation byte is missing/wrong, or
///   - the full candidate length when the value is rejected for
///     being overlong / a surrogate / above U+10FFFF.
///
/// The "advance past the malformed sequence" guarantee lets callers
/// walk a buffer end-to-end via `i += n` without getting stuck on
/// garbage — useful for display / display-width / printf-render
/// paths where strict rejection would block forward progress.
pub fn decode_utf8_lossy(bytes: &[u8]) -> (u32, usize) {
    if bytes.is_empty() {
        return (REPLACEMENT_CODEPOINT, 1);
    }
    let b0 = bytes[0];
    if b0 < 0x80 {
        return (b0 as u32, 1);
    }
    if b0 < 0xC0 {
        return (REPLACEMENT_CODEPOINT, 1); // continuation byte without lead
    }

    let is_cont = |b: u8| (b & 0xC0) == 0x80;

    if b0 < 0xE0 {
        if bytes.len() < 2 || !is_cont(bytes[1]) {
            return (REPLACEMENT_CODEPOINT, 1);
        }
        let cp = ((b0 as u32 & 0x1F) << 6) | (bytes[1] as u32 & 0x3F);
        if cp < 0x80 {
            return (REPLACEMENT_CODEPOINT, 2);
        }
        (cp, 2)
    } else if b0 < 0xF0 {
        if bytes.len() < 3 || !is_cont(bytes[1]) || !is_cont(bytes[2]) {
            return (REPLACEMENT_CODEPOINT, 1);
        }
        let cp =
            ((b0 as u32 & 0x0F) << 12) | ((bytes[1] as u32 & 0x3F) << 6) | (bytes[2] as u32 & 0x3F);
        if cp < 0x800 || (0xD800..=0xDFFF).contains(&cp) {
            return (REPLACEMENT_CODEPOINT, 3);
        }
        (cp, 3)
    } else if b0 < 0xF8 {
        if bytes.len() < 4 || !is_cont(bytes[1]) || !is_cont(bytes[2]) || !is_cont(bytes[3]) {
            return (REPLACEMENT_CODEPOINT, 1);
        }
        let cp = ((b0 as u32 & 0x07) << 18)
            | ((bytes[1] as u32 & 0x3F) << 12)
            | ((bytes[2] as u32 & 0x3F) << 6)
            | (bytes[3] as u32 & 0x3F);
        if !(0x10000..=0x10FFFF).contains(&cp) {
            return (REPLACEMENT_CODEPOINT, 4);
        }
        (cp, 4)
    } else {
        // 0xF8..=0xFF: invalid lead byte (5/6-byte UTF-8 forbidden by RFC 3629).
        (REPLACEMENT_CODEPOINT, 1)
    }
}

/// Decode one UTF-8 character from `src`, returning `(wchar, bytes_consumed)`.
///
/// Returns `None` on invalid or incomplete sequence, or if `src` is empty.
pub fn mbtowc(src: &[u8]) -> Option<(u32, usize)> {
    if src.is_empty() {
        return None;
    }
    let b0 = src[0];
    if b0 < 0x80 {
        return Some((b0 as u32, 1));
    }
    let (expected_len, mut wc) = if b0 & 0xE0 == 0xC0 {
        (2, (b0 & 0x1F) as u32)
    } else if b0 & 0xF0 == 0xE0 {
        (3, (b0 & 0x0F) as u32)
    } else if b0 & 0xF8 == 0xF0 {
        (4, (b0 & 0x07) as u32)
    } else {
        return None; // invalid lead byte
    };
    if src.len() < expected_len {
        return None; // incomplete sequence
    }
    for &b in src.iter().take(expected_len).skip(1) {
        if b & 0xC0 != 0x80 {
            return None; // invalid continuation byte
        }
        wc = (wc << 6) | (b & 0x3F) as u32;
    }
    // Reject overlong encodings and surrogates
    match expected_len {
        2 if wc < 0x80 => return None,
        3 if wc < 0x800 => return None,
        4 if wc < 0x10000 => return None,
        _ => {}
    }
    if (0xD800..=0xDFFF).contains(&wc) || wc > 0x10FFFF {
        return None;
    }
    Some((wc, expected_len))
}

/// Encode one wide character to UTF-8, writing into `dest`.
///
/// Returns the number of bytes written, or `None` if the character is invalid
/// or `dest` is too small.
pub fn wctomb(wc: u32, dest: &mut [u8]) -> Option<usize> {
    if (0xD800..=0xDFFF).contains(&wc) || wc > 0x10FFFF {
        return None;
    }
    if wc < 0x80 {
        if dest.is_empty() {
            return None;
        }
        dest[0] = wc as u8;
        Some(1)
    } else if wc < 0x800 {
        if dest.len() < 2 {
            return None;
        }
        dest[0] = 0xC0 | (wc >> 6) as u8;
        dest[1] = 0x80 | (wc & 0x3F) as u8;
        Some(2)
    } else if wc < 0x10000 {
        if dest.len() < 3 {
            return None;
        }
        dest[0] = 0xE0 | (wc >> 12) as u8;
        dest[1] = 0x80 | ((wc >> 6) & 0x3F) as u8;
        dest[2] = 0x80 | (wc & 0x3F) as u8;
        Some(3)
    } else {
        if dest.len() < 4 {
            return None;
        }
        dest[0] = 0xF0 | (wc >> 18) as u8;
        dest[1] = 0x80 | ((wc >> 12) & 0x3F) as u8;
        dest[2] = 0x80 | ((wc >> 6) & 0x3F) as u8;
        dest[3] = 0x80 | (wc & 0x3F) as u8;
        Some(4)
    }
}

/// Determine the length in bytes of a multibyte character.
///
/// Returns the number of bytes in the character, 0 for NUL, or `None` for
/// invalid input.
pub fn mblen(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return Some(0);
    }
    if s[0] == 0 {
        return Some(0);
    }
    mbtowc(s).map(|(_, n)| n)
}

/// Convert a multibyte string (UTF-8) to a wide character string.
///
/// Reads from `src` and writes wide characters to `dest`. Returns the number
/// of wide characters written (not including NUL terminator), or `None` on
/// invalid input.
pub fn mbstowcs(dest: &mut [u32], src: &[u8]) -> Option<usize> {
    let mut si = 0usize;
    let mut di = 0usize;
    while si < src.len() {
        if src[si] == 0 {
            // NUL terminator
            if di < dest.len() {
                dest[di] = 0;
            }
            return Some(di);
        }
        let (wc, n) = mbtowc(&src[si..])?;
        if di < dest.len() {
            dest[di] = wc;
        } else {
            return Some(di);
        }
        si += n;
        di += 1;
    }
    // No NUL found, but all bytes converted
    Some(di)
}

/// Convert a wide character string to a multibyte string (UTF-8).
///
/// Returns the number of bytes written (not including NUL terminator), or
/// `None` on invalid input.
pub fn wcstombs(dest: &mut [u8], src: &[u32]) -> Option<usize> {
    let mut si = 0usize;
    let mut di = 0usize;
    while si < src.len() {
        if src[si] == 0 {
            // NUL terminator
            if di < dest.len() {
                dest[di] = 0;
            }
            return Some(di);
        }
        let remaining = if di < dest.len() {
            dest.len() - di
        } else {
            return Some(di);
        };
        let n = wctomb(src[si], &mut dest[di..di + remaining])?;
        di += n;
        si += 1;
    }
    Some(di)
}

/// Wide character classification: is `wc` an alphanumeric character?
pub fn iswalnum(wc: u32) -> bool {
    char::from_u32(wc).is_some_and(|c| c.is_alphanumeric())
}

/// Wide character classification: is `wc` an alphabetic character?
pub fn iswalpha(wc: u32) -> bool {
    char::from_u32(wc).is_some_and(|c| c.is_alphabetic())
}

/// Wide character classification: is `wc` a digit?
pub fn iswdigit(wc: u32) -> bool {
    // POSIX iswdigit is only '0'-'9'
    (0x30..=0x39).contains(&wc)
}

/// Wide character classification: is `wc` a lowercase letter?
pub fn iswlower(wc: u32) -> bool {
    char::from_u32(wc).is_some_and(|c| c.is_lowercase())
}

/// Wide character classification: is `wc` an uppercase letter?
pub fn iswupper(wc: u32) -> bool {
    char::from_u32(wc).is_some_and(|c| c.is_uppercase())
}

/// Wide character classification: is `wc` a whitespace character?
///
/// Mirrors glibc's `iswspace` in a UTF-8 locale: matches the POSIX whitespace
/// set rather than the broader Unicode `White_Space` property. This excludes
/// NEL (U+0085), NBSP (U+00A0), and NNBSP (U+202F), which Rust's
/// `char::is_whitespace` would otherwise report as whitespace.
pub fn iswspace(wc: u32) -> bool {
    matches!(
        wc,
        0x09..=0x0D            // TAB, LF, VT, FF, CR
            | 0x20             // SPACE
            | 0x1680           // OGHAM SPACE MARK
            | 0x2000..=0x200A  // EN QUAD .. HAIR SPACE
            | 0x2028..=0x2029  // LINE SEPARATOR / PARAGRAPH SEPARATOR
            | 0x205F           // MEDIUM MATHEMATICAL SPACE
            | 0x3000           // IDEOGRAPHIC SPACE
    )
}

/// Wide character classification: is `wc` a printable character?
///
/// Mirrors glibc's `iswprint` in a UTF-8 locale. Excludes:
/// - Cc category (the ASCII range Rust's `char::is_control` already catches)
/// - Zl/Zp line/paragraph separators (U+2028, U+2029)
/// - The LANGUAGE TAG codepoint itself (U+E0000); the rest of the tag block
///   (U+E0001..U+E007F) is treated as printable by glibc.
pub fn iswprint(wc: u32) -> bool {
    let Some(c) = char::from_u32(wc) else {
        return false;
    };
    if c.is_control() {
        return false;
    }
    if wc == 0x2028 || wc == 0x2029 || wc == 0xE0000 {
        return false;
    }
    true
}

/// Convert wide character to uppercase.
pub fn towupper(wc: u32) -> u32 {
    char::from_u32(wc)
        .and_then(|c| c.to_uppercase().next())
        .map_or(wc, |c| c as u32)
}

/// Convert wide character to lowercase.
pub fn towlower(wc: u32) -> u32 {
    char::from_u32(wc)
        .and_then(|c| c.to_lowercase().next())
        .map_or(wc, |c| c as u32)
}

/// Compute display width of a wide character (simplified, glibc-aligned).
///
/// Mirrors glibc's `wcwidth(3)` in a UTF-8 locale on the main Unicode ranges:
///   - 0 for NUL and zero-width chars (combining marks, format controls, BOM, VS)
///   - -1 for control chars (Cc), line/paragraph separators (Zl/Zp), tag chars
///   - 2 for CJK / fullwidth / wide East Asian ranges
///   - 1 for everything else
///
/// This is a hand-coded approximation and not driven by Unicode general-category
/// tables, but it matches glibc on the cases tested in conformance harnesses.
pub fn wcwidth(wc: u32) -> i32 {
    if wc == 0 {
        return 0;
    }
    let Some(c) = char::from_u32(wc) else {
        return -1;
    };
    if c.is_control() {
        return -1;
    }

    // Zero-width: combining marks, zero-width format chars, BOM, variation selectors.
    if (0x0300..=0x036F).contains(&wc)        // Combining Diacritical Marks (Mn)
        || (0x0483..=0x0489).contains(&wc)    // Cyrillic combining (Mn/Me)
        || (0x0591..=0x05BD).contains(&wc)    // Hebrew combining marks (Mn)
        || (0x05BF..=0x05BF).contains(&wc)
        || (0x05C1..=0x05C2).contains(&wc)
        || (0x05C4..=0x05C5).contains(&wc)
        || wc == 0x05C7
        || (0x0610..=0x061A).contains(&wc)    // Arabic combining (Mn)
        || (0x064B..=0x065F).contains(&wc)
        || wc == 0x0670
        || (0x06D6..=0x06DC).contains(&wc)
        || (0x06DF..=0x06E4).contains(&wc)
        || (0x06E7..=0x06E8).contains(&wc)
        || (0x06EA..=0x06ED).contains(&wc)
        || (0x1AB0..=0x1AFF).contains(&wc)  // Combining Diacritical Marks Extended (Mn)
        || (0x1DC0..=0x1DFF).contains(&wc)  // Combining Diacritical Marks Supplement (Mn)
        || (0x200B..=0x200F).contains(&wc)    // ZWSP/ZWNJ/ZWJ/LRM/RLM (Cf, width 0)
        || (0x20D0..=0x20FF).contains(&wc)  // Combining Diacritical Marks for Symbols (Mn)
        || (0x202A..=0x202E).contains(&wc)    // bidi controls (Cf, width 0)
        || (0x2060..=0x2064).contains(&wc)    // word joiner / invisible separators (Cf)
        || (0x206A..=0x206F).contains(&wc)    // deprecated formatting (Cf)
        || (0x3099..=0x309A).contains(&wc)  // Hiragana/Katakana voiced sound marks (Mn)
        || wc == 0xFEFF                         // ZWNBSP / BOM
        || (0xFE00..=0xFE0F).contains(&wc)    // Variation Selectors (Mn)
        || (0xFE20..=0xFE2F).contains(&wc)    // Combining Half Marks (Mn)
        || (0xE0100..=0xE01EF).contains(&wc)
    {
        return 0;
    }

    // Non-printable: line/paragraph separators (Zl, Zp), language tags.
    if wc == 0x2028                            // LINE SEPARATOR (Zl)
        || wc == 0x2029                         // PARAGRAPH SEPARATOR (Zp)
        || (0xE0000..=0xE007F).contains(&wc)
    {
        return -1;
    }

    // CJK Unified Ideographs and common fullwidth ranges.
    if (0x1100..=0x115F).contains(&wc)    // Hangul Jamo
        || (0x2E80..=0x303E).contains(&wc)  // CJK Radicals
        || (0x3041..=0x33BF).contains(&wc)  // Hiragana, Katakana, CJK compatibility
        || (0x3400..=0x4DBF).contains(&wc)  // CJK Extension A
        || (0x4E00..=0x9FFF).contains(&wc)  // CJK Unified Ideographs
        || (0xF900..=0xFAFF).contains(&wc)  // CJK Compatibility Ideographs
        || (0xFE30..=0xFE6F).contains(&wc)  // CJK Compatibility Forms
        || (0xFF01..=0xFF60).contains(&wc)  // Fullwidth forms
        || (0xFFE0..=0xFFE6).contains(&wc)  // Fullwidth signs
        || (0x20000..=0x2FFFD).contains(&wc) // CJK Extension B+
        || (0x30000..=0x3FFFD).contains(&wc)
    // CJK Extension G+
    {
        return 2;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_roundtrip() {
        let (wc, n) = mbtowc(b"A").unwrap();
        assert_eq!(wc, 0x41);
        assert_eq!(n, 1);
        let mut buf = [0u8; 4];
        let n = wctomb(wc, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'A');
    }

    #[test]
    fn two_byte_utf8() {
        // U+00E9 = é = 0xC3 0xA9
        let src = [0xC3, 0xA9];
        let (wc, n) = mbtowc(&src).unwrap();
        assert_eq!(wc, 0x00E9);
        assert_eq!(n, 2);
    }

    #[test]
    fn three_byte_utf8() {
        // U+4E16 = 世 = 0xE4 0xB8 0x96
        let src = [0xE4, 0xB8, 0x96];
        let (wc, n) = mbtowc(&src).unwrap();
        assert_eq!(wc, 0x4E16);
        assert_eq!(n, 3);
    }

    #[test]
    fn four_byte_utf8() {
        // U+1F600 = 😀 = 0xF0 0x9F 0x98 0x80
        let src = [0xF0, 0x9F, 0x98, 0x80];
        let (wc, n) = mbtowc(&src).unwrap();
        assert_eq!(wc, 0x1F600);
        assert_eq!(n, 4);
    }

    #[test]
    fn invalid_overlong() {
        // Overlong encoding of NUL: 0xC0 0x80
        assert!(mbtowc(&[0xC0, 0x80]).is_none());
    }

    #[test]
    fn surrogate_rejected() {
        // U+D800 is a surrogate
        assert!(wctomb(0xD800, &mut [0u8; 4]).is_none());
    }

    #[test]
    fn mbstowcs_basic() {
        let src = b"Hello\0";
        let mut dest = [0u32; 10];
        let n = mbstowcs(&mut dest, src).unwrap();
        assert_eq!(n, 5);
        assert_eq!(dest[0], b'H' as u32);
        assert_eq!(dest[4], b'o' as u32);
        assert_eq!(dest[5], 0); // NUL
    }

    #[test]
    fn wcstombs_basic() {
        let src = [b'H' as u32, b'i' as u32, 0];
        let mut dest = [0u8; 10];
        let n = wcstombs(&mut dest, &src).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&dest[..2], b"Hi");
    }

    #[test]
    fn mblen_nul() {
        assert_eq!(mblen(&[0]).unwrap(), 0);
    }

    #[test]
    fn mblen_multibyte() {
        let src = [0xE4, 0xB8, 0x96]; // 世
        assert_eq!(mblen(&src).unwrap(), 3);
    }

    #[test]
    fn towupper_lowercase() {
        assert_eq!(towupper(b'a' as u32), b'A' as u32);
    }

    #[test]
    fn towlower_uppercase() {
        assert_eq!(towlower(b'Z' as u32), b'z' as u32);
    }

    #[test]
    fn wcwidth_ascii() {
        assert_eq!(wcwidth(b'A' as u32), 1);
    }

    #[test]
    fn wcwidth_cjk() {
        assert_eq!(wcwidth(0x4E16), 2); // 世
    }

    #[test]
    fn wcwidth_nul() {
        assert_eq!(wcwidth(0), 0);
    }

    #[test]
    fn wcwidth_control() {
        assert_eq!(wcwidth(0x01), -1);
    }

    #[test]
    fn wcwidth_separator_zero_width() {
        // Zero-width: combining marks, zero-width format chars, BOM, VS.
        assert_eq!(wcwidth(0x0300), 0); // COMBINING GRAVE ACCENT (Mn)
        assert_eq!(wcwidth(0x200B), 0); // ZERO WIDTH SPACE (Cf)
        assert_eq!(wcwidth(0x200D), 0); // ZERO WIDTH JOINER
        assert_eq!(wcwidth(0xFEFF), 0); // BOM / ZWNBSP
        assert_eq!(wcwidth(0xFE0F), 0); // VS-16
        assert_eq!(wcwidth(0x1AB0), 0); // Combining Diacritical Marks Extended
        assert_eq!(wcwidth(0x1DC0), 0); // Combining Diacritical Marks Supplement
        assert_eq!(wcwidth(0x20D0), 0); // Combining Diacritical Marks for Symbols
        assert_eq!(wcwidth(0x3099), 0); // COMBINING KATAKANA-HIRAGANA VOICED SOUND MARK
        assert_eq!(wcwidth(0xFE20), 0); // Combining Half Marks
        // Line/paragraph separators (Zl, Zp).
        assert_eq!(wcwidth(0x2028), -1); // LINE SEPARATOR
        assert_eq!(wcwidth(0x2029), -1); // PARAGRAPH SEPARATOR
        // Language tag chars (Cf, treated as -1 by glibc).
        assert_eq!(wcwidth(0xE0000), -1);
    }

    // ---- decode_utf8_lossy ----

    #[test]
    fn lossy_ascii() {
        for c in 0u8..=0x7F {
            assert_eq!(decode_utf8_lossy(&[c]), (c as u32, 1));
        }
    }

    #[test]
    fn lossy_two_byte_sequence() {
        // U+00A0 = NO-BREAK SPACE = 0xC2 0xA0
        assert_eq!(decode_utf8_lossy(&[0xC2, 0xA0]), (0x00A0, 2));
        // U+07FF = highest 2-byte = 0xDF 0xBF
        assert_eq!(decode_utf8_lossy(&[0xDF, 0xBF]), (0x07FF, 2));
    }

    #[test]
    fn lossy_three_byte_sequence() {
        // U+0800 = lowest 3-byte = 0xE0 0xA0 0x80
        assert_eq!(decode_utf8_lossy(&[0xE0, 0xA0, 0x80]), (0x0800, 3));
        // U+FFFD itself = 0xEF 0xBF 0xBD
        assert_eq!(
            decode_utf8_lossy(&[0xEF, 0xBF, 0xBD]),
            (REPLACEMENT_CODEPOINT, 3)
        );
    }

    #[test]
    fn lossy_four_byte_sequence() {
        // U+10000 = lowest 4-byte = 0xF0 0x90 0x80 0x80
        assert_eq!(decode_utf8_lossy(&[0xF0, 0x90, 0x80, 0x80]), (0x10000, 4));
        // U+10FFFF = highest valid = 0xF4 0x8F 0xBF 0xBF
        assert_eq!(decode_utf8_lossy(&[0xF4, 0x8F, 0xBF, 0xBF]), (0x10FFFF, 4));
    }

    #[test]
    fn lossy_empty_input_yields_replacement_with_advance_one() {
        assert_eq!(decode_utf8_lossy(&[]), (REPLACEMENT_CODEPOINT, 1));
    }

    #[test]
    fn lossy_continuation_without_lead() {
        for b in [0x80u8, 0xA5, 0xBF] {
            assert_eq!(decode_utf8_lossy(&[b]), (REPLACEMENT_CODEPOINT, 1));
        }
    }

    #[test]
    fn lossy_invalid_lead_byte() {
        // 0xF8..=0xFF are RFC 3629-forbidden lead bytes.
        for b in [0xF8u8, 0xFC, 0xFE, 0xFF] {
            assert_eq!(
                decode_utf8_lossy(&[b, 0x80, 0x80, 0x80]),
                (REPLACEMENT_CODEPOINT, 1)
            );
        }
    }

    #[test]
    fn lossy_overlong_two_byte_rejected_with_full_advance() {
        // 0xC0 0x80 would decode U+0000 (overlong NUL) — rejected, but
        // we still consume both bytes so the caller advances past the
        // malformed sequence.
        assert_eq!(decode_utf8_lossy(&[0xC0, 0x80]), (REPLACEMENT_CODEPOINT, 2));
        // 0xC1 0xBF → overlong U+007F.
        assert_eq!(decode_utf8_lossy(&[0xC1, 0xBF]), (REPLACEMENT_CODEPOINT, 2));
    }

    #[test]
    fn lossy_overlong_three_byte_rejected() {
        // 0xE0 0x80 0x80 → overlong U+0000.
        assert_eq!(
            decode_utf8_lossy(&[0xE0, 0x80, 0x80]),
            (REPLACEMENT_CODEPOINT, 3)
        );
    }

    #[test]
    fn lossy_surrogate_rejected() {
        // 0xED 0xA0 0x80 → U+D800 (surrogate).
        assert_eq!(
            decode_utf8_lossy(&[0xED, 0xA0, 0x80]),
            (REPLACEMENT_CODEPOINT, 3)
        );
        // 0xED 0xBF 0xBF → U+DFFF (high-surrogate end).
        assert_eq!(
            decode_utf8_lossy(&[0xED, 0xBF, 0xBF]),
            (REPLACEMENT_CODEPOINT, 3)
        );
    }

    #[test]
    fn lossy_above_max_unicode_rejected() {
        // 0xF4 0x90 0x80 0x80 → U+110000 (one past max).
        assert_eq!(
            decode_utf8_lossy(&[0xF4, 0x90, 0x80, 0x80]),
            (REPLACEMENT_CODEPOINT, 4)
        );
    }

    #[test]
    fn lossy_truncated_two_byte() {
        assert_eq!(decode_utf8_lossy(&[0xC2]), (REPLACEMENT_CODEPOINT, 1));
    }

    #[test]
    fn lossy_truncated_three_byte() {
        assert_eq!(decode_utf8_lossy(&[0xE0]), (REPLACEMENT_CODEPOINT, 1));
        assert_eq!(decode_utf8_lossy(&[0xE0, 0xA0]), (REPLACEMENT_CODEPOINT, 1));
    }

    #[test]
    fn lossy_truncated_four_byte() {
        assert_eq!(decode_utf8_lossy(&[0xF0]), (REPLACEMENT_CODEPOINT, 1));
        assert_eq!(decode_utf8_lossy(&[0xF0, 0x90]), (REPLACEMENT_CODEPOINT, 1));
        assert_eq!(
            decode_utf8_lossy(&[0xF0, 0x90, 0x80]),
            (REPLACEMENT_CODEPOINT, 1)
        );
    }

    #[test]
    fn lossy_invalid_continuation_byte() {
        // 0xC2 followed by ASCII (not 0x80..=0xBF) — bad continuation.
        assert_eq!(decode_utf8_lossy(&[0xC2, 0x41]), (REPLACEMENT_CODEPOINT, 1));
        // 0xE0 0xA0 followed by ASCII.
        assert_eq!(
            decode_utf8_lossy(&[0xE0, 0xA0, 0x41]),
            (REPLACEMENT_CODEPOINT, 1)
        );
    }

    #[test]
    fn lossy_walks_mixed_valid_and_invalid_stream_to_completion() {
        // "A" (ASCII) + invalid 0xC0 0x80 (overlong) + "ñ" (U+00F1
        // = 0xC3 0xB1) + truncated 0xE0 + ASCII tail "Z".
        let stream: &[u8] = &[0x41, 0xC0, 0x80, 0xC3, 0xB1, 0xE0, 0x5A];
        let mut i = 0;
        let mut out: Vec<u32> = Vec::new();
        while i < stream.len() {
            let (cp, n) = decode_utf8_lossy(&stream[i..]);
            out.push(cp);
            i += n;
        }
        assert_eq!(
            out,
            vec![
                0x41,                  // 'A'
                REPLACEMENT_CODEPOINT, // overlong 0xC0 0x80
                0x00F1,                // 'ñ'
                REPLACEMENT_CODEPOINT, // truncated 0xE0 (1 byte advanced)
                0x5A                   // 'Z'
            ]
        );
        // Importantly the loop terminates — every iteration advances by
        // at least 1 byte.
        assert_eq!(i, stream.len());
    }
}
