//! Multibyte ↔ wide character conversion (UTF-8 only).
//!
//! Implements `<wchar.h>` / `<stdlib.h>` conversion functions assuming UTF-8
//! encoding. This is appropriate for the "C.UTF-8" / "POSIX.UTF-8" locale.

use std::simd::{Simd, cmp::SimdPartialEq, cmp::SimdPartialOrd};

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
    // glibc's UTF-8 gconv module decodes the historical RFC 2279 form:
    // sequences of 1-6 bytes encoding code points through U+7FFFFFFF.
    // Lead bytes 0xFE and 0xFF are always invalid. We match that exactly
    // (verified against host glibc C.UTF-8/en_US.UTF-8), including the
    // acceptance of 4-byte sequences above U+10FFFF and 5/6-byte forms.
    let (expected_len, mut wc) = if b0 & 0xE0 == 0xC0 {
        (2, (b0 & 0x1F) as u32)
    } else if b0 & 0xF0 == 0xE0 {
        (3, (b0 & 0x0F) as u32)
    } else if b0 & 0xF8 == 0xF0 {
        (4, (b0 & 0x07) as u32)
    } else if b0 & 0xFC == 0xF8 {
        (5, (b0 & 0x03) as u32)
    } else if b0 & 0xFE == 0xFC {
        (6, (b0 & 0x01) as u32)
    } else {
        return None; // invalid lead byte (continuation, 0xFE, or 0xFF)
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
    // Reject overlong encodings: each length has a minimum code point.
    let min = match expected_len {
        2 => 0x80,
        3 => 0x800,
        4 => 0x1_0000,
        5 => 0x20_0000,
        6 => 0x400_0000,
        _ => unreachable!(),
    };
    if wc < min {
        return None;
    }
    // Reject UTF-16 surrogate code points; glibc rejects them in UTF-8.
    // No U+10FFFF cap: glibc accepts up to U+7FFFFFFF (the 6-byte max).
    if (0xD800..=0xDFFF).contains(&wc) {
        return None;
    }
    Some((wc, expected_len))
}

/// Encode one wide character to UTF-8, writing into `dest`.
///
/// Returns the number of bytes written, or `None` if the character is invalid
/// or `dest` is too small.
pub fn wctomb(wc: u32, dest: &mut [u8]) -> Option<usize> {
    // glibc's UTF-8 gconv encoder mirrors the RFC 2279 decoder: it emits
    // 1-6 byte sequences for code points through U+7FFFFFFF and rejects
    // surrogates. Verified against host glibc wctomb (MB_CUR_MAX == 6).
    if (0xD800..=0xDFFF).contains(&wc) || wc > 0x7FFF_FFFF {
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
    } else if wc < 0x1_0000 {
        if dest.len() < 3 {
            return None;
        }
        dest[0] = 0xE0 | (wc >> 12) as u8;
        dest[1] = 0x80 | ((wc >> 6) & 0x3F) as u8;
        dest[2] = 0x80 | (wc & 0x3F) as u8;
        Some(3)
    } else if wc < 0x20_0000 {
        if dest.len() < 4 {
            return None;
        }
        dest[0] = 0xF0 | (wc >> 18) as u8;
        dest[1] = 0x80 | ((wc >> 12) & 0x3F) as u8;
        dest[2] = 0x80 | ((wc >> 6) & 0x3F) as u8;
        dest[3] = 0x80 | (wc & 0x3F) as u8;
        Some(4)
    } else if wc < 0x400_0000 {
        if dest.len() < 5 {
            return None;
        }
        dest[0] = 0xF8 | (wc >> 24) as u8;
        dest[1] = 0x80 | ((wc >> 18) & 0x3F) as u8;
        dest[2] = 0x80 | ((wc >> 12) & 0x3F) as u8;
        dest[3] = 0x80 | ((wc >> 6) & 0x3F) as u8;
        dest[4] = 0x80 | (wc & 0x3F) as u8;
        Some(5)
    } else {
        if dest.len() < 6 {
            return None;
        }
        dest[0] = 0xFC | (wc >> 30) as u8;
        dest[1] = 0x80 | ((wc >> 24) & 0x3F) as u8;
        dest[2] = 0x80 | ((wc >> 18) & 0x3F) as u8;
        dest[3] = 0x80 | ((wc >> 12) & 0x3F) as u8;
        dest[4] = 0x80 | ((wc >> 6) & 0x3F) as u8;
        dest[5] = 0x80 | (wc & 0x3F) as u8;
        Some(6)
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

    // SIMD ASCII fast path. The overwhelming majority of multibyte text is
    // plain ASCII, where every byte b (0 < b < 0x80) widens to the codepoint
    // `b as u32` — exactly what `mbtowc` returns for a 1-byte sequence. Convert
    // whole ASCII runs a vector at a time, and bail to the scalar loop the
    // instant a chunk contains a NUL terminator or a non-ASCII lead byte, so
    // every terminator / multibyte / error path stays in the unchanged scalar
    // code below. Output is therefore byte-for-byte identical to the pure
    // scalar conversion.
    const LANES: usize = 16;
    let zero = Simd::<u8, LANES>::splat(0);
    let ascii_max = Simd::<u8, LANES>::splat(0x80);
    while si + LANES <= src.len() && di + LANES <= dest.len() {
        let bytes: [u8; LANES] = src[si..si + LANES].try_into().unwrap();
        let chunk = Simd::<u8, LANES>::from_array(bytes);
        // Any NUL (terminator) or any byte >= 0x80 (multibyte lead) ends the run.
        if chunk.simd_eq(zero).any() || chunk.simd_ge(ascii_max).any() {
            break;
        }
        // Zero-extend each ASCII byte to its u32 codepoint; LLVM lowers the
        // `as u32` map to a vector widening (e.g. vpmovzxbd).
        let widened = Simd::<u32, LANES>::from_array(bytes.map(|b| b as u32));
        widened.copy_to_slice(&mut dest[di..di + LANES]);
        si += LANES;
        di += LANES;
    }

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

/// Length of the leading plain-ASCII run of `src`: the count of bytes `b` with
/// `0 < b < 0x80`, stopping at the first NUL or byte `>= 0x80`. SIMD-scanned a
/// vector at a time. Identical to counting those bytes one at a time.
pub fn ascii_prefix_len(src: &[u8]) -> usize {
    const LANES: usize = 16;
    let zero = Simd::<u8, LANES>::splat(0);
    let ascii_max = Simd::<u8, LANES>::splat(0x80);
    let mut k = 0usize;
    while k + LANES <= src.len() {
        let bytes: [u8; LANES] = src[k..k + LANES].try_into().unwrap();
        let chunk = Simd::<u8, LANES>::from_array(bytes);
        if chunk.simd_eq(zero).any() || chunk.simd_ge(ascii_max).any() {
            break;
        }
        k += LANES;
    }
    while k < src.len() && src[k] != 0 && src[k] < 0x80 {
        k += 1;
    }
    k
}

/// Widen the leading plain-ASCII run of `src` (bytes `0 < b < 0x80`, no NUL)
/// into `dest` as codepoints, a SIMD vector at a time, bounded by `dest.len()`.
/// Returns the number of chars converted (= bytes consumed = `dest` slots
/// filled); stops at the first NUL, non-ASCII lead byte, or a full `dest`.
/// Byte-for-byte identical to converting those chars one at a time via
/// [`mbtowc`] — the same lever `mbstowcs` uses, exposed so the streaming
/// `mbsrtowcs` can fast-forward its ASCII runs.
pub fn mbs_ascii_prefix(dest: &mut [u32], src: &[u8]) -> usize {
    const LANES: usize = 16;
    let zero = Simd::<u8, LANES>::splat(0);
    let ascii_max = Simd::<u8, LANES>::splat(0x80);
    let mut k = 0usize;
    while k + LANES <= src.len() && k + LANES <= dest.len() {
        let bytes: [u8; LANES] = src[k..k + LANES].try_into().unwrap();
        let chunk = Simd::<u8, LANES>::from_array(bytes);
        if chunk.simd_eq(zero).any() || chunk.simd_ge(ascii_max).any() {
            break;
        }
        let widened = Simd::<u32, LANES>::from_array(bytes.map(|b| b as u32));
        widened.copy_to_slice(&mut dest[k..k + LANES]);
        k += LANES;
    }
    while k < src.len() && k < dest.len() && src[k] != 0 && src[k] < 0x80 {
        dest[k] = src[k] as u32;
        k += 1;
    }
    k
}

/// Convert a wide character string to a multibyte string (UTF-8).
///
/// Returns the number of bytes written (not including NUL terminator), or
/// `None` on invalid input.
pub fn wcstombs(dest: &mut [u8], src: &[u32]) -> Option<usize> {
    let mut si = 0usize;
    let mut di = 0usize;

    // SIMD ASCII fast path — the inverse of mbstowcs's. Every wide char wc with
    // 0 < wc < 0x80 encodes to the single byte `wc as u8`, exactly as wctomb
    // does for a 1-byte sequence. Narrow whole ASCII runs a vector at a time,
    // bailing to the scalar loop the moment a chunk holds a NUL terminator or a
    // wc >= 0x80 (which needs multibyte encoding, or is a surrogate / out-of-
    // range value wctomb rejects). Output is byte-for-byte identical, and the
    // None/error path stays entirely in the unchanged scalar code below.
    const LANES: usize = 16;
    let zero = Simd::<u32, LANES>::splat(0);
    let ascii_max = Simd::<u32, LANES>::splat(0x80);
    while si + LANES <= src.len() && di + LANES <= dest.len() {
        let wchars: [u32; LANES] = src[si..si + LANES].try_into().unwrap();
        let chunk = Simd::<u32, LANES>::from_array(wchars);
        // Any NUL (terminator) or any wc >= 0x80 (multibyte/invalid) ends the run.
        if chunk.simd_eq(zero).any() || chunk.simd_ge(ascii_max).any() {
            break;
        }
        // Narrow each ASCII codepoint to its single output byte.
        let bytes = Simd::<u8, LANES>::from_array(wchars.map(|w| w as u8));
        bytes.copy_to_slice(&mut dest[di..di + LANES]);
        si += LANES;
        di += LANES;
    }

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
///
/// Mirrors glibc semantics:
/// - 1:1 mappings: return the uppercase char
/// - 1:N where N > 1 and all are base letters (ß → SS, ﬀ → FF): return unchanged
/// - 1:N where base letter + combining marks: return the base letter (drop marks)
///
/// This matches glibc's `towupper(3)` in UTF-8 locales.
pub fn towupper(wc: u32) -> u32 {
    let Some(c) = char::from_u32(wc) else {
        return wc;
    };
    let mut iter = c.to_uppercase();
    let Some(first) = iter.next() else {
        return wc;
    };
    match iter.next() {
        None => first as u32, // 1:1 mapping
        Some(second) => {
            // Multi-char expansion. Glibc drops combining marks but keeps
            // unchanged if all chars are base letters (like ß → SS).
            if is_combining_mark(second) {
                first as u32
            } else {
                wc
            }
        }
    }
}

/// Convert wide character to lowercase.
///
/// Same multi-char-fold rule as [`towupper`].
pub fn towlower(wc: u32) -> u32 {
    let Some(c) = char::from_u32(wc) else {
        return wc;
    };
    let mut iter = c.to_lowercase();
    let Some(first) = iter.next() else {
        return wc;
    };
    match iter.next() {
        None => first as u32,
        Some(second) => {
            if is_combining_mark(second) {
                first as u32
            } else {
                wc
            }
        }
    }
}

/// Check if a character is a Unicode combining mark (Mn, Mc, or Me category).
fn is_combining_mark(c: char) -> bool {
    let cp = c as u32;
    // Combining Diacritical Marks (0300–036F)
    // Combining Diacritical Marks Extended (1AB0–1AFF)
    // Combining Diacritical Marks Supplement (1DC0–1DFF)
    // Combining Diacritical Marks for Symbols (20D0–20FF)
    // Combining Half Marks (FE20–FE2F)
    matches!(
        cp,
        0x0300..=0x036F
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x20D0..=0x20FF
            | 0xFE20..=0xFE2F
    )
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
        || (0x0900..=0x0902).contains(&wc)  // Devanagari signs (Mn)
        || wc == 0x093C                     // Devanagari sign nukta (Mn)
        || (0x0941..=0x0948).contains(&wc)  // Devanagari vowel signs (Mn)
        || wc == 0x094D                     // Devanagari sign virama (Mn)
        || wc == 0x0981                     // Bengali sign candrabindu (Mn)
        || wc == 0x09BC                     // Bengali sign nukta (Mn)
        || (0x09C1..=0x09C4).contains(&wc)  // Bengali vowel signs (Mn)
        || wc == 0x09CD                     // Bengali sign virama (Mn)
        || (0x09E2..=0x09E3).contains(&wc)  // Bengali vocalic marks (Mn)
        || wc == 0x09FE                     // Bengali sandhi mark (Mn)
        || (0x0A01..=0x0A02).contains(&wc)  // Gurmukhi signs (Mn)
        || wc == 0x0A3C                     // Gurmukhi sign nukta (Mn)
        || (0x0A41..=0x0A42).contains(&wc)  // Gurmukhi vowel signs (Mn)
        || (0x0A47..=0x0A48).contains(&wc)
        || (0x0A4B..=0x0A4D).contains(&wc)
        || wc == 0x0A51
        || (0x0A70..=0x0A71).contains(&wc)
        || wc == 0x0A75
        || wc == 0x0B01                     // Odia sign candrabindu (Mn)
        || wc == 0x0B3C                     // Odia sign nukta (Mn)
        || wc == 0x0B3F                     // Odia vowel sign i (Mn)
        || (0x0B41..=0x0B44).contains(&wc)
        || wc == 0x0B4D
        || (0x0B55..=0x0B56).contains(&wc)
        || (0x0B62..=0x0B63).contains(&wc)
        || wc == 0x0B82                     // Tamil sign anusvara (Mn)
        || wc == 0x0BC0
        || wc == 0x0BCD
        || wc == 0x0C00                     // Telugu sign combining candrabindu (Mn)
        || wc == 0x0C04
        || wc == 0x0C3C
        || (0x0C3E..=0x0C40).contains(&wc)
        || (0x0C46..=0x0C48).contains(&wc)
        || (0x0C4A..=0x0C4D).contains(&wc)
        || (0x0C55..=0x0C56).contains(&wc)
        || (0x0C62..=0x0C63).contains(&wc)
        || wc == 0x0C81                     // Kannada sign candrabindu (Mn)
        || wc == 0x0CBC
        || wc == 0x0CBF
        || wc == 0x0CC6
        || wc == 0x0CCC
        || wc == 0x0CCD
        || (0x0CE2..=0x0CE3).contains(&wc)
        || (0x0D00..=0x0D01).contains(&wc)  // Malayalam signs (Mn)
        || (0x0D3B..=0x0D3C).contains(&wc)
        || (0x0D41..=0x0D44).contains(&wc)
        || wc == 0x0D4D
        || (0x0D62..=0x0D63).contains(&wc)
        || wc == 0x0D81                     // Sinhala sign candrabindu (Mn)
        || wc == 0x0DCA
        || (0x0DD2..=0x0DD4).contains(&wc)
        || wc == 0x0DD6
        || wc == 0x0E31                     // Thai character mai han-akat (Mn)
        || (0x0E34..=0x0E3A).contains(&wc)  // Thai vowel signs / phinthu (Mn)
        || (0x0E47..=0x0E4E).contains(&wc)  // Thai tone/sign marks (Mn)
        || (0x0F18..=0x0F19).contains(&wc)  // Tibetan astrological signs (Mn)
        || wc == 0x0F35
        || wc == 0x0F37
        || wc == 0x0F39
        || (0x0F71..=0x0F84).contains(&wc)
        || (0x0F86..=0x0F87).contains(&wc)
        || (0x0F8D..=0x0FBC).contains(&wc)
        || wc == 0x0FC6
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

    // CJK Unified Ideographs, Emoji, and common fullwidth ranges.
    if (0x1100..=0x115F).contains(&wc)    // Hangul Jamo
        || (0x2E80..=0x303E).contains(&wc)  // CJK Radicals
        || (0x3041..=0x33BF).contains(&wc)  // Hiragana, Katakana, CJK compatibility
        || (0x3400..=0x4DBF).contains(&wc)  // CJK Extension A
        || (0x4E00..=0x9FFF).contains(&wc)  // CJK Unified Ideographs
        || (0xF900..=0xFAFF).contains(&wc)  // CJK Compatibility Ideographs
        || (0xFE30..=0xFE6F).contains(&wc)  // CJK Compatibility Forms
        || (0xFF01..=0xFF60).contains(&wc)  // Fullwidth forms
        || (0xFFE0..=0xFFE6).contains(&wc)  // Fullwidth signs
        || (0x1F300..=0x1F9FF).contains(&wc) // Emoji (Miscellaneous Symbols/Pictographs/Emoticons)
        || (0x1FA00..=0x1FAFF).contains(&wc) // Emoji Symbols and Pictographs Extended-A
        || (0x20000..=0x2FFFD).contains(&wc) // CJK Extension B+
        || (0x30000..=0x3FFFD).contains(&wc)
    // CJK Extension G+
    {
        return 2;
    }

    // Non-characters: glibc returns -1 for these.
    // U+FDD0..U+FDEF and U+xxFFFE..U+xxFFFF for each plane.
    if (0xFDD0..=0xFDEF).contains(&wc) || (wc & 0xFFFE) == 0xFFFE
    // catches FFFE and FFFF in every plane
    {
        return -1;
    }

    1
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure scalar reference: the original mbstowcs loop, with no SIMD fast path.
    // Used to prove the vectorised mbstowcs is byte-for-byte isomorphic.
    fn mbstowcs_scalar_reference(dest: &mut [u32], src: &[u8]) -> Option<usize> {
        let mut si = 0usize;
        let mut di = 0usize;
        while si < src.len() {
            if src[si] == 0 {
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
        Some(di)
    }

    // Pure scalar reference for wcstombs (no SIMD fast path).
    fn wcstombs_scalar_reference(dest: &mut [u8], src: &[u32]) -> Option<usize> {
        let mut si = 0usize;
        let mut di = 0usize;
        while si < src.len() {
            if src[si] == 0 {
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

    #[test]
    fn wcstombs_simd_isomorphic_to_scalar() {
        let mut corpus: Vec<Vec<u32>> = Vec::new();
        // Pure ASCII of every length around the 16-lane boundary.
        for len in 0..80usize {
            corpus.push((0..len).map(|i| 0x41 + (i % 26) as u32).collect());
        }
        // ASCII with a NUL planted at each offset.
        for pos in 0..40usize {
            let mut v: Vec<u32> = (0..40).map(|i| 0x61 + (i % 26) as u32).collect();
            v[pos] = 0;
            corpus.push(v);
        }
        // ASCII run interrupted by a multibyte codepoint at each offset
        // (€ = U+20AC -> 3 bytes; ☃ = U+2603; é = U+00E9 -> 2 bytes).
        for pos in 0..40usize {
            for &mb in &[0xE9u32, 0x20AC, 0x2603, 0x1F600] {
                let mut v: Vec<u32> = (0..40).map(|_| 0x78).collect();
                v.insert(pos, mb);
                corpus.push(v);
            }
        }
        // Surrogates / out-of-range values wctomb rejects (must bail to scalar
        // and return None identically).
        corpus.push(vec![0x78, 0x79, 0xD800, 0x7A]);
        corpus.push(vec![0x41; 20].into_iter().chain([0x8000_0000u32]).collect());
        // Random soup including high codepoints.
        let mut state: u64 = 0xFEED_FACE_DEAD_C0DE;
        for _ in 0..2000 {
            let len = (state % 70) as usize;
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                v.push((state >> 32) as u32);
            }
            corpus.push(v);
        }

        for src in &corpus {
            for &cap in &[0usize, 1, 7, 15, 16, 17, 33, 256] {
                let mut a = vec![0xAAu8; cap];
                let mut b = vec![0xAAu8; cap];
                let ra = wcstombs(&mut a, src);
                let rb = wcstombs_scalar_reference(&mut b, src);
                assert_eq!(ra, rb, "return mismatch: src={src:x?} cap={cap}");
                assert_eq!(a, b, "dest mismatch: src={src:x?} cap={cap}");
            }
        }
    }

    #[test]
    fn ascii_prefix_helpers_match_scalar() {
        // Scalar references: leading-ASCII run length, and the widen of it.
        fn ref_len(src: &[u8]) -> usize {
            let mut k = 0;
            while k < src.len() && src[k] != 0 && src[k] < 0x80 {
                k += 1;
            }
            k
        }
        // Varied corpus: ASCII around the 16-lane boundary, embedded NUL at each
        // offset, ASCII interrupted by a high byte at each offset, empty.
        let mut corpus: Vec<Vec<u8>> = Vec::new();
        for len in 0..80usize {
            corpus.push((0..len).map(|i| b'a' + (i % 26) as u8).collect());
        }
        for len in 1..40usize {
            for pos in 0..len {
                let mut v: Vec<u8> = (0..len).map(|_| b'x').collect();
                v[pos] = 0;
                corpus.push(v.clone());
                v[pos] = 0xC3; // non-ASCII lead byte
                corpus.push(v);
            }
        }
        for src in &corpus {
            let want_len = ref_len(src);
            assert_eq!(ascii_prefix_len(src), want_len, "ascii_prefix_len {src:?}");
            // mbs_ascii_prefix: bounded by dest len; verify for several dest caps.
            for cap in [0usize, 1, 7, 16, 17, 40, 100] {
                let mut dest = vec![0u32; cap];
                let k = mbs_ascii_prefix(&mut dest, src);
                let expect_k = want_len.min(cap);
                assert_eq!(k, expect_k, "mbs_ascii_prefix k {src:?} cap={cap}");
                for j in 0..k {
                    assert_eq!(dest[j], src[j] as u32, "widen {src:?} j={j}");
                }
            }
        }
    }

    #[test]
    fn mbstowcs_simd_isomorphic_to_scalar() {
        // Build a varied corpus: pure ASCII of every length around the 16-lane
        // boundary, ASCII with embedded NUL at each offset, ASCII interrupted by
        // multibyte sequences at each offset, and pseudo-random byte soup
        // (exercises invalid sequences -> both must agree on None or count).
        let mut corpus: Vec<Vec<u8>> = Vec::new();
        for len in 0..80usize {
            corpus.push((0..len).map(|i| b'a' + (i % 26) as u8).collect());
        }
        // ASCII with a NUL planted at every offset up to 40.
        for pos in 0..40usize {
            let mut v: Vec<u8> = (0..40).map(|i| b'A' + (i % 26) as u8).collect();
            v[pos] = 0;
            corpus.push(v);
        }
        // ASCII run then a 3-byte multibyte char (€ = E2 82 AC) at each offset.
        for pos in 0..40usize {
            let mut v: Vec<u8> = (0..40).map(|_| b'x').collect();
            v.splice(pos..pos, [0xE2, 0x82, 0xAC]);
            corpus.push(v);
        }
        // Multibyte-heavy and mixed (snowman ☃ = E2 98 83, é = C3 A9).
        corpus.push(b"caf\xc3\xa9 \xe2\x98\x83 \xe2\x82\xac done".to_vec());
        // Pseudo-random soup (LCG) including high bytes / invalid sequences.
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..2000 {
            let len = (state % 70) as usize;
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                v.push((state >> 33) as u8);
            }
            corpus.push(v);
        }

        // Sweep several destination capacities, including exact and truncating.
        for src in &corpus {
            for &cap in &[0usize, 1, 7, 15, 16, 17, 33, 128] {
                let mut a = vec![0xDEAD_BEEFu32; cap];
                let mut b = vec![0xDEAD_BEEFu32; cap];
                let ra = mbstowcs(&mut a, src);
                let rb = mbstowcs_scalar_reference(&mut b, src);
                assert_eq!(ra, rb, "return mismatch: src={src:02x?} cap={cap}");
                assert_eq!(a, b, "dest mismatch: src={src:02x?} cap={cap}");
            }
        }
    }

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
        assert_eq!(wcwidth(0x0900), 0); // DEVANAGARI SIGN INVERTED CANDRABINDU
        assert_eq!(wcwidth(0x093C), 0); // DEVANAGARI SIGN NUKTA
        assert_eq!(wcwidth(0x094D), 0); // DEVANAGARI SIGN VIRAMA
        assert_eq!(wcwidth(0x0981), 0); // BENGALI SIGN CANDRABINDU
        assert_eq!(wcwidth(0x09CD), 0); // BENGALI SIGN VIRAMA
        assert_eq!(wcwidth(0x0A4D), 0); // GURMUKHI SIGN VIRAMA
        assert_eq!(wcwidth(0x0B4D), 0); // ODIA SIGN VIRAMA
        assert_eq!(wcwidth(0x0BCD), 0); // TAMIL SIGN VIRAMA
        assert_eq!(wcwidth(0x0C4D), 0); // TELUGU SIGN VIRAMA
        assert_eq!(wcwidth(0x0CCD), 0); // KANNADA SIGN VIRAMA
        assert_eq!(wcwidth(0x0D4D), 0); // MALAYALAM SIGN VIRAMA
        assert_eq!(wcwidth(0x0DCA), 0); // SINHALA SIGN AL-LAKUNA
        assert_eq!(wcwidth(0x0E31), 0); // THAI CHARACTER MAI HAN-AKAT
        assert_eq!(wcwidth(0x0E34), 0); // THAI CHARACTER SARA I
        assert_eq!(wcwidth(0x0E4E), 0); // THAI CHARACTER YAMAKKAN
        assert_eq!(wcwidth(0x0F71), 0); // TIBETAN VOWEL SIGN AA
        assert_eq!(wcwidth(0x3099), 0); // COMBINING KATAKANA-HIRAGANA VOICED SOUND MARK
        assert_eq!(wcwidth(0xFE20), 0); // Combining Half Marks
        // Line/paragraph separators (Zl, Zp).
        assert_eq!(wcwidth(0x2028), -1); // LINE SEPARATOR
        assert_eq!(wcwidth(0x2029), -1); // PARAGRAPH SEPARATOR
        // Language tag chars (Cf, treated as -1 by glibc).
        assert_eq!(wcwidth(0xE0000), -1);
    }

    #[test]
    fn wcwidth_emoji() {
        // Emoji pictographs are width 2 (matching glibc).
        assert_eq!(wcwidth(0x1F600), 2); // 😀 GRINNING FACE
        assert_eq!(wcwidth(0x1F4A9), 2); // 💩 PILE OF POO
        assert_eq!(wcwidth(0x1F914), 2); // 🤔 THINKING FACE
        assert_eq!(wcwidth(0x1FA80), 2); // 🪀 YO-YO (Extended-A)
    }

    #[test]
    fn wcwidth_space_characters() {
        // Various space characters return width 1 in glibc C.UTF-8 locale.
        assert_eq!(wcwidth(0x0020), 1); // SPACE
        assert_eq!(wcwidth(0x00A0), 1); // NO-BREAK SPACE (NBSP)
        assert_eq!(wcwidth(0x1680), 1); // OGHAM SPACE MARK
        assert_eq!(wcwidth(0x2000), 1); // EN QUAD
        assert_eq!(wcwidth(0x2007), 1); // FIGURE SPACE
        assert_eq!(wcwidth(0x202F), 1); // NARROW NO-BREAK SPACE (NNBSP)
    }

    #[test]
    fn wcwidth_noncharacters_return_negative_one() {
        // Unicode non-characters: glibc returns -1 for these.
        assert_eq!(wcwidth(0xFFFE), -1);
        assert_eq!(wcwidth(0xFFFF), -1);
        assert_eq!(wcwidth(0xFDD0), -1);
        assert_eq!(wcwidth(0xFDEF), -1);
        // Non-characters in supplementary planes.
        assert_eq!(wcwidth(0x1FFFE), -1);
        assert_eq!(wcwidth(0x1FFFF), -1);
        assert_eq!(wcwidth(0x10FFFE), -1);
        assert_eq!(wcwidth(0x10FFFF), -1);
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

    #[test]
    fn towupper_towlower_unicode_extended() {
        // Latin extended
        assert_eq!(towupper(0x00F1), 0x00D1); // ñ → Ñ
        assert_eq!(towlower(0x00D1), 0x00F1); // Ñ → ñ

        // Greek
        assert_eq!(towupper(0x03B1), 0x0391); // α → Α
        assert_eq!(towlower(0x03A9), 0x03C9); // Ω → ω

        // Cyrillic
        assert_eq!(towupper(0x044F), 0x042F); // я → Я
        assert_eq!(towlower(0x042F), 0x044F); // Я → я

        // Turkish dotless i (U+0131) → ASCII I
        assert_eq!(towupper(0x0131), 0x0049); // ı → I
        // Turkish dotted I (U+0130) lowercases to i + combining dot (U+0307),
        // but glibc drops the combining mark and returns just 'i'.
        assert_eq!(towlower(0x0130), 0x0069); // İ → i

        // German sharp s stays unchanged (1:N mapping to multiple base letters)
        assert_eq!(towupper(0x00DF), 0x00DF); // ß unchanged (→ SS dropped)
        // Capital sharp s (U+1E9E) → lowercase ß (1:1)
        assert_eq!(towlower(0x1E9E), 0x00DF); // ẞ → ß

        // Ligatures stay unchanged (expand to multiple base letters)
        assert_eq!(towupper(0xFB00), 0xFB00); // ﬀ unchanged (→ FF dropped)

        // Non-letter unchanged
        assert_eq!(towupper(0x0035), 0x0035); // '5'
        assert_eq!(towlower(0x0021), 0x0021); // '!'

        // Invalid codepoint unchanged
        assert_eq!(towupper(0xFFFFFFFF), 0xFFFFFFFF);
        assert_eq!(towlower(0xFFFFFFFF), 0xFFFFFFFF);
    }

    #[test]
    fn glibc_towupper_digit_unchanged_parity() {
        // glibc: towupper(L'5') = L'5' (unchanged)
        assert_eq!(towupper(0x35), 0x35);
        assert_eq!(towlower(0x35), 0x35);
    }
}
