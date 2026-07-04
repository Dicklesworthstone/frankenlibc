//! Multibyte ↔ wide character conversion (UTF-8 only).
//!
//! Implements `<wchar.h>` / `<stdlib.h>` conversion functions assuming UTF-8
//! encoding. This is appropriate for the "C.UTF-8" / "POSIX.UTF-8" locale.

use std::simd::{Simd, cmp::SimdPartialEq, cmp::SimdPartialOrd, num::SimdUint};

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

/// Outcome of decoding one UTF-8 character from a byte prefix.
///
/// Distinguishes a well-formed character, a valid-but-truncated prefix
/// (caller should supply more bytes), and a malformed sequence — matching the
/// three glibc `mbrtowc` return sentinels (count / `(size_t)-2` / `(size_t)-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Utf8Step {
    /// A complete character of `wc` consuming `len` bytes.
    Char { wc: u32, len: usize },
    /// The available bytes are a valid prefix but the sequence is truncated.
    Incomplete,
    /// The available bytes cannot begin (or continue) a valid sequence.
    Invalid,
}

/// Decode one UTF-8 character per RFC 3629 + the Unicode "well-formed UTF-8"
/// byte-sequence table (Table 3-7), matching glibc's UTF-8 converter:
///
/// * 1–4 byte sequences only (lead bytes `0xC0`/`0xC1` and `0xF5`–`0xFF` are
///   never valid);
/// * the lead-byte-specific range on the *second* byte rejects overlong forms,
///   UTF-16 surrogates (`U+D800`–`U+DFFF`), and code points above `U+10FFFF`
///   without a separate post-decode check;
/// * a byte that is present but out of range is `Invalid` immediately — only a
///   valid-so-far truncated prefix is `Incomplete` (this is the distinction the
///   old length-only check got wrong, returning `Incomplete` for already-bad
///   input where glibc returns `EILSEQ`).
pub fn utf8_decode_step(bytes: &[u8]) -> Utf8Step {
    let Some(&b0) = bytes.first() else {
        return Utf8Step::Incomplete;
    };
    if b0 < 0x80 {
        return Utf8Step::Char {
            wc: b0 as u32,
            len: 1,
        };
    }
    // Lead-byte length (matching glibc's UTF-8 converter, empirically verified
    // by `mbrtowc_differential_probe`): 0xC0/0xC1 and 0xFE/0xFF are rejected at
    // the lead (always overlong / never valid), but 0xF8..=0xFD ARE accepted as
    // 5/6-byte lead bytes here — glibc defers their rejection to the completed
    // sequence, so a lone such byte is `Incomplete`, not `Invalid`.
    let len = match b0 {
        0xC2..=0xDF => 2usize,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        0xF8..=0xFB => 5,
        0xFC..=0xFD => 6,
        _ => return Utf8Step::Invalid, // continuation byte, 0xC0, 0xC1, 0xFE, 0xFF
    };
    // glibc's incremental check is a PLAIN continuation test (0x80..=0xBF) on the
    // bytes present; the lead-specific overlong/surrogate ranges are enforced
    // only once the whole sequence is in hand. A present byte that is not a
    // continuation is `Invalid` immediately; a valid-but-short prefix is
    // `Incomplete`.
    let avail = bytes.len().min(len);
    for &b in &bytes[1..avail] {
        if b & 0xC0 != 0x80 {
            return Utf8Step::Invalid;
        }
    }
    if bytes.len() < len {
        return Utf8Step::Incomplete;
    }
    let mut wc = (b0 as u32) & (0x7F >> len);
    for &b in &bytes[1..len] {
        wc = (wc << 6) | (b & 0x3F) as u32;
    }
    // Reject overlong encodings (each length has a minimum code point) and
    // UTF-16 surrogates, matching glibc. No U+10FFFF / U+7FFFFFFF cap beyond the
    // lead-byte length, also matching glibc's converter.
    let min: u32 = match len {
        2 => 0x80,
        3 => 0x800,
        4 => 0x1_0000,
        5 => 0x20_0000,
        6 => 0x400_0000,
        _ => unreachable!(),
    };
    if wc < min || (0xD800..=0xDFFF).contains(&wc) {
        return Utf8Step::Invalid;
    }
    Utf8Step::Char { wc, len }
}

/// Decode one UTF-8 character from `src`, returning `(wchar, bytes_consumed)`.
///
/// Returns `None` on an invalid or incomplete sequence, or if `src` is empty.
/// RFC 3629-strict (see [`utf8_decode_step`]).
pub fn mbtowc(src: &[u8]) -> Option<(u32, usize)> {
    match utf8_decode_step(src) {
        Utf8Step::Char { wc, len } => Some((wc, len)),
        Utf8Step::Incomplete | Utf8Step::Invalid => None,
    }
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
    // SIMD ASCII runs and scalar multibyte steps are INTERLEAVED: after each
    // scalar character the outer loop re-attempts the SIMD fast path, so a long
    // ASCII tail following an early multibyte char (e.g. "café" + a paragraph of
    // English) is vectorised instead of running scalar to end-of-string. Each
    // outer iteration advances `si` by >= 1 (the scalar step always consumes a
    // byte even if SIMD made no progress), so termination is guaranteed. Output
    // is byte-for-byte identical to the pure scalar conversion: the SIMD run only
    // ever consumes whole ASCII chunks, and every NUL / multibyte / error case is
    // handled by the unchanged scalar step below.
    loop {
        // The `src[si] < 0x80` guard skips the SIMD load+compare entirely when the
        // current byte is a multibyte lead (>= 0x80): the chunk would contain that
        // byte and break on the first iteration anyway, so probing it is pure waste
        // on multibyte-heavy text (e.g. CJK / Cyrillic). Identical result — the run
        // only ever advances on whole ASCII chunks. (Bounds check first: `si +
        // LANES <= src.len()` guarantees `si < src.len()`, so `src[si]` is in range.)
        while si + LANES <= src.len() && src[si] < 0x80 && di + LANES <= dest.len() {
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

        // SIMD 2-byte fast path: a run of >= 8 well-formed 2-byte UTF-8 sequences
        // decodes 8 code points per 16-byte vector. A 2-byte char is lead
        // 0xC2..=0xDF + continuation 0x80..=0xBF, yielding a code point in
        // 0x80..=0x7FF — never overlong (lead >= 0xC2 forces wc >= 0x80) and never
        // a UTF-16 surrogate (wc <= 0x7FF < 0xD800). So a window whose even lanes
        // are all valid leads and odd lanes all valid continuations is 8 valid
        // 2-byte chars needing no further validation, and produces byte-for-byte
        // what the scalar `mbtowc` would. Covers the common 2-byte scripts
        // (Cyrillic / Greek / Hebrew / Arabic / Latin-extended). Any non-clean
        // window (ASCII, 3/4-byte, malformed, NUL, or a sequence straddling the
        // 16-byte boundary) fails the mask test and drops to the scalar step.
        while si + 16 <= src.len() && di + 8 <= dest.len() && (0xC2..=0xDF).contains(&src[si]) {
            let bytes: [u8; 16] = src[si..si + 16].try_into().unwrap();
            let v = Simd::<u8, 16>::from_array(bytes);
            let leads = std::simd::simd_swizzle!(v, [0, 2, 4, 6, 8, 10, 12, 14]);
            let conts = std::simd::simd_swizzle!(v, [1, 3, 5, 7, 9, 11, 13, 15]);
            let leads_ok = leads.simd_ge(Simd::splat(0xC2)) & leads.simd_le(Simd::splat(0xDF));
            let conts_ok = conts.simd_ge(Simd::splat(0x80)) & conts.simd_le(Simd::splat(0xBF));
            if !(leads_ok & conts_ok).all() {
                break; // not a clean 2-byte window — let the scalar step handle it
            }
            let lw = leads.cast::<u32>() & Simd::splat(0x1F);
            let cw = conts.cast::<u32>() & Simd::splat(0x3F);
            let wc = (lw << Simd::splat(6)) | cw;
            wc.copy_to_slice(&mut dest[di..di + 8]);
            si += 16;
            di += 8;
        }

        // SIMD 3-byte fast path: a clean 12-byte window decodes four UTF-8
        // codepoints. Validate the full RFC 3629 3-byte shape before writing:
        // lead E0..EF, both continuations 80..BF, no E0 overlong second byte
        // below A0, and no ED surrogate second byte above 9F. Any mixed-width,
        // malformed, NUL, or boundary-straddling input drops to the scalar
        // `mbtowc` path, preserving the exact success/error contract.
        while si + 16 <= src.len() && di + 4 <= dest.len() && (0xE0..=0xEF).contains(&src[si]) {
            let bytes: [u8; 16] = src[si..si + 16].try_into().unwrap();
            let v = Simd::<u8, 16>::from_array(bytes);
            let leads = std::simd::simd_swizzle!(v, [0, 3, 6, 9]);
            let cont1 = std::simd::simd_swizzle!(v, [1, 4, 7, 10]);
            let cont2 = std::simd::simd_swizzle!(v, [2, 5, 8, 11]);
            let leads_ok = leads.simd_ge(Simd::splat(0xE0)) & leads.simd_le(Simd::splat(0xEF));
            let cont1_ok = cont1.simd_ge(Simd::splat(0x80)) & cont1.simd_le(Simd::splat(0xBF));
            let cont2_ok = cont2.simd_ge(Simd::splat(0x80)) & cont2.simd_le(Simd::splat(0xBF));
            let overlong_ok = !leads.simd_eq(Simd::splat(0xE0)) | cont1.simd_ge(Simd::splat(0xA0));
            let surrogate_ok = !leads.simd_eq(Simd::splat(0xED)) | cont1.simd_le(Simd::splat(0x9F));
            if !(leads_ok & cont1_ok & cont2_ok & overlong_ok & surrogate_ok).all() {
                break;
            }
            let lw = leads.cast::<u32>() & Simd::splat(0x0F);
            let c1w = cont1.cast::<u32>() & Simd::splat(0x3F);
            let c2w = cont2.cast::<u32>() & Simd::splat(0x3F);
            let wc = (lw << Simd::splat(12)) | (c1w << Simd::splat(6)) | c2w;
            wc.copy_to_slice(&mut dest[di..di + 4]);
            si += 12;
            di += 4;
        }

        // SIMD 4-byte fast path: a clean 16-byte window decodes four UTF-8
        // codepoints. This mirrors the scalar `utf8_decode_step` contract:
        // F0..=F7 leads, plain continuation bytes, and no overlong F0 sequence.
        // Code points above U+10FFFF are intentionally still accepted here when
        // encoded by F5..=F7, matching the existing glibc-compatible scalar path.
        while si + 16 <= src.len() && di + 4 <= dest.len() && (0xF0..=0xF7).contains(&src[si]) {
            let bytes: [u8; 16] = src[si..si + 16].try_into().unwrap();
            let v = Simd::<u8, 16>::from_array(bytes);
            let leads = std::simd::simd_swizzle!(v, [0, 4, 8, 12]);
            let cont1 = std::simd::simd_swizzle!(v, [1, 5, 9, 13]);
            let cont2 = std::simd::simd_swizzle!(v, [2, 6, 10, 14]);
            let cont3 = std::simd::simd_swizzle!(v, [3, 7, 11, 15]);
            let leads_ok = leads.simd_ge(Simd::splat(0xF0)) & leads.simd_le(Simd::splat(0xF7));
            let cont1_ok = cont1.simd_ge(Simd::splat(0x80)) & cont1.simd_le(Simd::splat(0xBF));
            let cont2_ok = cont2.simd_ge(Simd::splat(0x80)) & cont2.simd_le(Simd::splat(0xBF));
            let cont3_ok = cont3.simd_ge(Simd::splat(0x80)) & cont3.simd_le(Simd::splat(0xBF));
            let overlong_ok = !leads.simd_eq(Simd::splat(0xF0)) | cont1.simd_ge(Simd::splat(0x90));
            if !(leads_ok & cont1_ok & cont2_ok & cont3_ok & overlong_ok).all() {
                break;
            }
            let lw = leads.cast::<u32>() & Simd::splat(0x07);
            let c1w = cont1.cast::<u32>() & Simd::splat(0x3F);
            let c2w = cont2.cast::<u32>() & Simd::splat(0x3F);
            let c3w = cont3.cast::<u32>() & Simd::splat(0x3F);
            let wc =
                (lw << Simd::splat(18)) | (c1w << Simd::splat(12)) | (c2w << Simd::splat(6)) | c3w;
            wc.copy_to_slice(&mut dest[di..di + 4]);
            si += 16;
            di += 4;
        }

        // One scalar step, then re-attempt the SIMD run.
        if si >= src.len() {
            // No NUL found, but all bytes converted.
            return Some(di);
        }
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

/// Length of the leading plain-ASCII run of wide chars `src`: the count of `wc`
/// with `0 < wc < 0x80`, stopping at the first NUL or `wc >= 0x80`. The wide
/// inverse of [`ascii_prefix_len`].
pub fn wcs_ascii_prefix_len(src: &[u32]) -> usize {
    const LANES: usize = 16;
    let zero = Simd::<u32, LANES>::splat(0);
    let ascii_max = Simd::<u32, LANES>::splat(0x80);
    let mut k = 0usize;
    while k + LANES <= src.len() {
        let chunk = Simd::<u32, LANES>::from_array(src[k..k + LANES].try_into().unwrap());
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

/// Narrow the leading plain-ASCII run of wide chars `src` (`0 < wc < 0x80`, no
/// NUL) into `dest` as single output bytes, a SIMD vector at a time, bounded by
/// `dest.len()`. Returns the number of chars converted (= bytes written); stops
/// at the first NUL, `wc >= 0x80`, or a full `dest`. The wide-to-multibyte
/// inverse of [`mbs_ascii_prefix`] — byte-for-byte identical to encoding those
/// chars one at a time via [`wctomb`]; exposed so streaming `wcsrtombs` can
/// fast-forward its ASCII runs.
pub fn wcs_ascii_prefix(dest: &mut [u8], src: &[u32]) -> usize {
    const LANES: usize = 16;
    let zero = Simd::<u32, LANES>::splat(0);
    let ascii_max = Simd::<u32, LANES>::splat(0x80);
    let mut k = 0usize;
    while k + LANES <= src.len() && k + LANES <= dest.len() {
        let wchars: [u32; LANES] = src[k..k + LANES].try_into().unwrap();
        let chunk = Simd::<u32, LANES>::from_array(wchars);
        if chunk.simd_eq(zero).any() || chunk.simd_ge(ascii_max).any() {
            break;
        }
        // Lane-wise truncating SIMD cast (u32 -> u8, keeping the low byte) packs
        // the whole vector at once. Identical to `w as u8` per lane, but lowers
        // to a vector pack instead of 16 scalar truncations + an array rebuild.
        let bytes = chunk.cast::<u8>();
        bytes.copy_to_slice(&mut dest[k..k + LANES]);
        k += LANES;
    }
    while k < src.len() && k < dest.len() && src[k] != 0 && src[k] < 0x80 {
        dest[k] = src[k] as u8;
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
    // SIMD ASCII runs and scalar multibyte steps are INTERLEAVED (the inverse of
    // mbstowcs): after each scalar character the outer loop re-attempts the SIMD
    // fast path, so a long ASCII tail after an early wide char is vectorised
    // instead of narrowing scalar to end-of-string. Each outer iteration advances
    // `si` by >= 1, so termination is guaranteed; output is byte-for-byte
    // identical (SIMD only narrows whole ASCII chunks; NUL / multibyte / error
    // cases stay in the unchanged scalar step).
    loop {
        // The `src[si] < 0x80` guard skips the SIMD load+compare when the current
        // wide char needs multibyte encoding (>= 0x80): the chunk would break on it
        // immediately, so probing is pure waste on multibyte-heavy text. Identical
        // result. (Bounds check first keeps `src[si]` in range.)
        while si + LANES <= src.len() && src[si] < 0x80 && di + LANES <= dest.len() {
            let wchars: [u32; LANES] = src[si..si + LANES].try_into().unwrap();
            let chunk = Simd::<u32, LANES>::from_array(wchars);
            // Any NUL (terminator) or any wc >= 0x80 (multibyte/invalid) ends the run.
            if chunk.simd_eq(zero).any() || chunk.simd_ge(ascii_max).any() {
                break;
            }
            // Narrow each ASCII codepoint to its single output byte.
            // Lane-wise truncating SIMD cast (u32 -> u8, keeping the low byte) packs
            // the whole vector at once. Identical to `w as u8` per lane, but lowers
            // to a vector pack instead of 16 scalar truncations + an array rebuild.
            let bytes = chunk.cast::<u8>();
            bytes.copy_to_slice(&mut dest[di..di + LANES]);
            si += LANES;
            di += LANES;
        }

        // SIMD 2-byte encode fast path (inverse of mbstowcs's 2-byte decode): a run
        // of >= 8 wide chars all in 0x80..=0x7FF each encodes to exactly two bytes
        // (0xC0|(wc>>6), 0x80|(wc&0x3F)). No code point in that range is overlong or
        // a UTF-16 surrogate, so a range-validated window is byte-for-byte what
        // scalar `wctomb` produces. Build 16 output bytes by interleaving the lead
        // and continuation lanes. Any wchar outside the range (ASCII, 3/4-byte,
        // surrogate, out-of-range) or insufficient room (< 16 bytes) drops to the
        // scalar step. Covers the common 2-byte scripts (Cyrillic/Greek/…).
        // 1-char lookahead gate: a lone 2-byte char in mostly-ASCII text (café, ñ)
        // would enter here, do a full 8-wide load+range-check that breaks on the
        // very next (ASCII) lane, and fall to scalar anyway. Requiring src[si+1] to
        // also be 2-byte skips that wasted wide load; byte-identical because any
        // window whose 2nd lane disqualifies it would break on the `.all()` below.
        while si + 8 <= src.len()
            && di + 16 <= dest.len()
            && (0x80..=0x7FF).contains(&src[si])
            && (0x80..=0x7FF).contains(&src[si + 1])
        {
            let ws: [u32; 8] = src[si..si + 8].try_into().unwrap();
            let v = Simd::<u32, 8>::from_array(ws);
            if !(v.simd_ge(Simd::splat(0x80)) & v.simd_le(Simd::splat(0x7FF))).all() {
                break; // a non-2-byte wchar in the window — let the scalar step run
            }
            let leads = ((v >> Simd::splat(6)) | Simd::splat(0xC0)).cast::<u8>();
            let conts = ((v & Simd::splat(0x3F)) | Simd::splat(0x80)).cast::<u8>();
            let bytes = std::simd::simd_swizzle!(
                leads,
                conts,
                [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
            );
            bytes.copy_to_slice(&mut dest[di..di + 16]);
            si += 8;
            di += 16;
        }

        // SIMD 3-byte encode fast path for BMP non-surrogate runs. Each clean
        // window maps four code points in 0x0800..=0xFFFF, excluding UTF-16
        // surrogates, to four fixed-width UTF-8 triples. ASCII, 2-byte, astral,
        // surrogate, out-of-range, and short-output cases fall through to the
        // scalar wctomb step, preserving its exact error and truncation behavior.
        while si + 4 <= src.len()
            && di + 12 <= dest.len()
            && (0x0800..=0xFFFF).contains(&src[si])
            && (0x0800..=0xFFFF).contains(&src[si + 1])
        {
            let ws: [u32; 4] = src[si..si + 4].try_into().unwrap();
            let v = Simd::<u32, 4>::from_array(ws);
            let bmp_ok = v.simd_ge(Simd::splat(0x0800)) & v.simd_le(Simd::splat(0xFFFF));
            let surrogate_ok = v.simd_lt(Simd::splat(0xD800)) | v.simd_gt(Simd::splat(0xDFFF));
            if !(bmp_ok & surrogate_ok).all() {
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
            dest[di..di + 12].copy_from_slice(&packed[..12]);
            si += 4;
            di += 12;
        }

        // SIMD 4-byte encode fast path for scalar wctomb's RFC 2279 4-byte
        // branch. Each clean window maps four code points in
        // 0x1_0000..0x20_0000 to exactly sixteen output bytes. ASCII, 2/3-byte,
        // 5/6-byte, invalid, NUL, mixed-window, and short-output cases fall
        // through to scalar `wctomb`, preserving glibc-compatible semantics.
        while si + 4 <= src.len()
            && di + 16 <= dest.len()
            && (0x1_0000..0x20_0000).contains(&src[si])
            && (0x1_0000..0x20_0000).contains(&src[si + 1])
        {
            let ws: [u32; 4] = src[si..si + 4].try_into().unwrap();
            let v = Simd::<u32, 4>::from_array(ws);
            if !(v.simd_ge(Simd::splat(0x1_0000)) & v.simd_lt(Simd::splat(0x20_0000))).all() {
                break;
            }

            let leads = ((v >> Simd::splat(18)) | Simd::splat(0xF0)).cast::<u8>();
            let cont1 =
                (((v >> Simd::splat(12)) & Simd::splat(0x3F)) | Simd::splat(0x80)).cast::<u8>();
            let cont2 =
                (((v >> Simd::splat(6)) & Simd::splat(0x3F)) | Simd::splat(0x80)).cast::<u8>();
            let cont3 = ((v & Simd::splat(0x3F)) | Simd::splat(0x80)).cast::<u8>();
            let lead_cont1 = std::simd::simd_swizzle!(leads, cont1, [0, 4, 1, 5, 2, 6, 3, 7]);
            let cont2_cont3 = std::simd::simd_swizzle!(cont2, cont3, [0, 4, 1, 5, 2, 6, 3, 7]);
            let bytes = std::simd::simd_swizzle!(
                lead_cont1,
                cont2_cont3,
                [0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15]
            );
            bytes.copy_to_slice(&mut dest[di..di + 16]);
            si += 4;
            di += 16;
        }

        // One scalar step, then re-attempt the SIMD run.
        if si >= src.len() {
            return Some(di);
        }
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
}

// Wide character classification (`<wctype.h>` `isw*` predicates).
//
// All twelve predicates are driven by [`super::wctype_table::ctype_mask`], a
// run-length-encoded class-bit table generated offline from the host glibc
// `isw*` over every scalar value in a UTF-8 locale (bd-2g7oyh.254). This makes
// the whole wide-ctype surface glibc-exact: the former hand-coded ranges and
// Rust `char` Unicode classifiers diverged from glibc's UTF-8 ctype tables on
// hundreds of thousands of code points (`iswprint` over-accepted unassigned
// scalars; `iswalpha`/`iswalnum` mis-categorised Arabic-Indic digits; titlecase
// letters were mishandled by `iswlower`/`iswupper`). The lookup is a branchless
// binary search — the runtime stays 100% safe Rust.
use super::wctype_table::{
    self, ALNUM, ALPHA, BLANK, CNTRL, DIGIT, GRAPH, LOWER, PRINT, PUNCT, SPACE, UPPER, XDIGIT,
};

/// Wide character classification: is `wc` an alphanumeric character?
pub fn iswalnum(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & ALNUM != 0
}

/// Wide character classification: is `wc` an alphabetic character?
pub fn iswalpha(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & ALPHA != 0
}

/// Wide character classification: is `wc` a blank (horizontal whitespace)?
pub fn iswblank(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & BLANK != 0
}

/// Wide character classification: is `wc` a control character?
pub fn iswcntrl(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & CNTRL != 0
}

/// Wide character classification: is `wc` a digit?
pub fn iswdigit(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & DIGIT != 0
}

/// Wide character classification: is `wc` a graphic (printable non-space)?
pub fn iswgraph(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & GRAPH != 0
}

/// Wide character classification: is `wc` a lowercase letter?
pub fn iswlower(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & LOWER != 0
}

/// Wide character classification: is `wc` an uppercase letter?
pub fn iswupper(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & UPPER != 0
}

/// Wide character classification: is `wc` a whitespace character?
pub fn iswspace(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & SPACE != 0
}

/// Wide character classification: is `wc` a printable character?
pub fn iswprint(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & PRINT != 0
}

/// Wide character classification: is `wc` a punctuation character?
pub fn iswpunct(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & PUNCT != 0
}

/// Wide character classification: is `wc` a hexadecimal digit?
pub fn iswxdigit(wc: u32) -> bool {
    wctype_table::ctype_mask(wc) & XDIGIT != 0
}

/// Convert wide character to uppercase, matching glibc's `towupper(3)` in a
/// UTF-8 locale.
///
/// Driven by [`super::towcase_table::towupper`], a delta table generated offline
/// from the host glibc over every scalar value (bd-2g7oyh.254 follow-up). This
/// is glibc-exact by construction: it captures glibc's single-character mappings
/// (including the Greek ypogegrammeni titlecase forms) and naturally omits the
/// 1:N full-case expansions (ß→SS, ǰ→J̌) that glibc leaves unchanged, with no
/// dependence on Rust's Unicode version. The lookup is a branchless binary
/// search — the runtime stays 100% safe Rust.
pub fn towupper(wc: u32) -> u32 {
    super::towcase_table::towupper(wc)
}

/// Convert wide character to lowercase, matching glibc's `towlower(3)` in a
/// UTF-8 locale. See [`towupper`].
pub fn towlower(wc: u32) -> u32 {
    super::towcase_table::towlower(wc)
}

/// Compute the display width of a wide character, matching glibc `wcwidth(3)`
/// in a UTF-8 locale: `0` for NUL and zero-width chars (combining marks, format
/// controls, BOM, variation selectors), `-1` for control chars / unassigned /
/// noncharacters, `2` for wide East Asian + emoji, `1` otherwise.
///
/// Driven by [`super::wcwidth_table::WIDTH_TRANSITIONS`], a run-length-encoded
/// table generated offline from the host glibc over every scalar value, so the
/// result is glibc-exact across the whole code space (replacing the former
/// hand-coded range list which diverged on ~66k codepoints — bd-2g7oyh.194).
/// The lookup is a branchless binary search; values above `U+10FFFF` (e.g. a
/// negative `wchar_t` widened to `u32`) are not scalar values, so `-1`.
pub fn wcwidth(wc: u32) -> i32 {
    // The BMP (the overwhelmingly common case for terminal width work) is served
    // by a lazily-built direct `[i8; 0x10000]` lookup, replacing a per-character
    // `partition_point` binary search over 2144 transitions (~11 scattered,
    // cache-missing probes). Built once by calling `wcwidth_transitions` for
    // every BMP code point, so each entry is byte-for-byte what the binary search
    // returns — and astral code points still take that exact path. O(1) per char,
    // single hot cache line for runs of nearby characters.
    if wc < 0x10000 {
        static BMP_WIDTH: std::sync::OnceLock<Box<[i8; 0x10000]>> = std::sync::OnceLock::new();
        let table = BMP_WIDTH.get_or_init(|| {
            let mut t = Box::new([0i8; 0x10000]);
            for (cp, slot) in t.iter_mut().enumerate() {
                *slot = wcwidth_transitions(cp as u32) as i8;
            }
            t
        });
        return table[wc as usize] as i32;
    }
    wcwidth_transitions(wc)
}

/// Exact width via the sorted transition table — the canonical result the BMP
/// direct table is built from, and the path astral code points take directly.
fn wcwidth_transitions(wc: u32) -> i32 {
    if wc > 0x10FFFF {
        return -1;
    }
    let table = &super::wcwidth_table::WIDTH_TRANSITIONS;
    // Last transition whose start <= wc; the table always begins at (0, _), so
    // `partition_point` returns at least 1 for any in-range `wc`.
    let idx = table.partition_point(|&(start, _)| start <= wc);
    table[idx - 1].1 as i32
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
        // Pure 3-byte BMP runs around the 4-codepoint SIMD window, including
        // the legal boundaries adjacent to overlongs and surrogate exclusions.
        for len in 0..40usize {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(match i % 5 {
                    0 => 0x0800,
                    1 => 0x20AC,
                    2 => 0x4E00 + (i as u32 % 0x100),
                    3 => 0xD7FF,
                    _ => 0xE000,
                });
            }
            corpus.push(v);
        }
        // Pure 4-byte runs around the 4-codepoint SIMD window. The upper cases
        // intentionally cover scalar wctomb's glibc-compatible RFC 2279 range,
        // not just Unicode scalar values through U+10FFFF.
        for len in 0..40usize {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(match i % 5 {
                    0 => 0x1_0000,
                    1 => 0x1F600 + (i as u32 % 0x80),
                    2 => 0x10_FFFF,
                    3 => 0x11_0000 + (i as u32 % 0x100),
                    _ => 0x1F_FFFF,
                });
            }
            corpus.push(v);
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
    fn wcs_ascii_prefix_helpers_match_scalar() {
        fn ref_len(src: &[u32]) -> usize {
            let mut k = 0;
            while k < src.len() && src[k] != 0 && src[k] < 0x80 {
                k += 1;
            }
            k
        }
        // Varied wide corpus: ASCII codepoints around the 16-lane boundary, with
        // an embedded NUL / non-ASCII codepoint at each offset.
        let mut corpus: Vec<Vec<u32>> = Vec::new();
        for len in 0..80usize {
            corpus.push((0..len).map(|i| (b'a' as u32) + (i as u32 % 26)).collect());
        }
        for len in 1..40usize {
            for pos in 0..len {
                let mut v: Vec<u32> = (0..len).map(|_| b'x' as u32).collect();
                v[pos] = 0;
                corpus.push(v.clone());
                v[pos] = 0x1F600; // non-ASCII codepoint
                corpus.push(v);
            }
        }
        for src in &corpus {
            let want_len = ref_len(src);
            assert_eq!(
                wcs_ascii_prefix_len(src),
                want_len,
                "wcs_ascii_prefix_len {src:?}"
            );
            for cap in [0usize, 1, 7, 16, 17, 40, 100] {
                let mut dest = vec![0u8; cap];
                let k = wcs_ascii_prefix(&mut dest, src);
                assert_eq!(k, want_len.min(cap), "wcs_ascii_prefix k {src:?} cap={cap}");
                for j in 0..k {
                    assert_eq!(dest[j], src[j] as u8, "narrow {src:?} j={j}");
                }
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
        // Pure 3-byte runs around the 12-byte SIMD window and 16-byte load
        // boundary, including CJK and the edge ranges that exclude overlongs
        // and surrogates.
        for len in 0..40usize {
            let mut v = Vec::with_capacity(len * 3);
            for i in 0..len {
                let wc = match i % 5 {
                    0 => 0x0800u32,
                    1 => 0x20AC,
                    2 => 0x4E00 + (i as u32 % 0x100),
                    3 => 0xD7FF,
                    _ => 0xE000,
                };
                let ch = char::from_u32(wc).unwrap();
                let mut buf = [0u8; 4];
                v.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            corpus.push(v);
        }
        // Pure 4-byte runs around the 16-byte SIMD window. Include scalar
        // decoder-compatible values above U+10FFFF because glibc's converter and
        // `utf8_decode_step` accept F5..=F7 4-byte forms.
        for len in 0..40usize {
            let mut v = Vec::with_capacity(len * 4);
            for i in 0..len {
                let wc = match i % 5 {
                    0 => 0x1_0000u32,
                    1 => 0x1F600 + (i as u32 % 0x80),
                    2 => 0x10_FFFF,
                    3 => 0x11_0000 + (i as u32 % 0x100),
                    _ => 0x1F_FFFF,
                };
                let mut buf = [0u8; 6];
                let n = wctomb(wc, &mut buf).unwrap();
                assert_eq!(n, 4);
                v.extend_from_slice(&buf[..n]);
            }
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

    // Golden isomorphism: the direct BMP table (and the astral path) must return
    // byte-for-byte what the pure transition-table binary search produces for
    // EVERY code point 0..=0x10FFFF (plus an out-of-range probe).
    #[test]
    fn wcwidth_direct_table_matches_binary_search() {
        fn reference(wc: u32) -> i32 {
            if wc > 0x10FFFF {
                return -1;
            }
            let table = &super::super::wcwidth_table::WIDTH_TRANSITIONS;
            let idx = table.partition_point(|&(start, _)| start <= wc);
            table[idx - 1].1 as i32
        }
        for cp in 0..=0x10FFFFu32 {
            assert_eq!(wcwidth(cp), reference(cp), "wcwidth mismatch at U+{cp:04X}");
        }
        assert_eq!(wcwidth(0x11_0000), -1);
        assert_eq!(wcwidth(0xFFFF_FFFF), -1);
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
