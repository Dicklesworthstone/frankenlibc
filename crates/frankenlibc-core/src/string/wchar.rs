//! Multibyte ↔ wide character conversion (UTF-8 only).
//!
//! Implements `<wchar.h>` / `<stdlib.h>` conversion functions assuming UTF-8
//! encoding. This is appropriate for the "C.UTF-8" / "POSIX.UTF-8" locale.

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
pub fn iswspace(wc: u32) -> bool {
    char::from_u32(wc).is_some_and(|c| c.is_whitespace())
}

/// Wide character classification: is `wc` a printable character?
pub fn iswprint(wc: u32) -> bool {
    // Rough approximation: not a control character and is a valid Unicode char
    char::from_u32(wc).is_some_and(|c| !c.is_control())
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

/// Compute display width of a wide character (simplified).
///
/// Returns 0 for NUL, -1 for non-printable, 2 for CJK/fullwidth, 1 otherwise.
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
    // CJK Unified Ideographs and common fullwidth ranges
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
}
