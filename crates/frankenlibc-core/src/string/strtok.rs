//! String tokenization: strtok (legacy) and strtok_r (reentrant).
//!
//! Corresponds to `strtok` and `strtok_r` from `<string.h>`.
//!
//! In this safe Rust model, `strtok` replaces delimiter bytes in the buffer
//! with NUL bytes and returns token boundaries as `(start, len)` pairs.

/// Returns true if byte `b` is in the NUL-terminated `delimiters` set. Retained
/// only as the reference semantics that [`DelimSet`]'s guard test checks against.
#[cfg(test)]
fn is_delim(b: u8, delimiters: &[u8]) -> bool {
    for &d in delimiters {
        if d == 0 {
            break;
        }
        if b == d {
            return true;
        }
    }
    false
}

/// A 256-bit membership bitmap of the delimiter set, built once per tokenization
/// call so each input byte is tested in O(1) (`bit b`) instead of re-scanning the
/// delimiter string per character — turning the scan from O(input × delims) into
/// O(input + delims). NUL terminates the delimiter list and is never a member, so
/// bit 0 is left clear (matching [`is_delim`]).
///
/// Retained only as a test reference: the tokenizers now reuse the SIMD
/// `strspn_set`/`strcspn_set` scanners (bd-2g7oyh), which carry the same NUL-break
/// membership; the guard test below pins that equivalence.
#[cfg(test)]
struct DelimSet {
    words: [u64; 4],
}

#[cfg(test)]
impl DelimSet {
    fn new(delimiters: &[u8]) -> Self {
        let mut words = [0u64; 4];
        for &d in delimiters {
            if d == 0 {
                break;
            }
            words[(d >> 6) as usize] |= 1u64 << (d & 63);
        }
        Self { words }
    }

    #[inline]
    fn contains(&self, b: u8) -> bool {
        (self.words[(b >> 6) as usize] >> (b & 63)) & 1 != 0
    }
}

/// Tokenizes a NUL-terminated byte string (thread-unsafe legacy version).
///
/// POSIX `strtok` uses internal static state, making it non-reentrant.
/// This safe Rust version modifies the buffer in-place, writing NUL bytes
/// over delimiter positions.
///
/// `s` is the byte string to tokenize (mutable so delimiters can be overwritten).
/// `delimiters` is a NUL-terminated byte slice of delimiter characters.
///
/// Returns the start index and length of the next token, or `None` if
/// no more tokens remain.
///
/// Callers must track the `save_ptr` returned by the first call and pass
/// it as the starting offset for subsequent scans. For the first call,
/// start scanning from index 0. For a stateful wrapper, use a `Cell<usize>`
/// or similar.
pub fn strtok(s: &mut [u8], delimiters: &[u8]) -> Option<(usize, usize)> {
    strtok_at(s, delimiters, 0)
}

/// Stateful tokenizer that scans starting from `offset`.
///
/// Returns `Some((token_start, token_len))` and writes a NUL over the
/// first delimiter after the token. Returns `None` if no tokens remain.
fn strtok_at(s: &mut [u8], delimiters: &[u8], offset: usize) -> Option<(usize, usize)> {
    let len = s.len();
    // Exact delimiter set (bytes up to the first NUL or slice end) — same membership
    // as DelimSet, without strlen-over-reading a non-NUL-terminated arg.
    let dn = delimiters.iter().position(|&b| b == 0).unwrap_or(delimiters.len());
    let delim_set = &delimiters[..dn];
    let mut pos = offset.min(len);

    // Skip leading delimiters (SIMD strspn over the exact set — was a scalar
    // per-byte DelimSet loop, ~3x slower than glibc on long runs; bd-2g7oyh).
    pos += crate::string::str::strspn_set(&s[pos..], delim_set);

    if pos >= len || s[pos] == 0 {
        return None;
    }

    let token_start = pos;

    // Find end of token (SIMD strcspn over the exact set).
    let token_len = crate::string::str::strcspn_set(&s[token_start..], delim_set);
    pos = token_start + token_len;

    // Write NUL terminator over the delimiter (if not already at end).
    if pos < len && s[pos] != 0 {
        s[pos] = 0;
    }

    Some((token_start, token_len))
}

/// Reentrant string tokenizer.
///
/// POSIX `strtok_r`. The `save_ptr` parameter holds the position for the
/// next call, making this safe for concurrent use across different strings.
///
/// `s` is the NUL-terminated byte string to tokenize.
/// `delimiters` is a NUL-terminated byte slice of delimiter characters.
/// `save_ptr` is the saved position (initially 0 for the first call).
///
/// Returns `Some((token_start, token_len, new_save_ptr))` for the next
/// token, or `None` if no more tokens remain.
pub fn strtok_r(s: &mut [u8], delimiters: &[u8], save_ptr: usize) -> Option<(usize, usize, usize)> {
    let len = s.len();
    let dn = delimiters.iter().position(|&b| b == 0).unwrap_or(delimiters.len());
    let delim_set = &delimiters[..dn];
    let mut pos = save_ptr.min(len);

    // Skip leading delimiters (SIMD strspn over the exact set; bd-2g7oyh).
    pos += crate::string::str::strspn_set(&s[pos..], delim_set);

    // Check if we've exhausted the string
    if pos >= len || s[pos] == 0 {
        return None;
    }

    let token_start = pos;

    // Find end of token (SIMD strcspn over the exact set).
    let token_len = crate::string::str::strcspn_set(&s[token_start..], delim_set);
    pos = token_start + token_len;

    // Write NUL terminator and advance save pointer
    if pos < len && s[pos] != 0 {
        s[pos] = 0;
        pos += 1;
    }

    Some((token_start, token_len, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimset_matches_is_delim_reference() {
        // The bitmap must encode exactly the same membership as the reference
        // is_delim loop, for every possible input byte and across delimiter sets
        // that span word boundaries (bytes 63/64/127/128/255).
        let delim_sets: &[&[u8]] = &[
            b"\0",
            b" \t\n\0",
            b",;:\0",
            b"abcXYZ \0",
            b"\x3f\x40\x7f\x80\xff\0", // 63,64,127,128,255
            b"\xff\xfe\xfd\0",
        ];
        for delims in delim_sets {
            let set = DelimSet::new(delims);
            for b in 0..=255u8 {
                assert_eq!(
                    set.contains(b),
                    is_delim(b, delims),
                    "DelimSet mismatch for byte {b} in delims {delims:?}"
                );
            }
        }
    }

    #[test]
    fn test_strtok_r_basic() {
        let mut buf = *b"hello world foo\0";
        let delim = b" \0";

        let (start, len, save) = strtok_r(&mut buf, delim, 0).unwrap();
        assert_eq!(&buf[start..start + len], b"hello");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"world");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"foo");

        assert!(strtok_r(&mut buf, delim, save).is_none());
    }

    #[test]
    fn test_strtok_r_multiple_delims() {
        let mut buf = *b"a,,b,c\0";
        let delim = b",\0";

        let (start, len, save) = strtok_r(&mut buf, delim, 0).unwrap();
        assert_eq!(&buf[start..start + len], b"a");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"b");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"c");

        assert!(strtok_r(&mut buf, delim, save).is_none());
    }

    #[test]
    fn test_strtok_r_leading_delims() {
        let mut buf = *b"  hello\0";
        let delim = b" \0";

        let (start, len, _) = strtok_r(&mut buf, delim, 0).unwrap();
        assert_eq!(&buf[start..start + len], b"hello");
    }

    #[test]
    fn test_strtok_r_empty() {
        let mut buf = *b"\0";
        let delim = b" \0";
        assert!(strtok_r(&mut buf, delim, 0).is_none());
    }

    #[test]
    fn test_strtok_r_all_delims() {
        let mut buf = *b"   \0";
        let delim = b" \0";
        assert!(strtok_r(&mut buf, delim, 0).is_none());
    }

    #[test]
    fn test_strtok_basic() {
        let mut buf = *b"a-b-c\0";
        let delim = b"-\0";

        let result = strtok(&mut buf, delim);
        assert!(result.is_some());
        let (start, len) = result.unwrap();
        assert_eq!(&buf[start..start + len], b"a");
    }
}
