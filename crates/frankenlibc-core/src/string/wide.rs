//! Wide-character string operations: wcslen, wcscpy, wcscmp.
//!
//! Corresponds to `<wchar.h>` functions. These operate on `u32` slices
//! representing `wchar_t` strings (NUL-terminated with `0u32`).

/// Returns the length of a NUL-terminated wide string (not counting the NUL).
///
/// Equivalent to C `wcslen`. Scans `s` for the first `0u32` element.
/// If no NUL is found, returns the full slice length.
pub fn wcslen(s: &[u32]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Returns the length of a wide string, bounded by `maxlen`.
///
/// Equivalent to C `wcsnlen`.
pub fn wcsnlen(s: &[u32], maxlen: usize) -> usize {
    let limit = maxlen.min(s.len());
    s.iter().take(limit).position(|&c| c == 0).unwrap_or(limit)
}

/// Computes the display width of up to `n` wide characters.
///
/// Equivalent to C `wcswidth`. Returns `-1` if any character is non-printable.
pub fn wcswidth(s: &[u32], n: usize) -> i32 {
    let mut total = 0_i32;
    for &wc in s.iter().take(n) {
        if wc == 0 {
            break;
        }
        let width = super::wchar::wcwidth(wc);
        if width < 0 {
            return -1;
        }
        total = total.saturating_add(width);
    }
    total
}

/// Copies a NUL-terminated wide string from `src` into `dest`.
///
/// Equivalent to C `wcscpy`. Copies elements from `src` until (and including)
/// the NUL terminator. Returns the number of elements copied (including NUL).
///
/// # Panics
///
/// Panics if `dest` is too small to hold `src` plus the NUL terminator.
pub fn wcscpy(dest: &mut [u32], src: &[u32]) -> usize {
    let src_len = wcslen(src);
    assert!(
        dest.len() > src_len,
        "wcscpy: destination buffer too small ({} elements for {} element string + NUL)",
        dest.len(),
        src_len
    );
    dest[..src_len].copy_from_slice(&src[..src_len]);
    dest[src_len] = 0;
    src_len + 1
}

/// Copies a wide string from `src` into `dest` with a size limit.
///
/// Equivalent to C `wcsncpy`. Copies at most `n` wide characters.
/// If `src` is shorter than `n`, the remaining elements in `dest` are filled with NULs.
/// If `src` is longer or equal to `n`, `dest` will NOT be NUL-terminated.
///
/// Returns `dest`.
///
/// # Panics
///
/// Panics if `dest` is smaller than `n`.
pub fn wcsncpy(dest: &mut [u32], src: &[u32], n: usize) {
    assert!(
        dest.len() >= n,
        "wcsncpy: destination buffer too small ({} elements for request {})",
        dest.len(),
        n
    );
    let src_len = wcslen(src);
    let copy_len = src_len.min(n);

    // Copy characters
    dest[..copy_len].copy_from_slice(&src[..copy_len]);

    // Pad with NULs if necessary
    if copy_len < n {
        dest[copy_len..n].fill(0);
    }
}

/// Appends the wide string `src` to the end of `dest`.
///
/// Equivalent to C `wcscat`. Finds the NUL terminator in `dest` and overwrites it
/// with the contents of `src` (including `src`'s NUL terminator).
///
/// Returns the new length of `dest` (including NUL).
///
/// # Panics
///
/// Panics if `dest` does not have enough space after its current NUL terminator
/// to hold `src`.
pub fn wcscat(dest: &mut [u32], src: &[u32]) -> usize {
    let dest_len = wcslen(dest);
    let src_len = wcslen(src);
    let needed = dest_len + src_len + 1;

    assert!(
        dest.len() >= needed,
        "wcscat: destination buffer too small ({} elements for {} needed)",
        dest.len(),
        needed
    );

    dest[dest_len..dest_len + src_len].copy_from_slice(&src[..src_len]);
    dest[dest_len + src_len] = 0;
    needed
}

/// Compares two NUL-terminated wide strings lexicographically.
///
/// Equivalent to C `wcscmp`. Compares element-by-element until a difference
/// is found or both strings reach a NUL terminator.
///
/// Returns a negative value if `s1 < s2`, zero if equal, positive if `s1 > s2`.
/// Performs signed comparison (treating `u32` as `i32`) to match Linux `wchar_t`.
pub fn wcscmp(s1: &[u32], s2: &[u32]) -> i32 {
    let mut i = 0;
    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            // wchar_t is i32 on Linux, so we must compare as signed.
            if (a as i32) < (b as i32) {
                return -1;
            } else {
                return 1;
            }
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Compares at most `n` wide characters of two strings.
///
/// Equivalent to C `wcsncmp`.
pub fn wcsncmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            if (a as i32) < (b as i32) {
                return -1;
            } else {
                return 1;
            }
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// Locates the first occurrence of wide character `c` in string `s`.
///
/// Equivalent to C `wcschr`. Returns the index of the character, or `None` if not found.
/// The terminating NUL character is considered part of the string.
pub fn wcschr(s: &[u32], c: u32) -> Option<usize> {
    for (i, &ch) in s.iter().enumerate() {
        if ch == c {
            return Some(i);
        }
        if ch == 0 {
            // NUL matched c?
            if c == 0 {
                return Some(i);
            }
            return None;
        }
    }
    None
}

/// Locates the last occurrence of wide character `c` in string `s`.
///
/// Equivalent to C `wcsrchr`. Returns the index of the character, or `None` if not found.
/// The terminating NUL character is considered part of the string.
pub fn wcsrchr(s: &[u32], c: u32) -> Option<usize> {
    let len = wcslen(s);
    if c == 0 {
        return Some(len);
    }
    // Scan backwards from the end of the string (not including NUL)
    (0..len).rev().find(|&i| s[i] == c)
}

/// Locates the first occurrence of substring `needle` in `haystack`.
///
/// Equivalent to C `wcsstr`. Returns the index of the start of the substring,
/// or `None` if not found.
pub fn wcsstr(haystack: &[u32], needle: &[u32]) -> Option<usize> {
    let needle_len = wcslen(needle);
    let haystack_len = wcslen(haystack);

    if needle_len == 0 {
        return Some(0);
    }
    if needle_len > haystack_len {
        return None;
    }

    for i in 0..=(haystack_len - needle_len) {
        if haystack[i..i + needle_len] == needle[..needle_len] {
            return Some(i);
        }
    }
    None
}

/// Copies `n` wide characters from `src` to `dest`.
///
/// Equivalent to C `wmemcpy`.
pub fn wmemcpy(dest: &mut [u32], src: &[u32], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies `n` wide characters from `src` to `dest`, handling overlap.
///
/// Equivalent to C `wmemmove`.
pub fn wmemmove(dest: &mut [u32], src: &[u32], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Fills `n` wide characters of `dest` with `c`.
///
/// Equivalent to C `wmemset`.
pub fn wmemset(dest: &mut [u32], c: u32, n: usize) -> usize {
    let count = n.min(dest.len());
    dest[..count].fill(c);
    count
}

/// Compares `n` wide characters.
///
/// Equivalent to C `wmemcmp`.
/// Performs signed comparison (treating `u32` as `i32`) to match Linux `wchar_t`.
pub fn wmemcmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
    let count = n.min(s1.len()).min(s2.len());
    for i in 0..count {
        let a = s1[i] as i32;
        let b = s2[i] as i32;
        if a != b {
            return if a < b { -1 } else { 1 };
        }
    }
    0
}

/// Locates the first occurrence of `c` in the first `n` wide characters of `s`.
///
/// Equivalent to C `wmemchr`.
pub fn wmemchr(s: &[u32], c: u32, n: usize) -> Option<usize> {
    let count = n.min(s.len());
    s[..count].iter().position(|&x| x == c)
}

/// Appends at most `n` wide characters from `src` to `dest`, plus a NUL terminator.
///
/// Equivalent to C `wcsncat`. Returns the new total length (including NUL).
///
/// # Panics
///
/// Panics if `dest` doesn't have enough space.
pub fn wcsncat(dest: &mut [u32], src: &[u32], n: usize) -> usize {
    let dest_len = wcslen(dest);
    let src_len = wcslen(src);
    let copy_len = src_len.min(n);
    let needed = dest_len + copy_len + 1;

    assert!(
        dest.len() >= needed,
        "wcsncat: destination buffer too small ({} elements for {} needed)",
        dest.len(),
        needed
    );

    dest[dest_len..dest_len + copy_len].copy_from_slice(&src[..copy_len]);
    dest[dest_len + copy_len] = 0;
    needed
}

/// Returns the bytes needed to duplicate a wide string (including NUL),
/// and the string length (excluding NUL).
///
/// This is the core of `wcsdup` — the ABI layer handles allocation.
pub fn wcsdup_len(s: &[u32]) -> usize {
    wcslen(s)
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// wide characters in `accept`.
///
/// Equivalent to C `wcsspn`.
pub fn wcsspn(s: &[u32], accept: &[u32]) -> usize {
    let accept_len = wcslen(accept);
    let accept_set = &accept[..accept_len];

    for (i, &ch) in s.iter().enumerate() {
        if ch == 0 {
            return i;
        }
        if !accept_set.contains(&ch) {
            return i;
        }
    }
    s.len()
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// wide characters NOT in `reject`.
///
/// Equivalent to C `wcscspn`.
pub fn wcscspn(s: &[u32], reject: &[u32]) -> usize {
    let reject_len = wcslen(reject);
    let reject_set = &reject[..reject_len];

    for (i, &ch) in s.iter().enumerate() {
        if ch == 0 {
            return i;
        }
        if reject_set.contains(&ch) {
            return i;
        }
    }
    s.len()
}

/// Locates the first occurrence in `s` of any wide character in `accept`.
///
/// Equivalent to C `wcspbrk`. Returns the index of the first match, or `None`.
pub fn wcspbrk(s: &[u32], accept: &[u32]) -> Option<usize> {
    let accept_len = wcslen(accept);
    let accept_set = &accept[..accept_len];

    for (i, &ch) in s.iter().enumerate() {
        if ch == 0 {
            return None;
        }
        if accept_set.contains(&ch) {
            return Some(i);
        }
    }
    None
}

/// Tokenizes a wide string, similar to C `wcstok`.
///
/// Takes a mutable slice, a set of delimiter characters, and the offset to
/// resume from. Returns `Some((token_start, next_state))` or `None` if no
/// more tokens.
pub fn wcstok(s: &mut [u32], delim: &[u32], start: usize) -> Option<(usize, usize)> {
    let delim_len = wcslen(delim);
    let delim_set = &delim[..delim_len];

    // Skip leading delimiters
    let mut pos = start;
    while pos < s.len() && s[pos] != 0 && delim_set.contains(&s[pos]) {
        pos += 1;
    }

    if pos >= s.len() || s[pos] == 0 {
        return None;
    }

    let token_start = pos;

    // Find end of token
    while pos < s.len() && s[pos] != 0 && !delim_set.contains(&s[pos]) {
        pos += 1;
    }

    // NUL-terminate the token if we hit a delimiter
    if pos < s.len() && s[pos] != 0 {
        s[pos] = 0;
        pos += 1;
    }

    Some((token_start, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wcslen_basic() {
        assert_eq!(wcslen(&[b'h' as u32, b'i' as u32, 0]), 2);
        assert_eq!(wcslen(&[0]), 0);
        assert_eq!(wcslen(&[65, 66, 67]), 3); // no NUL found
    }

    #[test]
    fn test_wcsnlen_basic() {
        let value = [b'a' as u32, b'b' as u32, 0, b'c' as u32];
        assert_eq!(wcsnlen(&value, 8), 2);
        assert_eq!(wcsnlen(&value, 1), 1);
        assert_eq!(wcsnlen(&[b'a' as u32, b'b' as u32], 8), 2);
    }

    #[test]
    fn test_wcswidth_basic() {
        let value = [b'A' as u32, '界' as u32, 0];
        assert_eq!(wcswidth(&value, 8), 3);
        assert_eq!(wcswidth(&value, 1), 1);
        assert_eq!(wcswidth(&[0x07, 0], 8), -1);
    }

    #[test]
    fn test_wcscpy_basic() {
        let src = [b'H' as u32, b'i' as u32, 0];
        let mut dest = [0u32; 4];
        let n = wcscpy(&mut dest, &src);
        assert_eq!(n, 3);
        assert_eq!(&dest[..3], &[b'H' as u32, b'i' as u32, 0]);
    }

    #[test]
    fn test_wcsncpy_basic() {
        let src = [b'H' as u32, b'i' as u32, 0];
        let mut dest = [0u32; 6];
        // Copy 2 chars, no NUL
        wcsncpy(&mut dest, &src, 2);
        assert_eq!(dest[0], b'H' as u32);
        assert_eq!(dest[1], b'i' as u32);
        assert_eq!(dest[2], 0); // Originally initialized to 0

        // Copy more than src length, check padding
        let mut dest2 = [0xFFFFu32; 6];
        wcsncpy(&mut dest2, &src, 5);
        assert_eq!(dest2[0], b'H' as u32);
        assert_eq!(dest2[1], b'i' as u32);
        assert_eq!(dest2[2], 0); // NUL from src
        assert_eq!(dest2[3], 0); // Padding
        assert_eq!(dest2[4], 0); // Padding
        assert_eq!(dest2[5], 0xFFFF); // Untouched
    }

    #[test]
    fn test_wcscat_basic() {
        let mut dest = [0u32; 10];
        dest[0] = b'H' as u32;
        dest[1] = 0;
        let src = [b'i' as u32, b'!' as u32, 0];
        wcscat(&mut dest, &src);
        assert_eq!(dest[0], b'H' as u32);
        assert_eq!(dest[1], b'i' as u32);
        assert_eq!(dest[2], b'!' as u32);
        assert_eq!(dest[3], 0);
    }

    #[test]
    fn test_wcscmp_equal() {
        assert_eq!(wcscmp(&[65, 66, 0], &[65, 66, 0]), 0);
    }

    #[test]
    fn test_wcscmp_less() {
        assert!(wcscmp(&[65, 0], &[66, 0]) < 0);
    }

    #[test]
    fn test_wcscmp_greater() {
        assert!(wcscmp(&[66, 0], &[65, 0]) > 0);
    }

    #[test]
    fn test_wcscmp_prefix() {
        assert!(wcscmp(&[65, 0], &[65, 66, 0]) < 0);
        assert!(wcscmp(&[65, 66, 0], &[65, 0]) > 0);
    }

    #[test]
    fn test_wcsncmp_basic() {
        // "ABC" vs "ABD", n=2 => equal
        assert_eq!(wcsncmp(&[65, 66, 67, 0], &[65, 66, 68, 0], 2), 0);
        // "ABC" vs "ABD", n=3 => less
        assert!(wcsncmp(&[65, 66, 67, 0], &[65, 66, 68, 0], 3) < 0);
    }

    #[test]
    fn test_wcschr_basic() {
        let s = [b'A' as u32, b'B' as u32, b'C' as u32, 0];
        assert_eq!(wcschr(&s, b'B' as u32), Some(1));
        assert_eq!(wcschr(&s, b'D' as u32), None);
        assert_eq!(wcschr(&s, 0), Some(3));
    }

    #[test]
    fn test_wcsrchr_basic() {
        let s = [b'A' as u32, b'B' as u32, b'A' as u32, 0];
        assert_eq!(wcsrchr(&s, b'A' as u32), Some(2));
        assert_eq!(wcsrchr(&s, b'C' as u32), None);
        assert_eq!(wcsrchr(&s, 0), Some(3));
    }

    #[test]
    fn test_wcsstr_basic() {
        let haystack = [b'A' as u32, b'B' as u32, b'C' as u32, b'D' as u32, 0];
        let needle = [b'B' as u32, b'C' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle), Some(1));

        let needle_not_found = [b'X' as u32, 0];
        assert_eq!(wcsstr(&haystack, &needle_not_found), None);

        let empty = [0u32];
        assert_eq!(wcsstr(&haystack, &empty), Some(0));
    }

    #[test]
    fn test_wmemcpy_basic() {
        let src = [1u32, 2, 3, 4];
        let mut dest = [0u32; 4];
        assert_eq!(wmemcpy(&mut dest, &src, 4), 4);
        assert_eq!(dest, src);
    }

    #[test]
    fn test_wmemmove_basic() {
        let src = [1u32, 2, 3, 4];
        let mut dest = [0u32; 4];
        assert_eq!(wmemmove(&mut dest, &src, 4), 4);
        assert_eq!(dest, src);
    }

    #[test]
    fn test_wmemset_basic() {
        let mut dest = [0u32; 4];
        assert_eq!(wmemset(&mut dest, 0x1234, 4), 4);
        assert_eq!(dest, [0x1234; 4]);
    }

    #[test]
    fn test_wmemcmp_basic() {
        let a = [1u32, 2, 3];
        let b = [1u32, 2, 4];
        assert_eq!(wmemcmp(&a, &a, 3), 0);
        assert_eq!(wmemcmp(&a, &b, 3), -1);
        assert_eq!(wmemcmp(&b, &a, 3), 1);
    }

    #[test]
    fn test_wmemchr_basic() {
        let haystack = [1u32, 2, 3, 4];
        assert_eq!(wmemchr(&haystack, 3, 4), Some(2));
        assert_eq!(wmemchr(&haystack, 5, 4), None);
    }

    #[test]
    fn test_wcsncat_basic() {
        let mut dest = [0u32; 10];
        dest[0] = b'H' as u32;
        dest[1] = 0;
        let src = [b'e' as u32, b'l' as u32, b'l' as u32, b'o' as u32, 0];
        wcsncat(&mut dest, &src, 2);
        assert_eq!(dest[0], b'H' as u32);
        assert_eq!(dest[1], b'e' as u32);
        assert_eq!(dest[2], b'l' as u32);
        assert_eq!(dest[3], 0);
    }

    #[test]
    fn test_wcsncat_full() {
        let mut dest = [0u32; 10];
        dest[0] = b'A' as u32;
        dest[1] = 0;
        let src = [b'B' as u32, b'C' as u32, 0];
        wcsncat(&mut dest, &src, 10); // n > src_len
        assert_eq!(dest[0], b'A' as u32);
        assert_eq!(dest[1], b'B' as u32);
        assert_eq!(dest[2], b'C' as u32);
        assert_eq!(dest[3], 0);
    }

    #[test]
    fn test_wcsdup_len() {
        let s = [b'H' as u32, b'i' as u32, 0];
        assert_eq!(wcsdup_len(&s), 2);
        assert_eq!(wcsdup_len(&[0u32]), 0);
    }

    #[test]
    fn test_wcsspn_basic() {
        let s = [b'a' as u32, b'b' as u32, b'c' as u32, b'x' as u32, 0];
        let accept = [b'a' as u32, b'b' as u32, b'c' as u32, 0];
        assert_eq!(wcsspn(&s, &accept), 3);
    }

    #[test]
    fn test_wcsspn_empty() {
        let s = [b'x' as u32, 0];
        let accept = [b'a' as u32, 0];
        assert_eq!(wcsspn(&s, &accept), 0);
    }

    #[test]
    fn test_wcscspn_basic() {
        let s = [b'a' as u32, b'b' as u32, b'c' as u32, b'x' as u32, 0];
        let reject = [b'x' as u32, b'y' as u32, 0];
        assert_eq!(wcscspn(&s, &reject), 3);
    }

    #[test]
    fn test_wcscspn_none_rejected() {
        let s = [b'a' as u32, b'b' as u32, 0];
        let reject = [b'x' as u32, 0];
        assert_eq!(wcscspn(&s, &reject), 2);
    }

    #[test]
    fn test_wcspbrk_basic() {
        let s = [b'a' as u32, b'b' as u32, b'c' as u32, 0];
        let accept = [b'c' as u32, b'd' as u32, 0];
        assert_eq!(wcspbrk(&s, &accept), Some(2));
    }

    #[test]
    fn test_wcspbrk_not_found() {
        let s = [b'a' as u32, b'b' as u32, 0];
        let accept = [b'x' as u32, 0];
        assert_eq!(wcspbrk(&s, &accept), None);
    }

    #[test]
    fn test_wcstok_basic() {
        let mut s = [
            b'h' as u32,
            b'e' as u32,
            b'l' as u32,
            b'l' as u32,
            b'o' as u32,
            b' ' as u32,
            b'w' as u32,
            b'o' as u32,
            b'r' as u32,
            b'l' as u32,
            b'd' as u32,
            0,
        ];
        let delim = [b' ' as u32, 0];

        // First token: "hello"
        let (start1, next1) = wcstok(&mut s, &delim, 0).unwrap();
        assert_eq!(start1, 0);
        assert_eq!(
            &s[start1..start1 + 5],
            &[
                b'h' as u32,
                b'e' as u32,
                b'l' as u32,
                b'l' as u32,
                b'o' as u32
            ]
        );

        // Second token: "world"
        let (start2, _) = wcstok(&mut s, &delim, next1).unwrap();
        assert_eq!(
            &s[start2..start2 + 5],
            &[
                b'w' as u32,
                b'o' as u32,
                b'r' as u32,
                b'l' as u32,
                b'd' as u32
            ]
        );
    }

    #[test]
    fn test_wcstok_no_more() {
        let mut s = [0u32];
        let delim = [b' ' as u32, 0];
        assert!(wcstok(&mut s, &delim, 0).is_none());
    }
}
