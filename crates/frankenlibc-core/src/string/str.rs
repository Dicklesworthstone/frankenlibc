//! String operations: strlen, strnlen, strcmp, strncmp, strcpy, stpcpy, strncpy,
//! stpncpy, strcat, strncat, strchr, strchrnul, strrchr, strstr.
//!
//! These are safe Rust implementations operating on byte slices that represent
//! NUL-terminated C strings. In this safe Rust model, strings are `&[u8]` slices
//! where a NUL byte (`0x00`) marks the logical end of the string.

/// Returns the length of a NUL-terminated byte string (not counting the NUL).
///
/// Equivalent to C `strlen`. Scans `s` for the first `0x00` byte and returns
/// its index. If no NUL is found, returns the full slice length.
pub fn strlen(s: &[u8]) -> usize {
    s.iter().position(|&b| b == 0).unwrap_or(s.len())
}

/// Returns the length of a C string up to a maximum of `maxlen` bytes.
///
/// Equivalent to C `strnlen`. Scans at most `maxlen` bytes and returns:
/// - index of first `0x00` byte if found before `maxlen`
/// - otherwise `maxlen` (or `s.len()` when the slice is shorter)
pub fn strnlen(s: &[u8], maxlen: usize) -> usize {
    let limit = maxlen.min(s.len());
    s.iter().take(limit).position(|&b| b == 0).unwrap_or(limit)
}

/// Compares two NUL-terminated byte strings lexicographically.
///
/// Equivalent to C `strcmp`. Compares byte-by-byte until a difference is found
/// or both strings reach a NUL terminator.
///
/// Returns a negative value if `s1 < s2`, zero if equal, positive if `s1 > s2`.
pub fn strcmp(s1: &[u8], s2: &[u8]) -> i32 {
    let mut i = 0;
    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            return (a as i32) - (b as i32);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Compares at most `n` bytes of two NUL-terminated byte strings.
///
/// Equivalent to C `strncmp`. Like [`strcmp`], but stops after `n` bytes.
pub fn strncmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            return (a as i32) - (b as i32);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

/// Copies a NUL-terminated string from `src` into `dest`.
///
/// Equivalent to C `strcpy`. Copies bytes from `src` until (and including)
/// the NUL terminator. Returns the number of bytes copied (including the NUL).
///
/// # Panics
///
/// Panics if `dest` is too small to hold the source string plus NUL.
pub fn strcpy(dest: &mut [u8], src: &[u8]) -> usize {
    let src_len = strlen(src);
    assert!(
        dest.len() > src_len,
        "strcpy: destination buffer too small ({} bytes for {} byte string + NUL)",
        dest.len(),
        src_len
    );
    dest[..src_len].copy_from_slice(&src[..src_len]);
    dest[src_len] = 0;
    src_len + 1
}

/// Copies a NUL-terminated string from `src` into `dest` and returns the
/// index of the trailing NUL byte in `dest`.
///
/// Equivalent to C `stpcpy`. Return value models the pointer arithmetic as an
/// index relative to `dest`.
pub fn stpcpy(dest: &mut [u8], src: &[u8]) -> usize {
    let copied = strcpy(dest, src);
    copied.saturating_sub(1)
}

/// Copies at most `n` bytes from `src` into `dest`.
///
/// Equivalent to C `strncpy`. If `src` is shorter than `n`, the remainder of
/// `dest` is filled with NUL bytes. If `src` is `n` or longer, `dest` will
/// NOT be NUL-terminated.
///
/// Returns the number of bytes written to `dest` (always `min(n, dest.len())`).
pub fn strncpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len());
    let src_len = strlen(src);
    let copy_len = src_len.min(count);

    dest[..copy_len].copy_from_slice(&src[..copy_len]);

    // Pad remainder with NUL bytes.
    for byte in &mut dest[copy_len..count] {
        *byte = 0;
    }

    count
}

/// Copies at most `n` bytes from `src` into `dest` and returns the index
/// corresponding to C `stpncpy`'s returned pointer.
///
/// If `src` is shorter than `n`, returns the index of the first written NUL.
/// Otherwise returns `min(n, dest.len())`.
pub fn stpncpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = strncpy(dest, src, n);
    let src_len = strlen(src);
    if src_len < count { src_len } else { count }
}

/// Appends `src` to the end of the NUL-terminated string in `dest`.
///
/// Equivalent to C `strcat`. Finds the NUL in `dest`, then copies `src`
/// (up to and including its NUL) after it.
///
/// Returns the total length of the resulting string (not counting the NUL).
///
/// # Panics
///
/// Panics if `dest` is too small.
pub fn strcat(dest: &mut [u8], src: &[u8]) -> usize {
    let dest_len = strlen(dest);
    let src_len = strlen(src);
    let total = dest_len + src_len;
    assert!(
        dest.len() > total,
        "strcat: destination buffer too small ({} bytes for {} byte result + NUL)",
        dest.len(),
        total,
    );
    dest[dest_len..dest_len + src_len].copy_from_slice(&src[..src_len]);
    dest[total] = 0;
    total
}

/// Appends at most `n` bytes from `src` to the NUL-terminated string in `dest`.
///
/// Equivalent to C `strncat`. Always NUL-terminates the result.
///
/// Returns the total length of the resulting string (not counting the NUL).
///
/// # Panics
///
/// Panics if `dest` is too small.
pub fn strncat(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let dest_len = strlen(dest);
    let src_len = strlen(src).min(n);
    let total = dest_len + src_len;
    assert!(
        dest.len() > total,
        "strncat: destination buffer too small ({} bytes for {} byte result + NUL)",
        dest.len(),
        total,
    );
    dest[dest_len..dest_len + src_len].copy_from_slice(&src[..src_len]);
    dest[total] = 0;
    total
}

/// Locates the first occurrence of `c` in the NUL-terminated string `s`.
///
/// Equivalent to C `strchr`. Returns the index of the first byte equal to `c`,
/// or `None` if not found before the NUL terminator. If `c` is `0`, returns
/// the index of the NUL terminator.
pub fn strchr(s: &[u8], c: u8) -> Option<usize> {
    let len = strlen(s);
    if c == 0 {
        return Some(len);
    }
    s[..len].iter().position(|&b| b == c)
}

/// Locates `c` in `s`, returning either the match index or the terminating NUL index.
///
/// Equivalent to GNU C `strchrnul`.
pub fn strchrnul(s: &[u8], c: u8) -> usize {
    strchr(s, c).unwrap_or_else(|| strlen(s))
}

/// Locates the last occurrence of `c` in the NUL-terminated string `s`.
///
/// Equivalent to C `strrchr`. Returns the index of the last byte equal to `c`,
/// or `None` if not found.
pub fn strrchr(s: &[u8], c: u8) -> Option<usize> {
    let len = strlen(s);
    if c == 0 {
        return Some(len);
    }
    s[..len].iter().rposition(|&b| b == c)
}

/// Finds the first occurrence of the NUL-terminated substring `needle` in
/// the NUL-terminated string `haystack`.
///
/// Equivalent to C `strstr`. Returns the byte index where `needle` starts,
/// or `None` if not found.
pub fn strstr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let h_len = strlen(haystack);
    let n_len = strlen(needle);

    if n_len == 0 {
        return Some(0);
    }
    if n_len > h_len {
        return None;
    }

    let haystack = &haystack[..h_len];
    let needle = &needle[..n_len];

    haystack.windows(n_len).position(|window| window == needle)
}

/// Case-insensitive comparison of two NUL-terminated byte strings.
///
/// Equivalent to POSIX `strcasecmp`. Compares byte-by-byte after converting
/// ASCII letters to lowercase.
pub fn strcasecmp(s1: &[u8], s2: &[u8]) -> i32 {
    let mut i = 0;
    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();

        if la != lb {
            return (la as i32) - (lb as i32);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Case-insensitive comparison of at most `n` bytes of two NUL-terminated strings.
///
/// Equivalent to POSIX `strncasecmp`.
pub fn strncasecmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();

        if la != lb {
            return (la as i32) - (lb as i32);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// bytes in `accept`.
///
/// Equivalent to C `strspn`.
pub fn strspn(s: &[u8], accept: &[u8]) -> usize {
    let s_len = strlen(s);
    let accept_len = strlen(accept);
    let accept_set = &accept[..accept_len];

    s[..s_len]
        .iter()
        .position(|b| !accept_set.contains(b))
        .unwrap_or(s_len)
}

/// Returns the length of the initial segment of `s` consisting entirely of
/// bytes NOT in `reject`.
///
/// Equivalent to C `strcspn`.
pub fn strcspn(s: &[u8], reject: &[u8]) -> usize {
    let s_len = strlen(s);
    let reject_len = strlen(reject);
    let reject_set = &reject[..reject_len];

    s[..s_len]
        .iter()
        .position(|b| reject_set.contains(b))
        .unwrap_or(s_len)
}

/// Locates the first occurrence of any byte from `accept` in `s`.
///
/// Equivalent to C `strpbrk`. Returns the index of the first match, or `None`.
pub fn strpbrk(s: &[u8], accept: &[u8]) -> Option<usize> {
    let s_len = strlen(s);
    let accept_len = strlen(accept);
    let accept_set = &accept[..accept_len];

    s[..s_len].iter().position(|b| accept_set.contains(b))
}

/// Case-insensitive version of `strstr`. Finds the first occurrence of
/// `needle` in `haystack`, ignoring ASCII case.
///
/// Equivalent to GNU `strcasestr`. Returns the byte index where `needle` starts,
/// or `None` if not found.
pub fn strcasestr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let h_len = strlen(haystack);
    let n_len = strlen(needle);

    if n_len == 0 {
        return Some(0);
    }
    if n_len > h_len {
        return None;
    }

    let haystack = &haystack[..h_len];
    let needle = &needle[..n_len];

    haystack
        .windows(n_len)
        .position(|window| window.eq_ignore_ascii_case(needle))
}

/// Duplicates a NUL-terminated string into a new `Vec<u8>`.
///
/// This is the safe core of C `strdup`. The ABI layer handles the actual
/// malloc allocation. Returns the string bytes including the trailing NUL.
pub fn strdup_bytes(s: &[u8]) -> Vec<u8> {
    let len = strlen(s);
    let mut out = Vec::with_capacity(len + 1);
    out.extend_from_slice(&s[..len]);
    out.push(0);
    out
}

/// Duplicates at most `n` bytes of a NUL-terminated string into a new `Vec<u8>`.
///
/// This is the safe core of C `strndup`. Always NUL-terminates the result.
pub fn strndup_bytes(s: &[u8], n: usize) -> Vec<u8> {
    let len = strlen(s).min(n);
    let mut out = Vec::with_capacity(len + 1);
    out.extend_from_slice(&s[..len]);
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn to_c_string(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.retain(|byte| *byte != 0);
        bytes.push(0);
        bytes
    }

    #[test]
    fn test_strlen_basic() {
        assert_eq!(strlen(b"hello\0"), 5);
        assert_eq!(strlen(b"\0"), 0);
        assert_eq!(strlen(b"abc"), 3); // no NUL found
    }

    #[test]
    fn test_strcmp_equal() {
        assert_eq!(strcmp(b"abc\0", b"abc\0"), 0);
    }

    #[test]
    fn test_strcmp_less() {
        assert!(strcmp(b"abc\0", b"abd\0") < 0);
    }

    #[test]
    fn test_strcmp_greater() {
        assert!(strcmp(b"abd\0", b"abc\0") > 0);
    }

    #[test]
    fn test_strcmp_prefix() {
        assert!(strcmp(b"ab\0", b"abc\0") < 0);
        assert!(strcmp(b"abc\0", b"ab\0") > 0);
    }

    #[test]
    fn test_strnlen_basic() {
        assert_eq!(strnlen(b"hello\0", 10), 5);
        assert_eq!(strnlen(b"hello\0", 3), 3);
        assert_eq!(strnlen(b"\0", 5), 0);
        assert_eq!(strnlen(b"abc", 8), 3);
    }

    #[test]
    fn test_strncmp_basic() {
        assert_eq!(strncmp(b"abcdef\0", b"abcxyz\0", 3), 0);
        assert!(strncmp(b"abcdef\0", b"abcxyz\0", 4) < 0);
    }

    #[test]
    fn test_strcpy_basic() {
        let mut buf = [0u8; 10];
        let n = strcpy(&mut buf, b"hello\0");
        assert_eq!(n, 6);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_stpcpy_returns_terminator_index() {
        let mut buf = [0u8; 10];
        let idx = stpcpy(&mut buf, b"hello\0");
        assert_eq!(idx, 5);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strncpy_basic() {
        let mut buf = [0xFFu8; 10];
        strncpy(&mut buf, b"hi\0", 5);
        assert_eq!(&buf[..5], b"hi\0\0\0");
    }

    #[test]
    fn test_strncpy_truncate() {
        let mut buf = [0xFFu8; 3];
        strncpy(&mut buf, b"hello\0", 3);
        // Not NUL-terminated because src was longer than n.
        assert_eq!(&buf, b"hel");
    }

    #[test]
    fn test_stpncpy_returns_first_padding_nul_when_source_short() {
        let mut buf = [0xFFu8; 8];
        let idx = stpncpy(&mut buf, b"hi\0", 5);
        assert_eq!(idx, 2);
        assert_eq!(&buf[..5], b"hi\0\0\0");
    }

    #[test]
    fn test_stpncpy_returns_n_when_source_long() {
        let mut buf = [0xFFu8; 8];
        let idx = stpncpy(&mut buf, b"hello\0", 3);
        assert_eq!(idx, 3);
        assert_eq!(&buf[..3], b"hel");
    }

    #[test]
    fn test_strcat_basic() {
        let mut buf = [0u8; 12];
        strcpy(&mut buf, b"hello\0");
        let total = strcat(&mut buf, b" world\0");
        assert_eq!(total, 11);
        assert_eq!(&buf[..12], b"hello world\0");
    }

    #[test]
    fn test_strncat_basic() {
        let mut buf = [0u8; 10];
        strcpy(&mut buf, b"hi\0");
        let total = strncat(&mut buf, b"there\0", 3);
        assert_eq!(total, 5);
        assert_eq!(&buf[..6], b"hithe\0");
    }

    #[test]
    fn test_strchr_found() {
        assert_eq!(strchr(b"hello\0", b'l'), Some(2));
    }

    #[test]
    fn test_strchr_not_found() {
        assert_eq!(strchr(b"hello\0", b'z'), None);
    }

    #[test]
    fn test_strchr_nul() {
        assert_eq!(strchr(b"hello\0", 0), Some(5));
    }

    #[test]
    fn test_strchrnul_found() {
        assert_eq!(strchrnul(b"hello\0", b'l'), 2);
    }

    #[test]
    fn test_strchrnul_not_found_returns_terminator() {
        assert_eq!(strchrnul(b"hello\0", b'z'), 5);
    }

    #[test]
    fn test_strrchr_found() {
        assert_eq!(strrchr(b"hello\0", b'l'), Some(3));
    }

    #[test]
    fn test_strstr_found() {
        assert_eq!(strstr(b"hello world\0", b"world\0"), Some(6));
    }

    #[test]
    fn test_strstr_not_found() {
        assert_eq!(strstr(b"hello world\0", b"xyz\0"), None);
    }

    #[test]
    fn test_strstr_empty_needle() {
        assert_eq!(strstr(b"hello\0", b"\0"), Some(0));
    }

    #[test]
    fn test_strcasestr_found() {
        assert_eq!(strcasestr(b"Hello World\0", b"world\0"), Some(6));
    }

    #[test]
    fn test_strcasestr_not_found() {
        assert_eq!(strcasestr(b"Hello World\0", b"xyz\0"), None);
    }

    #[test]
    fn test_strcasestr_empty_needle() {
        assert_eq!(strcasestr(b"hello\0", b"\0"), Some(0));
    }

    #[test]
    fn test_strcasestr_exact_match() {
        assert_eq!(strcasestr(b"ABC\0", b"abc\0"), Some(0));
    }

    proptest! {
        #[test]
        fn prop_strlen_matches_first_nul_or_slice_len(data in proptest::collection::vec(any::<u8>(), 0..128)) {
            let expected = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
            prop_assert_eq!(strlen(&data), expected);
        }

        #[test]
        fn prop_strcmp_is_antisymmetric(
            left in proptest::collection::vec(any::<u8>(), 0..96),
            right in proptest::collection::vec(any::<u8>(), 0..96)
        ) {
            let left_c = to_c_string(left);
            let right_c = to_c_string(right);

            let lr = strcmp(&left_c, &right_c);
            let rl = strcmp(&right_c, &left_c);
            prop_assert_eq!(lr.signum(), -rl.signum());
        }

        #[test]
        fn prop_strstr_aligns_with_manual_window_search(
            hay in proptest::collection::vec(any::<u8>(), 0..96),
            needle in proptest::collection::vec(any::<u8>(), 0..24)
        ) {
            let hay_c = to_c_string(hay);
            let needle_c = to_c_string(needle);

            let hay_len = strlen(&hay_c);
            let needle_len = strlen(&needle_c);
            let expected = if needle_len == 0 {
                Some(0)
            } else if needle_len > hay_len {
                None
            } else {
                hay_c[..hay_len]
                    .windows(needle_len)
                    .position(|window| window == &needle_c[..needle_len])
            };

            prop_assert_eq!(strstr(&hay_c, &needle_c), expected);
        }
    }
}
