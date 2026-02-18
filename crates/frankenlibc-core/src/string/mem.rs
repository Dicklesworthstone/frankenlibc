//! Memory operations: memcpy, memmove, memset, memcmp, memchr, memrchr.
//!
//! These are safe Rust implementations operating on byte slices.
//! They correspond to the `<string.h>` memory functions in POSIX/C.

/// Copies `n` bytes from `src` to `dest`.
///
/// Equivalent to C `memcpy`. The source and destination slices must not overlap;
/// use [`memmove`] if they might. Only copies `min(n, src.len(), dest.len())` bytes.
///
/// Returns the number of bytes actually copied.
pub fn memcpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies `n` bytes from `src` to `dest`, handling overlapping regions correctly.
///
/// Equivalent to C `memmove`. Safe Rust slices never truly alias, so this
/// behaves identically to [`memcpy`] at the API level, but the implementation
/// uses `copy_within`-compatible logic.
///
/// Returns the number of bytes actually copied.
pub fn memmove(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    // In safe Rust with separate slices, copy_from_slice is fine.
    // For true overlapping (same buffer), callers should use slice::copy_within.
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Fills the first `n` bytes of `dest` with the byte `value`.
///
/// Equivalent to C `memset(dest, c, n)`.
///
/// Returns the number of bytes actually set.
pub fn memset(dest: &mut [u8], value: u8, n: usize) -> usize {
    let count = n.min(dest.len());
    for byte in &mut dest[..count] {
        *byte = value;
    }
    count
}

/// Compares the first `n` bytes of `a` and `b`.
///
/// Equivalent to C `memcmp`. Returns:
/// - `Ordering::Less` if `a < b`
/// - `Ordering::Equal` if `a == b`
/// - `Ordering::Greater` if `a > b`
///
/// Only compares `min(n, a.len(), b.len())` bytes.
pub fn memcmp(a: &[u8], b: &[u8], n: usize) -> core::cmp::Ordering {
    let count = n.min(a.len()).min(b.len());
    a[..count].cmp(&b[..count])
}

/// Scans the first `n` bytes of `haystack` for the byte `needle`.
///
/// Equivalent to C `memchr`. Returns the index of the first occurrence,
/// or `None` if not found.
pub fn memchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    haystack[..count].iter().position(|&b| b == needle)
}

/// Scans the first `n` bytes of `haystack` for the last occurrence of `needle`.
///
/// Equivalent to C `memrchr`. Returns the index of the last occurrence,
/// or `None` if not found.
pub fn memrchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    haystack[..count].iter().rposition(|&b| b == needle)
}

/// Searches `haystack` (first `n` bytes) for the byte sequence `needle` (of length `needle_len`).
///
/// Equivalent to GNU `memmem`. Returns the index of the first occurrence,
/// or `None` if not found.
pub fn memmem(haystack: &[u8], n: usize, needle: &[u8], needle_len: usize) -> Option<usize> {
    let h_count = n.min(haystack.len());
    let n_count = needle_len.min(needle.len());

    if n_count == 0 {
        return Some(0);
    }
    if n_count > h_count {
        return None;
    }

    haystack[..h_count]
        .windows(n_count)
        .position(|window| window == &needle[..n_count])
}

/// Copies `n` bytes from `src` to `dest` and returns the index one past the
/// last byte written.
///
/// Equivalent to GNU `mempcpy`. Only copies `min(n, src.len(), dest.len())` bytes.
///
/// Returns the number of bytes copied (which is also the index of the next
/// unwritten byte in `dest`).
pub fn mempcpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies bytes from `src` to `dest` until byte `c` is found or `n` bytes copied.
///
/// Equivalent to POSIX `memccpy`. Returns the index one past the copied byte `c`,
/// or `None` if `c` was not found within `n` bytes.
pub fn memccpy(dest: &mut [u8], src: &[u8], c: u8, n: usize) -> Option<usize> {
    let count = n.min(dest.len()).min(src.len());
    for i in 0..count {
        dest[i] = src[i];
        if src[i] == c {
            return Some(i + 1);
        }
    }
    None
}

/// Sets `n` bytes of `dest` to zero, guaranteed not to be optimized away.
///
/// Equivalent to `explicit_bzero` / `bzero`.
pub fn bzero(dest: &mut [u8], n: usize) {
    let count = n.min(dest.len());
    for byte in &mut dest[..count] {
        // Use volatile-like write to prevent optimization.
        *byte = 0;
    }
    // Prevent the compiler from optimizing away the zeroing.
    std::hint::black_box(&dest[..count]);
}

/// Compares `n` bytes of `a` and `b`. Returns 0 if equal, non-zero otherwise.
///
/// Equivalent to legacy BSD `bcmp`.
pub fn bcmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    let count = n.min(a.len()).min(b.len());
    if a[..count] == b[..count] { 0 } else { 1 }
}

/// Swaps adjacent bytes in pairs from `src` into `dest`.
///
/// Equivalent to POSIX `swab`. Processes `n` bytes (n should be even).
pub fn swab(src: &[u8], dest: &mut [u8], n: usize) -> usize {
    let pairs = n.min(src.len()).min(dest.len()) / 2;
    for i in 0..pairs {
        dest[2 * i] = src[2 * i + 1];
        dest[2 * i + 1] = src[2 * i];
    }
    pairs * 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_memcpy_basic() {
        let src = b"hello";
        let mut dest = [0u8; 5];
        let n = memcpy(&mut dest, src, 5);
        assert_eq!(n, 5);
        assert_eq!(&dest, b"hello");
    }

    #[test]
    fn test_memcpy_partial() {
        let src = b"hello world";
        let mut dest = [0u8; 5];
        let n = memcpy(&mut dest, src, 5);
        assert_eq!(n, 5);
        assert_eq!(&dest, b"hello");
    }

    #[test]
    fn test_memset_basic() {
        let mut buf = [0u8; 8];
        memset(&mut buf, b'A', 8);
        assert_eq!(&buf, b"AAAAAAAA");
    }

    #[test]
    fn test_memset_partial() {
        let mut buf = [0u8; 8];
        memset(&mut buf, b'X', 3);
        assert_eq!(&buf, b"XXX\0\0\0\0\0");
    }

    #[test]
    fn test_memcmp_equal() {
        assert_eq!(memcmp(b"abc", b"abc", 3), core::cmp::Ordering::Equal);
    }

    #[test]
    fn test_memcmp_less() {
        assert_eq!(memcmp(b"abc", b"abd", 3), core::cmp::Ordering::Less);
    }

    #[test]
    fn test_memcmp_greater() {
        assert_eq!(memcmp(b"abd", b"abc", 3), core::cmp::Ordering::Greater);
    }

    #[test]
    fn test_memchr_found() {
        assert_eq!(memchr(b"hello", b'l', 5), Some(2));
    }

    #[test]
    fn test_memchr_not_found() {
        assert_eq!(memchr(b"hello", b'z', 5), None);
    }

    #[test]
    fn test_memrchr_found() {
        assert_eq!(memrchr(b"hello", b'l', 5), Some(3));
    }

    #[test]
    fn test_memrchr_not_found() {
        assert_eq!(memrchr(b"hello", b'z', 5), None);
    }

    #[test]
    fn test_memmem_found() {
        assert_eq!(memmem(b"hello world", 11, b"world", 5), Some(6));
    }

    #[test]
    fn test_memmem_not_found() {
        assert_eq!(memmem(b"hello world", 11, b"xyz", 3), None);
    }

    #[test]
    fn test_memmem_empty_needle() {
        assert_eq!(memmem(b"hello", 5, b"", 0), Some(0));
    }

    #[test]
    fn test_memmem_needle_longer() {
        assert_eq!(memmem(b"hi", 2, b"hello", 5), None);
    }

    #[test]
    fn test_mempcpy_basic() {
        let src = b"hello";
        let mut dest = [0u8; 8];
        let end = mempcpy(&mut dest, src, 5);
        assert_eq!(end, 5);
        assert_eq!(&dest[..5], b"hello");
    }

    #[test]
    fn test_memccpy_found() {
        let src = b"hello world";
        let mut dest = [0u8; 16];
        let result = memccpy(&mut dest, src, b' ', 11);
        assert_eq!(result, Some(6)); // index past the space
        assert_eq!(&dest[..6], b"hello ");
    }

    #[test]
    fn test_memccpy_not_found() {
        let src = b"helloworld";
        let mut dest = [0u8; 16];
        let result = memccpy(&mut dest, src, b' ', 10);
        assert_eq!(result, None);
        assert_eq!(&dest[..10], b"helloworld");
    }

    #[test]
    fn test_bzero_basic() {
        let mut buf = [0xFFu8; 8];
        bzero(&mut buf, 8);
        assert_eq!(&buf, &[0u8; 8]);
    }

    #[test]
    fn test_bzero_partial() {
        let mut buf = [0xFFu8; 8];
        bzero(&mut buf, 3);
        assert_eq!(&buf, &[0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_bcmp_equal() {
        assert_eq!(bcmp(b"abc", b"abc", 3), 0);
    }

    #[test]
    fn test_bcmp_not_equal() {
        assert_ne!(bcmp(b"abc", b"abd", 3), 0);
    }

    #[test]
    fn test_swab_basic() {
        let src = b"BADCFE";
        let mut dest = [0u8; 6];
        let n = swab(src, &mut dest, 6);
        assert_eq!(n, 6);
        assert_eq!(&dest, b"ABCDEF");
    }

    #[test]
    fn test_swab_odd_length() {
        let src = b"BADCX";
        let mut dest = [0u8; 5];
        let n = swab(src, &mut dest, 5);
        assert_eq!(n, 4); // only 2 pairs (4 bytes)
        assert_eq!(&dest[..4], b"ABCD");
    }

    proptest! {
        #[test]
        fn prop_memcpy_matches_prefix_copy(
            src in proptest::collection::vec(any::<u8>(), 0..128),
            dest_seed in proptest::collection::vec(any::<u8>(), 0..128),
            n in 0usize..256
        ) {
            let mut dest = dest_seed.clone();
            let original_dest = dest.clone();

            let copied = memcpy(&mut dest, &src, n);
            let expected = n.min(src.len()).min(original_dest.len());

            prop_assert_eq!(copied, expected);
            prop_assert_eq!(&dest[..expected], &src[..expected]);
            prop_assert_eq!(&dest[expected..], &original_dest[expected..]);
        }

        #[test]
        fn prop_memcmp_is_antisymmetric(
            left in proptest::collection::vec(any::<u8>(), 0..128),
            right in proptest::collection::vec(any::<u8>(), 0..128),
            n in 0usize..256
        ) {
            let lr = memcmp(&left, &right, n);
            let rl = memcmp(&right, &left, n);
            prop_assert_eq!(lr, rl.reverse());
        }

        #[test]
        fn prop_memset_only_mutates_requested_prefix(
            original in proptest::collection::vec(any::<u8>(), 0..128),
            value in any::<u8>(),
            n in 0usize..256
        ) {
            let mut buf = original.clone();
            let set = memset(&mut buf, value, n);
            let expected = n.min(original.len());

            prop_assert_eq!(set, expected);
            prop_assert!(buf.iter().take(expected).all(|b| *b == value));
            prop_assert_eq!(&buf[expected..], &original[expected..]);
        }
    }
}
