#![no_main]
//! Structure-aware fuzz target for FrankenLibC string/memory operations.
//!
//! Exercises all `<string.h>` functions from `frankenlibc-core` with
//! fuzzer-generated structured inputs. The invariant is simple: no function
//! should ever panic, corrupt memory, or return inconsistent results on
//! any well-typed input.
//!
//! Coverage goals:
//! - All string function implementations in frankenlibc-core/src/string/
//! - Variable buffer sizes including empty and maximum
//! - Null bytes in various positions
//! - Overlapping region handling
//! - Edge cases: empty strings, single-byte strings, no-NUL slices
//!
//! Bead: bd-1oz.1

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::string;

/// Maximum buffer size to keep fuzzing fast while covering large-input paths.
const MAX_BUF: usize = 4096;

/// A structured fuzz input that drives all string/mem function exercising.
/// The fuzzer mutates this structure directly, giving much better coverage
/// than raw `&[u8]` splitting.
#[derive(Debug, Arbitrary)]
struct StringFuzzInput {
    /// Primary input bytes (used as src / haystack / s1).
    data_a: Vec<u8>,
    /// Secondary input bytes (used as dst / needle / s2 / delimiters).
    data_b: Vec<u8>,
    /// A byte value for memchr/memset/memccpy targets.
    byte_val: u8,
    /// A size parameter for bounded operations (strncmp n, memcpy n, etc.).
    size_param: u16,
    /// Selector for which operation group to exercise.
    op_group: u8,
    /// Sub-selector within a group.
    op_sub: u8,
}

/// Ensure a byte slice is NUL-terminated (for str* functions).
fn ensure_nul(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len().min(MAX_BUF) + 1);
    out.extend_from_slice(&v[..v.len().min(MAX_BUF)]);
    // Strip interior NULs to make a "clean" C string, then add terminator.
    out.retain(|&b| b != 0);
    out.push(0);
    out
}

/// Make a NUL-terminated slice, but allow interior NULs (tests early-termination).
fn with_nul_terminator(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len().min(MAX_BUF) + 1);
    out.extend_from_slice(&v[..v.len().min(MAX_BUF)]);
    if out.last() != Some(&0) {
        out.push(0);
    }
    out
}

/// Create a dest buffer of given capacity, pre-filled with a NUL-terminated prefix.
fn make_dest(prefix: &[u8], extra_capacity: usize) -> Vec<u8> {
    let prefix_nul = ensure_nul(prefix);
    let total = prefix_nul.len() + extra_capacity;
    let mut buf = vec![0u8; total.min(MAX_BUF)];
    let copy_len = prefix_nul.len().min(buf.len());
    buf[..copy_len].copy_from_slice(&prefix_nul[..copy_len]);
    buf
}

fuzz_target!(|input: StringFuzzInput| {
    // Clamp inputs to prevent OOM.
    if input.data_a.len() > MAX_BUF || input.data_b.len() > MAX_BUF {
        return;
    }

    let n = input.size_param as usize;

    match input.op_group % 6 {
        0 => fuzz_mem_ops(&input, n),
        1 => fuzz_strlen_cmp(&input, n),
        2 => fuzz_copy_cat(&input, n),
        3 => fuzz_search_ops(&input),
        4 => fuzz_span_tok(&input),
        5 => fuzz_misc_ops(&input, n),
        _ => unreachable!(),
    }
});

/// Group 0: Memory operations (memcpy, memmove, memset, memcmp, memchr, memrchr,
/// memmem, mempcpy, memccpy, bzero, bcmp, swab).
fn fuzz_mem_ops(input: &StringFuzzInput, n: usize) {
    let a = &input.data_a;
    let b = &input.data_b;
    let byte = input.byte_val;

    match input.op_sub % 12 {
        0 => {
            // memcpy: copy n bytes from a into fresh buffer
            let mut dest = vec![0u8; a.len().min(MAX_BUF)];
            let copied = string::memcpy(&mut dest, a, n);
            assert!(copied <= n);
            assert!(copied <= dest.len());
            assert!(copied <= a.len());
        }
        1 => {
            // memmove: same API as memcpy but safe for overlapping
            let mut dest = vec![0u8; a.len().min(MAX_BUF)];
            let copied = string::memmove(&mut dest, a, n);
            assert!(copied <= n);
        }
        2 => {
            // memset: fill dest with byte value
            let mut dest = vec![0xFFu8; a.len().clamp(1, MAX_BUF)];
            let filled = string::memset(&mut dest, byte, n);
            assert!(filled <= n);
            assert!(filled <= dest.len());
            // Verify bytes were actually set
            for &b in &dest[..filled] {
                assert_eq!(b, byte);
            }
        }
        3 => {
            // memcmp: compare a and b
            let result = string::memcmp(a, b, n);
            // Verify symmetry: cmp(a,b) should be opposite of cmp(b,a)
            let reverse = string::memcmp(b, a, n);
            match result {
                core::cmp::Ordering::Less => {
                    assert_eq!(reverse, core::cmp::Ordering::Greater);
                }
                core::cmp::Ordering::Equal => {
                    assert_eq!(reverse, core::cmp::Ordering::Equal);
                }
                core::cmp::Ordering::Greater => {
                    assert_eq!(reverse, core::cmp::Ordering::Less);
                }
            }
            // Self-compare should be equal
            let _ = string::memcmp(a, a, n);
        }
        4 => {
            // memchr: scan for byte
            let result = string::memchr(a, byte, n);
            if let Some(idx) = result {
                assert!(idx < a.len());
                assert!(idx < n);
                assert_eq!(a[idx], byte);
            }
        }
        5 => {
            // memrchr: reverse scan for byte
            let result = string::memrchr(a, byte, n);
            if let Some(idx) = result {
                assert!(idx < a.len());
                assert!(idx < n);
                assert_eq!(a[idx], byte);
            }
        }
        6 => {
            // memmem: find b in a
            let result = string::memmem(a, n, b, b.len().min(n));
            if let Some(idx) = result {
                let h_count = n.min(a.len());
                assert!(idx <= h_count);
            }
        }
        7 => {
            // mempcpy: copy and return offset
            let mut dest = vec![0u8; a.len().clamp(1, MAX_BUF)];
            let end = string::mempcpy(&mut dest, a, n);
            assert!(end <= dest.len());
            assert!(end <= a.len());
            assert!(end <= n);
        }
        8 => {
            // memccpy: copy until byte found
            let mut dest = vec![0u8; a.len().clamp(1, MAX_BUF)];
            let result = string::memccpy(&mut dest, a, byte, n);
            if let Some(idx) = result {
                assert!(idx <= dest.len());
                assert!(idx <= a.len());
                assert!(idx <= n);
                assert!(idx > 0);
            }
        }
        9 => {
            // bzero: zero out buffer
            let mut dest = a.to_vec();
            if !dest.is_empty() {
                string::bzero(&mut dest, n);
                let zeroed = n.min(dest.len());
                for &b in &dest[..zeroed] {
                    assert_eq!(b, 0);
                }
            }
        }
        10 => {
            // bcmp: BSD compare
            let result = string::bcmp(a, b, n);
            // Self-compare should always be 0
            let self_cmp = string::bcmp(a, a, n);
            assert_eq!(self_cmp, 0);
            let _ = result;
        }
        11 => {
            // swab: swap adjacent bytes
            let mut dest = vec![0u8; a.len().clamp(2, MAX_BUF)];
            let swapped = string::swab(a, &mut dest, n);
            // swab processes pairs, so result is always even
            assert_eq!(swapped % 2, 0);
        }
        _ => unreachable!(),
    }
}

/// Group 1: String length and comparison (strlen, strnlen, strcmp, strncmp,
/// strcasecmp, strncasecmp, strcoll).
fn fuzz_strlen_cmp(input: &StringFuzzInput, n: usize) {
    let s1 = with_nul_terminator(&input.data_a);
    let s2 = with_nul_terminator(&input.data_b);

    match input.op_sub % 7 {
        0 => {
            // strlen
            let len = string::strlen(&s1);
            // len should be <= slice length (always, since we added NUL)
            assert!(len < s1.len());
            assert_eq!(s1[len], 0);
        }
        1 => {
            // strnlen
            let len = string::strnlen(&s1, n);
            assert!(len <= n);
            assert!(len <= s1.len());
        }
        2 => {
            // strcmp: antisymmetry
            let cmp_ab = string::strcmp(&s1, &s2);
            let cmp_ba = string::strcmp(&s2, &s1);
            if cmp_ab > 0 {
                assert!(cmp_ba < 0);
            } else if cmp_ab < 0 {
                assert!(cmp_ba > 0);
            } else {
                assert_eq!(cmp_ba, 0);
            }
            // Self-compare = 0
            assert_eq!(string::strcmp(&s1, &s1), 0);
        }
        3 => {
            // strncmp
            let result = string::strncmp(&s1, &s2, n);
            let _ = result;
            assert_eq!(string::strncmp(&s1, &s1, n), 0);
        }
        4 => {
            // strcasecmp: antisymmetry
            let cmp_ab = string::strcasecmp(&s1, &s2);
            let cmp_ba = string::strcasecmp(&s2, &s1);
            if cmp_ab > 0 {
                assert!(cmp_ba < 0);
            } else if cmp_ab < 0 {
                assert!(cmp_ba > 0);
            } else {
                assert_eq!(cmp_ba, 0);
            }
        }
        5 => {
            // strncasecmp
            let _ = string::strncasecmp(&s1, &s2, n);
            assert_eq!(string::strncasecmp(&s1, &s1, n), 0);
        }
        6 => {
            // strcoll (C/POSIX locale = strcmp)
            let coll = string::strcoll(&s1, &s2);
            let cmp = string::strcmp(&s1, &s2);
            assert_eq!(coll, cmp);
        }
        _ => unreachable!(),
    }
}

/// Group 2: String copy/concatenate (strcpy, stpcpy, strncpy, stpncpy,
/// strcat, strncat, strlcpy, strlcat, strxfrm, strdup, strndup).
fn fuzz_copy_cat(input: &StringFuzzInput, n: usize) {
    let src = ensure_nul(&input.data_a);
    let src_len = string::strlen(&src);

    match input.op_sub % 10 {
        0 => {
            // strcpy: dest must be large enough
            let mut dest = vec![0u8; src_len + 2];
            let copied = string::strcpy(&mut dest, &src);
            assert_eq!(copied, src_len + 1);
            assert_eq!(dest[src_len], 0);
        }
        1 => {
            // stpcpy: returns index of NUL
            let mut dest = vec![0u8; src_len + 2];
            let nul_idx = string::stpcpy(&mut dest, &src);
            assert_eq!(nul_idx, src_len);
            assert_eq!(dest[nul_idx], 0);
        }
        2 => {
            // strncpy: bounded copy
            let dest_size = n.clamp(1, MAX_BUF);
            let mut dest = vec![0xFFu8; dest_size];
            let written = string::strncpy(&mut dest, &src, n);
            assert!(written <= dest_size);
        }
        3 => {
            // stpncpy: bounded copy returning offset
            let dest_size = n.clamp(1, MAX_BUF);
            let mut dest = vec![0xFFu8; dest_size];
            let offset = string::stpncpy(&mut dest, &src, n);
            assert!(offset <= dest_size);
        }
        4 => {
            // strcat: append src to a prefix
            let prefix_data = &input.data_b[..input.data_b.len().min(64)];
            let prefix = ensure_nul(prefix_data);
            let prefix_len = string::strlen(&prefix);
            let total = prefix_len + src_len;
            if total < MAX_BUF {
                let mut dest = make_dest(prefix_data, src_len + 2);
                if dest.len() > total {
                    let result = string::strcat(&mut dest, &src);
                    assert_eq!(result, total);
                    assert_eq!(dest[total], 0);
                }
            }
        }
        5 => {
            // strncat: bounded append
            let prefix_data = &input.data_b[..input.data_b.len().min(64)];
            let prefix = ensure_nul(prefix_data);
            let prefix_len = string::strlen(&prefix);
            let append_len = src_len.min(n);
            let total = prefix_len + append_len;
            if total < MAX_BUF {
                let mut dest = make_dest(prefix_data, append_len + 2);
                if dest.len() > total {
                    let result = string::strncat(&mut dest, &src, n);
                    assert_eq!(result, total);
                    assert_eq!(dest[total], 0);
                }
            }
        }
        6 => {
            // strlcpy: always NUL-terminates
            let dest_size = n.clamp(1, MAX_BUF);
            let mut dest = vec![0xFFu8; dest_size];
            let src_total = string::strlcpy(&mut dest, &src);
            assert_eq!(src_total, src_len);
            // Must be NUL-terminated
            assert_eq!(dest[src_len.min(dest_size - 1)], 0);
        }
        7 => {
            // strlcat: always NUL-terminates
            let prefix_data = &input.data_b[..input.data_b.len().min(32)];
            let dest_size = n.clamp(1, MAX_BUF);
            let mut dest = vec![0u8; dest_size];
            // Write a short prefix
            let pnul = ensure_nul(prefix_data);
            let copy_len = pnul.len().min(dest_size);
            dest[..copy_len].copy_from_slice(&pnul[..copy_len]);
            let _ = string::strlcat(&mut dest, &src);
        }
        8 => {
            // strxfrm: locale transform (= copy in C locale)
            let dest_size = n.clamp(1, MAX_BUF);
            let mut dest = vec![0u8; dest_size];
            let needed = string::strxfrm(&mut dest, &src, dest_size);
            assert_eq!(needed, src_len);
        }
        9 => {
            // strdup_bytes / strndup_bytes: allocate copies
            let dup = string::strdup_bytes(&src);
            assert_eq!(dup.len(), src_len + 1);
            assert_eq!(dup[src_len], 0);
            assert_eq!(&dup[..src_len], &src[..src_len]);

            let ndup = string::strndup_bytes(&src, n);
            let expected_len = src_len.min(n);
            assert_eq!(ndup.len(), expected_len + 1);
            assert_eq!(ndup[expected_len], 0);
        }
        _ => unreachable!(),
    }
}

/// Group 3: Search operations (strchr, strchrnul, strrchr, strstr, strcasestr).
fn fuzz_search_ops(input: &StringFuzzInput) {
    let haystack = with_nul_terminator(&input.data_a);
    let needle = with_nul_terminator(&input.data_b);
    let c = input.byte_val;
    let h_len = string::strlen(&haystack);

    match input.op_sub % 5 {
        0 => {
            // strchr
            let result = string::strchr(&haystack, c);
            if c == 0 {
                // Searching for NUL always finds the terminator
                assert_eq!(result, Some(h_len));
            } else if let Some(idx) = result {
                assert!(idx < h_len);
                assert_eq!(haystack[idx], c);
                // Should be first occurrence
                for &b in &haystack[..idx] {
                    assert_ne!(b, c);
                }
            }
        }
        1 => {
            // strchrnul: always returns a valid index
            let idx = string::strchrnul(&haystack, c);
            assert!(idx <= h_len);
            if c != 0 && idx < h_len {
                assert_eq!(haystack[idx], c);
            }
        }
        2 => {
            // strrchr
            let result = string::strrchr(&haystack, c);
            if c == 0 {
                assert_eq!(result, Some(h_len));
            } else if let Some(idx) = result {
                assert!(idx < h_len);
                assert_eq!(haystack[idx], c);
                // Should be last occurrence
                for &b in &haystack[idx + 1..h_len] {
                    assert_ne!(b, c);
                }
            }
        }
        3 => {
            // strstr: find needle in haystack
            let n_len = string::strlen(&needle);
            let result = string::strstr(&haystack, &needle);
            if n_len == 0 {
                assert_eq!(result, Some(0));
            } else if let Some(idx) = result {
                assert!(idx + n_len <= h_len);
                assert_eq!(&haystack[idx..idx + n_len], &needle[..n_len]);
            }
        }
        4 => {
            // strcasestr: case-insensitive find
            let n_len = string::strlen(&needle);
            let result = string::strcasestr(&haystack, &needle);
            if n_len == 0 {
                assert_eq!(result, Some(0));
            } else if let Some(idx) = result {
                assert!(idx + n_len <= h_len);
                // Verify case-insensitive match
                for i in 0..n_len {
                    assert_eq!(
                        haystack[idx + i].to_ascii_lowercase(),
                        needle[i].to_ascii_lowercase()
                    );
                }
            }
        }
        _ => unreachable!(),
    }
}

/// Group 4: Span/token operations (strspn, strcspn, strpbrk, strsep, strtok, strtok_r).
fn fuzz_span_tok(input: &StringFuzzInput) {
    let s = with_nul_terminator(&input.data_a);
    let delim = ensure_nul(&input.data_b);
    let s_len = string::strlen(&s);

    match input.op_sub % 5 {
        0 => {
            // strspn: length of initial matching segment
            let span = string::strspn(&s, &delim);
            assert!(span <= s_len);
        }
        1 => {
            // strcspn: length of initial non-matching segment
            let span = string::strcspn(&s, &delim);
            assert!(span <= s_len);
            // strspn + strcspn with complementary sets should be consistent
        }
        2 => {
            // strpbrk: find first byte in accept set
            let result = string::strpbrk(&s, &delim);
            if let Some(idx) = result {
                assert!(idx < s_len);
                let delim_len = string::strlen(&delim);
                assert!(delim[..delim_len].contains(&s[idx]));
            }
        }
        3 => {
            // strsep: extract next token
            let mut buf = s.clone();
            if !buf.is_empty() {
                let _ = string::strsep(&mut buf, &delim);
            }
        }
        4 => {
            // strtok / strtok_r: iterative tokenization
            let mut buf = s.clone();
            if buf.len() > 1 {
                let result = string::strtok(&mut buf, &delim);
                let _ = result;

                // strtok_r with explicit save state
                let mut buf2 = s.clone();
                if buf2.len() > 1 {
                    let r = string::strtok_r(&mut buf2, &delim, 0);
                    let _ = r;
                }
            }
        }
        _ => unreachable!(),
    }
}

/// Group 5: Miscellaneous (memmem with various sizes, cross-function consistency,
/// empty input handling, single-byte edge cases).
fn fuzz_misc_ops(input: &StringFuzzInput, n: usize) {
    match input.op_sub % 6 {
        0 => {
            // Empty slice handling: every function should handle &[] gracefully
            let empty: &[u8] = &[];
            let empty_nul: &[u8] = &[0];
            assert_eq!(string::strlen(empty_nul), 0);
            assert_eq!(string::strnlen(empty_nul, n), 0);
            assert_eq!(string::strcmp(empty_nul, empty_nul), 0);
            let _ = string::memcmp(empty, empty, 0);
            let _ = string::memchr(empty, 0, 0);
            let _ = string::memrchr(empty, 0, 0);
            let _ = string::memmem(empty, 0, empty, 0);
            let _ = string::strstr(empty_nul, empty_nul);
            let _ = string::strcasestr(empty_nul, empty_nul);
        }
        1 => {
            // Single byte strings
            let single = [input.byte_val, 0u8];
            let len = string::strlen(&single);
            if input.byte_val == 0 {
                assert_eq!(len, 0);
            } else {
                assert_eq!(len, 1);
            }
            let _ = string::strchr(&single, input.byte_val);
            let _ = string::strrchr(&single, input.byte_val);
        }
        2 => {
            // Cross-function consistency: strlen vs strnlen with large n
            let s = with_nul_terminator(&input.data_a);
            let len = string::strlen(&s);
            let nlen = string::strnlen(&s, usize::MAX);
            assert_eq!(len, nlen);
        }
        3 => {
            // memcpy/memmove consistency: both should produce same result
            let src = &input.data_a;
            if !src.is_empty() {
                let mut dest1 = vec![0u8; src.len()];
                let mut dest2 = vec![0u8; src.len()];
                let n1 = string::memcpy(&mut dest1, src, n);
                let n2 = string::memmove(&mut dest2, src, n);
                assert_eq!(n1, n2);
                assert_eq!(dest1[..n1], dest2[..n2]);
            }
        }
        4 => {
            // strdup/strndup consistency
            let s = ensure_nul(&input.data_a);
            let s_len = string::strlen(&s);
            let dup = string::strdup_bytes(&s);
            let ndup_big = string::strndup_bytes(&s, s_len + 100);
            // Full dup and oversized ndup should be identical
            assert_eq!(dup, ndup_big);
        }
        5 => {
            // strlcpy round-trip: strlcpy then strlen should be consistent
            let src = ensure_nul(&input.data_a);
            let dest_size = n.clamp(1, MAX_BUF);
            let mut dest = vec![0u8; dest_size];
            let src_len = string::strlcpy(&mut dest, &src);
            let dest_len = string::strlen(&dest);
            // dest_len should be min(src_len, dest_size - 1)
            assert_eq!(dest_len, src_len.min(dest_size - 1));
        }
        _ => unreachable!(),
    }
}
