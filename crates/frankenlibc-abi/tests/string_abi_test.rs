#![cfg(target_os = "linux")]

//! Integration tests for `<string.h>` ABI entrypoints.

use frankenlibc_abi::string_abi::{stpcpy, stpncpy, strchrnul, strncmp, strnlen};

#[test]
fn strncmp_returns_zero_for_n_zero() {
    let lhs = c"alpha".as_ptr();
    let rhs = c"beta".as_ptr();

    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let result = unsafe { strncmp(lhs, rhs, 0) };
    assert_eq!(result, 0);
}

#[test]
fn strncmp_obeys_count_limit() {
    let lhs = c"abcdef".as_ptr();
    let rhs = c"abcxyz".as_ptr();

    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let first = unsafe { strncmp(lhs, rhs, 3) };
    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let second = unsafe { strncmp(lhs, rhs, 4) };

    assert_eq!(first, 0);
    assert!(second < 0);
}

#[test]
fn strncmp_stops_after_nul_terminator() {
    let lhs_buf = [b'a', b'b', 0, b'c', b'd', 0];
    let rhs_buf = [b'a', b'b', 0, b'e', b'f', 0];
    let lhs = lhs_buf.as_ptr().cast();
    let rhs = rhs_buf.as_ptr().cast();

    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let result = unsafe { strncmp(lhs, rhs, 8) };
    assert_eq!(result, 0);
}

#[test]
fn strnlen_stops_at_nul() {
    let value = c"hello".as_ptr();

    // SAFETY: pointer references a static NUL-terminated C string.
    let result = unsafe { strnlen(value, 16) };
    assert_eq!(result, 5);
}

#[test]
fn strnlen_respects_maximum_count() {
    let value = c"hello".as_ptr();

    // SAFETY: pointer references a static NUL-terminated C string.
    let result = unsafe { strnlen(value, 3) };
    assert_eq!(result, 3);
}

#[test]
fn stpcpy_returns_pointer_to_trailing_nul() {
    let src = c"hello".as_ptr();
    let mut dst = [0_i8; 16];

    // SAFETY: destination is writable and source is a valid C string.
    let end = unsafe { stpcpy(dst.as_mut_ptr(), src) };

    // SAFETY: `end` points inside `dst` by contract of `stpcpy`.
    let offset = unsafe { end.offset_from(dst.as_ptr()) };
    assert_eq!(offset, 5);
    assert_eq!(
        &dst[..6],
        &[
            b'h' as i8, b'e' as i8, b'l' as i8, b'l' as i8, b'o' as i8, 0
        ]
    );
}

#[test]
fn stpncpy_returns_n_when_source_prefix_exhausts_count() {
    let src = c"world".as_ptr();
    let mut dst = [0_i8; 16];

    // SAFETY: destination is writable and source is a valid C string.
    let end = unsafe { stpncpy(dst.as_mut_ptr(), src, 3) };

    // SAFETY: `end` points inside `dst` by contract of `stpncpy`.
    let offset = unsafe { end.offset_from(dst.as_ptr()) };
    assert_eq!(offset, 3);
    assert_eq!(&dst[..3], &[b'w' as i8, b'o' as i8, b'r' as i8]);
}

#[test]
fn stpncpy_returns_first_nul_when_source_shorter_than_count() {
    let src = c"hi".as_ptr();
    let mut dst = [0_i8; 16];

    // SAFETY: destination is writable and source is a valid C string.
    let end = unsafe { stpncpy(dst.as_mut_ptr(), src, 5) };

    // SAFETY: `end` points inside `dst` by contract of `stpncpy`.
    let offset = unsafe { end.offset_from(dst.as_ptr()) };
    assert_eq!(offset, 2);
    assert_eq!(&dst[..5], &[b'h' as i8, b'i' as i8, 0, 0, 0]);
}

#[test]
fn strchrnul_returns_match_when_present() {
    let haystack = c"franken".as_ptr();

    // SAFETY: pointer references a static NUL-terminated C string.
    let pos = unsafe { strchrnul(haystack, b'n' as i32) };
    // SAFETY: return value points inside the same C string.
    let offset = unsafe { pos.offset_from(haystack) };
    assert_eq!(offset, 3);
}

#[test]
fn strchrnul_returns_terminator_when_absent() {
    let haystack = c"franken".as_ptr();

    // SAFETY: pointer references a static NUL-terminated C string.
    let pos = unsafe { strchrnul(haystack, b'z' as i32) };
    // SAFETY: return value points inside the same C string.
    let offset = unsafe { pos.offset_from(haystack) };
    assert_eq!(offset, 7);
}
