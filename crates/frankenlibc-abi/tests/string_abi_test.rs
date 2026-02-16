#![cfg(target_os = "linux")]

//! Integration tests for `<string.h>` ABI entrypoints.

use std::ffi::c_char;

use frankenlibc_abi::string_abi::strncmp;

#[test]
fn strncmp_returns_zero_for_n_zero() {
    let lhs = b"alpha\0".as_ptr().cast::<c_char>();
    let rhs = b"beta\0".as_ptr().cast::<c_char>();

    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let result = unsafe { strncmp(lhs, rhs, 0) };
    assert_eq!(result, 0);
}

#[test]
fn strncmp_obeys_count_limit() {
    let lhs = b"abcdef\0".as_ptr().cast::<c_char>();
    let rhs = b"abcxyz\0".as_ptr().cast::<c_char>();

    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let first = unsafe { strncmp(lhs, rhs, 3) };
    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let second = unsafe { strncmp(lhs, rhs, 4) };

    assert_eq!(first, 0);
    assert!(second < 0);
}

#[test]
fn strncmp_stops_after_nul_terminator() {
    let lhs = b"ab\0cd\0".as_ptr().cast::<c_char>();
    let rhs = b"ab\0ef\0".as_ptr().cast::<c_char>();

    // SAFETY: both pointers refer to static NUL-terminated byte strings.
    let result = unsafe { strncmp(lhs, rhs, 8) };
    assert_eq!(result, 0);
}
