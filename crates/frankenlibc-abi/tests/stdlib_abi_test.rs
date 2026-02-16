#![cfg(target_os = "linux")]

//! Integration tests for `<stdlib.h>` ABI entrypoints.

use frankenlibc_abi::stdlib_abi::{atoll, strtoll, strtoull};
use std::ptr;

#[test]
fn atoll_parses_i64_limits() {
    // SAFETY: both pointers reference static NUL-terminated C strings.
    let max = unsafe { atoll(c"9223372036854775807".as_ptr()) };
    // SAFETY: both pointers reference static NUL-terminated C strings.
    let min = unsafe { atoll(c"-9223372036854775808".as_ptr()) };

    assert_eq!(max, i64::MAX);
    assert_eq!(min, i64::MIN);
}

#[test]
fn strtoll_sets_endptr_to_first_unparsed_byte() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtoll(c"123x".as_ptr(), &mut endptr, 10) };
    assert_eq!(value, 123);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"123x".as_ptr()) };
    assert_eq!(offset, 3);
}

#[test]
fn strtoull_sets_endptr_to_first_unparsed_byte() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtoull(c"18446744073709551615!".as_ptr(), &mut endptr, 10) };
    assert_eq!(value, u64::MAX);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"18446744073709551615!".as_ptr()) };
    assert_eq!(offset, 20);
}
