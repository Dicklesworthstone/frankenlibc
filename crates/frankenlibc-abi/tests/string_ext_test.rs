#![cfg(target_os = "linux")]

//! Integration tests for GNU string extensions: strverscmp, rawmemchr.

use frankenlibc_abi::string_abi::{rawmemchr, strverscmp};
use std::ffi::{c_char, c_int, c_void};

// ---------------------------------------------------------------------------
// strverscmp
// ---------------------------------------------------------------------------

#[test]
fn test_strverscmp_equal() {
    let a = b"file1.txt\0";
    let b = b"file1.txt\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert_eq!(rc, 0);
}

#[test]
fn test_strverscmp_numeric_order() {
    let a = b"file9\0";
    let b = b"file10\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(rc < 0, "file9 should come before file10, got {}", rc);
}

#[test]
fn test_strverscmp_numeric_order_reverse() {
    let a = b"file10\0";
    let b = b"file9\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(rc > 0, "file10 should come after file9, got {}", rc);
}

#[test]
fn test_strverscmp_no_digits() {
    let a = b"abc\0";
    let b = b"abd\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(rc < 0, "abc should come before abd");
}

#[test]
fn test_strverscmp_multi_digit() {
    let a = b"ver2.10\0";
    let b = b"ver2.9\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(rc > 0, "ver2.10 should come after ver2.9, got {}", rc);
}

#[test]
fn test_strverscmp_leading_zeros() {
    let a = b"file007\0";
    let b = b"file08\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    // With leading zeros, comparison is fractional: 007 < 08
    assert!(
        rc < 0,
        "file007 should come before file08 (leading zero), got {}",
        rc
    );
}

#[test]
fn test_strverscmp_null() {
    assert_eq!(unsafe { strverscmp(std::ptr::null(), std::ptr::null()) }, 0);
    assert!(unsafe { strverscmp(std::ptr::null(), c"a".as_ptr().cast()) } < 0);
    assert!(unsafe { strverscmp(c"a".as_ptr().cast(), std::ptr::null()) } > 0);
}

// ---------------------------------------------------------------------------
// rawmemchr
// ---------------------------------------------------------------------------

#[test]
fn test_rawmemchr_basic() {
    let data = b"hello world\0";
    let result = unsafe { rawmemchr(data.as_ptr() as *const c_void, b'w' as c_int) };
    assert!(!result.is_null());
    let offset = result as usize - data.as_ptr() as usize;
    assert_eq!(offset, 6, "should find 'w' at index 6");
}

#[test]
fn test_rawmemchr_first_byte() {
    let data = b"test\0";
    let result = unsafe { rawmemchr(data.as_ptr() as *const c_void, b't' as c_int) };
    assert!(!result.is_null());
    let offset = result as usize - data.as_ptr() as usize;
    assert_eq!(offset, 0);
}

#[test]
fn test_rawmemchr_null_byte() {
    let data = b"test\0";
    let result = unsafe { rawmemchr(data.as_ptr() as *const c_void, 0 as c_int) };
    assert!(!result.is_null());
    let offset = result as usize - data.as_ptr() as usize;
    assert_eq!(offset, 4, "should find NUL at index 4");
}

#[test]
fn test_rawmemchr_null_ptr() {
    let result = unsafe { rawmemchr(std::ptr::null(), b'x' as c_int) };
    assert!(result.is_null(), "rawmemchr(NULL) should return NULL");
}

#[test]
fn test_rawmemchr_last_before_nul() {
    let data = b"abcde\0";
    let result = unsafe { rawmemchr(data.as_ptr() as *const c_void, b'e' as c_int) };
    let offset = result as usize - data.as_ptr() as usize;
    assert_eq!(offset, 4);
}

#[test]
fn test_rawmemchr_repeated_byte_finds_first() {
    let data = b"aabaa\0";
    let result = unsafe { rawmemchr(data.as_ptr() as *const c_void, b'b' as c_int) };
    let offset = result as usize - data.as_ptr() as usize;
    assert_eq!(offset, 2, "should find first occurrence of 'b'");
}

#[test]
fn test_strverscmp_empty_strings() {
    let a = b"\0";
    let b = b"\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert_eq!(rc, 0, "two empty strings should be equal");
}

#[test]
fn test_strverscmp_empty_vs_nonempty() {
    let a = b"\0";
    let b = b"a\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(rc < 0, "empty string should come before 'a'");
}

#[test]
fn test_strverscmp_same_prefix_different_length() {
    let a = b"file\0";
    let b = b"file1\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(rc < 0, "file should come before file1");
}

#[test]
fn test_strverscmp_reflexive() {
    let s = b"version2.5.1\0";
    let rc = unsafe { strverscmp(s.as_ptr() as *const c_char, s.as_ptr() as *const c_char) };
    assert_eq!(rc, 0, "comparing string with itself should return 0");
}

#[test]
fn test_strverscmp_antisymmetric() {
    let a = b"ver1\0";
    let b = b"ver2\0";
    let ab = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    let ba = unsafe { strverscmp(b.as_ptr() as *const c_char, a.as_ptr() as *const c_char) };
    assert!(ab < 0);
    assert!(ba > 0);
    // Signs must be opposite.
    assert!(
        (ab < 0 && ba > 0) || (ab > 0 && ba < 0),
        "strverscmp should be antisymmetric"
    );
}

#[test]
fn test_strverscmp_all_digits() {
    let a = b"100\0";
    let b = b"20\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(
        rc > 0,
        "100 should come after 20 in version order, got {rc}"
    );
}

#[test]
fn test_rawmemchr_all_same_byte() {
    let data = b"aaaaaa\0";
    let result = unsafe { rawmemchr(data.as_ptr() as *const c_void, b'a' as c_int) };
    let offset = result as usize - data.as_ptr() as usize;
    assert_eq!(offset, 0, "should find first 'a' at index 0");
}

#[test]
fn test_rawmemchr_single_byte_buffer() {
    let data = b"x\0";
    let result = unsafe { rawmemchr(data.as_ptr() as *const c_void, b'x' as c_int) };
    let offset = result as usize - data.as_ptr() as usize;
    assert_eq!(offset, 0);
}

#[test]
fn test_strverscmp_long_numeric_segments() {
    let a = b"file123456\0";
    let b = b"file123457\0";
    let rc = unsafe { strverscmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) };
    assert!(rc < 0, "file123456 should come before file123457");
}
