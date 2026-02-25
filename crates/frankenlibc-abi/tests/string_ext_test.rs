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
    assert!(rc < 0, "file007 should come before file08 (leading zero), got {}", rc);
}

#[test]
fn test_strverscmp_null() {
    assert_eq!(unsafe { strverscmp(std::ptr::null(), std::ptr::null()) }, 0);
    assert!(unsafe { strverscmp(std::ptr::null(), b"a\0".as_ptr() as *const c_char) } < 0);
    assert!(unsafe { strverscmp(b"a\0".as_ptr() as *const c_char, std::ptr::null()) } > 0);
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
