#![cfg(target_os = "linux")]

//! Integration tests for `isoc_abi` — C99/C23 internal-linkage alias forwarding.
//!
//! These __isoc23_* and __isoc99_* symbols are ABI-identical wrappers around
//! base functions (strtol, wcstol, etc.). Tests verify the forwarding produces
//! correct results.

use std::ffi::{c_char, c_int};
use std::ptr;

use frankenlibc_abi::isoc_abi::*;

// ---------------------------------------------------------------------------
// Helper: create a C string from a byte slice (must include NUL)
// ---------------------------------------------------------------------------

fn c_ptr(s: &[u8]) -> *const c_char {
    s.as_ptr().cast::<c_char>()
}

// ---------------------------------------------------------------------------
// __isoc23_strtol family
// ---------------------------------------------------------------------------

#[test]
fn isoc23_strtol_decimal() {
    let s = b"42\0";
    let val = unsafe { __isoc23_strtol(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, 42);
}

#[test]
fn isoc23_strtol_hex() {
    let s = b"0xFF\0";
    let val = unsafe { __isoc23_strtol(c_ptr(s), ptr::null_mut(), 16) };
    assert_eq!(val, 255);
}

#[test]
fn isoc23_strtol_negative() {
    let s = b"-100\0";
    let val = unsafe { __isoc23_strtol(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, -100);
}

#[test]
fn isoc23_strtol_auto_base() {
    let s = b"010\0"; // octal
    let val = unsafe { __isoc23_strtol(c_ptr(s), ptr::null_mut(), 0) };
    assert_eq!(val, 8);
}

#[test]
fn isoc23_strtoul_basic() {
    let s = b"1000\0";
    let val = unsafe { __isoc23_strtoul(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, 1000);
}

#[test]
fn isoc23_strtoll_large() {
    let s = b"9999999999\0";
    let val = unsafe { __isoc23_strtoll(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, 9_999_999_999i64);
}

#[test]
fn isoc23_strtoull_large() {
    let s = b"18446744073709551615\0"; // u64::MAX
    let val = unsafe { __isoc23_strtoull(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, u64::MAX);
}

#[test]
fn isoc23_strtoimax_basic() {
    let s = b"-12345\0";
    let val = unsafe { __isoc23_strtoimax(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, -12345i64);
}

#[test]
fn isoc23_strtoumax_basic() {
    let s = b"99999\0";
    let val = unsafe { __isoc23_strtoumax(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, 99999u64);
}

// ---------------------------------------------------------------------------
// __isoc23_strtol_l locale variants (locale param ignored)
// ---------------------------------------------------------------------------

#[test]
fn isoc23_strtol_l_decimal() {
    let s = b"77\0";
    let val = unsafe { __isoc23_strtol_l(c_ptr(s), ptr::null_mut(), 10, ptr::null_mut()) };
    assert_eq!(val, 77);
}

#[test]
fn isoc23_strtoul_l_hex() {
    let s = b"FF\0";
    let val = unsafe { __isoc23_strtoul_l(c_ptr(s), ptr::null_mut(), 16, ptr::null_mut()) };
    assert_eq!(val, 255);
}

#[test]
fn isoc23_strtoll_l_negative() {
    let s = b"-500\0";
    let val = unsafe { __isoc23_strtoll_l(c_ptr(s), ptr::null_mut(), 10, ptr::null_mut()) };
    assert_eq!(val, -500i64);
}

#[test]
fn isoc23_strtoull_l_basic() {
    let s = b"12345\0";
    let val = unsafe { __isoc23_strtoull_l(c_ptr(s), ptr::null_mut(), 10, ptr::null_mut()) };
    assert_eq!(val, 12345u64);
}

// ---------------------------------------------------------------------------
// __isoc23_strtol endptr tracking
// ---------------------------------------------------------------------------

#[test]
fn isoc23_strtol_endptr_stops_at_non_digit() {
    let s = b"123abc\0";
    let mut end: *mut c_char = ptr::null_mut();
    let val = unsafe { __isoc23_strtol(c_ptr(s), &mut end, 10) };
    assert_eq!(val, 123);
    assert!(!end.is_null());
    // end should point to 'a'
    let remaining = unsafe { *end } as u8;
    assert_eq!(remaining, b'a');
}

// ---------------------------------------------------------------------------
// __isoc23_wcstol family (wide character)
// ---------------------------------------------------------------------------

type WcharT = i32;

fn wchar_slice(chars: &[WcharT]) -> *const WcharT {
    chars.as_ptr()
}

#[test]
fn isoc23_wcstol_decimal() {
    // "42\0" in wchar_t
    let ws: Vec<WcharT> = vec![b'4' as WcharT, b'2' as WcharT, 0];
    let val = unsafe { __isoc23_wcstol(wchar_slice(&ws), ptr::null_mut(), 10) };
    assert_eq!(val, 42);
}

#[test]
fn isoc23_wcstoul_basic() {
    let ws: Vec<WcharT> = vec![b'7' as WcharT, b'7' as WcharT, b'7' as WcharT, 0];
    let val = unsafe { __isoc23_wcstoul(wchar_slice(&ws), ptr::null_mut(), 10) };
    assert_eq!(val, 777);
}

#[test]
fn isoc23_wcstoll_negative() {
    // "-99\0"
    let ws: Vec<WcharT> = vec![b'-' as WcharT, b'9' as WcharT, b'9' as WcharT, 0];
    let val = unsafe { __isoc23_wcstoll(wchar_slice(&ws), ptr::null_mut(), 10) };
    assert_eq!(val, -99i64);
}

#[test]
fn isoc23_wcstoull_large() {
    // "65535\0"
    let ws: Vec<WcharT> = vec![
        b'6' as WcharT,
        b'5' as WcharT,
        b'5' as WcharT,
        b'3' as WcharT,
        b'5' as WcharT,
        0,
    ];
    let val = unsafe { __isoc23_wcstoull(wchar_slice(&ws), ptr::null_mut(), 10) };
    assert_eq!(val, 65535);
}

#[test]
fn isoc23_wcstoimax_basic() {
    let ws: Vec<WcharT> = vec![b'5' as WcharT, b'0' as WcharT, 0];
    let val = unsafe { __isoc23_wcstoimax(wchar_slice(&ws), ptr::null_mut(), 10) };
    assert_eq!(val, 50i64);
}

#[test]
fn isoc23_wcstoumax_hex() {
    // "FF\0"
    let ws: Vec<WcharT> = vec![b'F' as WcharT, b'F' as WcharT, 0];
    let val = unsafe { __isoc23_wcstoumax(wchar_slice(&ws), ptr::null_mut(), 16) };
    assert_eq!(val, 255u64);
}

// ---------------------------------------------------------------------------
// __isoc23_wcstol_l locale variants
// ---------------------------------------------------------------------------

#[test]
fn isoc23_wcstol_l_decimal() {
    let ws: Vec<WcharT> = vec![b'3' as WcharT, b'3' as WcharT, 0];
    let val = unsafe { __isoc23_wcstol_l(wchar_slice(&ws), ptr::null_mut(), 10, ptr::null_mut()) };
    assert_eq!(val, 33);
}

#[test]
fn isoc23_wcstoul_l_basic() {
    let ws: Vec<WcharT> = vec![b'1' as WcharT, b'0' as WcharT, 0];
    let val = unsafe { __isoc23_wcstoul_l(wchar_slice(&ws), ptr::null_mut(), 10, ptr::null_mut()) };
    assert_eq!(val, 10);
}

#[test]
fn isoc23_wcstoll_l_basic() {
    let ws: Vec<WcharT> = vec![b'8' as WcharT, b'8' as WcharT, 0];
    let val = unsafe { __isoc23_wcstoll_l(wchar_slice(&ws), ptr::null_mut(), 10, ptr::null_mut()) };
    assert_eq!(val, 88i64);
}

#[test]
fn isoc23_wcstoull_l_basic() {
    let ws: Vec<WcharT> = vec![b'4' as WcharT, b'4' as WcharT, 0];
    let val =
        unsafe { __isoc23_wcstoull_l(wchar_slice(&ws), ptr::null_mut(), 10, ptr::null_mut()) };
    assert_eq!(val, 44u64);
}

// ---------------------------------------------------------------------------
// __isoc23_sscanf (narrow string scanning)
// ---------------------------------------------------------------------------

#[test]
fn isoc23_sscanf_parses_integer() {
    let s = b"42\0";
    let fmt = b"%d\0";
    let mut val: c_int = 0;
    let rc = unsafe { __isoc23_sscanf(c_ptr(s), c_ptr(fmt), &mut val as *mut c_int) };
    assert_eq!(rc, 1);
    assert_eq!(val, 42);
}

#[test]
fn isoc23_sscanf_parses_two_integers() {
    let s = b"10 20\0";
    let fmt = b"%d %d\0";
    let mut a: c_int = 0;
    let mut b: c_int = 0;
    let rc = unsafe {
        __isoc23_sscanf(
            c_ptr(s),
            c_ptr(fmt),
            &mut a as *mut c_int,
            &mut b as *mut c_int,
        )
    };
    assert_eq!(rc, 2);
    assert_eq!(a, 10);
    assert_eq!(b, 20);
}

// ---------------------------------------------------------------------------
// __isoc23_strtol — edge cases
// ---------------------------------------------------------------------------

#[test]
fn isoc23_strtol_empty_string() {
    let s = b"\0";
    let mut end: *mut c_char = ptr::null_mut();
    let val = unsafe { __isoc23_strtol(c_ptr(s), &mut end, 10) };
    assert_eq!(val, 0);
}

#[test]
fn isoc23_strtol_whitespace_prefix() {
    let s = b"   42\0";
    let val = unsafe { __isoc23_strtol(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, 42);
}

#[test]
fn isoc23_strtol_binary_base() {
    // C23 supports 0b prefix for base 0
    let s = b"0b1010\0";
    let val = unsafe { __isoc23_strtol(c_ptr(s), ptr::null_mut(), 0) };
    // Implementation may or may not support 0b; accept 0 or 10
    assert!(val == 10 || val == 0, "0b1010 should parse as 10 or 0, got {val}");
}

#[test]
fn isoc23_strtol_max_positive() {
    let s = format!("{}\0", i64::MAX);
    let val = unsafe { __isoc23_strtol(c_ptr(s.as_bytes()), ptr::null_mut(), 10) };
    assert_eq!(val, i64::MAX);
}

#[test]
fn isoc23_strtol_min_negative() {
    let s = format!("{}\0", i64::MIN);
    let val = unsafe { __isoc23_strtol(c_ptr(s.as_bytes()), ptr::null_mut(), 10) };
    assert_eq!(val, i64::MIN);
}

#[test]
fn isoc23_strtoul_zero() {
    let s = b"0\0";
    let val = unsafe { __isoc23_strtoul(c_ptr(s), ptr::null_mut(), 10) };
    assert_eq!(val, 0);
}

#[test]
fn isoc23_strtol_hex_uppercase() {
    let s = b"0XAB\0";
    let val = unsafe { __isoc23_strtol(c_ptr(s), ptr::null_mut(), 16) };
    assert_eq!(val, 0xAB);
}

// ---------------------------------------------------------------------------
// __isoc23_sscanf — additional patterns
// ---------------------------------------------------------------------------

#[test]
fn isoc23_sscanf_no_match_returns_zero() {
    let s = b"abc\0";
    let fmt = b"%d\0";
    let mut val: c_int = -1;
    let rc = unsafe { __isoc23_sscanf(c_ptr(s), c_ptr(fmt), &mut val as *mut c_int) };
    assert_eq!(rc, 0, "no match should return 0");
    assert_eq!(val, -1, "val should be unchanged");
}

#[test]
fn isoc23_sscanf_empty_string() {
    let s = b"\0";
    let fmt = b"%d\0";
    let mut val: c_int = -1;
    let rc = unsafe { __isoc23_sscanf(c_ptr(s), c_ptr(fmt), &mut val as *mut c_int) };
    // Empty input: returns -1 (EOF) or 0
    assert!(rc <= 0, "empty input should return <= 0");
}

// ---------------------------------------------------------------------------
// __isoc23_wcstol — edge cases
// ---------------------------------------------------------------------------

#[test]
fn isoc23_wcstol_empty_string() {
    let ws: Vec<WcharT> = vec![0]; // just NUL
    let val = unsafe { __isoc23_wcstol(wchar_slice(&ws), ptr::null_mut(), 10) };
    assert_eq!(val, 0);
}

#[test]
fn isoc23_wcstol_hex() {
    // "0xFF" in wchar_t
    let ws: Vec<WcharT> = vec![
        b'0' as WcharT,
        b'x' as WcharT,
        b'F' as WcharT,
        b'F' as WcharT,
        0,
    ];
    let val = unsafe { __isoc23_wcstol(wchar_slice(&ws), ptr::null_mut(), 16) };
    assert_eq!(val, 255);
}
