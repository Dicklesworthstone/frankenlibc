#![cfg(target_os = "linux")]

//! Integration tests for stdlib extensions: gnu_get_libc_version, confstr.

use frankenlibc_abi::stdlib_abi::{confstr, gnu_get_libc_version};
use std::ffi::{c_char, CStr};

// ---------------------------------------------------------------------------
// gnu_get_libc_version
// ---------------------------------------------------------------------------

#[test]
fn test_gnu_get_libc_version_not_null() {
    let ver = unsafe { gnu_get_libc_version() };
    assert!(!ver.is_null());
}

#[test]
fn test_gnu_get_libc_version_value() {
    let ver = unsafe { gnu_get_libc_version() };
    let s = unsafe { CStr::from_ptr(ver) };
    let ver_str = s.to_str().unwrap();
    assert!(
        ver_str.contains('.'),
        "version should contain a dot: {}",
        ver_str
    );
    assert_eq!(ver_str, "2.38");
}

// ---------------------------------------------------------------------------
// confstr
// ---------------------------------------------------------------------------

#[test]
fn test_confstr_cs_path() {
    // _CS_PATH = 0
    let needed = unsafe { confstr(0, std::ptr::null_mut(), 0) };
    assert!(needed > 0, "confstr(_CS_PATH) should return positive length");

    let mut buf = vec![0u8; needed];
    let written = unsafe { confstr(0, buf.as_mut_ptr() as *mut c_char, needed) };
    assert_eq!(written, needed);
    let path = CStr::from_bytes_with_nul(&buf).unwrap();
    assert!(
        path.to_str().unwrap().contains("/usr"),
        "CS_PATH should contain /usr: {:?}",
        path
    );
}

#[test]
fn test_confstr_libc_version() {
    // _CS_GNU_LIBC_VERSION = 2
    let needed = unsafe { confstr(2, std::ptr::null_mut(), 0) };
    assert!(needed > 0);

    let mut buf = vec![0u8; needed];
    let _ = unsafe { confstr(2, buf.as_mut_ptr() as *mut c_char, needed) };
    let ver = CStr::from_bytes_with_nul(&buf).unwrap();
    assert!(
        ver.to_str().unwrap().contains("glibc"),
        "should contain glibc: {:?}",
        ver
    );
}

#[test]
fn test_confstr_invalid_name() {
    let result = unsafe { confstr(9999, std::ptr::null_mut(), 0) };
    assert_eq!(result, 0, "confstr with invalid name should return 0");
}

#[test]
fn test_confstr_truncation() {
    // Request _CS_PATH but with tiny buffer
    let mut buf = [0u8; 4];
    let needed = unsafe { confstr(0, buf.as_mut_ptr() as *mut c_char, 4) };
    assert!(needed > 4, "CS_PATH should be longer than 4 bytes");
    // Last byte should be NUL (truncated).
    assert_eq!(buf[3], 0);
}
