#![cfg(target_os = "linux")]

//! Integration tests for stdlib extensions: gnu_get_libc_version, confstr.

use frankenlibc_abi::stdlib_abi::{confstr, gnu_get_libc_version};
use std::ffi::{CStr, c_char};

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
    assert!(
        needed > 0,
        "confstr(_CS_PATH) should return positive length"
    );

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

#[test]
fn test_gnu_get_libc_version_stable_across_calls() {
    let v1 = unsafe { gnu_get_libc_version() };
    let v2 = unsafe { gnu_get_libc_version() };
    // Should return the same pointer (static string)
    assert_eq!(v1, v2, "repeated calls should return same pointer");
}

#[test]
fn test_confstr_cs_path_null_buffer_returns_needed() {
    // _CS_PATH = 0, buffer=null, size=0 — should return needed size
    let needed = unsafe { confstr(0, std::ptr::null_mut(), 0) };
    assert!(needed > 1, "CS_PATH needs at least some bytes");
}

#[test]
fn test_confstr_pthread_filenames() {
    // _CS_GNU_LIBPTHREAD_VERSION = 3
    let needed = unsafe { confstr(3, std::ptr::null_mut(), 0) };
    if needed > 0 {
        let mut buf = vec![0u8; needed];
        let written = unsafe { confstr(3, buf.as_mut_ptr() as *mut c_char, needed) };
        assert_eq!(written, needed);
        let ver = CStr::from_bytes_with_nul(&buf).unwrap();
        assert!(
            !ver.to_str().unwrap().is_empty(),
            "pthread version should not be empty"
        );
    }
}

#[test]
fn test_confstr_size_one_buffer() {
    // Buffer of size 1 — should write just a NUL
    let mut buf = [0xFFu8; 1];
    let needed = unsafe { confstr(0, buf.as_mut_ptr() as *mut c_char, 1) };
    assert!(needed > 1, "CS_PATH should need more than 1 byte");
    assert_eq!(buf[0], 0, "size-1 buffer should contain only NUL");
}

#[test]
fn test_confstr_caps_tracked_short_output_buffer() {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(1) };
    assert!(!raw.is_null());
    unsafe { raw.cast::<u8>().write(0xff) };
    let tracked_remaining =
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(raw).unwrap_or(usize::MAX);
    assert_eq!(tracked_remaining, 1);

    let needed = unsafe { confstr(0, raw.cast::<c_char>(), 256) };

    assert!(needed > 1, "CS_PATH should need more than 1 byte");
    assert_eq!(unsafe { raw.cast::<u8>().read() }, 0);

    unsafe {
        frankenlibc_abi::malloc_abi::free(raw);
    }
}

#[test]
fn test_gnu_get_libc_version_is_ascii() {
    let ver = unsafe { gnu_get_libc_version() };
    let s = unsafe { CStr::from_ptr(ver) };
    let ver_str = s.to_str().unwrap();
    assert!(
        ver_str.is_ascii(),
        "version string should be pure ASCII: {:?}",
        ver_str
    );
}

#[test]
fn test_confstr_exact_buffer_succeeds() {
    // Get exact needed size, then provide exactly that much buffer.
    let needed = unsafe { confstr(0, std::ptr::null_mut(), 0) };
    assert!(needed > 0);
    let mut buf = vec![0u8; needed];
    let written = unsafe { confstr(0, buf.as_mut_ptr() as *mut c_char, needed) };
    assert_eq!(written, needed, "exact-size buffer should fill completely");
    // Last byte should be NUL
    assert_eq!(buf[needed - 1], 0);
}

#[test]
fn test_confstr_multiple_invalid_names_return_zero() {
    for name in [100, 200, 9999, -1i32 as u32 as i32] {
        let result = unsafe { confstr(name, std::ptr::null_mut(), 0) };
        assert_eq!(
            result, 0,
            "confstr({name}) should return 0 for invalid name"
        );
    }
}

#[test]
fn test_confstr_cs_path_deterministic() {
    let needed1 = unsafe { confstr(0, std::ptr::null_mut(), 0) };
    let needed2 = unsafe { confstr(0, std::ptr::null_mut(), 0) };
    assert_eq!(
        needed1, needed2,
        "confstr should return the same needed size on repeated calls"
    );

    let mut buf1 = vec![0u8; needed1];
    let mut buf2 = vec![0u8; needed2];
    unsafe {
        confstr(0, buf1.as_mut_ptr() as *mut c_char, needed1);
        confstr(0, buf2.as_mut_ptr() as *mut c_char, needed2);
    }
    assert_eq!(buf1, buf2, "confstr should produce identical output");
}
