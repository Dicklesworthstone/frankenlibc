#![cfg(target_os = "linux")]

//! Integration tests for `<stdlib.h>` ABI entrypoints.

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::stdlib_abi::{
    atoll, clearenv, getenv, mkostemp, mkostemps, mkstemps, reallocarray, setenv, strtold,
    strtoll, strtoull,
};
use frankenlibc_abi::unistd_abi::mkdtemp;
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

#[test]
fn reallocarray_allocates_and_can_reallocate() {
    // SAFETY: null + valid size requests a fresh allocation.
    let ptr = unsafe { reallocarray(ptr::null_mut(), 4, 16) } as *mut u8;
    assert!(!ptr.is_null());

    // SAFETY: allocation is at least 64 bytes as requested.
    unsafe {
        for i in 0..64 {
            *ptr.add(i) = i as u8;
        }
    }

    // SAFETY: pointer came from reallocarray and requested larger valid size.
    let grown = unsafe { reallocarray(ptr.cast(), 8, 16) } as *mut u8;
    assert!(!grown.is_null());

    // SAFETY: realloc preserves prefix bytes of the old allocation.
    unsafe {
        for i in 0..64 {
            assert_eq!(*grown.add(i), i as u8);
        }
        libc::free(grown.cast());
    }
}

#[test]
fn reallocarray_overflow_sets_enomem() {
    // SAFETY: __errno_location points to this thread's errno.
    unsafe {
        *__errno_location() = 0;
    }

    // SAFETY: null pointer with overflowing product should fail with ENOMEM.
    let out = unsafe { reallocarray(ptr::null_mut(), usize::MAX, 2) };
    assert!(out.is_null());

    // SAFETY: read thread-local errno after call.
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::ENOMEM);
}

#[test]
fn strtold_sets_endptr_to_first_unparsed_byte() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtold(c"12.5x".as_ptr(), &mut endptr) };
    assert!((value - 12.5).abs() < f64::EPSILON);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"12.5x".as_ptr()) };
    assert_eq!(offset, 4);
}

#[test]
fn clearenv_removes_newly_set_variable() {
    let name = c"FRANKENLIBC_CLEAR_TEST_VAR";
    let value = c"present";

    // SAFETY: pointers are valid NUL-terminated C strings.
    assert_eq!(unsafe { setenv(name.as_ptr(), value.as_ptr(), 1) }, 0);
    // SAFETY: pointer is a valid NUL-terminated C string.
    assert!(!unsafe { getenv(name.as_ptr()) }.is_null());

    // SAFETY: clearenv has no pointer parameters.
    assert_eq!(unsafe { clearenv() }, 0);

    // SAFETY: pointer is a valid NUL-terminated C string.
    assert!(unsafe { getenv(name.as_ptr()) }.is_null());
}

fn temp_template(prefix: &str, suffix: &str) -> Vec<u8> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    format!("/tmp/frankenlibc-{prefix}-{stamp}-XXXXXX{suffix}\0").into_bytes()
}

#[test]
fn mkostemp_creates_unique_file_and_honors_cloexec() {
    let mut template = temp_template("mkostemp", "");

    // SAFETY: template is writable and NUL-terminated.
    let fd = unsafe { mkostemp(template.as_mut_ptr().cast(), libc::O_CLOEXEC) };
    assert!(fd >= 0);

    // SAFETY: template remains a valid NUL-terminated string after mkostemp.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(!path.contains("XXXXXX"));

    // SAFETY: fd is valid from mkostemp success path.
    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(fd_flags >= 0);
    assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);

    // SAFETY: close the descriptor we just opened.
    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn mkstemps_preserves_suffix_and_replaces_pattern() {
    let suffix = ".txt";
    let mut template = temp_template("mkstemps", suffix);

    // SAFETY: template is writable and NUL-terminated.
    let fd = unsafe { mkstemps(template.as_mut_ptr().cast(), suffix.len() as i32) };
    assert!(fd >= 0);

    // SAFETY: template remains a valid NUL-terminated string after mkstemps.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(path.ends_with(suffix));
    let stem = &path[..path.len() - suffix.len()];
    assert!(!stem.contains("XXXXXX"));

    // SAFETY: close the descriptor we just opened.
    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn mkostemps_rejects_invalid_flag_bits() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    let mut template = temp_template("mkostemps-invalid", ".bin");

    // O_TRUNC is not accepted by mkostemps flag contract in this implementation.
    // SAFETY: template is writable and NUL-terminated.
    let fd = unsafe {
        mkostemps(
            template.as_mut_ptr().cast(),
            4,
            libc::O_CLOEXEC | libc::O_TRUNC,
        )
    };
    assert_eq!(fd, -1);

    // SAFETY: read thread-local errno after call.
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn mkdtemp_creates_directory_and_rewrites_suffix() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let mut template = format!("/tmp/frankenlibc-mkdtemp-{stamp}-XXXXXX\0").into_bytes();

    // SAFETY: template is writable and NUL-terminated.
    let out = unsafe { mkdtemp(template.as_mut_ptr().cast()) };
    assert!(!out.is_null());

    // SAFETY: mkdtemp rewrites template in place as a valid C string.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(!path.ends_with("XXXXXX"));

    let meta = std::fs::metadata(&path).expect("mkdtemp should create directory");
    assert!(meta.is_dir());
    let _ = std::fs::remove_dir(path);
}
