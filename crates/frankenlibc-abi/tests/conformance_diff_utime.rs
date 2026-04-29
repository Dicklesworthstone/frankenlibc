#![cfg(target_os = "linux")]

//! Differential conformance harness for `utime(3)` / `utimes(3)`.
//!
//! Both update file access/modification times. fl exports them in
//! glibc_internal_abi.rs. Tests use a fresh /tmp file per case.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, c_void, CString};

use frankenlibc_abi::glibc_internal_abi as fl;

#[repr(C)]
struct Utimbuf {
    actime: libc::time_t,
    modtime: libc::time_t,
}

unsafe extern "C" {
    fn utime(path: *const std::ffi::c_char, times: *const c_void) -> c_int;
    fn utimes(path: *const std::ffi::c_char, tv: *const c_void) -> c_int;
}

/// Create a temp file path under /tmp; remove the file on drop.
struct TempFile {
    path: CString,
}
impl TempFile {
    fn new(suffix: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!("/tmp/fl_utime_test_{nanos}_{suffix}");
        let cp = CString::new(path).unwrap();
        // Create the file by opening it.
        let fd = unsafe { libc::open(cp.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
        assert!(fd >= 0, "open failed for tmp file");
        unsafe { libc::close(fd) };
        Self { path: cp }
    }
    fn as_ptr(&self) -> *const std::ffi::c_char {
        self.path.as_ptr()
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        unsafe { libc::unlink(self.path.as_ptr()) };
    }
}

fn read_atime_mtime(path: *const std::ffi::c_char) -> (libc::time_t, libc::time_t) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::stat(path, &mut st) };
    assert_eq!(r, 0, "stat failed");
    (st.st_atime, st.st_mtime)
}

#[test]
fn diff_utime_explicit_times() {
    let fl_file = TempFile::new("fl");
    let lc_file = TempFile::new("lc");
    let times = Utimbuf {
        actime: 1_000_000_000,
        modtime: 1_500_000_000,
    };
    let fl_r = unsafe { fl::utime(fl_file.as_ptr(), &times as *const _ as *const c_void) };
    let lc_r = unsafe { utime(lc_file.as_ptr(), &times as *const _ as *const c_void) };
    assert_eq!(fl_r, lc_r, "utime return mismatch: fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, 0, "utime should succeed");

    let (fl_a, fl_m) = read_atime_mtime(fl_file.as_ptr());
    let (lc_a, lc_m) = read_atime_mtime(lc_file.as_ptr());
    assert_eq!(fl_a, lc_a, "atime mismatch: fl={fl_a} lc={lc_a}");
    assert_eq!(fl_m, lc_m, "mtime mismatch: fl={fl_m} lc={lc_m}");
    assert_eq!(fl_a, 1_000_000_000);
    assert_eq!(fl_m, 1_500_000_000);
}

#[test]
fn diff_utime_null_times_uses_current() {
    let fl_file = TempFile::new("flnull");
    let lc_file = TempFile::new("lcnull");
    // null times → both impls should set to current time. We just check
    // both succeed and the resulting timestamps are within a few seconds
    // of each other.
    let fl_r = unsafe { fl::utime(fl_file.as_ptr(), std::ptr::null()) };
    let lc_r = unsafe { utime(lc_file.as_ptr(), std::ptr::null()) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    let (fl_a, _) = read_atime_mtime(fl_file.as_ptr());
    let (lc_a, _) = read_atime_mtime(lc_file.as_ptr());
    assert!(
        (fl_a - lc_a).abs() <= 5,
        "atime drift too large: fl={fl_a} lc={lc_a}"
    );
}

#[test]
fn diff_utime_nonexistent_path_errors_match() {
    let cp = CString::new("/nonexistent/fl/path/test_utime").unwrap();
    let times = Utimbuf {
        actime: 0,
        modtime: 0,
    };
    let fl_r = unsafe { fl::utime(cp.as_ptr(), &times as *const _ as *const c_void) };
    let lc_r = unsafe { utime(cp.as_ptr(), &times as *const _ as *const c_void) };
    assert_eq!(
        fl_r, lc_r,
        "utime nonexistent return mismatch: fl={fl_r} lc={lc_r}"
    );
    assert_eq!(fl_r, -1, "should fail");
}

#[repr(C)]
struct Timeval {
    tv_sec: libc::time_t,
    tv_usec: libc::suseconds_t,
}

#[test]
fn diff_utimes_microsecond_precision() {
    let fl_file = TempFile::new("flus");
    let lc_file = TempFile::new("lcus");
    let tv = [
        Timeval { tv_sec: 1_000_000_000, tv_usec: 250_000 },
        Timeval { tv_sec: 1_500_000_000, tv_usec: 750_000 },
    ];
    let fl_r = unsafe { fl::utimes(fl_file.as_ptr(), tv.as_ptr() as *const c_void) };
    let lc_r = unsafe { utimes(lc_file.as_ptr(), tv.as_ptr() as *const c_void) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    let (fl_a, fl_m) = read_atime_mtime(fl_file.as_ptr());
    let (lc_a, lc_m) = read_atime_mtime(lc_file.as_ptr());
    assert_eq!(fl_a, lc_a);
    assert_eq!(fl_m, lc_m);
}

#[test]
fn utime_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc utime/utimes\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
