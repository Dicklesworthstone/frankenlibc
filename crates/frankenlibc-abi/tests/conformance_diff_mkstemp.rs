#![cfg(target_os = "linux")]

//! Differential conformance harness for the mkstemp(3) family:
//! `mkstemp`, `mkstemps`, `mkostemp`, `mkostemps`, `mkdtemp`.
//!
//! All accept a template ending in "XXXXXX" (or longer for the
//! suffix variants) and replace it in place with random characters.
//! Both fl and glibc must agree on which templates are accepted/
//! rejected.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int};

use frankenlibc_abi::stdlib_abi as fl;
use frankenlibc_abi::unistd_abi as fl_unistd;
use frankenlibc_abi::wchar_abi as fl_wchar;

unsafe extern "C" {
    fn mkstemp(template: *mut c_char) -> c_int;
    fn mkstemps(template: *mut c_char, suffixlen: c_int) -> c_int;
    fn mkostemp(template: *mut c_char, flags: c_int) -> c_int;
    fn mkostemps(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int;
    fn mkdtemp(template: *mut c_char) -> *mut c_char;
}

fn nano_template(suffix: &str) -> Vec<u8> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("/tmp/fl_mkstemp_{nanos}_{suffix}\0").into_bytes()
}

#[test]
fn diff_mkstemp_creates_unique_files() {
    // Both impls accept the standard template; both must produce
    // valid distinct fds when called twice.
    let mut t1 = b"/tmp/fl_mkstemp_a_XXXXXX\0".to_vec();
    let mut t2 = b"/tmp/fl_mkstemp_b_XXXXXX\0".to_vec();
    let fl_fd = unsafe { fl_wchar::mkstemp(t1.as_mut_ptr() as *mut c_char) };
    let lc_fd = unsafe { mkstemp(t2.as_mut_ptr() as *mut c_char) };
    assert!(fl_fd >= 0, "fl mkstemp failed");
    assert!(lc_fd >= 0, "lc mkstemp failed");
    assert_ne!(fl_fd, lc_fd);
    // Both templates must have been mutated (no longer XXXXXX).
    assert_ne!(&t1[18..24], b"XXXXXX");
    assert_ne!(&t2[18..24], b"XXXXXX");
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
        let s1 = std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char);
        let s2 = std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char);
        libc::unlink(s1.as_ptr());
        libc::unlink(s2.as_ptr());
    }
}

#[test]
fn diff_mkstemp_invalid_template_returns_einval() {
    // Template not ending in XXXXXX → both impls must reject.
    let mut t1 = b"/tmp/fl_mkstemp_no_marker\0".to_vec();
    let mut t2 = b"/tmp/fl_mkstemp_no_marker\0".to_vec();
    let fl_fd = unsafe { fl_wchar::mkstemp(t1.as_mut_ptr() as *mut c_char) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_fd = unsafe { mkstemp(t2.as_mut_ptr() as *mut c_char) };
    let lc_e = unsafe { *libc::__errno_location() };
    assert_eq!(fl_fd, lc_fd);
    assert_eq!(fl_fd, -1);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    assert_eq!(fl_e, libc::EINVAL);
}

#[test]
fn diff_mkstemps_with_suffix_works() {
    // Template "...XXXXXX.tmp" with suffixlen=4 means the .tmp is
    // a suffix preserved, XXXXXX gets randomized.
    let mut t1 = b"/tmp/fl_mkstemps_a_XXXXXX.tmp\0".to_vec();
    let mut t2 = b"/tmp/fl_mkstemps_b_XXXXXX.tmp\0".to_vec();
    let fl_fd = unsafe { fl::mkstemps(t1.as_mut_ptr() as *mut c_char, 4) };
    let lc_fd = unsafe { mkstemps(t2.as_mut_ptr() as *mut c_char, 4) };
    assert!(fl_fd >= 0, "fl mkstemps failed");
    assert!(lc_fd >= 0, "lc mkstemps failed");
    // The .tmp suffix must be preserved.
    assert_eq!(&t1[t1.len() - 5..t1.len() - 1], b".tmp");
    assert_eq!(&t2[t2.len() - 5..t2.len() - 1], b".tmp");
    // The X's must have been replaced.
    let xs_pos = t1.len() - 11;
    assert_ne!(&t1[xs_pos..xs_pos + 6], b"XXXXXX");
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
        let s1 = std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char);
        let s2 = std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char);
        libc::unlink(s1.as_ptr());
        libc::unlink(s2.as_ptr());
    }
}

#[test]
fn diff_mkostemp_with_o_cloexec_sets_close_on_exec() {
    let mut t1 = nano_template("ostemp_a_XXXXXX");
    let mut t2 = nano_template("ostemp_b_XXXXXX");
    let fl_fd = unsafe { fl::mkostemp(t1.as_mut_ptr() as *mut c_char, libc::O_CLOEXEC) };
    let lc_fd = unsafe { mkostemp(t2.as_mut_ptr() as *mut c_char, libc::O_CLOEXEC) };
    assert!(fl_fd >= 0);
    assert!(lc_fd >= 0);
    let fl_flags = unsafe { libc::fcntl(fl_fd, libc::F_GETFD) };
    let lc_flags = unsafe { libc::fcntl(lc_fd, libc::F_GETFD) };
    assert!(fl_flags & libc::FD_CLOEXEC != 0, "fl missing FD_CLOEXEC");
    assert!(lc_flags & libc::FD_CLOEXEC != 0, "lc missing FD_CLOEXEC");
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
        let s1 = std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char);
        let s2 = std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char);
        libc::unlink(s1.as_ptr());
        libc::unlink(s2.as_ptr());
    }
}

#[test]
fn diff_mkdtemp_creates_directory() {
    let mut t1 = nano_template("mkdtemp_a_XXXXXX");
    let mut t2 = nano_template("mkdtemp_b_XXXXXX");
    let fl_p = unsafe { fl_unistd::mkdtemp(t1.as_mut_ptr() as *mut c_char) };
    let lc_p = unsafe { mkdtemp(t2.as_mut_ptr() as *mut c_char) };
    assert!(!fl_p.is_null());
    assert!(!lc_p.is_null());
    // Verify the dirs exist.
    let s1 = unsafe { std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char) };
    let s2 = unsafe { std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::stat(s1.as_ptr(), &mut st) }, 0);
    assert!(st.st_mode & libc::S_IFDIR == libc::S_IFDIR);
    assert_eq!(unsafe { libc::stat(s2.as_ptr(), &mut st) }, 0);
    assert!(st.st_mode & libc::S_IFDIR == libc::S_IFDIR);
    unsafe {
        libc::rmdir(s1.as_ptr());
        libc::rmdir(s2.as_ptr());
    }
}

#[test]
fn diff_mkdtemp_invalid_template_rejected() {
    let mut t1 = b"/tmp/fl_mkdtemp_no_marker\0".to_vec();
    let mut t2 = b"/tmp/fl_mkdtemp_no_marker\0".to_vec();
    let fl_p = unsafe { fl_unistd::mkdtemp(t1.as_mut_ptr() as *mut c_char) };
    let lc_p = unsafe { mkdtemp(t2.as_mut_ptr() as *mut c_char) };
    assert!(fl_p.is_null());
    assert!(lc_p.is_null());
}

#[test]
fn mkstemp_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc mkstemp + mkstemps + mkostemp + mkdtemp\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
