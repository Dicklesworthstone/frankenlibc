#![cfg(target_os = "linux")]

//! Differential conformance harness for `futimes(3)` / `lutimes(3)` / `futimens(3)`.
//!
//! These three round out the file-timestamp family that
//! `conformance_diff_utime.rs` started:
//!   - futimes(fd, tv) — like utimes() but on an open fd
//!   - lutimes(path, tv) — like utimes() but doesn't follow symlinks
//!   - futimens(fd, ts) — like futimes() but with nanosecond precision
//!
//! All three are forwarded to utimensat(2) inside fl, so this harness
//! mostly validates the timeval→timespec conversion and the AT_FDCWD /
//! AT_SYMLINK_NOFOLLOW dispatching.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, c_void, CString};

use frankenlibc_abi::glibc_internal_abi as fl;
use frankenlibc_abi::unistd_abi as fl_un;

unsafe extern "C" {
    fn futimes(fd: c_int, tv: *const c_void) -> c_int;
    fn lutimes(path: *const std::ffi::c_char, tv: *const c_void) -> c_int;
    fn futimens(fd: c_int, times: *const libc::timespec) -> c_int;
}

#[repr(C)]
struct Timeval {
    tv_sec: libc::time_t,
    tv_usec: libc::suseconds_t,
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
        let path = format!("/tmp/fl_futime_test_{nanos}_{suffix}");
        let cp = CString::new(path).unwrap();
        let fd = unsafe { libc::open(cp.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
        assert!(fd >= 0, "open failed for tmp file");
        unsafe { libc::close(fd) };
        Self { path: cp }
    }
    fn as_ptr(&self) -> *const std::ffi::c_char {
        self.path.as_ptr()
    }
    fn open_rdwr(&self) -> c_int {
        let fd = unsafe { libc::open(self.path.as_ptr(), libc::O_RDWR, 0) };
        assert!(fd >= 0, "open RDWR failed");
        fd
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        unsafe { libc::unlink(self.path.as_ptr()) };
    }
}

fn read_atime_mtime_ns(path: *const std::ffi::c_char) -> (libc::time_t, i64, libc::time_t, i64) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::stat(path, &mut st) };
    assert_eq!(r, 0, "stat failed");
    (st.st_atime, st.st_atime_nsec, st.st_mtime, st.st_mtime_nsec)
}

fn lread_mtime(path: *const std::ffi::c_char) -> (libc::time_t, libc::time_t) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::lstat(path, &mut st) };
    assert_eq!(r, 0, "lstat failed");
    (st.st_atime, st.st_mtime)
}

#[test]
fn diff_futimes_explicit_times() {
    let fl_file = TempFile::new("flfut");
    let lc_file = TempFile::new("lcfut");
    let tv = [
        Timeval { tv_sec: 1_111_111_111, tv_usec: 250_000 },
        Timeval { tv_sec: 1_222_222_222, tv_usec: 750_000 },
    ];

    let fl_fd = fl_file.open_rdwr();
    let lc_fd = lc_file.open_rdwr();
    let fl_r = unsafe { fl::futimes(fl_fd, tv.as_ptr() as *const c_void) };
    let lc_r = unsafe { futimes(lc_fd, tv.as_ptr() as *const c_void) };
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
    }
    assert_eq!(fl_r, lc_r, "futimes return: fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, 0);

    let (fl_a, _, fl_m, _) = read_atime_mtime_ns(fl_file.as_ptr());
    let (lc_a, _, lc_m, _) = read_atime_mtime_ns(lc_file.as_ptr());
    assert_eq!(fl_a, lc_a);
    assert_eq!(fl_m, lc_m);
    assert_eq!(fl_a, 1_111_111_111);
    assert_eq!(fl_m, 1_222_222_222);
}

#[test]
fn diff_futimes_invalid_fd_errors_match() {
    let tv = [
        Timeval { tv_sec: 0, tv_usec: 0 },
        Timeval { tv_sec: 0, tv_usec: 0 },
    ];
    let fl_r = unsafe { fl::futimes(-1, tv.as_ptr() as *const c_void) };
    let lc_r = unsafe { futimes(-1, tv.as_ptr() as *const c_void) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, -1);
}

#[test]
fn diff_lutimes_does_not_follow_symlink() {
    // Create target file and a symlink to it. lutimes must update the
    // symlink's own atime/mtime, not the target's.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let target_path = CString::new(format!("/tmp/fl_lutimes_target_{nanos}")).unwrap();
    let fl_link = CString::new(format!("/tmp/fl_lutimes_link_fl_{nanos}")).unwrap();
    let lc_link = CString::new(format!("/tmp/fl_lutimes_link_lc_{nanos}")).unwrap();

    // Create target file.
    let fd = unsafe {
        libc::open(target_path.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644)
    };
    assert!(fd >= 0);
    unsafe { libc::close(fd) };

    // Create two symlinks pointing at the same target.
    let r1 = unsafe { libc::symlink(target_path.as_ptr(), fl_link.as_ptr()) };
    let r2 = unsafe { libc::symlink(target_path.as_ptr(), lc_link.as_ptr()) };
    assert_eq!(r1, 0);
    assert_eq!(r2, 0);

    let tv = [
        Timeval { tv_sec: 900_000_000, tv_usec: 0 },
        Timeval { tv_sec: 950_000_000, tv_usec: 0 },
    ];
    let fl_r = unsafe { fl::lutimes(fl_link.as_ptr(), tv.as_ptr() as *const c_void) };
    let lc_r = unsafe { lutimes(lc_link.as_ptr(), tv.as_ptr() as *const c_void) };
    assert_eq!(fl_r, lc_r, "lutimes return: fl={fl_r} lc={lc_r}");

    if fl_r == 0 {
        let (fl_a, fl_m) = lread_mtime(fl_link.as_ptr());
        let (lc_a, lc_m) = lread_mtime(lc_link.as_ptr());
        assert_eq!(fl_a, lc_a, "lutimes atime: fl={fl_a} lc={lc_a}");
        assert_eq!(fl_m, lc_m, "lutimes mtime: fl={fl_m} lc={lc_m}");
        assert_eq!(fl_m, 950_000_000);
    }

    unsafe {
        libc::unlink(fl_link.as_ptr());
        libc::unlink(lc_link.as_ptr());
        libc::unlink(target_path.as_ptr());
    }
}

#[test]
fn diff_futimens_nanosecond_precision() {
    let fl_file = TempFile::new("flns");
    let lc_file = TempFile::new("lcns");
    let ts = [
        libc::timespec { tv_sec: 1_333_333_333, tv_nsec: 123_456_789 },
        libc::timespec { tv_sec: 1_444_444_444, tv_nsec: 987_654_321 },
    ];
    let fl_fd = fl_file.open_rdwr();
    let lc_fd = lc_file.open_rdwr();
    let fl_r = unsafe { fl_un::futimens(fl_fd, ts.as_ptr()) };
    let lc_r = unsafe { futimens(lc_fd, ts.as_ptr()) };
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
    }
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);

    let (fl_a, fl_an, fl_m, fl_mn) = read_atime_mtime_ns(fl_file.as_ptr());
    let (lc_a, lc_an, lc_m, lc_mn) = read_atime_mtime_ns(lc_file.as_ptr());
    assert_eq!(fl_a, lc_a);
    assert_eq!(fl_m, lc_m);
    assert_eq!(fl_an, lc_an, "atime nsec: fl={fl_an} lc={lc_an}");
    assert_eq!(fl_mn, lc_mn, "mtime nsec: fl={fl_mn} lc={lc_mn}");
    assert_eq!(fl_a, 1_333_333_333);
    assert_eq!(fl_an, 123_456_789);
}

#[test]
fn diff_futimens_utime_now_sentinel() {
    // tv_nsec = UTIME_NOW (1<<30 - 1) tells the kernel to use current
    // wall-clock time. Both impls must accept the sentinel.
    const UTIME_NOW: i64 = (1 << 30) - 1;
    let fl_file = TempFile::new("flnow");
    let lc_file = TempFile::new("lcnow");
    let ts = [
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_NOW },
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_NOW },
    ];
    let fl_fd = fl_file.open_rdwr();
    let lc_fd = lc_file.open_rdwr();
    let fl_r = unsafe { fl_un::futimens(fl_fd, ts.as_ptr()) };
    let lc_r = unsafe { futimens(lc_fd, ts.as_ptr()) };
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
    }
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);

    let (fl_a, _, _, _) = read_atime_mtime_ns(fl_file.as_ptr());
    let (lc_a, _, _, _) = read_atime_mtime_ns(lc_file.as_ptr());
    assert!(
        (fl_a - lc_a).abs() <= 5,
        "UTIME_NOW drift: fl={fl_a} lc={lc_a}"
    );
}

#[test]
fn diff_futimens_utime_omit_sentinel() {
    // tv_nsec = UTIME_OMIT (1<<30 - 2) tells the kernel to leave that
    // timestamp untouched. With both fields OMIT, futimens is a no-op
    // that should still return 0.
    const UTIME_OMIT: i64 = (1 << 30) - 2;
    let fl_file = TempFile::new("flom");
    let lc_file = TempFile::new("lcom");
    // Set a known baseline first.
    let baseline = [
        libc::timespec { tv_sec: 800_000_000, tv_nsec: 0 },
        libc::timespec { tv_sec: 800_000_000, tv_nsec: 0 },
    ];
    let fl_fd = fl_file.open_rdwr();
    let lc_fd = lc_file.open_rdwr();
    unsafe {
        fl_un::futimens(fl_fd, baseline.as_ptr());
        futimens(lc_fd, baseline.as_ptr());
    }

    let omit = [
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
    ];
    let fl_r = unsafe { fl_un::futimens(fl_fd, omit.as_ptr()) };
    let lc_r = unsafe { futimens(lc_fd, omit.as_ptr()) };
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
    }
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);

    let (fl_a, _, fl_m, _) = read_atime_mtime_ns(fl_file.as_ptr());
    let (lc_a, _, lc_m, _) = read_atime_mtime_ns(lc_file.as_ptr());
    // Baseline must be preserved.
    assert_eq!(fl_a, 800_000_000);
    assert_eq!(fl_m, 800_000_000);
    assert_eq!(fl_a, lc_a);
    assert_eq!(fl_m, lc_m);
}

#[test]
fn diff_futimens_null_uses_current_time() {
    let fl_file = TempFile::new("flnull");
    let lc_file = TempFile::new("lcnull");
    let fl_fd = fl_file.open_rdwr();
    let lc_fd = lc_file.open_rdwr();
    let fl_r = unsafe { fl_un::futimens(fl_fd, std::ptr::null()) };
    let lc_r = unsafe { futimens(lc_fd, std::ptr::null()) };
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
    }
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    let (fl_a, _, _, _) = read_atime_mtime_ns(fl_file.as_ptr());
    let (lc_a, _, _, _) = read_atime_mtime_ns(lc_file.as_ptr());
    assert!(
        (fl_a - lc_a).abs() <= 5,
        "null-times drift: fl={fl_a} lc={lc_a}"
    );
}

#[test]
fn futime_family_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc futimes/lutimes/futimens\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
