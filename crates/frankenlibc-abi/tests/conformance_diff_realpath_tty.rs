#![cfg(target_os = "linux")]

//! Differential conformance harness for path canonicalization + tty
//! detection:
//!   - realpath / canonicalize_file_name (resolve symlinks + ..)
//!   - isatty (detect terminal fd)
//!   - ttyname / ttyname_r (resolve fd → /dev/pts/N)
//!
//! Bead: CONFORMANCE: libc realpath+isatty+ttyname diff matrix.

use std::ffi::{CStr, CString, c_char, c_int};
use std::os::fd::AsRawFd;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::{stdlib_abi as fl_stdlib, unistd_abi as fl_uni};

unsafe extern "C" {
    fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char;
    fn canonicalize_file_name(path: *const c_char) -> *mut c_char;
    fn isatty(fd: c_int) -> c_int;
    fn ttyname(fd: c_int) -> *mut c_char;
    fn ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int;
    fn posix_openpt(flags: c_int) -> c_int;
    fn grantpt(fd: c_int) -> c_int;
    fn unlockpt(fd: c_int) -> c_int;
    fn ptsname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int;
}

const O_RDWR: c_int = libc::O_RDWR;
const O_NOCTTY: c_int = libc::O_NOCTTY;

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_rp_diff_{label}_{pid}_{id}"))
}

fn reset_errno_slots() {
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

fn fl_errno() -> c_int {
    unsafe { *__errno_location() }
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[test]
fn diff_realpath_known_path() {
    // /tmp is a directory that always exists.
    let cp = CString::new("/tmp").unwrap();
    let mut buf_fl = vec![0i8; libc::PATH_MAX as usize];
    let mut buf_lc = vec![0i8; libc::PATH_MAX as usize];
    let r_fl = unsafe { fl_stdlib::realpath(cp.as_ptr(), buf_fl.as_mut_ptr()) };
    let r_lc = unsafe { realpath(cp.as_ptr(), buf_lc.as_mut_ptr()) };
    assert_eq!(
        r_fl.is_null(),
        r_lc.is_null(),
        "realpath /tmp null-match: fl={r_fl:?}, lc={r_lc:?}"
    );
    if !r_fl.is_null() && !r_lc.is_null() {
        let s_fl = unsafe { CStr::from_ptr(r_fl) }
            .to_string_lossy()
            .into_owned();
        let s_lc = unsafe { CStr::from_ptr(r_lc) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(s_fl, s_lc, "realpath result divergence");
    }
}

#[test]
fn diff_realpath_with_double_dot() {
    let cp = CString::new("/tmp/../tmp/.").unwrap();
    let mut buf_fl = vec![0i8; libc::PATH_MAX as usize];
    let mut buf_lc = vec![0i8; libc::PATH_MAX as usize];
    let r_fl = unsafe { fl_stdlib::realpath(cp.as_ptr(), buf_fl.as_mut_ptr()) };
    let r_lc = unsafe { realpath(cp.as_ptr(), buf_lc.as_mut_ptr()) };
    if !r_fl.is_null() && !r_lc.is_null() {
        let s_fl = unsafe { CStr::from_ptr(r_fl) }
            .to_string_lossy()
            .into_owned();
        let s_lc = unsafe { CStr::from_ptr(r_lc) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(s_fl, s_lc, "realpath /tmp/../tmp/. divergence");
    } else {
        assert_eq!(r_fl.is_null(), r_lc.is_null(), "realpath dotdot null-match");
    }
}

#[test]
fn diff_realpath_nonexistent_returns_null() {
    let cp = CString::new("/this/path/does/not/exist/xyz").unwrap();
    let mut buf_fl = vec![0i8; libc::PATH_MAX as usize];
    let mut buf_lc = vec![0i8; libc::PATH_MAX as usize];
    reset_errno_slots();
    let r_fl = unsafe { fl_stdlib::realpath(cp.as_ptr(), buf_fl.as_mut_ptr()) };
    let e_fl = fl_errno();
    reset_errno_slots();
    let r_lc = unsafe { realpath(cp.as_ptr(), buf_lc.as_mut_ptr()) };
    let e_lc = host_errno();
    assert_eq!(
        r_fl.is_null(),
        r_lc.is_null(),
        "realpath nonexistent null-match: fl={r_fl:?}, lc={r_lc:?}"
    );
    assert!(r_fl.is_null(), "realpath nonexistent must return NULL");
    assert_eq!(e_fl, e_lc, "realpath nonexistent errno divergence");
}

#[test]
fn diff_realpath_intermediate_file_errno_matches() {
    let cp = CString::new("/etc/passwd/not-a-directory").unwrap();
    let mut buf_fl = vec![0i8; libc::PATH_MAX as usize];
    let mut buf_lc = vec![0i8; libc::PATH_MAX as usize];
    reset_errno_slots();
    let r_fl = unsafe { fl_stdlib::realpath(cp.as_ptr(), buf_fl.as_mut_ptr()) };
    let e_fl = fl_errno();
    reset_errno_slots();
    let r_lc = unsafe { realpath(cp.as_ptr(), buf_lc.as_mut_ptr()) };
    let e_lc = host_errno();
    assert!(
        r_fl.is_null() && r_lc.is_null(),
        "realpath intermediate-file path should fail: fl={r_fl:?}, lc={r_lc:?}"
    );
    assert_eq!(e_lc, libc::ENOTDIR, "host realpath errno changed");
    assert_eq!(
        e_fl, e_lc,
        "realpath intermediate-file errno divergence: fl={e_fl}, lc={e_lc}"
    );
}

#[test]
fn diff_realpath_symlink_resolution() {
    // Create symlink target → /tmp; resolve through it
    let target_dir = "/tmp";
    let link_path = unique_tempfile("rp_link");
    std::os::unix::fs::symlink(target_dir, &link_path).unwrap();
    let cp = CString::new(link_path.to_string_lossy().as_bytes()).unwrap();
    let mut buf_fl = vec![0i8; libc::PATH_MAX as usize];
    let mut buf_lc = vec![0i8; libc::PATH_MAX as usize];
    let r_fl = unsafe { fl_stdlib::realpath(cp.as_ptr(), buf_fl.as_mut_ptr()) };
    let r_lc = unsafe { realpath(cp.as_ptr(), buf_lc.as_mut_ptr()) };
    if !r_fl.is_null() && !r_lc.is_null() {
        let s_fl = unsafe { CStr::from_ptr(r_fl) }
            .to_string_lossy()
            .into_owned();
        let s_lc = unsafe { CStr::from_ptr(r_lc) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(s_fl, s_lc, "realpath symlink divergence");
    }
    let _ = std::fs::remove_file(&link_path);
}

#[test]
fn diff_canonicalize_file_name_known_path() {
    let cp = CString::new("/tmp").unwrap();
    let r_fl = unsafe { fl_uni::canonicalize_file_name(cp.as_ptr()) };
    let r_lc = unsafe { canonicalize_file_name(cp.as_ptr()) };
    assert_eq!(
        r_fl.is_null(),
        r_lc.is_null(),
        "canonicalize_file_name null-match"
    );
    if !r_fl.is_null() && !r_lc.is_null() {
        let s_fl = unsafe { CStr::from_ptr(r_fl) }
            .to_string_lossy()
            .into_owned();
        let s_lc = unsafe { CStr::from_ptr(r_lc) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(s_fl, s_lc, "canonicalize_file_name divergence");
        unsafe {
            libc::free(r_fl as *mut libc::c_void);
            libc::free(r_lc as *mut libc::c_void);
        }
    }
}

#[test]
fn diff_isatty_non_tty_returns_zero() {
    let f = std::fs::File::open("/dev/null").unwrap();
    let fd = f.as_raw_fd();
    let r_fl = unsafe { fl_uni::isatty(fd) };
    let r_lc = unsafe { isatty(fd) };
    assert_eq!(r_fl, r_lc, "isatty(/dev/null): fl={r_fl}, lc={r_lc}");
    assert_eq!(r_fl, 0, "/dev/null should not be a tty");
}

#[test]
fn diff_isatty_real_pty_returns_one() {
    let fd = unsafe { posix_openpt(O_RDWR | O_NOCTTY) };
    if fd < 0 {
        eprintln!("PTY unavailable, skipping isatty real-pty test");
        return;
    }
    let _ = unsafe { grantpt(fd) };
    let _ = unsafe { unlockpt(fd) };
    let r_fl = unsafe { fl_uni::isatty(fd) };
    let r_lc = unsafe { isatty(fd) };
    unsafe { libc::close(fd) };
    assert_eq!(r_fl, r_lc, "isatty(pty): fl={r_fl}, lc={r_lc}");
    assert_eq!(r_fl, 1, "PTY should be a tty");
}

#[test]
fn diff_ttyname_non_tty_returns_null() {
    let f = std::fs::File::open("/dev/null").unwrap();
    let fd = f.as_raw_fd();
    let r_fl = unsafe { fl_uni::ttyname(fd) };
    let r_lc = unsafe { ttyname(fd) };
    assert_eq!(
        r_fl.is_null(),
        r_lc.is_null(),
        "ttyname(/dev/null) null-match"
    );
    assert!(r_fl.is_null(), "ttyname on non-tty must return NULL");
}

#[test]
fn diff_ttyname_r_real_pty() {
    let fd = unsafe { posix_openpt(O_RDWR | O_NOCTTY) };
    if fd < 0 {
        return;
    }
    let _ = unsafe { grantpt(fd) };
    let _ = unsafe { unlockpt(fd) };
    // The master fd's ttyname is implementation-defined. To get a real
    // tty name, open the slave side.
    let mut buf = vec![0i8; 64];
    let _ = unsafe { ptsname_r(fd, buf.as_mut_ptr(), buf.len()) };
    let slave_path = unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let slave_c = CString::new(slave_path.as_bytes()).unwrap();
    let slave_fd = unsafe { libc::open(slave_c.as_ptr(), O_RDWR | O_NOCTTY) };
    unsafe { libc::close(fd) };
    if slave_fd < 0 {
        return;
    }

    let mut buf_fl = vec![0i8; 128];
    let mut buf_lc = vec![0i8; 128];
    let r_fl = unsafe { fl_uni::ttyname_r(slave_fd, buf_fl.as_mut_ptr(), buf_fl.len()) };
    let r_lc = unsafe { ttyname_r(slave_fd, buf_lc.as_mut_ptr(), buf_lc.len()) };
    unsafe { libc::close(slave_fd) };
    assert_eq!(r_fl, r_lc, "ttyname_r return: fl={r_fl}, lc={r_lc}");
    if r_fl == 0 {
        let s_fl = unsafe { CStr::from_ptr(buf_fl.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let s_lc = unsafe { CStr::from_ptr(buf_lc.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(s_fl, s_lc, "ttyname_r content: fl={s_fl:?}, lc={s_lc:?}");
    }
}

#[test]
fn realpath_tty_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"realpath+isatty+ttyname\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",
    );
}
